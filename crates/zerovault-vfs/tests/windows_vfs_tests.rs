#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use cloud_filter::error::CloudErrorKind;
use cloud_filter::filter::{Filter, StateWatchEvent};
use parking_lot::Mutex;
use tempfile::TempDir;
use tokio::sync::mpsc;
use uuid::Uuid;
use widestring::U16CString;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_PINNED,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_UNPINNED, SetFileAttributesW,
};
use windows::core::PCWSTR;
use zerovault_types::mocks::MockVfsBackend;
use zerovault_types::{
    CreateEntrySpec, DriveStats, EntryKind, HydrationState, InodeId, InodeRecord, ROOT_INODE,
    SetAttrSpec, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult,
};
use zerovault_vfs::windows::{
    CFAPI_BLOCK_ALIGN, FILE_IDENTITY_LEN, FILE_IDENTITY_MAGIC, FileIdentity,
    MAX_HYDRATION_STREAM_SLICE, PlaceholderSpec, TransferSink, WindowsCfConfig, WindowsCfDrive,
    WindowsCfFilter, align_cfapi_transfer_range, apply_delete_inode, apply_rename_inode,
    datetime_to_file_time, guard_dehydrate_inode, placeholder_create_info_from_record,
    process_state_change_path, resolve_inode_from_blob_or_path, run_state_watcher_worker,
    split_virtual_parent_and_name, stream_chunked_hydration, virtual_path_to_windows_path,
    windows_path_to_virtual_path,
};

#[derive(Default)]
struct RecordingSink {
    slices: Mutex<Vec<(u64, Vec<u8>)>>,
    progress: Mutex<Vec<(u64, u64)>>,
    cancel_after_slices: Option<usize>,
    cancelled: Arc<AtomicBool>,
}

impl RecordingSink {
    fn new(cancelled: Arc<AtomicBool>, cancel_after_slices: Option<usize>) -> Self {
        Self {
            slices: Mutex::new(Vec::new()),
            progress: Mutex::new(Vec::new()),
            cancel_after_slices,
            cancelled,
        }
    }

    fn reassemble(&self, total_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; total_len];
        for (offset, data) in self.slices.lock().iter() {
            let start = *offset as usize;
            let end = start + data.len();
            out[start..end].copy_from_slice(data);
        }
        out
    }
}

impl TransferSink for RecordingSink {
    fn write_slice(&self, offset: u64, data: &[u8]) -> Result<(), CloudErrorKind> {
        assert!(
            data.len() <= MAX_HYDRATION_STREAM_SLICE,
            "streaming slice {} exceeded 4 MiB bound",
            data.len()
        );
        let mut guard = self.slices.lock();
        guard.push((offset, data.to_vec()));
        if let Some(limit) = self.cancel_after_slices
            && guard.len() >= limit
        {
            self.cancelled.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn report_progress(&self, total: u64, completed: u64) {
        self.progress.lock().push((total, completed));
    }
}

struct TamperingBackend {
    inner: Arc<MockVfsBackend>,
    tamper_reads: bool,
    short_read_len: Option<usize>,
    read_calls: AtomicUsize,
}

#[async_trait]
impl VfsBackend for TamperingBackend {
    async fn getattr(&self, inode: InodeId) -> ZeroVaultResult<InodeRecord> {
        self.inner.getattr(inode).await
    }

    async fn lookup(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<InodeRecord> {
        self.inner.lookup(parent_inode, name).await
    }

    async fn resolve_path(&self, virtual_path: &str) -> ZeroVaultResult<InodeRecord> {
        self.inner.resolve_path(virtual_path).await
    }

    async fn readdir(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.inner.readdir(parent_inode).await
    }

    async fn read_range(&self, inode: InodeId, offset: u64, len: usize) -> ZeroVaultResult<Bytes> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        if self.tamper_reads {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "simulated GCM authentication tag mismatch".into(),
            ));
        }
        let full = self.inner.read_range(inode, offset, len).await?;
        if let Some(short) = self.short_read_len {
            return Ok(full.slice(..short.min(full.len())));
        }
        Ok(full)
    }

    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize> {
        self.inner.write_range(inode, offset, data).await
    }

    async fn create_entry(&self, spec: CreateEntrySpec) -> ZeroVaultResult<InodeRecord> {
        self.inner.create_entry(spec).await
    }

    async fn mkdir(
        &self,
        parent_inode: InodeId,
        name: &str,
        mode: u32,
    ) -> ZeroVaultResult<InodeRecord> {
        self.inner.mkdir(parent_inode, name, mode).await
    }

    async fn unlink(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        self.inner.unlink(parent_inode, name).await
    }

    async fn rmdir(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        self.inner.rmdir(parent_inode, name).await
    }

    async fn rename(
        &self,
        parent_inode: InodeId,
        name: &str,
        new_parent_inode: InodeId,
        new_name: &str,
    ) -> ZeroVaultResult<InodeRecord> {
        self.inner
            .rename(parent_inode, name, new_parent_inode, new_name)
            .await
    }

    async fn setattr(&self, inode: InodeId, attrs: SetAttrSpec) -> ZeroVaultResult<InodeRecord> {
        self.inner.setattr(inode, attrs).await
    }

    async fn flush(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.inner.flush(inode).await
    }

    async fn fsync(&self, inode: InodeId, datasync: bool) -> ZeroVaultResult<()> {
        self.inner.fsync(inode, datasync).await
    }

    async fn pin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.inner.pin(inode).await
    }

    async fn dehydrate(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.inner.dehydrate(inode).await
    }

    async fn get_xattr_state(&self, inode: InodeId) -> ZeroVaultResult<HydrationState> {
        self.inner.get_xattr_state(inode).await
    }

    async fn drive_stats(&self) -> ZeroVaultResult<DriveStats> {
        self.inner.drive_stats().await
    }
}

fn set_win32_attributes(path: &Path, attrs: u32) {
    let wide = U16CString::from_os_str(path.as_os_str()).expect("valid utf16 path");
    unsafe {
        SetFileAttributesW(
            PCWSTR(wide.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(attrs),
        )
    }
    .expect("SetFileAttributesW");
}

#[test]
fn file_identity_roundtrip_and_corrupt_rejection() {
    let file_id = Uuid::from_bytes([
        0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01,
    ]);
    let identity = FileIdentity::new(0x1234_5678_9abc_def0, file_id);
    let encoded = identity.encode();

    assert_eq!(encoded.len(), FILE_IDENTITY_LEN);
    assert_eq!(&encoded[0..4], &FILE_IDENTITY_MAGIC);
    assert_eq!(&encoded[4..12], &0x1234_5678_9abc_def0u64.to_le_bytes());
    assert_eq!(&encoded[12..28], file_id.as_bytes());

    let decoded = FileIdentity::decode(&encoded).expect("valid identity decode");
    assert_eq!(decoded, identity);

    // Reject wrong magic
    let mut bad_magic = encoded;
    bad_magic[0..4].copy_from_slice(b"NOPE");
    assert!(matches!(
        FileIdentity::decode(&bad_magic),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));

    // Reject empty, truncated, and oversized blobs
    assert!(FileIdentity::decode(&[]).is_err());
    assert!(FileIdentity::decode(&encoded[..27]).is_err());
    let mut oversized = encoded.to_vec();
    oversized.push(0x99);
    assert!(FileIdentity::decode(&oversized).is_err());
}

#[test]
fn cfapi_4kib_alignment_covers_all_range_boundaries() {
    // Empty / EOF ranges yield None
    assert_eq!(align_cfapi_transfer_range(0..0, 10_000).unwrap(), None);
    assert_eq!(align_cfapi_transfer_range(0..100, 0).unwrap(), None);
    assert_eq!(
        align_cfapi_transfer_range(10_000..12_000, 10_000).unwrap(),
        None
    );

    // Reversed range errors cleanly
    assert!(matches!(
        align_cfapi_transfer_range(std::ops::Range { start: 5000, end: 4096 }, 10_000),
        Err(ZeroVaultError::InvalidRange { .. })
    ));

    // Unaligned interior slice aligns out to [0, 4096)
    assert_eq!(
        align_cfapi_transfer_range(100..500, 10_000).unwrap(),
        Some(0..4096)
    );

    // Cross-boundary interior slice aligns to [4096, 12288)
    assert_eq!(
        align_cfapi_transfer_range(5000..9000, 10_000_000).unwrap(),
        Some(4096..12_288)
    );

    // Exact aligned slice stays exact
    assert_eq!(
        align_cfapi_transfer_range(4096..8192, 16_384).unwrap(),
        Some(4096..8192)
    );

    // Tail slice clamps at EOF cleanly even when length is not 4 KiB-multiple
    assert_eq!(
        align_cfapi_transfer_range(4096..9000, 5000).unwrap(),
        Some(4096..5000)
    );

    // Small file below 4 KiB aligns to [0, file_size)
    assert_eq!(
        align_cfapi_transfer_range(12..34, 1500).unwrap(),
        Some(0..1500)
    );
}

#[tokio::test]
async fn stream_chunked_hydration_streams_over_5mib_in_4mib_aligned_slices() {
    let backend = Arc::new(MockVfsBackend::new());
    let file_len = 5 * 1024 * 1024 + 13_377; // > 5 MiB and non-4 KiB aligned EOF
    let payload: Vec<u8> = (0..file_len)
        .map(|i: usize| ((i.wrapping_mul(37)) ^ (i >> 9)) as u8)
        .collect();

    let rec = backend
        .seed_remote_file(ROOT_INODE, "archive.tar.zst", &payload)
        .await
        .expect("seed >5 MiB file");

    let cancelled = Arc::new(AtomicBool::new(false));
    let sink = RecordingSink::new(Arc::clone(&cancelled), None);

    let transferred = stream_chunked_hydration(
        &*backend,
        rec.inode,
        123..rec.size,
        rec.size,
        MAX_HYDRATION_STREAM_SLICE,
        || cancelled.load(Ordering::Acquire),
        &sink,
    )
    .await
    .expect("stream hydration succeeds");

    assert_eq!(transferred, file_len as u64);

    {
        let slices = sink.slices.lock();
        assert_eq!(slices.len(), 2, "5.01 MiB should stream in 2 bounded slices");
        assert_eq!(slices[0].0, 0);
        assert_eq!(slices[0].1.len(), MAX_HYDRATION_STREAM_SLICE);
        assert_eq!(slices[0].0 % CFAPI_BLOCK_ALIGN, 0);
        assert_eq!(slices[0].1.len() as u64 % CFAPI_BLOCK_ALIGN, 0);

        assert_eq!(slices[1].0, MAX_HYDRATION_STREAM_SLICE as u64);
        assert_eq!(slices[1].1.len(), file_len - MAX_HYDRATION_STREAM_SLICE);
        assert_eq!(slices[1].0 % CFAPI_BLOCK_ALIGN, 0);
        assert_eq!(
            slices[1].0 + slices[1].1.len() as u64,
            file_len as u64,
            "final non-4KiB slice must reach EOF"
        );
    }

    assert_eq!(sink.reassemble(file_len), payload);

    {
        let progress = sink.progress.lock();
        assert_eq!(progress.first().copied(), Some((file_len as u64, 0)));
        assert_eq!(
            progress.last().copied(),
            Some((file_len as u64, file_len as u64))
        );
    }

    let stats = backend.drive_stats().await.expect("stats");
    assert_eq!(stats.bytes_read, file_len as u64);
}

#[tokio::test]
async fn stream_chunked_hydration_aborts_on_cancellation() {
    let backend = Arc::new(MockVfsBackend::new());
    let file_len = 6 * 1024 * 1024;
    let payload = vec![0x5Au8; file_len];
    let rec = backend
        .seed_remote_file(ROOT_INODE, "video.mkv", &payload)
        .await
        .expect("seed 6 MiB file");

    let cancelled = Arc::new(AtomicBool::new(false));
    let sink = RecordingSink::new(Arc::clone(&cancelled), Some(2));

    let res = stream_chunked_hydration(
        &*backend,
        rec.inode,
        500..4_500_000,
        rec.size,
        1024 * 1024, // 1 MiB slices
        || cancelled.load(Ordering::Acquire),
        &sink,
    )
    .await;

    assert!(matches!(res, Err(CloudErrorKind::RequestCancelled)));
    assert_eq!(sink.slices.lock().len(), 2);
}

#[tokio::test]
async fn stream_chunked_hydration_fails_closed_on_crypto_tamper_or_short_read() {
    let inner = Arc::new(MockVfsBackend::new());
    let rec = inner
        .seed_remote_file(ROOT_INODE, "secret.db", &[0xAAu8; 16_384])
        .await
        .expect("seed");

    let tampered_backend = TamperingBackend {
        inner: Arc::clone(&inner),
        tamper_reads: true,
        short_read_len: None,
        read_calls: AtomicUsize::new(0),
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let sink = RecordingSink::new(Arc::clone(&cancelled), None);

    let err = stream_chunked_hydration(
        &tampered_backend,
        rec.inode,
        0..16_384,
        rec.size,
        MAX_HYDRATION_STREAM_SLICE,
        || false,
        &sink,
    )
    .await
    .expect_err("AEAD tamper must fail closed");

    assert!(matches!(err, CloudErrorKind::Unsuccessful));
    assert!(
        sink.slices.lock().is_empty(),
        "no tampered bytes may reach CfApi sink"
    );

    // Short read before expected slice length must also fail closed
    let short_backend = TamperingBackend {
        inner,
        tamper_reads: false,
        short_read_len: Some(512),
        read_calls: AtomicUsize::new(0),
    };
    let err_short = stream_chunked_hydration(
        &short_backend,
        rec.inode,
        0..8192,
        rec.size,
        MAX_HYDRATION_STREAM_SLICE,
        || false,
        &sink,
    )
    .await
    .expect_err("short read must fail closed");

    assert!(matches!(err_short, CloudErrorKind::Unsuccessful));
    assert!(sink.slices.lock().is_empty());
}

#[tokio::test]
async fn pin_blocks_storage_sense_dehydration_while_unpinned_succeeds() {
    let backend = Arc::new(MockVfsBackend::new());
    let pinned_rec = backend
        .seed_remote_file(ROOT_INODE, "pinned.pdf", b"pinned-payload-bytes")
        .await
        .expect("seed pinned");
    let unpinned_rec = backend
        .seed_remote_file(ROOT_INODE, "ephemeral.log", b"cached-payload-bytes")
        .await
        .expect("seed unpinned");

    // Pin first file and verify dehydration guard rejects with AccessDenied
    backend.pin(pinned_rec.inode).await.expect("pin");
    let guard_res = guard_dehydrate_inode(&*backend, pinned_rec.inode).await;
    assert!(matches!(guard_res, Err(CloudErrorKind::AccessDenied)));
    let attr = backend.getattr(pinned_rec.inode).await.expect("getattr");
    assert!(attr.pinned);
    assert_eq!(attr.hydration, HydrationState::Pinned);

    // Partially hydrate second file, then allow dehydration back to OnlineOnly
    let _ = backend
        .read_range(unpinned_rec.inode, 0, 6)
        .await
        .expect("read");
    assert_eq!(
        backend
            .getattr(unpinned_rec.inode)
            .await
            .expect("getattr")
            .hydration,
        HydrationState::PartiallyHydrated
    );

    guard_dehydrate_inode(&*backend, unpinned_rec.inode)
        .await
        .expect("unpinned dehydration allowed");

    let dehydrated = backend.getattr(unpinned_rec.inode).await.expect("getattr");
    assert!(!dehydrated.pinned);
    assert_eq!(dehydrated.hydration, HydrationState::OnlineOnly);
}

#[test]
fn placeholder_create_info_construction_for_files_and_directories() {
    let created = Utc.with_ymd_and_hms(2026, 3, 15, 10, 30, 0).unwrap();
    let modified = Utc.with_ymd_and_hms(2026, 11, 17, 14, 0, 0).unwrap();
    let file_id = Uuid::new_v4();

    let file_rec = InodeRecord {
        inode: 17,
        parent_inode: ROOT_INODE,
        file_id,
        name: "budget.xlsx".to_owned(),
        virtual_path: "/budget.xlsx".to_owned(),
        kind: EntryKind::File,
        size: 987_654,
        mode: 0o644,
        hydration: HydrationState::OnlineOnly,
        pinned: false,
        version: 3,
        wrapped_dek: None,
        modified_at: modified,
        created_at: created,
    };

    let spec = PlaceholderSpec::from_record(&file_rec).expect("file placeholder spec");
    assert_eq!(spec.relative_name, "budget.xlsx");
    assert!(!spec.is_directory);
    assert_eq!(spec.file_size, 987_654);
    assert_eq!(spec.file_attributes, FILE_ATTRIBUTE_NORMAL.0);
    assert!(spec.mark_in_sync);
    assert_eq!(spec.created_at, datetime_to_file_time(created));
    assert_eq!(spec.modified_at, datetime_to_file_time(modified));
    assert_eq!(spec.identity, FileIdentity::new(17, file_id));
    assert!(placeholder_create_info_from_record(&file_rec).is_ok());

    let readonly_dirty_rec = InodeRecord {
        inode: 18,
        mode: 0o444,
        hydration: HydrationState::DirtyLocal,
        ..file_rec.clone()
    };
    let ro_spec = PlaceholderSpec::from_record(&readonly_dirty_rec).expect("readonly spec");
    assert_ne!(ro_spec.file_attributes & FILE_ATTRIBUTE_READONLY.0, 0);
    assert!(!ro_spec.mark_in_sync);
    assert!(placeholder_create_info_from_record(&readonly_dirty_rec).is_ok());

    let dir_rec = InodeRecord {
        inode: 19,
        parent_inode: ROOT_INODE,
        file_id: Uuid::new_v4(),
        name: "Finance".to_owned(),
        virtual_path: "/Finance".to_owned(),
        kind: EntryKind::Directory,
        size: 4096, // directories must force logical placeholder size to 0
        mode: 0o755,
        hydration: HydrationState::Pinned,
        pinned: true,
        version: 1,
        wrapped_dek: None,
        modified_at: modified,
        created_at: created,
    };
    let dir_spec = PlaceholderSpec::from_record(&dir_rec).expect("dir spec");
    assert!(dir_spec.is_directory);
    assert_eq!(dir_spec.file_size, 0);
    assert_eq!(dir_spec.file_attributes, FILE_ATTRIBUTE_DIRECTORY.0);
    assert!(dir_spec.mark_in_sync);
    assert!(placeholder_create_info_from_record(&dir_rec).is_ok());

    // Invalid names are rejected before reaching U16CString::unwrap()
    for bad_name in ["", ".", "..", "a/b", r"a\b", "bad\0name"] {
        let mut invalid = file_rec.clone();
        invalid.name = bad_name.to_owned();
        assert!(placeholder_create_info_from_record(&invalid).is_err());
    }
}

#[test]
fn windows_and_virtual_path_conversions() {
    let mount = Path::new(r"\\?\C:\Users\Nick\Zerovault");
    assert_eq!(
        windows_path_to_virtual_path(mount, Path::new(r"c:\Users\Nick\Zerovault")).unwrap(),
        "/"
    );
    assert_eq!(
        windows_path_to_virtual_path(mount, Path::new(r"C:\Users\Nick\Zerovault\Docs\a.txt"))
            .unwrap(),
        "/Docs/a.txt"
    );
    assert!(windows_path_to_virtual_path(mount, Path::new(r"C:\Users\Nick\Other\a.txt")).is_err());

    assert_eq!(
        virtual_path_to_windows_path(Path::new(r"C:\Vault"), "/").unwrap(),
        PathBuf::from(r"C:\Vault")
    );
    assert_eq!(
        virtual_path_to_windows_path(Path::new(r"C:\Vault"), "/Docs/a.txt").unwrap(),
        PathBuf::from(r"C:\Vault\Docs\a.txt")
    );
    assert_eq!(
        split_virtual_parent_and_name("/Docs/a.txt").unwrap(),
        ("/Docs".to_owned(), "a.txt".to_owned())
    );
    assert_eq!(
        split_virtual_parent_and_name("/root_file.bin").unwrap(),
        ("/".to_owned(), "root_file.bin".to_owned())
    );
}

#[tokio::test]
async fn delete_and_rename_preserve_backend_consistency() {
    let backend = Arc::new(MockVfsBackend::new());
    let dir = backend
        .mkdir(ROOT_INODE, "Docs", 0o755)
        .await
        .expect("mkdir Docs");
    let sub = backend
        .mkdir(ROOT_INODE, "Archive", 0o755)
        .await
        .expect("mkdir Archive");
    let file = backend
        .seed_remote_file(dir.inode, "notes.txt", b"hello")
        .await
        .expect("seed file");

    // Deleting non-empty directory must fail closed and keep directory intact
    let del_non_empty = apply_delete_inode(&*backend, dir.inode, true, false).await;
    assert!(matches!(del_non_empty, Err(CloudErrorKind::InvalidRequest)));
    assert!(backend.getattr(dir.inode).await.is_ok());

    // Rename across directories updates parent and virtual path
    let mount = Path::new(r"C:\Zerovault");
    apply_rename_inode(
        &*backend,
        mount,
        file.inode,
        true,
        true,
        Path::new(r"C:\Zerovault\Archive\moved.txt"),
    )
    .await
    .expect("rename succeeds");

    assert!(backend.resolve_path("/Docs/notes.txt").await.is_err());
    let moved = backend
        .resolve_path("/Archive/moved.txt")
        .await
        .expect("moved path resolves");
    assert_eq!(moved.inode, file.inode);
    assert_eq!(moved.parent_inode, sub.inode);

    // Delete file and now-empty Docs dir
    apply_delete_inode(&*backend, moved.inode, false, false)
        .await
        .expect("unlink file");
    apply_delete_inode(&*backend, dir.inode, true, false)
        .await
        .expect("rmdir empty dir");

    // Undelete check fails if inode no longer exists
    assert!(matches!(
        apply_delete_inode(&*backend, moved.inode, false, true).await,
        Err(CloudErrorKind::NotSupported)
    ));
}

#[tokio::test]
async fn state_changed_reconciles_local_writes_and_pin_attributes() {
    let temp = TempDir::new().expect("tempdir");
    let mount = temp.path().to_path_buf();
    let backend = Arc::new(MockVfsBackend::new());

    // 1. Existing file modified locally (including truncation) -> synced & flushed
    let existing = backend
        .seed_remote_file(ROOT_INODE, "notes.txt", b"initial-longer-remote-payload")
        .await
        .expect("seed");
    let local_notes = mount.join("notes.txt");
    tokio::fs::write(&local_notes, b"short-edit")
        .await
        .expect("write local");
    process_state_change_path(&mount, &local_notes, &*backend)
        .await
        .expect("reconcile edit");
    let updated = backend.getattr(existing.inode).await.expect("getattr");
    assert_eq!(updated.size, 10);
    assert_eq!(updated.hydration, HydrationState::LocallyCached);
    assert_eq!(
        backend
            .read_range(existing.inode, 0, 10)
            .await
            .expect("read")
            .as_ref(),
        b"short-edit"
    );

    // 2. New local file inside new nested folder -> created, streamed, and flushed
    let nested_dir = mount.join("Inbox");
    tokio::fs::create_dir_all(&nested_dir)
        .await
        .expect("mkdir Inbox");
    let nested_file = nested_dir.join("draft.bin");
    let draft_bytes = vec![0x42u8; 64 * 1024];
    tokio::fs::write(&nested_file, &draft_bytes)
        .await
        .expect("write draft");
    process_state_change_path(&mount, &nested_file, &*backend)
        .await
        .expect("reconcile new file");
    let draft_rec = backend
        .resolve_path("/Inbox/draft.bin")
        .await
        .expect("resolve /Inbox/draft.bin");
    assert_eq!(draft_rec.size, draft_bytes.len() as u64);
    assert_eq!(draft_rec.hydration, HydrationState::LocallyCached);

    // 3. FILE_ATTRIBUTE_PINNED transition -> pins file in backend
    let pin_target = backend
        .seed_remote_file(ROOT_INODE, "pin_me.dat", b"pin-payload")
        .await
        .expect("seed pin_me");
    let local_pin = mount.join("pin_me.dat");
    tokio::fs::write(&local_pin, b"").await.expect("stub");
    set_win32_attributes(&local_pin, FILE_ATTRIBUTE_PINNED.0);
    process_state_change_path(&mount, &local_pin, &*backend)
        .await
        .expect("reconcile pin attr");
    let pin_attr = backend.getattr(pin_target.inode).await.expect("getattr");
    assert!(pin_attr.pinned);
    assert_eq!(pin_attr.hydration, HydrationState::Pinned);
    assert_eq!(
        backend
            .read_range(pin_target.inode, 0, 11)
            .await
            .expect("read preserved remote content")
            .as_ref(),
        b"pin-payload"
    );

    // 4. FILE_ATTRIBUTE_UNPINNED transition -> dehydrates unpinned file back to OnlineOnly
    let unpin_target = backend
        .seed_remote_file(ROOT_INODE, "unpin_me.dat", b"unpin-payload")
        .await
        .expect("seed unpin_me");
    let _ = backend
        .read_range(unpin_target.inode, 0, 13)
        .await
        .expect("hydrate");
    let local_unpin = mount.join("unpin_me.dat");
    tokio::fs::write(&local_unpin, b"").await.expect("stub");
    set_win32_attributes(&local_unpin, FILE_ATTRIBUTE_UNPINNED.0);
    process_state_change_path(&mount, &local_unpin, &*backend)
        .await
        .expect("reconcile unpin attr");
    let unpin_attr = backend.getattr(unpin_target.inode).await.expect("getattr");
    assert!(!unpin_attr.pinned);
    assert_eq!(unpin_attr.hydration, HydrationState::OnlineOnly);

    // 5. Async worker channel via WindowsCfFilter::state_changed never blocks caller
    let (tx, rx) = mpsc::unbounded_channel();
    let worker_backend = Arc::clone(&backend);
    let worker_mount = mount.clone();
    let worker = tokio::spawn(async move {
        run_state_watcher_worker(worker_mount, worker_backend, rx).await;
    });
    let filter = WindowsCfFilter::new(
        Arc::clone(&backend) as Arc<dyn VfsBackend>,
        mount.clone(),
        tx,
    );
    let queued_file = mount.join("queued.txt");
    tokio::fs::write(&queued_file, b"queued-content")
        .await
        .expect("write queued");
    filter
        .state_changed(StateWatchEvent::Changed(vec![queued_file]))
        .await;
    drop(filter);
    worker.await.expect("worker exits cleanly when channel drops");

    let queued_rec = backend
        .resolve_path("/queued.txt")
        .await
        .expect("worker reconciled /queued.txt");
    assert_eq!(queued_rec.size, 14);
}

#[tokio::test]
async fn resolve_inode_prefers_file_identity_and_rejects_mismatched_uuid() {
    let backend = Arc::new(MockVfsBackend::new());
    let dir = backend.mkdir(ROOT_INODE, "Docs", 0o755).await.expect("mkdir");
    let rec = backend
        .seed_remote_file(dir.inode, "contract.pdf", b"pdf-bytes")
        .await
        .expect("seed");

    let mount = Path::new(r"C:\Zerovault");
    let valid_blob = FileIdentity::from_record(&rec).encode();

    // Even if the path passed is stale (simulating concurrent rename), FileIdentity resolves O(1).
    let resolved = resolve_inode_from_blob_or_path(
        &*backend,
        mount,
        &valid_blob,
        Path::new(r"C:\Zerovault\Docs\stale-name.pdf"),
    )
    .await
    .expect("resolve via FileIdentity");
    assert_eq!(resolved.inode, rec.inode);
    assert_eq!(resolved.file_id, rec.file_id);

    // Mismatched cryptographic file_id fails closed with MetadataCorrupt.
    let wrong_blob = FileIdentity::new(rec.inode, Uuid::new_v4()).encode();
    let err = resolve_inode_from_blob_or_path(
        &*backend,
        mount,
        &wrong_blob,
        Path::new(r"C:\Zerovault\Docs\contract.pdf"),
    )
    .await
    .expect_err("wrong file_id must fail");
    assert!(matches!(err, CloudErrorKind::MetadataCorrupt));

    // Empty blob (such as sync root folder) falls back to normalized virtual path resolution.
    let root = resolve_inode_from_blob_or_path(&*backend, mount, &[], mount)
        .await
        .expect("root fallback");
    assert_eq!(root.inode, ROOT_INODE);
}

#[tokio::test]
async fn state_changed_streams_over_5mib_local_write_without_full_buffering() {
    let temp = TempDir::new().expect("tempdir");
    let mount = temp.path().to_path_buf();
    let backend = Arc::new(MockVfsBackend::new());

    let large_len = 5 * 1024 * 1024 + 777;
    let large_payload: Vec<u8> = (0..large_len)
        .map(|i: usize| ((i.wrapping_mul(19)) ^ (i >> 7)) as u8)
        .collect();
    let rec = backend
        .seed_remote_file(ROOT_INODE, "big_upload.bin", b"tiny")
        .await
        .expect("seed");

    let local_path = mount.join("big_upload.bin");
    tokio::fs::write(&local_path, &large_payload)
        .await
        .expect("write >5 MiB file");

    process_state_change_path(&mount, &local_path, &*backend)
        .await
        .expect("reconcile >5 MiB local write");

    let updated = backend.getattr(rec.inode).await.expect("getattr");
    assert_eq!(updated.size, large_len as u64);
    assert_eq!(updated.hydration, HydrationState::LocallyCached);

    let first_half = backend
        .read_range(rec.inode, 0, MAX_HYDRATION_STREAM_SLICE)
        .await
        .expect("read first chunk");
    let second_half = backend
        .read_range(
            rec.inode,
            MAX_HYDRATION_STREAM_SLICE as u64,
            large_len - MAX_HYDRATION_STREAM_SLICE,
        )
        .await
        .expect("read tail chunk");
    assert_eq!(first_half.as_ref(), &large_payload[..MAX_HYDRATION_STREAM_SLICE]);
    assert_eq!(second_half.as_ref(), &large_payload[MAX_HYDRATION_STREAM_SLICE..]);
}

#[tokio::test]
async fn windows_cf_drive_config_and_unmounted_lifecycle() {
    let bad_cfg = WindowsCfConfig {
        provider_name: "Bad!Name".to_owned(),
        ..Default::default()
    };
    assert!(bad_cfg.validate().is_err());

    let backend = Arc::new(MockVfsBackend::new());
    let rec = backend
        .seed_remote_file(ROOT_INODE, "hello.txt", b"hello-world")
        .await
        .expect("seed");
    let drive = WindowsCfDrive::new(Arc::clone(&backend) as Arc<dyn VfsBackend>);

    assert!(!drive.is_mounted());
    assert!(drive.mount_point().is_none());
    assert!(drive.connection_key().is_none());

    let root_id = drive.build_sync_root_id().expect("build SyncRootId");
    let (provider, sid, account) = root_id.to_components();
    assert_eq!(provider.to_string_lossy(), "Zerovault");
    assert!(!sid.is_empty());
    assert_eq!(account.to_string_lossy(), "default");

    let info_dir = TempDir::new().expect("tempdir for SyncRootInfo");
    let info = drive
        .build_sync_root_info(info_dir.path())
        .expect("build SyncRootInfo");
    assert!(info.allow_pinning());
    assert_eq!(
        info.hydration_type(),
        cloud_filter::root::HydrationType::Progressive
    );
    assert_eq!(
        info.population_type(),
        cloud_filter::root::PopulationType::Full
    );

    // Unmounted VirtualDrive methods delegate cleanly to VfsBackend
    drive.pin_path("/hello.txt").await.expect("pin_path");
    assert!(backend.getattr(rec.inode).await.expect("attr").pinned);
    assert!(matches!(
        drive.dehydrate_path("/hello.txt").await,
        Err(ZeroVaultError::PinnedDehydrationDenied(_))
    ));
    drive.notify_change("/hello.txt").await.expect("notify");
    let _stats = drive.stats().await.expect("stats");
    drive.unmount().await.expect("unmount idempotent");
}

#[tokio::test]
#[ignore = "requires live Windows Explorer / Shell SyncRoot registration context"]
async fn live_cfapi_sync_root_mount_and_unmount_integration() {
    let temp = TempDir::new().expect("tempdir");
    let backend = Arc::new(MockVfsBackend::new());
    backend
        .seed_remote_file(ROOT_INODE, "remote_doc.txt", b"live-cfapi-content")
        .await
        .expect("seed");

    let cfg = WindowsCfConfig {
        account_name: format!("test-{}", Uuid::new_v4().as_simple()),
        unregister_on_unmount: true,
        ..Default::default()
    };
    let drive = WindowsCfDrive::with_config(backend, cfg);

    drive.mount(temp.path().to_path_buf()).await.expect("mount");
    assert!(drive.is_mounted());
    assert!(drive.connection_key().is_some());

    let hydrated = tokio::fs::read(temp.path().join("remote_doc.txt"))
        .await
        .expect("read hydrated placeholder");
    assert_eq!(hydrated, b"live-cfapi-content");

    drive.unmount().await.expect("unmount");
    assert!(!drive.is_mounted());
}
