#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr};
use std::io;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use fuser::{Errno, FileType, INodeNo, MountOption, OpenFlags, RenameFlags, SessionACL, TimeOrNow};
use parking_lot::Mutex;
use tempfile::TempDir;
use uuid::Uuid;
use zerovault_types::mocks::MockVfsBackend;
use zerovault_types::{
    CreateEntrySpec, DriveStats, EntryKind, HydrationState, InodeId, InodeRecord,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, SetAttrSpec, VfsBackend, VirtualDrive, XATTR_ZEROVAULT_PIN,
    XATTR_ZEROVAULT_STATE, ZeroVaultError, ZeroVaultResult,
};
use zerovault_vfs::linux::{
    DirtyWriteBuffer, LinuxFuseDrive, LinuxFuseFilesystem, error_to_errno, inode_to_file_attr,
    paginate_readdir_entries, xattr_list_payload,
};

#[derive(Debug, Default)]
struct RecordedBackendCalls {
    reads: Vec<(InodeId, u64, usize)>,
    writes: Vec<(InodeId, u64, usize)>,
    flushes: Vec<InodeId>,
    fsyncs: Vec<(InodeId, bool)>,
}

struct SpyVfsBackend {
    inner: MockVfsBackend,
    calls: Mutex<RecordedBackendCalls>,
}

impl SpyVfsBackend {
    fn new() -> Self {
        Self {
            inner: MockVfsBackend::new(),
            calls: Mutex::new(RecordedBackendCalls::default()),
        }
    }

    fn take_calls(&self) -> RecordedBackendCalls {
        std::mem::take(&mut *self.calls.lock())
    }
}

#[async_trait]
impl VfsBackend for SpyVfsBackend {
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
        self.calls.lock().reads.push((inode, offset, len));
        self.inner.read_range(inode, offset, len).await
    }

    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize> {
        self.calls.lock().writes.push((inode, offset, data.len()));
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
        self.calls.lock().flushes.push(inode);
        self.inner.flush(inode).await
    }

    async fn fsync(&self, inode: InodeId, datasync: bool) -> ZeroVaultResult<()> {
        self.calls.lock().fsyncs.push((inode, datasync));
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

#[test]
fn error_to_errno_maps_all_domain_errors() {
    assert_eq!(
        error_to_errno(&ZeroVaultError::InodeNotFound(42)),
        Errno::ENOENT
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::InvalidPath("bad".into())),
        Errno::ENOENT
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::StorageNotFound("missing".into())),
        Errno::ENOENT
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::AlreadyExists("dup".into())),
        Errno::EEXIST
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::NotADirectory(7)),
        Errno::ENOTDIR
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::IsADirectory(8)),
        Errno::EISDIR
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::DirectoryNotEmpty(9)),
        Errno::ENOTEMPTY
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::PinnedDehydrationDenied(10)),
        Errno::EBUSY
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::CryptoTamperDetected("tag".into())),
        Errno::EIO
    );
    assert_eq!(error_to_errno(&ZeroVaultError::VaultLocked), Errno::EACCES);
    assert_eq!(
        error_to_errno(&ZeroVaultError::InvalidPassphrase),
        Errno::EACCES
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::InvalidRange {
            offset: 10,
            len: 5,
            size: 2,
        }),
        Errno::EINVAL
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::StorageQuotaExceeded("full".into())),
        Errno::ENOSPC
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::StorageConflict("etag".into())),
        Errno::EAGAIN
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::Io(io::Error::from_raw_os_error(libc::EPERM))),
        Errno::EPERM
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "gone"
        ))),
        Errno::ENOENT
    );
    assert_eq!(
        error_to_errno(&ZeroVaultError::VfsError("boom".into())),
        Errno::EIO
    );
}

#[test]
fn inode_record_to_file_attr_conversion() {
    let now = Utc::now();
    let file_rec = InodeRecord {
        inode: 42,
        parent_inode: ROOT_INODE,
        file_id: Uuid::new_v4(),
        name: "archive.bin".to_owned(),
        virtual_path: "/archive.bin".to_owned(),
        kind: EntryKind::File,
        size: 513,
        mode: 0o10_0640, // includes S_IFREG bits to verify masking to 0o7777
        hydration: HydrationState::OnlineOnly,
        pinned: false,
        version: 3,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };

    let attr = inode_to_file_attr(&file_rec, 1000, 1000);
    assert_eq!(attr.ino, INodeNo(42));
    assert_eq!(attr.size, 513);
    assert_eq!(attr.blocks, 2);
    assert_eq!(attr.blksize, 4096);
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.perm, 0o640);
    assert_eq!(attr.nlink, 1);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);

    let zero_file = InodeRecord {
        size: 0,
        ..file_rec.clone()
    };
    assert_eq!(inode_to_file_attr(&zero_file, 1000, 1000).blocks, 0);

    let dir_rec = InodeRecord {
        inode: 99,
        parent_inode: ROOT_INODE,
        file_id: Uuid::new_v4(),
        name: "docs".to_owned(),
        virtual_path: "/docs".to_owned(),
        kind: EntryKind::Directory,
        size: 0,
        mode: 0o755,
        hydration: HydrationState::Pinned,
        pinned: true,
        version: 1,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };
    let dir_attr = inode_to_file_attr(&dir_rec, 1000, 1000);
    assert_eq!(dir_attr.ino, INodeNo(99));
    assert_eq!(dir_attr.kind, FileType::Directory);
    assert_eq!(dir_attr.perm, 0o755);
    assert_eq!(dir_attr.nlink, 2);
    assert_eq!(dir_attr.blksize, 4096);
}

#[test]
fn readdir_pagination_emits_dot_dotdot_and_children_with_offsets() {
    let now = Utc::now();
    let dir = InodeRecord {
        inode: 10,
        parent_inode: ROOT_INODE,
        file_id: Uuid::new_v4(),
        name: "folder".to_owned(),
        virtual_path: "/folder".to_owned(),
        kind: EntryKind::Directory,
        size: 0,
        mode: 0o755,
        hydration: HydrationState::Pinned,
        pinned: true,
        version: 1,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };
    let child_a = InodeRecord {
        inode: 11,
        parent_inode: 10,
        file_id: Uuid::new_v4(),
        name: "alpha.txt".to_owned(),
        virtual_path: "/folder/alpha.txt".to_owned(),
        kind: EntryKind::File,
        size: 12,
        mode: 0o644,
        hydration: HydrationState::OnlineOnly,
        pinned: false,
        version: 1,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };
    let child_b = InodeRecord {
        inode: 12,
        parent_inode: 10,
        file_id: Uuid::new_v4(),
        name: "sub".to_owned(),
        virtual_path: "/folder/sub".to_owned(),
        kind: EntryKind::Directory,
        size: 0,
        mode: 0o755,
        hydration: HydrationState::Pinned,
        pinned: true,
        version: 1,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };

    let children = vec![child_a, child_b];

    let page0 = paginate_readdir_entries(&dir, &children, 0);
    assert_eq!(page0.len(), 4);
    assert_eq!(
        (&page0[0].name, page0[0].ino, page0[0].offset, page0[0].kind),
        (&".".to_owned(), INodeNo(10), 1, FileType::Directory)
    );
    assert_eq!(
        (&page0[1].name, page0[1].ino, page0[1].offset, page0[1].kind),
        (&"..".to_owned(), INodeNo(ROOT_INODE), 2, FileType::Directory)
    );
    assert_eq!(
        (&page0[2].name, page0[2].ino, page0[2].offset, page0[2].kind),
        (&"alpha.txt".to_owned(), INodeNo(11), 3, FileType::RegularFile)
    );
    assert_eq!(
        (&page0[3].name, page0[3].ino, page0[3].offset, page0[3].kind),
        (&"sub".to_owned(), INodeNo(12), 4, FileType::Directory)
    );

    let page_after_dotdot = paginate_readdir_entries(&dir, &children, 2);
    assert_eq!(page_after_dotdot.len(), 2);
    assert_eq!(page_after_dotdot[0].name, "alpha.txt");
    assert_eq!(page_after_dotdot[0].offset, 3);
    assert_eq!(page_after_dotdot[1].name, "sub");
    assert_eq!(page_after_dotdot[1].offset, 4);

    let page_last = paginate_readdir_entries(&dir, &children, 3);
    assert_eq!(page_last.len(), 1);
    assert_eq!(page_last[0].name, "sub");

    let page_eof = paginate_readdir_entries(&dir, &children, 4);
    assert!(page_eof.is_empty());

    let page_far = paginate_readdir_entries(&dir, &children, u64::MAX);
    assert!(page_far.is_empty());
}

#[test]
fn dirty_write_buffer_coalesces_and_auto_flushes_at_4mib_and_chunk_boundaries() {
    let mut buf = DirtyWriteBuffer::new();
    let mut flushes: Vec<(u64, Vec<u8>)> = Vec::new();

    // Coalesce contiguous writes strictly below 4 MiB without flushing.
    let part1 = vec![0xAA; 1_000_000];
    let n1 = buf
        .write_with(0, &part1, |off, slice| {
            flushes.push((off, slice.to_vec()));
            Ok(slice.len())
        })
        .expect("write part1");
    assert_eq!(n1, 1_000_000);
    assert_eq!(buf.len(), 1_000_000);
    assert!(flushes.is_empty());

    // Write remaining bytes to reach exact PLAINTEXT_CHUNK_SIZE (4 MiB).
    let remaining_to_4mib = PLAINTEXT_CHUNK_SIZE - 1_000_000;
    let part2 = vec![0xBB; remaining_to_4mib];
    let n2 = buf
        .write_with(1_000_000, &part2, |off, slice| {
            flushes.push((off, slice.to_vec()));
            Ok(slice.len())
        })
        .expect("write part2");
    assert_eq!(n2, remaining_to_4mib);
    assert_eq!(buf.len(), 0);
    assert_eq!(flushes.len(), 1);
    assert_eq!(flushes[0].0, 0);
    assert_eq!(flushes[0].1.len(), PLAINTEXT_CHUNK_SIZE);
    assert!(flushes[0].1[..1_000_000].iter().all(|&b| b == 0xAA));
    assert!(flushes[0].1[1_000_000..].iter().all(|&b| b == 0xBB));
    flushes.clear();

    // Start mid-chunk near chunk 1 boundary and cross chunk 1 -> chunk 2 boundary.
    let chunk1_end = (PLAINTEXT_CHUNK_SIZE as u64) * 2;
    let start = chunk1_end - 300;
    buf.write_with(start, &[0xCC; 100], |off, slice| {
        flushes.push((off, slice.to_vec()));
        Ok(slice.len())
    })
    .expect("pre-boundary write");
    assert_eq!(buf.len(), 100);
    assert!(flushes.is_empty());

    // 500 bytes starting at chunk1_end - 200 crosses boundary by 300 bytes.
    buf.write_with(start + 100, &[0xDD; 500], |off, slice| {
        flushes.push((off, slice.to_vec()));
        Ok(slice.len())
    })
    .expect("cross-boundary write");
    assert_eq!(flushes.len(), 1);
    assert_eq!(flushes[0].0, start);
    assert_eq!(flushes[0].1.len(), 300);
    assert_eq!(buf.start_offset(), Some(chunk1_end));
    assert_eq!(buf.len(), 300);
    flushes.clear();

    // Non-contiguous write flushes [chunk1_end, chunk1_end + 300) before buffering new offset.
    buf.write_with(128, &[0xEE; 64], |off, slice| {
        flushes.push((off, slice.to_vec()));
        Ok(slice.len())
    })
    .expect("non-contiguous write");
    assert_eq!(flushes.len(), 1);
    assert_eq!(flushes[0].0, chunk1_end);
    assert_eq!(flushes[0].1.len(), 300);
    assert_eq!(buf.start_offset(), Some(128));
    assert_eq!(buf.len(), 64);
    flushes.clear();

    // Large write > 2x 4 MiB flushes 4 MiB chunks directly without ever exceeding 4 MiB buffer.
    buf.flush_with(|off, slice| {
        flushes.push((off, slice.to_vec()));
        Ok(slice.len())
    })
    .expect("drain");
    flushes.clear();

    let big_len = PLAINTEXT_CHUNK_SIZE * 2 + 1024;
    let big = vec![0x55; big_len];
    let n_big = buf
        .write_with(0, &big, |off, slice| {
            assert!(slice.len() <= PLAINTEXT_CHUNK_SIZE);
            flushes.push((off, slice.to_vec()));
            Ok(slice.len())
        })
        .expect("big write");
    assert_eq!(n_big, big_len);
    assert_eq!(flushes.len(), 2);
    assert_eq!((flushes[0].0, flushes[0].1.len()), (0, PLAINTEXT_CHUNK_SIZE));
    assert_eq!(
        (flushes[1].0, flushes[1].1.len()),
        (PLAINTEXT_CHUNK_SIZE as u64, PLAINTEXT_CHUNK_SIZE)
    );
    assert_eq!(buf.start_offset(), Some((PLAINTEXT_CHUNK_SIZE * 2) as u64));
    assert_eq!(buf.len(), 1024);
}

#[tokio::test]
async fn filesystem_xattrs_pin_dehydrate_and_hydration_states() {
    let backend = Arc::new(MockVfsBackend::new());
    let rec = backend
        .seed_remote_file(ROOT_INODE, "notes.txt", b"hello-zerovault-xattr")
        .await
        .expect("seed");
    let fs = LinuxFuseFilesystem::new(backend.clone());

    assert_eq!(
        xattr_list_payload(),
        b"user.zerovault.state\0user.zerovault.pin\0"
    );
    assert_eq!(
        fs.handle_listxattr(rec.inode).expect("listxattr"),
        b"user.zerovault.state\0user.zerovault.pin\0"
    );
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("state"),
        HydrationState::OnlineOnly.as_xattr_str().as_bytes()
    );
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN))
            .expect("pin"),
        b"0"
    );
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new("user.unknown"))
            .unwrap_err(),
        Errno::ENODATA
    );

    // Partial read transitions OnlineOnly -> PartiallyHydrated.
    let slice = fs.handle_read(rec.inode, 6, 9).expect("partial read");
    assert_eq!(slice, b"zerovault");
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("state"),
        b"partially-hydrated"
    );

    // Pin via setxattr "1".
    fs.handle_setxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"1", 0, 0)
        .expect("pin via xattr");
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("state"),
        b"pinned"
    );
    assert_eq!(
        fs.handle_getxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN))
            .expect("pin"),
        b"1"
    );

    // Dehydrate while pinned must fail with EBUSY (PinnedDehydrationDenied).
    assert_eq!(
        fs.handle_setxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"0", 0, 0)
            .unwrap_err(),
        Errno::EBUSY
    );

    // Unpin in backend, verify dehydrate via setxattr "0" resets to online-only.
    let mut updated = backend.getattr(rec.inode).await.expect("getattr");
    updated.pinned = false;
    updated.hydration = HydrationState::LocallyCached;
    // Create a fresh unpinned file and test setxattr "0" -> online-only.
    let unpinned = backend
        .seed_remote_file(ROOT_INODE, "ephemeral.bin", b"cached-content")
        .await
        .expect("seed unpinned");
    let _ = fs.handle_read(unpinned.inode, 0, 6).expect("hydrate");
    assert_eq!(
        fs.handle_getxattr(unpinned.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("state"),
        b"partially-hydrated"
    );
    fs.handle_setxattr(unpinned.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"0", 0, 0)
        .expect("dehydrate via xattr");
    assert_eq!(
        fs.handle_getxattr(unpinned.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("state"),
        b"online-only"
    );

    // Validation errors on setxattr.
    assert_eq!(
        fs.handle_setxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"2", 0, 0)
            .unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        fs.handle_setxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"1", 0, 4)
            .unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        fs.handle_setxattr(
            rec.inode,
            OsStr::new(XATTR_ZEROVAULT_PIN),
            b"1",
            libc::XATTR_CREATE,
            0
        )
        .unwrap_err(),
        Errno::EEXIST
    );
    assert_eq!(
        fs.handle_setxattr(rec.inode, OsStr::new(XATTR_ZEROVAULT_STATE), b"x", 0, 0)
            .unwrap_err(),
        Errno::EACCES
    );
    assert_eq!(
        fs.handle_setxattr(rec.inode, OsStr::new("user.other"), b"x", 0, 0)
            .unwrap_err(),
        Errno::ENOTSUP
    );
}

#[tokio::test]
async fn filesystem_streaming_write_flush_release_and_bounded_read() {
    let backend = Arc::new(SpyVfsBackend::new());
    let fs = LinuxFuseFilesystem::new(backend.clone());

    let (attr, fh) = fs
        .handle_create(ROOT_INODE, OsStr::new("stream.bin"), 0o644, libc::O_RDWR)
        .expect("create");
    let ino = attr.ino.0;
    assert_eq!(fs.active_file_handle_count(), 1);

    // Buffered writes below 4 MiB remain in per-handle DirtyWriteBuffer.
    let w1 = fs
        .handle_write(ino, fh, 0, &[0x11; 4096])
        .expect("write 4 KiB");
    assert_eq!(w1, 4096);
    assert_eq!(fs.buffered_dirty_bytes(fh), 4096);
    assert!(backend.take_calls().writes.is_empty());

    // getattr sees buffered dirty extent and "dirty" xattr immediately without flushing.
    let mid_attr = fs.handle_getattr(ino).expect("getattr");
    assert_eq!(mid_attr.size, 4096);
    assert_eq!(
        fs.handle_getxattr(ino, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("dirty state"),
        b"dirty"
    );

    // Reaching 4 MiB auto-flushes exactly one 4 MiB chunk.
    let fill = vec![0x22; PLAINTEXT_CHUNK_SIZE - 4096];
    let w2 = fs
        .handle_write(ino, fh, 4096, &fill)
        .expect("write to 4 MiB");
    assert_eq!(w2 as usize, PLAINTEXT_CHUNK_SIZE - 4096);
    assert_eq!(fs.buffered_dirty_bytes(fh), 0);

    let calls = backend.take_calls();
    assert_eq!(calls.writes, vec![(ino, 0, PLAINTEXT_CHUNK_SIZE)]);

    // Write tail bytes into chunk 1 and release handle -> flushes remaining dirty bytes + backend.flush().
    let w3 = fs
        .handle_write(ino, fh, PLAINTEXT_CHUNK_SIZE as u64, b"tail-bytes")
        .expect("write tail");
    assert_eq!(w3, 10);
    assert_eq!(fs.buffered_dirty_bytes(fh), 10);

    fs.handle_release(ino, fh).expect("release");
    assert_eq!(fs.active_file_handle_count(), 0);
    assert_eq!(fs.buffered_dirty_bytes(fh), 0);

    let release_calls = backend.take_calls();
    assert_eq!(
        release_calls.writes,
        vec![(ino, PLAINTEXT_CHUNK_SIZE as u64, 10)]
    );
    assert_eq!(release_calls.flushes, vec![ino]);
    assert_eq!(
        fs.handle_getxattr(ino, OsStr::new(XATTR_ZEROVAULT_STATE))
            .expect("cached after flush"),
        b"cached"
    );

    // Bounded slice read on multi-chunk file only asks VfsBackend for requested range.
    let mut big_payload = vec![0u8; PLAINTEXT_CHUNK_SIZE * 2 + 1024];
    big_payload[PLAINTEXT_CHUNK_SIZE + 500..PLAINTEXT_CHUNK_SIZE + 512]
        .copy_from_slice(b"slice-marker");
    let big_file = backend
        .inner
        .seed_remote_file(ROOT_INODE, "huge.bin", &big_payload)
        .await
        .expect("seed huge");
    let _ = backend.take_calls();

    let got = fs
        .handle_read(big_file.inode, (PLAINTEXT_CHUNK_SIZE + 500) as u64, 12)
        .expect("read slice");
    assert_eq!(got, b"slice-marker");
    let read_calls = backend.take_calls();
    assert_eq!(
        read_calls.reads,
        vec![(big_file.inode, (PLAINTEXT_CHUNK_SIZE + 500) as u64, 12)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filesystem_cross_boundary_read_after_dirty_write_and_mt_handle() {
    let backend = Arc::new(SpyVfsBackend::new());
    let handle = tokio::runtime::Handle::current();
    let fs = LinuxFuseFilesystem::with_runtime_handle(backend.clone(), handle.clone());

    let (attr, fh) = fs
        .handle_create(ROOT_INODE, OsStr::new("cross.bin"), 0o644, libc::O_RDWR)
        .expect("create");
    let ino = attr.ino.0;

    // Write starting 100 bytes before the 4 MiB boundary and spanning 250 bytes into chunk 1.
    let start = (PLAINTEXT_CHUNK_SIZE as u64) - 100;
    let payload = vec![0x7A; 350];
    assert_eq!(fs.handle_write(ino, fh, start, &payload).expect("write"), 350);
    // First 100 bytes auto-flushed at chunk 0 boundary; 250 bytes stay buffered in chunk 1.
    assert_eq!(fs.buffered_dirty_bytes(fh), 250);
    let calls = backend.take_calls();
    assert_eq!(calls.writes, vec![(ino, start, 100)]);

    // Reading while dirty bytes are still buffered must flush remaining dirty bytes first.
    let read_back = fs
        .handle_read(ino, start, 350)
        .expect("read after dirty write");
    assert_eq!(read_back, payload);
    assert_eq!(fs.buffered_dirty_bytes(fh), 0);
    let calls_after_read = backend.take_calls();
    assert_eq!(
        calls_after_read.writes,
        vec![(ino, PLAINTEXT_CHUNK_SIZE as u64, 250)]
    );

    // Explicit flush propagates to VfsBackend::flush.
    fs.handle_write(ino, fh, 0, b"hdr").expect("write hdr");
    assert_eq!(fs.buffered_dirty_bytes(fh), 3);
    fs.handle_flush(ino, fh).expect("flush");
    assert_eq!(fs.buffered_dirty_bytes(fh), 0);
    let calls_after_flush = backend.take_calls();
    assert_eq!(calls_after_flush.writes, vec![(ino, 0, 3)]);
    assert_eq!(calls_after_flush.flushes, vec![ino]);

    // EFBIG guard when offset + len overflows u64.
    assert_eq!(
        fs.handle_write(ino, fh, u64::MAX - 2, b"abcd")
            .unwrap_err(),
        Errno::EFBIG
    );

    fs.handle_release(ino, fh).expect("release");

    // Verify LinuxFuseDrive::with_runtime_handle constructs cleanly on multi-thread runtime.
    let drive = LinuxFuseDrive::with_runtime_handle(backend, handle);
    assert!(!drive.is_mounted());
}

#[tokio::test]
async fn filesystem_crud_setattr_rename_and_readdir() {
    let backend = Arc::new(MockVfsBackend::new());
    let fs = LinuxFuseFilesystem::new(backend.clone());

    // mkdir & lookup
    let dir_attr = fs
        .handle_mkdir(ROOT_INODE, OsStr::new("projects"), 0o755)
        .expect("mkdir");
    assert_eq!(dir_attr.kind, FileType::Directory);
    let looked = fs
        .handle_lookup(ROOT_INODE, OsStr::new("projects"))
        .expect("lookup");
    assert_eq!(looked.ino, dir_attr.ino);

    // create + write + fsync + setattr (truncate, mode, mtime)
    let (file_attr, fh) = fs
        .handle_create(dir_attr.ino.0, OsStr::new("todo.txt"), 0o644, libc::O_RDWR)
        .expect("create");
    fs.handle_write(file_attr.ino.0, fh, 0, b"0123456789")
        .expect("write");
    fs.handle_fsync(file_attr.ino.0, fh, true).expect("fsync");
    fs.handle_release(file_attr.ino.0, fh).expect("release");

    let custom_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let updated = fs
        .handle_setattr(
            file_attr.ino.0,
            Some(0o10_0600),
            None,
            None,
            Some(4),
            Some(TimeOrNow::SpecificTime(custom_mtime)),
        )
        .expect("setattr");
    assert_eq!(updated.size, 4);
    assert_eq!(updated.perm, 0o600);
    assert_eq!(updated.mtime, custom_mtime);
    assert_eq!(
        fs.handle_read(file_attr.ino.0, 0, 16).expect("read truncated"),
        b"0123"
    );

    // open existing file + rename + RENAME_NOREPLACE / RENAME_EXCHANGE
    let fh2 = fs
        .handle_open(file_attr.ino.0, OpenFlags(libc::O_RDONLY))
        .expect("open");
    fs.handle_release(file_attr.ino.0, fh2).expect("release");

    assert_eq!(
        fs.handle_rename(
            dir_attr.ino.0,
            OsStr::new("todo.txt"),
            ROOT_INODE,
            OsStr::new("moved.txt"),
            RenameFlags::RENAME_EXCHANGE,
        )
        .unwrap_err(),
        Errno::EINVAL
    );

    fs.handle_rename(
        dir_attr.ino.0,
        OsStr::new("todo.txt"),
        ROOT_INODE,
        OsStr::new("moved.txt"),
        RenameFlags::RENAME_NOREPLACE,
    )
    .expect("rename");
    assert_eq!(
        fs.handle_rename(
            ROOT_INODE,
            OsStr::new("moved.txt"),
            ROOT_INODE,
            OsStr::new("moved.txt"),
            RenameFlags::RENAME_NOREPLACE,
        )
        .unwrap_err(),
        Errno::EEXIST
    );

    // readdir on root includes ., .., projects, moved.txt
    let entries = fs.handle_readdir(ROOT_INODE, 0).expect("readdir");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec![".", "..", "projects", "moved.txt"]);

    // rmdir non-empty vs empty, unlink
    let (tmp_attr, tmp_fh) = fs
        .handle_create(dir_attr.ino.0, OsStr::new("lock"), 0o644, libc::O_RDWR)
        .expect("create in dir");
    fs.handle_release(tmp_attr.ino.0, tmp_fh).expect("release");
    assert_eq!(
        fs.handle_rmdir(ROOT_INODE, OsStr::new("projects"))
            .unwrap_err(),
        Errno::ENOTEMPTY
    );
    fs.handle_unlink(dir_attr.ino.0, OsStr::new("lock"))
        .expect("unlink");
    fs.handle_rmdir(ROOT_INODE, OsStr::new("projects"))
        .expect("rmdir");

    let statfs = fs.handle_statfs();
    assert_eq!(statfs.bsize, 4096);
    assert_eq!(statfs.namelen, 255);
}

#[tokio::test]
async fn linux_fuse_drive_config_state_and_pin_dehydrate_without_dev_fuse() {
    let backend = Arc::new(MockVfsBackend::new());
    let rec = backend
        .seed_remote_file(ROOT_INODE, "budget.csv", b"month,amount\njan,100\n")
        .await
        .expect("seed");

    let drive = LinuxFuseDrive::new(backend.clone());
    assert!(!drive.is_mounted());
    assert!(drive.mount_point().is_none());
    let dbg = format!("{drive:?}");
    assert!(dbg.contains("LinuxFuseDrive"));
    assert!(!dbg.contains("budget.csv"));

    // Verify canonical unprivileged FUSE3 mount options.
    let opts = LinuxFuseDrive::mount_options();
    assert_eq!(
        opts,
        vec![
            MountOption::FSName("zerovault".to_owned()),
            MountOption::Subtype("zerovault".to_owned()),
            MountOption::NoAtime,
            MountOption::DefaultPermissions,
        ]
    );
    let cfg = LinuxFuseDrive::build_fuser_config();
    assert_eq!(cfg.mount_options, opts);
    assert_eq!(cfg.acl, SessionACL::Owner);

    // Pin / dehydrate / notify_change / stats work deterministically against MockVfsBackend.
    drive.pin_path("/budget.csv").await.expect("pin");
    assert!(backend.getattr(rec.inode).await.expect("attr").pinned);
    assert!(matches!(
        drive.dehydrate_path("/budget.csv").await,
        Err(ZeroVaultError::PinnedDehydrationDenied(_))
    ));

    drive
        .notify_change("/budget.csv")
        .await
        .expect("notify when unmounted is Ok");

    let stats = drive.stats().await.expect("stats");
    assert_eq!(stats.open_handles, 0);
    assert!(stats.bytes_read > 0);

    // Mounting to missing path fails cleanly; unmount is idempotent.
    let missing = std::path::PathBuf::from("/nonexistent-zerovault-mountpoint-test");
    assert!(drive.mount(missing).await.is_err());
    assert!(!drive.is_mounted());
    drive.unmount().await.expect("idempotent unmount");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires /dev/fuse and fusermount3 in Linux userspace"]
async fn live_fuse3_mount_roundtrip_integration() {
    let backend = Arc::new(MockVfsBackend::new());
    backend
        .seed_remote_file(ROOT_INODE, "hello.txt", b"hello from live fuse3")
        .await
        .expect("seed");

    let mount_dir = TempDir::new().expect("tempdir");
    let drive = LinuxFuseDrive::new(backend.clone());
    drive
        .mount(mount_dir.path().to_path_buf())
        .await
        .expect("fuse3 mount");
    assert!(drive.is_mounted());
    assert_eq!(drive.mount_point(), Some(mount_dir.path().to_path_buf()));

    let hello_path = mount_dir.path().join("hello.txt");
    let content = std::fs::read_to_string(&hello_path).expect("read mounted file");
    assert_eq!(content, "hello from live fuse3");

    let created_path = mount_dir.path().join("written.txt");
    std::fs::write(&created_path, b"live write payload").expect("write mounted file");
    assert_eq!(
        std::fs::read(&created_path).expect("read back"),
        b"live write payload"
    );

    // Verify xattr query via libc::getxattr.
    let c_path = CString::new(hello_path.to_str().expect("utf8")).expect("cstring");
    let c_key = CString::new(XATTR_ZEROVAULT_STATE).expect("cstring");
    let mut xbuf = [0u8; 64];
    let xlen = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_key.as_ptr(),
            xbuf.as_mut_ptr().cast::<libc::c_void>(),
            xbuf.len(),
        )
    };
    assert!(xlen > 0);

    drive.notify_change("/hello.txt").await.expect("notify");
    drive.unmount().await.expect("unmount");
    assert!(!drive.is_mounted());
}
