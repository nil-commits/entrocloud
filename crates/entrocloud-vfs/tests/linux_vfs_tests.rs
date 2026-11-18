//! Cross-platform unit, property-based (`proptest`), and Linux `fuser v0.18` handler tests
//! for the Wave 2 ZeroVault Linux FUSE3 + `xattr` virtual filesystem.
//!
//! Portable state-machine tests execute natively on **both** Windows and Linux; `fuser`
//! kernel-type adapter tests compile and run under `#[cfg(target_os = "linux")]`.

use std::io;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use parking_lot::Mutex;
use proptest::prelude::*;
use uuid::Uuid;
use entrocloud_types::mocks::MockVfsBackend;
use entrocloud_types::{
    CreateEntrySpec, DriveStats, EntryKind, HydrationState, InodeId, InodeRecord,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, SetAttrSpec, VfsBackend, XATTR_ZEROVAULT_FILE_ID,
    XATTR_ZEROVAULT_PIN, XATTR_ZEROVAULT_STATE, ZeroVaultError, ZeroVaultResult,
};
use entrocloud_vfs::linux::{
    DirtyWriteBuffer, LINUX_O_RDWR, PortableErrno, PortableFuseState, PortableMtime,
    PortableOpenFlags, PortableRenameFlags, XATTR_FLAG_CREATE, XATTR_FLAG_REPLACE,
    datetime_to_system_time, inode_to_portable_attr, paginate_portable_readdir,
    portable_error_to_errno, xattr_list_payload,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendOp {
    Read(InodeId, u64, usize),
    Write(InodeId, u64, usize),
    Flush(InodeId),
    Fsync(InodeId, bool),
    Pin(InodeId),
    Unpin(InodeId),
    Dehydrate(InodeId),
}

#[derive(Default)]
struct FaultConfig {
    fail_writes_after_calls: Option<(usize, ZeroVaultError)>,
    fail_next_flush: Option<ZeroVaultError>,
}

struct SpyFaultVfsBackend {
    inner: MockVfsBackend,
    ops: Mutex<Vec<BackendOp>>,
    faults: Mutex<FaultConfig>,
    write_call_count: Mutex<usize>,
}

impl SpyFaultVfsBackend {
    fn new() -> Self {
        Self {
            inner: MockVfsBackend::new(),
            ops: Mutex::new(Vec::new()),
            faults: Mutex::new(FaultConfig::default()),
            write_call_count: Mutex::new(0),
        }
    }

    fn take_ops(&self) -> Vec<BackendOp> {
        std::mem::take(&mut *self.ops.lock())
    }

    fn fail_writes_from_call(&self, call_idx: usize, err: ZeroVaultError) {
        *self.write_call_count.lock() = 0;
        self.faults.lock().fail_writes_after_calls = Some((call_idx, err));
    }

    fn clear_faults(&self) {
        let mut guard = self.faults.lock();
        guard.fail_writes_after_calls = None;
        guard.fail_next_flush = None;
    }

    fn fail_next_flush_with(&self, err: ZeroVaultError) {
        self.faults.lock().fail_next_flush = Some(err);
    }
}

fn clone_injected_error(err: &ZeroVaultError) -> ZeroVaultError {
    match err {
        ZeroVaultError::StorageQuotaExceeded(m) => ZeroVaultError::StorageQuotaExceeded(m.clone()),
        ZeroVaultError::StorageBackendError(m) => ZeroVaultError::StorageBackendError(m.clone()),
        ZeroVaultError::VaultLocked => ZeroVaultError::VaultLocked,
        other => ZeroVaultError::VfsError(other.to_string()),
    }
}

#[async_trait]
impl VfsBackend for SpyFaultVfsBackend {
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
        self.ops.lock().push(BackendOp::Read(inode, offset, len));
        self.inner.read_range(inode, offset, len).await
    }

    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize> {
        let cur_call = {
            let mut cnt = self.write_call_count.lock();
            let cur = *cnt;
            *cnt += 1;
            cur
        };
        if let Some((trigger_idx, ref err)) = self.faults.lock().fail_writes_after_calls
            && cur_call >= trigger_idx
        {
            return Err(clone_injected_error(err));
        }
        self.ops
            .lock()
            .push(BackendOp::Write(inode, offset, data.len()));
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
        if let Some(err) = self.faults.lock().fail_next_flush.take() {
            return Err(err);
        }
        self.ops.lock().push(BackendOp::Flush(inode));
        self.inner.flush(inode).await
    }

    async fn fsync(&self, inode: InodeId, datasync: bool) -> ZeroVaultResult<()> {
        self.ops.lock().push(BackendOp::Fsync(inode, datasync));
        self.inner.fsync(inode, datasync).await
    }

    async fn pin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ops.lock().push(BackendOp::Pin(inode));
        self.inner.pin(inode).await
    }

    async fn unpin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ops.lock().push(BackendOp::Unpin(inode));
        self.inner.unpin(inode).await
    }

    async fn dehydrate(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ops.lock().push(BackendOp::Dehydrate(inode));
        self.inner.dehydrate(inode).await
    }

    async fn get_xattr_state(&self, inode: InodeId) -> ZeroVaultResult<HydrationState> {
        self.inner.get_xattr_state(inode).await
    }

    async fn drive_stats(&self) -> ZeroVaultResult<DriveStats> {
        self.inner.drive_stats().await
    }
}

fn assert_spare_capacity_is_zeroed(buf: &DirtyWriteBuffer) {
    let (ptr, cap) = buf.raw_allocation_range();
    let len = buf.len();
    if cap > len {
        // Every byte in `len..cap` is initialized to 0 by `DirtyWriteBuffer`'s resize+zeroize
        // scrubbers before truncating/clearing.
        let spare = unsafe { std::slice::from_raw_parts(ptr.add(len), cap - len) };
        assert!(
            spare.iter().all(|&b| b == 0),
            "found non-zero residual plaintext byte in spare capacity (len={len}, cap={cap})"
        );
    }
}

#[test]
fn portable_error_to_errno_maps_all_domain_errors() {
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::InodeNotFound(42)),
        PortableErrno::Enoent
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::InvalidPath("bad".into())),
        PortableErrno::Enoent
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::StorageNotFound("missing".into())),
        PortableErrno::Enoent
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::AlreadyExists("dup".into())),
        PortableErrno::Eexist
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::NotADirectory(7)),
        PortableErrno::Enotdir
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::IsADirectory(8)),
        PortableErrno::Eisdir
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::DirectoryNotEmpty(9)),
        PortableErrno::Enotempty
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::PinnedDehydrationDenied(10)),
        PortableErrno::Ebusy
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::CryptoTamperDetected("tag".into())),
        PortableErrno::Eio
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::VaultLocked),
        PortableErrno::Eacces
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::InvalidPassphrase),
        PortableErrno::Eacces
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::UnauthorizedRecipient("revoked".into())),
        PortableErrno::Eacces
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::InvalidRange {
            offset: 10,
            len: 5,
            size: 2,
        }),
        PortableErrno::Einval
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::StorageQuotaExceeded("full".into())),
        PortableErrno::Enospc
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::StorageConflict("etag".into())),
        PortableErrno::Eagain
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "gone"
        ))),
        PortableErrno::Enoent
    );
    assert_eq!(
        portable_error_to_errno(&ZeroVaultError::VfsError("boom".into())),
        PortableErrno::Eio
    );

    for errno in [
        PortableErrno::Eperm,
        PortableErrno::Enoent,
        PortableErrno::Eio,
        PortableErrno::Ebadf,
        PortableErrno::Eagain,
        PortableErrno::Eacces,
        PortableErrno::Ebusy,
        PortableErrno::Eexist,
        PortableErrno::Enotdir,
        PortableErrno::Eisdir,
        PortableErrno::Einval,
        PortableErrno::Efbig,
        PortableErrno::Enospc,
        PortableErrno::Erange,
        PortableErrno::Enametoolong,
        PortableErrno::Enosys,
        PortableErrno::Enotempty,
        PortableErrno::Enodata,
        PortableErrno::Eoverflow,
        PortableErrno::Enotsup,
        PortableErrno::Etimedout,
    ] {
        assert_eq!(PortableErrno::from_code(errno.code()), errno);
    }
}

#[test]
fn portable_attr_and_readdir_pagination_invariants() {
    let pre_epoch = Utc.timestamp_opt(-10, 250_000_000).single().expect("ts");
    let expected_pre = UNIX_EPOCH - Duration::new(9, 750_000_000);
    assert_eq!(datetime_to_system_time(pre_epoch), expected_pre);

    let now = Utc::now();
    let file_rec = InodeRecord {
        inode: 42,
        parent_inode: ROOT_INODE,
        file_id: Uuid::new_v4(),
        name: "archive.bin".to_owned(),
        virtual_path: "/archive.bin".to_owned(),
        kind: EntryKind::File,
        size: 513,
        mode: 0o10_0640,
        hydration: HydrationState::OnlineOnly,
        pinned: false,
        version: 3,
        wrapped_dek: None,
        modified_at: now,
        created_at: now,
    };

    let attr = inode_to_portable_attr(&file_rec, 1000, 1000);
    assert_eq!(attr.ino, 42);
    assert_eq!(attr.size, 513);
    assert_eq!(attr.blocks, 2);
    assert_eq!(attr.blksize, 4096);
    assert_eq!(attr.kind, EntryKind::File);
    assert_eq!(attr.perm, 0o640);
    assert_eq!(attr.nlink, 1);

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
    let children = vec![file_rec];
    let page0 = paginate_portable_readdir(&dir, &children, 0);
    assert_eq!(page0.len(), 3);
    assert_eq!((&page0[0].name, page0[0].ino, page0[0].offset), (&".".to_owned(), 10, 1));
    assert_eq!(
        (&page0[1].name, page0[1].ino, page0[1].offset),
        (&"..".to_owned(), ROOT_INODE, 2)
    );
    assert_eq!(
        (&page0[2].name, page0[2].ino, page0[2].offset),
        (&"archive.bin".to_owned(), 42, 3)
    );
    assert!(paginate_portable_readdir(&dir, &children, 3).is_empty());
    assert!(paginate_portable_readdir(&dir, &children, u64::MAX).is_empty());
}

#[test]
fn dirty_write_buffer_coalesces_and_zeroizes_spare_capacity() {
    let mut buf = DirtyWriteBuffer::new();
    let mut flushes: Vec<(u64, Vec<u8>)> = Vec::new();

    // Coalesce contiguous writes below 4 MiB.
    let part1 = vec![0xAA; 1_000_000];
    let n1 = buf
        .write_with::<PortableErrno, _>(0, &part1, |off, slice| {
            flushes.push((off, slice.to_vec()));
            Ok(slice.len())
        })
        .expect("write part1");
    assert_eq!(n1, 1_000_000);
    assert_eq!(buf.len(), 1_000_000);
    assert!(flushes.is_empty());

    // Reach exact 4 MiB boundary -> auto-flush AND zeroize entire 4 MiB spare capacity!
    let remaining_to_4mib = PLAINTEXT_CHUNK_SIZE - 1_000_000;
    let part2 = vec![0xBB; remaining_to_4mib];
    let n2 = buf
        .write_with::<PortableErrno, _>(1_000_000, &part2, |off, slice| {
            flushes.push((off, slice.to_vec()));
            Ok(slice.len())
        })
        .expect("write part2");
    assert_eq!(n2, remaining_to_4mib);
    assert!(buf.is_empty());
    assert_eq!(buf.capacity(), PLAINTEXT_CHUNK_SIZE);
    assert_spare_capacity_is_zeroed(&buf);
    assert_eq!(flushes.len(), 1);
    assert_eq!(flushes[0].0, 0);
    assert_eq!(flushes[0].1.len(), PLAINTEXT_CHUNK_SIZE);
    flushes.clear();

    // Error rollback during boundary-crossing write must also scrub rolled-back spare capacity.
    let boundary = PLAINTEXT_CHUNK_SIZE as u64;
    buf.write_with::<PortableErrno, _>(boundary - 128, &[0xCC; 64], |_, _| Ok(64))
        .expect("seed 64B");
    assert_eq!(buf.len(), 64);
    let err = buf
        .write_with::<PortableErrno, _>(boundary - 64, &[0xDD; 64], |_, _| {
            Err(PortableErrno::Enospc)
        })
        .expect_err("simulated ENOSPC");
    assert_eq!(err, PortableErrno::Enospc);
    assert_eq!(buf.len(), 64);
    assert_spare_capacity_is_zeroed(&buf);

    // Partial drain on short write must scrub shifted tail bytes in spare capacity.
    let short_err = buf
        .flush_with::<PortableErrno, _>(|_off, _slice| Ok(24))
        .expect_err("short flush");
    assert_eq!(short_err, PortableErrno::Eio);
    assert_eq!(buf.len(), 40);
    assert_spare_capacity_is_zeroed(&buf);

    // Complete flush clears and zeroizes 0..capacity.
    buf.flush_with::<PortableErrno, _>(|off, slice| {
        flushes.push((off, slice.to_vec()));
        Ok(slice.len())
    })
    .expect("drain remaining");
    assert!(buf.is_empty());
    assert_spare_capacity_is_zeroed(&buf);
}

#[tokio::test]
async fn portable_xattr_engine_pin_unpin_dehydrate_and_file_id() {
    let backend = Arc::new(SpyFaultVfsBackend::new());
    let rec = backend
        .inner
        .seed_remote_file(ROOT_INODE, "notes.txt", b"hello-zerovault-xattr")
        .await
        .expect("seed");
    let state = PortableFuseState::new(backend.clone(), 1000, 1000);

    let expected_list = b"user.zerovault.state\0user.zerovault.pin\0user.zerovault.file_id\0";
    assert_eq!(xattr_list_payload(), expected_list);
    assert_eq!(state.listxattr(rec.inode).await.expect("list"), expected_list);
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_FILE_ID)
            .await
            .expect("file_id"),
        rec.file_id.to_string().into_bytes()
    );
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_STATE)
            .await
            .expect("state"),
        b"online-only"
    );
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_PIN)
            .await
            .expect("pin"),
        b"0"
    );

    // Partial read transitions OnlineOnly -> PartiallyHydrated.
    let slice = state.read(rec.inode, 6, 9).await.expect("partial read");
    assert_eq!(slice, b"zerovault");
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_STATE)
            .await
            .expect("state"),
        b"partially-hydrated"
    );

    // Pin via setxattr "1".
    let _ = backend.take_ops();
    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"1", 0, 0)
        .await
        .expect("pin via xattr");
    assert_eq!(backend.take_ops(), vec![BackendOp::Pin(rec.inode)]);
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_STATE)
            .await
            .expect("state"),
        b"pinned"
    );
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_PIN)
            .await
            .expect("pin"),
        b"1"
    );

    // Fix NEW-H02 / VFS-2: Setting pin="0" on a pinned file MUST call unpin(ino) BEFORE
    // dehydrate(ino) and succeed cleanly without EBUSY!
    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"0", XATTR_FLAG_REPLACE, 0)
        .await
        .expect("unpin + dehydrate via setxattr 0");
    assert_eq!(
        backend.take_ops(),
        vec![BackendOp::Unpin(rec.inode), BackendOp::Dehydrate(rec.inode)]
    );
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_STATE)
            .await
            .expect("state"),
        b"online-only"
    );
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_PIN)
            .await
            .expect("pin"),
        b"0"
    );

    // Verify "true"/"false" and "pin"/"unpin" aliases as well.
    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"true", 0, 0)
        .await
        .expect("pin=true");
    assert_eq!(
        state.getxattr(rec.inode, XATTR_ZEROVAULT_PIN).await.expect("pin"),
        b"1"
    );
    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"false", 0, 0)
        .await
        .expect("pin=false");
    assert_eq!(
        state.getxattr(rec.inode, XATTR_ZEROVAULT_PIN).await.expect("pin"),
        b"0"
    );

    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"pin", 0, 0)
        .await
        .expect("pin=pin");
    state
        .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"unpin", 0, 0)
        .await
        .expect("pin=unpin");
    assert_eq!(
        state
            .getxattr(rec.inode, XATTR_ZEROVAULT_STATE)
            .await
            .expect("state"),
        b"online-only"
    );

    // Validation guards.
    assert_eq!(
        state
            .setxattr(rec.inode, XATTR_ZEROVAULT_PIN, b"1", XATTR_FLAG_CREATE, 0)
            .await
            .expect_err("XATTR_CREATE"),
        PortableErrno::Eexist
    );
    assert_eq!(
        state
            .setxattr(rec.inode, XATTR_ZEROVAULT_STATE, b"cached", 0, 0)
            .await
            .expect_err("read-only state"),
        PortableErrno::Eacces
    );
    assert_eq!(
        state
            .setxattr(rec.inode, XATTR_ZEROVAULT_FILE_ID, b"0000", 0, 0)
            .await
            .expect_err("read-only file_id"),
        PortableErrno::Eacces
    );
    assert_eq!(
        state
            .setxattr(rec.inode, "user.other", b"1", 0, 0)
            .await
            .expect_err("unsupported xattr"),
        PortableErrno::Enotsup
    );
    assert_eq!(
        state
            .removexattr(rec.inode, XATTR_ZEROVAULT_PIN)
            .await
            .expect_err("removexattr"),
        PortableErrno::Eperm
    );
}

#[tokio::test]
async fn case_sensitive_posix_siblings_and_overwrite_rename() {
    let backend = Arc::new(MockVfsBackend::new());
    let state = PortableFuseState::new(backend, 1000, 1000);

    // CloudBridge CB-03 fix: case-distinct siblings Makefile & makefile coexist cleanly.
    let (upper_attr, upper_fh) = state
        .create(ROOT_INODE, "Makefile", 0o644, LINUX_O_RDWR)
        .await
        .expect("create Makefile");
    let (lower_attr, lower_fh) = state
        .create(ROOT_INODE, "makefile", 0o644, LINUX_O_RDWR)
        .await
        .expect("create makefile");
    assert_ne!(upper_attr.ino, lower_attr.ino);

    state
        .write(upper_attr.ino, upper_fh, 0, b"all:\n\tcargo build\n")
        .await
        .expect("write Makefile");
    state
        .write(lower_attr.ino, lower_fh, 0, b"clean:\n\trm -rf out\n")
        .await
        .expect("write makefile");
    state.release(upper_attr.ino, upper_fh).await.expect("rel1");
    state.release(lower_attr.ino, lower_fh).await.expect("rel2");

    assert_eq!(
        state.lookup(ROOT_INODE, "Makefile").await.expect("lookup upper").ino,
        upper_attr.ino
    );
    assert_eq!(
        state.lookup(ROOT_INODE, "makefile").await.expect("lookup lower").ino,
        lower_attr.ino
    );
    assert_eq!(
        state.read(upper_attr.ino, 0, 64).await.expect("read upper"),
        b"all:\n\tcargo build\n"
    );
    assert_eq!(
        state.read(lower_attr.ino, 0, 64).await.expect("read lower"),
        b"clean:\n\trm -rf out\n"
    );

    // Linux allows Windows-reserved stems like CON.txt while still blocking traversal & ADS.
    let (con_attr, con_fh) = state
        .create(ROOT_INODE, "CON.txt", 0o644, LINUX_O_RDWR)
        .await
        .expect("CON.txt valid on Linux POSIX");
    state.release(con_attr.ino, con_fh).await.expect("rel con");
    assert_eq!(
        state
            .create(ROOT_INODE, "../escape", 0o644, LINUX_O_RDWR)
            .await
            .expect_err("traversal"),
        PortableErrno::Einval
    );
    assert_eq!(
        state
            .create(ROOT_INODE, "ntfs:ads", 0o644, LINUX_O_RDWR)
            .await
            .expect_err("ads"),
        PortableErrno::Einval
    );
    let overlong = "x".repeat(256);
    assert_eq!(
        state
            .create(ROOT_INODE, &overlong, 0o644, LINUX_O_RDWR)
            .await
            .expect_err("enametoolong"),
        PortableErrno::Enametoolong
    );

    // Atomic POSIX save-via-rename over Makefile preserves lowercase sibling `makefile`.
    let (tmp_attr, tmp_fh) = state
        .create(ROOT_INODE, ".Makefile.tmp", 0o644, LINUX_O_RDWR)
        .await
        .expect("create tmp");
    state
        .write(tmp_attr.ino, tmp_fh, 0, b"all:\n\tcargo test --locked\n")
        .await
        .expect("write tmp");
    state.release(tmp_attr.ino, tmp_fh).await.expect("rel tmp");

    assert_eq!(
        state
            .rename(
                ROOT_INODE,
                ".Makefile.tmp",
                ROOT_INODE,
                "Makefile",
                PortableRenameFlags::NOREPLACE,
            )
            .await
            .expect_err("noreplace"),
        PortableErrno::Eexist
    );
    state
        .rename(
            ROOT_INODE,
            ".Makefile.tmp",
            ROOT_INODE,
            "Makefile",
            PortableRenameFlags::NONE,
        )
        .await
        .expect("overwrite Makefile");

    let replaced = state.lookup(ROOT_INODE, "Makefile").await.expect("lookup replaced");
    assert_eq!(replaced.ino, tmp_attr.ino);
    assert_eq!(
        state.read(replaced.ino, 0, 64).await.expect("read replaced"),
        b"all:\n\tcargo test --locked\n"
    );
    assert_eq!(
        state.read(lower_attr.ino, 0, 64).await.expect("lowercase intact"),
        b"clean:\n\trm -rf out\n"
    );

    let names: Vec<String> = state
        .readdir(ROOT_INODE, 0)
        .await
        .expect("readdir")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec![".", "..", "makefile", "CON.txt", "Makefile"]);

    // Verify setattr + open(O_TRUNC) + mkdir/rmdir/unlink.
    let dir_attr = state.mkdir(ROOT_INODE, "build", 0o755).await.expect("mkdir");
    let custom_mtime = UNIX_EPOCH + Duration::from_secs(1_720_000_000);
    let sattr = state
        .setattr(
            replaced.ino,
            Some(0o10_0600),
            None,
            None,
            Some(4),
            Some(PortableMtime::Specific(custom_mtime)),
        )
        .await
        .expect("setattr");
    assert_eq!(sattr.size, 4);
    assert_eq!(sattr.perm, 0o600);
    assert_eq!(sattr.mtime, custom_mtime);

    let trunc_fh = state
        .open(replaced.ino, PortableOpenFlags::read_write_truncate())
        .await
        .expect("open trunc");
    assert_eq!(state.getattr(replaced.ino).await.expect("getattr").size, 0);
    state.release(replaced.ino, trunc_fh).await.expect("rel trunc");

    state.rmdir(ROOT_INODE, "build").await.expect("rmdir");
    assert!(state.lookup(ROOT_INODE, "build").await.is_err());
    let _ = dir_attr;
}

#[tokio::test]
async fn handle_background_flush_error_latching_reports_on_close_and_release() {
    let backend = Arc::new(SpyFaultVfsBackend::new());
    let state = PortableFuseState::new(backend.clone(), 1000, 1000);

    // Sub-test A: Background flush fails with ENOSPC -> latched on fh -> reported on flush & release!
    let (attr1, fh1) = state
        .create(ROOT_INODE, "quota_victim.bin", 0o644, LINUX_O_RDWR)
        .await
        .expect("create 1");
    state
        .write(attr1.ino, fh1, 0, &[0x41; 65_536])
        .await
        .expect("buffered write");
    assert_eq!(state.buffered_dirty_bytes(fh1), 65_536);

    backend.fail_writes_from_call(0, ZeroVaultError::StorageQuotaExceeded("pool-0".into()));
    assert_eq!(
        state
            .flush_handle_background(fh1)
            .await
            .expect_err("bg flush fails"),
        PortableErrno::Enospc
    );
    assert_eq!(state.peek_latched_error(fh1), Some(PortableErrno::Enospc));

    // Even if storage recovers before close(2), the latched background error is still surfaced!
    backend.clear_faults();
    assert_eq!(
        state
            .flush(attr1.ino, fh1)
            .await
            .expect_err("POSIX close(2) flush reports latched ENOSPC"),
        PortableErrno::Enospc
    );
    assert_eq!(
        state
            .release(attr1.ino, fh1)
            .await
            .expect_err("release also reports latched ENOSPC"),
        PortableErrno::Enospc
    );
    assert_eq!(state.active_file_handle_count(), 0);

    // Sub-test B: Multi-chunk write succeeds on chunk 0 (4 MiB) and fails on chunk 1 ->
    // returns POSIX short write (4 MiB) and latches ENOSPC for close(2)!
    let (attr2, fh2) = state
        .create(ROOT_INODE, "partial_stream.bin", 0o644, LINUX_O_RDWR)
        .await
        .expect("create 2");
    backend.fail_writes_from_call(1, ZeroVaultError::StorageQuotaExceeded("pool-1".into()));
    let two_chunks = vec![0x5A; PLAINTEXT_CHUNK_SIZE * 2];
    let short_written = state
        .write(attr2.ino, fh2, 0, &two_chunks)
        .await
        .expect("first chunk accepted as POSIX short write");
    assert_eq!(short_written as usize, PLAINTEXT_CHUNK_SIZE);
    assert_eq!(state.peek_latched_error(fh2), Some(PortableErrno::Enospc));

    backend.clear_faults();
    assert_eq!(
        state.flush(attr2.ino, fh2).await.expect_err("latched short-write error"),
        PortableErrno::Enospc
    );
    assert_eq!(
        state.release(attr2.ino, fh2).await.expect_err("release latched"),
        PortableErrno::Enospc
    );
    assert_eq!(state.active_file_handle_count(), 0);

    // Sub-test C: Backend flush failure during background inode flush latches onto open handle.
    let (attr3, fh3) = state
        .create(ROOT_INODE, "manifest_fail.bin", 0o644, LINUX_O_RDWR)
        .await
        .expect("create 3");
    state
        .write(attr3.ino, fh3, 0, b"important-bytes")
        .await
        .expect("write");
    backend.fail_next_flush_with(ZeroVaultError::StorageBackendError("503 unavailable".into()));
    assert_eq!(
        state
            .flush_inode_background(attr3.ino)
            .await
            .expect_err("bg inode flush fails"),
        PortableErrno::Eio
    );
    assert_eq!(
        state.flush(attr3.ino, fh3).await.expect_err("close reports EIO"),
        PortableErrno::Eio
    );
    let _ = state.release(attr3.ino, fh3).await;
    assert_eq!(state.active_file_handle_count(), 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_dirty_write_buffer_coalescing_matches_oracle_and_zeroizes(
        ops in prop::collection::vec(
            (0u64..(PLAINTEXT_CHUNK_SIZE as u64 * 3), 0usize..600_000usize, any::<u8>()),
            1..24
        )
    ) {
        let mut buf = DirtyWriteBuffer::new();
        let mut disk: Vec<u8> = Vec::new();
        let mut oracle: Vec<u8> = Vec::new();

        for (offset, len, fill_byte) in ops {
            let payload = vec![fill_byte; len];
            if len > 0 {
                let end = (offset as usize) + len;
                if oracle.len() < end {
                    oracle.resize(end, 0);
                }
                oracle[offset as usize..end].copy_from_slice(&payload);
            }

            let written = buf
                .write_with::<PortableErrno, _>(offset, &payload, |flush_off, slice| {
                    assert!(slice.len() <= PLAINTEXT_CHUNK_SIZE);
                    if !slice.is_empty() {
                        let start_chunk = flush_off / (PLAINTEXT_CHUNK_SIZE as u64);
                        let end_chunk =
                            (flush_off + (slice.len() as u64) - 1) / (PLAINTEXT_CHUNK_SIZE as u64);
                        assert_eq!(start_chunk, end_chunk);
                    }
                    let end = (flush_off as usize) + slice.len();
                    if disk.len() < end {
                        disk.resize(end, 0);
                    }
                    disk[flush_off as usize..end].copy_from_slice(slice);
                    Ok(slice.len())
                })
                .expect("infallible flush");
            prop_assert_eq!(written, len);
            prop_assert!(buf.len() < PLAINTEXT_CHUNK_SIZE);
        }

        buf.flush_with::<PortableErrno, _>(|flush_off, slice| {
            assert!(slice.len() <= PLAINTEXT_CHUNK_SIZE);
            let end = (flush_off as usize) + slice.len();
            if disk.len() < end {
                disk.resize(end, 0);
            }
            disk[flush_off as usize..end].copy_from_slice(slice);
            Ok(slice.len())
        })
        .expect("final flush");

        prop_assert_eq!(disk, oracle);
        prop_assert!(buf.is_empty());
        assert_spare_capacity_is_zeroed(&buf);
    }

    #[test]
    fn prop_pin_unpin_dehydrate_xattr_sequences_never_deadlock_or_ebusy(
        actions in prop::collection::vec(0u8..6u8, 1..30)
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let backend = Arc::new(MockVfsBackend::new());
            let seeded = backend
                .seed_remote_file(ROOT_INODE, "prop.bin", b"property-based-payload")
                .await
                .expect("seed");
            let state = PortableFuseState::new(backend, 1000, 1000);

            for act in actions {
                let (val, expect_pinned): (&[u8], bool) = match act {
                    0 => (b"1", true),
                    1 => (b"true", true),
                    2 => (b"pin", true),
                    3 => (b"0", false),
                    4 => (b"false", false),
                    _ => (b"unpin", false),
                };
                state
                    .setxattr(seeded.inode, XATTR_ZEROVAULT_PIN, val, 0, 0)
                    .await
                    .expect("setxattr transition must succeed");
                let pin_bytes = state
                    .getxattr(seeded.inode, XATTR_ZEROVAULT_PIN)
                    .await
                    .expect("get pin");
                let state_bytes = state
                    .getxattr(seeded.inode, XATTR_ZEROVAULT_STATE)
                    .await
                    .expect("get state");
                if expect_pinned {
                    assert_eq!(pin_bytes, b"1");
                    assert_eq!(state_bytes, b"pinned");
                } else {
                    assert_eq!(pin_bytes, b"0");
                    assert_eq!(state_bytes, b"online-only");
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
mod linux_fuser_tests {
    use std::ffi::{CString, OsStr};
    use std::sync::Arc;

    use chrono::Utc;
    use fuser::{Errno, FileType, INodeNo, MountOption, OpenFlags, RenameFlags, SessionACL};
    use tempfile::TempDir;
    use uuid::Uuid;
    use entrocloud_types::mocks::MockVfsBackend;
    use entrocloud_types::{
        EntryKind, HydrationState, InodeRecord, PLAINTEXT_CHUNK_SIZE, ROOT_INODE, VirtualDrive,
        XATTR_ZEROVAULT_FILE_ID, XATTR_ZEROVAULT_PIN, XATTR_ZEROVAULT_STATE, ZeroVaultError,
    };
    use entrocloud_vfs::linux::{
        LinuxFuseDrive, ZeroVaultFuseFs, error_to_errno, inode_to_file_attr,
        paginate_readdir_entries,
    };

    #[test]
    fn linux_error_to_errno_and_file_attr_mapping() {
        assert_eq!(
            error_to_errno(&ZeroVaultError::InodeNotFound(9)),
            Errno::ENOENT
        );
        assert_eq!(
            error_to_errno(&ZeroVaultError::PinnedDehydrationDenied(9)),
            Errno::EBUSY
        );
        assert_eq!(
            error_to_errno(&ZeroVaultError::StorageQuotaExceeded("q".into())),
            Errno::ENOSPC
        );
        assert_eq!(
            error_to_errno(&ZeroVaultError::UnauthorizedRecipient("r".into())),
            Errno::EACCES
        );

        let now = Utc::now();
        let rec = InodeRecord {
            inode: 77,
            parent_inode: ROOT_INODE,
            file_id: Uuid::new_v4(),
            name: "Makefile".to_owned(),
            virtual_path: "/Makefile".to_owned(),
            kind: EntryKind::File,
            size: 1024,
            mode: 0o10_0644,
            hydration: HydrationState::LocallyCached,
            pinned: false,
            version: 1,
            wrapped_dek: None,
            modified_at: now,
            created_at: now,
        };
        let attr = inode_to_file_attr(&rec, 1000, 1000);
        assert_eq!(attr.ino, INodeNo(77));
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.blocks, 2);

        let dir_rec = InodeRecord {
            inode: ROOT_INODE,
            kind: EntryKind::Directory,
            mode: 0o755,
            ..rec.clone()
        };
        let entries = paginate_readdir_entries(&dir_rec, &[rec], 0);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "Makefile");
    }

    #[tokio::test]
    async fn zerovault_fuse_fs_single_thread_xattr_siblings_and_latched_close() {
        let backend = Arc::new(MockVfsBackend::new());
        let seeded = backend
            .seed_remote_file(ROOT_INODE, "doc.pdf", b"zerovault-linux-fuse")
            .await
            .expect("seed");
        let fs = ZeroVaultFuseFs::new(backend.clone());

        // Verify all 3 xattrs including file_id and pin="1" -> pin="0" unpin+dehydrate!
        assert_eq!(
            fs.handle_listxattr(seeded.inode).expect("listxattr"),
            b"user.zerovault.state\0user.zerovault.pin\0user.zerovault.file_id\0"
        );
        assert_eq!(
            fs.handle_getxattr(seeded.inode, OsStr::new(XATTR_ZEROVAULT_FILE_ID))
                .expect("file_id"),
            seeded.file_id.to_string().into_bytes()
        );
        fs.handle_setxattr(seeded.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"1", 0, 0)
            .expect("pin=1");
        assert_eq!(
            fs.handle_getxattr(seeded.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
                .expect("state"),
            b"pinned"
        );
        fs.handle_setxattr(seeded.inode, OsStr::new(XATTR_ZEROVAULT_PIN), b"0", 0, 0)
            .expect("pin=0 unpins then dehydrates");
        assert_eq!(
            fs.handle_getxattr(seeded.inode, OsStr::new(XATTR_ZEROVAULT_STATE))
                .expect("state"),
            b"online-only"
        );

        // Case-sensitive siblings + handle error latching on close.
        let (a1, fh1) = fs
            .handle_create(ROOT_INODE, OsStr::new("Makefile"), 0o644, libc::O_RDWR)
            .expect("Makefile");
        let (a2, fh2) = fs
            .handle_create(ROOT_INODE, OsStr::new("makefile"), 0o644, libc::O_RDWR)
            .expect("makefile");
        assert_ne!(a1.ino, a2.ino);
        fs.handle_write(a1.ino.0, fh1, 0, b"UPPER").expect("w1");
        fs.handle_write(a2.ino.0, fh2, 0, b"lower").expect("w2");
        assert!(fs.latch_handle_error(fh1, Errno::ENOSPC));
        assert_eq!(fs.handle_flush(a1.ino.0, fh1), Err(Errno::ENOSPC));
        assert_eq!(fs.handle_release(a1.ino.0, fh1), Err(Errno::ENOSPC));
        fs.handle_release(a2.ino.0, fh2).expect("rel2");
        assert_eq!(fs.active_file_handle_count(), 0);

        let open_fh = fs
            .handle_open(a2.ino.0, OpenFlags(libc::O_RDONLY))
            .expect("open");
        assert_eq!(fs.handle_read(a2.ino.0, 0, 16).expect("read"), b"lower");
        fs.handle_release(a2.ino.0, open_fh).expect("rel open");

        assert_eq!(
            fs.handle_rename(
                ROOT_INODE,
                OsStr::new("makefile"),
                ROOT_INODE,
                OsStr::new("Makefile"),
                RenameFlags::RENAME_NOREPLACE
            ),
            Err(Errno::EEXIST)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zerovault_fuse_fs_multi_thread_streaming_and_drive_unpin_path() {
        let backend = Arc::new(MockVfsBackend::new());
        let handle = tokio::runtime::Handle::current();
        let fs = ZeroVaultFuseFs::with_runtime_handle(backend.clone(), handle.clone());

        let (attr, fh) = fs
            .handle_create(ROOT_INODE, OsStr::new("big.bin"), 0o644, libc::O_RDWR)
            .expect("create");
        let payload = vec![0x3C; PLAINTEXT_CHUNK_SIZE + 512];
        assert_eq!(
            fs.handle_write(attr.ino.0, fh, 0, &payload).expect("write") as usize,
            payload.len()
        );
        assert_eq!(fs.buffered_dirty_bytes(fh), 512);
        fs.handle_fsync(attr.ino.0, fh, true).expect("fsync");
        assert_eq!(fs.buffered_dirty_bytes(fh), 0);
        fs.handle_release(attr.ino.0, fh).expect("release");

        // Verify LinuxFuseDrive options, SessionACL::Owner, and VirtualDrive::unpin_path!
        let opts = LinuxFuseDrive::mount_options();
        assert_eq!(
            opts,
            vec![
                MountOption::FSName("zerovault".to_owned()),
                MountOption::Subtype("zerovault".to_owned()),
                MountOption::NoAtime,
                MountOption::DefaultPermissions,
                MountOption::AutoUnmount,
            ]
        );
        let owner_cfg = LinuxFuseDrive::build_fuser_config();
        assert_eq!(owner_cfg.acl, SessionACL::Owner);
        let auto_cfg = LinuxFuseDrive::build_auto_unmount_config();
        assert!(auto_cfg.mount_options.contains(&MountOption::AutoUnmount));

        let drive = LinuxFuseDrive::with_runtime_handle(backend.clone(), handle);
        drive.pin_path("/big.bin").await.expect("pin_path");
        assert!(matches!(
            drive.dehydrate_path("/big.bin").await,
            Err(ZeroVaultError::PinnedDehydrationDenied(_))
        ));
        drive.unpin_path("/big.bin").await.expect("unpin_path");
        drive
            .dehydrate_path("/big.bin")
            .await
            .expect("dehydrate_path after unpin_path");

        let missing = std::path::PathBuf::from("/nonexistent-zerovault-mountpoint-test");
        assert!(drive.mount(missing).await.is_err());
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
        let drive = LinuxFuseDrive::new(backend);
        drive
            .mount(mount_dir.path().to_path_buf())
            .await
            .expect("fuse3 mount");
        assert!(drive.is_mounted());

        let hello_path = mount_dir.path().join("hello.txt");
        assert_eq!(
            std::fs::read_to_string(&hello_path).expect("read"),
            "hello from live fuse3"
        );

        let c_path = CString::new(hello_path.to_str().expect("utf8")).expect("cstring");
        let c_key = CString::new(XATTR_ZEROVAULT_FILE_ID).expect("cstring");
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

        drive.pin_path("/hello.txt").await.expect("pin");
        drive.unpin_path("/hello.txt").await.expect("unpin");
        drive.dehydrate_path("/hello.txt").await.expect("dehydrate");
        drive.unmount().await.expect("unmount");
    }
}
