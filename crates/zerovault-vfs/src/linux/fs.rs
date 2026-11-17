//! FUSE3 (`fuser::Filesystem`) implementation bridging kernel VFS requests to [`VfsBackend`].

use std::ffi::OsStr;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use parking_lot::Mutex;
use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};
use zerovault_types::{
    CreateEntrySpec, EntryKind, HydrationState, InodeId, InodeRecord, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, SetAttrSpec, VfsBackend, XATTR_ZEROVAULT_PIN, XATTR_ZEROVAULT_STATE, ZeroVaultError,
};

const DEFAULT_TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 4096;
const MAX_NAME_LEN: u32 = 255;
const VIRTUAL_TOTAL_BLOCKS: u64 = 268_435_456; // 1 TiB in 4 KiB blocks
const VIRTUAL_TOTAL_FILES: u64 = 1_000_000;

/// Maps a [`ZeroVaultError`] to its corresponding Linux `fuser::Errno`.
#[must_use]
pub fn error_to_errno(err: &ZeroVaultError) -> Errno {
    match err {
        ZeroVaultError::InodeNotFound(_)
        | ZeroVaultError::InvalidPath(_)
        | ZeroVaultError::StorageNotFound(_) => Errno::ENOENT,
        ZeroVaultError::AlreadyExists(_) => Errno::EEXIST,
        ZeroVaultError::NotADirectory(_) => Errno::ENOTDIR,
        ZeroVaultError::IsADirectory(_) => Errno::EISDIR,
        ZeroVaultError::DirectoryNotEmpty(_) => Errno::ENOTEMPTY,
        ZeroVaultError::PinnedDehydrationDenied(_) => Errno::EBUSY,
        ZeroVaultError::VaultLocked | ZeroVaultError::InvalidPassphrase => Errno::EACCES,
        ZeroVaultError::CryptoTamperDetected(_) => Errno::EIO,
        ZeroVaultError::InvalidRange { .. } => Errno::EINVAL,
        ZeroVaultError::StorageQuotaExceeded(_) => Errno::ENOSPC,
        ZeroVaultError::StorageConflict(_) => Errno::EAGAIN,
        ZeroVaultError::Io(io_err) => io_error_to_errno(io_err),
        ZeroVaultError::HardwareAccelerationUnavailable(_)
        | ZeroVaultError::InvalidWireFormat(_)
        | ZeroVaultError::KdfPolicyViolation { .. }
        | ZeroVaultError::KeyringError(_)
        | ZeroVaultError::OAuthError(_)
        | ZeroVaultError::StorageBackendError(_)
        | ZeroVaultError::VfsError(_)
        | ZeroVaultError::MetadataError(_)
        | ZeroVaultError::IpcError(_)
        | ZeroVaultError::ConfigError(_) => Errno::EIO,
    }
}

fn io_error_to_errno(err: &std::io::Error) -> Errno {
    if let Some(raw) = err.raw_os_error()
        && raw > 0
    {
        return Errno::from_i32(raw);
    }
    match err.kind() {
        std::io::ErrorKind::NotFound => Errno::ENOENT,
        std::io::ErrorKind::PermissionDenied => Errno::EACCES,
        std::io::ErrorKind::AlreadyExists => Errno::EEXIST,
        std::io::ErrorKind::InvalidInput => Errno::EINVAL,
        std::io::ErrorKind::TimedOut => Errno::ETIMEDOUT,
        std::io::ErrorKind::WouldBlock => Errno::EAGAIN,
        std::io::ErrorKind::DirectoryNotEmpty => Errno::ENOTEMPTY,
        std::io::ErrorKind::NotADirectory => Errno::ENOTDIR,
        std::io::ErrorKind::IsADirectory => Errno::EISDIR,
        _ => Errno::EIO,
    }
}

/// Converts a UTC timestamp into `SystemTime`, clamping out-of-range dates safely.
#[must_use]
pub fn datetime_to_system_time(dt: DateTime<Utc>) -> SystemTime {
    let secs = dt.timestamp();
    let nanos = dt.timestamp_subsec_nanos().min(999_999_999);
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(secs as u64, nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        let abs_secs = secs.unsigned_abs();
        if nanos == 0 {
            UNIX_EPOCH
                .checked_sub(Duration::new(abs_secs, 0))
                .unwrap_or(UNIX_EPOCH)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::new(
                    abs_secs.saturating_sub(1),
                    1_000_000_000 - nanos,
                ))
                .unwrap_or(UNIX_EPOCH)
        }
    }
}

/// Converts an [`InodeRecord`] to [`fuser::FileAttr`].
#[must_use]
pub fn inode_to_file_attr(rec: &InodeRecord, uid: u32, gid: u32) -> FileAttr {
    let kind = match rec.kind {
        EntryKind::File => FileType::RegularFile,
        EntryKind::Directory => FileType::Directory,
    };
    let nlink = if rec.kind == EntryKind::Directory {
        2
    } else {
        1
    };
    let mtime = datetime_to_system_time(rec.modified_at);
    let crtime = datetime_to_system_time(rec.created_at);
    FileAttr {
        ino: INodeNo(rec.inode),
        size: rec.size,
        blocks: rec.size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime,
        kind,
        perm: (rec.mode & 0o7777) as u16,
        nlink,
        uid,
        gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

/// Single entry yielded by paginated `readdir` enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntrySpec {
    /// Entry inode number.
    pub ino: INodeNo,
    /// Next stream cookie passed to FUSE `ReplyDirectory::add`.
    pub offset: u64,
    /// Entry file type.
    pub kind: FileType,
    /// Entry basename.
    pub name: String,
}

/// Builds deterministic `.`, `..`, and child `readdir` entries starting after `offset`.
#[must_use]
pub fn paginate_readdir_entries(
    dir: &InodeRecord,
    children: &[InodeRecord],
    offset: u64,
) -> Vec<DirEntrySpec> {
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push(DirEntrySpec {
        ino: INodeNo(dir.inode),
        offset: 1,
        kind: FileType::Directory,
        name: ".".to_owned(),
    });
    let parent_ino = if dir.inode == ROOT_INODE {
        ROOT_INODE
    } else {
        dir.parent_inode
    };
    entries.push(DirEntrySpec {
        ino: INodeNo(parent_ino),
        offset: 2,
        kind: FileType::Directory,
        name: "..".to_owned(),
    });
    for (idx, child) in children.iter().enumerate() {
        let kind = match child.kind {
            EntryKind::File => FileType::RegularFile,
            EntryKind::Directory => FileType::Directory,
        };
        entries.push(DirEntrySpec {
            ino: INodeNo(child.inode),
            offset: (idx + 3) as u64,
            kind,
            name: child.name.clone(),
        });
    }
    let skip = usize::try_from(offset).unwrap_or(usize::MAX);
    entries.into_iter().skip(skip).collect()
}

/// Returns the NUL-separated `listxattr` payload advertising Zerovault extended attributes.
#[must_use]
pub fn xattr_list_payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(
        XATTR_ZEROVAULT_STATE.len() + 1 + XATTR_ZEROVAULT_PIN.len() + 1,
    );
    out.extend_from_slice(XATTR_ZEROVAULT_STATE.as_bytes());
    out.push(0);
    out.extend_from_slice(XATTR_ZEROVAULT_PIN.as_bytes());
    out.push(0);
    out
}

/// Filesystem statistics snapshot returned by `statfs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFsInfo {
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Available blocks for unprivileged users.
    pub bavail: u64,
    /// Total file nodes.
    pub files: u64,
    /// Free file nodes.
    pub ffree: u64,
    /// Preferred block size.
    pub bsize: u32,
    /// Maximum filename length.
    pub namelen: u32,
    /// Fragment size.
    pub frsize: u32,
}

/// Bounded per-handle dirty write buffer capped strictly at [`PLAINTEXT_CHUNK_SIZE`] (4 MiB).
///
/// Contiguous writes inside the same 4 MiB chunk coalesce in memory and auto-flush whenever
/// buffered bytes reach `PLAINTEXT_CHUNK_SIZE` or a 4 MiB chunk boundary is crossed. Any
/// non-contiguous write flushes previously buffered bytes first.
#[derive(Debug)]
pub struct DirtyWriteBuffer {
    start_offset: Option<u64>,
    buf: Vec<u8>,
    chunk_size: usize,
    last_write_at: Option<DateTime<Utc>>,
}

impl Default for DirtyWriteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DirtyWriteBuffer {
    /// Creates an empty dirty write buffer with the canonical 4 MiB chunk threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_offset: None,
            buf: Vec::new(),
            chunk_size: PLAINTEXT_CHUNK_SIZE,
            last_write_at: None,
        }
    }

    /// Returns the number of dirty bytes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` when no dirty bytes are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the starting file offset of the buffered contiguous slice, if non-empty.
    #[must_use]
    pub fn start_offset(&self) -> Option<u64> {
        self.start_offset
    }

    /// Returns the exclusive end file offset of the buffered slice, if non-empty.
    #[must_use]
    pub fn end_offset(&self) -> Option<u64> {
        self.start_offset
            .map(|start| start.saturating_add(self.buf.len() as u64))
    }

    /// Returns the UTC timestamp of the most recent buffered write, if non-empty.
    #[must_use]
    pub fn last_write_at(&self) -> Option<DateTime<Utc>> {
        self.last_write_at
    }

    /// Writes `data` at `offset`, invoking `flush_fn(flush_offset, slice)` whenever flushing
    /// is required due to non-contiguity, reaching `PLAINTEXT_CHUNK_SIZE`, or crossing a
    /// 4 MiB chunk boundary.
    pub fn write_with<F>(
        &mut self,
        offset: u64,
        data: &[u8],
        mut flush_fn: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut(u64, &[u8]) -> Result<usize, Errno>,
    {
        if data.is_empty() {
            return Ok(0);
        }

        if let Some(end) = self.end_offset()
            && offset != end
        {
            self.flush_with(&mut flush_fn)?;
        }

        let chunk_size_u64 = self.chunk_size as u64;
        let mut total_written = 0usize;
        let mut cur_offset = offset;
        let mut remaining = data;

        while !remaining.is_empty() {
            let in_chunk_offset = (cur_offset % chunk_size_u64) as usize;
            let bytes_to_chunk_end = self.chunk_size - in_chunk_offset;
            let take = remaining.len().min(bytes_to_chunk_end);
            let reaches_boundary = take == bytes_to_chunk_end;

            // Fast path: empty buffer and this slice finishes at or fills a chunk boundary.
            if self.start_offset.is_none() && (reaches_boundary || take >= self.chunk_size) {
                let slice = &remaining[..take];
                match flush_fn(cur_offset, slice) {
                    Ok(n) => {
                        total_written += n;
                        if n < take {
                            return Ok(total_written);
                        }
                        cur_offset = cur_offset.saturating_add(n as u64);
                        remaining = &remaining[n..];
                    }
                    Err(err) => {
                        return if total_written > 0 {
                            Ok(total_written)
                        } else {
                            Err(err)
                        };
                    }
                }
                continue;
            }

            let prev_len = self.buf.len();
            let prev_start = self.start_offset;
            let prev_ts = self.last_write_at;
            if self.start_offset.is_none() {
                self.start_offset = Some(cur_offset);
            }
            self.reserve_bounded(take);
            self.buf.extend_from_slice(&remaining[..take]);
            self.last_write_at = Some(Utc::now());

            if reaches_boundary || self.buf.len() >= self.chunk_size {
                let flush_start = self.start_offset.unwrap_or(cur_offset);
                match flush_fn(flush_start, &self.buf) {
                    Ok(n) if n == self.buf.len() => {
                        self.buf.clear();
                        self.start_offset = None;
                        self.last_write_at = None;
                        total_written += take;
                        cur_offset = cur_offset.saturating_add(take as u64);
                        remaining = &remaining[take..];
                    }
                    Ok(n) => {
                        self.buf.drain(..n);
                        self.start_offset = Some(flush_start.saturating_add(n as u64));
                        return if total_written > 0 {
                            Ok(total_written)
                        } else {
                            Err(Errno::EIO)
                        };
                    }
                    Err(err) => {
                        self.buf.truncate(prev_len);
                        self.start_offset = prev_start;
                        self.last_write_at = prev_ts;
                        return if total_written > 0 {
                            Ok(total_written)
                        } else {
                            Err(err)
                        };
                    }
                }
            } else {
                total_written += take;
                cur_offset = cur_offset.saturating_add(take as u64);
                remaining = &remaining[take..];
            }
        }

        Ok(total_written)
    }

    /// Flushes any remaining dirty bytes in this buffer via `flush_fn`.
    pub fn flush_with<F>(&mut self, mut flush_fn: F) -> Result<(), Errno>
    where
        F: FnMut(u64, &[u8]) -> Result<usize, Errno>,
    {
        let Some(start) = self.start_offset else {
            return Ok(());
        };
        if self.buf.is_empty() {
            self.start_offset = None;
            self.last_write_at = None;
            return Ok(());
        }
        let written = flush_fn(start, &self.buf)?;
        if written < self.buf.len() {
            self.buf.drain(..written);
            self.start_offset = Some(start.saturating_add(written as u64));
            return Err(Errno::EIO);
        }
        self.buf.clear();
        self.start_offset = None;
        self.last_write_at = None;
        Ok(())
    }

    fn reserve_bounded(&mut self, additional: usize) {
        let needed = self.buf.len().saturating_add(additional);
        if self.buf.capacity() >= needed {
            return;
        }
        let doubled = self.buf.capacity().saturating_mul(2);
        let target = needed.max(doubled).min(self.chunk_size);
        let extra = target.saturating_sub(self.buf.len());
        self.buf.reserve_exact(extra);
    }
}

enum RuntimeBridge {
    Handle(Handle),
    Owned(Runtime),
}

impl RuntimeBridge {
    fn from_ambient() -> Self {
        if let Ok(handle) = Handle::try_current()
            && matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread)
        {
            return Self::Handle(handle);
        }
        Self::new_owned()
    }

    fn new_owned() -> Self {
        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("zerovault-fuse-rt")
            .enable_all()
            .build()
            .expect("failed to initialize Tokio runtime bridge for Linux FUSE");
        Self::Owned(rt)
    }

    fn raw_block_on<F: Future>(&self, fut: F) -> F::Output {
        match self {
            Self::Handle(handle) => handle.block_on(fut),
            Self::Owned(rt) => rt.block_on(fut),
        }
    }

    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send,
        F::Output: Send,
    {
        match Handle::try_current() {
            Ok(cur) if matches!(cur.runtime_flavor(), RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.raw_block_on(fut))
            }
            Ok(_) => std::thread::scope(|scope| {
                scope
                    .spawn(|| self.raw_block_on(fut))
                    .join()
                    .expect("Tokio bridge worker thread panicked")
            }),
            Err(_) => self.raw_block_on(fut),
        }
    }
}

struct OpenFileHandle {
    ino: InodeId,
    _flags: i32,
    dirty: Mutex<DirtyWriteBuffer>,
}

/// FUSE3 filesystem adapter forwarding synchronous kernel callbacks to [`VfsBackend`].
pub struct LinuxFuseFilesystem {
    backend: Arc<dyn VfsBackend>,
    runtime: RuntimeBridge,
    handles: DashMap<u64, Arc<OpenFileHandle>>,
    dir_handles: DashMap<u64, InodeId>,
    next_fh: AtomicU64,
    active_file_handles: Arc<AtomicU64>,
    uid: u32,
    gid: u32,
}

impl std::fmt::Debug for LinuxFuseFilesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFuseFilesystem")
            .field(
                "active_file_handles",
                &self.active_file_handles.load(Ordering::Relaxed),
            )
            .field("open_dir_handles", &self.dir_handles.len())
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

impl LinuxFuseFilesystem {
    /// Creates a new FUSE3 filesystem adapter using the ambient multi-thread Tokio runtime
    /// or a dedicated fallback runtime if none is active.
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>) -> Self {
        Self::build(backend, RuntimeBridge::from_ambient(), Arc::new(AtomicU64::new(0)))
    }

    /// Creates a new FUSE3 filesystem adapter bound explicitly to `handle`.
    #[must_use]
    pub fn with_runtime_handle(backend: Arc<dyn VfsBackend>, handle: Handle) -> Self {
        Self::build(
            backend,
            RuntimeBridge::Handle(handle),
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub(crate) fn with_shared_handle_counter(
        backend: Arc<dyn VfsBackend>,
        active_file_handles: Arc<AtomicU64>,
        runtime_handle: Option<Handle>,
    ) -> Self {
        let bridge = match runtime_handle {
            Some(handle) if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) => {
                RuntimeBridge::Handle(handle)
            }
            _ => RuntimeBridge::from_ambient(),
        };
        Self::build(backend, bridge, active_file_handles)
    }

    fn build(
        backend: Arc<dyn VfsBackend>,
        runtime: RuntimeBridge,
        active_file_handles: Arc<AtomicU64>,
    ) -> Self {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        Self {
            backend,
            runtime,
            handles: DashMap::new(),
            dir_handles: DashMap::new(),
            next_fh: AtomicU64::new(1),
            active_file_handles,
            uid,
            gid,
        }
    }

    /// Returns the owner UID reported in `FileAttr`.
    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.uid
    }

    /// Returns the owner GID reported in `FileAttr`.
    #[must_use]
    pub fn owner_gid(&self) -> u32 {
        self.gid
    }

    /// Returns the number of currently open file handles.
    #[must_use]
    pub fn active_file_handle_count(&self) -> u64 {
        self.active_file_handles.load(Ordering::Acquire)
    }

    /// Returns the number of currently buffered dirty bytes on handle `fh`.
    #[must_use]
    pub fn buffered_dirty_bytes(&self, fh: u64) -> usize {
        let Some(handle) = self.handles.get(&fh).map(|entry| Arc::clone(entry.value())) else {
            return 0;
        };
        handle.dirty.lock().len()
    }

    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send,
        F::Output: Send,
    {
        self.runtime.block_on(fut)
    }

    fn to_file_attr(&self, rec: &InodeRecord) -> FileAttr {
        inode_to_file_attr(rec, self.uid, self.gid)
    }

    fn allocate_handle(&self, ino: InodeId, flags: i32) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(
            fh,
            Arc::new(OpenFileHandle {
                ino,
                _flags: flags,
                dirty: Mutex::new(DirtyWriteBuffer::new()),
            }),
        );
        self.active_file_handles.fetch_add(1, Ordering::AcqRel);
        fh
    }

    fn flush_single_handle(&self, handle: &OpenFileHandle) -> Result<(), Errno> {
        let mut dirty = handle.dirty.lock();
        dirty.flush_with(|flush_offset, slice| {
            self.block_on(self.backend.write_range(handle.ino, flush_offset, slice))
                .map_err(|err| error_to_errno(&err))
        })
    }

    fn flush_dirty_handles_for_inode(&self, ino: InodeId) -> Result<(), Errno> {
        let matching: Vec<Arc<OpenFileHandle>> = self
            .handles
            .iter()
            .filter(|entry| entry.value().ino == ino)
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        for handle in matching {
            self.flush_single_handle(&handle)?;
        }
        Ok(())
    }

    fn dirty_summary_for_inode(&self, ino: InodeId) -> Option<(u64, DateTime<Utc>)> {
        let matching: Vec<Arc<OpenFileHandle>> = self
            .handles
            .iter()
            .filter(|entry| entry.value().ino == ino)
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let mut max_end: Option<u64> = None;
        let mut max_ts: Option<DateTime<Utc>> = None;
        for handle in matching {
            let dirty = handle.dirty.lock();
            if let Some(end) = dirty.end_offset() {
                max_end = Some(max_end.map_or(end, |prev| prev.max(end)));
                if let Some(ts) = dirty.last_write_at() {
                    max_ts = Some(max_ts.map_or(ts, |prev| prev.max(ts)));
                }
            }
        }
        max_end.map(|end| (end, max_ts.unwrap_or_else(Utc::now)))
    }

    fn os_str_to_name(name: &OsStr, invalid_errno: Errno) -> Result<&str, Errno> {
        name.to_str().ok_or(invalid_errno)
    }

    /// Resolves a child entry `(parent, name)` into FUSE attributes.
    pub fn handle_lookup(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        let mut rec = self
            .block_on(self.backend.lookup(parent, name_str))
            .map_err(|err| error_to_errno(&err))?;
        self.apply_dirty_summary(&mut rec);
        Ok(self.to_file_attr(&rec))
    }

    /// Fetches FUSE attributes for `ino`, incorporating any buffered dirty writes.
    pub fn handle_getattr(&self, ino: u64) -> Result<FileAttr, Errno> {
        let mut rec = self
            .block_on(self.backend.getattr(ino))
            .map_err(|err| error_to_errno(&err))?;
        self.apply_dirty_summary(&mut rec);
        Ok(self.to_file_attr(&rec))
    }

    fn apply_dirty_summary(&self, rec: &mut InodeRecord) {
        if let Some((dirty_end, dirty_ts)) = self.dirty_summary_for_inode(rec.inode) {
            rec.size = rec.size.max(dirty_end);
            rec.hydration = HydrationState::DirtyLocal;
            if dirty_ts > rec.modified_at {
                rec.modified_at = dirty_ts;
            }
        }
    }

    /// Updates inode attributes (`size`, `mode`, `mtime`), flushing buffered dirty writes first.
    pub fn handle_setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr, Errno> {
        if uid.is_some_and(|u| u != self.uid) || gid.is_some_and(|g| g != self.gid) {
            return Err(Errno::EPERM);
        }

        self.flush_dirty_handles_for_inode(ino)?;

        let modified_at = mtime.map(|t| match t {
            TimeOrNow::Now => Utc::now(),
            TimeOrNow::SpecificTime(st) => DateTime::<Utc>::from(st),
        });
        let spec = SetAttrSpec {
            size,
            mode: mode.map(|m| m & 0o7777),
            modified_at,
        };
        let rec = self
            .block_on(self.backend.setattr(ino, spec))
            .map_err(|err| error_to_errno(&err))?;
        Ok(self.to_file_attr(&rec))
    }

    /// Creates and opens a regular file, returning `(FileAttr, fh)`.
    pub fn handle_create(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        flags: i32,
    ) -> Result<(FileAttr, u64), Errno> {
        let name_str = Self::os_str_to_name(name, Errno::EINVAL)?;
        let spec = CreateEntrySpec {
            parent_inode: parent,
            name: name_str.to_owned(),
            mode: mode & 0o7777,
        };
        let rec = self
            .block_on(self.backend.create_entry(spec))
            .map_err(|err| error_to_errno(&err))?;
        let fh = self.allocate_handle(rec.inode, flags);
        Ok((self.to_file_attr(&rec), fh))
    }

    /// Creates a directory under `parent`.
    pub fn handle_mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Result<FileAttr, Errno> {
        let name_str = Self::os_str_to_name(name, Errno::EINVAL)?;
        let rec = self
            .block_on(self.backend.mkdir(parent, name_str, mode & 0o7777))
            .map_err(|err| error_to_errno(&err))?;
        Ok(self.to_file_attr(&rec))
    }

    /// Unlinks a regular file under `parent`.
    pub fn handle_unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        self.block_on(self.backend.unlink(parent, name_str))
            .map_err(|err| error_to_errno(&err))
    }

    /// Removes an empty directory under `parent`.
    pub fn handle_rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        self.block_on(self.backend.rmdir(parent, name_str))
            .map_err(|err| error_to_errno(&err))
    }

    /// Moves or renames an entry atomically.
    pub fn handle_rename(
        &self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: RenameFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return Err(Errno::EINVAL);
        }
        let old_name = Self::os_str_to_name(name, Errno::ENOENT)?;
        let new_name = Self::os_str_to_name(newname, Errno::EINVAL)?;

        if flags.contains(RenameFlags::RENAME_NOREPLACE) {
            match self.block_on(self.backend.lookup(newparent, new_name)) {
                Ok(_) => return Err(Errno::EEXIST),
                Err(ZeroVaultError::InodeNotFound(_)) => {}
                Err(err) => return Err(error_to_errno(&err)),
            }
        }

        self.block_on(self.backend.rename(parent, old_name, newparent, new_name))
            .map(|_| ())
            .map_err(|err| error_to_errno(&err))
    }

    /// Opens an existing file and allocates a tracked handle ID.
    pub fn handle_open(&self, ino: u64, flags: OpenFlags) -> Result<u64, Errno> {
        let rec = self
            .block_on(self.backend.getattr(ino))
            .map_err(|err| error_to_errno(&err))?;
        if rec.kind == EntryKind::Directory {
            return Err(Errno::EISDIR);
        }
        if (flags.0 & libc::O_TRUNC) != 0 {
            let acc = flags.0 & libc::O_ACCMODE;
            if acc != libc::O_WRONLY && acc != libc::O_RDWR {
                return Err(Errno::EACCES);
            }
            self.flush_dirty_handles_for_inode(ino)?;
            self.block_on(self.backend.setattr(
                ino,
                SetAttrSpec {
                    size: Some(0),
                    ..Default::default()
                },
            ))
            .map_err(|err| error_to_errno(&err))?;
        }
        Ok(self.allocate_handle(ino, flags.0))
    }

    /// Reads `[offset, offset + size)` via bounded `<= 4 MiB` `VfsBackend::read_range` calls.
    pub fn handle_read(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        self.flush_dirty_handles_for_inode(ino)?;
        let requested = size as usize;
        if requested == 0 {
            let _ = self
                .block_on(self.backend.read_range(ino, offset, 0))
                .map_err(|err| error_to_errno(&err))?;
            return Ok(Vec::new());
        }
        if requested <= PLAINTEXT_CHUNK_SIZE {
            let data: Bytes = self
                .block_on(self.backend.read_range(ino, offset, requested))
                .map_err(|err| error_to_errno(&err))?;
            return Ok(data.to_vec());
        }

        let mut out = Vec::new();
        let mut cur_offset = offset;
        let mut remaining = requested;
        while remaining > 0 {
            let slice_len = remaining.min(PLAINTEXT_CHUNK_SIZE);
            let chunk = self
                .block_on(self.backend.read_range(ino, cur_offset, slice_len))
                .map_err(|err| error_to_errno(&err))?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
            let got = chunk.len();
            cur_offset = cur_offset.saturating_add(got as u64);
            remaining -= got;
            if got < slice_len {
                break;
            }
        }
        Ok(out)
    }

    /// Writes `data` at `offset` through the per-handle bounded 4 MiB dirty write buffer.
    pub fn handle_write(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, Errno> {
        if offset.checked_add(data.len() as u64).is_none() {
            return Err(Errno::EFBIG);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let maybe_handle = self.handles.get(&fh).map(|entry| Arc::clone(entry.value()));
        let written = if let Some(handle) = maybe_handle {
            if handle.ino != ino {
                return Err(Errno::EBADF);
            }
            let mut dirty = handle.dirty.lock();
            dirty.write_with(offset, data, |flush_offset, slice| {
                self.block_on(self.backend.write_range(ino, flush_offset, slice))
                    .map_err(|err| error_to_errno(&err))
            })?
        } else {
            self.write_unbuffered_bounded(ino, offset, data)?
        };

        u32::try_from(written).map_err(|_| Errno::EOVERFLOW)
    }

    fn write_unbuffered_bounded(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, Errno> {
        let mut total_written = 0usize;
        let mut cur_offset = offset;
        let mut remaining = data;
        while !remaining.is_empty() {
            let slice_len = remaining.len().min(PLAINTEXT_CHUNK_SIZE);
            let n = self
                .block_on(self.backend.write_range(ino, cur_offset, &remaining[..slice_len]))
                .map_err(|err| error_to_errno(&err))?;
            total_written += n;
            if n < slice_len {
                break;
            }
            cur_offset = cur_offset.saturating_add(n as u64);
            remaining = &remaining[n..];
        }
        Ok(total_written)
    }

    /// Flushes dirty buffered writes on `fh` and calls `VfsBackend::flush`.
    pub fn handle_flush(&self, ino: u64, fh: u64) -> Result<(), Errno> {
        if let Some(handle) = self.handles.get(&fh).map(|entry| Arc::clone(entry.value())) {
            self.flush_single_handle(&handle)?;
        }
        self.block_on(self.backend.flush(ino))
            .map_err(|err| error_to_errno(&err))
    }

    /// Flushes all dirty buffers for `ino` and calls `VfsBackend::fsync`.
    pub fn handle_fsync(&self, ino: u64, fh: u64, datasync: bool) -> Result<(), Errno> {
        if let Some(handle) = self.handles.get(&fh).map(|entry| Arc::clone(entry.value())) {
            self.flush_single_handle(&handle)?;
        }
        self.flush_dirty_handles_for_inode(ino)?;
        self.block_on(self.backend.fsync(ino, datasync))
            .map_err(|err| error_to_errno(&err))
    }

    /// Releases `fh`, flushing any remaining buffered dirty writes and calling `VfsBackend::flush`.
    pub fn handle_release(&self, ino: u64, fh: u64) -> Result<(), Errno> {
        let mut had_dirty = false;
        if let Some((_, handle)) = self.handles.remove(&fh) {
            self.active_file_handles.fetch_sub(1, Ordering::AcqRel);
            had_dirty = !handle.dirty.lock().is_empty();
            self.flush_single_handle(&handle)?;
        }
        match self.block_on(self.backend.flush(ino)) {
            Ok(()) => Ok(()),
            // File may have been unlinked while an open read handle remained.
            Err(ZeroVaultError::InodeNotFound(_)) if !had_dirty => Ok(()),
            Err(err) => Err(error_to_errno(&err)),
        }
    }

    /// Lists paginated directory entries (`.` + `..` + children) starting after `offset`.
    pub fn handle_readdir(&self, ino: u64, offset: u64) -> Result<Vec<DirEntrySpec>, Errno> {
        let dir = self
            .block_on(self.backend.getattr(ino))
            .map_err(|err| error_to_errno(&err))?;
        if dir.kind != EntryKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let children = self
            .block_on(self.backend.readdir(ino))
            .map_err(|err| error_to_errno(&err))?;
        Ok(paginate_readdir_entries(&dir, &children, offset))
    }

    /// Lists Zerovault extended attributes for `ino`.
    pub fn handle_listxattr(&self, ino: u64) -> Result<Vec<u8>, Errno> {
        let _ = self
            .block_on(self.backend.getattr(ino))
            .map_err(|err| error_to_errno(&err))?;
        Ok(xattr_list_payload())
    }

    /// Reads `user.zerovault.state` or `user.zerovault.pin` for `ino`.
    pub fn handle_getxattr(&self, ino: u64, name: &OsStr) -> Result<Vec<u8>, Errno> {
        let rec = self
            .block_on(self.backend.getattr(ino))
            .map_err(|err| error_to_errno(&err))?;

        let Some(name_str) = name.to_str() else {
            return Err(Errno::ENODATA);
        };

        if name_str == XATTR_ZEROVAULT_STATE {
            let state = if self.dirty_summary_for_inode(ino).is_some() {
                HydrationState::DirtyLocal
            } else {
                self.block_on(self.backend.get_xattr_state(ino))
                    .map_err(|err| error_to_errno(&err))?
            };
            return Ok(state.as_xattr_str().as_bytes().to_vec());
        }

        if name_str == XATTR_ZEROVAULT_PIN {
            let val = if rec.pinned { b"1" } else { b"0" };
            return Ok(val.to_vec());
        }

        Err(Errno::ENODATA)
    }

    /// Sets `user.zerovault.pin` (`"1"` to pin, `"0"` to dehydrate) on `ino`.
    pub fn handle_setxattr(
        &self,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<(), Errno> {
        if position != 0 {
            return Err(Errno::EINVAL);
        }
        let Some(name_str) = name.to_str() else {
            return Err(Errno::ENOTSUP);
        };
        if name_str == XATTR_ZEROVAULT_STATE {
            return Err(Errno::EACCES);
        }
        if name_str != XATTR_ZEROVAULT_PIN {
            return Err(Errno::ENOTSUP);
        }
        if (flags & libc::XATTR_CREATE) != 0 {
            return Err(Errno::EEXIST);
        }

        match value {
            b"1" => {
                self.flush_dirty_handles_for_inode(ino)?;
                self.block_on(self.backend.pin(ino))
                    .map_err(|err| error_to_errno(&err))
            }
            b"0" => {
                self.flush_dirty_handles_for_inode(ino)?;
                self.block_on(self.backend.dehydrate(ino))
                    .map_err(|err| error_to_errno(&err))
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Returns filesystem statistics for `statfs`.
    #[must_use]
    pub fn handle_statfs(&self) -> StatFsInfo {
        StatFsInfo {
            blocks: VIRTUAL_TOTAL_BLOCKS,
            bfree: VIRTUAL_TOTAL_BLOCKS,
            bavail: VIRTUAL_TOTAL_BLOCKS,
            files: VIRTUAL_TOTAL_FILES,
            ffree: VIRTUAL_TOTAL_FILES.saturating_sub(1),
            bsize: BLOCK_SIZE,
            namelen: MAX_NAME_LEN,
            frsize: BLOCK_SIZE,
        }
    }
}

fn reply_xattr_bytes(size: u32, payload: &[u8], reply: ReplyXattr) {
    if size == 0 {
        match u32::try_from(payload.len()) {
            Ok(len) => reply.size(len),
            Err(_) => reply.error(Errno::EOVERFLOW),
        }
    } else if (size as usize) < payload.len() {
        reply.error(Errno::ERANGE);
    } else {
        reply.data(payload);
    }
}

impl Filesystem for LinuxFuseFilesystem {
    fn destroy(&mut self) {
        let remaining: Vec<(u64, Arc<OpenFileHandle>)> = self
            .handles
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect();
        for (fh, handle) in remaining {
            if self.handles.remove(&fh).is_some() {
                self.active_file_handles.fetch_sub(1, Ordering::AcqRel);
            }
            let _ = self.flush_single_handle(&handle);
            let _ = self.block_on(self.backend.flush(handle.ino));
        }
        self.dir_handles.clear();
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.handle_lookup(parent.0, name) {
            Ok(attr) => reply.entry(&DEFAULT_TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.handle_getattr(ino.0) {
            Ok(attr) => reply.attr(&DEFAULT_TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        match self.handle_setattr(ino.0, mode, uid, gid, size, mtime) {
            Ok(attr) => reply.attr(&DEFAULT_TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.handle_mkdir(parent.0, name, mode) {
            Ok(attr) => reply.entry(&DEFAULT_TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.handle_unlink(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.handle_rmdir(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        match self.handle_rename(parent.0, name, newparent.0, newname, flags) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        match self.handle_open(ino.0, flags) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(errno) => reply.error(errno),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.handle_create(parent.0, name, mode, flags) {
            Ok((attr, fh)) => reply.created(
                &DEFAULT_TTL,
                &attr,
                Generation(0),
                FileHandle(fh),
                FopenFlags::empty(),
            ),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.handle_read(ino.0, offset, size) {
            Ok(data) => reply.data(&data),
            Err(errno) => reply.error(errno),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.handle_write(ino.0, fh.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(errno) => reply.error(errno),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.handle_flush(ino.0, fh.0) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.handle_fsync(ino.0, fh.0, datasync) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.handle_release(ino.0, fh.0) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.block_on(self.backend.getattr(ino.0)) {
            Ok(rec) if rec.kind == EntryKind::Directory => {
                let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                self.dir_handles.insert(fh, ino.0);
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Ok(_) => reply.error(Errno::ENOTDIR),
            Err(err) => reply.error(error_to_errno(&err)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.handle_readdir(ino.0, offset) {
            Ok(entries) => {
                for entry in entries {
                    if reply.add(entry.ino, entry.offset, entry.kind, &entry.name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.dir_handles.remove(&fh.0);
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.block_on(self.backend.fsync(ino.0, datasync)) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(error_to_errno(&err)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let info = self.handle_statfs();
        reply.statfs(
            info.blocks,
            info.bfree,
            info.bavail,
            info.files,
            info.ffree,
            info.bsize,
            info.namelen,
            info.frsize,
        );
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        match self.handle_listxattr(ino.0) {
            Ok(payload) => reply_xattr_bytes(size, &payload, reply),
            Err(errno) => reply.error(errno),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        match self.handle_getxattr(ino.0, name) {
            Ok(payload) => reply_xattr_bytes(size, &payload, reply),
            Err(errno) => reply.error(errno),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        match self.handle_setxattr(ino.0, name, value, flags, position) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(err) = self.block_on(self.backend.getattr(ino.0)) {
            reply.error(error_to_errno(&err));
            return;
        }
        match name.to_str() {
            Some(XATTR_ZEROVAULT_STATE | XATTR_ZEROVAULT_PIN) => reply.error(Errno::EPERM),
            _ => reply.error(Errno::ENODATA),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        match self.block_on(self.backend.getattr(ino.0)) {
            Ok(_) => reply.ok(),
            Err(err) => reply.error(error_to_errno(&err)),
        }
    }
}
