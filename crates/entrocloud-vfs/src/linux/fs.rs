//! FUSE3 (`fuser::Filesystem`) implementation bridging kernel VFS requests to [`PortableFuseState`].

use std::ffi::OsStr;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};
use entrocloud_types::{EntryKind, InodeRecord, VfsBackend, ZeroVaultError};

use super::portable::{
    PortableAttr, PortableDirEntry, PortableErrno, PortableFuseState, PortableMtime,
    PortableOpenFlags, PortableRenameFlags, StatFsInfo, inode_to_portable_attr,
    paginate_portable_readdir, portable_error_to_errno,
};

const DEFAULT_TTL: Duration = Duration::from_secs(1);

impl From<PortableErrno> for Errno {
    fn from(err: PortableErrno) -> Self {
        match err {
            PortableErrno::Eperm => Self::EPERM,
            PortableErrno::Enoent => Self::ENOENT,
            PortableErrno::Eio => Self::EIO,
            PortableErrno::Ebadf => Self::EBADF,
            PortableErrno::Eagain => Self::EAGAIN,
            PortableErrno::Eacces => Self::EACCES,
            PortableErrno::Ebusy => Self::EBUSY,
            PortableErrno::Eexist => Self::EEXIST,
            PortableErrno::Enotdir => Self::ENOTDIR,
            PortableErrno::Eisdir => Self::EISDIR,
            PortableErrno::Einval => Self::EINVAL,
            PortableErrno::Efbig => Self::EFBIG,
            PortableErrno::Enospc => Self::ENOSPC,
            PortableErrno::Erange => Self::ERANGE,
            PortableErrno::Enametoolong => Self::ENAMETOOLONG,
            PortableErrno::Enosys => Self::ENOSYS,
            PortableErrno::Enotempty => Self::ENOTEMPTY,
            PortableErrno::Enodata => Self::ENODATA,
            PortableErrno::Eoverflow => Self::EOVERFLOW,
            PortableErrno::Enotsup => Self::ENOTSUP,
            PortableErrno::Etimedout => Self::ETIMEDOUT,
            PortableErrno::Raw(raw) => Self::from_i32(raw.max(1)),
        }
    }
}

impl From<Errno> for PortableErrno {
    fn from(errno: Errno) -> Self {
        let code: i32 = errno.into();
        Self::from_code(code)
    }
}

/// Maps a [`ZeroVaultError`] to its corresponding Linux `fuser::Errno`.
#[must_use]
pub fn error_to_errno(err: &ZeroVaultError) -> Errno {
    Errno::from(portable_error_to_errno(err))
}

/// Converts a [`PortableAttr`] into [`fuser::FileAttr`].
#[must_use]
pub fn portable_attr_to_file_attr(attr: &PortableAttr) -> FileAttr {
    let kind = match attr.kind {
        EntryKind::File => FileType::RegularFile,
        EntryKind::Directory => FileType::Directory,
    };
    FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        crtime: attr.crtime,
        kind,
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags: attr.flags,
    }
}

/// Converts an [`InodeRecord`] directly to [`fuser::FileAttr`].
#[must_use]
pub fn inode_to_file_attr(rec: &InodeRecord, uid: u32, gid: u32) -> FileAttr {
    portable_attr_to_file_attr(&inode_to_portable_attr(rec, uid, gid))
}

/// Single entry yielded by paginated `readdir` enumeration on Linux FUSE3.
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

impl From<PortableDirEntry> for DirEntrySpec {
    fn from(entry: PortableDirEntry) -> Self {
        let kind = match entry.kind {
            EntryKind::File => FileType::RegularFile,
            EntryKind::Directory => FileType::Directory,
        };
        Self {
            ino: INodeNo(entry.ino),
            offset: entry.offset,
            kind,
            name: entry.name,
        }
    }
}

/// Builds deterministic `.`, `..`, and child `readdir` entries starting after `offset`.
#[must_use]
pub fn paginate_readdir_entries(
    dir: &InodeRecord,
    children: &[InodeRecord],
    offset: u64,
) -> Vec<DirEntrySpec> {
    paginate_portable_readdir(dir, children, offset)
        .into_iter()
        .map(DirEntrySpec::from)
        .collect()
}

/// Non-blocking bridge executing async [`PortableFuseState`] operations from synchronous
/// `fuser` worker threads (or ambient Tokio multi-thread / single-thread test runtimes)
/// without deadlocking or panicking on drop.
enum RuntimeBridge {
    Handle(Handle),
    Owned(Result<Option<Runtime>, String>),
}

impl Drop for RuntimeBridge {
    fn drop(&mut self) {
        if let Self::Owned(Ok(opt_rt)) = self
            && let Some(rt) = opt_rt.take()
        {
            if Handle::try_current().is_ok() {
                // Dropping a Tokio Runtime directly inside an async context panics;
                // `shutdown_background` safely tears down worker threads off-context.
                rt.shutdown_background();
            } else {
                drop(rt);
            }
        }
    }
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

    fn from_optional_handle(runtime_handle: Option<Handle>) -> Self {
        match runtime_handle {
            Some(handle) if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) => {
                Self::Handle(handle)
            }
            _ => Self::from_ambient(),
        }
    }

    fn new_owned() -> Self {
        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("zerovault-fuse-rt")
            .enable_all()
            .build()
            .map(Some)
            .map_err(|err| {
                format!("failed to initialize Tokio runtime bridge for Linux FUSE: {err}")
            });
        Self::Owned(rt)
    }

    fn raw_block_on<T, F>(&self, fut: F) -> Result<T, PortableErrno>
    where
        F: Future<Output = Result<T, PortableErrno>>,
    {
        match self {
            Self::Handle(handle) => handle.block_on(fut),
            Self::Owned(Ok(Some(rt))) => rt.block_on(fut),
            Self::Owned(Ok(None)) => Err(PortableErrno::Eio),
            Self::Owned(Err(msg)) => {
                tracing::error!(error = %msg, "Linux FUSE runtime bridge unavailable");
                Err(PortableErrno::Eio)
            }
        }
    }

    fn block_on<T, F>(&self, fut: F) -> Result<T, Errno>
    where
        F: Future<Output = Result<T, PortableErrno>> + Send,
        T: Send,
    {
        let res = match Handle::try_current() {
            Ok(cur) if matches!(cur.runtime_flavor(), RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.raw_block_on(fut))
            }
            Ok(_) => std::thread::scope(|scope| match scope.spawn(|| self.raw_block_on(fut)).join()
            {
                Ok(inner) => inner,
                Err(_) => Err(PortableErrno::Eio),
            }),
            Err(_) => self.raw_block_on(fut),
        };
        res.map_err(Errno::from)
    }

    fn block_on_infallible<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send,
    {
        let _ = self.block_on(async move {
            fut.await;
            Ok(())
        });
    }
}

/// FUSE3 (`fuser v0.18`) filesystem adapter forwarding synchronous kernel callbacks to
/// [`PortableFuseState`] and [`VfsBackend`].
pub struct ZeroVaultFuseFs {
    state: Arc<PortableFuseState>,
    runtime: RuntimeBridge,
}

/// Backwards-compatible alias for [`ZeroVaultFuseFs`].
pub type LinuxFuseFilesystem = ZeroVaultFuseFs;

impl std::fmt::Debug for ZeroVaultFuseFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroVaultFuseFs")
            .field("active_file_handles", &self.active_file_handle_count())
            .field("open_dir_handles", &self.state.active_dir_handle_count())
            .field("uid", &self.owner_uid())
            .field("gid", &self.owner_gid())
            .finish_non_exhaustive()
    }
}

impl ZeroVaultFuseFs {
    /// Creates a new FUSE3 filesystem adapter using the ambient multi-thread Tokio runtime
    /// or a dedicated fallback runtime if none is active.
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>) -> Self {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let state = Arc::new(PortableFuseState::new(backend, uid, gid));
        Self {
            state,
            runtime: RuntimeBridge::from_ambient(),
        }
    }

    /// Creates a new FUSE3 filesystem adapter bound explicitly to `handle` (when multi-threaded;
    /// automatically spawns an isolated bridge runtime if `handle` is single-threaded).
    #[must_use]
    pub fn with_runtime_handle(backend: Arc<dyn VfsBackend>, handle: Handle) -> Self {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let state = Arc::new(PortableFuseState::new(backend, uid, gid));
        Self {
            state,
            runtime: RuntimeBridge::from_optional_handle(Some(handle)),
        }
    }

    pub(crate) fn with_shared_state(
        state: Arc<PortableFuseState>,
        runtime_handle: Option<Handle>,
    ) -> Self {
        Self {
            state,
            runtime: RuntimeBridge::from_optional_handle(runtime_handle),
        }
    }

    pub(crate) fn new_shared_state(
        backend: Arc<dyn VfsBackend>,
        active_file_handles: Arc<AtomicU64>,
    ) -> Arc<PortableFuseState> {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        Arc::new(PortableFuseState::with_shared_handle_counter(
            backend,
            active_file_handles,
            uid,
            gid,
        ))
    }

    /// Borrows the underlying cross-platform [`PortableFuseState`].
    #[must_use]
    pub fn state(&self) -> &Arc<PortableFuseState> {
        &self.state
    }

    /// Returns the owner UID reported in `FileAttr`.
    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.state.owner_uid()
    }

    /// Returns the owner GID reported in `FileAttr`.
    #[must_use]
    pub fn owner_gid(&self) -> u32 {
        self.state.owner_gid()
    }

    /// Returns the number of currently open file handles.
    #[must_use]
    pub fn active_file_handle_count(&self) -> u64 {
        self.state.active_file_handle_count()
    }

    /// Returns the number of currently buffered dirty bytes on handle `fh`.
    #[must_use]
    pub fn buffered_dirty_bytes(&self, fh: u64) -> usize {
        self.state.buffered_dirty_bytes(fh)
    }

    /// Explicitly latches a background flush `Errno` onto handle `fh` for `close(2)` reporting.
    pub fn latch_handle_error(&self, fh: u64, errno: Errno) -> bool {
        self.state
            .latch_handle_error(fh, PortableErrno::from(errno))
    }

    fn os_str_to_name(name: &OsStr, invalid_errno: Errno) -> Result<&str, Errno> {
        name.to_str().ok_or(invalid_errno)
    }

    /// Resolves a child entry `(parent, name)` into FUSE attributes.
    pub fn handle_lookup(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        let attr = self.runtime.block_on(self.state.lookup(parent, name_str))?;
        Ok(portable_attr_to_file_attr(&attr))
    }

    /// Fetches FUSE attributes for `ino`, incorporating any buffered dirty writes.
    pub fn handle_getattr(&self, ino: u64) -> Result<FileAttr, Errno> {
        let attr = self.runtime.block_on(self.state.getattr(ino))?;
        Ok(portable_attr_to_file_attr(&attr))
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
        let portable_mtime = mtime.map(|t| match t {
            TimeOrNow::Now => PortableMtime::Now,
            TimeOrNow::SpecificTime(st) => PortableMtime::Specific(st),
        });
        let attr = self
            .runtime
            .block_on(self.state.setattr(ino, mode, uid, gid, size, portable_mtime))?;
        Ok(portable_attr_to_file_attr(&attr))
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
        let (attr, fh) = self
            .runtime
            .block_on(self.state.create(parent, name_str, mode, flags))?;
        Ok((portable_attr_to_file_attr(&attr), fh))
    }

    /// Creates a directory under `parent`.
    pub fn handle_mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Result<FileAttr, Errno> {
        let name_str = Self::os_str_to_name(name, Errno::EINVAL)?;
        let attr = self
            .runtime
            .block_on(self.state.mkdir(parent, name_str, mode))?;
        Ok(portable_attr_to_file_attr(&attr))
    }

    /// Unlinks a regular file under `parent`.
    pub fn handle_unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        self.runtime.block_on(self.state.unlink(parent, name_str))
    }

    /// Removes an empty directory under `parent`.
    pub fn handle_rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let name_str = Self::os_str_to_name(name, Errno::ENOENT)?;
        self.runtime.block_on(self.state.rmdir(parent, name_str))
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
        let old_name = Self::os_str_to_name(name, Errno::ENOENT)?;
        let new_name = Self::os_str_to_name(newname, Errno::EINVAL)?;
        let portable_flags = PortableRenameFlags {
            noreplace: flags.contains(RenameFlags::RENAME_NOREPLACE),
            exchange: flags.contains(RenameFlags::RENAME_EXCHANGE),
            whiteout: flags.contains(RenameFlags::RENAME_WHITEOUT),
        };
        self.runtime.block_on(
            self.state
                .rename(parent, old_name, newparent, new_name, portable_flags),
        )
    }

    /// Opens an existing file and allocates a tracked handle ID.
    pub fn handle_open(&self, ino: u64, flags: OpenFlags) -> Result<u64, Errno> {
        let acc = flags.0 & libc::O_ACCMODE;
        let portable_flags = PortableOpenFlags {
            write_access: acc == libc::O_WRONLY || acc == libc::O_RDWR,
            truncate: (flags.0 & libc::O_TRUNC) != 0,
            raw_flags: flags.0,
        };
        self.runtime.block_on(self.state.open(ino, portable_flags))
    }

    /// Reads `[offset, offset + size)` via bounded `<= 4 MiB` `VfsBackend::read_range` calls.
    pub fn handle_read(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        self.runtime.block_on(self.state.read(ino, offset, size))
    }

    /// Writes `data` at `offset` through the per-handle bounded 4 MiB zeroizing dirty write buffer.
    pub fn handle_write(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, Errno> {
        self.runtime
            .block_on(self.state.write(ino, fh, offset, data))
    }

    /// Flushes dirty buffered writes on `fh` and reports any latched error for `close(2)`.
    pub fn handle_flush(&self, ino: u64, fh: u64) -> Result<(), Errno> {
        self.runtime.block_on(self.state.flush(ino, fh))
    }

    /// Flushes all dirty buffers for `ino` and calls `VfsBackend::fsync`.
    pub fn handle_fsync(&self, ino: u64, fh: u64, datasync: bool) -> Result<(), Errno> {
        self.runtime.block_on(self.state.fsync(ino, fh, datasync))
    }

    /// Releases `fh`, flushing/zeroizing dirty buffers and reporting any latched error.
    pub fn handle_release(&self, ino: u64, fh: u64) -> Result<(), Errno> {
        self.runtime.block_on(self.state.release(ino, fh))
    }

    /// Lists paginated directory entries (`.` + `..` + children) starting after `offset`.
    pub fn handle_readdir(&self, ino: u64, offset: u64) -> Result<Vec<DirEntrySpec>, Errno> {
        let entries = self.runtime.block_on(self.state.readdir(ino, offset))?;
        Ok(entries.into_iter().map(DirEntrySpec::from).collect())
    }

    /// Lists ZeroVault extended attributes (`state`, `pin`, `file_id`) for `ino`.
    pub fn handle_listxattr(&self, ino: u64) -> Result<Vec<u8>, Errno> {
        self.runtime.block_on(self.state.listxattr(ino))
    }

    /// Reads `user.zerovault.state`, `user.zerovault.pin`, or `user.zerovault.file_id` for `ino`.
    pub fn handle_getxattr(&self, ino: u64, name: &OsStr) -> Result<Vec<u8>, Errno> {
        let Some(name_str) = name.to_str() else {
            return Err(Errno::ENODATA);
        };
        self.runtime.block_on(self.state.getxattr(ino, name_str))
    }

    /// Sets `user.zerovault.pin` (`"1"`/`"true"`/`"pin"` or `"0"`/`"false"`/`"unpin"`) on `ino`.
    pub fn handle_setxattr(
        &self,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<(), Errno> {
        let Some(name_str) = name.to_str() else {
            return Err(Errno::ENOTSUP);
        };
        self.runtime
            .block_on(self.state.setxattr(ino, name_str, value, flags, position))
    }

    /// Rejects removal of virtual ZeroVault attributes (`EPERM`) or missing attributes (`ENODATA`).
    pub fn handle_removexattr(&self, ino: u64, name: &OsStr) -> Result<(), Errno> {
        let Some(name_str) = name.to_str() else {
            return Err(Errno::ENODATA);
        };
        self.runtime.block_on(self.state.removexattr(ino, name_str))
    }

    /// Returns filesystem statistics for `statfs`.
    #[must_use]
    pub fn handle_statfs(&self) -> StatFsInfo {
        self.state.statfs()
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

impl Filesystem for ZeroVaultFuseFs {
    fn destroy(&mut self) {
        self.runtime.block_on_infallible(self.state.destroy());
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
        match self.runtime.block_on(self.state.opendir(ino.0)) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(errno) => reply.error(errno),
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
        self.state.releasedir(fh.0);
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
        match self.runtime.block_on(self.state.fsyncdir(ino.0, datasync)) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
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
        match self.handle_removexattr(ino.0, name) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        match self.runtime.block_on(self.state.access(ino.0)) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }
}
