//! Cross-platform portable Linux FUSE3 state-machine, bounded zeroizing write coalescer,
//! POSIX `xattr` engine, case-sensitive path validator, and per-handle flush error latching.
//!
//! Compiled unconditionally on **both** Windows and Linux so deterministic unit tests,
//! `proptest` state-machine fuzzers, and `criterion` benchmarks execute natively on any host.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use zeroize::{Zeroize, Zeroizing};
use entrocloud_types::{
    CreateEntrySpec, EntryKind, HydrationState, InodeId, InodeRecord, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, SetAttrSpec, VfsBackend, XATTR_ZEROVAULT_FILE_ID, XATTR_ZEROVAULT_PIN,
    XATTR_ZEROVAULT_STATE, ZeroVaultError, validate_portable_entry_name,
};

/// Preferred filesystem block size (`st_blksize` / `f_bsize` = 4 KiB).
pub const FUSE_BLOCK_SIZE: u32 = 4096;
/// Maximum UTF-8 filename component byte length on POSIX FUSE mounts.
pub const FUSE_MAX_NAME_LEN: u32 = 255;
/// Virtual total 4 KiB blocks reported by `statfs` (1 TiB logical).
pub const VIRTUAL_TOTAL_BLOCKS: u64 = 268_435_456;
/// Virtual total file slots reported by `statfs`.
pub const VIRTUAL_TOTAL_FILES: u64 = 1_000_000;

/// Linux `XATTR_CREATE` flag (`0x1`): fail with `EEXIST` if attribute already exists.
pub const XATTR_FLAG_CREATE: i32 = 0x1;
/// Linux `XATTR_REPLACE` flag (`0x2`): replace existing attribute.
pub const XATTR_FLAG_REPLACE: i32 = 0x2;

/// Linux `O_ACCMODE` mask (`0o3`).
pub const LINUX_O_ACCMODE: i32 = 0o3;
/// Linux `O_RDONLY` access mode (`0o0`).
pub const LINUX_O_RDONLY: i32 = 0o0;
/// Linux `O_WRONLY` access mode (`0o1`).
pub const LINUX_O_WRONLY: i32 = 0o1;
/// Linux `O_RDWR` access mode (`0o2`).
pub const LINUX_O_RDWR: i32 = 0o2;
/// Linux `O_TRUNC` open flag (`0o1000`).
pub const LINUX_O_TRUNC: i32 = 0o1000;

/// Cross-platform POSIX/Linux errno representation shared between `PortableFuseState`
/// and `ZeroVaultFuseFs` (`fuser::Errno`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortableErrno {
    /// Operation not permitted (`EPERM = 1`).
    Eperm,
    /// No such file or directory (`ENOENT = 2`).
    Enoent,
    /// I/O error (`EIO = 5`).
    Eio,
    /// Bad file descriptor/handle (`EBADF = 9`).
    Ebadf,
    /// Resource temporarily unavailable / conflict (`EAGAIN = 11`).
    Eagain,
    /// Permission denied (`EACCES = 13`).
    Eacces,
    /// Device or resource busy (`EBUSY = 16`).
    Ebusy,
    /// File or attribute already exists (`EEXIST = 17`).
    Eexist,
    /// Not a directory (`ENOTDIR = 20`).
    Enotdir,
    /// Is a directory (`EISDIR = 21`).
    Eisdir,
    /// Invalid argument (`EINVAL = 22`).
    Einval,
    /// File too large (`EFBIG = 27`).
    Efbig,
    /// No space left on device / quota exceeded (`ENOSPC = 28`).
    Enospc,
    /// Result too large for caller buffer (`ERANGE = 34`).
    Erange,
    /// File name too long (`ENAMETOOLONG = 36`).
    Enametoolong,
    /// Function not implemented (`ENOSYS = 38`).
    Enosys,
    /// Directory not empty (`ENOTEMPTY = 39`).
    Enotempty,
    /// No data available / missing xattr (`ENODATA = 61`).
    Enodata,
    /// Value too large for defined data type (`EOVERFLOW = 75`).
    Eoverflow,
    /// Operation not supported (`ENOTSUP = 95`).
    Enotsup,
    /// Operation timed out (`ETIMEDOUT = 110`).
    Etimedout,
    /// Preserved positive raw OS errno code.
    Raw(i32),
}

impl PortableErrno {
    /// Returns the canonical positive Linux x86_64/generic errno integer.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Eperm => 1,
            Self::Enoent => 2,
            Self::Eio => 5,
            Self::Ebadf => 9,
            Self::Eagain => 11,
            Self::Eacces => 13,
            Self::Ebusy => 16,
            Self::Eexist => 17,
            Self::Enotdir => 20,
            Self::Eisdir => 21,
            Self::Einval => 22,
            Self::Efbig => 27,
            Self::Enospc => 28,
            Self::Erange => 34,
            Self::Enametoolong => 36,
            Self::Enosys => 38,
            Self::Enotempty => 39,
            Self::Enodata => 61,
            Self::Eoverflow => 75,
            Self::Enotsup => 95,
            Self::Etimedout => 110,
            Self::Raw(raw) => {
                if raw > 0 {
                    raw
                } else {
                    5
                }
            }
        }
    }

    /// Reconstructs a [`PortableErrno`] from a positive errno integer.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            1 => Self::Eperm,
            2 => Self::Enoent,
            5 => Self::Eio,
            9 => Self::Ebadf,
            11 => Self::Eagain,
            13 => Self::Eacces,
            16 => Self::Ebusy,
            17 => Self::Eexist,
            20 => Self::Enotdir,
            21 => Self::Eisdir,
            22 => Self::Einval,
            27 => Self::Efbig,
            28 => Self::Enospc,
            34 => Self::Erange,
            36 => Self::Enametoolong,
            38 => Self::Enosys,
            39 => Self::Enotempty,
            61 => Self::Enodata,
            75 => Self::Eoverflow,
            95 => Self::Enotsup,
            110 => Self::Etimedout,
            other if other > 0 => Self::Raw(other),
            _ => Self::Eio,
        }
    }
}

impl std::fmt::Display for PortableErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "POSIX errno {} ({self:?})", self.code())
    }
}

impl std::error::Error for PortableErrno {}

/// Maps a [`ZeroVaultError`] to its corresponding [`PortableErrno`].
#[must_use]
pub fn portable_error_to_errno(err: &ZeroVaultError) -> PortableErrno {
    match err {
        ZeroVaultError::InodeNotFound(_)
        | ZeroVaultError::InvalidPath(_)
        | ZeroVaultError::StorageNotFound(_) => PortableErrno::Enoent,
        ZeroVaultError::AlreadyExists(_) => PortableErrno::Eexist,
        ZeroVaultError::NotADirectory(_) => PortableErrno::Enotdir,
        ZeroVaultError::IsADirectory(_) => PortableErrno::Eisdir,
        ZeroVaultError::DirectoryNotEmpty(_) => PortableErrno::Enotempty,
        ZeroVaultError::PinnedDehydrationDenied(_) => PortableErrno::Ebusy,
        ZeroVaultError::VaultLocked
        | ZeroVaultError::InvalidPassphrase
        | ZeroVaultError::UnauthorizedRecipient(_) => PortableErrno::Eacces,
        ZeroVaultError::CryptoTamperDetected(_) => PortableErrno::Eio,
        ZeroVaultError::InvalidRange { .. } => PortableErrno::Einval,
        ZeroVaultError::StorageQuotaExceeded(_) => PortableErrno::Enospc,
        ZeroVaultError::StorageConflict(_) => PortableErrno::Eagain,
        ZeroVaultError::Io(io_err) => io_error_to_portable_errno(io_err),
        ZeroVaultError::HardwareAccelerationUnavailable(_)
        | ZeroVaultError::InvalidWireFormat(_)
        | ZeroVaultError::KdfPolicyViolation { .. }
        | ZeroVaultError::KeyringError(_)
        | ZeroVaultError::OAuthError(_)
        | ZeroVaultError::StorageBackendError(_)
        | ZeroVaultError::VfsError(_)
        | ZeroVaultError::MetadataError(_)
        | ZeroVaultError::IpcError(_)
        | ZeroVaultError::ConfigError(_) => PortableErrno::Eio,
    }
}

fn io_error_to_portable_errno(err: &std::io::Error) -> PortableErrno {
    #[cfg(target_os = "linux")]
    if let Some(raw) = err.raw_os_error()
        && raw > 0
    {
        return PortableErrno::from_code(raw);
    }
    match err.kind() {
        std::io::ErrorKind::NotFound => PortableErrno::Enoent,
        std::io::ErrorKind::PermissionDenied => PortableErrno::Eacces,
        std::io::ErrorKind::AlreadyExists => PortableErrno::Eexist,
        std::io::ErrorKind::InvalidInput => PortableErrno::Einval,
        std::io::ErrorKind::TimedOut => PortableErrno::Etimedout,
        std::io::ErrorKind::WouldBlock => PortableErrno::Eagain,
        std::io::ErrorKind::DirectoryNotEmpty => PortableErrno::Enotempty,
        std::io::ErrorKind::NotADirectory => PortableErrno::Enotdir,
        std::io::ErrorKind::IsADirectory => PortableErrno::Eisdir,
        std::io::ErrorKind::StorageFull => PortableErrno::Enospc,
        _ => {
            if let Some(raw) = err.raw_os_error()
                && raw > 0
            {
                PortableErrno::from_code(raw)
            } else {
                PortableErrno::Eio
            }
        }
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

/// Cross-platform POSIX inode attribute snapshot corresponding 1:1 with `fuser::FileAttr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableAttr {
    /// Virtual inode number.
    pub ino: InodeId,
    /// Logical file size in bytes.
    pub size: u64,
    /// Allocated 512-byte blocks (`div_ceil(512)`).
    pub blocks: u64,
    /// Last access timestamp.
    pub atime: SystemTime,
    /// Last modification timestamp.
    pub mtime: SystemTime,
    /// Last status change timestamp.
    pub ctime: SystemTime,
    /// Creation timestamp.
    pub crtime: SystemTime,
    /// Entry kind (regular file or directory).
    pub kind: EntryKind,
    /// Masked POSIX permission bits (`mode & 0o7777`).
    pub perm: u16,
    /// Hard link count (`2` for directories, `1` for regular files).
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Special device ID (`0`).
    pub rdev: u32,
    /// Preferred I/O block size (`4096`).
    pub blksize: u32,
    /// BSD flags (`0`).
    pub flags: u32,
}

/// Converts an [`InodeRecord`] into a [`PortableAttr`].
#[must_use]
pub fn inode_to_portable_attr(rec: &InodeRecord, uid: u32, gid: u32) -> PortableAttr {
    let nlink = if rec.kind == EntryKind::Directory {
        2
    } else {
        1
    };
    let mtime = datetime_to_system_time(rec.modified_at);
    let crtime = datetime_to_system_time(rec.created_at);
    PortableAttr {
        ino: rec.inode,
        size: rec.size,
        blocks: rec.size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime,
        kind: rec.kind,
        perm: (rec.mode & 0o7777) as u16,
        nlink,
        uid,
        gid,
        rdev: 0,
        blksize: FUSE_BLOCK_SIZE,
        flags: 0,
    }
}

/// Cross-platform paginated `readdir` item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableDirEntry {
    /// Entry inode number.
    pub ino: InodeId,
    /// Next stream cookie (`1` for `.`, `2` for `..`, `3..` for children).
    pub offset: u64,
    /// Entry file or directory kind.
    pub kind: EntryKind,
    /// Entry basename (exact POSIX case preserved).
    pub name: String,
}

/// Builds deterministic `.`, `..`, and child `readdir` entries starting after `offset`.
#[must_use]
pub fn paginate_portable_readdir(
    dir: &InodeRecord,
    children: &[InodeRecord],
    offset: u64,
) -> Vec<PortableDirEntry> {
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push(PortableDirEntry {
        ino: dir.inode,
        offset: 1,
        kind: EntryKind::Directory,
        name: ".".to_owned(),
    });
    let parent_ino = if dir.inode == ROOT_INODE {
        ROOT_INODE
    } else {
        dir.parent_inode
    };
    entries.push(PortableDirEntry {
        ino: parent_ino,
        offset: 2,
        kind: EntryKind::Directory,
        name: "..".to_owned(),
    });
    for (idx, child) in children.iter().enumerate() {
        entries.push(PortableDirEntry {
            ino: child.inode,
            offset: (idx + 3) as u64,
            kind: child.kind,
            name: child.name.clone(),
        });
    }
    let skip = usize::try_from(offset).unwrap_or(usize::MAX);
    entries.into_iter().skip(skip).collect()
}

/// Returns the NUL-separated `listxattr` payload advertising all ZeroVault extended attributes:
/// `user.zerovault.state\0user.zerovault.pin\0user.zerovault.file_id\0`.
#[must_use]
pub fn xattr_list_payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(
        XATTR_ZEROVAULT_STATE.len()
            + 1
            + XATTR_ZEROVAULT_PIN.len()
            + 1
            + XATTR_ZEROVAULT_FILE_ID.len()
            + 1,
    );
    out.extend_from_slice(XATTR_ZEROVAULT_STATE.as_bytes());
    out.push(0);
    out.extend_from_slice(XATTR_ZEROVAULT_PIN.as_bytes());
    out.push(0);
    out.extend_from_slice(XATTR_ZEROVAULT_FILE_ID.as_bytes());
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

/// Portable open flags specification decoded from POSIX `open(2)` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableOpenFlags {
    /// Whether the handle permits writes (`O_WRONLY` or `O_RDWR`).
    pub write_access: bool,
    /// Whether `O_TRUNC` was requested on open.
    pub truncate: bool,
    /// Raw POSIX open flags integer.
    pub raw_flags: i32,
}

impl PortableOpenFlags {
    /// Decodes standard Linux `O_*` bitflags.
    #[must_use]
    pub const fn from_linux_flags(flags: i32) -> Self {
        let acc = flags & LINUX_O_ACCMODE;
        let write_access = acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR;
        let truncate = (flags & LINUX_O_TRUNC) != 0;
        Self {
            write_access,
            truncate,
            raw_flags: flags,
        }
    }

    /// Read-only open (`O_RDONLY`).
    #[must_use]
    pub const fn read_only() -> Self {
        Self::from_linux_flags(LINUX_O_RDONLY)
    }

    /// Read-write open (`O_RDWR`).
    #[must_use]
    pub const fn read_write() -> Self {
        Self::from_linux_flags(LINUX_O_RDWR)
    }

    /// Write-truncate open (`O_RDWR | O_TRUNC`).
    #[must_use]
    pub const fn read_write_truncate() -> Self {
        Self::from_linux_flags(LINUX_O_RDWR | LINUX_O_TRUNC)
    }
}

/// Portable `renameat2(2)` flags representation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortableRenameFlags {
    /// Fail with `EEXIST` if the destination already exists (`RENAME_NOREPLACE`).
    pub noreplace: bool,
    /// Atomically exchange source and destination (`RENAME_EXCHANGE` — unsupported, returns `EINVAL`).
    pub exchange: bool,
    /// Create whiteout object (`RENAME_WHITEOUT` — unsupported, returns `EINVAL`).
    pub whiteout: bool,
}

impl PortableRenameFlags {
    /// Standard POSIX `rename(2)` (overwrite allowed).
    pub const NONE: Self = Self {
        noreplace: false,
        exchange: false,
        whiteout: false,
    };

    /// `RENAME_NOREPLACE`: reject overwrite with `EEXIST`.
    pub const NOREPLACE: Self = Self {
        noreplace: true,
        exchange: false,
        whiteout: false,
    };

    /// `RENAME_EXCHANGE`.
    pub const EXCHANGE: Self = Self {
        noreplace: false,
        exchange: true,
        whiteout: false,
    };
}

/// Portable modification timestamp specifier for `setattr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableMtime {
    /// Stamp with current wall-clock UTC time.
    Now,
    /// Stamp with explicit `SystemTime`.
    Specific(SystemTime),
}

/// Detailed result of a tracked async write into [`DirtyWriteBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedWriteOutcome {
    /// Number of bytes from the caller's slice accepted before returning.
    pub bytes_accepted: usize,
    /// Deferred flush error encountered after accepting partial bytes (must be latched on `fh`).
    pub deferred_flush_error: Option<PortableErrno>,
    /// True if flushing previously acknowledged buffered bytes failed before accepting new bytes.
    pub prior_buffer_flush_failed: bool,
}

fn scrub_zeroize_vec(buf: &mut Zeroizing<Vec<u8>>) {
    let cap = buf.capacity();
    if cap > 0 {
        buf.resize(cap, 0);
        buf.zeroize();
    }
}

fn scrub_truncate_vec(buf: &mut Zeroizing<Vec<u8>>, new_len: usize) {
    let cap = buf.capacity();
    if cap > new_len {
        buf.resize(cap, 0);
        buf[new_len..cap].zeroize();
        buf.truncate(new_len);
    } else {
        buf.truncate(new_len);
    }
}

fn scrub_drain_prefix(buf: &mut Zeroizing<Vec<u8>>, count: usize) {
    let drain_len = count.min(buf.len());
    if drain_len == 0 {
        return;
    }
    buf.drain(..drain_len);
    let rem_len = buf.len();
    scrub_truncate_vec(buf, rem_len);
}

/// Bounded per-handle dirty write buffer capped strictly at [`PLAINTEXT_CHUNK_SIZE`] (4 MiB).
///
/// ### Security Remediation (`NEW-M04`)
/// - Stores plaintext inside [`Zeroizing<Vec<u8>>`].
/// - Every clear, partial drain, error rollback, capacity growth, and [`Drop`] resizes or wipes
///   `0..capacity` to `0` and invokes [`Zeroize::zeroize`], ensuring zero residual plaintext
///   ever remains in initialized slices, spare `Vec` capacity, or reallocated heap blocks.
pub struct DirtyWriteBuffer {
    start_offset: Option<u64>,
    buf: Zeroizing<Vec<u8>>,
    chunk_size: usize,
    last_write_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for DirtyWriteBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirtyWriteBuffer")
            .field("start_offset", &self.start_offset)
            .field("buffered_len", &self.buf.len())
            .field("capacity", &self.buf.capacity())
            .field("chunk_size", &self.chunk_size)
            .field("last_write_at", &self.last_write_at)
            .finish()
    }
}

impl Default for DirtyWriteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DirtyWriteBuffer {
    fn drop(&mut self) {
        self.zeroize_and_clear();
    }
}

impl DirtyWriteBuffer {
    /// Creates an empty dirty write buffer with the canonical 4 MiB chunk threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_offset: None,
            buf: Zeroizing::new(Vec::new()),
            chunk_size: PLAINTEXT_CHUNK_SIZE,
            last_write_at: None,
        }
    }

    /// Explicitly resizes `0..capacity` to `0`, calls `zeroize()`, and resets offset metadata.
    pub fn zeroize_and_clear(&mut self) {
        scrub_zeroize_vec(&mut self.buf);
        self.start_offset = None;
        self.last_write_at = None;
    }

    /// Returns the number of dirty bytes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns the current heap allocation capacity in bytes (`<= PLAINTEXT_CHUNK_SIZE`).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Returns `(as_ptr, capacity)` for empirical zeroization verification in tests.
    #[must_use]
    pub fn raw_allocation_range(&self) -> (*const u8, usize) {
        (self.buf.as_ptr(), self.buf.capacity())
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

    /// Writes `data` at `offset`, invoking synchronous `flush_fn(flush_offset, slice)` whenever
    /// flushing is required due to non-contiguity, reaching `PLAINTEXT_CHUNK_SIZE`, or crossing
    /// a 4 MiB chunk boundary.
    pub fn write_with<E, F>(
        &mut self,
        offset: u64,
        data: &[u8],
        mut flush_fn: F,
    ) -> Result<usize, E>
    where
        E: From<PortableErrno>,
        F: FnMut(u64, &[u8]) -> Result<usize, E>,
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
                        let accepted = n.min(take);
                        total_written += accepted;
                        if accepted < take {
                            return Ok(total_written);
                        }
                        cur_offset = cur_offset.saturating_add(accepted as u64);
                        remaining = &remaining[accepted..];
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
                    Ok(n) if n >= self.buf.len() => {
                        self.zeroize_and_clear();
                        total_written += take;
                        cur_offset = cur_offset.saturating_add(take as u64);
                        remaining = &remaining[take..];
                    }
                    Ok(n) => {
                        scrub_drain_prefix(&mut self.buf, n);
                        self.start_offset = Some(flush_start.saturating_add(n as u64));
                        return if total_written > 0 {
                            Ok(total_written)
                        } else {
                            Err(PortableErrno::Eio.into())
                        };
                    }
                    Err(err) => {
                        scrub_truncate_vec(&mut self.buf, prev_len);
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

    /// Flushes any remaining dirty bytes in this buffer via synchronous `flush_fn`, zeroizing
    /// all buffer and spare-capacity bytes on completion.
    pub fn flush_with<E, F>(&mut self, mut flush_fn: F) -> Result<(), E>
    where
        E: From<PortableErrno>,
        F: FnMut(u64, &[u8]) -> Result<usize, E>,
    {
        let Some(start) = self.start_offset else {
            return Ok(());
        };
        if self.buf.is_empty() {
            self.zeroize_and_clear();
            return Ok(());
        }
        let written = flush_fn(start, &self.buf)?;
        if written < self.buf.len() {
            scrub_drain_prefix(&mut self.buf, written);
            self.start_offset = Some(start.saturating_add(written as u64));
            return Err(PortableErrno::Eio.into());
        }
        self.zeroize_and_clear();
        Ok(())
    }

    /// Asynchronously flushes any buffered dirty bytes directly to [`VfsBackend::write_range`],
    /// scrubbing and zeroizing `0..capacity` on completion.
    pub async fn flush_to_backend(
        &mut self,
        backend: &dyn VfsBackend,
        ino: InodeId,
    ) -> Result<(), PortableErrno> {
        let Some(start) = self.start_offset else {
            return Ok(());
        };
        if self.buf.is_empty() {
            self.zeroize_and_clear();
            return Ok(());
        }
        let written = backend
            .write_range(ino, start, &self.buf)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        if written < self.buf.len() {
            scrub_drain_prefix(&mut self.buf, written);
            self.start_offset = Some(start.saturating_add(written as u64));
            return Err(PortableErrno::Eio);
        }
        self.zeroize_and_clear();
        Ok(())
    }

    /// Asynchronously writes `data` at `offset` to `backend` with 4 MiB chunk coalescing and
    /// tracks deferred/prior-buffer flush errors for POSIX `close(2)` / `release` error latching.
    pub async fn write_to_backend_tracked(
        &mut self,
        backend: &dyn VfsBackend,
        ino: InodeId,
        offset: u64,
        data: &[u8],
    ) -> Result<TrackedWriteOutcome, (PortableErrno, bool)> {
        if data.is_empty() {
            return Ok(TrackedWriteOutcome {
                bytes_accepted: 0,
                deferred_flush_error: None,
                prior_buffer_flush_failed: false,
            });
        }

        if let Some(end) = self.end_offset()
            && offset != end
            && let Err(err) = self.flush_to_backend(backend, ino).await
        {
            return Err((err, true));
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

            if self.start_offset.is_none() && (reaches_boundary || take >= self.chunk_size) {
                let slice = &remaining[..take];
                match backend.write_range(ino, cur_offset, slice).await {
                    Ok(n) => {
                        let accepted = n.min(take);
                        total_written += accepted;
                        if accepted < take {
                            return Ok(TrackedWriteOutcome {
                                bytes_accepted: total_written,
                                deferred_flush_error: Some(PortableErrno::Eio),
                                prior_buffer_flush_failed: false,
                            });
                        }
                        cur_offset = cur_offset.saturating_add(accepted as u64);
                        remaining = &remaining[accepted..];
                    }
                    Err(err) => {
                        let errno = portable_error_to_errno(&err);
                        return if total_written > 0 {
                            Ok(TrackedWriteOutcome {
                                bytes_accepted: total_written,
                                deferred_flush_error: Some(errno),
                                prior_buffer_flush_failed: false,
                            })
                        } else {
                            Err((errno, false))
                        };
                    }
                }
                continue;
            }

            let prev_len = self.buf.len();
            let prev_start = self.start_offset;
            let prev_ts = self.last_write_at;
            let had_prior_buffered = prev_len > 0;
            if self.start_offset.is_none() {
                self.start_offset = Some(cur_offset);
            }
            self.reserve_bounded(take);
            self.buf.extend_from_slice(&remaining[..take]);
            self.last_write_at = Some(Utc::now());

            if reaches_boundary || self.buf.len() >= self.chunk_size {
                let flush_start = self.start_offset.unwrap_or(cur_offset);
                match backend.write_range(ino, flush_start, &self.buf).await {
                    Ok(n) if n >= self.buf.len() => {
                        self.zeroize_and_clear();
                        total_written += take;
                        cur_offset = cur_offset.saturating_add(take as u64);
                        remaining = &remaining[take..];
                    }
                    Ok(n) => {
                        scrub_drain_prefix(&mut self.buf, n);
                        self.start_offset = Some(flush_start.saturating_add(n as u64));
                        return if total_written > 0 {
                            Ok(TrackedWriteOutcome {
                                bytes_accepted: total_written,
                                deferred_flush_error: Some(PortableErrno::Eio),
                                prior_buffer_flush_failed: had_prior_buffered,
                            })
                        } else {
                            Err((PortableErrno::Eio, had_prior_buffered))
                        };
                    }
                    Err(err) => {
                        let errno = portable_error_to_errno(&err);
                        scrub_truncate_vec(&mut self.buf, prev_len);
                        self.start_offset = prev_start;
                        self.last_write_at = prev_ts;
                        return if total_written > 0 {
                            Ok(TrackedWriteOutcome {
                                bytes_accepted: total_written,
                                deferred_flush_error: Some(errno),
                                prior_buffer_flush_failed: had_prior_buffered,
                            })
                        } else {
                            Err((errno, had_prior_buffered))
                        };
                    }
                }
            } else {
                total_written += take;
                cur_offset = cur_offset.saturating_add(take as u64);
                remaining = &remaining[take..];
            }
        }

        Ok(TrackedWriteOutcome {
            bytes_accepted: total_written,
            deferred_flush_error: None,
            prior_buffer_flush_failed: false,
        })
    }

    fn reserve_bounded(&mut self, additional: usize) {
        let needed = self.buf.len().saturating_add(additional);
        if self.buf.capacity() >= needed {
            return;
        }
        let doubled = self.buf.capacity().saturating_mul(2);
        let target = needed.max(doubled).min(self.chunk_size);
        if self.buf.is_empty() {
            scrub_zeroize_vec(&mut self.buf);
            let extra = target.saturating_sub(self.buf.len());
            self.buf.reserve_exact(extra);
        } else {
            // Allocate new bounded buffer, copy initialized plaintext, and scrub-zeroize the
            // previous allocation BEFORE dropping it so realloc never leaves plaintext in RAM.
            let mut next = Zeroizing::new(Vec::with_capacity(target));
            next.extend_from_slice(&self.buf);
            scrub_zeroize_vec(&mut self.buf);
            self.buf = next;
        }
    }
}

struct OpenFileHandle {
    ino: InodeId,
    _flags: i32,
    dirty: tokio::sync::Mutex<DirtyWriteBuffer>,
    buffered_bytes: AtomicUsize,
    has_dirty: AtomicBool,
    dirty_end_offset: AtomicU64,
    dirty_mtime_nanos: AtomicI64,
    latched_error: AtomicI32,
}

impl OpenFileHandle {
    fn new(ino: InodeId, flags: i32) -> Self {
        Self {
            ino,
            _flags: flags,
            dirty: tokio::sync::Mutex::new(DirtyWriteBuffer::new()),
            buffered_bytes: AtomicUsize::new(0),
            has_dirty: AtomicBool::new(false),
            dirty_end_offset: AtomicU64::new(0),
            dirty_mtime_nanos: AtomicI64::new(0),
            latched_error: AtomicI32::new(0),
        }
    }

    fn sync_shadow_from_buffer(&self, dirty: &DirtyWriteBuffer) {
        self.buffered_bytes.store(dirty.len(), Ordering::Release);
        if let Some(end) = dirty.end_offset() {
            self.dirty_end_offset.store(end, Ordering::Release);
            let nanos = dirty
                .last_write_at()
                .and_then(|dt| dt.timestamp_nanos_opt())
                .unwrap_or(0);
            self.dirty_mtime_nanos.store(nanos, Ordering::Release);
            self.has_dirty.store(true, Ordering::Release);
        } else {
            self.dirty_end_offset.store(0, Ordering::Release);
            self.dirty_mtime_nanos.store(0, Ordering::Release);
            self.has_dirty.store(false, Ordering::Release);
        }
    }

    fn latch_error(&self, errno: PortableErrno) {
        let code = errno.code();
        let _ =
            self.latched_error
                .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }

    fn peek_error(&self) -> Option<PortableErrno> {
        let code = self.latched_error.load(Ordering::Acquire);
        if code > 0 {
            Some(PortableErrno::from_code(code))
        } else {
            None
        }
    }
}

/// Validates a single POSIX entry component name for lookup/unlink/rmdir.
/// Preserves exact POSIX case (`Makefile` vs `makefile`) via `validate_portable_entry_name(name, false)`.
pub fn validate_posix_lookup_name(name: &str) -> Result<(), PortableErrno> {
    if name.len() > FUSE_MAX_NAME_LEN as usize {
        return Err(PortableErrno::Enametoolong);
    }
    validate_portable_entry_name(name, false).map_err(|_| PortableErrno::Enoent)
}

/// Validates a single POSIX entry component name for create/mkdir/rename.
/// Preserves exact POSIX case (`Makefile` vs `makefile`) via `validate_portable_entry_name(name, false)`.
pub fn validate_posix_mutation_name(name: &str) -> Result<(), PortableErrno> {
    if name.len() > FUSE_MAX_NAME_LEN as usize {
        return Err(PortableErrno::Enametoolong);
    }
    validate_portable_entry_name(name, false).map_err(|_| PortableErrno::Einval)
}

/// Cross-platform async Linux FUSE3 state core.
///
/// Implements the complete ZeroVault POSIX FUSE state machine (`lookup`, `getattr`, `setattr`,
/// `create`, `mkdir`, `unlink`, `rmdir`, `rename`, `open`, `read`, `write`, `flush`, `fsync`,
/// `release`, `opendir`, `readdir`, `releasedir`, `fsyncdir`, `listxattr`, `getxattr`, `setxattr`,
/// `removexattr`, `access`, `statfs`, `destroy`), including:
/// - 4 MiB zeroizing write coalescing (`NEW-M04` fix),
/// - `user.zerovault.{state,pin,file_id}` `xattr` handling with `unpin -> dehydrate` sequencing (`NEW-H02` / `VFS-2` fix),
/// - Case-sensitive POSIX sibling entries (`CB-03` fix),
/// - Per-`fh` flush error latching for POSIX `close(2)` / `release` reporting.
pub struct PortableFuseState {
    backend: Arc<dyn VfsBackend>,
    handles: DashMap<u64, Arc<OpenFileHandle>>,
    dir_handles: DashMap<u64, InodeId>,
    next_fh: AtomicU64,
    active_file_handles: Arc<AtomicU64>,
    uid: u32,
    gid: u32,
}

impl std::fmt::Debug for PortableFuseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableFuseState")
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

impl PortableFuseState {
    /// Constructs a new [`PortableFuseState`] owned by `(uid, gid)`.
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>, uid: u32, gid: u32) -> Self {
        Self::with_shared_handle_counter(backend, Arc::new(AtomicU64::new(0)), uid, gid)
    }

    /// Constructs a [`PortableFuseState`] sharing an external `active_file_handles` gauge.
    #[must_use]
    pub fn with_shared_handle_counter(
        backend: Arc<dyn VfsBackend>,
        active_file_handles: Arc<AtomicU64>,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self {
            backend,
            handles: DashMap::new(),
            dir_handles: DashMap::new(),
            next_fh: AtomicU64::new(1),
            active_file_handles,
            uid,
            gid,
        }
    }

    /// Borrows the underlying [`VfsBackend`].
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn VfsBackend> {
        &self.backend
    }

    /// Returns the owner UID reported in attributes.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.uid
    }

    /// Returns the owner GID reported in attributes.
    #[must_use]
    pub const fn owner_gid(&self) -> u32 {
        self.gid
    }

    /// Returns the number of currently open file handles.
    #[must_use]
    pub fn active_file_handle_count(&self) -> u64 {
        self.active_file_handles.load(Ordering::Acquire)
    }

    /// Returns the number of currently open directory handles.
    #[must_use]
    pub fn active_dir_handle_count(&self) -> usize {
        self.dir_handles.len()
    }

    /// Returns the number of currently buffered dirty bytes on file handle `fh`.
    #[must_use]
    pub fn buffered_dirty_bytes(&self, fh: u64) -> usize {
        let Some(handle) = self.handles.get(&fh) else {
            return 0;
        };
        handle.buffered_bytes.load(Ordering::Acquire)
    }

    /// Explicitly latches a background flush error onto file handle `fh` so POSIX `close(2)`
    /// (`flush` / `release`) reports it. Returns `true` if `fh` is currently open.
    pub fn latch_handle_error(&self, fh: u64, errno: PortableErrno) -> bool {
        let Some(handle) = self.handles.get(&fh) else {
            return false;
        };
        handle.latch_error(errno);
        true
    }

    /// Explicitly latches a background flush error onto all open file handles for `ino`.
    /// Returns the number of handles updated.
    pub fn latch_inode_error(&self, ino: InodeId, errno: PortableErrno) -> usize {
        let mut count = 0usize;
        for entry in &self.handles {
            if entry.value().ino == ino {
                entry.value().latch_error(errno);
                count += 1;
            }
        }
        count
    }

    /// Peeks the currently latched flush error on file handle `fh`, if any.
    #[must_use]
    pub fn peek_latched_error(&self, fh: u64) -> Option<PortableErrno> {
        self.handles.get(&fh).and_then(|h| h.peek_error())
    }

    /// Performs a background flush of handle `fh` (and `VfsBackend::flush`), latching any
    /// error onto `fh` so a subsequent `flush` / `release` (`close(2)`) surfaces it.
    pub async fn flush_handle_background(&self, fh: u64) -> Result<(), PortableErrno> {
        let Some(handle) = self.handles.get(&fh).map(|e| Arc::clone(e.value())) else {
            return Err(PortableErrno::Ebadf);
        };
        self.flush_single_handle(&handle, true).await?;
        if let Err(err) = self.backend.flush(handle.ino).await {
            let errno = portable_error_to_errno(&err);
            handle.latch_error(errno);
            return Err(errno);
        }
        Ok(())
    }

    /// Performs a background flush of all open handles for `ino`, latching any error onto
    /// the affected handle(s).
    pub async fn flush_inode_background(&self, ino: InodeId) -> Result<(), PortableErrno> {
        self.flush_dirty_handles_for_inode(ino).await?;
        if let Err(err) = self.backend.flush(ino).await {
            let errno = portable_error_to_errno(&err);
            let _ = self.latch_inode_error(ino, errno);
            return Err(errno);
        }
        Ok(())
    }

    fn allocate_handle(&self, ino: InodeId, flags: i32) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles
            .insert(fh, Arc::new(OpenFileHandle::new(ino, flags)));
        self.active_file_handles.fetch_add(1, Ordering::AcqRel);
        fh
    }

    async fn flush_single_handle(
        &self,
        handle: &OpenFileHandle,
        latch_on_err: bool,
    ) -> Result<(), PortableErrno> {
        let mut dirty = handle.dirty.lock().await;
        let res = dirty
            .flush_to_backend(self.backend.as_ref(), handle.ino)
            .await;
        handle.sync_shadow_from_buffer(&dirty);
        if let Err(errno) = res
            && latch_on_err
        {
            handle.latch_error(errno);
        }
        res
    }

    async fn flush_dirty_handles_for_inode(&self, ino: InodeId) -> Result<(), PortableErrno> {
        let matching: Vec<Arc<OpenFileHandle>> = self
            .handles
            .iter()
            .filter(|entry| entry.value().ino == ino)
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        for handle in matching {
            self.flush_single_handle(&handle, true).await?;
        }
        Ok(())
    }

    fn dirty_summary_for_inode(&self, ino: InodeId) -> Option<(u64, DateTime<Utc>)> {
        let mut max_end: Option<u64> = None;
        let mut max_nanos: Option<i64> = None;
        for entry in &self.handles {
            let h = entry.value();
            if h.ino == ino && h.has_dirty.load(Ordering::Acquire) {
                let end = h.dirty_end_offset.load(Ordering::Acquire);
                let nanos = h.dirty_mtime_nanos.load(Ordering::Acquire);
                max_end = Some(max_end.map_or(end, |prev| prev.max(end)));
                if nanos > 0 {
                    max_nanos = Some(max_nanos.map_or(nanos, |prev| prev.max(nanos)));
                }
            }
        }
        max_end.map(|end| {
            let ts = max_nanos.map_or_else(Utc::now, |ns| Utc.timestamp_nanos(ns));
            (end, ts)
        })
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

    fn to_portable_attr(&self, rec: &InodeRecord) -> PortableAttr {
        inode_to_portable_attr(rec, self.uid, self.gid)
    }

    /// Resolves `(parent, name)` with exact POSIX case sensitivity.
    pub async fn lookup(&self, parent: InodeId, name: &str) -> Result<PortableAttr, PortableErrno> {
        validate_posix_lookup_name(name)?;
        let mut rec = self
            .backend
            .lookup(parent, name)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        self.apply_dirty_summary(&mut rec);
        Ok(self.to_portable_attr(&rec))
    }

    /// Fetches attributes for `ino`, incorporating buffered dirty write extents.
    pub async fn getattr(&self, ino: InodeId) -> Result<PortableAttr, PortableErrno> {
        let mut rec = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        self.apply_dirty_summary(&mut rec);
        Ok(self.to_portable_attr(&rec))
    }

    /// Updates inode attributes (`size`, `mode`, `mtime`), flushing dirty handles first.
    pub async fn setattr(
        &self,
        ino: InodeId,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        mtime: Option<PortableMtime>,
    ) -> Result<PortableAttr, PortableErrno> {
        if uid.is_some_and(|u| u != self.uid) || gid.is_some_and(|g| g != self.gid) {
            return Err(PortableErrno::Eperm);
        }

        self.flush_dirty_handles_for_inode(ino).await?;

        let modified_at = mtime.map(|t| match t {
            PortableMtime::Now => Utc::now(),
            PortableMtime::Specific(st) => DateTime::<Utc>::from(st),
        });
        let spec = SetAttrSpec {
            size,
            mode: mode.map(|m| m & 0o7777),
            modified_at,
        };
        let rec = self
            .backend
            .setattr(ino, spec)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        Ok(self.to_portable_attr(&rec))
    }

    /// Creates and opens a regular file with exact POSIX case preservation (`CB-03` fix).
    pub async fn create(
        &self,
        parent: InodeId,
        name: &str,
        mode: u32,
        flags: i32,
    ) -> Result<(PortableAttr, u64), PortableErrno> {
        validate_posix_mutation_name(name)?;
        let spec = CreateEntrySpec {
            parent_inode: parent,
            name: name.to_owned(),
            mode: mode & 0o7777,
        };
        let rec = self
            .backend
            .create_entry(spec)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        let fh = self.allocate_handle(rec.inode, flags);
        Ok((self.to_portable_attr(&rec), fh))
    }

    /// Creates a directory under `parent` with exact POSIX case preservation.
    pub async fn mkdir(
        &self,
        parent: InodeId,
        name: &str,
        mode: u32,
    ) -> Result<PortableAttr, PortableErrno> {
        validate_posix_mutation_name(name)?;
        let rec = self
            .backend
            .mkdir(parent, name, mode & 0o7777)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        Ok(self.to_portable_attr(&rec))
    }

    /// Unlinks a regular file under `parent`.
    pub async fn unlink(&self, parent: InodeId, name: &str) -> Result<(), PortableErrno> {
        validate_posix_lookup_name(name)?;
        self.backend
            .unlink(parent, name)
            .await
            .map_err(|err| portable_error_to_errno(&err))
    }

    /// Removes an empty directory under `parent`.
    pub async fn rmdir(&self, parent: InodeId, name: &str) -> Result<(), PortableErrno> {
        validate_posix_lookup_name(name)?;
        self.backend
            .rmdir(parent, name)
            .await
            .map_err(|err| portable_error_to_errno(&err))
    }

    /// Moves or renames an entry atomically, enforcing `RENAME_NOREPLACE`, `RENAME_EXCHANGE`,
    /// POSIX file-vs-directory overwrite rules, and flushing buffered writes on the source inode.
    pub async fn rename(
        &self,
        parent: InodeId,
        old_name: &str,
        newparent: InodeId,
        new_name: &str,
        flags: PortableRenameFlags,
    ) -> Result<(), PortableErrno> {
        if flags.exchange || flags.whiteout {
            return Err(PortableErrno::Einval);
        }
        validate_posix_lookup_name(old_name)?;
        validate_posix_mutation_name(new_name)?;

        let src = self
            .backend
            .lookup(parent, old_name)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        self.flush_dirty_handles_for_inode(src.inode).await?;

        match self.backend.lookup(newparent, new_name).await {
            Ok(dst) => {
                if flags.noreplace {
                    return Err(PortableErrno::Eexist);
                }
                if dst.inode == src.inode {
                    return Ok(());
                }
                match (src.kind, dst.kind) {
                    (EntryKind::Directory, EntryKind::File) => return Err(PortableErrno::Enotdir),
                    (EntryKind::File, EntryKind::Directory) => return Err(PortableErrno::Eisdir),
                    (EntryKind::Directory, EntryKind::Directory) => {
                        let children = self
                            .backend
                            .readdir(dst.inode)
                            .await
                            .map_err(|err| portable_error_to_errno(&err))?;
                        if !children.is_empty() {
                            return Err(PortableErrno::Enotempty);
                        }
                        self.backend
                            .rmdir(newparent, new_name)
                            .await
                            .map_err(|err| portable_error_to_errno(&err))?;
                    }
                    (EntryKind::File, EntryKind::File) => {
                        self.flush_dirty_handles_for_inode(dst.inode).await?;
                        self.backend
                            .unlink(newparent, new_name)
                            .await
                            .map_err(|err| portable_error_to_errno(&err))?;
                    }
                }
            }
            Err(ZeroVaultError::InodeNotFound(_)) => {}
            Err(err) => return Err(portable_error_to_errno(&err)),
        }

        self.backend
            .rename(parent, old_name, newparent, new_name)
            .await
            .map(|_| ())
            .map_err(|err| portable_error_to_errno(&err))
    }

    /// Opens an existing file and allocates a tracked handle ID.
    pub async fn open(&self, ino: InodeId, flags: PortableOpenFlags) -> Result<u64, PortableErrno> {
        let rec = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        if rec.kind == EntryKind::Directory {
            return Err(PortableErrno::Eisdir);
        }
        if flags.truncate {
            if !flags.write_access {
                return Err(PortableErrno::Eacces);
            }
            self.flush_dirty_handles_for_inode(ino).await?;
            self.backend
                .setattr(
                    ino,
                    SetAttrSpec {
                        size: Some(0),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
        }
        Ok(self.allocate_handle(ino, flags.raw_flags))
    }

    /// Reads `[offset, offset + size)` via bounded `<= 4 MiB` `VfsBackend::read_range` calls
    /// after flushing any buffered dirty writes on `ino`.
    pub async fn read(
        &self,
        ino: InodeId,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, PortableErrno> {
        self.flush_dirty_handles_for_inode(ino).await?;
        let requested = size as usize;
        if requested == 0 {
            let _ = self
                .backend
                .read_range(ino, offset, 0)
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
            return Ok(Vec::new());
        }
        if requested <= PLAINTEXT_CHUNK_SIZE {
            let data: Bytes = self
                .backend
                .read_range(ino, offset, requested)
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
            return Ok(data.to_vec());
        }

        let mut out = Vec::new();
        let mut cur_offset = offset;
        let mut remaining = requested;
        while remaining > 0 {
            let slice_len = remaining.min(PLAINTEXT_CHUNK_SIZE);
            let chunk = self
                .backend
                .read_range(ino, cur_offset, slice_len)
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
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

    /// Writes `data` at `offset` through the per-handle bounded 4 MiB zeroizing [`DirtyWriteBuffer`],
    /// latching any background/deferred flush failures onto `fh` for `close(2)` reporting.
    pub async fn write(
        &self,
        ino: InodeId,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, PortableErrno> {
        if offset.checked_add(data.len() as u64).is_none() {
            return Err(PortableErrno::Efbig);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let maybe_handle = self.handles.get(&fh).map(|entry| Arc::clone(entry.value()));
        let written = if let Some(handle) = maybe_handle {
            if handle.ino != ino {
                return Err(PortableErrno::Ebadf);
            }
            let mut dirty = handle.dirty.lock().await;
            let res = dirty
                .write_to_backend_tracked(self.backend.as_ref(), ino, offset, data)
                .await;
            handle.sync_shadow_from_buffer(&dirty);
            drop(dirty);

            match res {
                Ok(outcome) => {
                    if let Some(deferred_err) = outcome.deferred_flush_error {
                        handle.latch_error(deferred_err);
                    }
                    outcome.bytes_accepted
                }
                Err((errno, prior_failed)) => {
                    if prior_failed {
                        handle.latch_error(errno);
                    }
                    return Err(errno);
                }
            }
        } else {
            self.write_unbuffered_bounded(ino, offset, data).await?
        };

        u32::try_from(written).map_err(|_| PortableErrno::Eoverflow)
    }

    async fn write_unbuffered_bounded(
        &self,
        ino: InodeId,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, PortableErrno> {
        let mut total_written = 0usize;
        let mut cur_offset = offset;
        let mut remaining = data;
        while !remaining.is_empty() {
            let slice_len = remaining.len().min(PLAINTEXT_CHUNK_SIZE);
            let n = self
                .backend
                .write_range(ino, cur_offset, &remaining[..slice_len])
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
            total_written += n;
            if n < slice_len {
                break;
            }
            cur_offset = cur_offset.saturating_add(n as u64);
            remaining = &remaining[n..];
        }
        Ok(total_written)
    }

    /// Flushes dirty buffered writes on `fh`, invokes `VfsBackend::flush`, and surfaces any
    /// previously latched background flush error for POSIX `close(2)`.
    pub async fn flush(&self, ino: InodeId, fh: u64) -> Result<(), PortableErrno> {
        let maybe_handle = self.handles.get(&fh).map(|entry| Arc::clone(entry.value()));
        if let Some(ref handle) = maybe_handle {
            if handle.ino != ino {
                return Err(PortableErrno::Ebadf);
            }
            self.flush_single_handle(handle, true).await?;
        }
        if let Err(err) = self.backend.flush(ino).await {
            let errno = portable_error_to_errno(&err);
            if let Some(ref handle) = maybe_handle {
                handle.latch_error(errno);
            }
            return Err(errno);
        }
        if let Some(ref handle) = maybe_handle
            && let Some(latched) = handle.peek_error()
        {
            return Err(latched);
        }
        Ok(())
    }

    /// Flushes all dirty buffers for `ino`, invokes `VfsBackend::fsync`, and surfaces any
    /// latched flush error on `fh`.
    pub async fn fsync(&self, ino: InodeId, fh: u64, datasync: bool) -> Result<(), PortableErrno> {
        let maybe_handle = self.handles.get(&fh).map(|entry| Arc::clone(entry.value()));
        if let Some(ref handle) = maybe_handle {
            if handle.ino != ino {
                return Err(PortableErrno::Ebadf);
            }
            self.flush_single_handle(handle, true).await?;
        }
        self.flush_dirty_handles_for_inode(ino).await?;
        if let Err(err) = self.backend.fsync(ino, datasync).await {
            let errno = portable_error_to_errno(&err);
            if let Some(ref handle) = maybe_handle {
                handle.latch_error(errno);
            }
            return Err(errno);
        }
        if let Some(ref handle) = maybe_handle
            && let Some(latched) = handle.peek_error()
        {
            return Err(latched);
        }
        Ok(())
    }

    /// Releases `fh`, removing the handle, flushing remaining dirty bytes (zeroizing capacity),
    /// calling `VfsBackend::flush`, and reporting any latched flush error.
    pub async fn release(&self, ino: InodeId, fh: u64) -> Result<(), PortableErrno> {
        let mut had_dirty = false;
        let mut first_err: Option<PortableErrno> = None;

        if let Some((_, handle)) = self.handles.remove(&fh) {
            self.active_file_handles.fetch_sub(1, Ordering::AcqRel);
            had_dirty = handle.has_dirty.load(Ordering::Acquire);
            if let Some(latched) = handle.peek_error() {
                first_err = Some(latched);
            }
            if let Err(flush_err) = self.flush_single_handle(&handle, false).await
                && first_err.is_none()
            {
                first_err = Some(flush_err);
            }
            // Explicitly ensure zeroization of spare capacity before handle drops.
            handle.dirty.lock().await.zeroize_and_clear();
        }

        match self.backend.flush(ino).await {
            Ok(()) => {}
            Err(ZeroVaultError::InodeNotFound(_)) if !had_dirty && first_err.is_none() => {}
            Err(err) => {
                if first_err.is_none() {
                    first_err = Some(portable_error_to_errno(&err));
                }
            }
        }

        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Opens a directory inode and returns a tracked directory handle ID.
    pub async fn opendir(&self, ino: InodeId) -> Result<u64, PortableErrno> {
        let rec = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        if rec.kind != EntryKind::Directory {
            return Err(PortableErrno::Enotdir);
        }
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.dir_handles.insert(fh, ino);
        Ok(fh)
    }

    /// Lists paginated directory entries (`.` + `..` + children) starting after `offset`.
    pub async fn readdir(
        &self,
        ino: InodeId,
        offset: u64,
    ) -> Result<Vec<PortableDirEntry>, PortableErrno> {
        let dir = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        if dir.kind != EntryKind::Directory {
            return Err(PortableErrno::Enotdir);
        }
        let children = self
            .backend
            .readdir(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        Ok(paginate_portable_readdir(&dir, &children, offset))
    }

    /// Releases a directory handle allocated by [`Self::opendir`].
    pub fn releasedir(&self, fh: u64) {
        self.dir_handles.remove(&fh);
    }

    /// Synchronizes directory metadata on `ino`.
    pub async fn fsyncdir(&self, ino: InodeId, datasync: bool) -> Result<(), PortableErrno> {
        self.backend
            .fsync(ino, datasync)
            .await
            .map_err(|err| portable_error_to_errno(&err))
    }

    /// Lists ZeroVault extended attributes (`user.zerovault.state`, `pin`, `file_id`) for `ino`.
    pub async fn listxattr(&self, ino: InodeId) -> Result<Vec<u8>, PortableErrno> {
        let _ = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        Ok(xattr_list_payload())
    }

    /// Reads `user.zerovault.state`, `user.zerovault.pin`, or `user.zerovault.file_id` on `ino`.
    pub async fn getxattr(&self, ino: InodeId, name: &str) -> Result<Vec<u8>, PortableErrno> {
        let rec = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;

        match name {
            XATTR_ZEROVAULT_STATE => {
                let state = if self.dirty_summary_for_inode(ino).is_some() {
                    HydrationState::DirtyLocal
                } else {
                    self.backend
                        .get_xattr_state(ino)
                        .await
                        .map_err(|err| portable_error_to_errno(&err))?
                };
                Ok(state.as_xattr_str().as_bytes().to_vec())
            }
            XATTR_ZEROVAULT_PIN => {
                let val = if rec.pinned { b"1" } else { b"0" };
                Ok(val.to_vec())
            }
            XATTR_ZEROVAULT_FILE_ID => Ok(rec.file_id.to_string().into_bytes()),
            _ => Err(PortableErrno::Enodata),
        }
    }

    /// Updates `user.zerovault.pin` on `ino`.
    ///
    /// ### Security & Usability Fix (`NEW-H02` / `VFS-2`)
    /// - `b"1" | b"true" | b"pin"` (case-insensitive): flushes dirty writes and pins `ino` offline.
    /// - `b"0" | b"false" | b"unpin"` (case-insensitive): flushes dirty writes, **calls
    ///   `backend.unpin(ino)` first**, and then calls `backend.dehydrate(ino)` so previously
    ///   pinned files unpin and dehydrate cleanly without failing with `EBUSY`!
    pub async fn setxattr(
        &self,
        ino: InodeId,
        name: &str,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<(), PortableErrno> {
        if position != 0 {
            return Err(PortableErrno::Einval);
        }
        if name == XATTR_ZEROVAULT_STATE || name == XATTR_ZEROVAULT_FILE_ID {
            return Err(PortableErrno::Eacces);
        }
        if name != XATTR_ZEROVAULT_PIN {
            return Err(PortableErrno::Enotsup);
        }
        if (flags & !(XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE)) != 0 {
            return Err(PortableErrno::Einval);
        }
        if (flags & XATTR_FLAG_CREATE) != 0 {
            return Err(PortableErrno::Eexist);
        }

        let had_buffered_dirty = self.dirty_summary_for_inode(ino).is_some();

        if value == b"1" || value.eq_ignore_ascii_case(b"true") || value.eq_ignore_ascii_case(b"pin")
        {
            self.flush_dirty_handles_for_inode(ino).await?;
            if had_buffered_dirty {
                self.backend
                    .flush(ino)
                    .await
                    .map_err(|err| portable_error_to_errno(&err))?;
            }
            self.backend
                .pin(ino)
                .await
                .map_err(|err| portable_error_to_errno(&err))
        } else if value == b"0"
            || value.eq_ignore_ascii_case(b"false")
            || value.eq_ignore_ascii_case(b"unpin")
        {
            self.flush_dirty_handles_for_inode(ino).await?;
            if had_buffered_dirty {
                self.backend
                    .flush(ino)
                    .await
                    .map_err(|err| portable_error_to_errno(&err))?;
            }
            self.backend
                .unpin(ino)
                .await
                .map_err(|err| portable_error_to_errno(&err))?;
            self.backend
                .dehydrate(ino)
                .await
                .map_err(|err| portable_error_to_errno(&err))
        } else {
            Err(PortableErrno::Einval)
        }
    }

    /// Handles `removexattr` on `ino` (virtual ZeroVault attributes are non-removable -> `EPERM`).
    pub async fn removexattr(&self, ino: InodeId, name: &str) -> Result<(), PortableErrno> {
        let _ = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        match name {
            XATTR_ZEROVAULT_STATE | XATTR_ZEROVAULT_PIN | XATTR_ZEROVAULT_FILE_ID => {
                Err(PortableErrno::Eperm)
            }
            _ => Err(PortableErrno::Enodata),
        }
    }

    /// Validates `access(2)` against `ino`.
    pub async fn access(&self, ino: InodeId) -> Result<(), PortableErrno> {
        let _ = self
            .backend
            .getattr(ino)
            .await
            .map_err(|err| portable_error_to_errno(&err))?;
        Ok(())
    }

    /// Returns filesystem statistics for `statfs`.
    #[must_use]
    pub const fn statfs(&self) -> StatFsInfo {
        StatFsInfo {
            blocks: VIRTUAL_TOTAL_BLOCKS,
            bfree: VIRTUAL_TOTAL_BLOCKS,
            bavail: VIRTUAL_TOTAL_BLOCKS,
            files: VIRTUAL_TOTAL_FILES,
            ffree: VIRTUAL_TOTAL_FILES.saturating_sub(1),
            bsize: FUSE_BLOCK_SIZE,
            namelen: FUSE_MAX_NAME_LEN,
            frsize: FUSE_BLOCK_SIZE,
        }
    }

    /// Flushes and zeroizes all remaining open file handles on FUSE session teardown (`destroy`).
    pub async fn destroy(&self) {
        let remaining: Vec<(u64, Arc<OpenFileHandle>)> = self
            .handles
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect();
        for (fh, handle) in remaining {
            if self.handles.remove(&fh).is_some() {
                self.active_file_handles.fetch_sub(1, Ordering::AcqRel);
            }
            let _ = self.flush_single_handle(&handle, false).await;
            handle.dirty.lock().await.zeroize_and_clear();
            let _ = self.backend.flush(handle.ino).await;
        }
        self.dir_handles.clear();
    }
}
