//! Arch Linux / Linux FUSE3 (`fuser v0.18`) virtual filesystem adapter and cross-platform
//! portable POSIX FUSE state-machine core.
//!
//! - [`portable`] compiles on **both** Windows and Linux, providing [`PortableFuseState`],
//!   zeroizing 4 MiB [`DirtyWriteBuffer`] (`NEW-M04` fix), `user.zerovault.{state,pin,file_id}`
//!   `xattr` handling with `unpin -> dehydrate` sequencing (`NEW-H02` / `VFS-2` fix),
//!   case-sensitive POSIX sibling entries (`CB-03` fix), and per-handle flush error latching.
//! - [`fs`] and [`drive`] (`#[cfg(target_os = "linux")]`) provide [`ZeroVaultFuseFs`] and
//!   [`LinuxFuseDrive`] implementing unprivileged user-space FUSE3 mounts.

#[cfg(target_os = "linux")]
pub mod drive;
#[cfg(target_os = "linux")]
pub mod fs;
pub mod portable;

#[cfg(target_os = "linux")]
pub use drive::LinuxFuseDrive;
#[cfg(target_os = "linux")]
pub use fs::{
    DirEntrySpec, LinuxFuseFilesystem, ZeroVaultFuseFs, error_to_errno, inode_to_file_attr,
    paginate_readdir_entries, portable_attr_to_file_attr,
};
pub use portable::{
    DirtyWriteBuffer, FUSE_BLOCK_SIZE, FUSE_MAX_NAME_LEN, LINUX_O_ACCMODE, LINUX_O_RDONLY,
    LINUX_O_RDWR, LINUX_O_TRUNC, LINUX_O_WRONLY, PortableAttr, PortableDirEntry, PortableErrno,
    PortableFuseState, PortableMtime, PortableOpenFlags, PortableRenameFlags, StatFsInfo,
    TrackedWriteOutcome, VIRTUAL_TOTAL_BLOCKS, VIRTUAL_TOTAL_FILES, XATTR_FLAG_CREATE,
    XATTR_FLAG_REPLACE, datetime_to_system_time, inode_to_portable_attr, paginate_portable_readdir,
    portable_error_to_errno, validate_posix_lookup_name, validate_posix_mutation_name,
    xattr_list_payload,
};
