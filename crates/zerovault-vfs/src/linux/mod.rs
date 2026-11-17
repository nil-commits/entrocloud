//! Linux FUSE3 (`fuser`) virtual filesystem adapter.
//!
//! Provides [`LinuxFuseFilesystem`] implementing [`fuser::Filesystem`] and
//! [`LinuxFuseDrive`] implementing [`zerovault_types::VirtualDrive`] for
//! unprivileged user-space FUSE3 mounts on Arch Linux and other Linux distros.

pub mod drive;
pub mod fs;

pub use drive::LinuxFuseDrive;
pub use fs::{
    DirEntrySpec, DirtyWriteBuffer, LinuxFuseFilesystem, StatFsInfo, datetime_to_system_time,
    error_to_errno, inode_to_file_attr, paginate_readdir_entries, xattr_list_payload,
};
