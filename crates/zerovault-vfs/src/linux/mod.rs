//! Linux FUSE3 (`fuser`) virtual filesystem adapter.
//!
//! Wave 0 stub — implemented by `Agent-VFS-Linux` in Wave 1.

use std::sync::Arc;
use zerovault_types::VfsBackend;

/// Placeholder handle during Wave 0; replaced by `LinuxFuseDrive` in Wave 1.
pub struct LinuxFuseDriveStub {
    _backend: Arc<dyn VfsBackend>,
}
