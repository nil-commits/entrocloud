//! Windows Cloud Files API (`cloud-filter`) virtual filesystem adapter.
//!
//! Wave 0 stub — implemented by `Agent-VFS-Windows` in Wave 1.

use std::sync::Arc;
use zerovault_types::VfsBackend;

/// Placeholder handle during Wave 0; replaced by `WindowsCfDrive` in Wave 1.
pub struct WindowsCfDriveStub {
    _backend: Arc<dyn VfsBackend>,
}
