//! Cross-platform on-demand virtual filesystem for Zerovault.
//!
//! Provides native Windows Cloud Files (`CfApi`) under `windows`, Arch Linux user-space
//! FUSE3 (`fuser`) under `linux`, and a cross-platform [`MockDrive`] test harness.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use zerovault_types::{DriveStats, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Constructs the native [`VirtualDrive`] adapter for the current host OS.
///
/// - Windows 10/11: [`windows::WindowsCfDrive`] (native `CfApi` sparse placeholders)
/// - Arch Linux / Linux: [`linux::LinuxFuseDrive`] (`fuser` unprivileged FUSE3 mount)
/// - Other platforms: [`MockDrive`] fallback
#[must_use]
pub fn create_platform_drive(backend: Arc<dyn VfsBackend>) -> Arc<dyn VirtualDrive> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(windows::WindowsCfDrive::new(backend))
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::LinuxFuseDrive::new(backend))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Arc::new(MockDrive::new(backend))
    }
}

/// Cross-platform virtual drive test harness delegating directly to a [`VfsBackend`].
pub struct MockDrive {
    backend: Arc<dyn VfsBackend>,
    mounted: AtomicBool,
    mount_point: RwLock<Option<PathBuf>>,
}

impl std::fmt::Debug for MockDrive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockDrive")
            .field("mounted", &self.mounted.load(Ordering::Relaxed))
            .field("mount_point", &*self.mount_point.read())
            .finish_non_exhaustive()
    }
}

impl MockDrive {
    /// Wraps a [`VfsBackend`] in a cross-platform [`MockDrive`].
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>) -> Self {
        Self {
            backend,
            mounted: AtomicBool::new(false),
            mount_point: RwLock::new(None),
        }
    }

    /// Accesses the underlying [`VfsBackend`] for deterministic file operations in tests.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn VfsBackend> {
        &self.backend
    }
}

#[async_trait]
impl VirtualDrive for MockDrive {
    async fn mount(&self, mount_point: PathBuf) -> ZeroVaultResult<()> {
        if self.mounted.swap(true, Ordering::AcqRel) {
            return Err(ZeroVaultError::VfsError(
                "MockDrive is already mounted".into(),
            ));
        }
        *self.mount_point.write() = Some(mount_point);
        Ok(())
    }

    async fn unmount(&self) -> ZeroVaultResult<()> {
        self.mounted.store(false, Ordering::Release);
        *self.mount_point.write() = None;
        Ok(())
    }

    fn is_mounted(&self) -> bool {
        self.mounted.load(Ordering::Acquire)
    }

    fn mount_point(&self) -> Option<PathBuf> {
        self.mount_point.read().clone()
    }

    async fn pin_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let rec = self.backend.resolve_path(virtual_path).await?;
        self.backend.pin(rec.inode).await
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let rec = self.backend.resolve_path(virtual_path).await?;
        self.backend.dehydrate(rec.inode).await
    }

    async fn notify_change(&self, _virtual_path: &str) -> ZeroVaultResult<()> {
        Ok(())
    }

    async fn stats(&self) -> ZeroVaultResult<DriveStats> {
        self.backend.drive_stats().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tempfile::TempDir;
    use zerovault_types::ROOT_INODE;
    use zerovault_types::mocks::MockVfsBackend;

    use super::*;

    #[tokio::test]
    async fn mock_drive_lifecycle_and_pin_dehydrate() {
        let backend = Arc::new(MockVfsBackend::new());
        let rec = backend
            .seed_remote_file(ROOT_INODE, "report.bin", b"zerovault-payload")
            .await
            .expect("seed");
        let drive = MockDrive::new(backend.clone());
        let dir = TempDir::new().expect("tempdir");

        drive.mount(dir.path().to_path_buf()).await.expect("mount");
        assert!(drive.is_mounted());
        assert_eq!(drive.mount_point(), Some(dir.path().to_path_buf()));

        drive.pin_path("/report.bin").await.expect("pin");
        assert!(drive.dehydrate_path("/report.bin").await.is_err());
        assert!(backend.getattr(rec.inode).await.expect("attr").pinned);

        drive.unmount().await.expect("unmount");
        assert!(!drive.is_mounted());
    }
}
