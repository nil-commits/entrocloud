//! [`VirtualDrive`] lifecycle controller managing an unprivileged user-space FUSE3 mount.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use fuser::{BackgroundSession, Config, INodeNo, MountOption, Notifier, SessionACL};
use parking_lot::{Mutex, RwLock};
use tokio::runtime::{Handle, RuntimeFlavor};
use zerovault_types::{
    DriveStats, InodeId, ROOT_INODE, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult,
};

use super::fs::LinuxFuseFilesystem;

/// Arch Linux / Linux FUSE3 [`VirtualDrive`] backed by [`fuser::spawn_mount`].
pub struct LinuxFuseDrive {
    backend: Arc<dyn VfsBackend>,
    runtime_handle: Option<Handle>,
    mounted: AtomicBool,
    mount_point: RwLock<Option<PathBuf>>,
    session: Mutex<Option<BackgroundSession>>,
    notifier: Mutex<Option<Notifier>>,
    open_handles: Arc<AtomicU64>,
    lifecycle_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for LinuxFuseDrive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFuseDrive")
            .field("mounted", &self.mounted.load(Ordering::Relaxed))
            .field("has_session", &self.session.lock().is_some())
            .field("open_handles", &self.open_handles.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Drop for LinuxFuseDrive {
    fn drop(&mut self) {
        self.mounted.store(false, Ordering::Release);
        *self.notifier.lock() = None;
        *self.mount_point.write() = None;
        if let Some(session) = self.session.lock().take() {
            let _ = session.umount_and_join();
        }
    }
}

impl LinuxFuseDrive {
    /// Creates a new unmounted [`LinuxFuseDrive`] wrapping `backend`.
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>) -> Self {
        Self {
            backend,
            runtime_handle: None,
            mounted: AtomicBool::new(false),
            mount_point: RwLock::new(None),
            session: Mutex::new(None),
            notifier: Mutex::new(None),
            open_handles: Arc::new(AtomicU64::new(0)),
            lifecycle_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Creates a new unmounted [`LinuxFuseDrive`] bound explicitly to a Tokio [`Handle`].
    #[must_use]
    pub fn with_runtime_handle(backend: Arc<dyn VfsBackend>, handle: Handle) -> Self {
        Self {
            backend,
            runtime_handle: Some(handle),
            mounted: AtomicBool::new(false),
            mount_point: RwLock::new(None),
            session: Mutex::new(None),
            notifier: Mutex::new(None),
            open_handles: Arc::new(AtomicU64::new(0)),
            lifecycle_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Accesses the underlying [`VfsBackend`].
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn VfsBackend> {
        &self.backend
    }

    /// Returns the canonical unprivileged FUSE3 mount options used by Zerovault.
    #[must_use]
    pub fn mount_options() -> Vec<MountOption> {
        vec![
            MountOption::FSName("zerovault".to_owned()),
            MountOption::Subtype("zerovault".to_owned()),
            MountOption::NoAtime,
            MountOption::DefaultPermissions,
        ]
    }

    /// Builds the [`fuser::Config`] used when mounting the virtual drive.
    #[must_use]
    pub fn build_fuser_config() -> Config {
        let mut config = Config::default();
        config.mount_options = Self::mount_options();
        config.acl = SessionACL::Owner;
        config
    }

    fn resolve_runtime_handle(&self) -> Option<Handle> {
        if let Some(ref handle) = self.runtime_handle {
            return Some(handle.clone());
        }
        if let Ok(handle) = Handle::try_current()
            && matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread)
        {
            return Some(handle);
        }
        None
    }

    async fn invalidate_inode_best_effort(&self, inode: InodeId, flush_pages: bool) {
        let Some(notifier) = self.notifier.lock().clone() else {
            return;
        };
        let len = if flush_pages { 0 } else { -1 };
        let _ = tokio::task::spawn_blocking(move || {
            let _ = notifier.inval_inode(INodeNo(inode), 0, len);
        })
        .await;
    }
}

fn split_parent_and_name(virtual_path: &str) -> Option<(&str, &str)> {
    let trimmed = virtual_path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let idx = trimmed.rfind('/')?;
    let name = &trimmed[idx + 1..];
    if name.is_empty() {
        return None;
    }
    let parent = if idx == 0 { "/" } else { &trimmed[..idx] };
    Some((parent, name))
}

#[async_trait]
impl VirtualDrive for LinuxFuseDrive {
    async fn mount(&self, mount_point: PathBuf) -> ZeroVaultResult<()> {
        let _guard = self.lifecycle_lock.lock().await;
        if self.mounted.load(Ordering::Acquire) {
            return Err(ZeroVaultError::VfsError(
                "LinuxFuseDrive is already mounted".into(),
            ));
        }

        let meta = tokio::fs::metadata(&mount_point)
            .await
            .map_err(|err| ZeroVaultError::VfsError(format!("invalid mount point: {err}")))?;
        if !meta.is_dir() {
            return Err(ZeroVaultError::VfsError(
                "mount point must be an existing directory".into(),
            ));
        }

        let fs = LinuxFuseFilesystem::with_shared_handle_counter(
            Arc::clone(&self.backend),
            Arc::clone(&self.open_handles),
            self.resolve_runtime_handle(),
        );
        let config = Self::build_fuser_config();
        let mp = mount_point.clone();

        let session = tokio::task::spawn_blocking(move || fuser::spawn_mount(fs, &mp, &config))
            .await
            .map_err(|err| ZeroVaultError::VfsError(format!("FUSE mount task failed: {err}")))?
            .map_err(|err| ZeroVaultError::VfsError(format!("FUSE3 mount failed: {err}")))?;

        let notifier = session.notifier();
        *self.session.lock() = Some(session);
        *self.notifier.lock() = Some(notifier);
        *self.mount_point.write() = Some(mount_point);
        self.mounted.store(true, Ordering::Release);
        Ok(())
    }

    async fn unmount(&self) -> ZeroVaultResult<()> {
        let _guard = self.lifecycle_lock.lock().await;
        self.mounted.store(false, Ordering::Release);
        *self.notifier.lock() = None;
        *self.mount_point.write() = None;
        let session = self.session.lock().take();
        if let Some(session) = session {
            tokio::task::spawn_blocking(move || session.umount_and_join())
                .await
                .map_err(|err| {
                    ZeroVaultError::VfsError(format!("FUSE unmount task failed: {err}"))
                })?
                .map_err(|err| ZeroVaultError::VfsError(format!("FUSE3 unmount failed: {err}")))?;
        }
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
        self.backend.pin(rec.inode).await?;
        self.invalidate_inode_best_effort(rec.inode, false).await;
        Ok(())
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let rec = self.backend.resolve_path(virtual_path).await?;
        self.backend.dehydrate(rec.inode).await?;
        self.invalidate_inode_best_effort(rec.inode, true).await;
        Ok(())
    }

    async fn notify_change(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let Some(notifier) = self.notifier.lock().clone() else {
            return Ok(());
        };

        match self.backend.resolve_path(virtual_path).await {
            Ok(rec) => {
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = notifier.inval_inode(INodeNo(rec.inode), 0, 0);
                    if rec.inode != ROOT_INODE {
                        let _ =
                            notifier.inval_entry(INodeNo(rec.parent_inode), OsStr::new(&rec.name));
                    }
                })
                .await;
                Ok(())
            }
            Err(ZeroVaultError::InvalidPath(_) | ZeroVaultError::InodeNotFound(_)) => {
                if let Some((parent_path, name)) = split_parent_and_name(virtual_path)
                    && let Ok(parent) = self.backend.resolve_path(parent_path).await
                {
                    let name_owned = name.to_owned();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = notifier.inval_entry(INodeNo(parent.inode), OsStr::new(&name_owned));
                    })
                    .await;
                }
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn stats(&self) -> ZeroVaultResult<DriveStats> {
        let mut stats = self.backend.drive_stats().await?;
        stats.open_handles = stats
            .open_handles
            .max(self.open_handles.load(Ordering::Acquire));
        Ok(stats)
    }
}
