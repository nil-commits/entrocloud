//! [`VirtualDrive`] lifecycle controller managing an unprivileged user-space FUSE3 mount.

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use fuser::{BackgroundSession, Config, INodeNo, MountOption, Notifier, SessionACL};
use parking_lot::{Mutex, RwLock};
use tokio::runtime::{Handle, RuntimeFlavor};
use entrocloud_types::{
    DriveStats, InodeId, ROOT_INODE, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult,
    normalize_virtual_path,
};

use super::fs::ZeroVaultFuseFs;

/// Arch Linux / Linux FUSE3 [`VirtualDrive`] backed by [`fuser::spawn_mount`] (`fuser v0.18`).
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
            match Handle::try_current() {
                Ok(handle) if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) => {
                    tokio::task::block_in_place(|| {
                        let _ = session.umount_and_join();
                    });
                }
                Ok(_) => {
                    let _ = std::thread::Builder::new()
                        .name("zerovault-fuse-umount".into())
                        .spawn(move || {
                            let _ = session.umount_and_join();
                        });
                }
                Err(_) => {
                    let _ = session.umount_and_join();
                }
            }
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

    /// Returns the full unprivileged FUSE3 mount options including `AutoUnmount`.
    #[must_use]
    pub fn mount_options() -> Vec<MountOption> {
        vec![
            MountOption::FSName("zerovault".to_owned()),
            MountOption::Subtype("zerovault".to_owned()),
            MountOption::NoAtime,
            MountOption::DefaultPermissions,
            MountOption::AutoUnmount,
        ]
    }

    /// Returns the strict owner-only mount options for hosts without `user_allow_other` in `/etc/fuse.conf`.
    #[must_use]
    pub fn owner_mount_options() -> Vec<MountOption> {
        vec![
            MountOption::FSName("zerovault".to_owned()),
            MountOption::Subtype("zerovault".to_owned()),
            MountOption::NoAtime,
            MountOption::DefaultPermissions,
        ]
    }

    /// Builds the strict owner-isolated [`fuser::Config`] (`SessionACL::Owner`).
    #[must_use]
    pub fn build_fuser_config() -> Config {
        let mut config = Config::default();
        config.mount_options = Self::owner_mount_options();
        config.acl = SessionACL::Owner;
        config
    }

    /// Builds the opportunistic crash-safe `AutoUnmount` [`fuser::Config`].
    ///
    /// Note: `fuser v0.18` requires `acl != SessionACL::Owner` when `MountOption::AutoUnmount`
    /// is present so `fusermount3` can maintain the auto-unmount socket. When `/etc/fuse.conf`
    /// does not permit `user_allow_other`, [`Self::mount`] automatically falls back to
    /// [`Self::build_fuser_config`] (`SessionACL::Owner`).
    #[must_use]
    pub fn build_auto_unmount_config() -> Config {
        let mut config = Config::default();
        config.mount_options = Self::mount_options();
        config.acl = SessionACL::RootAndOwner;
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

fn should_fallback_to_owner_acl(err: &std::io::Error) -> bool {
    if matches!(err.kind(), ErrorKind::PermissionDenied | ErrorKind::InvalidInput) {
        return true;
    }
    let msg = err.to_string();
    msg.contains("user_allow_other") || msg.contains("allow_other") || msg.contains("auto_unmount")
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

        let shared_state = ZeroVaultFuseFs::new_shared_state(
            Arc::clone(&self.backend),
            Arc::clone(&self.open_handles),
        );
        let rt_handle = self.resolve_runtime_handle();
        let auto_config = Self::build_auto_unmount_config();
        let owner_config = Self::build_fuser_config();
        let mp = mount_point.clone();

        let session = tokio::task::spawn_blocking(move || {
            let fs_auto =
                ZeroVaultFuseFs::with_shared_state(Arc::clone(&shared_state), rt_handle.clone());
            match fuser::spawn_mount(fs_auto, &mp, &auto_config) {
                Ok(sess) => Ok(sess),
                Err(auto_err) if should_fallback_to_owner_acl(&auto_err) => {
                    tracing::debug!(
                        error = %auto_err,
                        "AutoUnmount requires user_allow_other; falling back to SessionACL::Owner"
                    );
                    let fs_owner = ZeroVaultFuseFs::with_shared_state(shared_state, rt_handle);
                    fuser::spawn_mount(fs_owner, &mp, &owner_config)
                }
                Err(err) => Err(err),
            }
        })
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
        let norm = normalize_virtual_path(virtual_path)?;
        let rec = self.backend.resolve_path(&norm).await?;
        self.backend.pin(rec.inode).await?;
        self.invalidate_inode_best_effort(rec.inode, false).await;
        Ok(())
    }

    async fn unpin_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let norm = normalize_virtual_path(virtual_path)?;
        let rec = self.backend.resolve_path(&norm).await?;
        self.backend.unpin(rec.inode).await?;
        self.invalidate_inode_best_effort(rec.inode, false).await;
        Ok(())
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let norm = normalize_virtual_path(virtual_path)?;
        let rec = self.backend.resolve_path(&norm).await?;
        self.backend.dehydrate(rec.inode).await?;
        self.invalidate_inode_best_effort(rec.inode, true).await;
        Ok(())
    }

    async fn notify_change(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let norm = normalize_virtual_path(virtual_path)?;
        let Some(notifier) = self.notifier.lock().clone() else {
            return Ok(());
        };

        match self.backend.resolve_path(&norm).await {
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
                if let Some((parent_path, name)) = split_parent_and_name(&norm)
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
