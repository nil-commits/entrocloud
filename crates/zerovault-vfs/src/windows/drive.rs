//! Windows Cloud Filter (`VirtualDrive`) mount lifecycle controller.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use cloud_filter::placeholder::{ConvertOptions, PinOptions, PinState, Placeholder, UpdateOptions};
use cloud_filter::placeholder_create_info::BatchCreate;
use cloud_filter::root::{
    Connection, HydrationPolicy, HydrationType, PopulationType, ProtectionMode, SecurityId,
    Session, SupportedAttribute, SyncRootId, SyncRootIdBuilder, SyncRootInfo,
};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, warn};
use windows::Win32::Storage::CloudFilters::CF_MAX_PROVIDER_NAME_LENGTH;
use zerovault_types::{
    DriveStats, EntryKind, InodeRecord, ROOT_INODE, VfsBackend, VirtualDrive, ZeroVaultError,
    ZeroVaultResult,
};

use super::filter::WindowsCfFilter;
use super::placeholder::{
    FileIdentity, metadata_from_record, placeholder_create_info_from_record,
    virtual_path_to_windows_path, win32_error_to_vfs,
};

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

trait ConnectedSession: Send {
    fn connection_key(&self) -> i64;
}

impl<F: Send + Sync> ConnectedSession for Connection<F> {
    fn connection_key(&self) -> i64 {
        Connection::connection_key(self)
    }
}

/// Configuration for registering and connecting a Windows Cloud Filter sync root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCfConfig {
    /// Sync provider identifier registered with Windows Cloud Filter (max 255 UTF-16 units, no `!`).
    pub provider_name: String,
    /// Stable account identifier segment in the `SyncRootId` triple (must not contain `!`).
    pub account_name: String,
    /// Display name shown in Windows File Explorer navigation pane.
    pub display_name: String,
    /// Provider version string shown in sync root properties.
    pub version: String,
    /// Win32 icon resource path (e.g. `%SystemRoot%\system32\imageres.dll,-1043`).
    pub icon_resource: String,
    /// Whether `unmount()` unregisters the sync root from Windows Shell in addition to disconnecting.
    pub unregister_on_unmount: bool,
}

impl Default for WindowsCfConfig {
    fn default() -> Self {
        Self {
            provider_name: "Zerovault".to_owned(),
            account_name: "default".to_owned(),
            display_name: "Zerovault".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            icon_resource: r"%SystemRoot%\system32\imageres.dll,-1043".to_owned(),
            unregister_on_unmount: false,
        }
    }
}

impl WindowsCfConfig {
    /// Validates provider/account identifiers against `CfApi` sync-root ID restrictions.
    pub fn validate(&self) -> ZeroVaultResult<()> {
        if self.provider_name.is_empty()
            || self.provider_name.contains('!')
            || self.provider_name.encode_utf16().count() > CF_MAX_PROVIDER_NAME_LENGTH as usize
        {
            return Err(ZeroVaultError::ConfigError(format!(
                "invalid Windows Cloud Filter provider_name: {:?}",
                self.provider_name
            )));
        }
        if self.account_name.is_empty() || self.account_name.contains('!') {
            return Err(ZeroVaultError::ConfigError(format!(
                "invalid Windows Cloud Filter account_name: {:?}",
                self.account_name
            )));
        }
        if self.display_name.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "display_name cannot be empty".into(),
            ));
        }
        if self.version.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "version cannot be empty".into(),
            ));
        }
        if self.icon_resource.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "icon_resource cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

struct ActiveMount {
    sync_root_id: SyncRootId,
    connection: Box<dyn ConnectedSession>,
    watcher_task: tokio::task::JoinHandle<()>,
}

/// Windows Cloud Files API (`CfApi`) implementation of [`VirtualDrive`].
pub struct WindowsCfDrive {
    backend: Arc<dyn VfsBackend>,
    config: WindowsCfConfig,
    lifecycle_lock: tokio::sync::Mutex<()>,
    mounted: AtomicBool,
    mount_point: RwLock<Option<PathBuf>>,
    active: Mutex<Option<ActiveMount>>,
}

impl std::fmt::Debug for WindowsCfDrive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsCfDrive")
            .field("config", &self.config)
            .field("mounted", &self.mounted.load(Ordering::Relaxed))
            .field("mount_point", &*self.mount_point.read())
            .finish_non_exhaustive()
    }
}

impl WindowsCfDrive {
    /// Wraps a [`VfsBackend`] with default [`WindowsCfConfig`].
    #[must_use]
    pub fn new(backend: Arc<dyn VfsBackend>) -> Self {
        Self::with_config(backend, WindowsCfConfig::default())
    }

    /// Wraps a [`VfsBackend`] with explicit [`WindowsCfConfig`].
    #[must_use]
    pub fn with_config(backend: Arc<dyn VfsBackend>, config: WindowsCfConfig) -> Self {
        Self {
            backend,
            config,
            lifecycle_lock: tokio::sync::Mutex::new(()),
            mounted: AtomicBool::new(false),
            mount_point: RwLock::new(None),
            active: Mutex::new(None),
        }
    }

    /// Returns a reference to the active [`WindowsCfConfig`].
    #[must_use]
    pub fn config(&self) -> &WindowsCfConfig {
        &self.config
    }

    /// Accesses the underlying [`VfsBackend`].
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn VfsBackend> {
        &self.backend
    }

    /// Returns the active Cloud Filter connection key when mounted.
    #[must_use]
    pub fn connection_key(&self) -> Option<i64> {
        self.active
            .lock()
            .as_ref()
            .map(|mount| mount.connection.connection_key())
    }

    /// Builds the `provider-id!security-id!account-name` [`SyncRootId`] for the current user.
    pub fn build_sync_root_id(&self) -> ZeroVaultResult<SyncRootId> {
        self.config.validate()?;
        let security_id = SecurityId::current_user()
            .map_err(|err| win32_error_to_vfs("query current user SID", err))?;
        Ok(SyncRootIdBuilder::new(&self.config.provider_name)
            .user_security_id(security_id)
            .account_name(&self.config.account_name)
            .build())
    }

    /// Builds a [`SyncRootInfo`] configured for progressive hydration, Storage Sense callbacks,
    /// full on-demand directory population, and user pinning.
    pub fn build_sync_root_info(&self, mount_point: &Path) -> ZeroVaultResult<SyncRootInfo> {
        self.config.validate()?;
        let info = SyncRootInfo::default()
            .with_display_name(&self.config.display_name)
            .with_version(&self.config.version)
            .with_icon(&self.config.icon_resource)
            .with_allow_pinning(true)
            .with_hydration_type(HydrationType::Progressive)
            .with_hydration_policy(
                HydrationPolicy::StreamingAllowed | HydrationPolicy::AutoDehydrationAllowed,
            )
            .with_population_type(PopulationType::Full)
            .with_protection_mode(ProtectionMode::Personal)
            .with_supported_attribute(
                SupportedAttribute::FileCreationTime
                    | SupportedAttribute::FileLastWriteTime
                    | SupportedAttribute::DirectoryLastWriteTime
                    | SupportedAttribute::PreserveInSyncForSyncEngine,
            )
            .with_blob(b"zerovault-sync-root-v1")
            .with_path(mount_point)
            .map_err(|err| win32_error_to_vfs("set sync root path", err))?;
        Ok(info)
    }
}

fn block_on_tokio(handle: &tokio::runtime::Handle, fut: LocalBoxFuture<'_, ()>) {
    if tokio::runtime::Handle::try_current().is_ok()
        && matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    {
        tokio::task::block_in_place(|| handle.block_on(fut));
    } else {
        handle.block_on(fut);
    }
}

fn create_or_reconcile_placeholder(parent_dir: &Path, rec: &InodeRecord) -> ZeroVaultResult<()> {
    let dest = parent_dir.join(&rec.name);
    if dest.exists() {
        let mut placeholder = Placeholder::open(&dest)
            .map_err(|err| win32_error_to_vfs("open existing entry for placeholder check", err))?;
        let is_placeholder = placeholder
            .info()
            .map_err(|err| win32_error_to_vfs("query placeholder info", err))?
            .is_some();
        let identity = FileIdentity::from_record(rec);
        if !is_placeholder {
            let mut opts = ConvertOptions::default()
                .blob(identity.to_vec())
                .mark_in_sync();
            if rec.kind == EntryKind::Directory {
                opts = opts.has_children();
            }
            placeholder
                .convert_to_placeholder(opts, None)
                .map_err(|err| win32_error_to_vfs("convert entry to placeholder", err))?;
        } else {
            let meta = metadata_from_record(rec);
            let blob = identity.encode();
            placeholder
                .update(
                    UpdateOptions::default()
                        .metadata(meta)
                        .blob(&blob)
                        .mark_in_sync(),
                    None,
                )
                .map_err(|err| win32_error_to_vfs("update placeholder metadata", err))?;
        }

        if rec.pinned && rec.kind == EntryKind::File {
            let _ = placeholder.mark_pin(PinState::Pinned, PinOptions::default());
        }
        return Ok(());
    }

    let info = placeholder_create_info_from_record(rec)?;
    info.create(parent_dir)
        .map_err(|err| win32_error_to_vfs("create initial sparse placeholder", err))?;

    if rec.pinned
        && rec.kind == EntryKind::File
        && let Ok(mut ph) = Placeholder::open(&dest)
    {
        let _ = ph.mark_pin(PinState::Pinned, PinOptions::default());
    }
    Ok(())
}

async fn populate_initial_root_placeholders(
    mount_point: &Path,
    backend: &dyn VfsBackend,
) -> ZeroVaultResult<()> {
    let root_children = backend.readdir(ROOT_INODE).await?;
    if root_children.is_empty() {
        return Ok(());
    }

    let mut to_create = Vec::new();
    let mut existing = Vec::new();

    for rec in root_children {
        if mount_point.join(&rec.name).exists() {
            existing.push(rec);
        } else {
            to_create.push(rec);
        }
    }

    let mount_owned = mount_point.to_path_buf();
    tokio::task::spawn_blocking(move || -> ZeroVaultResult<()> {
        if !to_create.is_empty() {
            let mut batch = Vec::with_capacity(to_create.len());
            for rec in &to_create {
                batch.push(placeholder_create_info_from_record(rec)?);
            }
            batch
                .as_mut_slice()
                .create(&mount_owned)
                .map_err(|err| win32_error_to_vfs("create root placeholders", err))?;
            for rec in &to_create {
                if rec.pinned
                    && rec.kind == EntryKind::File
                    && let Ok(mut ph) = Placeholder::open(mount_owned.join(&rec.name))
                {
                    let _ = ph.mark_pin(PinState::Pinned, PinOptions::default());
                }
            }
        }

        for rec in &existing {
            create_or_reconcile_placeholder(&mount_owned, rec)?;
        }
        Ok(())
    })
    .await
    .map_err(|err| ZeroVaultError::VfsError(format!("initial placeholder task failed: {err}")))??;

    Ok(())
}

fn update_local_pin_state(local_path: &Path, pinned: bool, dehydrate: bool) -> ZeroVaultResult<()> {
    if !local_path.exists() {
        return Ok(());
    }

    if dehydrate {
        let mut ph = Placeholder::options()
            .exclusive()
            .open(local_path)
            .map_err(|err| win32_error_to_vfs("open placeholder exclusively for dehydrate", err))?;
        ph.mark_pin(PinState::Unpinned, PinOptions::default())
            .map_err(|err| win32_error_to_vfs("set unpinned state", err))?;
        ph.update(UpdateOptions::default().dehydrate().mark_in_sync(), None)
            .map_err(|err| win32_error_to_vfs("dehydrate local placeholder", err))?;
        return Ok(());
    }

    let mut ph = Placeholder::open(local_path)
        .map_err(|err| win32_error_to_vfs("open placeholder for pin", err))?;
    let state = if pinned {
        PinState::Pinned
    } else {
        PinState::Unpinned
    };
    ph.mark_pin(state, PinOptions::default())
        .map_err(|err| win32_error_to_vfs("set pin state", err))?;
    ph.mark_in_sync(true, None)
        .map_err(|err| win32_error_to_vfs("mark placeholder in sync", err))?;
    Ok(())
}

#[async_trait]
impl VirtualDrive for WindowsCfDrive {
    async fn mount(&self, mount_point: PathBuf) -> ZeroVaultResult<()> {
        let _guard = self.lifecycle_lock.lock().await;
        if self.mounted.load(Ordering::Acquire) {
            return Err(ZeroVaultError::VfsError(
                "WindowsCfDrive is already mounted".into(),
            ));
        }

        tokio::fs::create_dir_all(&mount_point).await?;
        let abs_mount = std::path::absolute(&mount_point)?;

        let sync_root_id = self.build_sync_root_id()?;
        let needs_register = match sync_root_id.is_registered() {
            Ok(false) => true,
            Ok(true) => sync_root_id
                .info()
                .map(|existing| existing.path() != abs_mount)
                .unwrap_or(true),
            Err(err) => return Err(win32_error_to_vfs("query sync root registration", err)),
        };

        if needs_register {
            let info = self.build_sync_root_info(&abs_mount)?;
            sync_root_id
                .register(info)
                .map_err(|err| win32_error_to_vfs("register sync root", err))?;
        }

        populate_initial_root_placeholders(&abs_mount, &*self.backend).await?;

        let rt_handle = tokio::runtime::Handle::current();
        let (filter, watcher_task) =
            WindowsCfFilter::with_background_watcher(Arc::clone(&self.backend), abs_mount.clone(), &rt_handle);

        let connect_path = abs_mount.clone();
        let connect_handle = rt_handle.clone();
        let connection = tokio::task::spawn_blocking(move || {
            Session::new()
                .block_implicit_hydration()
                .connect_async(connect_path, filter, move |fut| {
                    block_on_tokio(&connect_handle, fut);
                })
        })
        .await
        .map_err(|err| ZeroVaultError::VfsError(format!("CfConnectSyncRoot task failed: {err}")))?
        .map_err(|err| win32_error_to_vfs("connect Windows Cloud Filter session", err))?;

        debug!(
            connection_key = connection.connection_key(),
            mount_point = %abs_mount.display(),
            "Windows Cloud Filter sync root connected"
        );

        *self.mount_point.write() = Some(abs_mount);
        *self.active.lock() = Some(ActiveMount {
            sync_root_id,
            connection: Box::new(connection),
            watcher_task,
        });
        self.mounted.store(true, Ordering::Release);
        Ok(())
    }

    async fn unmount(&self) -> ZeroVaultResult<()> {
        let _guard = self.lifecycle_lock.lock().await;
        self.mounted.store(false, Ordering::Release);
        *self.mount_point.write() = None;

        let active = self.active.lock().take();
        if let Some(ActiveMount {
            sync_root_id,
            connection,
            watcher_task,
        }) = active
        {
            if let Err(err) = tokio::task::spawn_blocking(move || {
                drop(connection);
            })
            .await
            {
                warn!(error = %err, "failed waiting for CfApi connection drop");
            }

            let _ = watcher_task.await;

            if self.config.unregister_on_unmount {
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(err) = sync_root_id.unregister() {
                        warn!(error = %err, "failed to unregister Windows Cloud Filter sync root");
                    }
                })
                .await;
            }
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

        if let Some(root) = self.mount_point() {
            let local_path = virtual_path_to_windows_path(&root, &rec.virtual_path)?;
            tokio::task::spawn_blocking(move || update_local_pin_state(&local_path, true, false))
                .await
                .map_err(|err| ZeroVaultError::VfsError(format!("pin task failed: {err}")))??;
        }
        Ok(())
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let rec = self.backend.resolve_path(virtual_path).await?;
        self.backend.dehydrate(rec.inode).await?;

        if let Some(root) = self.mount_point() {
            let local_path = virtual_path_to_windows_path(&root, &rec.virtual_path)?;
            let dehydrate_data = rec.kind == EntryKind::File;
            tokio::task::spawn_blocking(move || {
                update_local_pin_state(&local_path, false, dehydrate_data)
            })
            .await
            .map_err(|err| ZeroVaultError::VfsError(format!("dehydrate task failed: {err}")))??;
        }
        Ok(())
    }

    async fn notify_change(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        let Some(root) = self.mount_point() else {
            return Ok(());
        };

        match self.backend.resolve_path(virtual_path).await {
            Ok(rec) => {
                if rec.kind == EntryKind::Directory {
                    let dir_local = virtual_path_to_windows_path(&root, &rec.virtual_path)?;
                    if !dir_local.exists()
                        && let Some(parent_local) = dir_local.parent()
                        && parent_local.exists()
                    {
                        let rec_clone = rec.clone();
                        let parent_owned = parent_local.to_path_buf();
                        tokio::task::spawn_blocking(move || {
                            create_or_reconcile_placeholder(&parent_owned, &rec_clone)
                        })
                        .await
                        .map_err(|err| {
                            ZeroVaultError::VfsError(format!("notify dir task failed: {err}"))
                        })??;
                    }
                    if dir_local.exists() {
                        let children = self.backend.readdir(rec.inode).await?;
                        tokio::task::spawn_blocking(move || -> ZeroVaultResult<()> {
                            for child in &children {
                                create_or_reconcile_placeholder(&dir_local, child)?;
                            }
                            Ok(())
                        })
                        .await
                        .map_err(|err| {
                            ZeroVaultError::VfsError(format!("notify children task failed: {err}"))
                        })??;
                    }
                } else {
                    let file_local = virtual_path_to_windows_path(&root, &rec.virtual_path)?;
                    if let Some(parent_local) = file_local.parent()
                        && parent_local.exists()
                    {
                        let parent_owned = parent_local.to_path_buf();
                        tokio::task::spawn_blocking(move || {
                            create_or_reconcile_placeholder(&parent_owned, &rec)
                        })
                        .await
                        .map_err(|err| {
                            ZeroVaultError::VfsError(format!("notify file task failed: {err}"))
                        })??;
                    }
                }
            }
            Err(ZeroVaultError::InvalidPath(_)) | Err(ZeroVaultError::InodeNotFound(_)) => {
                let local_path = virtual_path_to_windows_path(&root, virtual_path)?;
                tokio::task::spawn_blocking(move || {
                    if !local_path.exists() {
                        return;
                    }
                    let should_remove = Placeholder::open(&local_path)
                        .ok()
                        .and_then(|ph| ph.info().ok().flatten())
                        .is_some_and(|info| info.is_in_sync() && info.modified_data_size() == 0);
                    if should_remove {
                        if local_path.is_dir() {
                            let _ = std::fs::remove_dir(&local_path);
                        } else {
                            let _ = std::fs::remove_file(&local_path);
                        }
                    }
                })
                .await
                .map_err(|err| {
                    ZeroVaultError::VfsError(format!("notify delete task failed: {err}"))
                })?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }

    async fn stats(&self) -> ZeroVaultResult<DriveStats> {
        self.backend.drive_stats().await
    }
}
