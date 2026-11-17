//! Core daemon service runtime, trait factories, and request dispatch for `zerovaultd`.
//!
//! Interacts strictly with `zerovault_types` traits (`CryptoEngine`, `SecretStore`,
//! `StorageRouterTrait`, `MetadataStore`, `VfsBackend`, `VirtualDrive`) plus `zerovault_crypto`,
//! `zerovault_storage`, and `zerovault_vfs` so `Lead-Architect` can wire `zerovault_core`
//! cleanly through [`SyncEngineFactory`].

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use parking_lot::{Mutex as SyncMutex, RwLock as SyncRwLock};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, Notify, RwLock as AsyncRwLock};
use uuid::Uuid;
use zeroize::Zeroizing;
use zerovault_core::{SqliteMetadataStore, SyncEngine, SyncEngineConfig};
use zerovault_crypto::{AwsLcCryptoEngine, OsKeyringSecretStore};
use zerovault_storage::{
    CloudBackend, DEFAULT_TOKEN_SECRET_SERVICE, DEFAULT_UNBOUNDED_QUOTA_BYTES,
    LoopbackOAuthListener, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenBundle,
    StorageRouter, persist_tokens,
};
use zerovault_types::mocks::{MockMetadataStore, MockVfsBackend};
use zerovault_types::{
    AddRemoteParams, BackendConfig, BackendHealth, BackendId, BackendKind, BackendQuota,
    BlobPlacement, CreateEntrySpec, CryptoEngine, DaemonRequest, DaemonResponse, DriveStats,
    EntryKind, InodeId, KdfParams, MetadataStore, OAuthLoginParams, PLAINTEXT_CHUNK_SIZE,
    RedactedSecret, RemoteAccountSummary, RemoteVersion, RoutingPolicy, SecretStore, SetAttrSpec,
    StorageRouterTrait, ThroughputSnapshot, VAULT_HEADER_LEN, VaultEntrySummary, VaultHeader,
    VaultStatusReport, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult,
};
use zerovault_vfs::{MockDrive, create_platform_drive};

/// Optional background sync trigger exposed by a [`SyncEngineFactory`] backend bundle.
#[async_trait]
pub trait SyncRunner: Send + Sync {
    /// Executes an immediate manifest & dirty-queue synchronization cycle.
    async fn sync_now(&self) -> ZeroVaultResult<()>;
}

/// Optional live throughput and cache telemetry hook exposed by a [`SyncEngineFactory`] bundle.
#[async_trait]
pub trait SyncTelemetryProvider: Send + Sync {
    /// Captures a point-in-time throughput & pending-work snapshot.
    async fn throughput(&self) -> ZeroVaultResult<ThroughputSnapshot>;
}

/// Live metadata, VFS backend, and optional sync/telemetry handles created on vault unlock.
pub struct SyncBackendBundle {
    /// Local metadata WAL store.
    pub metadata: Arc<dyn MetadataStore>,
    /// Virtual filesystem backend bridging OS drive callbacks to encrypted chunk I/O.
    pub vfs: Arc<dyn VfsBackend>,
    /// Optional explicit sync runner invoked by [`DaemonRequest::SyncNow`].
    pub sync_runner: Option<Arc<dyn SyncRunner>>,
    /// Optional explicit throughput telemetry source.
    pub telemetry: Option<Arc<dyn SyncTelemetryProvider>>,
}

impl std::fmt::Debug for SyncBackendBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncBackendBundle")
            .field("has_sync_runner", &self.sync_runner.is_some())
            .field("has_telemetry", &self.telemetry.is_some())
            .finish_non_exhaustive()
    }
}

/// Factory hook creating the sync engine / VFS backend once a vault is unlocked.
///
/// `Lead-Architect` provides the production `zerovault-core` implementation at Gate 2 while
/// [`MockSyncEngineFactory`] serves as the clean Wave 2 default.
#[async_trait]
pub trait SyncEngineFactory: Send + Sync {
    /// Creates a `(MetadataStore, VfsBackend)` bundle for an unlocked vault.
    async fn create_backend(
        &self,
        state_dir: &Path,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle>;

    /// Optional factory-level fallback invoked on `SyncNow` if the bundle provides no
    /// dedicated [`SyncRunner`].
    async fn sync_now(&self, _bundle: &SyncBackendBundle) -> ZeroVaultResult<()> {
        Ok(())
    }
}

/// Compatibility supertrait alias for injectable sync backend providers.
pub trait SyncBackendProvider: SyncEngineFactory {}

impl<T: SyncEngineFactory + ?Sized> SyncBackendProvider for T {}

/// Default Wave 2 [`SyncEngineFactory`] backed by [`MockMetadataStore`] and [`MockVfsBackend`].
#[derive(Debug, Default)]
pub struct MockSyncEngineFactory {
    preset_metadata: Option<Arc<MockMetadataStore>>,
    preset_vfs: Option<Arc<MockVfsBackend>>,
    last_bundle: SyncRwLock<Option<(Arc<MockMetadataStore>, Arc<MockVfsBackend>)>>,
}

impl MockSyncEngineFactory {
    /// Creates a factory returning the provided shared mock stores for deterministic tests.
    #[must_use]
    pub fn with_mocks(metadata: Arc<MockMetadataStore>, vfs: Arc<MockVfsBackend>) -> Self {
        Self {
            preset_metadata: Some(metadata),
            preset_vfs: Some(vfs),
            last_bundle: SyncRwLock::new(None),
        }
    }

    /// Returns the most recently created mock VFS backend, if any.
    #[must_use]
    pub fn last_vfs(&self) -> Option<Arc<MockVfsBackend>> {
        self.last_bundle.read().as_ref().map(|(_, v)| Arc::clone(v))
    }

    /// Returns the most recently created mock metadata store, if any.
    #[must_use]
    pub fn last_metadata(&self) -> Option<Arc<MockMetadataStore>> {
        self.last_bundle.read().as_ref().map(|(m, _)| Arc::clone(m))
    }
}

#[async_trait]
impl SyncEngineFactory for MockSyncEngineFactory {
    async fn create_backend(
        &self,
        _state_dir: &Path,
        _crypto: Arc<dyn CryptoEngine>,
        _storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle> {
        let metadata = self
            .preset_metadata
            .clone()
            .unwrap_or_else(|| Arc::new(MockMetadataStore::new()));
        let vfs = self
            .preset_vfs
            .clone()
            .unwrap_or_else(|| Arc::new(MockVfsBackend::new()));
        *self.last_bundle.write() = Some((Arc::clone(&metadata), Arc::clone(&vfs)));
        Ok(SyncBackendBundle {
            metadata,
            vfs,
            sync_runner: None,
            telemetry: None,
        })
    }
}

/// Production [`SyncEngineFactory`] wiring [`SqliteMetadataStore`] (WAL) and [`SyncEngine`].
#[derive(Debug, Default, Clone)]
pub struct CoreSyncEngineFactory {
    /// Optional explicit device ID stored in manifests and conflict filenames.
    pub device_id: Option<String>,
}

impl CoreSyncEngineFactory {
    /// Creates a [`CoreSyncEngineFactory`] using default host/device configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

struct CoreSyncAdapter(Arc<SyncEngine>);

#[async_trait]
impl SyncRunner for CoreSyncAdapter {
    async fn sync_now(&self) -> ZeroVaultResult<()> {
        let _report = self.0.sync_once().await?;
        Ok(())
    }
}

#[async_trait]
impl SyncTelemetryProvider for CoreSyncAdapter {
    async fn throughput(&self) -> ZeroVaultResult<ThroughputSnapshot> {
        self.0.throughput_snapshot().await
    }
}

#[async_trait]
impl SyncEngineFactory for CoreSyncEngineFactory {
    async fn create_backend(
        &self,
        state_dir: &Path,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle> {
        let db_path = state_dir.join("metadata.db");
        let meta = Arc::new(SqliteMetadataStore::open(&db_path)?);
        let metadata: Arc<dyn MetadataStore> = Arc::clone(&meta) as Arc<dyn MetadataStore>;

        let mut cfg = SyncEngineConfig {
            staging_dir: state_dir.join("staging"),
            ..SyncEngineConfig::default()
        };
        if let Some(ref dev) = self.device_id {
            cfg.device_id = dev.clone();
        }

        let engine = Arc::new(SyncEngine::new(
            cfg,
            Arc::clone(&metadata),
            crypto,
            storage,
        )?);
        let adapter = Arc::new(CoreSyncAdapter(Arc::clone(&engine)));

        Ok(SyncBackendBundle {
            metadata,
            vfs: engine,
            sync_runner: Some(adapter.clone()),
            telemetry: Some(adapter),
        })
    }
}

/// Factory hook creating the platform [`VirtualDrive`] (`CfApi`, `FUSE3`, or [`MockDrive`]).
#[async_trait]
pub trait DriveFactory: Send + Sync {
    /// Constructs a [`VirtualDrive`] wrapping `backend`.
    async fn create_drive(
        &self,
        backend: Arc<dyn VfsBackend>,
        use_mock: bool,
    ) -> ZeroVaultResult<Arc<dyn VirtualDrive>>;
}

/// Default [`DriveFactory`] dispatching to [`zerovault_vfs::create_platform_drive`] or [`MockDrive`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultDriveFactory;

#[async_trait]
impl DriveFactory for DefaultDriveFactory {
    async fn create_drive(
        &self,
        backend: Arc<dyn VfsBackend>,
        use_mock: bool,
    ) -> ZeroVaultResult<Arc<dyn VirtualDrive>> {
        if use_mock {
            Ok(Arc::new(MockDrive::new(backend)))
        } else {
            Ok(create_platform_drive(backend))
        }
    }
}

/// Persistent local filesystem configuration for `zerovaultd`.
///
/// Secrets and passphrases are NEVER stored in `remotes_config_path`; only non-secret
/// backend metadata and [`SecretStore`] key references are written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStateConfig {
    /// Local daemon state directory.
    pub state_dir: PathBuf,
    /// When `true`, mounts use [`MockDrive`] rather than OS VFS (`CfApi`/`FUSE`).
    pub use_mock_vfs: bool,
    /// Path to persisted 112-byte `VaultHeader` (`ZVH1`).
    pub vault_header_path: PathBuf,
    /// Path to non-secret remote backend configuration JSON.
    pub remotes_config_path: PathBuf,
    /// OS secret store service namespace.
    pub secret_service: String,
}

impl DaemonStateConfig {
    /// Creates a [`DaemonStateConfig`] storing state files inside `state_dir`.
    #[must_use]
    pub fn new(state_dir: PathBuf) -> Self {
        let vault_header_path = state_dir.join("vault.zvh");
        let remotes_config_path = state_dir.join("remotes.json");
        Self {
            state_dir,
            use_mock_vfs: false,
            vault_header_path,
            remotes_config_path,
            secret_service: DEFAULT_TOKEN_SECRET_SERVICE.to_owned(),
        }
    }

    /// Returns the default OS local state directory (`$XDG_DATA_HOME/zerovault` or `%LOCALAPPDATA%\zerovault`).
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zerovault")
    }

    /// Sets whether [`MockDrive`] should be used for mounts instead of native OS VFS.
    #[must_use]
    pub fn with_mock_vfs(mut self, use_mock_vfs: bool) -> Self {
        self.use_mock_vfs = use_mock_vfs;
        self
    }

    /// Overrides the `SecretStore` service namespace (useful for isolated tests).
    #[must_use]
    pub fn with_secret_service(mut self, service: impl Into<String>) -> Self {
        self.secret_service = service.into();
        self
    }
}

impl Default for DaemonStateConfig {
    fn default() -> Self {
        Self::new(Self::default_state_dir())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedRemotesConfig {
    remotes: Vec<PersistedRemoteEntry>,
    routing_policy: Option<RoutingPolicy>,
}

/// Non-secret remote backend entry persisted in `remotes.json`.
///
/// Secrets (`secret_access_key` / OAuth tokens) are explicitly excluded and stored solely
/// inside [`SecretStore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRemoteEntry {
    id: String,
    kind: BackendKind,
    root: String,
    endpoint: Option<String>,
    bucket: Option<String>,
    region: Option<String>,
    quota_limit_bytes: Option<u64>,
    min_free_reserve_bytes: u64,
    username: Option<String>,
    access_key_id: Option<String>,
    secret_account_key: Option<String>,
}

impl PersistedRemoteEntry {
    fn to_backend_config(&self) -> BackendConfig {
        BackendConfig {
            id: self.id.clone(),
            kind: self.kind.clone(),
            root: self.root.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            quota_limit_bytes: self.quota_limit_bytes,
            min_free_reserve_bytes: self.min_free_reserve_bytes,
            username: self.username.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: None,
            secret_account_key: self.secret_account_key.clone(),
        }
    }

    fn offline_health(&self) -> BackendHealth {
        let total = self
            .quota_limit_bytes
            .unwrap_or(DEFAULT_UNBOUNDED_QUOTA_BYTES);
        BackendHealth {
            backend_id: self.id.clone(),
            kind: self.kind.clone(),
            healthy: false,
            latency_ms: None,
            last_error: Some("vault is locked".to_owned()),
            quota: BackendQuota {
                backend_id: self.id.clone(),
                total_bytes: total,
                used_bytes: 0,
                available_bytes: total,
            },
        }
    }
}

/// Dynamic [`StorageRouterTrait`] wrapper permitting zero-remote startup and live router reloads
/// when remotes are added or the vault is unlocked/locked without breaking existing `SyncEngine`
/// references.
#[derive(Debug, Default)]
pub struct DynamicStorageRouter {
    inner: SyncRwLock<Option<Arc<StorageRouter>>>,
    fallback_policy: SyncRwLock<Option<RoutingPolicy>>,
}

impl DynamicStorageRouter {
    /// Replaces or clears the active concrete [`StorageRouter`].
    pub fn set_router(
        &self,
        router: Option<Arc<StorageRouter>>,
        fallback_policy: Option<RoutingPolicy>,
    ) {
        *self.inner.write() = router;
        *self.fallback_policy.write() = fallback_policy;
    }

    fn active(&self) -> ZeroVaultResult<Arc<StorageRouter>> {
        self.inner.read().clone().ok_or_else(|| {
            ZeroVaultError::ConfigError(
                "no active remote storage backends configured or vault is locked".into(),
            )
        })
    }

    /// Best-effort remote health probe across all active backends.
    pub async fn probe_all_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        let router = self.inner.read().clone();
        if let Some(router) = router {
            router.probe_all_health().await
        } else {
            Ok(Vec::new())
        }
    }
}

#[async_trait]
impl StorageRouterTrait for DynamicStorageRouter {
    async fn put_blob(
        &self,
        virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        self.active()?
            .put_blob(virtual_hint_path, object_key, ciphertext)
            .await
    }

    async fn get_blob(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        self.active()?
            .get_blob(object_key, preferred_backends)
            .await
    }

    async fn delete_blob(
        &self,
        object_key: &str,
        backends: &[BackendId],
    ) -> ZeroVaultResult<()> {
        self.active()?.delete_blob(object_key, backends).await
    }

    async fn stat_object(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>> {
        self.active()?
            .stat_object(object_key, preferred_backends)
            .await
    }

    async fn put_manifest_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        self.active()?
            .put_manifest_cas(object_key, sealed_manifest, expected_etag)
            .await
    }

    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        let router = self.inner.read().clone();
        match router {
            Some(router) => router.list_backend_health().await,
            None => Ok(Vec::new()),
        }
    }

    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
        let router = self.inner.read().clone();
        match router {
            Some(router) => router.pooled_quota().await,
            None => Ok(BackendQuota {
                backend_id: "pool-total".to_owned(),
                total_bytes: 0,
                used_bytes: 0,
                available_bytes: 0,
            }),
        }
    }

    fn routing_policy(&self) -> RoutingPolicy {
        if let Some(router) = self.inner.read().as_ref() {
            return router.routing_policy();
        }
        self.fallback_policy
            .read()
            .clone()
            .unwrap_or_else(|| RoutingPolicy::QuotaPooled {
                pool_backends: Vec::new(),
            })
    }
}

#[derive(Debug, Default)]
struct ThroughputTracker {
    last_sample: Option<Instant>,
    last_bytes_read: u64,
    last_bytes_written: u64,
}

impl ThroughputTracker {
    fn sample(&mut self, stats: &DriveStats, pending_dirty_ops: usize) -> ThroughputSnapshot {
        let now = Instant::now();
        let (upload_bps, download_bps) = if let Some(prev) = self.last_sample {
            let secs = now.duration_since(prev).as_secs_f64();
            if secs > 0.001 {
                let d_up = stats.bytes_written.saturating_sub(self.last_bytes_written) as f64;
                let d_down = stats.bytes_read.saturating_sub(self.last_bytes_read) as f64;
                ((d_up / secs) as u64, (d_down / secs) as u64)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        self.last_sample = Some(now);
        self.last_bytes_read = stats.bytes_read;
        self.last_bytes_written = stats.bytes_written;

        ThroughputSnapshot {
            upload_bytes_per_sec: upload_bps,
            download_bytes_per_sec: download_bps,
            pending_dirty_ops,
            cache_bytes_used: 0,
            sampled_at: Some(Utc::now()),
        }
    }
}

/// Builder for constructing [`DaemonRuntime`] with injectable crypto, secret store, sync engine,
/// and drive factories.
pub struct DaemonRuntimeBuilder {
    config: DaemonStateConfig,
    crypto: Option<Arc<dyn CryptoEngine>>,
    secret_store: Option<Arc<dyn SecretStore>>,
    sync_factory: Option<Arc<dyn SyncEngineFactory>>,
    drive_factory: Option<Arc<dyn DriveFactory>>,
}

impl DaemonRuntimeBuilder {
    /// Creates a new builder targeting `config`.
    #[must_use]
    pub fn new(config: DaemonStateConfig) -> Self {
        Self {
            config,
            crypto: None,
            secret_store: None,
            sync_factory: None,
            drive_factory: None,
        }
    }

    /// Injects a custom [`CryptoEngine`] implementation (defaults to [`AwsLcCryptoEngine`]).
    #[must_use]
    pub fn with_crypto(mut self, crypto: Arc<dyn CryptoEngine>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Injects a custom [`SecretStore`] implementation (defaults to [`OsKeyringSecretStore`]).
    #[must_use]
    pub fn with_secret_store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.secret_store = Some(store);
        self
    }

    /// Injects a custom [`SyncEngineFactory`] (defaults to [`MockSyncEngineFactory`]).
    #[must_use]
    pub fn with_sync_factory(mut self, factory: Arc<dyn SyncEngineFactory>) -> Self {
        self.sync_factory = Some(factory);
        self
    }

    /// Injects a custom [`DriveFactory`] (defaults to [`DefaultDriveFactory`]).
    #[must_use]
    pub fn with_drive_factory(mut self, factory: Arc<dyn DriveFactory>) -> Self {
        self.drive_factory = Some(factory);
        self
    }

    /// Validates paths and builds the [`DaemonRuntime`].
    pub fn build(self) -> ZeroVaultResult<DaemonRuntime> {
        ensure_state_dir(&self.config.state_dir)?;

        let crypto: Arc<dyn CryptoEngine> = match self.crypto {
            Some(c) => c,
            None => Arc::new(AwsLcCryptoEngine::new()?),
        };
        let secret_store: Arc<dyn SecretStore> = self
            .secret_store
            .unwrap_or_else(|| Arc::new(OsKeyringSecretStore::new()));
        let sync_factory: Arc<dyn SyncEngineFactory> = self
            .sync_factory
            .unwrap_or_else(|| Arc::new(CoreSyncEngineFactory::default()));
        let drive_factory: Arc<dyn DriveFactory> = self
            .drive_factory
            .unwrap_or_else(|| Arc::new(DefaultDriveFactory));

        let persisted_remotes = load_remotes_config(&self.config.remotes_config_path)?;
        let storage_router = Arc::new(DynamicStorageRouter::default());
        storage_router.set_router(None, persisted_remotes.routing_policy.clone());

        Ok(DaemonRuntime {
            config: self.config,
            crypto,
            secret_store,
            sync_factory,
            drive_factory,
            storage_router,
            remotes_config: AsyncRwLock::new(persisted_remotes),
            sync_bundle: AsyncRwLock::new(None),
            active_drive: AsyncMutex::new(None),
            throughput: SyncMutex::new(ThroughputTracker::default()),
            shutdown_notify: Arc::new(Notify::new()),
            lifecycle_lock: AsyncMutex::new(()),
        })
    }
}

/// Core stateful runtime for `zerovaultd` handling IPC commands, vault key lifecycle,
/// multi-cloud backend registration, and virtual drive mount orchestration.
pub struct DaemonRuntime {
    config: DaemonStateConfig,
    crypto: Arc<dyn CryptoEngine>,
    secret_store: Arc<dyn SecretStore>,
    sync_factory: Arc<dyn SyncEngineFactory>,
    drive_factory: Arc<dyn DriveFactory>,
    storage_router: Arc<DynamicStorageRouter>,
    remotes_config: AsyncRwLock<PersistedRemotesConfig>,
    sync_bundle: AsyncRwLock<Option<Arc<SyncBackendBundle>>>,
    active_drive: AsyncMutex<Option<Arc<dyn VirtualDrive>>>,
    throughput: SyncMutex<ThroughputTracker>,
    shutdown_notify: Arc<Notify>,
    lifecycle_lock: AsyncMutex<()>,
}

impl std::fmt::Debug for DaemonRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonRuntime")
            .field("state_dir", &self.config.state_dir)
            .field("use_mock_vfs", &self.config.use_mock_vfs)
            .field("unlocked", &self.crypto.is_unlocked())
            .finish_non_exhaustive()
    }
}

impl DaemonRuntime {
    /// Starts a [`DaemonRuntimeBuilder`] for `config`.
    #[must_use]
    pub fn builder(config: DaemonStateConfig) -> DaemonRuntimeBuilder {
        DaemonRuntimeBuilder::new(config)
    }

    /// Constructs a [`DaemonRuntime`] using production defaults (`AwsLcCryptoEngine`,
    /// `OsKeyringSecretStore`, [`CoreSyncEngineFactory`], and [`DefaultDriveFactory`]).
    pub fn new_default(config: DaemonStateConfig) -> ZeroVaultResult<Self> {
        Self::builder(config).build()
    }

    /// Returns the daemon state configuration.
    #[must_use]
    pub fn config(&self) -> &DaemonStateConfig {
        &self.config
    }

    /// Returns a handle to the shutdown notifier signaled by [`DaemonRequest::Shutdown`].
    #[must_use]
    pub fn shutdown_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown_notify)
    }

    /// Dispatches a single [`DaemonRequest`] and maps domain errors to [`DaemonResponse::Error`].
    pub async fn handle_request(&self, req: DaemonRequest) -> DaemonResponse {
        match self.dispatch_inner(req).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(code = error_code(&err), error = %err, "daemon request failed");
                error_to_daemon_response(&err)
            }
        }
    }

    /// Gracefully unmounts any active virtual drive and locks/zeroizes vault keys.
    pub async fn graceful_shutdown(&self) -> ZeroVaultResult<()> {
        let _guard = self.lifecycle_lock.lock().await;
        self.lock_and_unmount_locked().await?;
        self.shutdown_notify.notify_waiters();
        Ok(())
    }

    async fn dispatch_inner(&self, req: DaemonRequest) -> ZeroVaultResult<DaemonResponse> {
        match req {
            DaemonRequest::Ping => Ok(DaemonResponse::Ok {
                message: "pong".to_owned(),
            }),
            DaemonRequest::InitVault { passphrase } => {
                let secret = RedactedSecret::from(passphrase);
                self.init_vault(&secret).await
            }
            DaemonRequest::UnlockVault { passphrase } => {
                let secret = RedactedSecret::from(passphrase);
                self.unlock_vault(&secret).await
            }
            DaemonRequest::LockVault => self.lock_vault().await,
            DaemonRequest::AddRemote(params) => self.add_remote(*params).await,
            DaemonRequest::RemoveRemote { id } => self.remove_remote(&id).await,
            DaemonRequest::SetRoutingPolicy { policy } => self.set_routing_policy(policy).await,
            DaemonRequest::OAuthLogin(params) => self.oauth_login(*params).await,
            DaemonRequest::ListRemotes => self.list_remotes().await,
            DaemonRequest::Mount { mount_point } => {
                self.mount_drive_with_options(&mount_point, None).await
            }
            DaemonRequest::MountWithOptions {
                mount_point,
                use_mock_vfs,
            } => {
                self.mount_drive_with_options(&mount_point, Some(use_mock_vfs))
                    .await
            }
            DaemonRequest::Unmount => self.unmount_drive().await,
            DaemonRequest::Pin { virtual_path } => self.pin_path(&virtual_path).await,
            DaemonRequest::Unpin { virtual_path } => self.unpin_path(&virtual_path).await,
            DaemonRequest::Dehydrate { virtual_path } => self.dehydrate_path(&virtual_path).await,
            DaemonRequest::ListDirectory { virtual_path } => {
                self.list_directory(&virtual_path).await
            }
            DaemonRequest::CreateDirectory { virtual_path } => {
                self.create_directory(&virtual_path).await
            }
            DaemonRequest::ImportLocalFile {
                local_path,
                virtual_dest_path,
            } => self.import_local_file(&local_path, &virtual_dest_path).await,
            DaemonRequest::ExportVaultFile {
                virtual_path,
                local_dest_path,
            } => self.export_vault_file(&virtual_path, &local_dest_path).await,
            DaemonRequest::DeleteEntry {
                virtual_path,
                recursive,
            } => self.delete_entry(&virtual_path, recursive).await,
            DaemonRequest::RenameEntry {
                virtual_path,
                new_virtual_path,
            } => self.rename_entry(&virtual_path, &new_virtual_path).await,
            DaemonRequest::ListConflicts => self.list_conflicts().await,
            DaemonRequest::SyncNow => self.sync_now().await,
            DaemonRequest::Status => self.status().await,
            DaemonRequest::Shutdown => {
                self.graceful_shutdown().await?;
                Ok(DaemonResponse::Ok {
                    message: "daemon shutting down".to_owned(),
                })
            }
        }
    }

    async fn init_vault(&self, passphrase: &RedactedSecret) -> ZeroVaultResult<DaemonResponse> {
        if passphrase.as_str().is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "vault passphrase must not be empty".into(),
            ));
        }

        let _guard = self.lifecycle_lock.lock().await;
        if self.config.vault_header_path.exists() {
            return Err(ZeroVaultError::AlreadyExists(format!(
                "vault header already exists at {}",
                self.config.vault_header_path.display()
            )));
        }

        let header = self
            .crypto
            .init_vault(passphrase, KdfParams::interactive_production())
            .await?;
        persist_vault_header(&self.config.vault_header_path, &header)?;

        self.activate_unlocked_subsystems().await?;

        tracing::info!(vault_id = %header.vault_id, "initialized and unlocked new vault");
        Ok(DaemonResponse::Ok {
            message: format!("vault {} initialized", header.vault_id),
        })
    }

    async fn unlock_vault(&self, passphrase: &RedactedSecret) -> ZeroVaultResult<DaemonResponse> {
        if passphrase.as_str().is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "vault passphrase must not be empty".into(),
            ));
        }

        let _guard = self.lifecycle_lock.lock().await;
        let header = load_vault_header(&self.config.vault_header_path)?;
        self.crypto
            .unlock_with_passphrase(&header, passphrase)
            .await?;

        if let Err(err) = self.activate_unlocked_subsystems().await {
            let _ = self.crypto.lock_vault().await;
            return Err(err);
        }

        tracing::info!(vault_id = %header.vault_id, "vault unlocked");
        Ok(DaemonResponse::Ok {
            message: format!("vault {} unlocked", header.vault_id),
        })
    }

    async fn activate_unlocked_subsystems(&self) -> ZeroVaultResult<()> {
        let cfg_snapshot = self.remotes_config.read().await.clone();
        self.rebuild_storage_router(&cfg_snapshot, true).await?;

        let storage_trait: Arc<dyn StorageRouterTrait> = self.storage_router.clone();
        let bundle = self
            .sync_factory
            .create_backend(
                &self.config.state_dir,
                Arc::clone(&self.crypto),
                storage_trait,
            )
            .await?;
        *self.sync_bundle.write().await = Some(Arc::new(bundle));
        Ok(())
    }

    async fn lock_vault(&self) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        self.lock_and_unmount_locked().await?;
        tracing::info!("vault locked and key material zeroized");
        Ok(DaemonResponse::Ok {
            message: "vault locked".to_owned(),
        })
    }

    async fn lock_and_unmount_locked(&self) -> ZeroVaultResult<()> {
        if let Some(drive) = self.active_drive.lock().await.take()
            && drive.is_mounted()
        {
            drive.unmount().await?;
        }
        *self.sync_bundle.write().await = None;
        let policy = self.remotes_config.read().await.routing_policy.clone();
        self.storage_router.set_router(None, policy);
        self.crypto.lock_vault().await?;
        Ok(())
    }

    async fn add_remote(&self, mut params: AddRemoteParams) -> ZeroVaultResult<DaemonResponse> {
        let secret = params.secret.take().map(RedactedSecret::from);

        let id = params.id.trim().to_owned();
        if id.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "remote backend id must not be empty".into(),
            ));
        }

        let kind = parse_backend_kind(&params.kind)?;
        let _guard = self.lifecycle_lock.lock().await;

        let mut cfg = self.remotes_config.read().await.clone();
        if cfg.remotes.iter().any(|r| r.id == id) {
            return Err(ZeroVaultError::AlreadyExists(format!(
                "remote backend '{id}' is already registered"
            )));
        }

        let mut secret_account_key: Option<String> = None;
        if let Some(ref secret_val) = secret {
            if !self.crypto.is_unlocked() {
                return Err(ZeroVaultError::VaultLocked);
            }
            let acct_key = format!("remote:{id}");
            store_remote_secret(
                &kind,
                &acct_key,
                params.username.as_deref(),
                secret_val,
                self.secret_store.as_ref(),
                self.crypto.as_ref(),
                &self.config.secret_service,
            )
            .await?;
            secret_account_key = Some(acct_key);
        } else if matches!(
            kind,
            BackendKind::GoogleDrive | BackendKind::OneDrive | BackendKind::Dropbox
        ) {
            let acct_key = format!("remote:{id}");
            let existing = self
                .secret_store
                .get_secret(&self.config.secret_service, &acct_key)
                .await?;
            if existing.is_none() {
                return Err(ZeroVaultError::ConfigError(format!(
                    "OAuth2 backend '{id}' requires --secret-stdin token bundle or prior OAuth enrollment"
                )));
            }
            secret_account_key = Some(acct_key);
        }

        let (username, access_key_id) = match kind {
            BackendKind::S3 => (None, params.username.clone()),
            _ => (params.username.clone(), None),
        };

        let entry = PersistedRemoteEntry {
            id: id.clone(),
            kind: kind.clone(),
            root: params.root.clone(),
            endpoint: params.endpoint.clone(),
            bucket: params.bucket.clone(),
            region: params.region.clone(),
            quota_limit_bytes: params.quota_limit_bytes,
            min_free_reserve_bytes: 0,
            username,
            access_key_id,
            secret_account_key: secret_account_key.clone(),
        };

        cfg.remotes.push(entry);
        let all_ids: Vec<String> = cfg.remotes.iter().map(|r| r.id.clone()).collect();
        let next_policy = compute_updated_routing_policy(
            cfg.routing_policy.take(),
            &all_ids,
            &id,
            params.policy.as_deref(),
            params.prefix.as_deref(),
        )?;
        cfg.routing_policy = Some(next_policy);

        // Validate construction before committing config to disk.
        let build_res = self
            .build_concrete_router(&cfg, self.crypto.is_unlocked())
            .await;
        let built_router = match build_res {
            Ok(r) => r,
            Err(err) => {
                if let Some(ref acct_key) = secret_account_key {
                    let _ = self
                        .secret_store
                        .delete_secret(&self.config.secret_service, acct_key)
                        .await;
                }
                return Err(err);
            }
        };

        persist_remotes_config(&self.config.remotes_config_path, &cfg)?;
        *self.remotes_config.write().await = cfg.clone();

        if self.crypto.is_unlocked() {
            self.storage_router
                .set_router(built_router, cfg.routing_policy.clone());
        } else {
            self.storage_router
                .set_router(None, cfg.routing_policy.clone());
        }

        tracing::info!(remote_id = %id, kind = ?kind, "registered remote storage backend");
        Ok(DaemonResponse::Ok {
            message: format!("remote '{id}' registered"),
        })
    }

    async fn remove_remote(&self, id: &str) -> ZeroVaultResult<DaemonResponse> {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "remote backend id must not be empty".into(),
            ));
        }

        let _guard = self.lifecycle_lock.lock().await;
        let mut cfg = self.remotes_config.read().await.clone();
        let Some(pos) = cfg.remotes.iter().position(|r| r.id == trimmed) else {
            return Err(ZeroVaultError::StorageNotFound(format!(
                "remote backend '{trimmed}' not found"
            )));
        };
        cfg.remotes.remove(pos);

        let acct_key = format!("remote:{trimmed}");
        let _ = self
            .secret_store
            .delete_secret(&self.config.secret_service, &acct_key)
            .await;

        if cfg.remotes.is_empty() {
            cfg.routing_policy = None;
        } else {
            let remaining_ids: Vec<String> = cfg.remotes.iter().map(|r| r.id.clone()).collect();
            cfg.routing_policy = cfg.routing_policy.take().map(|policy| match policy {
                RoutingPolicy::QuotaPooled { mut pool_backends } => {
                    pool_backends.retain(|b| b != trimmed);
                    if pool_backends.is_empty() {
                        pool_backends = remaining_ids;
                    }
                    RoutingPolicy::QuotaPooled { pool_backends }
                }
                RoutingPolicy::Mirrored {
                    mut backends,
                    min_ack,
                } => {
                    backends.retain(|b| b != trimmed);
                    if backends.is_empty() {
                        backends = remaining_ids;
                    }
                    let clamped_ack = min_ack.clamp(1, backends.len().max(1));
                    RoutingPolicy::Mirrored {
                        backends,
                        min_ack: clamped_ack,
                    }
                }
                RoutingPolicy::Targeted {
                    mut prefix_routes,
                    default_backend,
                } => {
                    prefix_routes.retain(|(_, b)| b != trimmed);
                    let next_default = if default_backend == trimmed {
                        remaining_ids[0].clone()
                    } else {
                        default_backend
                    };
                    RoutingPolicy::Targeted {
                        prefix_routes,
                        default_backend: next_default,
                    }
                }
            });
        }

        let built_router = if self.crypto.is_unlocked() {
            self.build_concrete_router(&cfg, true).await?
        } else {
            None
        };

        persist_remotes_config(&self.config.remotes_config_path, &cfg)?;
        *self.remotes_config.write().await = cfg.clone();

        if self.crypto.is_unlocked() {
            self.storage_router
                .set_router(built_router, cfg.routing_policy.clone());
        } else {
            self.storage_router
                .set_router(None, cfg.routing_policy.clone());
        }

        tracing::info!(remote_id = %trimmed, "removed remote storage backend");
        Ok(DaemonResponse::Ok {
            message: format!("remote '{trimmed}' removed"),
        })
    }

    async fn set_routing_policy(&self, mut policy: RoutingPolicy) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        let mut cfg = self.remotes_config.read().await.clone();
        if cfg.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before setting routing policy".into(),
            ));
        }

        validate_routing_policy(&cfg.remotes, &mut policy)?;
        cfg.routing_policy = Some(policy.clone());

        let built_router = if self.crypto.is_unlocked() {
            self.build_concrete_router(&cfg, true).await?
        } else {
            None
        };

        persist_remotes_config(&self.config.remotes_config_path, &cfg)?;
        *self.remotes_config.write().await = cfg.clone();

        if self.crypto.is_unlocked() {
            self.storage_router
                .set_router(built_router, cfg.routing_policy.clone());
        } else {
            self.storage_router
                .set_router(None, cfg.routing_policy.clone());
        }

        tracing::info!("updated multi-cloud routing policy");
        Ok(DaemonResponse::Ok {
            message: "routing policy updated".to_owned(),
        })
    }

    async fn oauth_login(&self, mut params: OAuthLoginParams) -> ZeroVaultResult<DaemonResponse> {
        if !self.crypto.is_unlocked() {
            return Err(ZeroVaultError::VaultLocked);
        }

        let client_secret = params
            .client_secret
            .take()
            .filter(|s| !s.trim().is_empty())
            .map(RedactedSecret::from);
        let id = params.id.trim().to_owned();
        if id.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "remote backend id must not be empty".into(),
            ));
        }
        let client_id = params.client_id.trim().to_owned();
        if client_id.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "OAuth2 client_id must not be empty".into(),
            ));
        }

        let kind = parse_backend_kind(&params.kind)?;
        let preset = OAuthProviderPreset::try_from(&kind)?;

        {
            let cfg = self.remotes_config.read().await;
            if cfg.remotes.iter().any(|r| r.id == id) {
                return Err(ZeroVaultError::AlreadyExists(format!(
                    "remote backend '{id}' is already registered"
                )));
            }
        }

        let mut oauth_cfg = OAuthProviderConfig::for_preset(preset, client_id.clone(), client_secret);
        if let Some(auth_url) = params
            .auth_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let token_url = params
                .token_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| preset.default_token_url());
            oauth_cfg = oauth_cfg.with_endpoints(auth_url, token_url);
        } else if let Some(token_url) = params
            .token_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            oauth_cfg = oauth_cfg.with_endpoints(preset.default_auth_url(), token_url);
        }

        let listener = LoopbackOAuthListener::bind_ephemeral(oauth_cfg).await?;
        if params.open_browser {
            open_url_in_system_browser(listener.authorize_url().as_str())?;
        }

        let timeout = Duration::from_secs(params.timeout_secs.unwrap_or(180).clamp(5, 600));
        let bundle = listener.wait_for_callback_and_exchange(timeout).await?;

        if !self.crypto.is_unlocked() {
            return Err(ZeroVaultError::VaultLocked);
        }

        let acct_key = format!("remote:{id}");
        persist_tokens(
            &bundle,
            self.secret_store.as_ref(),
            self.crypto.as_ref(),
            &self.config.secret_service,
            &acct_key,
        )
        .await?;

        let reg_res = self
            .add_remote(AddRemoteParams {
                id: id.clone(),
                kind: params.kind,
                root: params.root,
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: params.quota_limit_bytes,
                policy: params.policy,
                prefix: params.prefix,
                username: Some(client_id),
                secret: None,
            })
            .await;

        if let Err(err) = reg_res {
            let _ = self
                .secret_store
                .delete_secret(&self.config.secret_service, &acct_key)
                .await;
            return Err(err);
        }
        reg_res
    }

    async fn rebuild_storage_router(
        &self,
        cfg: &PersistedRemotesConfig,
        sync_usage: bool,
    ) -> ZeroVaultResult<()> {
        if cfg.remotes.is_empty() {
            self.storage_router
                .set_router(None, cfg.routing_policy.clone());
            return Ok(());
        }

        let built = self
            .build_concrete_router(cfg, self.crypto.is_unlocked())
            .await?;
        if sync_usage && let Some(ref router) = built {
            for backend in router.backends() {
                if let Err(err) = backend.sync_used_bytes().await {
                    tracing::warn!(
                        remote_id = %backend.config().id,
                        error = %err,
                        "failed to reconcile remote quota usage on startup"
                    );
                }
            }
        }
        self.storage_router
            .set_router(built, cfg.routing_policy.clone());
        Ok(())
    }

    async fn build_concrete_router(
        &self,
        cfg: &PersistedRemotesConfig,
        include_crypto: bool,
    ) -> ZeroVaultResult<Option<Arc<StorageRouter>>> {
        if cfg.remotes.is_empty() {
            return Ok(None);
        }

        let policy = cfg.routing_policy.clone().unwrap_or_else(|| {
            if cfg.remotes.len() == 1 {
                RoutingPolicy::Targeted {
                    prefix_routes: Vec::new(),
                    default_backend: cfg.remotes[0].id.clone(),
                }
            } else {
                RoutingPolicy::QuotaPooled {
                    pool_backends: cfg.remotes.iter().map(|r| r.id.clone()).collect(),
                }
            }
        });

        let crypto_ref = if include_crypto {
            Some(self.crypto.as_ref())
        } else {
            None
        };
        let mut built = Vec::with_capacity(cfg.remotes.len());
        for entry in &cfg.remotes {
            let backend_cfg = entry.to_backend_config();
            let backend = CloudBackend::from_config_with_options(
                &backend_cfg,
                Some(self.secret_store.as_ref()),
                crypto_ref,
                &self.config.secret_service,
                Default::default(),
            )
            .await?;
            built.push(backend);
        }

        let router = StorageRouter::new(built, policy)?;
        Ok(Some(Arc::new(router)))
    }

    async fn list_remotes(&self) -> ZeroVaultResult<DaemonResponse> {
        let summaries = self.collect_remote_summaries().await?;
        Ok(DaemonResponse::Remotes(summaries))
    }

    async fn collect_remote_summaries(&self) -> ZeroVaultResult<Vec<RemoteAccountSummary>> {
        let cfg = self.remotes_config.read().await.clone();
        let health_list = self.storage_router.list_backend_health().await?;
        let health_map: HashMap<String, BackendHealth> = health_list
            .into_iter()
            .map(|h| (h.backend_id.clone(), h))
            .collect();

        let summaries = cfg
            .remotes
            .iter()
            .map(|entry| {
                let health = health_map
                    .get(&entry.id)
                    .cloned()
                    .unwrap_or_else(|| entry.offline_health());
                RemoteAccountSummary {
                    id: entry.id.clone(),
                    kind: backend_kind_label(&entry.kind).to_owned(),
                    root: entry.root.clone(),
                    health,
                }
            })
            .collect();
        Ok(summaries)
    }

    async fn mount_drive_with_options(
        &self,
        mount_point: &str,
        use_mock_vfs: Option<bool>,
    ) -> ZeroVaultResult<DaemonResponse> {
        let trimmed = mount_point.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "mount point path must not be empty".into(),
            ));
        }

        let mount_path = PathBuf::from(trimmed);
        if !mount_path.exists() {
            std::fs::create_dir_all(&mount_path)?;
        }

        let _guard = self.lifecycle_lock.lock().await;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let mut drive_guard = self.active_drive.lock().await;
        if let Some(existing) = drive_guard.as_ref()
            && existing.is_mounted()
        {
            return Err(ZeroVaultError::VfsError(
                "virtual drive is already mounted".into(),
            ));
        }

        let effective_mock = use_mock_vfs.unwrap_or(self.config.use_mock_vfs);
        let drive = self
            .drive_factory
            .create_drive(Arc::clone(&bundle.vfs), effective_mock)
            .await?;
        drive.mount(mount_path).await?;
        *drive_guard = Some(drive);

        tracing::info!(use_mock_vfs = effective_mock, "virtual drive mounted");
        Ok(DaemonResponse::Ok {
            message: format!("mounted at {trimmed}"),
        })
    }

    async fn notify_active_drive(&self, virtual_path: &str) {
        let drive = self.active_drive.lock().await.clone();
        if let Some(d) = drive
            && d.is_mounted()
        {
            let _ = d.notify_change(virtual_path).await;
        }
    }

    async fn unmount_drive(&self) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        let mut drive_guard = self.active_drive.lock().await;
        if let Some(drive) = drive_guard.take()
            && drive.is_mounted()
        {
            drive.unmount().await?;
            tracing::info!("virtual drive unmounted");
            return Ok(DaemonResponse::Ok {
                message: "virtual drive unmounted".to_owned(),
            });
        }

        Ok(DaemonResponse::Ok {
            message: "virtual drive was not mounted".to_owned(),
        })
    }

    async fn pin_path(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let norm = normalize_vault_virtual_path(virtual_path)?;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let drive = self.active_drive.lock().await.clone();
        if let Some(d) = drive
            && d.is_mounted()
        {
            d.pin_path(&norm).await?;
        } else {
            let rec = bundle.vfs.resolve_path(&norm).await?;
            bundle.vfs.pin(rec.inode).await?;
        }

        tracing::info!("pinned virtual entry offline");
        Ok(DaemonResponse::Ok {
            message: "entry pinned offline".to_owned(),
        })
    }

    async fn unpin_path(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let norm = normalize_vault_virtual_path(virtual_path)?;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let rec = bundle.vfs.resolve_path(&norm).await?;
        bundle.vfs.unpin(rec.inode).await?;

        tracing::info!("cleared offline pin on virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry unpinned".to_owned(),
        })
    }

    async fn list_directory(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let raw = if virtual_path.trim().is_empty() {
            "/"
        } else {
            virtual_path
        };
        let norm = normalize_vault_virtual_path(raw)?;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let dir = bundle.vfs.resolve_path(&norm).await?;
        if dir.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(dir.inode));
        }

        let mut children = bundle.vfs.readdir(dir.inode).await?;
        children.sort_by(|a, b| {
            (a.kind != EntryKind::Directory, a.name.to_ascii_lowercase(), &a.name).cmp(&(
                b.kind != EntryKind::Directory,
                b.name.to_ascii_lowercase(),
                &b.name,
            ))
        });

        let entries = children
            .into_iter()
            .map(|r| VaultEntrySummary {
                inode: r.inode,
                name: r.name,
                virtual_path: r.virtual_path,
                kind: r.kind,
                size: r.size,
                hydration: r.hydration,
                pinned: r.pinned,
                version: r.version,
                modified_at: r.modified_at,
            })
            .collect();

        Ok(DaemonResponse::DirectoryEntries {
            virtual_path: norm,
            entries,
        })
    }

    async fn create_directory(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let (parent_path, name) = split_parent_and_name(virtual_path)?;
        let parent = bundle.vfs.resolve_path(&parent_path).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(parent.inode));
        }

        let created = bundle.vfs.mkdir(parent.inode, &name, 0o755).await?;
        self.notify_active_drive(&created.virtual_path).await;

        tracing::info!("created virtual directory");
        Ok(DaemonResponse::Ok {
            message: "directory created".to_owned(),
        })
    }

    async fn import_local_file(
        &self,
        local_path: &str,
        virtual_dest_path: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let trimmed_local = local_path.trim();
        if trimmed_local.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "source local file path must not be empty".into(),
            ));
        }

        let meta = tokio::fs::metadata(trimmed_local).await?;
        if !meta.is_file() {
            return Err(ZeroVaultError::ConfigError(
                "source local path is not a regular file".into(),
            ));
        }

        let local_name = Path::new(trimmed_local)
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .ok_or_else(|| {
                ZeroVaultError::InvalidPath("source file name is invalid or non-UTF-8".into())
            })?
            .to_owned();

        let dest_raw = if virtual_dest_path.trim().is_empty() {
            "/"
        } else {
            virtual_dest_path
        };
        let dest_norm = normalize_vault_virtual_path(dest_raw)?;

        let (parent_path, file_name) = if dest_norm == "/" {
            ("/".to_owned(), local_name)
        } else {
            match bundle.vfs.resolve_path(&dest_norm).await {
                Ok(existing) if existing.kind == EntryKind::Directory => (dest_norm, local_name),
                _ => split_parent_and_name(&dest_norm)?,
            }
        };

        let parent = bundle.vfs.resolve_path(&parent_path).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(parent.inode));
        }

        let inode = match bundle.vfs.lookup(parent.inode, &file_name).await {
            Ok(existing) => {
                if existing.kind == EntryKind::Directory {
                    return Err(ZeroVaultError::IsADirectory(existing.inode));
                }
                bundle
                    .vfs
                    .setattr(
                        existing.inode,
                        SetAttrSpec {
                            size: Some(0),
                            mode: None,
                            modified_at: Some(Utc::now()),
                        },
                    )
                    .await?
                    .inode
            }
            Err(ZeroVaultError::InodeNotFound(_)) => {
                bundle
                    .vfs
                    .create_entry(CreateEntrySpec {
                        parent_inode: parent.inode,
                        name: file_name.clone(),
                        mode: 0o644,
                    })
                    .await?
                    .inode
            }
            Err(err) => return Err(err),
        };

        let mut src = tokio::fs::File::open(trimmed_local).await?;
        let mut chunk_buf = Zeroizing::new(vec![0u8; PLAINTEXT_CHUNK_SIZE]);
        let mut offset = 0u64;

        loop {
            let mut filled = 0usize;
            while filled < chunk_buf.len() {
                let n = src.read(&mut chunk_buf[filled..]).await?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            bundle
                .vfs
                .write_range(inode, offset, &chunk_buf[..filled])
                .await?;
            offset = offset.saturating_add(filled as u64);
            if filled < chunk_buf.len() {
                break;
            }
        }

        let has_remotes = !self.remotes_config.read().await.remotes.is_empty();
        let mut uploaded_immediately = false;
        if has_remotes || bundle.sync_runner.is_none() {
            match bundle.vfs.flush(inode).await {
                Ok(()) => {
                    uploaded_immediately = true;
                }
                Err(
                    err @ (ZeroVaultError::VaultLocked
                    | ZeroVaultError::CryptoTamperDetected(_)),
                ) => {
                    return Err(err);
                }
                Err(err) => {
                    tracing::warn!(
                        code = error_code(&err),
                        "remote upload deferred; chunk data staged locally"
                    );
                }
            }
        }

        let target_vpath = join_virtual_path(&parent.virtual_path, &file_name);
        self.notify_active_drive(&target_vpath).await;

        tracing::info!(bytes = offset, uploaded_immediately, "imported local file into vault");
        let message = if uploaded_immediately {
            format!("encrypted & uploaded {offset} bytes")
        } else {
            format!("encrypted & staged {offset} bytes locally (sync pending)")
        };
        Ok(DaemonResponse::Ok { message })
    }

    async fn export_vault_file(
        &self,
        virtual_path: &str,
        local_dest_path: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let norm = normalize_vault_virtual_path(virtual_path)?;
        let rec = bundle.vfs.resolve_path(&norm).await?;
        if rec.kind != EntryKind::File {
            return Err(ZeroVaultError::IsADirectory(rec.inode));
        }

        let trimmed_dest = local_dest_path.trim();
        if trimmed_dest.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "local destination path must not be empty".into(),
            ));
        }
        if rec.name.is_empty()
            || rec.name == "."
            || rec.name == ".."
            || rec.name.contains('/')
            || rec.name.contains('\\')
            || rec.name.contains('\0')
        {
            return Err(ZeroVaultError::InvalidPath(
                "vault entry contains invalid export filename characters".into(),
            ));
        }

        let candidate = PathBuf::from(trimmed_dest);
        let dest_path = if candidate.is_dir() {
            candidate.join(&rec.name)
        } else {
            candidate
        };
        if let Some(parent_dir) = dest_path.parent()
            && !parent_dir.as_os_str().is_empty()
            && !parent_dir.exists()
        {
            tokio::fs::create_dir_all(parent_dir).await?;
        }

        let mut dst = tokio::fs::File::create(&dest_path).await?;
        let mut offset = 0u64;
        while offset < rec.size {
            let read_len = ((rec.size - offset) as usize).min(PLAINTEXT_CHUNK_SIZE);
            let bytes = bundle.vfs.read_range(rec.inode, offset, read_len).await?;
            if bytes.is_empty() {
                break;
            }
            dst.write_all(&bytes).await?;
            offset = offset.saturating_add(bytes.len() as u64);
        }
        dst.flush().await?;

        tracing::info!(bytes = offset, "verified and exported vault file to disk");
        Ok(DaemonResponse::Ok {
            message: format!("verified & exported {offset} bytes"),
        })
    }

    async fn delete_entry(
        &self,
        virtual_path: &str,
        recursive: bool,
    ) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let (parent_path, name) = split_parent_and_name(virtual_path)?;
        let parent = bundle.vfs.resolve_path(&parent_path).await?;
        let entry = bundle.vfs.lookup(parent.inode, &name).await?;

        match entry.kind {
            EntryKind::File => {
                bundle.vfs.unlink(parent.inode, &name).await?;
            }
            EntryKind::Directory => {
                if recursive {
                    delete_dir_contents_iterative(bundle.vfs.as_ref(), entry.inode).await?;
                }
                bundle.vfs.rmdir(parent.inode, &name).await?;
            }
        }

        self.notify_active_drive(&entry.virtual_path).await;
        tracing::info!(recursive, "deleted virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry deleted".to_owned(),
        })
    }

    async fn rename_entry(
        &self,
        virtual_path: &str,
        new_virtual_path: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let (old_parent_path, old_name) = split_parent_and_name(virtual_path)?;
        let old_parent = bundle.vfs.resolve_path(&old_parent_path).await?;

        let trimmed_new = new_virtual_path.trim();
        if trimmed_new.is_empty() || trimmed_new.contains('\0') {
            return Err(ZeroVaultError::InvalidPath(
                "destination name or path must not be empty or contain NUL".into(),
            ));
        }

        let (new_parent_path, new_name) =
            if !trimmed_new.contains('/') && !trimmed_new.contains('\\') {
                if trimmed_new == "." || trimmed_new == ".." {
                    return Err(ZeroVaultError::InvalidPath(
                        "entry name cannot be '.' or '..'".into(),
                    ));
                }
                (old_parent_path, trimmed_new.to_owned())
            } else {
                split_parent_and_name(trimmed_new)?
            };

        let src = bundle.vfs.lookup(old_parent.inode, &old_name).await?;
        let new_parent = bundle.vfs.resolve_path(&new_parent_path).await?;
        if new_parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(new_parent.inode));
        }
        if src.kind == EntryKind::Directory {
            let prefix = if src.virtual_path == "/" {
                "/".to_owned()
            } else {
                format!("{}/", src.virtual_path)
            };
            if new_parent.inode == src.inode || new_parent.virtual_path.starts_with(&prefix) {
                return Err(ZeroVaultError::InvalidPath(
                    "cannot move a directory inside itself".into(),
                ));
            }
        }

        let updated = bundle
            .vfs
            .rename(old_parent.inode, &old_name, new_parent.inode, &new_name)
            .await?;
        self.notify_active_drive(&updated.virtual_path).await;

        tracing::info!("renamed virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry renamed".to_owned(),
        })
    }

    async fn list_conflicts(&self) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let mut conflicts = bundle.metadata.list_conflicts().await?;
        conflicts.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
        Ok(DaemonResponse::Conflicts(conflicts))
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let norm = normalize_vault_virtual_path(virtual_path)?;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let drive = self.active_drive.lock().await.clone();
        if let Some(d) = drive
            && d.is_mounted()
        {
            d.dehydrate_path(&norm).await?;
        } else {
            let rec = bundle.vfs.resolve_path(&norm).await?;
            bundle.vfs.dehydrate(rec.inode).await?;
        }

        tracing::info!("dehydrated virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry dehydrated".to_owned(),
        })
    }

    async fn sync_now(&self) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        if let Some(ref runner) = bundle.sync_runner {
            runner.sync_now().await?;
        } else {
            self.sync_factory.sync_now(&bundle).await?;
        }

        let _ = self.storage_router.probe_all_health().await;

        tracing::info!("sync cycle completed");
        Ok(DaemonResponse::Ok {
            message: "sync completed".to_owned(),
        })
    }

    async fn status(&self) -> ZeroVaultResult<DaemonResponse> {
        let unlocked = self.crypto.is_unlocked();
        let vault_id = if let Some(id) = self.crypto.vault_id() {
            Some(id)
        } else if self.config.vault_header_path.exists() {
            load_vault_header(&self.config.vault_header_path)
                .ok()
                .map(|h| h.vault_id)
        } else {
            None
        };

        let (mounted, mount_point, drive_stats_from_drive) = {
            let drive = self.active_drive.lock().await.clone();
            match drive {
                Some(d) => {
                    let is_m = d.is_mounted();
                    let mp = d.mount_point().map(|p| p.display().to_string());
                    let st = if is_m { d.stats().await.ok() } else { None };
                    (is_m, mp, st)
                }
                None => (false, None, None),
            }
        };

        let bundle = self.sync_bundle.read().await.clone();
        let (manifest_revision, pending_dirty_ops, conflict_count, vfs_stats) = match bundle.as_ref()
        {
            Some(b) => {
                let rev = b.metadata.manifest_cursor().await.map(|(r, _)| r).unwrap_or(0);
                let dirty = b
                    .metadata
                    .list_dirty_ops()
                    .await
                    .map(|d| d.len())
                    .unwrap_or(0);
                let conflicts = b
                    .metadata
                    .list_conflicts()
                    .await
                    .map(|c| c.len())
                    .unwrap_or(0);
                let st = if drive_stats_from_drive.is_none() {
                    b.vfs.drive_stats().await.ok()
                } else {
                    None
                };
                (rev, dirty, conflicts, st)
            }
            None => (0, 0, 0, None),
        };

        let drive_stats = drive_stats_from_drive.or(vfs_stats).unwrap_or_default();

        let throughput = if let Some(ref b) = bundle
            && let Some(ref tel) = b.telemetry
        {
            tel.throughput().await.unwrap_or_else(|_| {
                self.throughput
                    .lock()
                    .sample(&drive_stats, pending_dirty_ops)
            })
        } else {
            self.throughput
                .lock()
                .sample(&drive_stats, pending_dirty_ops)
        };

        let remotes = self.collect_remote_summaries().await?;
        let cfg = self.remotes_config.read().await.clone();
        let routing_policy = if cfg.remotes.is_empty() {
            None
        } else {
            Some(self.storage_router.routing_policy())
        };

        let pooled_quota = if cfg.remotes.is_empty() {
            None
        } else if unlocked {
            Some(self.storage_router.pooled_quota().await?)
        } else {
            let total = cfg.remotes.iter().fold(0u64, |acc, r| {
                acc.saturating_add(r.quota_limit_bytes.unwrap_or(DEFAULT_UNBOUNDED_QUOTA_BYTES))
            });
            Some(BackendQuota {
                backend_id: "pool-total".to_owned(),
                total_bytes: total,
                used_bytes: 0,
                available_bytes: total,
            })
        };

        Ok(DaemonResponse::Status(Box::new(VaultStatusReport {
            vault_id,
            unlocked,
            mounted,
            mount_point,
            manifest_revision,
            routing_policy,
            remotes,
            pooled_quota,
            throughput,
            drive_stats,
            conflict_count,
        })))
    }
}

#[derive(Deserialize)]
struct OAuthTokenInputDto {
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
    scopes: Option<Vec<String>>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn store_remote_secret(
    kind: &BackendKind,
    account_key: &str,
    username: Option<&str>,
    secret: &RedactedSecret,
    secret_store: &dyn SecretStore,
    crypto: &dyn CryptoEngine,
    secret_service: &str,
) -> ZeroVaultResult<()> {
    match kind {
        BackendKind::GoogleDrive | BackendKind::OneDrive | BackendKind::Dropbox => {
            let preset = OAuthProviderPreset::try_from(kind)?;
            let bundle: OAuthTokenBundle =
                if let Ok(parsed) = serde_json::from_str::<OAuthTokenInputDto>(secret.as_str()) {
                    OAuthTokenBundle {
                        provider: preset,
                        access_token: RedactedSecret::from(parsed.access_token),
                        refresh_token: parsed.refresh_token.map(RedactedSecret::from),
                        token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_owned()),
                        expires_at: parsed.expires_at,
                        scopes: parsed.scopes.unwrap_or_else(|| preset.default_scopes()),
                        client_id: parsed.client_id.or_else(|| username.map(str::to_owned)),
                        client_secret: parsed.client_secret.map(RedactedSecret::from),
                    }
                } else {
                    OAuthTokenBundle {
                        provider: preset,
                        access_token: secret.clone(),
                        refresh_token: None,
                        token_type: "Bearer".to_owned(),
                        expires_at: None,
                        scopes: preset.default_scopes(),
                        client_id: username.map(str::to_owned),
                        client_secret: None,
                    }
                };
            persist_tokens(&bundle, secret_store, crypto, secret_service, account_key).await
        }
        _ => {
            let wrapped = crypto.wrap_token_payload(secret.as_bytes())?;
            secret_store
                .set_secret(secret_service, account_key, &wrapped)
                .await
        }
    }
}

fn compute_updated_routing_policy(
    existing: Option<RoutingPolicy>,
    all_ids: &[String],
    new_id: &str,
    policy_arg: Option<&str>,
    prefix_arg: Option<&str>,
) -> ZeroVaultResult<RoutingPolicy> {
    let normalized_prefix = match prefix_arg {
        Some(p) => Some(normalize_vault_virtual_path(p)?),
        None => None,
    };

    match policy_arg.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("targeted") => {
            let (mut prefix_routes, default_backend) = match existing {
                Some(RoutingPolicy::Targeted {
                    prefix_routes,
                    default_backend,
                }) => (prefix_routes, default_backend),
                _ => (Vec::new(), new_id.to_owned()),
            };
            if let Some(pfx) = normalized_prefix {
                prefix_routes.retain(|(existing_pfx, _)| existing_pfx != &pfx);
                prefix_routes.push((pfx, new_id.to_owned()));
            }
            Ok(RoutingPolicy::Targeted {
                prefix_routes,
                default_backend,
            })
        }
        Some("mirrored") => {
            let min_ack = (all_ids.len() / 2) + 1;
            Ok(RoutingPolicy::Mirrored {
                backends: all_ids.to_vec(),
                min_ack: min_ack.max(1).min(all_ids.len()),
            })
        }
        Some("pooled" | "quota-pooled" | "quota_pooled") => Ok(RoutingPolicy::QuotaPooled {
            pool_backends: all_ids.to_vec(),
        }),
        Some(other) => Err(ZeroVaultError::ConfigError(format!(
            "unsupported routing policy '{other}'; expected targeted, mirrored, or pooled"
        ))),
        None => match existing {
            None => {
                let mut prefix_routes = Vec::new();
                if let Some(pfx) = normalized_prefix {
                    prefix_routes.push((pfx, new_id.to_owned()));
                }
                Ok(RoutingPolicy::Targeted {
                    prefix_routes,
                    default_backend: new_id.to_owned(),
                })
            }
            Some(RoutingPolicy::Targeted {
                mut prefix_routes,
                default_backend,
            }) => {
                if let Some(pfx) = normalized_prefix {
                    prefix_routes.retain(|(existing_pfx, _)| existing_pfx != &pfx);
                    prefix_routes.push((pfx, new_id.to_owned()));
                    Ok(RoutingPolicy::Targeted {
                        prefix_routes,
                        default_backend,
                    })
                } else if prefix_routes.is_empty() {
                    Ok(RoutingPolicy::QuotaPooled {
                        pool_backends: all_ids.to_vec(),
                    })
                } else {
                    Ok(RoutingPolicy::Targeted {
                        prefix_routes,
                        default_backend,
                    })
                }
            }
            Some(RoutingPolicy::Mirrored { .. }) => {
                let min_ack = (all_ids.len() / 2) + 1;
                Ok(RoutingPolicy::Mirrored {
                    backends: all_ids.to_vec(),
                    min_ack: min_ack.max(1).min(all_ids.len()),
                })
            }
            Some(RoutingPolicy::QuotaPooled { .. }) => Ok(RoutingPolicy::QuotaPooled {
                pool_backends: all_ids.to_vec(),
            }),
        },
    }
}

/// Parses a remote kind string (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`, `memory`).
pub fn parse_backend_kind(kind: &str) -> ZeroVaultResult<BackendKind> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "gdrive" | "google-drive" | "google_drive" | "googledrive" => Ok(BackendKind::GoogleDrive),
        "onedrive" | "one-drive" | "one_drive" => Ok(BackendKind::OneDrive),
        "dropbox" => Ok(BackendKind::Dropbox),
        "s3" => Ok(BackendKind::S3),
        "webdav" | "dav" => Ok(BackendKind::WebDav),
        "fs" | "local" | "localfs" | "local-fs" => Ok(BackendKind::LocalFs),
        "memory" | "mem" => Ok(BackendKind::Memory),
        other => Err(ZeroVaultError::ConfigError(format!(
            "unsupported remote backend kind '{other}'"
        ))),
    }
}

/// Returns the canonical short label for a [`BackendKind`].
#[must_use]
pub const fn backend_kind_label(kind: &BackendKind) -> &'static str {
    match kind {
        BackendKind::GoogleDrive => "gdrive",
        BackendKind::OneDrive => "onedrive",
        BackendKind::Dropbox => "dropbox",
        BackendKind::S3 => "s3",
        BackendKind::WebDav => "webdav",
        BackendKind::LocalFs => "fs",
        BackendKind::Memory => "memory",
    }
}

/// Validates and normalizes a virtual path inside the encrypted vault (`"/Docs/a.pdf"`).
pub fn normalize_vault_virtual_path(raw: &str) -> ZeroVaultResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(ZeroVaultError::InvalidPath(
            "virtual path must not be empty or contain NUL".into(),
        ));
    }
    let replaced = trimmed.replace('\\', "/");
    let mut parts = Vec::new();
    for seg in replaced.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(ZeroVaultError::InvalidPath(
                "virtual path traversal ('..') is forbidden".into(),
            ));
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

fn split_parent_and_name(raw: &str) -> ZeroVaultResult<(String, String)> {
    let norm = normalize_vault_virtual_path(raw)?;
    if norm == "/" {
        return Err(ZeroVaultError::InvalidPath(
            "operation cannot target the root '/' directory".into(),
        ));
    }
    let idx = norm
        .rfind('/')
        .ok_or_else(|| ZeroVaultError::InvalidPath("invalid normalized virtual path".into()))?;
    let parent = if idx == 0 {
        "/".to_owned()
    } else {
        norm[..idx].to_owned()
    };
    let name = norm[idx + 1..].to_owned();
    if name.is_empty() || name == "." || name == ".." {
        return Err(ZeroVaultError::InvalidPath(
            "entry name must be non-empty and not '.' or '..'".into(),
        ));
    }
    Ok((parent, name))
}

fn join_virtual_path(parent_virtual_path: &str, name: &str) -> String {
    if parent_virtual_path == "/" {
        format!("/{name}")
    } else {
        format!("{parent_virtual_path}/{name}")
    }
}

async fn delete_dir_contents_iterative(
    vfs: &dyn VfsBackend,
    root_dir_inode: InodeId,
) -> ZeroVaultResult<()> {
    let mut stack: Vec<(InodeId, bool)> = vec![(root_dir_inode, false)];
    while let Some((dir_inode, expanded)) = stack.pop() {
        let children = vfs.readdir(dir_inode).await?;
        if expanded || children.is_empty() {
            for child in children {
                match child.kind {
                    EntryKind::File => vfs.unlink(dir_inode, &child.name).await?,
                    EntryKind::Directory => vfs.rmdir(dir_inode, &child.name).await?,
                }
            }
        } else {
            let mut subdirs = Vec::new();
            for child in children {
                match child.kind {
                    EntryKind::File => vfs.unlink(dir_inode, &child.name).await?,
                    EntryKind::Directory => subdirs.push(child.inode),
                }
            }
            if !subdirs.is_empty() {
                stack.push((dir_inode, true));
                for sub in subdirs {
                    stack.push((sub, false));
                }
            }
        }
    }
    Ok(())
}

fn validate_routing_policy(
    remotes: &[PersistedRemoteEntry],
    policy: &mut RoutingPolicy,
) -> ZeroVaultResult<()> {
    let id_set: HashSet<&str> = remotes.iter().map(|r| r.id.as_str()).collect();
    match policy {
        RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        } => {
            if !id_set.contains(default_backend.as_str()) {
                return Err(ZeroVaultError::ConfigError(format!(
                    "targeted default backend '{default_backend}' is not registered"
                )));
            }
            for (prefix, backend) in prefix_routes.iter_mut() {
                *prefix = normalize_vault_virtual_path(prefix)?;
                if !id_set.contains(backend.as_str()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "targeted route backend '{backend}' is not registered"
                    )));
                }
            }
        }
        RoutingPolicy::Mirrored { backends, min_ack } => {
            if backends.is_empty() {
                return Err(ZeroVaultError::ConfigError(
                    "mirrored policy must include at least one backend".into(),
                ));
            }
            for b in backends.iter() {
                if !id_set.contains(b.as_str()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "mirrored backend '{b}' is not registered"
                    )));
                }
            }
            if *min_ack == 0 || *min_ack > backends.len() {
                return Err(ZeroVaultError::ConfigError(format!(
                    "mirrored min_ack ({min_ack}) must be between 1 and {}",
                    backends.len()
                )));
            }
        }
        RoutingPolicy::QuotaPooled { pool_backends } => {
            if pool_backends.is_empty() {
                return Err(ZeroVaultError::ConfigError(
                    "quota-pooled policy must include at least one backend".into(),
                ));
            }
            for b in pool_backends.iter() {
                if !id_set.contains(b.as_str()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "pooled backend '{b}' is not registered"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn open_url_in_system_browser(raw_url: &str) -> ZeroVaultResult<()> {
    if !raw_url.starts_with("https://") && !raw_url.starts_with("http://") {
        return Err(ZeroVaultError::OAuthError(
            "refusing to launch non-HTTP(S) authorization URL".into(),
        ));
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", raw_url])
            .spawn()
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("failed launching browser: {err}"))
            })?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(raw_url)
            .spawn()
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("failed launching browser: {err}"))
            })?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(raw_url)
            .spawn()
            .map_err(|err| {
                ZeroVaultError::OAuthError(format!("failed launching browser: {err}"))
            })?;
    }

    Ok(())
}

fn ensure_state_dir(dir: &Path) -> ZeroVaultResult<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_atomic_private(path: &Path, data: &[u8]) -> ZeroVaultResult<()> {
    if let Some(parent) = path.parent() {
        ensure_state_dir(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state");
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4().as_simple()));
    std::fs::write(&tmp_path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn persist_vault_header(path: &Path, header: &VaultHeader) -> ZeroVaultResult<()> {
    let encoded = header.encode();
    write_atomic_private(path, &encoded)
}

fn load_vault_header(path: &Path) -> ZeroVaultResult<VaultHeader> {
    if !path.exists() {
        return Err(ZeroVaultError::ConfigError(format!(
            "vault is not initialized (missing {})",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() != VAULT_HEADER_LEN {
        return Err(ZeroVaultError::InvalidWireFormat(format!(
            "invalid vault header size at {}: expected {VAULT_HEADER_LEN}, got {}",
            path.display(),
            bytes.len()
        )));
    }
    VaultHeader::decode(&bytes)
}

fn persist_remotes_config(path: &Path, cfg: &PersistedRemotesConfig) -> ZeroVaultResult<()> {
    let json = serde_json::to_vec_pretty(cfg).map_err(|e| {
        ZeroVaultError::ConfigError(format!("failed serializing remotes config: {e}"))
    })?;
    write_atomic_private(path, &json)
}

fn load_remotes_config(path: &Path) -> ZeroVaultResult<PersistedRemotesConfig> {
    if !path.exists() {
        return Ok(PersistedRemotesConfig::default());
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        ZeroVaultError::ConfigError(format!(
            "failed parsing remotes config at {}: {e}",
            path.display()
        ))
    })
}

fn error_code(err: &ZeroVaultError) -> &'static str {
    match err {
        ZeroVaultError::CryptoTamperDetected(_) => "crypto_tamper",
        ZeroVaultError::VaultLocked => "vault_locked",
        ZeroVaultError::InvalidPassphrase => "invalid_passphrase",
        ZeroVaultError::HardwareAccelerationUnavailable(_) => "hw_crypto_unavailable",
        ZeroVaultError::InvalidWireFormat(_) => "invalid_wire_format",
        ZeroVaultError::KdfPolicyViolation { .. } => "kdf_policy_violation",
        ZeroVaultError::KeyringError(_) => "keyring_error",
        ZeroVaultError::OAuthError(_) => "oauth_error",
        ZeroVaultError::StorageNotFound(_) => "storage_not_found",
        ZeroVaultError::StorageQuotaExceeded(_) => "quota_exceeded",
        ZeroVaultError::StorageConflict(_) => "storage_conflict",
        ZeroVaultError::StorageBackendError(_) => "storage_backend_error",
        ZeroVaultError::InodeNotFound(_) => "not_found",
        ZeroVaultError::AlreadyExists(_) => "already_exists",
        ZeroVaultError::NotADirectory(_) => "not_a_directory",
        ZeroVaultError::IsADirectory(_) => "is_a_directory",
        ZeroVaultError::DirectoryNotEmpty(_) => "directory_not_empty",
        ZeroVaultError::InvalidRange { .. } => "invalid_range",
        ZeroVaultError::InvalidPath(_) => "invalid_path",
        ZeroVaultError::PinnedDehydrationDenied(_) => "pinned_dehydration_denied",
        ZeroVaultError::VfsError(_) => "vfs_error",
        ZeroVaultError::MetadataError(_) => "metadata_error",
        ZeroVaultError::IpcError(_) => "ipc_error",
        ZeroVaultError::ConfigError(_) => "invalid_config",
        ZeroVaultError::Io(_) => "io_error",
    }
}

fn error_to_daemon_response(err: &ZeroVaultError) -> DaemonResponse {
    DaemonResponse::Error {
        code: error_code(err).to_owned(),
        message: err.to_string(),
    }
}
