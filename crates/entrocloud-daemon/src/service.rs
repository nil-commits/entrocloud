//! Core daemon service runtime, background sync & backup scheduler, sharing/keybox orchestration,
//! and complete [`DaemonRequest`] dispatch for `entrocloudd`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use parking_lot::{Mutex as SyncMutex, RwLock as SyncRwLock};
use serde::{Deserialize, Serialize};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, Notify, RwLock as AsyncRwLock, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};
use entrocloud_core::{
    EPOCH_SCOPE_KEYBOX, EPOCH_SCOPE_MANIFEST, SqliteMetadataStore, SyncEngine, SyncEngineConfig,
    compute_manifest_id, reclaim_process_memory,
};
use entrocloud_crypto::{AwsLcCryptoEngine, OsKeyringSecretStore};
use entrocloud_storage::{
    CloudBackend, DEFAULT_UNBOUNDED_QUOTA_BYTES, LoopbackOAuthListener, OAuthProviderConfig,
    OAuthProviderPreset, OAuthTokenBundle, StorageRouter, persist_tokens,
};
use entrocloud_types::mocks::{MockMetadataStore, MockVfsBackend};
use entrocloud_types::{
    AddRemoteParams, BackendConfig, BackendHealth, BackendId, BackendKind, BackendQuota,
    BackupJobSpec, BackupJobSummary, BackupRunReport, BlobObjectKey, BlobPlacement, CapabilityUri,
    ChunkRef, CreateEntrySpec, CryptoEngine, DaemonRequest, DaemonResponse, DekBytes,
    DetectedCloudFolder, DriveStats, EntryKind, HydrationState, InodeId, KEYBOX_OBJECT_KEY,
    KdfParams, KeyboxSummary, MANIFEST_HEAD_OBJECT_KEY, ManifestNode, ManifestObjectKey,
    MetadataStore, OAuthLoginParams, PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RecipientPrivateIdentity,
    RecipientPublicBundle, RedactedSecret, RemoteAccountSummary, RemoteTestReport, RemoteVersion,
    RoutingPolicy, SecretStore, SetAttrSpec, ShareObjectKey, SignedKeybox, SignedShareEnvelope,
    StorageRouterTrait, ThroughputSnapshot, VAULT_HEADER_LEN, VAULT_HEADER_OBJECT_KEY,
    VaultEntrySummary, VaultHeader, VaultManifest, VaultStatusReport, VfsBackend, VirtualDrive,
    ZeroVaultError, ZeroVaultResult, validate_portable_entry_name,
};
use entrocloud_vfs::{MockDrive, create_platform_drive};

use crate::backup::{
    PersistedBackupState, SchedulePolicy, StoredBackupJob, build_stored_backup_job,
    clean_local_path_display, execute_single_backup_job, format_backup_message,
    format_preview_message, is_backup_cancelled_error, load_backup_state,
    make_restore_folder_name, persist_backup_state, validate_restore_destination_parent,
};
use crate::dacl::{ensure_owner_only_dir, ensure_owner_only_file, is_symlink_or_reparse};

/// Default OS keyring / SecretStore service namespace for EntroCloud.
pub const DEFAULT_SECRET_SERVICE: &str = "entrocloud";

/// Maximum UTF-8 note byte size accepted by `ReadTextNote` and `SaveTextNote` (`2 MiB`).
pub const MAX_TEXT_NOTE_BYTES: usize = 2 * 1024 * 1024;

/// Default periodic background synchronization interval (`30s`).
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);

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

/// Live metadata, VFS backend, and concrete [`SyncEngine`] handles created on vault unlock.
pub struct SyncBackendBundle {
    /// Local metadata WAL store.
    pub metadata: Arc<dyn MetadataStore>,
    /// Virtual filesystem backend bridging OS drive callbacks to encrypted chunk I/O.
    pub vfs: Arc<dyn VfsBackend>,
    /// Concrete `entrocloud-core` [`SyncEngine`], when backed by [`CoreSyncEngineFactory`].
    pub sync_engine: Option<Arc<SyncEngine>>,
    /// Optional explicit sync runner invoked by [`DaemonRequest::SyncNow`].
    pub sync_runner: Option<Arc<dyn SyncRunner>>,
    /// Optional explicit throughput telemetry source.
    pub telemetry: Option<Arc<dyn SyncTelemetryProvider>>,
}

impl std::fmt::Debug for SyncBackendBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncBackendBundle")
            .field("has_sync_engine", &self.sync_engine.is_some())
            .field("has_sync_runner", &self.sync_runner.is_some())
            .field("has_telemetry", &self.telemetry.is_some())
            .finish_non_exhaustive()
    }
}

/// Factory hook creating the sync engine / VFS backend once a vault is unlocked.
#[async_trait]
pub trait SyncEngineFactory: Send + Sync {
    /// Creates a `(MetadataStore, VfsBackend)` bundle for an unlocked vault.
    async fn create_backend(
        &self,
        state_dir: &Path,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle>;

    /// Creates a `(MetadataStore, VfsBackend)` bundle with an explicit `staging_dir`.
    async fn create_backend_with_staging(
        &self,
        state_dir: &Path,
        staging_dir: &Path,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle> {
        let _ = staging_dir;
        self.create_backend(state_dir, crypto, storage).await
    }

    /// Optional factory-level fallback invoked on `SyncNow` if the bundle provides no
    /// dedicated [`SyncRunner`].
    async fn sync_now(&self, _bundle: &SyncBackendBundle) -> ZeroVaultResult<()> {
        Ok(())
    }
}

/// Compatibility supertrait alias for injectable sync backend providers.
pub trait SyncBackendProvider: SyncEngineFactory {}

impl<T: SyncEngineFactory + ?Sized> SyncBackendProvider for T {}

/// Deterministic mock [`SyncEngineFactory`] backed by [`MockMetadataStore`] and [`MockVfsBackend`].
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
            sync_engine: None,
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

    /// Creates a [`CoreSyncEngineFactory`] with an explicit `device_id`.
    #[must_use]
    pub fn with_device_id(device_id: impl Into<String>) -> Self {
        Self {
            device_id: Some(device_id.into()),
        }
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
        let staging_dir = state_dir.join("staging");
        self.create_backend_with_staging(state_dir, &staging_dir, crypto, storage)
            .await
    }

    async fn create_backend_with_staging(
        &self,
        state_dir: &Path,
        staging_dir: &Path,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<SyncBackendBundle> {
        ensure_owner_only_dir(state_dir)?;
        ensure_owner_only_dir(staging_dir)?;

        let db_path = state_dir.join("metadata.db");
        let meta = Arc::new(SqliteMetadataStore::open(&db_path, Arc::clone(&crypto))?);
        if db_path.exists() {
            let _ = ensure_owner_only_file(&db_path);
        }
        let metadata: Arc<dyn MetadataStore> = Arc::clone(&meta) as Arc<dyn MetadataStore>;

        let mut cfg = SyncEngineConfig {
            staging_dir: staging_dir.to_path_buf(),
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
            vfs: Arc::clone(&engine) as Arc<dyn VfsBackend>,
            sync_engine: Some(engine),
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

/// Default [`DriveFactory`] dispatching to [`entrocloud_vfs::create_platform_drive`] or [`MockDrive`].
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

/// Persistent local filesystem configuration for `entrocloudd`.
///
/// Secrets and passphrases are NEVER stored in `remotes_config_path` or `backup_jobs_path`;
/// only non-secret backend/backup metadata and [`SecretStore`] key references are written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStateConfig {
    /// Local daemon state directory (`0700` / `PROTECTED_DACL`).
    pub state_dir: PathBuf,
    /// Local encrypted dirty staging directory (`0700` / `PROTECTED_DACL`).
    pub staging_dir: PathBuf,
    /// When `true`, mounts use [`MockDrive`] rather than OS VFS (`CfApi`/`FUSE`).
    pub use_mock_vfs: bool,
    /// Path to persisted 112-byte `VaultHeader` (`ZVH1`).
    pub vault_header_path: PathBuf,
    /// Path to non-secret remote backend configuration JSON.
    pub remotes_config_path: PathBuf,
    /// Path to non-secret PC folder backup jobs schedule JSON (`backup_jobs.json`).
    pub backup_jobs_path: PathBuf,
    /// Path to non-secret authorized keybox recipient public bundles JSON.
    pub keybox_state_path: PathBuf,
    /// Path to `TokenWrapKey`-encrypted local recipient private identity fallback.
    pub identity_state_path: PathBuf,
    /// OS secret store service namespace (`"entrocloud"`).
    pub secret_service: String,
    /// Periodic background sync interval (`Duration::ZERO` disables background sync).
    pub sync_interval: Duration,
}

impl DaemonStateConfig {
    /// Creates a [`DaemonStateConfig`] storing state files inside `state_dir`.
    #[must_use]
    pub fn new(state_dir: PathBuf) -> Self {
        let staging_dir = state_dir.join("staging");
        let vault_header_path = state_dir.join("vault.zvh");
        let remotes_config_path = state_dir.join("remotes.json");
        let backup_jobs_path = state_dir.join("backup_jobs.json");
        let keybox_state_path = state_dir.join("keybox_state.json");
        let identity_state_path = state_dir.join("recipient_identity.zvi");
        Self {
            state_dir,
            staging_dir,
            use_mock_vfs: false,
            vault_header_path,
            remotes_config_path,
            backup_jobs_path,
            keybox_state_path,
            identity_state_path,
            secret_service: DEFAULT_SECRET_SERVICE.to_owned(),
            sync_interval: DEFAULT_SYNC_INTERVAL,
        }
    }

    /// Returns the default OS application data root (`%LOCALAPPDATA%\EntroCloud` on Windows,
    /// `~/.local/share/entrocloud` on Linux/Unix).
    #[must_use]
    pub fn default_app_root() -> PathBuf {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        #[cfg(target_os = "windows")]
        {
            base.join("EntroCloud")
        }
        #[cfg(not(target_os = "windows"))]
        {
            base.join("entrocloud")
        }
    }

    /// Returns the default OS local state directory (`%LOCALAPPDATA%\EntroCloud\state` on Windows,
    /// `~/.local/share/entrocloud` on Linux/Unix).
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            Self::default_app_root().join("state")
        }
        #[cfg(not(target_os = "windows"))]
        {
            Self::default_app_root()
        }
    }

    /// Returns the default OS encrypted staging directory (`%LOCALAPPDATA%\EntroCloud\staging` on Windows,
    /// `~/.local/share/entrocloud/staging` on Linux/Unix).
    #[must_use]
    pub fn default_staging_dir() -> PathBuf {
        Self::default_app_root().join("staging")
    }

    /// Returns the default OS configuration directory (`%LOCALAPPDATA%\EntroCloud` on Windows,
    /// `~/.config/entrocloud` on Linux/Unix).
    #[must_use]
    pub fn default_config_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            Self::default_app_root()
        }
        #[cfg(not(target_os = "windows"))]
        {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("entrocloud")
        }
    }

    /// Returns the default virtual drive mount point (`~/EntroCloud`).
    #[must_use]
    pub fn default_mount_point() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("EntroCloud")
    }

    /// Overrides the encrypted staging directory path.
    #[must_use]
    pub fn with_staging_dir(mut self, staging_dir: PathBuf) -> Self {
        self.staging_dir = staging_dir;
        self
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

    /// Configures the periodic background sync interval (`Duration::ZERO` disables it).
    #[must_use]
    pub fn with_sync_interval(mut self, interval: Duration) -> Self {
        self.sync_interval = interval;
        self
    }
}

impl Default for DaemonStateConfig {
    fn default() -> Self {
        Self::new(Self::default_state_dir()).with_staging_dir(Self::default_staging_dir())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedRemotesConfig {
    remotes: Vec<PersistedRemoteEntry>,
    routing_policy: Option<RoutingPolicy>,
}

/// Non-secret remote backend entry persisted in `remotes.json`.
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

/// Non-secret local book of authorized recipient public bundles for sealing `keybox.zv`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedKeyboxState {
    vault_id: Option<Uuid>,
    epoch: u64,
    owner_ed25519_pubkey: Option<[u8; 32]>,
    recipients: Vec<RecipientPublicBundle>,
}

/// Cancellable handle to a periodic background sync task (`NEW-H03` remediation).
pub struct BackgroundSyncHandle {
    stop_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl std::fmt::Debug for BackgroundSyncHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundSyncHandle")
            .field("finished", &self.join_handle.is_finished())
            .finish_non_exhaustive()
    }
}

impl BackgroundSyncHandle {
    /// Signals cancellation to the background sync loop without awaiting task completion.
    pub fn cancel(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Cancels the background sync loop and awaits clean task exit.
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.join_handle.await;
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

    /// Returns the active [`StorageRouter`], if configured.
    #[must_use]
    pub fn current_router(&self) -> Option<Arc<StorageRouter>> {
        self.inner.read().clone()
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

    async fn get_blob_from_backend(
        &self,
        backend_id: &str,
        object_key: &str,
    ) -> ZeroVaultResult<Bytes> {
        self.active()?
            .get_blob_from_backend(backend_id, object_key)
            .await
    }

    fn candidate_backends(&self, preferred_backends: &[BackendId]) -> Vec<BackendId> {
        match self.inner.read().as_ref() {
            Some(router) => router.candidate_backends(preferred_backends),
            None => preferred_backends.to_vec(),
        }
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

    /// Injects a custom [`SyncEngineFactory`] (defaults to [`CoreSyncEngineFactory`]).
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

    /// Validates paths, enforces `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)` / `0700` on `state_dir`
    /// and `staging_dir`, and builds the [`DaemonRuntime`].
    pub fn build(self) -> ZeroVaultResult<DaemonRuntime> {
        ensure_owner_only_dir(&self.config.state_dir)?;
        ensure_owner_only_dir(&self.config.staging_dir)?;

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
        let persisted_backups = load_backup_state(&self.config.backup_jobs_path)?;
        let persisted_keybox = load_keybox_state(&self.config.keybox_state_path)?;
        let initial_kb_epoch = persisted_keybox.epoch;

        let storage_router = Arc::new(DynamicStorageRouter::default());
        storage_router.set_router(None, persisted_remotes.routing_policy.clone());
        let (shutdown_tx, _) = watch::channel(false);

        Ok(DaemonRuntime {
            config: self.config,
            crypto,
            secret_store,
            sync_factory,
            drive_factory,
            storage_router,
            remotes_config: AsyncRwLock::new(persisted_remotes),
            backup_state: AsyncRwLock::new(persisted_backups),
            backup_exec_lock: AsyncMutex::new(()),
            backup_cancel_flag: Arc::new(AtomicBool::new(false)),
            active_backup_job_id: SyncRwLock::new(None),
            active_activity: SyncRwLock::new(None),
            oauth_exec_lock: AsyncMutex::new(()),
            oauth_cancel_flag: Arc::new(AtomicBool::new(false)),
            oauth_cancel_notify: Arc::new(Notify::new()),
            keybox_state: AsyncRwLock::new(persisted_keybox),
            cached_keybox_epoch: AtomicU64::new(initial_kb_epoch),
            sync_bundle: AsyncRwLock::new(None),
            active_drive: AsyncMutex::new(None),
            throughput: SyncMutex::new(ThroughputTracker::default()),
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_tx,
            lifecycle_lock: AsyncMutex::new(()),
        })
    }
}

/// Core stateful runtime for `entrocloudd` handling IPC commands, vault key lifecycle,
/// multi-device cloud bootstrap, automatic PC folder backups, sharing/keybox rotation,
/// and virtual drive mount orchestration.
pub struct DaemonRuntime {
    config: DaemonStateConfig,
    crypto: Arc<dyn CryptoEngine>,
    secret_store: Arc<dyn SecretStore>,
    sync_factory: Arc<dyn SyncEngineFactory>,
    drive_factory: Arc<dyn DriveFactory>,
    storage_router: Arc<DynamicStorageRouter>,
    remotes_config: AsyncRwLock<PersistedRemotesConfig>,
    backup_state: AsyncRwLock<PersistedBackupState>,
    backup_exec_lock: AsyncMutex<()>,
    backup_cancel_flag: Arc<AtomicBool>,
    active_backup_job_id: SyncRwLock<Option<String>>,
    active_activity: SyncRwLock<Option<String>>,
    oauth_exec_lock: AsyncMutex<()>,
    oauth_cancel_flag: Arc<AtomicBool>,
    oauth_cancel_notify: Arc<Notify>,
    keybox_state: AsyncRwLock<PersistedKeyboxState>,
    cached_keybox_epoch: AtomicU64,
    sync_bundle: AsyncRwLock<Option<Arc<SyncBackendBundle>>>,
    active_drive: AsyncMutex<Option<Arc<dyn VirtualDrive>>>,
    throughput: SyncMutex<ThroughputTracker>,
    shutdown_notify: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
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

    /// Spawns a cancellable periodic background sync loop (`NEW-H03` remediation).
    ///
    /// Returns `None` when `interval.is_zero()`. Whenever the vault is unlocked and at least one
    /// remote backend is configured, runs a sync cycle and calls [`reclaim_process_memory`] so
    /// `zerovaultd` drops back to `~5.7 MiB` idle physical RSS.
    #[must_use]
    pub fn spawn_background_sync(
        self: &Arc<Self>,
        interval: Duration,
    ) -> Option<BackgroundSyncHandle> {
        if interval.is_zero() {
            return None;
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let runtime = Arc::clone(self);

        let join_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Consume initial immediate tick so first periodic sync occurs after `interval`.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        if *stop_rx.borrow() || *shutdown_rx.borrow() {
                            break;
                        }
                        runtime.run_periodic_sync_tick().await;
                    }
                }
            }
        });

        Some(BackgroundSyncHandle {
            stop_tx,
            join_handle,
        })
    }

    async fn run_periodic_sync_tick(&self) {
        if !self.crypto.is_unlocked() {
            return;
        }

        // 1. Run any scheduled PC folder backup jobs that are currently due (`SchedulePolicy::is_due`).
        Box::pin(self.run_due_scheduled_backups()).await;

        if self.remotes_config.read().await.remotes.is_empty() {
            return;
        }

        let bundle = self.sync_bundle.read().await.clone();
        let Some(bundle) = bundle else {
            return;
        };

        self.ensure_remote_vault_header_best_effort().await;

        let res = if let Some(ref runner) = bundle.sync_runner {
            runner.sync_now().await
        } else {
            self.sync_factory.sync_now(&bundle).await
        };

        if let Err(err) = res {
            tracing::warn!(
                code = error_code(&err),
                error = %err,
                "periodic background sync cycle encountered error"
            );
        }

        reclaim_process_memory().await;
    }

    /// Dispatches a single [`DaemonRequest`] and maps domain errors to [`DaemonResponse::Error`].
    ///
    /// Returns a heap-pinned `Future` (`16` bytes on 64-bit targets) so callers never inline
    /// the multi-branch IPC state machine onto narrow OS stacks in unoptimized `dev` builds.
    pub fn handle_request(
        &self,
        req: DaemonRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DaemonResponse> + Send + '_>> {
        Box::pin(self.handle_request_inner(req))
    }

    async fn handle_request_inner(&self, req: DaemonRequest) -> DaemonResponse {
        match Box::pin(self.dispatch_inner(req)).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(code = error_code(&err), error = %err, "daemon request failed");
                error_to_daemon_response(&err)
            }
        }
    }

    /// Gracefully stops background sync, unmounts any active virtual drive, locks/zeroizes vault
    /// keys, purges staging/LRU caches, and reclaims `mimalloc` idle pages.
    pub async fn graceful_shutdown(&self) -> ZeroVaultResult<()> {
        let _ = self.shutdown_tx.send(true);
        self.oauth_cancel_flag.store(true, Ordering::SeqCst);
        self.oauth_cancel_notify.notify_waiters();
        self.backup_cancel_flag.store(true, Ordering::Release);
        let _guard = self.lifecycle_lock.lock().await;
        Box::pin(self.lock_and_unmount_locked()).await?;
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
                Box::pin(self.init_vault(&secret)).await
            }
            DaemonRequest::UnlockVault { passphrase } => {
                let secret = RedactedSecret::from(passphrase);
                Box::pin(self.unlock_vault(&secret)).await
            }
            DaemonRequest::LockVault => Box::pin(self.lock_vault()).await,
            DaemonRequest::AddRemote(params) => Box::pin(self.add_remote(*params)).await,
            DaemonRequest::RemoveRemote { id } => Box::pin(self.remove_remote(&id)).await,
            DaemonRequest::SetRoutingPolicy { policy } => {
                Box::pin(self.set_routing_policy(policy)).await
            }
            DaemonRequest::OAuthLogin(params) => Box::pin(self.oauth_login(*params)).await,
            DaemonRequest::CancelOAuth => {
                self.oauth_cancel_flag.store(true, Ordering::SeqCst);
                self.oauth_cancel_notify.notify_waiters();
                Ok(DaemonResponse::Ok {
                    message: "OAuth sign-in cancellation signaled".to_owned(),
                })
            }
            DaemonRequest::TestRemote { id } => Box::pin(self.test_remote(&id)).await,
            DaemonRequest::ListRemotes => Box::pin(self.list_remotes()).await,
            DaemonRequest::DetectLocalClouds => {
                let detected = tokio::task::spawn_blocking(detect_local_cloud_folders)
                    .await
                    .map_err(|e| {
                        ZeroVaultError::Io(std::io::Error::other(format!(
                            "cloud detection worker failed: {e}"
                        )))
                    })?;
                Ok(DaemonResponse::DetectedClouds(detected))
            }
            DaemonRequest::ListBackupJobs => Box::pin(self.list_backup_jobs()).await,
            DaemonRequest::UpsertBackupJob(spec) => Box::pin(self.upsert_backup_job(*spec)).await,
            DaemonRequest::RemoveBackupJob { id } => {
                Box::pin(self.remove_backup_job(&id)).await
            }
            DaemonRequest::RunBackupJob { id, preview } => {
                Box::pin(self.run_backup_job(&id, preview)).await
            }
            DaemonRequest::RunAllBackups { preview } => {
                Box::pin(self.run_all_backups(preview)).await
            }
            DaemonRequest::RestoreBackupJob {
                id,
                destination_parent,
            } => Box::pin(self.restore_backup_job(&id, &destination_parent)).await,
            DaemonRequest::SetBackupsPaused { paused } => {
                Box::pin(self.set_backups_paused(paused)).await
            }
            DaemonRequest::CancelActiveBackup => Box::pin(self.cancel_active_backup()).await,
            DaemonRequest::Mount { mount_point } => {
                Box::pin(self.mount_drive_with_options(&mount_point, None)).await
            }
            DaemonRequest::MountWithOptions {
                mount_point,
                use_mock_vfs,
            } => {
                Box::pin(self.mount_drive_with_options(&mount_point, Some(use_mock_vfs))).await
            }
            DaemonRequest::Unmount => Box::pin(self.unmount_drive()).await,
            DaemonRequest::Pin { virtual_path } => Box::pin(self.pin_path(&virtual_path)).await,
            DaemonRequest::Unpin { virtual_path } => Box::pin(self.unpin_path(&virtual_path)).await,
            DaemonRequest::Dehydrate { virtual_path } => {
                Box::pin(self.dehydrate_path(&virtual_path)).await
            }
            DaemonRequest::ListDirectory { virtual_path } => {
                Box::pin(self.list_directory(&virtual_path)).await
            }
            DaemonRequest::CreateDirectory { virtual_path } => {
                Box::pin(self.create_directory(&virtual_path)).await
            }
            DaemonRequest::ImportLocalFile {
                local_path,
                virtual_dest_path,
            } => Box::pin(self.import_local_file(&local_path, &virtual_dest_path)).await,
            DaemonRequest::ExportVaultFile {
                virtual_path,
                local_dest_path,
            } => Box::pin(self.export_vault_file(&virtual_path, &local_dest_path)).await,
            DaemonRequest::ReadTextNote { virtual_path } => {
                Box::pin(self.read_text_note(&virtual_path)).await
            }
            DaemonRequest::SaveTextNote {
                virtual_path,
                content,
            } => {
                let zeroizing_content = Zeroizing::new(content);
                Box::pin(self.save_text_note(&virtual_path, &zeroizing_content)).await
            }
            DaemonRequest::DeleteEntry {
                virtual_path,
                recursive,
            } => Box::pin(self.delete_entry(&virtual_path, recursive)).await,
            DaemonRequest::RenameEntry {
                virtual_path,
                new_virtual_path,
            } => Box::pin(self.rename_entry(&virtual_path, &new_virtual_path)).await,
            DaemonRequest::ExportRecipientBundle { label } => {
                Box::pin(self.export_recipient_bundle(&label)).await
            }
            DaemonRequest::CreateCapabilityShare { virtual_path } => {
                Box::pin(self.create_capability_share(&virtual_path)).await
            }
            DaemonRequest::ImportCapabilityShare {
                uri,
                dest_virtual_path,
            } => {
                let zeroizing_uri = Zeroizing::new(uri);
                Box::pin(self.import_capability_share(&zeroizing_uri, &dest_virtual_path)).await
            }
            DaemonRequest::InitKeybox => Box::pin(self.init_keybox()).await,
            DaemonRequest::GrantKeyboxRecipient {
                recipient_bundle_b64,
            } => Box::pin(self.grant_keybox_recipient(&recipient_bundle_b64)).await,
            DaemonRequest::RevokeKeyboxRecipient { recipient_id } => {
                Box::pin(self.revoke_keybox_recipient(&recipient_id)).await
            }
            DaemonRequest::KeyboxStatus => Box::pin(self.keybox_status()).await,
            DaemonRequest::BenchCrypto { total_mib } => {
                Box::pin(self.bench_crypto(total_mib)).await
            }
            DaemonRequest::ListConflicts => Box::pin(self.list_conflicts()).await,
            DaemonRequest::SyncNow => Box::pin(self.sync_now()).await,
            DaemonRequest::Status => Box::pin(self.status()).await,
            DaemonRequest::Shutdown => {
                Box::pin(self.graceful_shutdown()).await?;
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
        ensure_owner_only_dir(&self.config.state_dir)?;
        ensure_owner_only_dir(&self.config.staging_dir)?;

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

        Box::pin(self.activate_unlocked_subsystems(false)).await?;

        // `NEW-C01`: Automatically publish `vault/header.zvh` if remotes are already configured.
        if let Some(router) = self.storage_router.current_router() {
            publish_vault_header_to_router_best_effort(&router, &header, None).await;
        }

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
        ensure_owner_only_dir(&self.config.state_dir)?;
        ensure_owner_only_dir(&self.config.staging_dir)?;

        // `NEW-C01`: If local `vault.zvh` is missing, automatically fetch `vault/header.zvh` from remotes!
        let (header, bootstrapped_from_remote) = if self.config.vault_header_path.exists() {
            (load_vault_header(&self.config.vault_header_path)?, false)
        } else {
            let cfg_snapshot = self.remotes_config.read().await.clone();
            let Some(bootstrap_router) = self.build_bootstrap_router(&cfg_snapshot).await?
            else {
                return Err(ZeroVaultError::ConfigError(format!(
                    "vault is not initialized locally (missing {}) and no remote backends are configured to fetch {}",
                    self.config.vault_header_path.display(),
                    VAULT_HEADER_OBJECT_KEY
                )));
            };
            let fetched = SyncEngine::fetch_vault_header(bootstrap_router.as_ref()).await?;
            (fetched, true)
        };

        self.crypto
            .unlock_with_passphrase(&header, passphrase)
            .await?;

        if bootstrapped_from_remote {
            persist_vault_header(&self.config.vault_header_path, &header)?;
        }

        if let Err(err) = Box::pin(self.activate_unlocked_subsystems(bootstrapped_from_remote)).await
        {
            let _ = self.crypto.lock_vault().await;
            return Err(err);
        }

        reclaim_process_memory().await;

        tracing::info!(
            vault_id = %header.vault_id,
            bootstrapped_from_remote,
            "vault unlocked"
        );
        Ok(DaemonResponse::Ok {
            message: format!("vault {} unlocked", header.vault_id),
        })
    }

    async fn activate_unlocked_subsystems(
        &self,
        bootstrapped_from_remote: bool,
    ) -> ZeroVaultResult<()> {
        let cfg_snapshot = self.remotes_config.read().await.clone();
        self.promote_preunlock_remote_secrets(&cfg_snapshot).await?;
        self.rebuild_storage_router(&cfg_snapshot, true).await?;

        // Check if `vault/keybox.zv` exists on remotes BEFORE opening SQLite so that if the
        // vault's `FolderRootKey` was rotated by a prior `RevokeKeyboxRecipient`, we unlock
        // with the active rotated `FolderRootKey` and report accurate `keybox_epoch`!
        let mut remote_kb_missing = false;
        if !cfg_snapshot.remotes.is_empty() {
            remote_kb_missing = Box::pin(self.reconcile_keybox_on_unlock()).await?;
        }

        let storage_trait: Arc<dyn StorageRouterTrait> = self.storage_router.clone();
        let bundle = Arc::new(
            self.sync_factory
                .create_backend_with_staging(
                    &self.config.state_dir,
                    &self.config.staging_dir,
                    Arc::clone(&self.crypto),
                    storage_trait,
                )
                .await?,
        );

        let persisted_floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let cur_kb_epoch = self.cached_keybox_epoch.load(Ordering::Acquire);
        if remote_kb_missing && persisted_floor > 0 {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "remote keybox.zv missing despite local keybox epoch floor {persisted_floor}"
            )));
        }
        if cur_kb_epoch > 0 {
            bundle
                .metadata
                .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, cur_kb_epoch)
                .await?;
        } else if persisted_floor > 0 {
            self.cached_keybox_epoch
                .store(persisted_floor, Ordering::Release);
        }

        // When a brand-new secondary device just bootstrapped `vault/header.zvh` from remotes,
        // perform an initial manifest sync so remote entries are immediately visible.
        if bootstrapped_from_remote && let Some(ref engine) = bundle.sync_engine {
            match engine.sync_once().await {
                Ok(_) => {}
                Err(err) if is_fatal_unlock_error(&err) => return Err(err),
                Err(err) => {
                    tracing::warn!(
                        code = error_code(&err),
                        error = %err,
                        "deferred initial manifest pull during cloud bootstrap"
                    );
                }
            }
        }

        *self.sync_bundle.write().await = Some(bundle);
        Ok(())
    }

    /// Verifies any remote `vault/keybox.zv` (`Ed25519` signature, `vault_id`, pinned owner pubkey,
    /// and monotonic `epoch` floor) BEFORE opening SQLite or advancing `epoch_floor`.
    /// Returns `Ok(true)` when `vault/keybox.zv` was definitively `StorageNotFound` on remotes.
    async fn reconcile_keybox_on_unlock(&self) -> ZeroVaultResult<bool> {
        let Some(router) = self.storage_router.current_router() else {
            return Ok(false);
        };
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let mut persisted_kb = self.keybox_state.read().await.clone();
        let state_matches_vault =
            persisted_kb.vault_id.is_none() || persisted_kb.vault_id == Some(vault_id);
        let pinned_owner = if state_matches_vault {
            persisted_kb.owner_ed25519_pubkey
        } else {
            None
        };
        let min_floor = if state_matches_vault {
            persisted_kb
                .epoch
                .max(self.cached_keybox_epoch.load(Ordering::Acquire))
                .max(1)
        } else {
            self.cached_keybox_epoch.load(Ordering::Acquire).max(1)
        };

        let remote_kb = match tokio::time::timeout(
            Duration::from_secs(4),
            fetch_remote_keybox(
                router.as_ref(),
                self.crypto.as_ref(),
                Some(vault_id),
                pinned_owner.as_ref(),
                min_floor,
            ),
        )
        .await
        {
            Ok(Ok(Some(kb))) => kb,
            Ok(Ok(None)) => return Ok(true),
            Ok(Err(err @ ZeroVaultError::CryptoTamperDetected(_))) => return Err(err),
            Ok(Err(err)) => {
                tracing::warn!(
                    code = error_code(&err),
                    error = %err,
                    "unable to probe remote keybox.zv during unlock"
                );
                return Ok(false);
            }
            Err(_) => {
                tracing::warn!("timed out probing remote keybox.zv during unlock; continuing with local epoch floor");
                return Ok(false);
            }
        };

        // Always verify envelope (`Ed25519` signature + `vault_id` + pinned owner + `min_floor`).
        self.crypto.verify_keybox_envelope(
            &remote_kb,
            Some(vault_id),
            pinned_owner.as_ref(),
            min_floor,
        )?;

        let local_id_opt = self.load_existing_recipient_identity().await?;

        // Vector B (`W4-VETO-KEYBOX-SIG`): On a single-user vault with neither a pinned keybox
        // owner nor a local recipient identity, any unexpected remote `vault/keybox.zv` cannot be
        // authenticated to an authorized owner/recipient and MUST fail closed before SQLite opens!
        if local_id_opt.is_none() && pinned_owner.is_none() {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "unexpected remote keybox.zv present on single-user vault without pinned owner or recipient identity"
                    .into(),
            ));
        }

        if let Some(local_id) = local_id_opt {
            let frk = self.crypto.open_keybox(
                &remote_kb,
                pinned_owner.as_ref(),
                min_floor,
                &local_id,
            )?;
            self.crypto
                .unlock_with_folder_key(remote_kb.vault_id, &frk)?;

            if !state_matches_vault
                || persisted_kb.owner_ed25519_pubkey.is_none()
                || remote_kb.epoch > persisted_kb.epoch
            {
                persisted_kb.vault_id = Some(remote_kb.vault_id);
                persisted_kb.epoch = if state_matches_vault {
                    persisted_kb.epoch.max(remote_kb.epoch)
                } else {
                    remote_kb.epoch
                };
                persisted_kb.owner_ed25519_pubkey = Some(remote_kb.owner_ed25519_pubkey);
                persist_keybox_state(&self.config.keybox_state_path, &persisted_kb)?;
                *self.keybox_state.write().await = persisted_kb;
            }
        }

        self.cached_keybox_epoch
            .store(remote_kb.epoch, Ordering::Release);
        Ok(false)
    }

    async fn lock_vault(&self) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        self.lock_and_unmount_locked().await?;
        tracing::info!("vault locked, caches purged, and mimalloc pages reclaimed");
        Ok(DaemonResponse::Ok {
            message: "vault locked".to_owned(),
        })
    }

    async fn lock_and_unmount_locked(&self) -> ZeroVaultResult<()> {
        self.backup_cancel_flag.store(true, Ordering::Release);
        *self.active_backup_job_id.write() = None;
        *self.active_activity.write() = None;

        if let Some(drive) = self.active_drive.lock().await.take()
            && drive.is_mounted()
        {
            drive.unmount().await?;
        }

        let prev_bundle = self.sync_bundle.write().await.take();
        let policy = self.remotes_config.read().await.routing_policy.clone();
        self.storage_router.set_router(None, policy);

        if let Some(bundle) = prev_bundle
            && let Some(ref engine) = bundle.sync_engine
        {
            engine.lock_and_purge_cache().await?;
        } else {
            self.crypto.lock_vault().await?;
        }

        reclaim_process_memory().await;
        Ok(())
    }

    async fn promote_preunlock_remote_secrets(
        &self,
        cfg: &PersistedRemotesConfig,
    ) -> ZeroVaultResult<()> {
        if !self.crypto.is_unlocked() {
            return Ok(());
        }
        for entry in &cfg.remotes {
            let pre_key = preunlock_secret_account(&entry.id);
            if let Some(raw) = self
                .secret_store
                .get_secret(&self.config.secret_service, &pre_key)
                .await?
            {
                let z_raw = Zeroizing::new(raw);
                let secret_str = std::str::from_utf8(z_raw.as_slice()).map_err(|_| {
                    ZeroVaultError::InvalidWireFormat(
                        "corrupt pre-unlock remote credential in OS keyring".into(),
                    )
                })?;
                let redacted = RedactedSecret::new(secret_str);
                let acct_key = entry
                    .secret_account_key
                    .clone()
                    .unwrap_or_else(|| format!("remote:{}", entry.id));
                let user_hint = entry
                    .username
                    .as_deref()
                    .or(entry.access_key_id.as_deref());
                store_remote_secret(
                    &entry.kind,
                    &acct_key,
                    user_hint,
                    &redacted,
                    self.secret_store.as_ref(),
                    self.crypto.as_ref(),
                    &self.config.secret_service,
                )
                .await?;
                let _ = self
                    .secret_store
                    .delete_secret(&self.config.secret_service, &pre_key)
                    .await;
            }
        }
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

        let pre_key = preunlock_secret_account(&id);
        let mut secret_account_key: Option<String> = None;
        if let Some(ref secret_val) = secret {
            let acct_key = format!("remote:{id}");
            if self.crypto.is_unlocked() {
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
                let _ = self
                    .secret_store
                    .delete_secret(&self.config.secret_service, &pre_key)
                    .await;
            } else {
                self.secret_store
                    .set_secret(
                        &self.config.secret_service,
                        &pre_key,
                        secret_val.as_bytes(),
                    )
                    .await?;
            }
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
            let existing_pre = if existing.is_none() {
                self.secret_store
                    .get_secret(&self.config.secret_service, &pre_key)
                    .await?
            } else {
                None
            };
            if existing.is_none() && existing_pre.is_none() {
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

        let new_entry = entry.clone();
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
        let build_res: ZeroVaultResult<Option<Arc<StorageRouter>>> = if self.crypto.is_unlocked() {
            self.build_concrete_router(&cfg, true).await
        } else {
            // When locked, validate ONLY the newly added remote so pre-existing remotes whose
            // credentials are wrapped under the locked vault's TokenWrapKey do not abort setup.
            self.build_single_backend(&new_entry, false)
                .await
                .and_then(|backend| {
                    let single_policy = RoutingPolicy::Targeted {
                        prefix_routes: Vec::new(),
                        default_backend: id.clone(),
                    };
                    StorageRouter::new(vec![backend], single_policy).map(|r| Some(Arc::new(r)))
                })
        };
        let built_router = match build_res {
            Ok(r) => r,
            Err(err) => {
                if let Some(ref acct_key) = secret_account_key {
                    let _ = self
                        .secret_store
                        .delete_secret(&self.config.secret_service, acct_key)
                        .await;
                }
                let _ = self
                    .secret_store
                    .delete_secret(&self.config.secret_service, &pre_key)
                    .await;
                return Err(err);
            }
        };

        persist_remotes_config(&self.config.remotes_config_path, &cfg)?;
        *self.remotes_config.write().await = cfg.clone();

        // `NEW-C01`: Whenever a vault header already exists locally, publish `vault/header.zvh`
        // to the newly registered remote (even if the vault is currently locked, when possible).
        if self.config.vault_header_path.exists()
            && let Some(ref router) = built_router
            && let Ok(local_hdr) = load_vault_header(&self.config.vault_header_path)
        {
            publish_vault_header_to_router_best_effort(router, &local_hdr, Some(&id)).await;
        }

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

    async fn ensure_remote_vault_header_best_effort(&self) {
        if !self.config.vault_header_path.exists() {
            return;
        }
        let Some(router) = self.storage_router.current_router() else {
            return;
        };
        let Ok(header) = load_vault_header(&self.config.vault_header_path) else {
            return;
        };
        if let Ok(None) = router.stat_object(VAULT_HEADER_OBJECT_KEY, &[]).await {
            publish_vault_header_to_router_best_effort(&router, &header, None).await;
        }
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
        let pre_key = preunlock_secret_account(trimmed);
        let _ = self
            .secret_store
            .delete_secret(&self.config.secret_service, &acct_key)
            .await;
        let _ = self
            .secret_store
            .delete_secret(&self.config.secret_service, &pre_key)
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

    async fn set_routing_policy(
        &self,
        mut policy: RoutingPolicy,
    ) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        let mut cfg = self.remotes_config.read().await.clone();
        if cfg.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before setting routing policy".into(),
            ));
        }

        validate_routing_policy(&cfg.remotes, &mut policy)?;
        cfg.routing_policy = Some(policy);

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
        let _oauth_guard = self.oauth_exec_lock.try_lock().map_err(|_| {
            ZeroVaultError::OAuthError(
                "another OAuth sign-in is already in progress; finish or cancel it first".into(),
            )
        })?;
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

        self.oauth_cancel_flag.store(false, Ordering::SeqCst);
        let cancel_notified = self.oauth_cancel_notify.notified();
        tokio::pin!(cancel_notified);
        cancel_notified.as_mut().enable();

        let mut oauth_cfg =
            OAuthProviderConfig::for_preset(preset, client_id.clone(), client_secret);
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
        if self.oauth_cancel_flag.load(Ordering::SeqCst) {
            return Err(ZeroVaultError::OAuthError(
                "OAuth sign-in cancelled by user".into(),
            ));
        }
        if params.open_browser {
            open_url_in_system_browser(listener.authorize_url().as_str())?;
        }

        let timeout = Duration::from_secs(params.timeout_secs.unwrap_or(180).clamp(5, 600));
        let bundle = tokio::select! {
            biased;
            _ = &mut cancel_notified => {
                return Err(ZeroVaultError::OAuthError(
                    "OAuth sign-in cancelled by user".into(),
                ));
            }
            res = listener.wait_for_callback_and_exchange(timeout) => {
                if self.oauth_cancel_flag.load(Ordering::SeqCst) {
                    return Err(ZeroVaultError::OAuthError(
                        "OAuth sign-in cancelled by user".into(),
                    ));
                }
                res?
            }
        };

        let acct_key = format!("remote:{id}");
        let pre_key = preunlock_secret_account(&id);
        if self.crypto.is_unlocked() {
            persist_tokens(
                &bundle,
                self.secret_store.as_ref(),
                self.crypto.as_ref(),
                &self.config.secret_service,
                &acct_key,
            )
            .await?;
            let _ = self
                .secret_store
                .delete_secret(&self.config.secret_service, &pre_key)
                .await;
        } else {
            let dto = OAuthTokenInputDto {
                access_token: bundle.access_token.as_str().to_owned(),
                refresh_token: bundle.refresh_token.as_ref().map(|s| s.as_str().to_owned()),
                token_type: Some(bundle.token_type.clone()),
                expires_at: bundle.expires_at,
                scopes: Some(bundle.scopes.clone()),
                client_id: bundle.client_id.clone(),
                client_secret: bundle.client_secret.as_ref().map(|s| s.as_str().to_owned()),
            };
            let serialized = Zeroizing::new(serde_json::to_vec(&dto).map_err(|e| {
                ZeroVaultError::OAuthError(format!(
                    "failed serializing pre-unlock OAuth2 token bundle: {e}"
                ))
            })?);
            drop(dto);
            self.secret_store
                .set_secret(
                    &self.config.secret_service,
                    &pre_key,
                    serialized.as_slice(),
                )
                .await?;
        }

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
            let _ = self
                .secret_store
                .delete_secret(&self.config.secret_service, &pre_key)
                .await;
            return Err(err);
        }
        reg_res
    }

    async fn test_remote(&self, id: &str) -> ZeroVaultResult<DaemonResponse> {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "remote backend id must not be empty".into(),
            ));
        }

        let entry = {
            let cfg = self.remotes_config.read().await;
            cfg.remotes
                .iter()
                .find(|r| r.id == trimmed)
                .cloned()
                .ok_or_else(|| {
                    ZeroVaultError::StorageNotFound(format!("remote backend '{trimmed}' not found"))
                })?
        };
        let kind_label = backend_kind_label(&entry.kind).to_owned();
        let started = Instant::now();

        if let Some(router) = self.storage_router.current_router()
            && let Some(backend) = router.backend(trimmed)
        {
            let health = backend.probe_health().await;
            let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if health.healthy && backend.used_bytes() == 0 {
                if matches!(
                    backend.config().kind,
                    BackendKind::LocalFs | BackendKind::Memory
                ) {
                    let _ = backend.sync_used_bytes().await;
                } else {
                    let bg_router = Arc::clone(&router);
                    let bg_id = entry.id.clone();
                    tokio::spawn(async move {
                        if let Some(b) = bg_router.backend(&bg_id) {
                            let _ = b.sync_used_bytes().await;
                        }
                    });
                }
            }
            let quota = backend.quota();
            let message = if health.healthy {
                format!(
                    "Connected to '{}' ({kind_label}) in {latency_ms} ms",
                    entry.id
                )
            } else {
                health
                    .last_error
                    .unwrap_or_else(|| format!("Connectivity probe failed for '{}'", entry.id))
            };
            return Ok(DaemonResponse::RemoteTest(RemoteTestReport {
                id: entry.id,
                kind: kind_label,
                healthy: health.healthy,
                latency_ms,
                quota,
                message,
            }));
        }

        let unlocked = self.crypto.is_unlocked();
        match self.build_single_backend(&entry, unlocked).await {
            Ok(backend) => {
                let probe_started = Instant::now();
                let health = backend.probe_health().await;
                let latency_ms =
                    u64::try_from(probe_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                if health.healthy
                    && backend.used_bytes() == 0
                    && matches!(
                        backend.config().kind,
                        BackendKind::LocalFs | BackendKind::Memory
                    )
                {
                    let _ = backend.sync_used_bytes().await;
                }
                let quota = backend.quota();
                let message = if health.healthy {
                    format!(
                        "Connected to '{}' ({kind_label}) in {latency_ms} ms",
                        entry.id
                    )
                } else {
                    health
                        .last_error
                        .unwrap_or_else(|| format!("Connectivity probe failed for '{}'", entry.id))
                };
                Ok(DaemonResponse::RemoteTest(RemoteTestReport {
                    id: entry.id,
                    kind: kind_label,
                    healthy: health.healthy,
                    latency_ms,
                    quota,
                    message,
                }))
            }
            Err(err) => {
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let quota = entry.offline_health().quota;
                Ok(DaemonResponse::RemoteTest(RemoteTestReport {
                    id: entry.id,
                    kind: kind_label,
                    healthy: false,
                    latency_ms,
                    quota,
                    message: err.to_string(),
                }))
            }
        }
    }

    async fn build_single_backend(
        &self,
        entry: &PersistedRemoteEntry,
        include_crypto: bool,
    ) -> ZeroVaultResult<CloudBackend> {
        let mut backend_cfg = entry.to_backend_config();
        let crypto_ref = if include_crypto && self.crypto.is_unlocked() {
            Some(self.crypto.as_ref())
        } else {
            None
        };

        if crypto_ref.is_none() {
            let pre_key = preunlock_secret_account(&entry.id);
            if let Some(raw) = self
                .secret_store
                .get_secret(&self.config.secret_service, &pre_key)
                .await?
            {
                let z_raw = Zeroizing::new(raw);
                let secret_str = std::str::from_utf8(z_raw.as_slice()).map_err(|_| {
                    ZeroVaultError::InvalidWireFormat(
                        "corrupt pre-unlock remote credential in OS keyring".into(),
                    )
                })?;
                let resolved = match entry.kind {
                    BackendKind::GoogleDrive | BackendKind::OneDrive | BackendKind::Dropbox => {
                        if let Ok(mut parsed) = serde_json::from_str::<OAuthTokenInputDto>(secret_str)
                        {
                            let tok = std::mem::take(&mut parsed.access_token);
                            RedactedSecret::from(tok)
                        } else {
                            RedactedSecret::new(secret_str)
                        }
                    }
                    _ => RedactedSecret::new(secret_str),
                };
                backend_cfg.secret_access_key = Some(resolved);
                backend_cfg.secret_account_key = None;
            }
        }

        CloudBackend::from_config_with_options(
            &backend_cfg,
            Some(self.secret_store.as_ref()),
            crypto_ref,
            &self.config.secret_service,
            Default::default(),
        )
        .await
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
        let mut deferred_remote_sync = false;
        if sync_usage && let Some(ref router) = built {
            for backend in router.backends() {
                match backend.config().kind {
                    BackendKind::LocalFs | BackendKind::Memory => {
                        if let Err(err) = backend.sync_used_bytes().await {
                            tracing::warn!(
                                remote_id = %backend.config().id,
                                error = %err,
                                "failed to reconcile local backend quota usage on startup"
                            );
                        }
                    }
                    _ => {
                        deferred_remote_sync = true;
                    }
                }
            }
        }
        let bg_router = if deferred_remote_sync {
            built.clone()
        } else {
            None
        };
        self.storage_router
            .set_router(built, cfg.routing_policy.clone());

        // Reconcile cloud backend health and recursive quota usage asynchronously so unlocking
        // a vault with thousands of Google Drive / S3 chunks never blocks the user.
        if let Some(router) = bg_router {
            tokio::spawn(async move {
                for backend in router.backends() {
                    if matches!(
                        backend.config().kind,
                        BackendKind::LocalFs | BackendKind::Memory
                    ) {
                        continue;
                    }
                    let health = backend.probe_health().await;
                    if health.healthy
                        && let Err(err) = backend.sync_used_bytes().await
                    {
                        tracing::warn!(
                            remote_id = %backend.config().id,
                            error = %err,
                            "failed background remote quota usage reconciliation"
                        );
                    }
                }
            });
        }
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

        let mut built = Vec::with_capacity(cfg.remotes.len());
        for entry in &cfg.remotes {
            let backend = self.build_single_backend(entry, include_crypto).await?;
            built.push(backend);
        }

        let router = StorageRouter::new(built, policy)?;
        Ok(Some(Arc::new(router)))
    }

    /// Builds a best-effort pre-unlock bootstrap router for fetching `vault/header.zvh`,
    /// skipping any remotes whose credentials require an unlocked vault keyring.
    async fn build_bootstrap_router(
        &self,
        cfg: &PersistedRemotesConfig,
    ) -> ZeroVaultResult<Option<Arc<StorageRouter>>> {
        if cfg.remotes.is_empty() {
            return Ok(None);
        }

        let mut built = Vec::with_capacity(cfg.remotes.len());
        for entry in &cfg.remotes {
            match self.build_single_backend(entry, false).await {
                Ok(backend) => built.push(backend),
                Err(err) => {
                    tracing::warn!(
                        remote_id = %entry.id,
                        kind = ?entry.kind,
                        error = %err,
                        "skipping remote during pre-unlock bootstrap (requires unlocked vault keyring)"
                    );
                }
            }
        }
        if built.is_empty() {
            return Ok(None);
        }

        let policy = if built.len() == 1 {
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: built[0].config().id.clone(),
            }
        } else {
            RoutingPolicy::QuotaPooled {
                pool_backends: built.iter().map(|b| b.config().id.clone()).collect(),
            }
        };

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

        let rec = bundle.vfs.resolve_path(&norm).await?;
        bundle.vfs.pin(rec.inode).await?;

        let drive = self.active_drive.lock().await.clone();
        if let Some(d) = drive
            && d.is_mounted()
        {
            d.pin_path(&norm).await?;
        }

        tracing::info!("pinned virtual entry offline");
        Ok(DaemonResponse::Ok {
            message: "entry pinned offline".to_owned(),
        })
    }

    /// Clears the offline pin flag (`VFS-3` remediation: invokes BOTH `bundle.vfs.unpin` AND
    /// `drive.unpin_path` when mounted so OS placeholders and SQLite metadata stay synchronized).
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

        let drive = self.active_drive.lock().await.clone();
        if let Some(d) = drive
            && d.is_mounted()
        {
            d.unpin_path(&norm).await?;
        }

        tracing::info!("cleared offline pin on virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry unpinned".to_owned(),
        })
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
            let refreshed = bundle.vfs.resolve_path(&norm).await?;
            if refreshed.hydration != HydrationState::OnlineOnly {
                bundle.vfs.dehydrate(refreshed.inode).await?;
            }
        } else {
            let rec = bundle.vfs.resolve_path(&norm).await?;
            bundle.vfs.dehydrate(rec.inode).await?;
        }

        reclaim_process_memory().await;

        tracing::info!("dehydrated virtual entry");
        Ok(DaemonResponse::Ok {
            message: "entry dehydrated".to_owned(),
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
        let parent_inode = ensure_virtual_dir_chain(bundle.vfs.as_ref(), &parent_path).await?;

        let created = bundle.vfs.mkdir(parent_inode, &name, 0o755).await?;
        self.notify_active_drive(&created.virtual_path).await;

        tracing::info!("created virtual directory");
        Ok(DaemonResponse::Ok {
            message: "directory created".to_owned(),
        })
    }

    /// Symlink-safe local import (`NEW-D03` remediation) streaming bounded `4 MiB` chunks.
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
        if trimmed_local.is_empty() || trimmed_local.contains('\0') {
            return Err(ZeroVaultError::ConfigError(
                "source local file path must not be empty or contain NUL".into(),
            ));
        }

        let src_path = Path::new(trimmed_local);
        let sym_meta = tokio::fs::symlink_metadata(src_path).await?;
        if is_symlink_or_reparse(&sym_meta) {
            return Err(ZeroVaultError::InvalidPath(
                "refusing local import from symlink or NTFS reparse point".into(),
            ));
        }
        if !sym_meta.is_file() {
            return Err(ZeroVaultError::ConfigError(
                "source local path is not a regular file".into(),
            ));
        }
        if let Some(parent_dir) = src_path.parent()
            && !parent_dir.as_os_str().is_empty()
            && let Ok(parent_meta) = tokio::fs::symlink_metadata(parent_dir).await
            && is_symlink_or_reparse(&parent_meta)
        {
            return Err(ZeroVaultError::InvalidPath(
                "refusing local import through symlink or NTFS reparse directory".into(),
            ));
        }

        let local_name = src_path
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .ok_or_else(|| {
                ZeroVaultError::InvalidPath("source file name is invalid or non-UTF-8".into())
            })?
            .to_owned();

        let mut open_opts = OpenOptions::new();
        open_opts.read(true);
        #[cfg(unix)]
        {
            open_opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut src = open_opts.open(src_path).await?;
        let handle_meta = src.metadata().await?;
        if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
            return Err(ZeroVaultError::InvalidPath(
                "source handle failed TOCTOU regular-file verification".into(),
            ));
        }

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

        let parent_inode = ensure_virtual_dir_chain(bundle.vfs.as_ref(), &parent_path).await?;
        let parent = bundle.vfs.getattr(parent_inode).await?;

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
        drop(chunk_buf);

        let has_remotes = !self.remotes_config.read().await.remotes.is_empty();
        let uploaded_immediately = self
            .try_flush_after_mutation(&bundle, inode, has_remotes)
            .await?;

        let target_vpath = join_virtual_path(&parent.virtual_path, &file_name);
        self.notify_active_drive(&target_vpath).await;
        reclaim_process_memory().await;

        tracing::info!(
            bytes = offset,
            uploaded_immediately,
            "imported local file into vault"
        );
        let message = if uploaded_immediately {
            format!("encrypted & uploaded {offset} bytes")
        } else {
            format!("encrypted & staged {offset} bytes locally (sync pending)")
        };
        Ok(DaemonResponse::Ok { message })
    }

    /// Atomic `.partial` vault file export (`NEW-D03`: delegates to [`SyncEngine::export_file_atomic`]).
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
        let trimmed_dest = local_dest_path.trim();
        if trimmed_dest.is_empty() || trimmed_dest.contains('\0') {
            return Err(ZeroVaultError::ConfigError(
                "local destination path must not be empty or contain NUL".into(),
            ));
        }

        let exported_bytes = if let Some(ref engine) = bundle.sync_engine {
            let out_path = engine
                .export_file_atomic(&norm, Path::new(trimmed_dest))
                .await?;
            let meta = tokio::fs::symlink_metadata(&out_path).await?;
            meta.len()
        } else {
            export_vfs_file_atomic_fallback(bundle.vfs.as_ref(), &norm, Path::new(trimmed_dest))
                .await?
        };

        reclaim_process_memory().await;

        tracing::info!(
            bytes = exported_bytes,
            "verified and exported vault file to disk"
        );
        Ok(DaemonResponse::Ok {
            message: format!("verified & exported {exported_bytes} bytes"),
        })
    }

    async fn read_text_note(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
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
        if rec.size > MAX_TEXT_NOTE_BYTES as u64 {
            return Err(ZeroVaultError::InvalidRange {
                offset: 0,
                len: MAX_TEXT_NOTE_BYTES,
                size: rec.size,
            });
        }

        let content = if rec.size == 0 {
            String::new()
        } else {
            let bytes = bundle
                .vfs
                .read_range(rec.inode, 0, rec.size as usize)
                .await?;
            String::from_utf8(bytes.to_vec()).map_err(|_| {
                ZeroVaultError::InvalidWireFormat(
                    "vault entry is not valid UTF-8 text note".into(),
                )
            })?
        };

        Ok(DaemonResponse::TextNote {
            virtual_path: norm,
            content,
        })
    }

    async fn save_text_note(
        &self,
        virtual_path: &str,
        content: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        if content.len() > MAX_TEXT_NOTE_BYTES {
            return Err(ZeroVaultError::InvalidRange {
                offset: 0,
                len: content.len(),
                size: MAX_TEXT_NOTE_BYTES as u64,
            });
        }

        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let (parent_path, file_name) = split_parent_and_name(virtual_path)?;
        let parent_inode = ensure_virtual_dir_chain(bundle.vfs.as_ref(), &parent_path).await?;
        let parent = bundle.vfs.getattr(parent_inode).await?;

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

        if !content.is_empty() {
            bundle
                .vfs
                .write_range(inode, 0, content.as_bytes())
                .await?;
        }

        let has_remotes = !self.remotes_config.read().await.remotes.is_empty();
        let _ = self
            .try_flush_after_mutation(&bundle, inode, has_remotes)
            .await?;

        let target_vpath = join_virtual_path(&parent.virtual_path, &file_name);
        self.notify_active_drive(&target_vpath).await;

        Ok(DaemonResponse::Ok {
            message: format!("saved {} bytes", content.len()),
        })
    }

    async fn try_flush_after_mutation(
        &self,
        bundle: &SyncBackendBundle,
        inode: InodeId,
        has_remotes: bool,
    ) -> ZeroVaultResult<bool> {
        if !has_remotes && bundle.sync_runner.is_some() {
            return Ok(false);
        }
        match bundle.vfs.flush(inode).await {
            Ok(()) => Ok(true),
            Err(
                err @ (ZeroVaultError::VaultLocked | ZeroVaultError::CryptoTamperDetected(_)),
            ) => Err(err),
            Err(ZeroVaultError::StorageConflict(_)) => {
                if let Some(ref engine) = bundle.sync_engine
                    && engine.sync_once().await.is_ok()
                {
                    return Ok(true);
                }
                Ok(false)
            }
            Err(err) => {
                tracing::warn!(
                    code = error_code(&err),
                    "remote upload deferred; chunk data staged locally"
                );
                Ok(false)
            }
        }
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

    fn identity_secret_account(&self) -> String {
        let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
        let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
        for &b in self.config.state_dir.to_string_lossy().as_bytes() {
            h1 ^= u64::from(b);
            h1 = h1.wrapping_mul(0x0000_0100_0000_01b3);
            h2 = h2.wrapping_add(u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        format!("recipient-identity:{h1:016x}{h2:016x}")
    }

    fn identity_wrapped_account(&self) -> String {
        format!("{}:wrapped", self.identity_secret_account())
    }

    fn identity_wrap_key_account(&self) -> String {
        format!("{}:wrap-key", self.identity_secret_account())
    }

    async fn load_existing_recipient_identity(
        &self,
    ) -> ZeroVaultResult<Option<RecipientPrivateIdentity>> {
        // 1. Primary path (B2): compact postcard+AEAD `recipient_identity.zvi` wrapped under a
        //    32-byte key stored in OS keyring (well under Windows CredWriteW 2,560-byte cap).
        if self.config.identity_state_path.exists() {
            let raw_file = std::fs::read(&self.config.identity_state_path)?;
            if raw_file.starts_with(IDENTITY_ZVI_MAGIC) {
                let wrap_acct = self.identity_wrap_key_account();
                if let Some(key_bytes) = self
                    .secret_store
                    .get_secret(&self.config.secret_service, &wrap_acct)
                    .await?
                    && key_bytes.len() == IDENTITY_WRAP_KEY_LEN
                {
                    let mut wrap_key = Zeroizing::new([0u8; IDENTITY_WRAP_KEY_LEN]);
                    wrap_key.copy_from_slice(&key_bytes);
                    let parsed = open_recipient_identity_zvi(&wrap_key, &raw_file)?;
                    parsed.public.validate()?;
                    return Ok(Some(parsed));
                }
            } else if self.crypto.is_unlocked()
                && let Ok(unwrapped) = self.crypto.unwrap_token_payload(&raw_file)
            {
                // Backward-compatible fallback: legacy vault-wrapped JSON `recipient_identity.zvi`.
                let parsed: RecipientPrivateIdentity = serde_json::from_slice(unwrapped.as_slice())
                    .map_err(|e| {
                        ZeroVaultError::InvalidWireFormat(format!(
                            "corrupt wrapped recipient identity file: {e}"
                        ))
                    })?;
                parsed.public.validate()?;
                return Ok(Some(parsed));
            }
        }

        // 2. Backward-compatible fallback: legacy wrapped identity entry in OS keyring.
        if self.crypto.is_unlocked() {
            let wrapped_acct = self.identity_wrapped_account();
            if let Some(wrapped) = self
                .secret_store
                .get_secret(&self.config.secret_service, &wrapped_acct)
                .await?
                && let Ok(unwrapped) = self.crypto.unwrap_token_payload(wrapped.as_slice())
            {
                let parsed: RecipientPrivateIdentity = serde_json::from_slice(unwrapped.as_slice())
                    .map_err(|e| {
                        ZeroVaultError::InvalidWireFormat(format!(
                            "corrupt wrapped recipient identity in secret store: {e}"
                        ))
                    })?;
                parsed.public.validate()?;
                return Ok(Some(parsed));
            }
        }

        // 3. Backward-compatible fallback: legacy raw JSON entry in OS keyring.
        let raw_acct = self.identity_secret_account();
        if let Some(raw) = self
            .secret_store
            .get_secret(&self.config.secret_service, &raw_acct)
            .await?
        {
            let parsed: RecipientPrivateIdentity =
                serde_json::from_slice(raw.as_slice()).map_err(|e| {
                    ZeroVaultError::InvalidWireFormat(format!(
                        "corrupt recipient identity in OS keyring: {e}"
                    ))
                })?;
            parsed.public.validate()?;
            return Ok(Some(parsed));
        }

        Ok(None)
    }

    async fn persist_recipient_identity(
        &self,
        identity: &RecipientPrivateIdentity,
    ) -> ZeroVaultResult<()> {
        identity.public.validate()?;

        // Store ONLY a 32-byte wrapping key in the OS keyring (Windows CredWriteW caps at 2,560 bytes)
        // and persist the compact postcard+AEAD identity blob in `recipient_identity.zvi`.
        let wrap_acct = self.identity_wrap_key_account();
        let wrap_key: Zeroizing<[u8; IDENTITY_WRAP_KEY_LEN]> = if let Some(existing_key) = self
            .secret_store
            .get_secret(&self.config.secret_service, &wrap_acct)
            .await?
            && existing_key.len() == IDENTITY_WRAP_KEY_LEN
        {
            let mut arr = Zeroizing::new([0u8; IDENTITY_WRAP_KEY_LEN]);
            arr.copy_from_slice(&existing_key);
            arr
        } else {
            use ring::rand::SecureRandom as _;
            let mut arr = Zeroizing::new([0u8; IDENTITY_WRAP_KEY_LEN]);
            ring::rand::SystemRandom::new()
                .fill(arr.as_mut())
                .map_err(|_| {
                    ZeroVaultError::KeyringError(
                        "CSPRNG failure generating recipient identity wrapping key".into(),
                    )
                })?;
            self.secret_store
                .set_secret(&self.config.secret_service, &wrap_acct, arr.as_slice())
                .await?;
            arr
        };

        let sealed = seal_recipient_identity_zvi(&wrap_key, identity)?;
        write_atomic_private(&self.config.identity_state_path, &sealed)?;
        Ok(())
    }

    async fn load_or_create_recipient_identity(
        &self,
        label: &str,
    ) -> ZeroVaultResult<RecipientPrivateIdentity> {
        if let Some(existing) = self.load_existing_recipient_identity().await? {
            self.persist_recipient_identity(&existing).await?;
            return Ok(existing);
        }

        let clean_label = {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                "entrocloud-user"
            } else {
                trimmed
            }
        };
        let generated = self.crypto.generate_recipient_identity(clean_label)?;
        self.persist_recipient_identity(&generated).await?;
        Ok(generated)
    }

    async fn export_recipient_bundle(&self, label: &str) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        let identity = self.load_or_create_recipient_identity(label).await?;
        let bundle_b64 = identity.public.to_base64()?;
        Ok(DaemonResponse::RecipientBundle {
            recipient_id: identity.public.recipient_id.clone(),
            bundle_b64,
        })
    }

    async fn create_capability_share(&self, virtual_path: &str) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError(
                "capability sharing requires CoreSyncEngineFactory".into(),
            )
        })?;

        let norm = normalize_vault_virtual_path(virtual_path)?;
        let (backend_hint, root_locator) = self.resolve_share_locator(&norm).await?;
        let owner_id = self.load_or_create_recipient_identity("owner").await?;

        let (uri, _envelope) = engine
            .create_file_capability_share(&owner_id, &backend_hint, &root_locator, &norm)
            .await?;
        let encoded_uri = uri.encode()?;
        let share_id = uri.share_id;

        tracing::info!(share_id = %share_id, "created ec:// capability share");
        Ok(DaemonResponse::ShareUriCreated {
            uri: encoded_uri,
            share_id,
        })
    }

    async fn resolve_share_locator(&self, virtual_path: &str) -> ZeroVaultResult<(String, String)> {
        let cfg = self.remotes_config.read().await;
        if cfg.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before creating an ec:// share".into(),
            ));
        }

        let chosen_entry = match cfg.routing_policy.as_ref() {
            Some(RoutingPolicy::Targeted {
                prefix_routes,
                default_backend,
            }) => {
                let mut best: Option<&str> = None;
                let mut best_len = 0usize;
                for (pfx, bk) in prefix_routes {
                    if (virtual_path == pfx
                        || pfx == "/"
                        || virtual_path
                            .strip_prefix(pfx.as_str())
                            .is_some_and(|tail| tail.starts_with('/')))
                        && pfx.len() >= best_len
                    {
                        best = Some(bk.as_str());
                        best_len = pfx.len();
                    }
                }
                let target_id = best.unwrap_or(default_backend.as_str());
                cfg.remotes
                    .iter()
                    .find(|r| r.id == target_id)
                    .or_else(|| cfg.remotes.first())
            }
            _ => cfg.remotes.first(),
        }
        .ok_or_else(|| {
            ZeroVaultError::ConfigError("no remote backend available for capability share".into())
        })?;

        Ok((
            backend_kind_label(&chosen_entry.kind).to_owned(),
            chosen_entry.root.clone(),
        ))
    }

    async fn import_capability_share(
        &self,
        uri: &str,
        dest_virtual_path: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError(
                "capability sharing requires CoreSyncEngineFactory".into(),
            )
        })?;

        let dest_raw = if dest_virtual_path.trim().is_empty() {
            "/"
        } else {
            dest_virtual_path
        };
        let dest_norm = normalize_vault_virtual_path(dest_raw)?;

        let imported = match engine.import_capability_share(uri, &dest_norm).await {
            Ok(rec) => rec,
            Err(
                ZeroVaultError::ConfigError(_) | ZeroVaultError::StorageNotFound(_),
            ) => {
                self.import_capability_share_via_locator(engine, uri, &dest_norm)
                    .await?
            }
            Err(err) => return Err(err),
        };

        self.notify_active_drive(&imported.virtual_path).await;
        reclaim_process_memory().await;

        tracing::info!(inode = imported.inode, "imported capability share");
        Ok(DaemonResponse::Ok {
            message: format!("imported shared file ({} bytes)", imported.size),
        })
    }

    async fn import_capability_share_via_locator(
        &self,
        engine: &SyncEngine,
        uri: &str,
        dest_norm: &str,
    ) -> ZeroVaultResult<entrocloud_types::InodeRecord> {
        let parsed = CapabilityUri::parse(uri)?;
        if parsed.backend_hint != "fs" || parsed.root_locator.trim().is_empty() {
            return Err(ZeroVaultError::StorageNotFound(format!(
                "shared object {} not found in configured remotes",
                parsed.share_id
            )));
        }

        let locator_path = Path::new(&parsed.root_locator);
        let loc_meta = tokio::fs::symlink_metadata(locator_path).await?;
        if is_symlink_or_reparse(&loc_meta) || !loc_meta.is_dir() {
            return Err(ZeroVaultError::InvalidPath(
                "capability URI fs root locator must be a real directory".into(),
            ));
        }

        let temp_cfg = BackendConfig {
            id: "ec-share-locator".to_owned(),
            kind: BackendKind::LocalFs,
            root: parsed.root_locator.clone(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: None,
            min_free_reserve_bytes: 0,
            username: None,
            access_key_id: None,
            secret_access_key: None,
            secret_account_key: None,
        };
        let temp_backend = CloudBackend::from_config_with_options(
            &temp_cfg,
            None,
            None,
            &self.config.secret_service,
            Default::default(),
        )
        .await?;
        let temp_router = StorageRouter::new(
            vec![temp_backend],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "ec-share-locator".to_owned(),
            },
        )?;

        let share_key = ShareObjectKey::from_uuid(parsed.share_id);
        let raw_env = temp_router.get_blob(share_key.as_str(), &[]).await?;
        let env = SignedShareEnvelope::decode(&raw_env)?;
        let (descriptor, shared_dek) = self.crypto.open_capability_share(&parsed, &env)?;
        if descriptor.share_id != parsed.share_id {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "share descriptor share_id mismatch".into(),
            ));
        }
        validate_portable_entry_name(&descriptor.filename, false)?;

        let (parent_path, target_name) = if dest_norm == "/" {
            ("/".to_owned(), descriptor.filename.clone())
        } else {
            match engine.resolve_path(dest_norm).await {
                Ok(existing) if existing.kind == EntryKind::Directory => {
                    (dest_norm.to_owned(), descriptor.filename.clone())
                }
                _ => split_parent_and_name(dest_norm)?,
            }
        };
        let parent_inode = ensure_virtual_dir_chain(engine, &parent_path).await?;
        let created = engine
            .create_entry(CreateEntrySpec {
                parent_inode,
                name: target_name,
                mode: 0o644,
            })
            .await?;

        let mut ordered = descriptor.chunks.clone();
        ordered.sort_by_key(|c| c.chunk_index);

        let stream_res: ZeroVaultResult<()> = async {
            let mut total_written = 0u64;
            for chunk_ref in &ordered {
                let blob_key = BlobObjectKey::from_uuid(chunk_ref.blob_id);
                let wire = temp_router.get_blob(blob_key.as_str(), &[]).await?;
                let (_hdr, pt) = self.crypto.decrypt_chunk(
                    &shared_dek,
                    descriptor.file_id,
                    Some(chunk_ref.chunk_index),
                    &wire,
                )?;
                if pt.len() != chunk_ref.plaintext_len as usize {
                    return Err(ZeroVaultError::CryptoTamperDetected(
                        "shared chunk length mismatch".into(),
                    ));
                }
                let offset = chunk_ref
                    .chunk_index
                    .checked_mul(PLAINTEXT_CHUNK_SIZE as u64)
                    .ok_or(ZeroVaultError::InvalidRange {
                        offset: u64::MAX,
                        len: pt.len(),
                        size: descriptor.size,
                    })?;
                if !pt.is_empty() {
                    engine.write_range(created.inode, offset, &pt).await?;
                    total_written = total_written.saturating_add(pt.len() as u64);
                }
            }
            if total_written != descriptor.size {
                return Err(ZeroVaultError::CryptoTamperDetected(
                    "shared file total size mismatch".into(),
                ));
            }
            if !self.remotes_config.read().await.remotes.is_empty() {
                let _ = engine.flush(created.inode).await;
            }
            Ok(())
        }
        .await;

        if let Err(err) = stream_res {
            let _ = engine.unlink(parent_inode, &created.name).await;
            return Err(err);
        }

        engine.getattr(created.inode).await
    }

    async fn fetch_verified_keybox_for_vault(
        &self,
        engine: &SyncEngine,
        vault_id: Uuid,
        expected_owner_pubkey: Option<&[u8; 32]>,
        min_epoch_floor: u64,
    ) -> ZeroVaultResult<SignedKeybox> {
        let floor = min_epoch_floor.max(1);
        if let Some(router) = self.storage_router.current_router() {
            match fetch_remote_keybox(
                router.as_ref(),
                self.crypto.as_ref(),
                Some(vault_id),
                expected_owner_pubkey,
                floor,
            )
            .await?
            {
                Some(kb) => {
                    self.crypto.verify_keybox_envelope(
                        &kb,
                        Some(vault_id),
                        expected_owner_pubkey,
                        floor,
                    )?;
                    return Ok(kb);
                }
                None => {
                    return Err(ZeroVaultError::StorageNotFound(
                        KEYBOX_OBJECT_KEY.to_owned(),
                    ));
                }
            }
        }

        let kb = engine.fetch_keybox().await?;
        self.crypto.verify_keybox_envelope(
            &kb,
            Some(vault_id),
            expected_owner_pubkey,
            floor,
        )?;
        Ok(kb)
    }

    async fn init_keybox(&self) -> ZeroVaultResult<DaemonResponse> {
        let _guard = self.lifecycle_lock.lock().await;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError("keybox.zv requires CoreSyncEngineFactory".into())
        })?;
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;

        if self.remotes_config.read().await.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before initializing keybox.zv".into(),
            ));
        }

        let mut kb_state = self.keybox_state.read().await.clone();
        let state_matches = kb_state.vault_id.is_none() || kb_state.vault_id == Some(vault_id);
        let pinned_owner = if state_matches {
            kb_state.owner_ed25519_pubkey
        } else {
            None
        };
        let sql_floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let min_floor = sql_floor
            .max(if state_matches { kb_state.epoch } else { 0 })
            .max(self.cached_keybox_epoch.load(Ordering::Acquire))
            .max(1);

        let owner_id = self.load_or_create_recipient_identity("owner").await?;

        match self
            .fetch_verified_keybox_for_vault(engine, vault_id, pinned_owner.as_ref(), min_floor)
            .await
        {
            Ok(existing_kb) => {
                // If no owner was pinned yet, ensure the existing remote keybox either matches our
                // local owner Ed25519 pubkey or can be opened by our local recipient identity!
                if pinned_owner.is_none()
                    && existing_kb.owner_ed25519_pubkey != owner_id.public.ed25519_pubkey
                {
                    let _ = self
                        .crypto
                        .open_keybox(&existing_kb, None, min_floor, &owner_id)
                        .map_err(|_| {
                            ZeroVaultError::CryptoTamperDetected(
                                "remote keybox.zv signed by unpinned untrusted Ed25519 key".into(),
                            )
                        })?;
                }

                kb_state.vault_id = Some(vault_id);
                kb_state.epoch = existing_kb.epoch;
                kb_state.owner_ed25519_pubkey = Some(existing_kb.owner_ed25519_pubkey);
                persist_keybox_state(&self.config.keybox_state_path, &kb_state)?;
                *self.keybox_state.write().await = kb_state;

                bundle
                    .metadata
                    .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, existing_kb.epoch)
                    .await?;
                self.cached_keybox_epoch
                    .store(existing_kb.epoch, Ordering::Release);
                return Ok(DaemonResponse::KeyboxInfo(keybox_to_summary(&existing_kb)));
            }
            Err(ZeroVaultError::StorageNotFound(_)) => {
                if sql_floor > 0 {
                    return Err(ZeroVaultError::CryptoTamperDetected(format!(
                        "remote keybox.zv missing despite persisted keybox epoch floor {sql_floor}"
                    )));
                }
            }
            Err(err) => return Err(err),
        }

        let frk = self.crypto.export_folder_root_key()?;
        let recipients = vec![owner_id.public.clone()];
        let signed = self
            .crypto
            .seal_keybox(&owner_id, vault_id, 1, &frk, &recipients)?;
        self.crypto.verify_keybox_envelope(
            &signed,
            Some(vault_id),
            Some(&owner_id.public.ed25519_pubkey),
            1,
        )?;
        engine.publish_keybox(&signed).await?;

        let state = PersistedKeyboxState {
            vault_id: Some(vault_id),
            epoch: 1,
            owner_ed25519_pubkey: Some(owner_id.public.ed25519_pubkey),
            recipients,
        };
        persist_keybox_state(&self.config.keybox_state_path, &state)?;
        *self.keybox_state.write().await = state;
        self.cached_keybox_epoch.store(1, Ordering::Release);

        tracing::info!(vault_id = %vault_id, epoch = 1, "initialized post-quantum keybox.zv");
        Ok(DaemonResponse::KeyboxInfo(keybox_to_summary(&signed)))
    }

    async fn grant_keybox_recipient(
        &self,
        recipient_bundle_b64: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let new_rcpt = RecipientPublicBundle::from_base64(recipient_bundle_b64)?;

        let _guard = self.lifecycle_lock.lock().await;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError("keybox.zv requires CoreSyncEngineFactory".into())
        })?;
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;

        if self.remotes_config.read().await.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before granting keybox recipients".into(),
            ));
        }

        let owner_id = self.load_or_create_recipient_identity("owner").await?;
        let mut kb_state = self.keybox_state.read().await.clone();
        let state_matches = kb_state.vault_id.is_none() || kb_state.vault_id == Some(vault_id);
        if !state_matches {
            kb_state = PersistedKeyboxState::default();
        }
        let expected_owner = kb_state
            .owner_ed25519_pubkey
            .as_ref()
            .unwrap_or(&owner_id.public.ed25519_pubkey);

        let floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let min_floor = floor
            .max(kb_state.epoch)
            .max(self.cached_keybox_epoch.load(Ordering::Acquire))
            .max(1);
        let remote_epoch = match self
            .fetch_verified_keybox_for_vault(engine, vault_id, Some(expected_owner), min_floor)
            .await
        {
            Ok(kb) => kb.epoch,
            Err(ZeroVaultError::StorageNotFound(_)) => {
                if floor > 0 {
                    return Err(ZeroVaultError::CryptoTamperDetected(format!(
                        "remote keybox.zv missing despite persisted keybox epoch floor {floor}"
                    )));
                }
                0
            }
            Err(err) => return Err(err),
        };

        let target_epoch = kb_state.epoch.max(remote_epoch).max(floor).max(1);
        if !kb_state
            .recipients
            .iter()
            .any(|r| r.recipient_id == owner_id.public.recipient_id)
        {
            kb_state.recipients.insert(0, owner_id.public.clone());
        }
        if let Some(existing_slot) = kb_state
            .recipients
            .iter_mut()
            .find(|r| r.recipient_id == new_rcpt.recipient_id)
        {
            *existing_slot = new_rcpt;
        } else {
            kb_state.recipients.push(new_rcpt);
        }

        let frk = self.crypto.export_folder_root_key()?;
        let signed = self.crypto.seal_keybox(
            &owner_id,
            vault_id,
            target_epoch,
            &frk,
            &kb_state.recipients,
        )?;
        self.crypto.verify_keybox_envelope(
            &signed,
            Some(vault_id),
            Some(&owner_id.public.ed25519_pubkey),
            target_epoch,
        )?;
        engine.publish_keybox(&signed).await?;

        kb_state.vault_id = Some(vault_id);
        kb_state.epoch = target_epoch;
        kb_state.owner_ed25519_pubkey = Some(owner_id.public.ed25519_pubkey);
        persist_keybox_state(&self.config.keybox_state_path, &kb_state)?;
        *self.keybox_state.write().await = kb_state;
        self.cached_keybox_epoch
            .store(target_epoch, Ordering::Release);

        tracing::info!(epoch = target_epoch, "granted recipient in keybox.zv");
        Ok(DaemonResponse::KeyboxInfo(keybox_to_summary(&signed)))
    }

    /// Revokes `recipient_id` from `keybox.zv`, rotating `FolderRootKey`, advancing
    /// `epoch -> epoch + 1`, advancing `epoch_floor("keybox")`, re-wrapping DEKs/manifest/SQLite,
    /// and publishing the re-signed `SignedKeybox`.
    async fn revoke_keybox_recipient(
        &self,
        recipient_id: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let target_id = recipient_id.trim().to_ascii_lowercase();
        if target_id.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "recipient_id to revoke must not be empty".into(),
            ));
        }

        let _guard = self.lifecycle_lock.lock().await;
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError("keybox.zv requires CoreSyncEngineFactory".into())
        })?;
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;

        if self.remotes_config.read().await.remotes.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "configure at least one remote backend before revoking keybox recipients".into(),
            ));
        }

        let owner_id = self.load_or_create_recipient_identity("owner").await?;
        if target_id == owner_id.public.recipient_id {
            return Err(ZeroVaultError::ConfigError(
                "cannot revoke the vault owner's own recipient identity".into(),
            ));
        }

        let mut kb_state = self.keybox_state.read().await.clone();
        let state_matches = kb_state.vault_id.is_none() || kb_state.vault_id == Some(vault_id);
        if !state_matches {
            kb_state = PersistedKeyboxState::default();
        }
        let expected_owner = kb_state
            .owner_ed25519_pubkey
            .as_ref()
            .unwrap_or(&owner_id.public.ed25519_pubkey);
        let floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let min_floor = floor
            .max(kb_state.epoch)
            .max(self.cached_keybox_epoch.load(Ordering::Acquire))
            .max(1);

        let remote_kb = self
            .fetch_verified_keybox_for_vault(engine, vault_id, Some(expected_owner), min_floor)
            .await?;
        if !kb_state
            .recipients
            .iter()
            .any(|r| r.recipient_id == owner_id.public.recipient_id)
        {
            kb_state.recipients.insert(0, owner_id.public.clone());
        }

        let before_len = kb_state.recipients.len();
        kb_state.recipients.retain(|r| r.recipient_id != target_id);
        let was_in_remote = remote_kb.stanzas.iter().any(|s| s.recipient_id == target_id);
        if kb_state.recipients.len() == before_len && !was_in_remote {
            return Err(ZeroVaultError::StorageNotFound(format!(
                "recipient '{target_id}' is not authorized in keybox.zv"
            )));
        }

        // Flush any dirty local files under the current FolderRootKey before rotating.
        let _ = engine.sync_once().await?;

        // Snapshot all decrypted metadata, unwrapped file DEKs, and unwrapped remote secrets under old FRK.
        let mut all_inodes = bundle.metadata.list_all_inodes().await?;
        all_inodes.sort_by_key(|r| r.inode);

        let mut unwrapped_deks: HashMap<InodeId, DekBytes> = HashMap::new();
        for rec in &all_inodes {
            if let Some(ref wd) = rec.wrapped_dek {
                let dek = self.crypto.unwrap_dek(rec.file_id, wd)?;
                unwrapped_deks.insert(rec.inode, dek);
            }
        }

        let unwrapped_remote_secrets = self.snapshot_unwrapped_remote_secrets().await?;

        // Generate fresh CSPRNG 256-bit `FolderRootKey` and advance `epoch -> epoch + 1`.
        let cur_epoch = remote_kb.epoch.max(kb_state.epoch).max(floor).max(1);
        let next_epoch = cur_epoch.saturating_add(1);
        let fresh_dek = self.crypto.generate_dek()?;
        let new_frk = Zeroizing::new(*fresh_dek.as_bytes());

        let signed_next = self.crypto.seal_keybox(
            &owner_id,
            vault_id,
            next_epoch,
            &new_frk,
            &kb_state.recipients,
        )?;
        engine.publish_keybox(&signed_next).await?;

        // Activate the rotated FolderRootKey in memory and re-wrap all state under `new_frk`.
        self.crypto.unlock_with_folder_key(vault_id, &new_frk)?;
        self.persist_recipient_identity(&owner_id).await?;
        self.rewrap_remote_secrets(&unwrapped_remote_secrets).await?;

        for mut rec in all_inodes {
            if let Some(dek) = unwrapped_deks.get(&rec.inode) {
                rec.wrapped_dek = Some(self.crypto.wrap_dek(rec.file_id, dek)?);
            }
            bundle.metadata.upsert_inode(rec).await?;
        }

        // Re-seal and publish `manifests/head.zvm` under `new_frk` so revoked holders of `old_frk`
        // can neither decrypt future manifests nor unwrap rotated DEKs.
        self.republish_manifest_after_rotation(&bundle, vault_id)
            .await?;

        kb_state.vault_id = Some(vault_id);
        kb_state.epoch = next_epoch;
        kb_state.owner_ed25519_pubkey = Some(owner_id.public.ed25519_pubkey);
        persist_keybox_state(&self.config.keybox_state_path, &kb_state)?;
        *self.keybox_state.write().await = kb_state;
        self.cached_keybox_epoch
            .store(next_epoch, Ordering::Release);

        reclaim_process_memory().await;

        tracing::info!(
            revoked_recipient = %target_id,
            new_epoch = next_epoch,
            "revoked recipient and rotated FolderRootKey"
        );
        Ok(DaemonResponse::KeyboxInfo(keybox_to_summary(&signed_next)))
    }

    async fn snapshot_unwrapped_remote_secrets(
        &self,
    ) -> ZeroVaultResult<Vec<(String, Zeroizing<Vec<u8>>)>> {
        let cfg = self.remotes_config.read().await.clone();
        let mut out = Vec::new();
        for remote in &cfg.remotes {
            if let Some(ref acct) = remote.secret_account_key
                && let Some(wrapped) = self
                    .secret_store
                    .get_secret(&self.config.secret_service, acct)
                    .await?
                && let Ok(plain) = self.crypto.unwrap_token_payload(wrapped.as_slice())
            {
                out.push((acct.clone(), plain));
            }
        }
        Ok(out)
    }

    async fn rewrap_remote_secrets(
        &self,
        secrets: &[(String, Zeroizing<Vec<u8>>)],
    ) -> ZeroVaultResult<()> {
        for (acct, plain) in secrets {
            let rewrapped = self.crypto.wrap_token_payload(plain.as_slice())?;
            self.secret_store
                .set_secret(&self.config.secret_service, acct, &rewrapped)
                .await?;
        }
        Ok(())
    }

    async fn republish_manifest_after_rotation(
        &self,
        bundle: &SyncBackendBundle,
        vault_id: Uuid,
    ) -> ZeroVaultResult<()> {
        let (cur_rev, cur_etag) = bundle.metadata.manifest_cursor().await?;
        let floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_MANIFEST).await?;
        let all_inodes = bundle.metadata.list_all_inodes().await?;

        let has_user_nodes = all_inodes.iter().any(|r| r.inode != ROOT_INODE);
        if cur_rev == 0 && !has_user_nodes {
            return Ok(());
        }

        let mut nodes = Vec::new();
        for rec in all_inodes {
            if rec.inode == ROOT_INODE {
                continue;
            }
            let chunks = if rec.kind == EntryKind::File {
                bundle
                    .metadata
                    .list_chunks(rec.inode)
                    .await?
                    .into_iter()
                    .map(|c| ChunkRef {
                        chunk_index: c.chunk_index,
                        blob_id: c.blob_id,
                        plaintext_len: c.plaintext_len,
                        ciphertext_len: c.ciphertext_len,
                        blake3_plaintext: c.blake3_plaintext,
                        backend_ids: c.backend_ids,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            nodes.push(ManifestNode {
                inode: rec.inode,
                parent_inode: rec.parent_inode,
                file_id: rec.file_id,
                name: rec.name,
                kind: rec.kind,
                size: rec.size,
                mode: rec.mode,
                modified_at: rec.modified_at,
                created_at: rec.created_at,
                version: rec.version,
                wrapped_dek: rec.wrapped_dek,
                chunks,
            });
        }

        let next_rev = cur_rev.max(floor).saturating_add(1);
        let parent_manifest_id = if next_rev == 1 {
            None
        } else {
            bundle.metadata.parent_manifest_id().await?
        };
        let device_id = bundle
            .sync_engine
            .as_ref()
            .map(|e| e.config().device_id.clone())
            .unwrap_or_else(|| "local-device".to_owned());

        let manifest = VaultManifest {
            vault_id,
            revision: next_rev,
            parent_manifest_id,
            device_id,
            created_at: Utc::now(),
            nodes,
        };

        let snapshot_id = compute_manifest_id(&manifest)?;
        let sealed = self.crypto.seal_manifest(&manifest)?;
        let snapshot_key = ManifestObjectKey::from_uuid(snapshot_id);
        self.storage_router
            .put_manifest_cas(snapshot_key.as_str(), sealed.clone(), None)
            .await?;
        let head_ver = self
            .storage_router
            .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed, cur_etag.as_deref())
            .await?;

        bundle
            .metadata
            .advance_epoch_floor(EPOCH_SCOPE_MANIFEST, next_rev)
            .await?;
        bundle
            .metadata
            .set_parent_manifest_id(Some(snapshot_id))
            .await?;
        bundle
            .metadata
            .update_manifest_cursor(next_rev, head_ver.etag)
            .await?;

        Ok(())
    }

    async fn keybox_status(&self) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let engine = bundle.sync_engine.as_ref().ok_or_else(|| {
            ZeroVaultError::ConfigError("keybox.zv requires CoreSyncEngineFactory".into())
        })?;
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let mut kb_state = self.keybox_state.read().await.clone();
        let state_matches = kb_state.vault_id.is_none() || kb_state.vault_id == Some(vault_id);
        let pinned_owner = if state_matches {
            kb_state.owner_ed25519_pubkey
        } else {
            None
        };
        let sql_floor = bundle.metadata.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let min_floor = sql_floor
            .max(if state_matches { kb_state.epoch } else { 0 })
            .max(self.cached_keybox_epoch.load(Ordering::Acquire))
            .max(1);

        let kb = match self
            .fetch_verified_keybox_for_vault(engine, vault_id, pinned_owner.as_ref(), min_floor)
            .await
        {
            Ok(kb) => kb,
            Err(ZeroVaultError::StorageNotFound(msg)) => {
                if sql_floor > 0 {
                    return Err(ZeroVaultError::CryptoTamperDetected(format!(
                        "remote keybox.zv missing despite persisted keybox epoch floor {sql_floor}"
                    )));
                }
                return Err(ZeroVaultError::StorageNotFound(msg));
            }
            Err(err) => return Err(err),
        };

        // If no owner was pinned locally yet, require a local recipient identity that can
        // cryptographically open `kb` BEFORE trusting/pinning `owner_ed25519_pubkey` or advancing
        // SQLite `security_epochs("keybox")`!
        if pinned_owner.is_none() {
            let Some(local_id) = self.load_existing_recipient_identity().await? else {
                return Err(ZeroVaultError::CryptoTamperDetected(
                    "unexpected remote keybox.zv on single-user vault without pinned owner or recipient identity"
                        .into(),
                ));
            };
            let _ = self.crypto.open_keybox(&kb, None, min_floor, &local_id)?;
            kb_state.vault_id = Some(vault_id);
            kb_state.epoch = kb.epoch;
            kb_state.owner_ed25519_pubkey = Some(kb.owner_ed25519_pubkey);
            persist_keybox_state(&self.config.keybox_state_path, &kb_state)?;
            *self.keybox_state.write().await = kb_state;
        } else if kb.epoch > kb_state.epoch {
            kb_state.vault_id = Some(vault_id);
            kb_state.epoch = kb.epoch;
            persist_keybox_state(&self.config.keybox_state_path, &kb_state)?;
            *self.keybox_state.write().await = kb_state;
        }

        bundle
            .metadata
            .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, kb.epoch)
            .await?;
        self.cached_keybox_epoch.store(kb.epoch, Ordering::Release);

        Ok(DaemonResponse::KeyboxInfo(keybox_to_summary(&kb)))
    }

    async fn bench_crypto(&self, total_mib: usize) -> ZeroVaultResult<DaemonResponse> {
        let clamped = total_mib.clamp(4, 512);
        let crypto = Arc::clone(&self.crypto);
        let report = tokio::task::spawn_blocking(move || crypto.benchmark_aes256_gcm(clamped))
            .await
            .map_err(|e| {
                ZeroVaultError::Io(std::io::Error::other(format!(
                    "crypto benchmark worker failed: {e}"
                )))
            })??;
        reclaim_process_memory().await;
        Ok(DaemonResponse::CryptoBench(report))
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

    async fn sync_now(&self) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        self.ensure_remote_vault_header_best_effort().await;

        let sync_res = if let Some(ref runner) = bundle.sync_runner {
            runner.sync_now().await
        } else {
            self.sync_factory.sync_now(&bundle).await
        };

        let _ = self.storage_router.probe_all_health().await;
        reclaim_process_memory().await;
        sync_res?;

        tracing::info!("sync cycle completed and idle heap pages reclaimed");
        Ok(DaemonResponse::Ok {
            message: "sync completed".to_owned(),
        })
    }

    async fn current_mount_point(&self) -> Option<PathBuf> {
        let drive = self.active_drive.lock().await.clone();
        drive.and_then(|d| if d.is_mounted() { d.mount_point() } else { None })
    }

    async fn collect_backup_summaries(&self, unlocked: bool) -> (bool, Vec<BackupJobSummary>) {
        let state = self.backup_state.read().await.clone();
        let active_id = self.active_backup_job_id.read().clone();
        let summaries = state
            .jobs
            .iter()
            .map(|j| j.to_summary(unlocked, state.backups_paused, active_id.as_deref()))
            .collect();
        (state.backups_paused, summaries)
    }

    async fn list_backup_jobs(&self) -> ZeroVaultResult<DaemonResponse> {
        let unlocked = self.crypto.is_unlocked();
        let (_paused, summaries) = self.collect_backup_summaries(unlocked).await;
        Ok(DaemonResponse::BackupJobs(summaries))
    }

    async fn upsert_backup_job(&self, spec: BackupJobSpec) -> ZeroVaultResult<DaemonResponse> {
        let mount_point = self.current_mount_point().await;
        let _guard = self.lifecycle_lock.lock().await;

        let mut state = self.backup_state.read().await.clone();
        let existing_idx = spec
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|target_id| state.jobs.iter().position(|j| j.id == target_id));
        let existing_ref = existing_idx.and_then(|idx| state.jobs.get(idx));

        let built = build_stored_backup_job(
            spec,
            existing_ref,
            &self.config.state_dir,
            &self.config.staging_dir,
            mount_point.as_deref(),
        )?;

        for (idx, other) in state.jobs.iter().enumerate() {
            if Some(idx) == existing_idx {
                continue;
            }
            if other.id == built.id {
                return Err(ZeroVaultError::AlreadyExists(format!(
                    "backup job '{}' already exists",
                    built.id
                )));
            }
            let prefix_other = format!("{}/", other.vault_folder);
            let prefix_built = format!("{}/", built.vault_folder);
            if other.vault_folder == built.vault_folder
                || built.vault_folder.starts_with(&prefix_other)
                || other.vault_folder.starts_with(&prefix_built)
            {
                return Err(ZeroVaultError::ConfigError(format!(
                    "backup vault_folder '{}' overlaps existing backup job '{}'",
                    built.vault_folder, other.name
                )));
            }
        }

        let id = built.id.clone();
        let name = built.name.clone();
        if let Some(idx) = existing_idx {
            state.jobs[idx] = built;
        } else {
            state.jobs.push(built);
        }

        persist_backup_state(&self.config.backup_jobs_path, &state)?;
        *self.backup_state.write().await = state;

        tracing::info!(job_id = %id, "saved PC folder backup job");
        Ok(DaemonResponse::Ok {
            message: format!("backup job '{name}' ({id}) saved"),
        })
    }

    async fn remove_backup_job(&self, id: &str) -> ZeroVaultResult<DaemonResponse> {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "backup job id must not be empty".into(),
            ));
        }

        let _guard = self.lifecycle_lock.lock().await;
        let mut state = self.backup_state.read().await.clone();
        let Some(pos) = state.jobs.iter().position(|j| j.id == trimmed) else {
            return Err(ZeroVaultError::StorageNotFound(format!(
                "backup job '{trimmed}' not found"
            )));
        };
        let removed = state.jobs.remove(pos);

        persist_backup_state(&self.config.backup_jobs_path, &state)?;
        *self.backup_state.write().await = state;

        tracing::info!(job_id = %trimmed, "removed PC folder backup job");
        Ok(DaemonResponse::Ok {
            message: format!("backup job '{}' removed", removed.name),
        })
    }

    async fn set_backups_paused(&self, paused: bool) -> ZeroVaultResult<DaemonResponse> {
        if paused {
            self.backup_cancel_flag.store(true, Ordering::Release);
        }
        let _guard = self.lifecycle_lock.lock().await;
        {
            let mut state = self.backup_state.write().await;
            state.backups_paused = paused;
            persist_backup_state(&self.config.backup_jobs_path, &state)?;
        }

        let msg = if paused {
            "automatic backups paused"
        } else {
            "automatic backups resumed"
        };
        Ok(DaemonResponse::Ok {
            message: msg.to_owned(),
        })
    }

    async fn cancel_active_backup(&self) -> ZeroVaultResult<DaemonResponse> {
        self.backup_cancel_flag.store(true, Ordering::Release);
        let _guard = self.lifecycle_lock.lock().await;
        {
            let mut state = self.backup_state.write().await;
            state.backups_paused = true;
            persist_backup_state(&self.config.backup_jobs_path, &state)?;
        }

        Ok(DaemonResponse::Ok {
            message: "active backup cancelled and automatic backups paused".to_owned(),
        })
    }

    async fn run_backup_job(&self, id: &str, preview: bool) -> ZeroVaultResult<DaemonResponse> {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "backup job id must not be empty".into(),
            ));
        }

        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let exec_guard = if preview {
            None
        } else {
            match self.backup_exec_lock.try_lock() {
                Ok(g) => Some(g),
                Err(_) => {
                    let act = self
                        .active_activity
                        .read()
                        .clone()
                        .unwrap_or_else(|| "Backing up folders…".to_owned());
                    return Ok(DaemonResponse::Ok {
                        message: format!(
                            "Backup is already in progress ({act}). Watch live progress above or click Stop to cancel."
                        ),
                    });
                }
            }
        };
        let job = {
            let state = self.backup_state.read().await;
            state
                .jobs
                .iter()
                .find(|j| j.id == trimmed)
                .cloned()
                .ok_or_else(|| {
                    ZeroVaultError::StorageNotFound(format!("backup job '{trimmed}' not found"))
                })?
        };

        let report = Box::pin(self.execute_and_record_backup(&bundle, &job, preview)).await?;
        drop(exec_guard);
        reclaim_process_memory().await;
        Ok(DaemonResponse::BackupReport(report))
    }

    async fn run_all_backups(&self, preview: bool) -> ZeroVaultResult<DaemonResponse> {
        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let exec_guard = if preview {
            None
        } else {
            match self.backup_exec_lock.try_lock() {
                Ok(g) => Some(g),
                Err(_) => {
                    let act = self
                        .active_activity
                        .read()
                        .clone()
                        .unwrap_or_else(|| "Backing up folders…".to_owned());
                    return Ok(DaemonResponse::Ok {
                        message: format!(
                            "Backup is already in progress ({act}). Watch live progress above or click Stop to cancel."
                        ),
                    });
                }
            }
        };
        let enabled_jobs: Vec<StoredBackupJob> = {
            let state = self.backup_state.read().await;
            state.jobs.iter().filter(|j| j.enabled).cloned().collect()
        };

        let started = Instant::now();
        let mut total_scanned = 0u64;
        let mut total_uploaded = 0u64;
        let mut total_unchanged = 0u64;
        let mut total_bytes = 0u64;

        for job in &enabled_jobs {
            let rep = Box::pin(self.execute_and_record_backup(&bundle, job, preview)).await?;
            total_scanned = total_scanned.saturating_add(rep.files_scanned);
            total_uploaded = total_uploaded.saturating_add(rep.files_uploaded);
            total_unchanged = total_unchanged.saturating_add(rep.files_unchanged);
            total_bytes = total_bytes.saturating_add(rep.bytes_uploaded);
        }

        drop(exec_guard);
        reclaim_process_memory().await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let message = if preview {
            format_preview_message(total_uploaded, total_bytes, total_unchanged)
        } else {
            format_backup_message(total_uploaded, total_bytes, total_unchanged)
        };

        Ok(DaemonResponse::BackupReport(BackupRunReport {
            job_id: "*".to_owned(),
            preview,
            files_scanned: total_scanned,
            files_uploaded: total_uploaded,
            files_unchanged: total_unchanged,
            bytes_uploaded: total_bytes,
            elapsed_ms,
            message,
        }))
    }

    async fn run_due_scheduled_backups(&self) {
        if !self.crypto.is_unlocked() {
            return;
        }
        let Ok(_exec_guard) = self.backup_exec_lock.try_lock() else {
            return;
        };
        let Some(bundle) = self.sync_bundle.read().await.clone() else {
            return;
        };

        let now = Utc::now();
        let due_jobs: Vec<StoredBackupJob> = {
            let state = self.backup_state.read().await;
            if state.backups_paused {
                return;
            }
            state
                .jobs
                .iter()
                .filter(|j| SchedulePolicy::is_due(j, state.backups_paused, true, now))
                .cloned()
                .collect()
        };

        for job in due_jobs {
            if self.backup_state.read().await.backups_paused || !self.crypto.is_unlocked() {
                break;
            }
            if let Err(err) = Box::pin(self.execute_and_record_backup(&bundle, &job, false)).await {
                tracing::warn!(
                    job_id = %job.id,
                    code = error_code(&err),
                    "scheduled background backup encountered error"
                );
            }
        }
    }

    async fn execute_and_record_backup(
        &self,
        bundle: &SyncBackendBundle,
        job: &StoredBackupJob,
        preview: bool,
    ) -> ZeroVaultResult<BackupRunReport> {
        let preview_cancel_flag = AtomicBool::new(false);
        let preview_activity = SyncRwLock::new(None);
        if !preview {
            self.backup_cancel_flag.store(false, Ordering::Release);
        }
        let mount_point = self.current_mount_point().await;
        let has_remotes = !self.remotes_config.read().await.remotes.is_empty();

        if !preview {
            let attempt_now = Utc::now();
            {
                let mut state = self.backup_state.write().await;
                if let Some(slot) = state.jobs.iter_mut().find(|j| j.id == job.id) {
                    slot.last_attempt_at = Some(attempt_now);
                }
                let _ = persist_backup_state(&self.config.backup_jobs_path, &state);
            }
            *self.active_backup_job_id.write() = Some(job.id.clone());
            if has_remotes {
                self.ensure_remote_vault_header_best_effort().await;
            }
        }

        let cancel_flag_ref = if preview {
            &preview_cancel_flag
        } else {
            &self.backup_cancel_flag
        };
        let activity_ref = if preview {
            &preview_activity
        } else {
            &self.active_activity
        };

        let exec_res = Box::pin(execute_single_backup_job(
            bundle,
            job,
            preview,
            has_remotes,
            &self.config.state_dir,
            &self.config.staging_dir,
            mount_point.as_deref(),
            cancel_flag_ref,
            activity_ref,
        ))
        .await;

        if !preview {
            *self.active_backup_job_id.write() = None;
            *self.active_activity.write() = None;
        }

        match exec_res {
            Ok(report) => {
                if !preview {
                    let mut state = self.backup_state.write().await;
                    if let Some(slot) = state.jobs.iter_mut().find(|j| j.id == job.id) {
                        slot.last_success_at = Some(Utc::now());
                        slot.last_error = None;
                        slot.last_files_synced = report.files_uploaded;
                        slot.last_bytes_synced = report.bytes_uploaded;
                    }
                    persist_backup_state(&self.config.backup_jobs_path, &state)?;
                    self.notify_active_drive(&job.vault_folder).await;
                }
                Ok(report)
            }
            Err(err) => {
                if !preview
                    && !is_backup_cancelled_error(&err)
                    && !matches!(err, ZeroVaultError::VaultLocked)
                {
                    let mut state = self.backup_state.write().await;
                    if let Some(slot) = state.jobs.iter_mut().find(|j| j.id == job.id) {
                        slot.last_error = Some(err.to_string());
                    }
                    let _ = persist_backup_state(&self.config.backup_jobs_path, &state);
                }
                Err(err)
            }
        }
    }

    async fn restore_backup_job(
        &self,
        id: &str,
        destination_parent: &str,
    ) -> ZeroVaultResult<DaemonResponse> {
        let trimmed_id = id.trim();
        if trimmed_id.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "backup job id or vault folder path must not be empty".into(),
            ));
        }

        let bundle = self
            .sync_bundle
            .read()
            .await
            .clone()
            .ok_or(ZeroVaultError::VaultLocked)?;

        let _exec_guard = self.backup_exec_lock.lock().await;
        let mount_point = self.current_mount_point().await;
        let state_snapshot = self.backup_state.read().await.clone();

        let dest_parent = validate_restore_destination_parent(
            destination_parent,
            &self.config.state_dir,
            &self.config.staging_dir,
            mount_point.as_deref(),
            &state_snapshot.jobs,
        )?;

        let (vault_folder, display_label) =
            if let Some(found) = state_snapshot.jobs.iter().find(|j| j.id == trimmed_id) {
                (found.vault_folder.clone(), found.name.clone())
            } else if trimmed_id.starts_with('/') || trimmed_id.starts_with('\\') {
                let norm = normalize_vault_virtual_path(trimmed_id)?;
                if norm == "/" {
                    return Err(ZeroVaultError::InvalidPath(
                        "restore vault folder cannot be root '/'".into(),
                    ));
                }
                (norm.clone(), norm)
            } else {
                return Err(ZeroVaultError::StorageNotFound(format!(
                    "backup job '{trimmed_id}' not found"
                )));
            };

        // Ensure remote manifest is pulled if the vault folder is not yet visible locally.
        if bundle.vfs.resolve_path(&vault_folder).await.is_err()
            && !self.remotes_config.read().await.remotes.is_empty()
            && let Some(ref engine) = bundle.sync_engine
        {
            let _ = engine.sync_once().await;
        }

        let root_rec = bundle.vfs.resolve_path(&vault_folder).await.map_err(|_| {
            ZeroVaultError::StorageNotFound(format!(
                "backup folder '{vault_folder}' not found in vault"
            ))
        })?;
        if root_rec.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(root_rec.inode));
        }

        tokio::fs::create_dir_all(&dest_parent).await?;
        let post_parent_meta = tokio::fs::symlink_metadata(&dest_parent).await?;
        if is_symlink_or_reparse(&post_parent_meta) || !post_parent_meta.is_dir() {
            return Err(ZeroVaultError::InvalidPath(
                "restore destination parent failed directory verification".into(),
            ));
        }

        let folder_name = make_restore_folder_name(Utc::now());
        let restore_root = dest_parent.join(&folder_name);
        if std::fs::symlink_metadata(&restore_root).is_ok() {
            return Err(ZeroVaultError::AlreadyExists(format!(
                "refusing to overwrite existing restore folder {}",
                restore_root.display()
            )));
        }
        std::fs::DirBuilder::new().create(&restore_root)?;

        self.backup_cancel_flag.store(false, Ordering::Release);
        *self.active_activity.write() = Some(format!("Restoring {display_label}\u{2026}"));

        let mut files_restored = 0u64;
        let mut bytes_restored = 0u64;

        let restore_res: ZeroVaultResult<()> = async {
            let mut stack: Vec<(InodeId, PathBuf)> = vec![(root_rec.inode, PathBuf::new())];
            while let Some((dir_inode, rel_dir)) = stack.pop() {
                if self.backup_cancel_flag.load(Ordering::Acquire) {
                    return Err(ZeroVaultError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "restore cancelled by user",
                    )));
                }

                let mut children = bundle.vfs.readdir(dir_inode).await?;
                children.sort_by(|a, b| a.name.cmp(&b.name));

                let mut subdirs = Vec::new();
                for child in children {
                    validate_portable_entry_name(&child.name, cfg!(target_os = "windows"))?;
                    let child_rel = rel_dir.join(&child.name);
                    let target_local = restore_root.join(&child_rel);

                    match child.kind {
                        EntryKind::Directory => {
                            if let Ok(existing_meta) = std::fs::symlink_metadata(&target_local)
                                && is_symlink_or_reparse(&existing_meta)
                            {
                                return Err(ZeroVaultError::InvalidPath(
                                    "refusing restore into symlinked subdirectory".into(),
                                ));
                            }
                            tokio::fs::create_dir_all(&target_local).await?;
                            subdirs.push((child.inode, child_rel));
                        }
                        EntryKind::File => {
                            let next_idx = files_restored + 1;
                            *self.active_activity.write() = Some(format!(
                                "Restoring {display_label} ({next_idx} files)\u{2026}"
                            ));
                            let exported_bytes = if let Some(ref engine) = bundle.sync_engine {
                                let out_path = engine
                                    .export_file_atomic(&child.virtual_path, &target_local)
                                    .await?;
                                tokio::fs::symlink_metadata(&out_path).await?.len()
                            } else {
                                export_vfs_file_atomic_fallback(
                                    bundle.vfs.as_ref(),
                                    &child.virtual_path,
                                    &target_local,
                                )
                                .await?
                            };
                            files_restored = files_restored.saturating_add(1);
                            bytes_restored = bytes_restored.saturating_add(exported_bytes);
                        }
                    }
                }

                for sub in subdirs.into_iter().rev() {
                    stack.push(sub);
                }
            }
            Ok(())
        }
        .await;

        *self.active_activity.write() = None;
        reclaim_process_memory().await;
        restore_res?;

        let restored_folder = clean_local_path_display(&restore_root);
        tracing::info!(
            files_restored,
            bytes_restored,
            "completed verified backup restore"
        );
        Ok(DaemonResponse::RestoreCompleted {
            restored_folder,
            files_restored,
            bytes_restored,
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
        let (manifest_revision, pending_dirty_ops, conflict_count, vfs_stats, meta_kb_epoch) =
            match bundle.as_ref() {
                Some(b) => {
                    let rev = b
                        .metadata
                        .manifest_cursor()
                        .await
                        .map(|(r, _)| r)
                        .unwrap_or(0);
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
                    let kb_ep = b
                        .metadata
                        .epoch_floor(EPOCH_SCOPE_KEYBOX)
                        .await
                        .unwrap_or(0);
                    (rev, dirty, conflicts, st, kb_ep)
                }
                None => (0, 0, 0, None, 0),
            };

        let keybox_epoch = self
            .cached_keybox_epoch
            .load(Ordering::Acquire)
            .max(meta_kb_epoch);
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

        let (backups_paused, backup_jobs) = self.collect_backup_summaries(unlocked).await;
        let active_activity = self.active_activity.read().clone();

        Ok(DaemonResponse::Status(Box::new(VaultStatusReport {
            vault_id,
            unlocked,
            mounted,
            mount_point,
            manifest_revision,
            keybox_epoch,
            routing_policy,
            remotes,
            pooled_quota,
            throughput,
            drive_stats,
            conflict_count,
            backups_paused,
            backup_jobs,
            active_activity,
        })))
    }
}

/// Auto-detects locally installed cloud sync folders (OneDrive, Google Drive, Dropbox, iCloud Drive)
/// plus a guaranteed 1-click local backup folder.
#[must_use]
pub fn detect_local_cloud_folders() -> Vec<DetectedCloudFolder> {
    let mut results = Vec::new();
    let mut seen_roots: HashSet<String> = HashSet::new();
    let mut id_counts: HashMap<String, usize> = HashMap::new();

    let mut push_candidate = |provider: &str, base_id: &str, candidate: PathBuf| {
        if !candidate.exists() || !candidate.is_dir() {
            return;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&candidate)
            && is_symlink_or_reparse(&meta)
        {
            return;
        }
        let clean_root = clean_display_path(&candidate);
        let dedup_key = if cfg!(target_os = "windows") {
            clean_root.to_ascii_lowercase()
        } else {
            clean_root
        }
        ;
        if !seen_roots.insert(dedup_key) {
            return;
        }

        let count_entry = id_counts.entry(base_id.to_owned()).or_insert(0);
        *count_entry += 1;
        let suggested_id = if *count_entry == 1 {
            base_id.to_owned()
        } else {
            format!("{base_id}-{}", *count_entry)
        };

        let vault_subdir = clean_display_path(&candidate.join("EntroCloud"));
        results.push(DetectedCloudFolder {
            provider: provider.to_owned(),
            suggested_id,
            path: vault_subdir,
        });
    };

    // 1. Microsoft OneDrive
    for var in ["OneDriveConsumer", "OneDrive", "OneDriveCommercial"] {
        if let Some(val) = std::env::var_os(var) {
            push_candidate("OneDrive", "onedrive", PathBuf::from(val));
        }
    }
    if let Some(home) = dirs::home_dir() {
        push_candidate("OneDrive", "onedrive", home.join("OneDrive"));
    }

    // 2. Google Drive Desktop
    if let Some(home) = dirs::home_dir() {
        for sub in ["Google Drive", "My Drive"] {
            push_candidate("Google Drive", "gdrive", home.join(sub));
        }
    }
    #[cfg(target_os = "windows")]
    {
        for letter in b'D'..=b'Z' {
            let drive_path = format!("{}:\\My Drive", char::from(letter));
            push_candidate("Google Drive", "gdrive", PathBuf::from(drive_path));
        }
    }

    // 3. Dropbox (`info.json` + `~/Dropbox`)
    for base in [dirs::data_local_dir(), dirs::config_dir()]
        .into_iter()
        .flatten()
    {
        let info_path = base.join("Dropbox").join("info.json");
        if let Ok(raw) = std::fs::read_to_string(&info_path)
            && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw)
        {
            for tier in ["personal", "business"] {
                if let Some(p) = parsed
                    .get(tier)
                    .and_then(|obj| obj.get("path"))
                    .and_then(|v| v.as_str())
                {
                    push_candidate("Dropbox", "dropbox", PathBuf::from(p));
                }
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        push_candidate("Dropbox", "dropbox", home.join("Dropbox"));
    }

    // 4. Apple iCloud Drive
    if let Some(home) = dirs::home_dir() {
        push_candidate("iCloud Drive", "icloud", home.join("iCloudDrive"));
        push_candidate(
            "iCloud Drive",
            "icloud",
            home.join("Library")
                .join("Mobile Documents")
                .join("com~apple~CloudDocs"),
        );
    }

    // 5. Guaranteed Local Backup fallback
    let base_local = dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    let local_vault = clean_display_path(&base_local.join("EntroCloudBackup"));
    results.push(DetectedCloudFolder {
        provider: "Local Backup".to_owned(),
        suggested_id: "local-backup".to_owned(),
        path: local_vault,
    });

    results
}

fn clean_display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    #[cfg(target_os = "windows")]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            if let Some(unc_tail) = stripped.strip_prefix(r"UNC\") {
                return format!(r"\\{unc_tail}");
            }
            return stripped.to_owned();
        }
    }
    raw
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn keybox_to_summary(kb: &SignedKeybox) -> KeyboxSummary {
    KeyboxSummary {
        vault_id: kb.vault_id,
        epoch: kb.epoch,
        owner_pubkey_hex: encode_hex_lower(&kb.owner_ed25519_pubkey),
        recipient_ids: kb.stanzas.iter().map(|s| s.recipient_id.clone()).collect(),
    }
}

async fn publish_vault_header_to_router_best_effort(
    router: &StorageRouter,
    header: &VaultHeader,
    specific_backend_id: Option<&str>,
) {
    if header.kdf.validate_production().is_err() {
        return;
    }
    let payload = Bytes::copy_from_slice(&header.encode());

    if let Some(target_id) = specific_backend_id
        && let Some(backend) = router.backend(target_id)
        && let Err(err) = backend
            .put_object_cas(VAULT_HEADER_OBJECT_KEY, payload.clone(), None)
            .await
    {
        tracing::warn!(
            remote_id = %target_id,
            code = error_code(&err),
            "deferred vault/header.zvh publish on newly added remote"
        );
    }

    if let Err(err) = router
        .put_manifest_cas(VAULT_HEADER_OBJECT_KEY, payload, None)
        .await
    {
        tracing::warn!(
            code = error_code(&err),
            "deferred vault/header.zvh router publish until remote is reachable"
        );
    }
}

async fn fetch_remote_keybox(
    router: &StorageRouter,
    crypto: &dyn CryptoEngine,
    expected_vault_id: Option<Uuid>,
    expected_owner_pubkey: Option<&[u8; 32]>,
    min_epoch_floor: u64,
) -> ZeroVaultResult<Option<SignedKeybox>> {
    let mut tamper_err: Option<ZeroVaultError> = None;
    let mut transport_err: Option<ZeroVaultError> = None;
    let mut saw_not_found = false;

    let decode_and_verify = |raw: &[u8]| -> ZeroVaultResult<SignedKeybox> {
        let kb = SignedKeybox::decode(raw)?;
        crypto.verify_keybox_envelope(
            &kb,
            expected_vault_id,
            expected_owner_pubkey,
            min_epoch_floor,
        )?;
        Ok(kb)
    };

    match router.get_blob(KEYBOX_OBJECT_KEY, &[]).await {
        Ok(bytes) => match decode_and_verify(&bytes) {
            Ok(kb) => return Ok(Some(kb)),
            Err(err) => tamper_err = Some(err),
        },
        Err(ZeroVaultError::StorageNotFound(_)) => saw_not_found = true,
        Err(err) => transport_err = Some(err),
    }

    for backend_id in router.candidate_backends(&[]) {
        match router
            .get_blob_from_backend(&backend_id, KEYBOX_OBJECT_KEY)
            .await
        {
            Ok(alt_bytes) => match decode_and_verify(&alt_bytes) {
                Ok(kb) => return Ok(Some(kb)),
                Err(err) => tamper_err = Some(err),
            },
            Err(ZeroVaultError::StorageNotFound(_)) => saw_not_found = true,
            Err(err) => {
                if transport_err.is_none() {
                    transport_err = Some(err);
                }
            }
        }
    }

    if let Some(err) = tamper_err {
        return Err(err);
    }
    if saw_not_found && transport_err.is_none() {
        return Ok(None);
    }
    if let Some(err) = transport_err {
        return Err(err);
    }
    Ok(None)
}

fn is_fatal_unlock_error(err: &ZeroVaultError) -> bool {
    matches!(
        err,
        ZeroVaultError::CryptoTamperDetected(_)
            | ZeroVaultError::UnauthorizedRecipient(_)
            | ZeroVaultError::InvalidPassphrase
            | ZeroVaultError::KdfPolicyViolation { .. }
            | ZeroVaultError::HardwareAccelerationUnavailable(_)
    )
}

async fn ensure_virtual_dir_chain(
    vfs: &dyn VfsBackend,
    dir_vpath: &str,
) -> ZeroVaultResult<InodeId> {
    let norm = normalize_vault_virtual_path(dir_vpath)?;
    if norm == "/" {
        return Ok(ROOT_INODE);
    }

    let mut cur_inode = ROOT_INODE;
    for seg in norm.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        match vfs.lookup(cur_inode, seg).await {
            Ok(child) => {
                if child.kind != EntryKind::Directory {
                    return Err(ZeroVaultError::NotADirectory(child.inode));
                }
                cur_inode = child.inode;
            }
            Err(ZeroVaultError::InodeNotFound(_)) => {
                let created = vfs.mkdir(cur_inode, seg, 0o755).await?;
                cur_inode = created.inode;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(cur_inode)
}

async fn export_vfs_file_atomic_fallback(
    vfs: &dyn VfsBackend,
    norm_virtual_path: &str,
    raw_dest: &Path,
) -> ZeroVaultResult<u64> {
    let rec = vfs.resolve_path(norm_virtual_path).await?;
    if rec.kind != EntryKind::File {
        return Err(ZeroVaultError::IsADirectory(rec.inode));
    }

    if let Ok(meta) = std::fs::symlink_metadata(raw_dest)
        && is_symlink_or_reparse(&meta)
    {
        return Err(ZeroVaultError::InvalidPath(
            "refusing local export through symlink or NTFS reparse point".into(),
        ));
    }

    let dest_path = match std::fs::symlink_metadata(raw_dest) {
        Ok(meta) if meta.is_dir() => {
            validate_portable_entry_name(&rec.name, cfg!(target_os = "windows"))?;
            let joined = raw_dest.join(&rec.name);
            if let Ok(jm) = std::fs::symlink_metadata(&joined)
                && is_symlink_or_reparse(&jm)
            {
                return Err(ZeroVaultError::InvalidPath(
                    "refusing local export over symlink target".into(),
                ));
            }
            joined
        }
        _ => raw_dest.to_path_buf(),
    };

    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        if let Ok(pm) = std::fs::symlink_metadata(parent)
            && is_symlink_or_reparse(&pm)
        {
            return Err(ZeroVaultError::InvalidPath(
                "refusing local export into symlink parent directory".into(),
            ));
        }
        tokio::fs::create_dir_all(parent).await?;
    }

    let file_name = dest_path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .ok_or_else(|| ZeroVaultError::InvalidPath("invalid export destination basename".into()))?;
    let partial_name = format!("{file_name}.{}.partial", Uuid::new_v4().hyphenated());
    let partial_path = match dest_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(&partial_name),
        _ => PathBuf::from(&partial_name),
    };

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut partial = opts.open(&partial_path).await?;

    let mut offset = 0u64;
    let stream_res: ZeroVaultResult<()> = async {
        while offset < rec.size {
            let read_len = ((rec.size - offset) as usize).min(PLAINTEXT_CHUNK_SIZE);
            let bytes = vfs.read_range(rec.inode, offset, read_len).await?;
            if bytes.is_empty() {
                return Err(ZeroVaultError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while exporting virtual file",
                )));
            }
            partial.write_all(&bytes).await?;
            offset = offset.saturating_add(bytes.len() as u64);
        }
        partial.flush().await?;
        partial.sync_all().await?;
        Ok(())
    }
    .await;
    drop(partial);

    if let Err(err) = stream_res {
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(err);
    }

    if let Ok(dm) = std::fs::symlink_metadata(&dest_path)
        && is_symlink_or_reparse(&dm)
    {
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(ZeroVaultError::InvalidPath(
            "export destination became a symlink before promotion".into(),
        ));
    }

    if let Err(err) = tokio::fs::rename(&partial_path, &dest_path).await {
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(err.into());
    }

    Ok(offset)
}

fn preunlock_secret_account(id: &str) -> String {
    format!("remote:{id}:preunlock")
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct OAuthTokenInputDto {
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    #[zeroize(skip)]
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
                if let Ok(mut parsed) = serde_json::from_str::<OAuthTokenInputDto>(secret.as_str())
                {
                    let access_token = std::mem::take(&mut parsed.access_token);
                    let refresh_token = parsed.refresh_token.take();
                    let client_secret = parsed.client_secret.take();
                    OAuthTokenBundle {
                        provider: preset,
                        access_token: RedactedSecret::from(access_token),
                        refresh_token: refresh_token.map(RedactedSecret::from),
                        token_type: parsed.token_type.take().unwrap_or_else(|| "Bearer".to_owned()),
                        expires_at: parsed.expires_at,
                        scopes: parsed.scopes.take().unwrap_or_else(|| preset.default_scopes()),
                        client_id: parsed.client_id.take().or_else(|| username.map(str::to_owned)),
                        client_secret: client_secret.map(RedactedSecret::from),
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

const IDENTITY_ZVI_MAGIC: &[u8; 4] = b"ZVI1";
const IDENTITY_ZVI_AAD: &[u8] = b"entrocloud:recipient-identity:v1";
const IDENTITY_ZVI_NONCE_LEN: usize = 12;
const IDENTITY_WRAP_KEY_LEN: usize = 32;

fn seal_recipient_identity_zvi(
    key: &[u8; IDENTITY_WRAP_KEY_LEN],
    identity: &RecipientPrivateIdentity,
) -> ZeroVaultResult<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::{SecureRandom as _, SystemRandom};

    let mut plaintext = Zeroizing::new(postcard::to_allocvec(identity).map_err(|e| {
        ZeroVaultError::InvalidWireFormat(format!("failed serializing recipient identity: {e}"))
    })?);
    let mut nonce_bytes = [0u8; IDENTITY_ZVI_NONCE_LEN];
    SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| {
        ZeroVaultError::KeyringError("CSPRNG failure generating identity nonce".into())
    })?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ZeroVaultError::KeyringError("invalid identity wrap key".into()))?;
    let aead_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    aead_key
        .seal_in_place_append_tag(nonce, Aad::from(IDENTITY_ZVI_AAD), &mut *plaintext)
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("failed sealing recipient identity".into())
        })?;

    let mut out =
        Vec::with_capacity(IDENTITY_ZVI_MAGIC.len() + IDENTITY_ZVI_NONCE_LEN + plaintext.len());
    out.extend_from_slice(IDENTITY_ZVI_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(plaintext.as_slice());
    Ok(out)
}

fn open_recipient_identity_zvi(
    key: &[u8; IDENTITY_WRAP_KEY_LEN],
    blob: &[u8],
) -> ZeroVaultResult<RecipientPrivateIdentity> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    let header_len = IDENTITY_ZVI_MAGIC.len() + IDENTITY_ZVI_NONCE_LEN;
    if blob.len() < header_len + AES_256_GCM.tag_len() || !blob.starts_with(IDENTITY_ZVI_MAGIC) {
        return Err(ZeroVaultError::InvalidWireFormat(
            "invalid ZVI1 recipient identity envelope".into(),
        ));
    }
    let mut nonce_bytes = [0u8; IDENTITY_ZVI_NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[IDENTITY_ZVI_MAGIC.len()..header_len]);
    let mut buf = Zeroizing::new(blob[header_len..].to_vec());

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ZeroVaultError::KeyringError("invalid identity wrap key".into()))?;
    let aead_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext = aead_key
        .open_in_place(nonce, Aad::from(IDENTITY_ZVI_AAD), buf.as_mut_slice())
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected(
                "recipient_identity.zvi AEAD authentication failed".into(),
            )
        })?;
    postcard::from_bytes(plaintext).map_err(|e| {
        ZeroVaultError::InvalidWireFormat(format!("corrupt ZVI1 recipient identity payload: {e}"))
    })
}

fn write_atomic_private(path: &Path, data: &[u8]) -> ZeroVaultResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_owner_only_dir(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state");
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4().as_simple()));
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        if let Err(err) = file.write_all(data).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, data)?;
    }
    if let Err(err) = ensure_owner_only_file(&tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }
    Ok(())
}

fn persist_vault_header(path: &Path, header: &VaultHeader) -> ZeroVaultResult<()> {
    let mut encoded = header.encode();
    let res = write_atomic_private(path, &encoded);
    encoded.zeroize();
    res
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

fn persist_keybox_state(path: &Path, state: &PersistedKeyboxState) -> ZeroVaultResult<()> {
    let json = serde_json::to_vec_pretty(state).map_err(|e| {
        ZeroVaultError::ConfigError(format!("failed serializing keybox state: {e}"))
    })?;
    write_atomic_private(path, &json)
}

fn load_keybox_state(path: &Path) -> ZeroVaultResult<PersistedKeyboxState> {
    if !path.exists() {
        return Ok(PersistedKeyboxState::default());
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        ZeroVaultError::ConfigError(format!(
            "failed parsing keybox state at {}: {e}",
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
        ZeroVaultError::UnauthorizedRecipient(_) => "unauthorized_recipient",
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

#[cfg(test)]
mod b2_identity_tests {
    use super::*;
    use entrocloud_types::mocks::MockCryptoEngine;

    #[test]
    fn zvi1_recipient_identity_roundtrip_and_tamper_rejection() -> ZeroVaultResult<()> {
        let crypto = MockCryptoEngine::default();
        let identity = crypto.generate_recipient_identity("alice")?;
        let key = [0x42u8; IDENTITY_WRAP_KEY_LEN];

        let sealed = seal_recipient_identity_zvi(&key, &identity)?;
        assert!(sealed.starts_with(IDENTITY_ZVI_MAGIC));
        const {
            assert!(IDENTITY_WRAP_KEY_LEN <= 2560);
        }

        let opened = open_recipient_identity_zvi(&key, &sealed)?;
        assert_eq!(opened.public, identity.public);
        assert_eq!(*opened.ed25519_seed, *identity.ed25519_seed);
        assert_eq!(*opened.x25519_private, *identity.x25519_private);
        assert_eq!(*opened.mlkem768_decaps_key, *identity.mlkem768_decaps_key);

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            open_recipient_identity_zvi(&key, &tampered),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        Ok(())
    }
}
