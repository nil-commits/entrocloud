//! Multi-cloud OpenDAL `0.59` storage backend connectors, resilience layering, health tracking,
//! bounded streaming reads, byte-range reads, and lock-free atomic quota accounting.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::{BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::TryStreamExt;
use opendal::{ErrorKind, Metadata, Operator, layers, services};
use parking_lot::RwLock;
use uuid::Uuid;

use entrocloud_types::{
    BackendConfig, BackendHealth, BackendKind, BackendQuota, BlobObjectKey, CryptoEngine,
    KEYBOX_OBJECT_KEY, MAX_ENCRYPTED_CHUNK_SIZE, ManifestObjectKey, RedactedSecret, RemoteVersion,
    ReplicaTarget, SecretStore, ShareObjectKey, VAULT_HEADER_LEN, VAULT_HEADER_OBJECT_KEY,
    ZeroVaultError, ZeroVaultResult, validate_remote_object_key,
};

use crate::oauth::{DEFAULT_TOKEN_SECRET_SERVICE, OAuthTokenBundle, load_tokens};

/// Default fallback capacity reported when `BackendConfig::quota_limit_bytes` is `None` (1 TiB).
pub const DEFAULT_UNBOUNDED_QUOTA_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Maximum allowed wire size for `vault/keybox.zv` (`4 MiB`).
pub const MAX_KEYBOX_BYTES: usize = 4 * 1024 * 1024;
/// Maximum allowed wire size for `shares/<2-hex>/<2-hex>/<uuid>.zvs` (`4 MiB`).
pub const MAX_SHARE_OBJECT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum allowed wire size for any sealed manifest snapshot (`64 MiB`).
pub const MAX_SEALED_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

const NO_LATENCY_SENTINEL: u64 = u64::MAX;

/// Validates `object_key` against zero-knowledge naming policy and returns the strict maximum
/// wire byte ceiling permitted for that object class:
/// - `vault/header.zvh` (`VAULT_HEADER_OBJECT_KEY`): `112 B`
/// - `vault/keybox.zv` (`KEYBOX_OBJECT_KEY`): `4 MiB`
/// - `shares/<2-hex>/<2-hex>/<uuid>.zvs` (`ShareObjectKey`): `4 MiB`
/// - `blobs/<2-hex>/<2-hex>/<uuid>.zv` (`BlobObjectKey`): `MAX_ENCRYPTED_CHUNK_SIZE` (`4 MiB + 48 B`)
/// - `manifests/head.zvm` or `manifests/<2-hex>/<2-hex>/<uuid>.zvm`: `64 MiB`
pub fn max_wire_bytes_for_object_key(object_key: &str) -> ZeroVaultResult<usize> {
    validate_remote_object_key(object_key)?;
    if object_key == VAULT_HEADER_OBJECT_KEY {
        Ok(VAULT_HEADER_LEN)
    } else if object_key == KEYBOX_OBJECT_KEY {
        Ok(MAX_KEYBOX_BYTES)
    } else if ShareObjectKey::parse(object_key).is_ok() {
        Ok(MAX_SHARE_OBJECT_BYTES)
    } else if BlobObjectKey::parse(object_key).is_ok() {
        Ok(MAX_ENCRYPTED_CHUNK_SIZE)
    } else if ManifestObjectKey::parse(object_key).is_ok() {
        Ok(MAX_SEALED_MANIFEST_BYTES)
    } else {
        Err(ZeroVaultError::InvalidPath(format!(
            "unrecognized remote object key class: {object_key}"
        )))
    }
}

/// Resilience layer configuration applied to OpenDAL [`Operator`] instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendLayerConfig {
    /// Timeout for control operations (`stat`, `delete`, `list`).
    pub timeout: Duration,
    /// Timeout for data-plane I/O operations (`read`, `write`).
    pub io_timeout: Duration,
    /// Maximum automatic retry attempts for transient errors.
    pub max_retries: usize,
    /// Initial exponential backoff delay for retries.
    pub retry_min_delay: Duration,
    /// Maximum exponential backoff delay for retries.
    pub retry_max_delay: Duration,
    /// Maximum concurrent operations permitted per backend operator.
    pub concurrent_limit: usize,
}

impl Default for BackendLayerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_min_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(2),
            concurrent_limit: 16,
        }
    }
}

#[derive(Debug, Clone)]
struct SyntheticEtagEntry {
    etag: String,
    content_length: u64,
    last_modified: Option<(i64, u32)>,
}

/// Alias for [`CloudBackend`].
pub type OpenDalBackend = CloudBackend;

/// Single cloud storage backend wrapping an OpenDAL [`Operator`] with atomic quota accounting,
/// runtime health telemetry, bounded streaming reads, byte-range reads, and ETag tracking.
pub struct CloudBackend {
    config: BackendConfig,
    operator: Operator,
    used_bytes: AtomicU64,
    healthy: AtomicBool,
    latency_ms: AtomicU64,
    last_error: RwLock<Option<String>>,
    known_sizes: DashMap<String, u64>,
    synthetic_etags: DashMap<String, SyntheticEtagEntry>,
}

impl fmt::Debug for CloudBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudBackend")
            .field("id", &self.config.id)
            .field("kind", &self.config.kind)
            .field("root", &self.config.root)
            .field("healthy", &self.healthy.load(Ordering::Acquire))
            .field("used_bytes", &self.used_bytes.load(Ordering::Acquire))
            .field("quota_limit_bytes", &self.config.quota_limit_bytes)
            .field("min_free_reserve_bytes", &self.config.min_free_reserve_bytes)
            .finish_non_exhaustive()
    }
}

impl CloudBackend {
    /// Builds a [`CloudBackend`] synchronously for configs that do not require async [`SecretStore`]
    /// lookup (e.g. `LocalFs`, `Memory`, `S3`, `WebDav`, or direct-token configs).
    pub fn from_config(config: &BackendConfig) -> ZeroVaultResult<Self> {
        Self::build_internal(config, None, None, BackendLayerConfig::default())
    }

    /// Builds a [`CloudBackend`] and resolves wrapped OAuth2 tokens (or stored secrets) from
    /// [`SecretStore`] using [`CryptoEngine`] without ever logging secret material.
    pub async fn from_config_with_secrets(
        config: &BackendConfig,
        secret_store: Option<&dyn SecretStore>,
        crypto: Option<&dyn CryptoEngine>,
    ) -> ZeroVaultResult<Self> {
        Self::from_config_with_options(
            config,
            secret_store,
            crypto,
            DEFAULT_TOKEN_SECRET_SERVICE,
            BackendLayerConfig::default(),
        )
        .await
    }

    /// Builds a [`CloudBackend`] with explicit secret-store service namespace and layer config.
    pub async fn from_config_with_options(
        config: &BackendConfig,
        secret_store: Option<&dyn SecretStore>,
        crypto: Option<&dyn CryptoEngine>,
        secret_service: &str,
        layer_config: BackendLayerConfig,
    ) -> ZeroVaultResult<Self> {
        let mut oauth_bundle: Option<OAuthTokenBundle> = None;
        let mut resolved_secret: Option<RedactedSecret> = None;

        match config.kind {
            BackendKind::GoogleDrive | BackendKind::OneDrive | BackendKind::Dropbox => {
                if let Some(account_key) = config.secret_account_key.as_deref() {
                    if let (Some(store), Some(engine)) = (secret_store, crypto) {
                        oauth_bundle =
                            load_tokens(store, engine, secret_service, account_key).await?;
                        if oauth_bundle.is_none() && config.secret_access_key.is_none() {
                            return Err(ZeroVaultError::ConfigError(format!(
                                "no OAuth2 token bundle found in secret store for backend '{}'",
                                config.id
                            )));
                        }
                    } else if config.secret_access_key.is_none() {
                        return Err(ZeroVaultError::ConfigError(format!(
                            "backend '{}' requires SecretStore and CryptoEngine to unwrap OAuth2 tokens",
                            config.id
                        )));
                    }
                }
            }
            BackendKind::S3 | BackendKind::WebDav => {
                if config.secret_access_key.is_none()
                    && let Some(account_key) = config.secret_account_key.as_deref()
                    && let Some(store) = secret_store
                    && let Some(raw) = store.get_secret(secret_service, account_key).await?
                {
                    let plaintext = if let Some(engine) = crypto {
                        engine.unwrap_token_payload(raw.as_slice())?
                    } else {
                        raw
                    };
                    let secret_str = std::str::from_utf8(plaintext.as_slice()).map_err(|_| {
                        ZeroVaultError::InvalidWireFormat(
                            "stored backend secret is not valid UTF-8".into(),
                        )
                    })?;
                    resolved_secret = Some(RedactedSecret::new(secret_str));
                }
            }
            BackendKind::LocalFs | BackendKind::Memory => {}
        }

        Self::build_internal(
            config,
            oauth_bundle.as_ref(),
            resolved_secret.as_ref(),
            layer_config,
        )
    }

    /// Wraps a pre-constructed OpenDAL [`Operator`] (useful for custom middleware or test layers).
    #[must_use]
    pub fn from_operator(config: BackendConfig, operator: Operator) -> Self {
        Self {
            config,
            operator,
            used_bytes: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            latency_ms: AtomicU64::new(NO_LATENCY_SENTINEL),
            last_error: RwLock::new(None),
            known_sizes: DashMap::new(),
            synthetic_etags: DashMap::new(),
        }
    }

    fn build_internal(
        config: &BackendConfig,
        oauth_bundle: Option<&OAuthTokenBundle>,
        resolved_secret: Option<&RedactedSecret>,
        layer_config: BackendLayerConfig,
    ) -> ZeroVaultResult<Self> {
        if config.id.trim().is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "backend id must not be empty".into(),
            ));
        }

        let base_op = match config.kind {
            BackendKind::GoogleDrive => build_gdrive_operator(config, oauth_bundle)?,
            BackendKind::OneDrive => build_onedrive_operator(config, oauth_bundle)?,
            BackendKind::Dropbox => build_dropbox_operator(config, oauth_bundle)?,
            BackendKind::S3 => build_s3_operator(config, resolved_secret)?,
            BackendKind::WebDav => build_webdav_operator(config, resolved_secret)?,
            BackendKind::LocalFs => build_local_fs_operator(config)?,
            BackendKind::Memory => build_memory_operator(config)?,
        };

        let layered = apply_standard_layers(base_op, layer_config);
        tracing::info!(
            backend_id = %config.id,
            kind = ?config.kind,
            "initialized OpenDAL cloud backend"
        );

        Ok(Self::from_operator(config.clone(), layered))
    }

    /// Returns the immutable declarative configuration for this backend.
    #[must_use]
    pub fn config(&self) -> &BackendConfig {
        &self.config
    }

    /// Returns a reference to the underlying layered OpenDAL [`Operator`].
    #[must_use]
    pub fn operator(&self) -> &Operator {
        &self.operator
    }

    /// Returns `true` if the underlying OpenDAL backend natively enforces `If-Match` writes.
    #[must_use]
    pub fn supports_native_if_match(&self) -> bool {
        self.operator.info().capability().write_with_if_match
    }

    /// Returns `true` if this backend currently tracks a known object under `object_key`.
    #[must_use]
    pub(crate) fn has_known_object(&self, object_key: &str) -> bool {
        self.known_sizes.contains_key(object_key)
    }

    /// Returns tracked used bytes on this backend.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Acquire)
    }

    /// Returns configured quota cap or [`DEFAULT_UNBOUNDED_QUOTA_BYTES`].
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.config
            .quota_limit_bytes
            .unwrap_or(DEFAULT_UNBOUNDED_QUOTA_BYTES)
    }

    /// Returns remaining writable bytes (`total_bytes.saturating_sub(used_bytes)`).
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.total_bytes().saturating_sub(self.used_bytes())
    }

    /// Returns `true` when this backend is currently considered healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Updates health state explicitly (used by verified replica failover and circuit breakers).
    pub fn set_healthy(&self, healthy: bool, error: Option<String>) {
        self.healthy.store(healthy, Ordering::Release);
        *self.last_error.write() = error;
    }

    /// Returns a point-in-time [`BackendQuota`] snapshot.
    #[must_use]
    pub fn quota(&self) -> BackendQuota {
        let total = self.total_bytes();
        let used = self.used_bytes();
        BackendQuota {
            backend_id: self.config.id.clone(),
            total_bytes: total,
            used_bytes: used,
            available_bytes: total.saturating_sub(used),
        }
    }

    /// Returns a point-in-time [`BackendHealth`] snapshot.
    #[must_use]
    pub fn health(&self) -> BackendHealth {
        let raw_latency = self.latency_ms.load(Ordering::Acquire);
        let latency_ms = if raw_latency == NO_LATENCY_SENTINEL {
            None
        } else {
            Some(raw_latency)
        };
        BackendHealth {
            backend_id: self.config.id.clone(),
            kind: self.config.kind.clone(),
            healthy: self.is_healthy(),
            latency_ms,
            last_error: self.last_error.read().clone(),
            quota: self.quota(),
        }
    }

    /// Performs an active lightweight OpenDAL `check()` against the backend and updates health.
    pub async fn probe_health(&self) -> BackendHealth {
        let started = Instant::now();
        match self.operator.check().await {
            Ok(()) => {
                self.record_success(started.elapsed());
            }
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, "", err);
                self.record_backend_failure(&mapped);
            }
        }
        self.health()
    }

    /// Scans objects stored under this backend's root to reconcile `used_bytes` after restart.
    pub async fn sync_used_bytes(&self) -> ZeroVaultResult<u64> {
        let started = Instant::now();
        let mut lister = self
            .operator
            .lister_with("")
            .recursive(true)
            .await
            .map_err(|err| {
                let mapped = map_opendal_error(&self.config.id, "", err);
                self.record_backend_failure(&mapped);
                mapped
            })?;

        let mut total = 0u64;
        self.known_sizes.clear();
        while let Some(entry) = lister.try_next().await.map_err(|err| {
            let mapped = map_opendal_error(&self.config.id, "", err);
            self.record_backend_failure(&mapped);
            mapped
        })? {
            if entry.metadata().is_file() {
                let len = entry.metadata().content_length();
                total = total.saturating_add(len);
                self.known_sizes.insert(entry.path().to_owned(), len);
            }
        }

        self.used_bytes.store(total, Ordering::Release);
        self.record_success(started.elapsed());
        Ok(total)
    }

    /// Lock-free `AtomicU64` CAS quota reservation enforcing `quota_limit_bytes` and optional
    /// `min_free_reserve_bytes`.
    pub(crate) fn try_reserve_quota(
        &self,
        object_key: &str,
        new_len: u64,
        enforce_reserve: bool,
    ) -> Option<QuotaReservation> {
        let prev_len = self.known_sizes.get(object_key).map_or(0, |v| *v);
        let reserve_add = new_len.saturating_sub(prev_len);
        let reserve_floor = if enforce_reserve {
            self.config.min_free_reserve_bytes
        } else {
            0
        };

        if let Some(limit) = self.config.quota_limit_bytes {
            let mut cur = self.used_bytes.load(Ordering::Acquire);
            loop {
                let projected_after_write = cur.checked_add(reserve_add)?;
                let needed_with_reserve = projected_after_write.checked_add(reserve_floor)?;
                if needed_with_reserve > limit {
                    return None;
                }
                match self.used_bytes.compare_exchange_weak(
                    cur,
                    projected_after_write,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        } else if reserve_add > 0 {
            self.used_bytes.fetch_add(reserve_add, Ordering::AcqRel);
        }

        Some(QuotaReservation {
            reserved_add: reserve_add,
            prev_len,
            new_len,
        })
    }

    pub(crate) fn release_quota(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        let _ = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_sub(amount))
            });
    }

    fn commit_write_accounting(&self, object_key: &str, reservation: QuotaReservation) {
        if reservation.new_len < reservation.prev_len {
            let reclaimed = reservation.prev_len - reservation.new_len;
            self.release_quota(reclaimed);
        }
        self.known_sizes
            .insert(object_key.to_owned(), reservation.new_len);
    }

    /// Uploads an encrypted blob/object after validating zero-knowledge key grammar and wire bounds.
    pub async fn put_object(
        &self,
        object_key: &str,
        ciphertext: Bytes,
        enforce_reserve: bool,
    ) -> ZeroVaultResult<ReplicaTarget> {
        let max_bytes = max_wire_bytes_for_object_key(object_key)?;
        if ciphertext.len() > max_bytes {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "object '{object_key}' payload ({} bytes) exceeds wire ceiling ({max_bytes} bytes)",
                ciphertext.len()
            )));
        }
        let len = ciphertext.len() as u64;

        let Some(reservation) = self.try_reserve_quota(object_key, len, enforce_reserve) else {
            return Err(ZeroVaultError::StorageQuotaExceeded(self.config.id.clone()));
        };

        let started = Instant::now();
        let write_res = self.operator.write(object_key, ciphertext).await;
        match write_res {
            Ok(meta) => {
                self.commit_write_accounting(object_key, reservation);
                let etag = self.record_etag_after_write(object_key, &meta);
                self.record_success(started.elapsed());
                Ok(ReplicaTarget {
                    backend_id: self.config.id.clone(),
                    etag: Some(etag),
                })
            }
            Err(err) => {
                self.release_quota(reservation.reserved_add);
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                Err(mapped)
            }
        }
    }

    /// Uploads a manifest object with optional optimistic concurrency ETag enforcement.
    ///
    /// Uses native `If-Match` when supported by the provider (e.g. S3, OneDrive) and otherwise
    /// performs a pre-write `stat_object` ETag comparison (expected to be serialized by the caller's
    /// manifest CAS mutex).
    pub async fn put_object_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        let max_bytes = max_wire_bytes_for_object_key(object_key)?;
        if sealed_manifest.len() > max_bytes {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "object '{object_key}' payload ({} bytes) exceeds wire ceiling ({max_bytes} bytes)",
                sealed_manifest.len()
            )));
        }
        let len = sealed_manifest.len() as u64;

        if !self.supports_native_if_match()
            && let Some(expected) = expected_etag
        {
            match self.stat_object(object_key).await? {
                Some(current) if current.etag.as_deref() == Some(expected) => {}
                Some(_) => {
                    return Err(ZeroVaultError::StorageConflict(format!(
                        "manifest ETag mismatch for {object_key}"
                    )));
                }
                None => {
                    return Err(ZeroVaultError::StorageConflict(format!(
                        "manifest {object_key} does not exist for expected ETag"
                    )));
                }
            }
        }

        let Some(reservation) = self.try_reserve_quota(object_key, len, false) else {
            return Err(ZeroVaultError::StorageQuotaExceeded(self.config.id.clone()));
        };

        let started = Instant::now();
        let write_res = if self.supports_native_if_match() {
            if let Some(expected) = expected_etag {
                self.operator
                    .write_with(object_key, sealed_manifest)
                    .if_match(expected)
                    .await
            } else {
                self.operator.write(object_key, sealed_manifest).await
            }
        } else {
            self.operator.write(object_key, sealed_manifest).await
        };

        match write_res {
            Ok(meta) => {
                self.commit_write_accounting(object_key, reservation);
                let etag = self.record_etag_after_write(object_key, &meta);
                let last_modified = metadata_last_modified_utc(&meta).or_else(|| Some(Utc::now()));
                self.record_success(started.elapsed());
                Ok(RemoteVersion {
                    object_key: object_key.to_owned(),
                    etag: Some(etag),
                    content_length: len,
                    last_modified,
                })
            }
            Err(err) => {
                self.release_quota(reservation.reserved_add);
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                Err(mapped)
            }
        }
    }

    /// Downloads an encrypted object using strictly bounded streaming reads (`operator.reader(key)`
    /// -> `into_stream(..)`) after validating zero-knowledge key grammar.
    pub async fn get_object(&self, object_key: &str) -> ZeroVaultResult<Bytes> {
        let max_bytes = max_wire_bytes_for_object_key(object_key)?;
        let started = Instant::now();
        let reader = match self.operator.reader(object_key).await {
            Ok(r) => r,
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                return Err(mapped);
            }
        };
        let mut stream = match reader.into_stream(..).await {
            Ok(s) => s,
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                return Err(mapped);
            }
        };

        let mut out = BytesMut::new();
        loop {
            match stream.try_next().await {
                Ok(Some(chunk)) => {
                    let chunk_len = chunk.len();
                    let next_total = out.len().saturating_add(chunk_len);
                    if next_total > max_bytes {
                        let err = ZeroVaultError::InvalidWireFormat(format!(
                            "remote object '{object_key}' exceeded maximum allowed wire size ({max_bytes} bytes)"
                        ));
                        self.record_backend_failure(&err);
                        return Err(err);
                    }
                    for slice in chunk {
                        out.put_slice(&slice);
                    }
                }
                Ok(None) => {
                    self.record_success(started.elapsed());
                    return Ok(out.freeze());
                }
                Err(err) => {
                    let mapped = map_opendal_error(&self.config.id, object_key, err);
                    self.record_backend_failure(&mapped);
                    return Err(mapped);
                }
            }
        }
    }

    /// Downloads a bounded byte range `[offset, offset + len)` from `key` using OpenDAL native
    /// byte-range reading (`reader.read(offset..offset + len as u64)`).
    pub async fn get_object_range(
        &self,
        key: &str,
        offset: u64,
        len: usize,
    ) -> ZeroVaultResult<Bytes> {
        let max_bytes = max_wire_bytes_for_object_key(key)?;
        if len > max_bytes {
            return Err(ZeroVaultError::InvalidRange {
                offset,
                len,
                size: max_bytes as u64,
            });
        }

        let end = offset
            .checked_add(len as u64)
            .ok_or(ZeroVaultError::InvalidRange {
                offset,
                len,
                size: max_bytes as u64,
            })?;

        if len == 0 {
            let Some(meta) = self.stat_object(key).await? else {
                return Err(ZeroVaultError::StorageNotFound(key.to_owned()));
            };
            if offset > meta.content_length {
                return Err(ZeroVaultError::InvalidRange {
                    offset,
                    len,
                    size: meta.content_length,
                });
            }
            return Ok(Bytes::new());
        }

        let started = Instant::now();
        let reader = match self.operator.reader(key).await {
            Ok(r) => r,
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, key, err);
                self.record_backend_failure(&mapped);
                return Err(mapped);
            }
        };

        let buffer = match reader.read(offset..end).await {
            Ok(buf) => buf,
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, key, err);
                self.record_backend_failure(&mapped);
                return Err(mapped);
            }
        };

        if buffer.len() > len || buffer.len() > max_bytes {
            let err = ZeroVaultError::InvalidWireFormat(format!(
                "remote object '{key}' range read returned {} bytes, exceeding requested {len} bytes",
                buffer.len()
            ));
            self.record_backend_failure(&err);
            return Err(err);
        }

        self.record_success(started.elapsed());
        Ok(buffer.to_bytes())
    }

    /// Queries remote object metadata without downloading payload bytes.
    pub async fn stat_object(&self, object_key: &str) -> ZeroVaultResult<Option<RemoteVersion>> {
        validate_remote_object_key(object_key)?;
        let started = Instant::now();
        match self.operator.stat(object_key).await {
            Ok(meta) => {
                self.record_success(started.elapsed());
                let etag = self.resolve_etag(object_key, &meta);
                let last_modified = metadata_last_modified_utc(&meta);
                Ok(Some(RemoteVersion {
                    object_key: object_key.to_owned(),
                    etag: Some(etag),
                    content_length: meta.content_length(),
                    last_modified,
                }))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.record_success(started.elapsed());
                Ok(None)
            }
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                Err(mapped)
            }
        }
    }

    /// Deletes a remote object idempotently and reclaims tracked quota accounting.
    pub async fn delete_object(&self, object_key: &str) -> ZeroVaultResult<()> {
        validate_remote_object_key(object_key)?;
        let known_len = self.known_sizes.get(object_key).map(|v| *v);
        let fallback_len = if known_len.is_none() {
            match self.operator.stat(object_key).await {
                Ok(meta) => Some(meta.content_length()),
                Err(_) => None,
            }
        } else {
            None
        };

        let started = Instant::now();
        match self.operator.delete(object_key).await {
            Ok(()) => {
                self.known_sizes.remove(object_key);
                self.synthetic_etags.remove(object_key);
                if let Some(len) = known_len.or(fallback_len) {
                    self.release_quota(len);
                }
                self.record_success(started.elapsed());
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.known_sizes.remove(object_key);
                self.synthetic_etags.remove(object_key);
                self.record_success(started.elapsed());
                Ok(())
            }
            Err(err) => {
                let mapped = map_opendal_error(&self.config.id, object_key, err);
                self.record_backend_failure(&mapped);
                Err(mapped)
            }
        }
    }

    fn record_success(&self, elapsed: Duration) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX - 1);
        let bounded = ms.min(NO_LATENCY_SENTINEL - 1);
        self.latency_ms.store(bounded, Ordering::Release);
        self.healthy.store(true, Ordering::Release);
        *self.last_error.write() = None;
    }

    fn record_backend_failure(&self, err: &ZeroVaultError) {
        match err {
            ZeroVaultError::StorageNotFound(_) | ZeroVaultError::StorageConflict(_) => {}
            _ => {
                self.healthy.store(false, Ordering::Release);
                *self.last_error.write() = Some(err.to_string());
            }
        }
    }

    fn record_etag_after_write(&self, object_key: &str, meta: &Metadata) -> String {
        if let Some(etag) = meta.etag().filter(|s| !s.is_empty()) {
            return etag.to_owned();
        }
        let fresh = format!("\"{}\"", Uuid::new_v4().as_simple());
        let entry = SyntheticEtagEntry {
            etag: fresh.clone(),
            content_length: meta.content_length(),
            last_modified: metadata_ts_tuple(meta),
        };
        self.synthetic_etags.insert(object_key.to_owned(), entry);
        fresh
    }

    fn resolve_etag(&self, object_key: &str, meta: &Metadata) -> String {
        if let Some(etag) = meta.etag().filter(|s| !s.is_empty()) {
            return etag.to_owned();
        }
        let len = meta.content_length();
        let ts = metadata_ts_tuple(meta);
        if let Some(existing) = self.synthetic_etags.get(object_key)
            && existing.content_length == len
            && existing.last_modified == ts
        {
            return existing.etag.clone();
        }
        let derived = match ts {
            Some((secs, nanos)) => format!("\"zv-{len}-{secs}-{nanos}\""),
            None => format!("\"zv-{len}\""),
        };
        self.synthetic_etags.insert(
            object_key.to_owned(),
            SyntheticEtagEntry {
                etag: derived.clone(),
                content_length: len,
                last_modified: ts,
            },
        );
        derived
    }
}

pub(crate) struct QuotaReservation {
    pub(crate) reserved_add: u64,
    pub(crate) prev_len: u64,
    pub(crate) new_len: u64,
}

fn apply_standard_layers(op: Operator, cfg: BackendLayerConfig) -> Operator {
    op.layer(layers::ConcurrentLimitLayer::new(
        cfg.concurrent_limit.max(1),
    ))
    .layer(
        layers::TimeoutLayer::new()
            .with_timeout(cfg.timeout)
            .with_io_timeout(cfg.io_timeout),
    )
    .layer(
        layers::RetryLayer::new()
            .with_jitter()
            .with_min_delay(cfg.retry_min_delay)
            .with_max_delay(cfg.retry_max_delay)
            .with_max_times(cfg.max_retries),
    )
}

fn build_gdrive_operator(
    config: &BackendConfig,
    oauth_bundle: Option<&OAuthTokenBundle>,
) -> ZeroVaultResult<Operator> {
    let mut builder = services::Gdrive::default();
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }

    if let Some(bundle) = oauth_bundle {
        let client_id = bundle
            .client_id
            .as_deref()
            .or(config.access_key_id.as_deref());
        let client_secret = bundle
            .client_secret
            .as_ref()
            .or(config.secret_access_key.as_ref());

        if let (Some(rt), Some(cid), Some(csec)) =
            (bundle.refresh_token.as_ref(), client_id, client_secret)
        {
            builder = builder
                .refresh_token(rt.as_str())
                .client_id(cid)
                .client_secret(csec.as_str());
        } else {
            builder = builder.access_token(bundle.access_token.as_str());
        }
    } else if let Some(token) = config.secret_access_key.as_ref() {
        builder = builder.access_token(token.as_str());
    } else {
        return Err(ZeroVaultError::ConfigError(format!(
            "GoogleDrive backend '{}' requires OAuth2 tokens in SecretStore or secret_access_key",
            config.id
        )));
    }

    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_onedrive_operator(
    config: &BackendConfig,
    oauth_bundle: Option<&OAuthTokenBundle>,
) -> ZeroVaultResult<Operator> {
    let mut builder = services::Onedrive::default();
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }

    if let Some(bundle) = oauth_bundle {
        let client_id = bundle
            .client_id
            .as_deref()
            .or(config.access_key_id.as_deref());
        let client_secret = bundle
            .client_secret
            .as_ref()
            .or(config.secret_access_key.as_ref());

        if let (Some(rt), Some(cid)) = (bundle.refresh_token.as_ref(), client_id) {
            builder = builder.refresh_token(rt.as_str()).client_id(cid);
            if let Some(csec) = client_secret {
                builder = builder.client_secret(csec.as_str());
            }
        } else {
            builder = builder.access_token(bundle.access_token.as_str());
        }
    } else if let Some(token) = config.secret_access_key.as_ref() {
        builder = builder.access_token(token.as_str());
    } else {
        return Err(ZeroVaultError::ConfigError(format!(
            "OneDrive backend '{}' requires OAuth2 tokens in SecretStore or secret_access_key",
            config.id
        )));
    }

    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_dropbox_operator(
    config: &BackendConfig,
    oauth_bundle: Option<&OAuthTokenBundle>,
) -> ZeroVaultResult<Operator> {
    let mut builder = services::Dropbox::default();
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }

    if let Some(bundle) = oauth_bundle {
        let client_id = bundle
            .client_id
            .as_deref()
            .or(config.access_key_id.as_deref());
        let client_secret = bundle
            .client_secret
            .as_ref()
            .or(config.secret_access_key.as_ref());

        if let (Some(rt), Some(cid), Some(csec)) =
            (bundle.refresh_token.as_ref(), client_id, client_secret)
        {
            builder = builder
                .refresh_token(rt.as_str())
                .client_id(cid)
                .client_secret(csec.as_str());
        } else {
            builder = builder.access_token(bundle.access_token.as_str());
        }
    } else if let Some(token) = config.secret_access_key.as_ref() {
        builder = builder.access_token(token.as_str());
    } else {
        return Err(ZeroVaultError::ConfigError(format!(
            "Dropbox backend '{}' requires OAuth2 tokens in SecretStore or secret_access_key",
            config.id
        )));
    }

    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_s3_operator(
    config: &BackendConfig,
    resolved_secret: Option<&RedactedSecret>,
) -> ZeroVaultResult<Operator> {
    let bucket = config
        .bucket
        .as_deref()
        .filter(|b| !b.trim().is_empty())
        .ok_or_else(|| {
            ZeroVaultError::ConfigError(format!("S3 backend '{}' requires bucket name", config.id))
        })?;

    let mut builder = services::S3::default().bucket(bucket);
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }
    if let Some(region) = config.region.as_deref().filter(|r| !r.is_empty()) {
        builder = builder.region(region);
    }
    if let Some(endpoint) = config.endpoint.as_deref().filter(|e| !e.is_empty()) {
        builder = builder.endpoint(endpoint);
    }
    if let Some(ak) = config.access_key_id.as_deref().filter(|k| !k.is_empty()) {
        builder = builder.access_key_id(ak);
    }
    if let Some(sk) = config.secret_access_key.as_ref().or(resolved_secret) {
        builder = builder.secret_access_key(sk.as_str());
    }

    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_webdav_operator(
    config: &BackendConfig,
    resolved_secret: Option<&RedactedSecret>,
) -> ZeroVaultResult<Operator> {
    let endpoint = config
        .endpoint
        .as_deref()
        .filter(|e| !e.trim().is_empty())
        .ok_or_else(|| {
            ZeroVaultError::ConfigError(format!(
                "WebDAV backend '{}' requires endpoint URL",
                config.id
            ))
        })?;

    let mut builder = services::Webdav::default().endpoint(endpoint);
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }
    if let Some(username) = config.username.as_deref().filter(|u| !u.is_empty()) {
        builder = builder.username(username);
    }
    if let Some(password) = config.secret_access_key.as_ref().or(resolved_secret) {
        builder = builder.password(password.as_str());
    }

    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_local_fs_operator(config: &BackendConfig) -> ZeroVaultResult<Operator> {
    if config.root.trim().is_empty() {
        return Err(ZeroVaultError::ConfigError(format!(
            "LocalFs backend '{}' requires non-empty root directory",
            config.id
        )));
    }
    std::fs::create_dir_all(&config.root)?;
    let builder = services::Fs::default().root(&config.root);
    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn build_memory_operator(config: &BackendConfig) -> ZeroVaultResult<Operator> {
    let mut builder = services::Memory::default();
    if !config.root.is_empty() {
        builder = builder.root(&config.root);
    }
    Operator::new(builder).map_err(|err| map_opendal_error(&config.id, "", err))
}

fn metadata_last_modified_utc(meta: &Metadata) -> Option<DateTime<Utc>> {
    meta.last_modified()
        .map(|ts| DateTime::<Utc>::from(SystemTime::from(ts)))
}

fn metadata_ts_tuple(meta: &Metadata) -> Option<(i64, u32)> {
    metadata_last_modified_utc(meta).map(|dt| (dt.timestamp(), dt.timestamp_subsec_nanos()))
}

pub(crate) fn map_opendal_error(
    backend_id: &str,
    object_key: &str,
    err: opendal::Error,
) -> ZeroVaultError {
    let summary = format!("{}: {}", err.kind(), err.message());
    match err.kind() {
        ErrorKind::NotFound => ZeroVaultError::StorageNotFound(if object_key.is_empty() {
            format!("backend '{backend_id}' path not found")
        } else {
            object_key.to_owned()
        }),
        ErrorKind::ConditionNotMatch | ErrorKind::Conflict | ErrorKind::AlreadyExists => {
            ZeroVaultError::StorageConflict(format!(
                "backend '{backend_id}' conflict on '{object_key}': {summary}"
            ))
        }
        ErrorKind::ConfigInvalid => ZeroVaultError::ConfigError(format!(
            "backend '{backend_id}' invalid config: {summary}"
        )),
        _ => ZeroVaultError::StorageBackendError(format!(
            "backend '{backend_id}' error ({summary})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_wire_caps_cover_all_zero_knowledge_object_classes() -> ZeroVaultResult<()> {
        let blob = BlobObjectKey::from_uuid(Uuid::new_v4());
        let share = ShareObjectKey::from_uuid(Uuid::new_v4());
        let snap = ManifestObjectKey::from_uuid(Uuid::new_v4());

        assert_eq!(
            max_wire_bytes_for_object_key(VAULT_HEADER_OBJECT_KEY)?,
            VAULT_HEADER_LEN
        );
        assert_eq!(
            max_wire_bytes_for_object_key(KEYBOX_OBJECT_KEY)?,
            MAX_KEYBOX_BYTES
        );
        assert_eq!(
            max_wire_bytes_for_object_key(share.as_str())?,
            MAX_SHARE_OBJECT_BYTES
        );
        assert_eq!(
            max_wire_bytes_for_object_key(blob.as_str())?,
            MAX_ENCRYPTED_CHUNK_SIZE
        );
        assert_eq!(
            max_wire_bytes_for_object_key(snap.as_str())?,
            MAX_SEALED_MANIFEST_BYTES
        );
        assert!(max_wire_bytes_for_object_key("Taxes/2026.pdf").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn unit_memory_backend_stream_and_range_roundtrip() -> ZeroVaultResult<()> {
        let cfg = BackendConfig {
            id: "mem-unit".to_owned(),
            kind: BackendKind::Memory,
            root: "/".to_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(4096),
            min_free_reserve_bytes: 256,
            username: None,
            access_key_id: None,
            secret_access_key: None,
            secret_account_key: None,
        };
        let backend = CloudBackend::from_config(&cfg)?;
        let key = BlobObjectKey::from_uuid(Uuid::new_v4());
        let data = Bytes::from_static(b"0123456789abcdef0123456789abcdef");

        backend
            .put_object(key.as_str(), data.clone(), true)
            .await?;
        assert_eq!(backend.used_bytes(), 32);
        assert_eq!(backend.get_object(key.as_str()).await?, data);
        assert_eq!(
            backend.get_object_range(key.as_str(), 10, 6).await?.as_ref(),
            b"abcdef"
        );
        backend.delete_object(key.as_str()).await?;
        assert_eq!(backend.used_bytes(), 0);
        Ok(())
    }
}

