//! Bounded 4 MiB streaming sync engine implementing [`entrocloud_types::VfsBackend`],
//! verified mirror failover (`NEW-M02`), manifest chain & epoch rollback protection (`NEW-M01`),
//! orphan `.zv` blob GC (`NEW-L03`), serverless E2E sharing (`keybox.zv` & `zv://`), and atomic export.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use dashmap::DashMap;
use futures::stream::{self, StreamExt, TryStreamExt};
use parking_lot::Mutex;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;
use entrocloud_types::{
    BackendId, BlobObjectKey, CapabilityUri, ChunkAad, ChunkDescriptor, ChunkRef, CreateEntrySpec,
    CryptoEngine, DekBytes, DirtyOpKind, DriveStats, ED25519_PUBKEY_LEN, EntryKind, HydrationState,
    InodeId, InodeRecord, KEYBOX_OBJECT_KEY, MANIFEST_HEAD_OBJECT_KEY, ManifestNode,
    ManifestObjectKey, MetadataStore, PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RecipientPrivateIdentity,
    RemoteVersion, SetAttrSpec, ShareDescriptor, ShareObjectKey, SignedKeybox, SignedShareEnvelope,
    StorageRouterTrait, ThroughputSnapshot, VAULT_HEADER_OBJECT_KEY, VaultHeader, VaultManifest,
    VfsBackend, ZeroVaultError, ZeroVaultResult, chunk_span_for_range, normalize_virtual_path,
    validate_portable_entry_name,
};

use crate::cache::{ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES, secure_wipe_and_remove_file};
use crate::conflict::{ConflictResolver, join_virtual_path, rebase_descendant_paths};
use crate::pool::{
    BoundedBufferPool, DEFAULT_BUFFER_SLOTS, PooledBuffer, reclaim_process_memory,
};

/// Security epoch scope name for manifest revision rollback enforcement.
pub const EPOCH_SCOPE_MANIFEST: &str = "manifest";
/// Security epoch scope name for `keybox.zv` revocation/replay enforcement.
pub const EPOCH_SCOPE_KEYBOX: &str = "keybox";

/// Maximum historical manifest hops walked when verifying multi-step `parent_manifest_id` chains.
const MAX_MANIFEST_ANCESTOR_HOPS: usize = 32;

/// Configuration parameters for [`SyncEngine`].
#[derive(Clone, PartialEq, Eq)]
pub struct SyncEngineConfig {
    /// Local staging directory used for per-4-MiB encrypted `.zvpart` dirty chunk files.
    pub staging_dir: PathBuf,
    /// Stable local device identifier used in manifest headers and conflict filenames.
    pub device_id: String,
    /// Maximum RAM bytes allocated to the decrypted chunk LRU cache (default 32 MiB).
    pub max_ram_cache_bytes: usize,
    /// Maximum concurrent 4 MiB chunk transfer buffers in [`BoundedBufferPool`] (default 8).
    pub max_concurrent_transfers: usize,
}

impl Default for SyncEngineConfig {
    fn default() -> Self {
        Self {
            staging_dir: PathBuf::from(".zerovault-staging"),
            device_id: "local-device".to_owned(),
            max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
            max_concurrent_transfers: DEFAULT_BUFFER_SLOTS,
        }
    }
}

impl fmt::Debug for SyncEngineConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncEngineConfig")
            .field("device_id", &self.device_id)
            .field("max_ram_cache_bytes", &self.max_ram_cache_bytes)
            .field("max_concurrent_transfers", &self.max_concurrent_transfers)
            .finish_non_exhaustive()
    }
}

/// Summary report returned by [`SyncEngine::sync_once`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Remote manifest revision pulled during this cycle, if any.
    pub pulled_revision: Option<u64>,
    /// New manifest revision published during this cycle, if any.
    pub published_revision: Option<u64>,
    /// Number of remote manifest nodes applied locally.
    pub applied_remote_nodes: usize,
    /// Number of clean local nodes pruned after remote deletion.
    pub pruned_local_nodes: usize,
    /// Number of dirty-vs-remote conflicts resolved without data loss.
    pub conflicts_resolved: usize,
    /// Number of queued dirty ops successfully replayed.
    pub replayed_dirty_ops: usize,
    /// Number of queued dirty ops that hit transient failures and incremented retry count.
    pub failed_dirty_ops: usize,
    /// Number of superseded orphan `.zv` chunk blobs garbage-collected after commit.
    pub gc_deleted_blobs: usize,
}

#[derive(Debug)]
struct EngineTelemetry {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    chunks_hydrated: AtomicU64,
    cache_hits: AtomicU64,
    open_handles: AtomicU64,
    rate_window: Mutex<ThroughputWindow>,
}

#[derive(Debug)]
struct ThroughputWindow {
    window_start: Instant,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    last_upload_bps: u64,
    last_download_bps: u64,
}

impl Default for EngineTelemetry {
    fn default() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            chunks_hydrated: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            open_handles: AtomicU64::new(0),
            rate_window: Mutex::new(ThroughputWindow {
                window_start: Instant::now(),
                uploaded_bytes: 0,
                downloaded_bytes: 0,
                last_upload_bps: 0,
                last_download_bps: 0,
            }),
        }
    }
}

impl EngineTelemetry {
    fn record_upload(&self, bytes: u64) {
        let mut guard = self.rate_window.lock();
        Self::roll_window_if_needed(&mut guard);
        guard.uploaded_bytes = guard.uploaded_bytes.saturating_add(bytes);
    }

    fn record_download(&self, bytes: u64) {
        let mut guard = self.rate_window.lock();
        Self::roll_window_if_needed(&mut guard);
        guard.downloaded_bytes = guard.downloaded_bytes.saturating_add(bytes);
    }

    fn roll_window_if_needed(win: &mut ThroughputWindow) {
        let elapsed = win.window_start.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let secs = elapsed.as_secs_f64().max(0.001);
            win.last_upload_bps = (win.uploaded_bytes as f64 / secs) as u64;
            win.last_download_bps = (win.downloaded_bytes as f64 / secs) as u64;
            win.uploaded_bytes = 0;
            win.downloaded_bytes = 0;
            win.window_start = Instant::now();
        }
    }

    fn rates_bps(&self) -> (u64, u64) {
        let mut guard = self.rate_window.lock();
        let elapsed = guard.window_start.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            Self::roll_window_if_needed(&mut guard);
            (guard.last_upload_bps, guard.last_download_bps)
        } else if guard.uploaded_bytes > 0 || guard.downloaded_bytes > 0 {
            let secs = elapsed.max(0.01);
            (
                (guard.uploaded_bytes as f64 / secs) as u64,
                (guard.downloaded_bytes as f64 / secs) as u64,
            )
        } else {
            (guard.last_upload_bps, guard.last_download_bps)
        }
    }
}

/// Computes the canonical deterministic snapshot UUID for a [`VaultManifest`] (`NEW-M01` chain anchor).
pub fn compute_manifest_id(manifest: &VaultManifest) -> ZeroVaultResult<Uuid> {
    let encoded = postcard::to_allocvec(manifest).map_err(|e| {
        ZeroVaultError::InvalidWireFormat(format!("failed to encode manifest for ID hash: {e}"))
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ZV-MANIFEST-ID-V2");
    hasher.update(&encoded);
    let digest = hasher.finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[0..16]);
    Ok(Uuid::from_bytes(raw))
}

/// Downloads and AEAD-verifies a `.zv` chunk blob, automatically failing over across candidate
/// mirror replicas when a corrupt or bit-rotted replica fails verification (`NEW-M02` remediation).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_decrypt_chunk(
    storage: &dyn StorageRouterTrait,
    crypto: &dyn CryptoEngine,
    pool: &BoundedBufferPool,
    dek: &DekBytes,
    expected_file_id: Uuid,
    expected_chunk_index: u64,
    expected_plaintext_len: u32,
    expected_blake3: &[u8; 32],
    blob_key: &str,
    preferred_backends: &[BackendId],
) -> ZeroVaultResult<(PooledBuffer, usize)> {
    let mut pt_buf = pool.acquire_buffer().await?;

    let primary_res = storage.get_blob(blob_key, preferred_backends).await;
    let mut tamper_failure: Option<ZeroVaultError> = None;
    let mut transport_failure: Option<ZeroVaultError> = None;

    match primary_res {
        Ok(wire) => {
            match verify_chunk_payload(
                crypto,
                dek,
                expected_file_id,
                expected_chunk_index,
                expected_plaintext_len,
                expected_blake3,
                &wire,
                &mut pt_buf,
            ) {
                Ok(()) => return Ok((pt_buf, wire.len())),
                Err(err)
                    if matches!(
                        err,
                        ZeroVaultError::CryptoTamperDetected(_)
                            | ZeroVaultError::InvalidWireFormat(_)
                    ) =>
                {
                    tracing::warn!(
                        chunk_index = expected_chunk_index,
                        "primary replica failed chunk verification; trying mirror replicas"
                    );
                    tamper_failure = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        Err(err) => {
            if is_fatal_sync_error(&err) {
                return Err(err);
            }
            transport_failure = Some(err);
        }
    }

    for backend_id in storage.candidate_backends(preferred_backends) {
        match storage.get_blob_from_backend(&backend_id, blob_key).await {
            Ok(alt_wire) => {
                pt_buf.clear();
                match verify_chunk_payload(
                    crypto,
                    dek,
                    expected_file_id,
                    expected_chunk_index,
                    expected_plaintext_len,
                    expected_blake3,
                    &alt_wire,
                    &mut pt_buf,
                ) {
                    Ok(()) => return Ok((pt_buf, alt_wire.len())),
                    Err(err)
                        if matches!(
                            err,
                            ZeroVaultError::CryptoTamperDetected(_)
                                | ZeroVaultError::InvalidWireFormat(_)
                        ) =>
                    {
                        tamper_failure = Some(err);
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) => {
                if transport_failure.is_none() {
                    transport_failure = Some(err);
                }
            }
        }
    }

    if let Some(err) = tamper_failure {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "all mirror replicas failed chunk verification for {blob_key}: {err}"
        )));
    }
    Err(transport_failure.unwrap_or_else(|| ZeroVaultError::StorageNotFound(blob_key.to_owned())))
}

#[allow(clippy::too_many_arguments)]
fn verify_chunk_payload(
    crypto: &dyn CryptoEngine,
    dek: &DekBytes,
    expected_file_id: Uuid,
    expected_chunk_index: u64,
    expected_plaintext_len: u32,
    expected_blake3: &[u8; 32],
    wire: &[u8],
    pt_buf: &mut BytesMut,
) -> ZeroVaultResult<()> {
    let hdr = crypto.decrypt_chunk_into(
        dek,
        expected_file_id,
        Some(expected_chunk_index),
        wire,
        pt_buf,
    )?;

    if hdr.plaintext_len != expected_plaintext_len {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "chunk {expected_chunk_index} plaintext_len mismatch: header={}, metadata={expected_plaintext_len}",
            hdr.plaintext_len
        )));
    }

    if expected_blake3 != &[0u8; 32] {
        let actual = blake3::hash(pt_buf);
        if actual.as_bytes() != expected_blake3 {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "chunk {expected_chunk_index} BLAKE3 digest mismatch"
            )));
        }
    }

    Ok(())
}

/// Core zero-knowledge sync & virtual filesystem backend orchestrating encrypted SQLite WAL metadata,
/// bounded 4 MiB streaming crypto buffers, encrypted `.zvpart` local staging, and multi-cloud storage.
pub struct SyncEngine {
    config: SyncEngineConfig,
    meta: Arc<dyn MetadataStore>,
    crypto: Arc<dyn CryptoEngine>,
    storage: Arc<dyn StorageRouterTrait>,
    pool: BoundedBufferPool,
    cache: ChunkCache,
    stats: Arc<EngineTelemetry>,
    inode_locks: DashMap<InodeId, Arc<AsyncMutex<()>>>,
    sync_lock: AsyncMutex<()>,
    last_manifest_id: Mutex<Option<Uuid>>,
    committed_nodes: Mutex<HashMap<InodeId, ManifestNode>>,
    pending_gc_blobs: Mutex<HashMap<Uuid, Vec<BackendId>>>,
}

impl fmt::Debug for SyncEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncEngine")
            .field("config", &self.config)
            .field("pool", &self.pool)
            .field("cache_used_ram_bytes", &self.cache.used_ram_bytes())
            .field("cache_max_ram_bytes", &self.cache.max_ram_bytes())
            .field(
                "bytes_read",
                &self.stats.bytes_read.load(Ordering::Relaxed),
            )
            .field(
                "bytes_written",
                &self.stats.bytes_written.load(Ordering::Relaxed),
            )
            .field(
                "chunks_hydrated",
                &self.stats.chunks_hydrated.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl SyncEngine {
    /// Constructs a new [`SyncEngine`] with bounded memory pools and encrypted `.zvpart` disk staging.
    pub fn new(
        config: SyncEngineConfig,
        meta: Arc<dyn MetadataStore>,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<Self> {
        let pool = BoundedBufferPool::new(config.max_concurrent_transfers.max(2));
        let cache = ChunkCache::new(
            config.max_ram_cache_bytes,
            &config.staging_dir,
            Arc::clone(&crypto),
        )?;
        Ok(Self {
            config,
            meta,
            crypto,
            storage,
            pool,
            cache,
            stats: Arc::new(EngineTelemetry::default()),
            inode_locks: DashMap::new(),
            sync_lock: AsyncMutex::new(()),
            last_manifest_id: Mutex::new(None),
            committed_nodes: Mutex::new(HashMap::new()),
            pending_gc_blobs: Mutex::new(HashMap::new()),
        })
    }

    fn ensure_unlocked(&self) -> ZeroVaultResult<()> {
        if !self.crypto.is_unlocked() {
            self.cache.clear_ram();
            return Err(ZeroVaultError::VaultLocked);
        }
        Ok(())
    }

    /// Locks the cryptographic engine, clears decrypted LRU & manifest caches, removes stray/non-dirty
    /// staging files while preserving AEAD-encrypted `.zvpart` files for inodes with pending `dirty_ops`,
    /// releases pooled buffers, and reclaims `mimalloc` pages.
    pub async fn lock_and_purge_cache(&self) -> ZeroVaultResult<()> {
        let _sync_guard = self.sync_lock.lock().await;
        let dirty_inodes: HashSet<InodeId> = self
            .meta
            .list_dirty_ops()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|op| op.inode)
            .collect();
        let lock_res = self.crypto.lock_vault().await;
        let purge_res = self.cache.purge_preserving_dirty(&dirty_inodes).await;
        self.committed_nodes.lock().clear();
        self.pool.clear_idle_buffers();
        reclaim_process_memory().await;
        lock_res?;
        purge_res
    }

    /// Returns a reference to the engine configuration.
    #[must_use]
    pub fn config(&self) -> &SyncEngineConfig {
        &self.config
    }

    /// Returns a reference to the underlying [`MetadataStore`].
    #[must_use]
    pub fn metadata(&self) -> &Arc<dyn MetadataStore> {
        &self.meta
    }

    /// Returns a reference to the underlying [`CryptoEngine`].
    #[must_use]
    pub fn crypto(&self) -> &Arc<dyn CryptoEngine> {
        &self.crypto
    }

    /// Returns a reference to the underlying [`StorageRouterTrait`].
    #[must_use]
    pub fn storage(&self) -> &Arc<dyn StorageRouterTrait> {
        &self.storage
    }

    /// Returns a reference to the [`BoundedBufferPool`].
    #[must_use]
    pub fn pool(&self) -> &BoundedBufferPool {
        &self.pool
    }

    /// Returns a reference to the [`ChunkCache`].
    #[must_use]
    pub fn cache(&self) -> &ChunkCache {
        &self.cache
    }

    /// Captures a live throughput and cache snapshot for daemon/UI telemetry.
    pub async fn throughput_snapshot(&self) -> ZeroVaultResult<ThroughputSnapshot> {
        let (upload_bps, download_bps) = self.stats.rates_bps();
        let pending_dirty_ops = self.meta.list_dirty_ops().await?.len();
        Ok(ThroughputSnapshot {
            upload_bytes_per_sec: upload_bps,
            download_bytes_per_sec: download_bps,
            pending_dirty_ops,
            cache_bytes_used: self.cache.used_ram_bytes() as u64,
            sampled_at: Some(Utc::now()),
        })
    }

    /// Publishes an initialized `ZVH1` [`VaultHeader`] to `vault/header.zvh`.
    pub async fn publish_vault_header(
        &self,
        header: &VaultHeader,
    ) -> ZeroVaultResult<RemoteVersion> {
        header.kdf.validate_production()?;
        let encoded = header.encode();
        self.storage
            .put_manifest_cas(
                VAULT_HEADER_OBJECT_KEY,
                Bytes::copy_from_slice(&encoded),
                None,
            )
            .await
    }

    /// Downloads and validates the remote `ZVH1` [`VaultHeader`] from `vault/header.zvh`,
    /// failing over across candidate mirror backends if the primary returns corrupt bytes.
    pub async fn fetch_vault_header(router: &dyn StorageRouterTrait) -> ZeroVaultResult<VaultHeader> {
        let mut format_err: Option<ZeroVaultError> = None;
        let mut transport_err: Option<ZeroVaultError> = None;

        match router.get_blob(VAULT_HEADER_OBJECT_KEY, &[]).await {
            Ok(bytes) => match VaultHeader::decode(&bytes) {
                Ok(hdr) => return Ok(hdr),
                Err(err) => format_err = Some(err),
            },
            Err(err) => transport_err = Some(err),
        }

        for backend_id in router.candidate_backends(&[]) {
            if let Ok(alt_bytes) = router
                .get_blob_from_backend(&backend_id, VAULT_HEADER_OBJECT_KEY)
                .await
            {
                match VaultHeader::decode(&alt_bytes) {
                    Ok(hdr) => return Ok(hdr),
                    Err(err) => format_err = Some(err),
                }
            }
        }

        if let Some(err) = format_err {
            return Err(err);
        }
        Err(transport_err
            .unwrap_or_else(|| ZeroVaultError::StorageNotFound(VAULT_HEADER_OBJECT_KEY.to_owned())))
    }

    fn active_vault_id(&self) -> Option<Uuid> {
        if self.crypto.is_unlocked() {
            self.crypto.vault_id()
        } else {
            None
        }
    }

    /// Publishes a signed post-quantum multi-recipient [`SignedKeybox`] (`ZVK1`) to `vault/keybox.zv`,
    /// verifying `Ed25519` signature + `vault_id` + epoch floor BEFORE uploading or advancing SQLite `"keybox"` floor.
    pub async fn publish_keybox(&self, keybox: &SignedKeybox) -> ZeroVaultResult<RemoteVersion> {
        let floor = self.meta.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        self.crypto
            .verify_keybox_envelope(keybox, self.active_vault_id(), None, floor)?;
        let encoded = keybox.encode()?;
        let ver = self
            .storage
            .put_manifest_cas(KEYBOX_OBJECT_KEY, Bytes::from(encoded), None)
            .await?;
        self.stats.record_upload(ver.content_length);
        self.meta
            .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, keybox.epoch)
            .await?;
        Ok(ver)
    }

    /// Downloads, decodes, and cryptographically verifies (`Ed25519` signature + `vault_id` + SQLite
    /// `"keybox"` epoch floor) the current `vault/keybox.zv` (`ZVK1`) with replica failover (`W4-VETO-KEYBOX-SIG`).
    pub async fn fetch_keybox(&self) -> ZeroVaultResult<SignedKeybox> {
        let floor = self.meta.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
        let expected_vault_id = self.active_vault_id();

        let verify_raw = |raw: &[u8]| -> ZeroVaultResult<SignedKeybox> {
            let kb = SignedKeybox::decode(raw)?;
            self.crypto
                .verify_keybox_envelope(&kb, expected_vault_id, None, floor)?;
            Ok(kb)
        };

        let mut tamper_err: Option<ZeroVaultError> = None;
        let mut transport_err: Option<ZeroVaultError> = None;

        match self.storage.get_blob(KEYBOX_OBJECT_KEY, &[]).await {
            Ok(bytes) => match verify_raw(&bytes) {
                Ok(kb) => {
                    self.stats.record_download(bytes.len() as u64);
                    self.meta
                        .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, kb.epoch)
                        .await?;
                    return Ok(kb);
                }
                Err(err) => tamper_err = Some(err),
            },
            Err(err) => transport_err = Some(err),
        }

        for backend_id in self.storage.candidate_backends(&[]) {
            if let Ok(alt_bytes) = self
                .storage
                .get_blob_from_backend(&backend_id, KEYBOX_OBJECT_KEY)
                .await
            {
                match verify_raw(&alt_bytes) {
                    Ok(kb) => {
                        self.stats.record_download(alt_bytes.len() as u64);
                        self.meta
                            .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, kb.epoch)
                            .await?;
                        return Ok(kb);
                    }
                    Err(err) => tamper_err = Some(err),
                }
            }
        }

        if let Some(err) = tamper_err {
            return Err(match err {
                ZeroVaultError::CryptoTamperDetected(_) => err,
                other => ZeroVaultError::CryptoTamperDetected(other.to_string()),
            });
        }
        Err(transport_err
            .unwrap_or_else(|| ZeroVaultError::StorageNotFound(KEYBOX_OBJECT_KEY.to_owned())))
    }

    /// Downloads `vault/keybox.zv`, verifies the owner `Ed25519` signature, enforces and advances
    /// the persisted SQLite `"keybox"` epoch floor (preventing stale epoch replay), decapsulates
    /// the hybrid `X25519 + ML-KEM-768` stanza for `recipient_identity`, and unlocks the engine.
    pub async fn fetch_and_open_keybox(
        &self,
        expected_owner: Option<&[u8; ED25519_PUBKEY_LEN]>,
        recipient_identity: &RecipientPrivateIdentity,
    ) -> ZeroVaultResult<(SignedKeybox, Zeroizing<[u8; 32]>)> {
        let min_floor = self.meta.epoch_floor(EPOCH_SCOPE_KEYBOX).await?.max(1);
        let expected_vault_id = self.active_vault_id();

        let mut tamper_err: Option<ZeroVaultError> = None;
        let mut auth_err: Option<ZeroVaultError> = None;
        let mut transport_err: Option<ZeroVaultError> = None;

        let try_open = |raw: &[u8]| -> ZeroVaultResult<(SignedKeybox, Zeroizing<[u8; 32]>)> {
            let kb = SignedKeybox::decode(raw)?;
            self.crypto.verify_keybox_envelope(
                &kb,
                expected_vault_id,
                expected_owner,
                min_floor,
            )?;
            let frk =
                self.crypto
                    .open_keybox(&kb, expected_owner, min_floor, recipient_identity)?;
            Ok((kb, frk))
        };

        let mut opened: Option<(SignedKeybox, Zeroizing<[u8; 32]>, usize)> = None;
        match self.storage.get_blob(KEYBOX_OBJECT_KEY, &[]).await {
            Ok(raw) => match try_open(&raw) {
                Ok((kb, frk)) => opened = Some((kb, frk, raw.len())),
                Err(err @ ZeroVaultError::UnauthorizedRecipient(_)) => auth_err = Some(err),
                Err(err) => tamper_err = Some(err),
            },
            Err(err) => transport_err = Some(err),
        }

        if opened.is_none() && auth_err.is_none() {
            for backend_id in self.storage.candidate_backends(&[]) {
                if let Ok(alt_raw) = self
                    .storage
                    .get_blob_from_backend(&backend_id, KEYBOX_OBJECT_KEY)
                    .await
                {
                    match try_open(&alt_raw) {
                        Ok((kb, frk)) => {
                            opened = Some((kb, frk, alt_raw.len()));
                            break;
                        }
                        Err(err @ ZeroVaultError::UnauthorizedRecipient(_)) => {
                            auth_err = Some(err);
                            break;
                        }
                        Err(err) => tamper_err = Some(err),
                    }
                }
            }
        }

        let (keybox, frk, wire_len) = if let Some(valid) = opened {
            valid
        } else if let Some(err) = auth_err {
            return Err(err);
        } else if let Some(err) = tamper_err {
            return Err(err);
        } else {
            return Err(transport_err
                .unwrap_or_else(|| ZeroVaultError::StorageNotFound(KEYBOX_OBJECT_KEY.to_owned())));
        };

        self.stats.record_download(wire_len as u64);
        self.meta
            .advance_epoch_floor(EPOCH_SCOPE_KEYBOX, keybox.epoch)
            .await?;
        self.crypto.unlock_with_folder_key(keybox.vault_id, &frk)?;
        Ok((keybox, frk))
    }

    /// Creates a signed read-only `zv://` capability share (`ZVS1`) for `virtual_path`, flushing
    /// any pending local writes first and uploading the sealed descriptor to `shares/<aa>/<bb>/<uuid>.zvs`.
    pub async fn create_file_capability_share(
        &self,
        owner_id: &RecipientPrivateIdentity,
        backend_hint: &str,
        root_locator: &str,
        virtual_path: &str,
    ) -> ZeroVaultResult<(CapabilityUri, SignedShareEnvelope)> {
        self.ensure_unlocked()?;
        let mut rec = self.resolve_path(virtual_path).await?;
        if rec.kind != EntryKind::File {
            return Err(ZeroVaultError::IsADirectory(rec.inode));
        }

        if rec.hydration == HydrationState::DirtyLocal
            || self.cache.has_any_dirty_chunks(rec.inode).await?
        {
            self.flush(rec.inode).await?;
            rec = self.getattr(rec.inode).await?;
        }

        let wrapped_dek = rec.wrapped_dek.as_ref().ok_or_else(|| {
            ZeroVaultError::CryptoTamperDetected(format!(
                "missing wrapped DEK for shared inode {}",
                rec.inode
            ))
        })?;
        let file_dek = self.crypto.unwrap_dek(rec.file_id, wrapped_dek)?;
        let chunk_descs = self.meta.list_chunks(rec.inode).await?;
        let chunks: Vec<ChunkRef> = chunk_descs
            .into_iter()
            .map(|c| ChunkRef {
                chunk_index: c.chunk_index,
                blob_id: c.blob_id,
                plaintext_len: c.plaintext_len,
                ciphertext_len: c.ciphertext_len,
                blake3_plaintext: c.blake3_plaintext,
                backend_ids: c.backend_ids,
            })
            .collect();

        let descriptor = ShareDescriptor {
            share_id: Uuid::new_v4(),
            file_id: rec.file_id,
            filename: rec.name.clone(),
            size: rec.size,
            created_at: Utc::now(),
            wrapped_dek: wrapped_dek.clone(),
            chunks,
        };

        let (uri, envelope) = self.crypto.create_capability_share(
            owner_id,
            backend_hint,
            root_locator,
            &file_dek,
            &descriptor,
        )?;
        let wire_bytes = Bytes::from(envelope.encode()?);
        let share_key = ShareObjectKey::from_uuid(uri.share_id);
        let placement = self
            .storage
            .put_blob(&rec.virtual_path, share_key.as_str(), wire_bytes)
            .await?;
        self.stats.record_upload(placement.bytes_written as u64);

        Ok((uri, envelope))
    }

    /// Verifies and imports a `zv://` capability share URI into `dest_virtual_path` inside the local vault,
    /// streaming and AEAD-verifying every 4 MiB chunk in bounded RAM before sealing under the local vault's KEK.
    pub async fn import_capability_share(
        &self,
        uri: &str,
        dest_virtual_path: &str,
    ) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        let parsed_uri = CapabilityUri::parse(uri)?;
        let share_key = ShareObjectKey::from_uuid(parsed_uri.share_id);

        let (descriptor, shared_dek) = self
            .fetch_and_open_share_envelope(share_key.as_str(), &parsed_uri)
            .await?;
        if descriptor.share_id != parsed_uri.share_id {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "share descriptor share_id does not match capability URI".into(),
            ));
        }
        validate_entry_name(&descriptor.filename)?;

        let (parent_inode, target_name) = self
            .resolve_import_destination(dest_virtual_path, &descriptor.filename)
            .await?;

        let created = self
            .create_entry(CreateEntrySpec {
                parent_inode,
                name: target_name,
                mode: 0o644,
            })
            .await?;

        let mut ordered_chunks = descriptor.chunks.clone();
        ordered_chunks.sort_by_key(|c| c.chunk_index);

        let import_result: ZeroVaultResult<()> = async {
            let mut written_total = 0u64;
            for chunk_ref in &ordered_chunks {
                let blob_key = BlobObjectKey::from_uuid(chunk_ref.blob_id);
                let (pt_buf, wire_len) = fetch_and_decrypt_chunk(
                    self.storage.as_ref(),
                    self.crypto.as_ref(),
                    &self.pool,
                    &shared_dek,
                    descriptor.file_id,
                    chunk_ref.chunk_index,
                    chunk_ref.plaintext_len,
                    &chunk_ref.blake3_plaintext,
                    blob_key.as_str(),
                    &chunk_ref.backend_ids,
                )
                .await?;
                self.stats.record_download(wire_len as u64);

                let chunk_offset = chunk_ref
                    .chunk_index
                    .checked_mul(PLAINTEXT_CHUNK_SIZE as u64)
                    .ok_or(ZeroVaultError::InvalidRange {
                        offset: u64::MAX,
                        len: chunk_ref.plaintext_len as usize,
                        size: descriptor.size,
                    })?;

                if !pt_buf.is_empty() {
                    self.write_range(created.inode, chunk_offset, pt_buf.as_slice())
                        .await?;
                    written_total = written_total.saturating_add(pt_buf.len() as u64);
                }
            }

            if written_total != descriptor.size {
                return Err(ZeroVaultError::CryptoTamperDetected(format!(
                    "shared file size mismatch: descriptor={}, chunks_sum={written_total}",
                    descriptor.size
                )));
            }

            match self.flush(created.inode).await {
                Ok(()) => Ok(()),
                Err(ZeroVaultError::StorageConflict(_)) => {
                    match self
                        .fetch_and_open_manifest(MANIFEST_HEAD_OBJECT_KEY, &[])
                        .await
                    {
                        Ok(_) => self.sync_once().await.map(|_| ()),
                        Err(ZeroVaultError::CryptoTamperDetected(_)) => {
                            self.finalize_flushed_inode(created.inode).await?;
                            self.complete_inode_dirty_ops(created.inode).await
                        }
                        Err(err) => Err(err),
                    }
                }
                Err(err) => Err(err),
            }
        }
        .await;

        if let Err(err) = import_result {
            let _ = self.unlink(parent_inode, &created.name).await;
            return Err(err);
        }

        self.getattr(created.inode).await
    }

    /// Exports `virtual_path` to `local_dest_path` atomically in bounded 4 MiB chunks:
    /// 1. Rejects symlinks and NTFS reparse points / junctions (`symlink_metadata` + `FILE_ATTRIBUTE_REPARSE_POINT`).
    /// 2. Streams decrypted chunks to `<dest>.<uuid>.partial` created with `create_new(true)`.
    /// 3. Calls `flush()` and `sync_all()`, closes the handle, re-checks TOCTOU symlink absence,
    ///    and atomically renames `<dest>.<uuid>.partial` -> `<dest>`.
    pub async fn export_file_atomic(
        &self,
        virtual_path: &str,
        local_dest_path: impl AsRef<Path>,
    ) -> ZeroVaultResult<PathBuf> {
        self.ensure_unlocked()?;
        let rec = self.resolve_path(virtual_path).await?;
        if rec.kind != EntryKind::File {
            return Err(ZeroVaultError::IsADirectory(rec.inode));
        }

        let raw_dest = local_dest_path.as_ref();
        reject_if_existing_symlink_or_reparse(raw_dest)?;

        let dest_path = match std::fs::symlink_metadata(raw_dest) {
            Ok(meta) if meta.is_dir() => {
                validate_portable_entry_name(&rec.name, cfg!(target_os = "windows"))?;
                let joined = raw_dest.join(&rec.name);
                reject_if_existing_symlink_or_reparse(&joined)?;
                joined
            }
            Ok(_) | Err(_) => raw_dest.to_path_buf(),
        };

        ensure_safe_export_parent_dir(&dest_path).await?;
        reject_if_existing_symlink_or_reparse(&dest_path)?;

        let file_name = dest_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                ZeroVaultError::InvalidPath("invalid export destination filename".into())
            })?;
        if file_name.is_empty() || file_name == "." || file_name == ".." {
            return Err(ZeroVaultError::InvalidPath(
                "invalid export destination basename".into(),
            ));
        }

        let partial_name = format!("{file_name}.{}.partial", Uuid::new_v4().hyphenated());
        let partial_path = match dest_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(&partial_name),
            _ => PathBuf::from(&partial_name),
        };

        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut partial_file = opts.open(&partial_path).await?;

        let stream_res: ZeroVaultResult<()> = async {
            let mut offset = 0u64;
            while offset < rec.size {
                let step = ((rec.size - offset).min(PLAINTEXT_CHUNK_SIZE as u64)) as usize;
                let chunk = self.read_range(rec.inode, offset, step).await?;
                if chunk.is_empty() {
                    return Err(ZeroVaultError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while streaming vault file for export",
                    )));
                }
                partial_file.write_all(&chunk).await?;
                offset = offset.saturating_add(chunk.len() as u64);
            }
            partial_file.flush().await?;
            partial_file.sync_all().await?;
            Ok(())
        }
        .await;

        // Close handle BEFORE renaming or wiping (mandatory on Windows NTFS).
        drop(partial_file);

        if let Err(err) = stream_res {
            let _ = secure_wipe_and_remove_file(&partial_path).await;
            return Err(err);
        }

        if let Err(err) = verify_pre_rename_destination(&dest_path) {
            let _ = secure_wipe_and_remove_file(&partial_path).await;
            return Err(err);
        }

        if let Err(err) = fs::rename(&partial_path, &dest_path).await {
            let _ = secure_wipe_and_remove_file(&partial_path).await;
            return Err(err.into());
        }

        Ok(dest_path)
    }

    /// Synchronizes local state with remote cloud storage and reclaims `mimalloc` idle pages on completion.
    pub async fn sync_once(&self) -> ZeroVaultResult<SyncReport> {
        self.sync_once_with_options(None, None).await
    }

    /// Synchronizes local state with remote cloud storage with optional cooperative cancellation
    /// and live `(completed_ops, total_ops)` progress callbacks.
    pub async fn sync_once_with_options(
        &self,
        cancel_flag: Option<&AtomicBool>,
        progress_cb: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
    ) -> ZeroVaultResult<SyncReport> {
        let res = self.sync_once_inner(cancel_flag, progress_cb).await;
        if self.pool.in_use_slots() == 0 {
            self.pool.clear_idle_buffers();
        }
        reclaim_process_memory().await;
        res
    }

    async fn sync_once_inner(
        &self,
        cancel_flag: Option<&AtomicBool>,
        progress_cb: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
    ) -> ZeroVaultResult<SyncReport> {
        self.ensure_unlocked()?;

        let _sync_guard = self.sync_lock.lock().await;
        let mut report = SyncReport::default();

        // Phase 1: Pull remote manifest head if present, with mirror failover & rollback enforcement.
        let mut pull_err: Option<ZeroVaultError> = None;
        match self.storage.stat_object(MANIFEST_HEAD_OBJECT_KEY, &[]).await {
            Ok(Some(remote_ver)) => {
                let (local_rev, local_etag) = self.meta.manifest_cursor().await?;
                let should_pull = local_rev == 0
                    || remote_ver.etag.is_none()
                    || remote_ver.etag.as_deref() != local_etag.as_deref();

                if should_pull {
                    match self
                        .fetch_and_open_manifest(MANIFEST_HEAD_OBJECT_KEY, &[])
                        .await
                    {
                        Ok(manifest) => {
                            self.verify_manifest_rollback_and_lineage(&manifest, local_rev)
                                .await?;

                            let remote_changed = manifest.revision > local_rev
                                || (local_rev == 0 && !manifest.nodes.is_empty())
                                || (manifest.revision == local_rev
                                    && manifest.device_id != self.config.device_id
                                    && remote_ver.etag.as_deref() != local_etag.as_deref());

                            if remote_changed {
                                let summary = ConflictResolver::reconcile_remote_manifest(
                                    self.meta.as_ref(),
                                    self.crypto.as_ref(),
                                    self.storage.as_ref(),
                                    &self.pool,
                                    &self.cache,
                                    &self.config.device_id,
                                    &manifest,
                                    Utc::now(),
                                )
                                .await?;
                                report.applied_remote_nodes = summary.applied_remote_nodes;
                                report.pruned_local_nodes = summary.pruned_local_nodes;
                                report.conflicts_resolved = summary.conflicts_recorded;
                                self.refresh_committed_nodes_snapshot().await?;
                            }

                            let manifest_id = compute_manifest_id(&manifest)?;
                            self.meta
                                .advance_epoch_floor(EPOCH_SCOPE_MANIFEST, manifest.revision)
                                .await?;
                            self.meta.set_parent_manifest_id(Some(manifest_id)).await?;
                            self.meta
                                .update_manifest_cursor(manifest.revision, remote_ver.etag.clone())
                                .await?;
                            *self.last_manifest_id.lock() = Some(manifest_id);
                            report.pulled_revision = Some(manifest.revision);
                        }
                        Err(ZeroVaultError::StorageNotFound(_)) => {}
                        Err(err) => {
                            if is_fatal_sync_error(&err) {
                                return Err(err);
                            }
                            tracing::warn!("transient remote manifest fetch error during sync");
                            pull_err = Some(err);
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(err) => {
                if is_fatal_sync_error(&err) {
                    return Err(err);
                }
                tracing::warn!("transient remote manifest stat error during sync");
                pull_err = Some(err);
            }
        }

        // Phase 2: Replay queued dirty operations in bounded parallel batches with live checkpoints.
        const SYNC_BATCH_SIZE: usize = 64;
        let dirty_ops = self.meta.list_dirty_ops().await?;
        let total_dirty = dirty_ops.len();
        let completed_counter = AtomicUsize::new(0);
        let file_concurrency = (self.pool.max_slots() / 2).clamp(1, 8);
        let mut last_op_err: Option<ZeroVaultError> = None;
        let mut fatal_err: Option<ZeroVaultError> = None;
        let mut cancelled = false;

        if total_dirty > 0
            && let Some(cb) = progress_cb
        {
            cb(0, total_dirty);
        }

        type DirtyOpOutcome = Result<Option<(Option<InodeId>, i64)>, (i64, ZeroVaultError)>;

        for batch in dirty_ops.chunks(SYNC_BATCH_SIZE) {
            if cancel_flag.is_some_and(|f| f.load(Ordering::Acquire)) {
                cancelled = true;
                break;
            }

            let outcomes: Vec<DirtyOpOutcome> =
                stream::iter(batch.iter().cloned())
                    .map(|op| {
                        let completed_ref = &completed_counter;
                        async move {
                            if cancel_flag.is_some_and(|f| f.load(Ordering::Acquire)) {
                                return Err((
                                    op.id,
                                    ZeroVaultError::Io(std::io::Error::new(
                                        std::io::ErrorKind::Interrupted,
                                        "backup cancelled by user",
                                    )),
                                ));
                            }
                            let res = match op.kind {
                                DirtyOpKind::UpsertFile => {
                                    let inode_lock = self.inode_lock(op.inode);
                                    let _inode_guard = inode_lock.lock().await;
                                    match self.meta.get_inode(op.inode).await {
                                        Ok(None) => {
                                            let _ = self.meta.complete_dirty_op(op.id).await;
                                            Ok(None)
                                        }
                                        Ok(Some(_)) => match self.upload_dirty_inode_blobs(op.inode).await {
                                            Ok(()) => Ok(Some((Some(op.inode), op.id))),
                                            Err(err) => Err((op.id, err)),
                                        },
                                        Err(err) => Err((op.id, err)),
                                    }
                                }
                                DirtyOpKind::UpsertMetadata | DirtyOpKind::Delete => {
                                    Ok(Some((None, op.id)))
                                }
                            };
                            let done = completed_ref.fetch_add(1, Ordering::AcqRel) + 1;
                            if let Some(cb) = progress_cb {
                                cb(done.min(total_dirty), total_dirty);
                            }
                            res
                        }
                    })
                    .buffer_unordered(file_concurrency)
                    .collect()
                    .await;

            let mut staged_finalize: Vec<(Option<InodeId>, i64)> = Vec::with_capacity(outcomes.len());
            for item in outcomes {
                match item {
                    Ok(Some(pair)) => staged_finalize.push(pair),
                    Ok(None) => {}
                    Err((_, err))
                        if matches!(
                            &err,
                            ZeroVaultError::Io(io_e) if io_e.kind() == std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        cancelled = true;
                    }
                    Err((op_id, err)) => {
                        if is_fatal_sync_error(&err) && fatal_err.is_none() {
                            fatal_err = Some(err);
                        } else {
                            let _ = self.meta.mark_dirty_retry(op_id, &err.to_string()).await;
                            report.failed_dirty_ops += 1;
                            last_op_err = Some(err);
                        }
                    }
                }
            }

            if let Some(err) = fatal_err {
                return Err(err);
            }

            // Phase 3 (per-batch checkpoint): Publish updated manifest snapshot and run Orphan `.zv` Blob GC (`NEW-L03`).
            if !staged_finalize.is_empty() {
                let uploaded_inodes: Vec<InodeId> = staged_finalize
                    .iter()
                    .filter_map(|(maybe_ino, _)| *maybe_ino)
                    .collect();
                match self.publish_manifest_locked(&uploaded_inodes).await {
                    Ok((new_rev, gc_count)) => {
                        report.published_revision = Some(new_rev);
                        report.gc_deleted_blobs = report.gc_deleted_blobs.saturating_add(gc_count);
                        for (maybe_inode, op_id) in staged_finalize {
                            if let Some(inode) = maybe_inode {
                                self.finalize_flushed_inode(inode).await?;
                            }
                            self.meta.complete_dirty_op(op_id).await?;
                            report.replayed_dirty_ops += 1;
                        }
                    }
                    Err(err) => {
                        if is_fatal_sync_error(&err) {
                            return Err(err);
                        }
                        let err_str = err.to_string();
                        for (_, op_id) in staged_finalize {
                            self.meta.mark_dirty_retry(op_id, &err_str).await?;
                        }
                        return Err(err);
                    }
                }
            }

            if cancelled {
                break;
            }
        }

        if cancelled {
            return Err(ZeroVaultError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "backup cancelled by user",
            )));
        }

        if let Some(err) = last_op_err {
            return Err(err);
        }
        if let Some(err) = pull_err {
            return Err(err);
        }

        Ok(report)
    }

    /// Downloads and AEAD-verifies a sealed [`VaultManifest`] (`ZVM1`), automatically failing over
    /// across candidate mirror backends when a replica returns corrupted bytes (`NEW-M02`).
    pub async fn fetch_and_open_manifest(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<VaultManifest> {
        let mut tamper_failure: Option<ZeroVaultError> = None;
        let mut transport_failure: Option<ZeroVaultError> = None;

        match self.storage.get_blob(object_key, preferred_backends).await {
            Ok(sealed) => match self.open_and_check_manifest_vault(&sealed) {
                Ok(manifest) => {
                    self.stats.record_download(sealed.len() as u64);
                    return Ok(manifest);
                }
                Err(err)
                    if matches!(
                        err,
                        ZeroVaultError::CryptoTamperDetected(_)
                            | ZeroVaultError::InvalidWireFormat(_)
                    ) =>
                {
                    tracing::warn!(
                        object_key,
                        "primary replica failed manifest verification; trying mirror replicas"
                    );
                    tamper_failure = Some(err);
                }
                Err(err) => return Err(err),
            },
            Err(err) => {
                if is_fatal_sync_error(&err) {
                    return Err(err);
                }
                transport_failure = Some(err);
            }
        }

        for backend_id in self.storage.candidate_backends(preferred_backends) {
            match self
                .storage
                .get_blob_from_backend(&backend_id, object_key)
                .await
            {
                Ok(alt_sealed) => match self.open_and_check_manifest_vault(&alt_sealed) {
                    Ok(manifest) => {
                        self.stats.record_download(alt_sealed.len() as u64);
                        return Ok(manifest);
                    }
                    Err(err)
                        if matches!(
                            err,
                            ZeroVaultError::CryptoTamperDetected(_)
                                | ZeroVaultError::InvalidWireFormat(_)
                        ) =>
                    {
                        tamper_failure = Some(err);
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => {
                    if transport_failure.is_none() {
                        transport_failure = Some(err);
                    }
                }
            }
        }

        if let Some(err) = tamper_failure {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "all mirror replicas failed manifest verification for {object_key}: {err}"
            )));
        }
        Err(transport_failure
            .unwrap_or_else(|| ZeroVaultError::StorageNotFound(object_key.to_owned())))
    }

    fn open_and_check_manifest_vault(&self, sealed: &[u8]) -> ZeroVaultResult<VaultManifest> {
        let manifest = self.crypto.open_manifest(sealed)?;
        if let Some(expected_vault_id) = self.crypto.vault_id()
            && manifest.vault_id != expected_vault_id
        {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "remote manifest vault_id mismatch".into(),
            ));
        }
        Ok(manifest)
    }

    async fn verify_manifest_rollback_and_lineage(
        &self,
        manifest: &VaultManifest,
        local_rev: u64,
    ) -> ZeroVaultResult<()> {
        let floor = self.meta.epoch_floor(EPOCH_SCOPE_MANIFEST).await?;
        let min_required = floor.max(local_rev);
        if min_required > 0 && manifest.revision < min_required {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "remote manifest revision rollback detected: floor={min_required}, remote={}",
                manifest.revision
            )));
        }

        if manifest.revision == 1 && manifest.parent_manifest_id.is_some() {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "revision 1 manifest must not carry a parent_manifest_id".into(),
            ));
        }
        if manifest.revision > 1 && manifest.parent_manifest_id.is_none() {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "manifest revision {} missing mandatory parent_manifest_id",
                manifest.revision
            )));
        }

        let local_anchor = self.meta.parent_manifest_id().await?;
        if local_rev > 0
            && let Some(expected_anchor) = local_anchor
        {
            if manifest.revision == local_rev {
                let candidate_id = compute_manifest_id(manifest)?;
                if candidate_id != expected_anchor {
                    return Err(ZeroVaultError::CryptoTamperDetected(
                        "remote manifest fork detected at identical revision".into(),
                    ));
                }
            } else if manifest.revision == local_rev + 1 {
                if manifest.parent_manifest_id != Some(expected_anchor) {
                    return Err(ZeroVaultError::CryptoTamperDetected(format!(
                        "manifest parent_manifest_id mismatch at revision {}: expected {expected_anchor}, got {:?}",
                        manifest.revision, manifest.parent_manifest_id
                    )));
                }
            } else if manifest.revision > local_rev + 1 {
                // Walk historical manifest snapshots back to `local_rev` if retained in storage.
                let mut cur_rev = manifest.revision;
                let mut next_parent = manifest.parent_manifest_id;
                let mut hops = 0usize;

                while let Some(pid) = next_parent {
                    if hops >= MAX_MANIFEST_ANCESTOR_HOPS {
                        break;
                    }
                    hops += 1;

                    let snap_key = ManifestObjectKey::from_uuid(pid);
                    let anc = match self.fetch_and_open_manifest(snap_key.as_str(), &[]).await {
                        Ok(m) => m,
                        Err(ZeroVaultError::StorageNotFound(_)) => break,
                        Err(err) => return Err(err),
                    };

                    let computed_anc_id = compute_manifest_id(&anc)?;
                    if computed_anc_id != pid || anc.revision >= cur_rev {
                        return Err(ZeroVaultError::CryptoTamperDetected(
                            "manifest historical snapshot lineage tampered".into(),
                        ));
                    }

                    if anc.revision == local_rev {
                        if pid != expected_anchor {
                            return Err(ZeroVaultError::CryptoTamperDetected(
                                "manifest ancestor does not chain to local cursor anchor".into(),
                            ));
                        }
                        break;
                    }
                    if anc.revision < local_rev {
                        return Err(ZeroVaultError::CryptoTamperDetected(
                            "manifest ancestor skipped local cursor revision".into(),
                        ));
                    }

                    cur_rev = anc.revision;
                    next_parent = anc.parent_manifest_id;
                }
            }
        }

        Ok(())
    }

    async fn fetch_and_open_share_envelope(
        &self,
        share_key: &str,
        uri: &CapabilityUri,
    ) -> ZeroVaultResult<(ShareDescriptor, DekBytes)> {
        let preferred = if uri.backend_hint.is_empty() {
            Vec::new()
        } else {
            vec![uri.backend_hint.clone()]
        };

        let mut tamper_err: Option<ZeroVaultError> = None;
        let mut transport_err: Option<ZeroVaultError> = None;

        let primary = match self.storage.get_blob(share_key, &preferred).await {
            Ok(b) => Ok(b),
            Err(_) if !preferred.is_empty() => self.storage.get_blob(share_key, &[]).await,
            Err(e) => Err(e),
        };

        match primary {
            Ok(raw) => match SignedShareEnvelope::decode(&raw)
                .and_then(|env| self.crypto.open_capability_share(uri, &env))
            {
                Ok(opened) => {
                    self.stats.record_download(raw.len() as u64);
                    return Ok(opened);
                }
                Err(err) => tamper_err = Some(err),
            },
            Err(err) => transport_err = Some(err),
        }

        for backend_id in self.storage.candidate_backends(&[]) {
            if let Ok(alt_raw) = self
                .storage
                .get_blob_from_backend(&backend_id, share_key)
                .await
            {
                match SignedShareEnvelope::decode(&alt_raw)
                    .and_then(|env| self.crypto.open_capability_share(uri, &env))
                {
                    Ok(opened) => {
                        self.stats.record_download(alt_raw.len() as u64);
                        return Ok(opened);
                    }
                    Err(err) => tamper_err = Some(err),
                }
            }
        }

        if let Some(err) = tamper_err {
            return Err(err);
        }
        Err(transport_err.unwrap_or_else(|| ZeroVaultError::StorageNotFound(share_key.to_owned())))
    }

    async fn resolve_import_destination(
        &self,
        dest_virtual_path: &str,
        default_filename: &str,
    ) -> ZeroVaultResult<(InodeId, String)> {
        let norm = normalize_virtual_path(dest_virtual_path)?;
        if norm == "/" {
            return Ok((ROOT_INODE, default_filename.to_owned()));
        }

        if let Some(existing) = self.meta.get_by_path(&norm).await? {
            if existing.kind == EntryKind::Directory {
                return Ok((existing.inode, default_filename.to_owned()));
            }
            return Err(ZeroVaultError::AlreadyExists(norm));
        }

        let (parent_vpath, leaf_name) = match norm.rfind('/') {
            Some(0) => ("/".to_owned(), norm[1..].to_owned()),
            Some(idx) => (norm[..idx].to_owned(), norm[idx + 1..].to_owned()),
            None => ("/".to_owned(), norm),
        };
        validate_entry_name(&leaf_name)?;

        let parent_inode = self.ensure_virtual_dir_chain(&parent_vpath).await?;
        Ok((parent_inode, leaf_name))
    }

    async fn ensure_virtual_dir_chain(&self, dir_vpath: &str) -> ZeroVaultResult<InodeId> {
        if dir_vpath == "/" {
            return Ok(ROOT_INODE);
        }
        let mut cur_inode = ROOT_INODE;
        for seg in dir_vpath.trim_start_matches('/').split('/') {
            if seg.is_empty() {
                continue;
            }
            if let Some(child) = self.meta.lookup_child(cur_inode, seg).await? {
                if child.kind != EntryKind::Directory {
                    return Err(ZeroVaultError::NotADirectory(child.inode));
                }
                cur_inode = child.inode;
            } else {
                let created = self.mkdir(cur_inode, seg, 0o755).await?;
                cur_inode = created.inode;
            }
        }
        Ok(cur_inode)
    }

    fn inode_lock(&self, inode: InodeId) -> Arc<AsyncMutex<()>> {
        self.inode_locks
            .entry(inode)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    fn record_gc_candidates(&self, chunks: impl IntoIterator<Item = (Uuid, Vec<BackendId>)>) {
        let mut guard = self.pending_gc_blobs.lock();
        for (blob_id, backends) in chunks {
            guard.entry(blob_id).or_insert(backends);
        }
    }

    async fn hydrate_single_chunk(
        &self,
        rec: &InodeRecord,
        dek: &DekBytes,
        desc: &ChunkDescriptor,
    ) -> ZeroVaultResult<Arc<Zeroizing<Vec<u8>>>> {
        if let Some(cached) = self.cache.get(rec.file_id, desc.chunk_index) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }

        let blob_key = BlobObjectKey::from_uuid(desc.blob_id);
        let (pt_buf, wire_len) = fetch_and_decrypt_chunk(
            self.storage.as_ref(),
            self.crypto.as_ref(),
            &self.pool,
            dek,
            rec.file_id,
            desc.chunk_index,
            desc.plaintext_len,
            &desc.blake3_plaintext,
            blob_key.as_str(),
            &desc.backend_ids,
        )
        .await?;

        let pt_zero = Arc::new(Zeroizing::new(pt_buf.to_vec()));
        drop(pt_buf);

        self.cache
            .insert_zeroizing(rec.file_id, desc.chunk_index, Arc::clone(&pt_zero));
        self.meta
            .set_chunk_hydrated(rec.inode, desc.chunk_index, true)
            .await?;
        self.stats.chunks_hydrated.fetch_add(1, Ordering::Relaxed);
        self.stats.record_download(wire_len as u64);

        Ok(pt_zero)
    }

    async fn ensure_chunk_staged_for_partial_edit(
        &self,
        rec: &InodeRecord,
        existing_chunks: &[ChunkDescriptor],
        chunk_index: u64,
    ) -> ZeroVaultResult<()> {
        if self.cache.has_dirty_chunk(rec.inode, chunk_index).await {
            return Ok(());
        }
        let Some(desc) = existing_chunks.iter().find(|c| c.chunk_index == chunk_index) else {
            return Ok(());
        };
        let chunk_bytes = if let Some(cached) = self.cache.get(rec.file_id, chunk_index) {
            cached
        } else {
            let wrapped = rec.wrapped_dek.as_ref().ok_or_else(|| {
                ZeroVaultError::CryptoTamperDetected(format!(
                    "missing wrapped DEK for committed inode {}",
                    rec.inode
                ))
            })?;
            let dek = self.crypto.unwrap_dek(rec.file_id, wrapped)?;
            self.hydrate_single_chunk(rec, &dek, desc).await?
        };
        self.cache
            .write_full_dirty_chunk(rec.inode, chunk_index, &chunk_bytes)
            .await
    }

    async fn ensure_dirty_op_queued(
        &self,
        inode: InodeId,
        kind: DirtyOpKind,
        virtual_path: &str,
    ) -> ZeroVaultResult<()> {
        let ops = self.meta.list_dirty_ops().await?;
        let already_queued = ops.iter().any(|op| {
            op.inode == inode
                && (op.kind == kind
                    || (kind == DirtyOpKind::UpsertMetadata && op.kind == DirtyOpKind::UpsertFile))
        });
        if !already_queued {
            self.meta.enqueue_dirty(inode, kind, virtual_path).await?;
        }
        Ok(())
    }

    async fn upload_dirty_inode_blobs(&self, inode: InodeId) -> ZeroVaultResult<()> {
        if !self.crypto.is_unlocked() {
            return Err(ZeroVaultError::VaultLocked);
        }

        let mut rec = self
            .meta
            .get_inode(inode)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(inode))?;

        if rec.kind == EntryKind::Directory {
            return Ok(());
        }

        let has_dirty_parts = self.cache.has_any_dirty_chunks(inode).await?;
        if rec.hydration != HydrationState::DirtyLocal && !has_dirty_parts {
            return Ok(());
        }

        let (dek, wrapped_dek, reusing_dek) = match &rec.wrapped_dek {
            Some(existing) => (
                self.crypto.unwrap_dek(rec.file_id, existing)?,
                existing.clone(),
                true,
            ),
            None => {
                let fresh = self.crypto.generate_dek()?;
                let wrapped = self.crypto.wrap_dek(rec.file_id, &fresh)?;
                (fresh, wrapped, false)
            }
        };
        let dek = Arc::new(dek);

        let old_chunks = self.meta.list_chunks(inode).await?;
        let old_count = old_chunks.len() as u64;
        let old_by_idx: Arc<HashMap<u64, ChunkDescriptor>> = Arc::new(
            old_chunks
                .into_iter()
                .map(|c| (c.chunk_index, c))
                .collect(),
        );

        let num_chunks = if rec.size == 0 {
            1
        } else {
            rec.size.div_ceil(PLAINTEXT_CHUNK_SIZE as u64)
        };
        let concurrency = (self.pool.max_slots() / 2).max(1);
        let rec_snapshot = Arc::new(rec.clone());

        let mut descriptors: Vec<ChunkDescriptor> = stream::iter(0..num_chunks)
            .map(|chunk_index| {
                let is_final_chunk = chunk_index == num_chunks - 1;
                let expected_len = expected_chunk_plaintext_len(rec_snapshot.size, chunk_index);
                let dek = Arc::clone(&dek);
                let old_by_idx = Arc::clone(&old_by_idx);
                let rec_snapshot = Arc::clone(&rec_snapshot);

                async move {
                    let has_dirty_part = self.cache.has_dirty_chunk(inode, chunk_index).await;
                    if !has_dirty_part
                        && reusing_dek
                        && let Some(old_desc) = old_by_idx.get(&chunk_index)
                    {
                        let old_was_final = chunk_index + 1 == old_count;
                        if old_desc.plaintext_len as usize == expected_len
                            && old_was_final == is_final_chunk
                        {
                            return Ok::<ChunkDescriptor, ZeroVaultError>(old_desc.clone());
                        }
                    }

                    // Hydrate existing chunk (if needed) BEFORE acquiring the dual-buffer pair
                    // so `hydrate_single_chunk` cannot contend for a third pool slot.
                    let old_bytes = if !has_dirty_part {
                        if let Some(old_desc) = old_by_idx.get(&chunk_index) {
                            Some(
                                self.hydrate_single_chunk(&rec_snapshot, &dek, old_desc)
                                    .await?,
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let mut pair = self.pool.acquire_pair().await?;
                    if self
                        .cache
                        .read_dirty_chunk_into(inode, chunk_index, &mut pair.pt)
                        .await?
                        .is_some()
                    {
                        pair.pt.resize(expected_len, 0);
                    } else if let Some(ref prev) = old_bytes {
                        pair.pt.clear();
                        pair.pt.extend_from_slice(prev);
                        pair.pt.resize(expected_len, 0);
                    } else {
                        pair.pt.clear();
                        pair.pt.resize(expected_len, 0);
                    }

                    let blake3_hash = *blake3::hash(&pair.pt).as_bytes();
                    self.cache.insert_zeroizing(
                        rec_snapshot.file_id,
                        chunk_index,
                        Arc::new(Zeroizing::new(pair.pt.to_vec())),
                    );

                    let aad = ChunkAad {
                        file_id: rec_snapshot.file_id,
                        chunk_index,
                        is_final_chunk,
                    };
                    let hdr =
                        self.crypto
                            .encrypt_chunk_into(&dek, aad, &pair.pt, &mut pair.wire)?;
                    let wire_bytes = Bytes::copy_from_slice(&pair.wire);
                    drop(pair);

                    let blob_id = Uuid::new_v4();
                    let blob_key = BlobObjectKey::from_uuid(blob_id);

                    let placement = self
                        .storage
                        .put_blob(&rec_snapshot.virtual_path, blob_key.as_str(), wire_bytes)
                        .await?;
                    self.stats.record_upload(placement.bytes_written as u64);

                    Ok(ChunkDescriptor {
                        inode,
                        file_id: rec_snapshot.file_id,
                        chunk_index,
                        blob_id,
                        plaintext_len: hdr.plaintext_len,
                        ciphertext_len: placement.bytes_written as u32,
                        blake3_plaintext: blake3_hash,
                        backend_ids: placement
                            .replicas
                            .into_iter()
                            .map(|r| r.backend_id)
                            .collect(),
                        locally_hydrated: true,
                    })
                }
            })
            .buffer_unordered(concurrency)
            .try_collect()
            .await?;

        descriptors.sort_by_key(|d| d.chunk_index);

        let kept_blobs: HashSet<Uuid> = descriptors.iter().map(|d| d.blob_id).collect();
        let superseded = old_by_idx
            .values()
            .filter(|old| !kept_blobs.contains(&old.blob_id))
            .map(|old| (old.blob_id, old.backend_ids.clone()))
            .collect::<Vec<_>>();
        self.record_gc_candidates(superseded);

        rec.wrapped_dek = Some(wrapped_dek);
        self.meta.replace_chunks(inode, descriptors).await?;
        self.meta.upsert_inode(rec).await?;
        Ok(())
    }

    async fn finalize_flushed_inode(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.cache.clear_dirty_inode(inode).await?;
        if let Some(mut rec) = self.meta.get_inode(inode).await?
            && rec.hydration == HydrationState::DirtyLocal
        {
            rec.hydration = if rec.pinned {
                HydrationState::Pinned
            } else {
                HydrationState::LocallyCached
            };
            self.meta.upsert_inode(rec).await?;
        }
        Ok(())
    }

    async fn refresh_committed_nodes_snapshot(&self) -> ZeroVaultResult<()> {
        let all_inodes = self.meta.list_all_inodes().await?;
        let mut next_map = HashMap::new();
        for rec in all_inodes {
            if rec.inode == ROOT_INODE || rec.hydration == HydrationState::DirtyLocal {
                continue;
            }
            if let Some(node) = self.build_manifest_node(&rec).await? {
                next_map.insert(rec.inode, node);
            }
        }
        *self.committed_nodes.lock() = next_map;
        Ok(())
    }

    async fn build_manifest_node(&self, rec: &InodeRecord) -> ZeroVaultResult<Option<ManifestNode>> {
        let chunks = if rec.kind == EntryKind::File {
            let list = self.meta.list_chunks(rec.inode).await?;
            if rec.size > 0 && list.is_empty() {
                return Ok(None);
            }
            list.into_iter()
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

        Ok(Some(ManifestNode {
            inode: rec.inode,
            parent_inode: rec.parent_inode,
            file_id: rec.file_id,
            name: rec.name.clone(),
            kind: rec.kind,
            size: rec.size,
            mode: rec.mode,
            modified_at: rec.modified_at,
            created_at: rec.created_at,
            version: rec.version,
            wrapped_dek: rec.wrapped_dek.clone(),
            chunks,
        }))
    }

    async fn publish_manifest_locked(
        &self,
        just_uploaded: &[InodeId],
    ) -> ZeroVaultResult<(u64, usize)> {
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let (cur_rev, cur_etag) = self.meta.manifest_cursor().await?;
        let floor = self.meta.epoch_floor(EPOCH_SCOPE_MANIFEST).await?;

        if cur_etag.is_none()
            && self
                .storage
                .stat_object(MANIFEST_HEAD_OBJECT_KEY, &[])
                .await?
                .is_some()
        {
            return Err(ZeroVaultError::StorageConflict(
                "remote manifest head already exists; sync required before publish".into(),
            ));
        }

        let uploaded_set: HashSet<InodeId> = just_uploaded.iter().copied().collect();
        let base_rev = cur_rev.max(floor);
        let next_rev = base_rev.saturating_add(1);
        let all_inodes = self.meta.list_all_inodes().await?;
        let mut nodes = Vec::with_capacity(all_inodes.len());
        let mut next_committed = HashMap::with_capacity(all_inodes.len());
        let mut uncommitted_live_blobs: HashSet<Uuid> = HashSet::new();

        let prev_committed = self.committed_nodes.lock().clone();

        for rec in all_inodes {
            if rec.inode == ROOT_INODE {
                continue;
            }
            let is_ready = uploaded_set.contains(&rec.inode)
                || rec.hydration != HydrationState::DirtyLocal
                || rec.kind == EntryKind::Directory;

            if is_ready {
                if let Some(node) = self.build_manifest_node(&rec).await? {
                    next_committed.insert(rec.inode, node.clone());
                    nodes.push(node);
                }
            } else {
                if rec.kind == EntryKind::File {
                    for ch in self.meta.list_chunks(rec.inode).await? {
                        uncommitted_live_blobs.insert(ch.blob_id);
                    }
                }
                if let Some(prev_node) = prev_committed.get(&rec.inode).cloned() {
                    next_committed.insert(rec.inode, prev_node.clone());
                    nodes.push(prev_node);
                }
            }
        }

        let persisted_parent = self.meta.parent_manifest_id().await?;
        let parent_manifest_id = if next_rev == 1 {
            None
        } else {
            persisted_parent.or_else(|| *self.last_manifest_id.lock())
        };

        let manifest = VaultManifest {
            vault_id,
            revision: next_rev,
            parent_manifest_id,
            device_id: self.config.device_id.clone(),
            created_at: Utc::now(),
            nodes,
        };

        let snapshot_id = compute_manifest_id(&manifest)?;
        let sealed = self.crypto.seal_manifest(&manifest)?;
        let snapshot_key = ManifestObjectKey::from_uuid(snapshot_id);
        let snap_ver = self
            .storage
            .put_manifest_cas(snapshot_key.as_str(), sealed.clone(), None)
            .await?;
        self.stats.record_upload(snap_ver.content_length);

        let head_ver = match self
            .storage
            .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed.clone(), cur_etag.as_deref())
            .await
        {
            Ok(ver) => ver,
            Err(ZeroVaultError::StorageConflict(conflict_msg)) => {
                // Self-heal stale local ETag (e.g. after daemon restart on a synthetic-ETag
                // backend or upgrading from an older version) when the remote head has no
                // newer revision than our local cursor.
                let refreshed_etag = if let Ok(Some(remote_ver)) = self
                    .storage
                    .stat_object(MANIFEST_HEAD_OBJECT_KEY, &[])
                    .await
                    && remote_ver.etag.as_deref() != cur_etag.as_deref()
                    && let Ok(remote_manifest) = self
                        .fetch_and_open_manifest(MANIFEST_HEAD_OBJECT_KEY, &[])
                        .await
                    && remote_manifest.vault_id == vault_id
                    && self
                        .verify_manifest_rollback_and_lineage(&remote_manifest, cur_rev)
                        .await
                        .is_ok()
                    && remote_manifest.revision <= cur_rev
                {
                    tracing::info!(
                        cur_rev,
                        remote_rev = remote_manifest.revision,
                        "recovering from stale manifest ETag during publish"
                    );
                    Some(remote_ver.etag)
                } else {
                    None
                };

                if let Some(fresh_etag) = refreshed_etag {
                    self.storage
                        .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed, fresh_etag.as_deref())
                        .await?
                } else {
                    return Err(ZeroVaultError::StorageConflict(conflict_msg));
                }
            }
            Err(err) => return Err(err),
        };
        self.stats.record_upload(head_ver.content_length);

        self.meta
            .advance_epoch_floor(EPOCH_SCOPE_MANIFEST, next_rev)
            .await?;
        self.meta.set_parent_manifest_id(Some(snapshot_id)).await?;
        self.meta
            .update_manifest_cursor(next_rev, head_ver.etag)
            .await?;
        *self.last_manifest_id.lock() = Some(snapshot_id);

        // Orphan `.zv` Blob GC (`NEW-L03`): collect superseded blobs from `prev_committed` + `pending_gc_blobs`.
        let mut referenced_blobs: HashSet<Uuid> = uncommitted_live_blobs;
        for node in &manifest.nodes {
            for ch in &node.chunks {
                referenced_blobs.insert(ch.blob_id);
            }
        }

        let prev_superseded: Vec<(Uuid, Vec<BackendId>)> = prev_committed
            .values()
            .flat_map(|n| n.chunks.iter())
            .filter(|ch| !referenced_blobs.contains(&ch.blob_id))
            .map(|ch| (ch.blob_id, ch.backend_ids.clone()))
            .collect();
        self.record_gc_candidates(prev_superseded);

        *self.committed_nodes.lock() = next_committed;

        let gc_deleted = self.gc_orphan_blobs(&referenced_blobs).await;
        Ok((next_rev, gc_deleted))
    }

    async fn gc_orphan_blobs(&self, referenced_blobs: &HashSet<Uuid>) -> usize {
        let candidates: Vec<(Uuid, Vec<BackendId>)> = {
            let mut guard = self.pending_gc_blobs.lock();
            guard.retain(|blob_id, _| !referenced_blobs.contains(blob_id));
            guard
                .iter()
                .map(|(id, backends)| (*id, backends.clone()))
                .collect()
        };

        let mut deleted_count = 0usize;
        for (blob_id, backends) in candidates {
            let blob_key = BlobObjectKey::from_uuid(blob_id);
            match self.storage.delete_blob(blob_key.as_str(), &backends).await {
                Ok(()) | Err(ZeroVaultError::StorageNotFound(_)) => {
                    self.pending_gc_blobs.lock().remove(&blob_id);
                    deleted_count += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        blob_key = blob_key.as_str(),
                        error = %err,
                        "deferred orphan .zv blob deletion due to transient storage error"
                    );
                }
            }
        }
        deleted_count
    }

    async fn mark_inode_dirty_retry(&self, inode: InodeId, error: &str) {
        if let Ok(ops) = self.meta.list_dirty_ops().await {
            for op in ops {
                if op.inode == inode {
                    let _ = self.meta.mark_dirty_retry(op.id, error).await;
                }
            }
        }
    }

    async fn complete_inode_dirty_ops(&self, inode: InodeId) -> ZeroVaultResult<()> {
        for op in self.meta.list_dirty_ops().await? {
            if op.inode == inode {
                self.meta.complete_dirty_op(op.id).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl VfsBackend for SyncEngine {
    async fn getattr(&self, inode: InodeId) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        self.meta
            .get_inode(inode)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(inode))
    }

    async fn lookup(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        validate_entry_name(name)?;
        let parent = self.getattr(parent_inode).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(parent_inode));
        }
        self.meta
            .lookup_child(parent_inode, name)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(parent_inode))
    }

    async fn resolve_path(&self, virtual_path: &str) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        let norm = normalize_virtual_path(virtual_path)?;
        self.meta
            .get_by_path(&norm)
            .await?
            .ok_or_else(|| ZeroVaultError::InvalidPath(format!("path not found: {norm}")))
    }

    async fn readdir(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.ensure_unlocked()?;
        let parent = self.getattr(parent_inode).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(parent_inode));
        }
        self.meta.list_children(parent_inode).await
    }

    async fn read_range(&self, inode: InodeId, offset: u64, len: usize) -> ZeroVaultResult<Bytes> {
        self.ensure_unlocked()?;
        let rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(inode));
        }
        let Some(span) = chunk_span_for_range(offset, len, rec.size)? else {
            return Ok(Bytes::new());
        };

        let chunks = self.meta.list_chunks(inode).await?;
        let chunks_map: HashMap<u64, &ChunkDescriptor> =
            chunks.iter().map(|c| (c.chunk_index, c)).collect();
        let mut cached_dek: Option<DekBytes> = None;
        let mut out = BytesMut::with_capacity(span.readable_len);

        for slice in span.slices {
            let expected_chunk_len = expected_chunk_plaintext_len(rec.size, slice.chunk_index);
            if self.cache.has_dirty_chunk(inode, slice.chunk_index).await {
                let mut pt_buf = self.pool.acquire_buffer().await?;
                if self
                    .cache
                    .read_dirty_chunk_into(inode, slice.chunk_index, &mut pt_buf)
                    .await?
                    .is_some()
                {
                    if pt_buf.len() < expected_chunk_len {
                        pt_buf.resize(expected_chunk_len, 0);
                    }
                    let slice_end = slice.in_chunk_offset + slice.len;
                    if slice_end > pt_buf.len() {
                        return Err(ZeroVaultError::InvalidRange {
                            offset,
                            len,
                            size: rec.size,
                        });
                    }
                    out.extend_from_slice(&pt_buf[slice.in_chunk_offset..slice_end]);
                    continue;
                }
            }

            if let Some(cached) = self.cache.get(rec.file_id, slice.chunk_index) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                let slice_end = slice.in_chunk_offset + slice.len;
                if slice_end > cached.len() {
                    return Err(ZeroVaultError::InvalidWireFormat(
                        "cached chunk shorter than requested slice".into(),
                    ));
                }
                out.extend_from_slice(&cached[slice.in_chunk_offset..slice_end]);
                continue;
            }

            if let Some(desc) = chunks_map.get(&slice.chunk_index) {
                if cached_dek.is_none() {
                    let wrapped = rec.wrapped_dek.as_ref().ok_or_else(|| {
                        ZeroVaultError::CryptoTamperDetected(format!(
                            "missing wrapped DEK for inode {inode}"
                        ))
                    })?;
                    cached_dek = Some(self.crypto.unwrap_dek(rec.file_id, wrapped)?);
                }
                let dek = cached_dek
                    .as_ref()
                    .ok_or_else(|| ZeroVaultError::CryptoTamperDetected("DEK unavailable".into()))?;
                let chunk_bytes = self.hydrate_single_chunk(&rec, dek, desc).await?;
                let slice_end = slice.in_chunk_offset + slice.len;
                if slice_end > chunk_bytes.len() {
                    return Err(ZeroVaultError::CryptoTamperDetected(
                        "decrypted chunk shorter than manifest span".into(),
                    ));
                }
                out.extend_from_slice(&chunk_bytes[slice.in_chunk_offset..slice_end]);
            } else if rec.hydration == HydrationState::DirtyLocal {
                out.resize(out.len() + slice.len, 0);
            } else {
                return Err(ZeroVaultError::MetadataError(format!(
                    "missing chunk descriptor {} for inode {inode}",
                    slice.chunk_index
                )));
            }
        }

        self.stats
            .bytes_read
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(out.freeze())
    }

    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize> {
        self.ensure_unlocked()?;
        let inode_lock = self.inode_lock(inode);
        let _inode_guard = inode_lock.lock().await;

        let mut rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(inode));
        }
        let end_offset = offset
            .checked_add(data.len() as u64)
            .ok_or(ZeroVaultError::InvalidRange {
                offset,
                len: data.len(),
                size: rec.size,
            })?;

        if data.is_empty() {
            return Ok(0);
        }

        let existing_chunks = self.meta.list_chunks(inode).await?;
        let mut remaining = data;
        let mut cur_offset = offset;

        while !remaining.is_empty() {
            let chunk_index = cur_offset / (PLAINTEXT_CHUNK_SIZE as u64);
            let in_chunk_offset = (cur_offset % (PLAINTEXT_CHUNK_SIZE as u64)) as usize;
            let avail_in_chunk = PLAINTEXT_CHUNK_SIZE - in_chunk_offset;
            let write_len = remaining.len().min(avail_in_chunk);
            let slice = &remaining[..write_len];

            if let Some(desc) = existing_chunks.iter().find(|c| c.chunk_index == chunk_index)
                && (in_chunk_offset > 0 || write_len < desc.plaintext_len as usize)
            {
                self.ensure_chunk_staged_for_partial_edit(&rec, &existing_chunks, chunk_index)
                    .await?;
            }

            self.cache
                .write_dirty_chunk_slice(inode, chunk_index, in_chunk_offset, slice)
                .await?;

            cur_offset += write_len as u64;
            remaining = &remaining[write_len..];
        }

        if end_offset > rec.size {
            rec.size = end_offset;
        }
        rec.hydration = HydrationState::DirtyLocal;
        rec.modified_at = Utc::now();
        rec.version = rec.version.saturating_add(1);

        self.cache.invalidate_file(rec.file_id);
        let vpath = rec.virtual_path.clone();
        self.meta.upsert_inode(rec).await?;
        self.ensure_dirty_op_queued(inode, DirtyOpKind::UpsertFile, &vpath)
            .await?;
        self.stats
            .bytes_written
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn create_entry(&self, spec: CreateEntrySpec) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        validate_entry_name(&spec.name)?;
        let parent = self.getattr(spec.parent_inode).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(spec.parent_inode));
        }
        if self
            .meta
            .lookup_child(spec.parent_inode, &spec.name)
            .await?
            .is_some()
        {
            return Err(ZeroVaultError::AlreadyExists(spec.name));
        }

        let inode = self.meta.allocate_inode_id().await?;
        let now = Utc::now();
        let vpath = join_virtual_path(&parent.virtual_path, &spec.name);
        let rec = InodeRecord {
            inode,
            parent_inode: spec.parent_inode,
            file_id: Uuid::new_v4(),
            name: spec.name,
            virtual_path: vpath.clone(),
            kind: EntryKind::File,
            size: 0,
            mode: spec.mode,
            hydration: HydrationState::DirtyLocal,
            pinned: false,
            version: 1,
            wrapped_dek: None,
            modified_at: now,
            created_at: now,
        };
        let saved = self.meta.upsert_inode(rec).await?;
        self.meta
            .enqueue_dirty(inode, DirtyOpKind::UpsertFile, &vpath)
            .await?;
        Ok(saved)
    }

    async fn mkdir(
        &self,
        parent_inode: InodeId,
        name: &str,
        mode: u32,
    ) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        validate_entry_name(name)?;
        let parent = self.getattr(parent_inode).await?;
        if parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(parent_inode));
        }
        if self.meta.lookup_child(parent_inode, name).await?.is_some() {
            return Err(ZeroVaultError::AlreadyExists(name.to_owned()));
        }

        let inode = self.meta.allocate_inode_id().await?;
        let now = Utc::now();
        let vpath = join_virtual_path(&parent.virtual_path, name);
        let rec = InodeRecord {
            inode,
            parent_inode,
            file_id: Uuid::new_v4(),
            name: name.to_owned(),
            virtual_path: vpath.clone(),
            kind: EntryKind::Directory,
            size: 0,
            mode,
            hydration: HydrationState::Pinned,
            pinned: true,
            version: 1,
            wrapped_dek: None,
            modified_at: now,
            created_at: now,
        };
        let saved = self.meta.upsert_inode(rec).await?;
        self.meta
            .enqueue_dirty(inode, DirtyOpKind::UpsertMetadata, &vpath)
            .await?;
        Ok(saved)
    }

    async fn unlink(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        validate_entry_name(name)?;
        let entry = self.lookup(parent_inode, name).await?;
        if entry.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(entry.inode));
        }

        let inode_lock = self.inode_lock(entry.inode);
        let _inode_guard = inode_lock.lock().await;

        let old_chunks = self.meta.list_chunks(entry.inode).await?;
        self.record_gc_candidates(
            old_chunks
                .into_iter()
                .map(|c| (c.blob_id, c.backend_ids)),
        );

        self.cache.invalidate_file(entry.file_id);
        if let Some(prev_node) = self.committed_nodes.lock().remove(&entry.inode) {
            self.record_gc_candidates(
                prev_node
                    .chunks
                    .into_iter()
                    .map(|c| (c.blob_id, c.backend_ids)),
            );
        }
        self.cache.clear_dirty_inode(entry.inode).await?;
        self.complete_inode_dirty_ops(entry.inode).await?;
        self.meta
            .enqueue_dirty(entry.inode, DirtyOpKind::Delete, &entry.virtual_path)
            .await?;
        self.meta.delete_inode(entry.inode).await
    }

    async fn rmdir(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        validate_entry_name(name)?;
        let entry = self.lookup(parent_inode, name).await?;
        if entry.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(entry.inode));
        }
        if !self.meta.list_children(entry.inode).await?.is_empty() {
            return Err(ZeroVaultError::DirectoryNotEmpty(entry.inode));
        }

        self.committed_nodes.lock().remove(&entry.inode);
        self.complete_inode_dirty_ops(entry.inode).await?;
        self.meta
            .enqueue_dirty(entry.inode, DirtyOpKind::Delete, &entry.virtual_path)
            .await?;
        self.meta.delete_inode(entry.inode).await
    }

    async fn rename(
        &self,
        parent_inode: InodeId,
        name: &str,
        new_parent_inode: InodeId,
        new_name: &str,
    ) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        validate_entry_name(name)?;
        validate_entry_name(new_name)?;
        let new_parent = self.getattr(new_parent_inode).await?;
        if new_parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(new_parent_inode));
        }
        let mut entry = self.lookup(parent_inode, name).await?;
        if parent_inode == new_parent_inode && name == new_name {
            return Ok(entry);
        }

        if let Some(target) = self.meta.lookup_child(new_parent_inode, new_name).await?
            && target.inode != entry.inode
        {
            match (entry.kind, target.kind) {
                (EntryKind::Directory, EntryKind::File) => {
                    return Err(ZeroVaultError::NotADirectory(target.inode));
                }
                (EntryKind::File, EntryKind::Directory) => {
                    return Err(ZeroVaultError::IsADirectory(target.inode));
                }
                (EntryKind::Directory, EntryKind::Directory) => {
                    if !self.meta.list_children(target.inode).await?.is_empty() {
                        return Err(ZeroVaultError::DirectoryNotEmpty(target.inode));
                    }
                }
                (EntryKind::File, EntryKind::File) => {}
            }
            let overwritten_chunks = self.meta.list_chunks(target.inode).await?;
            self.record_gc_candidates(
                overwritten_chunks
                    .into_iter()
                    .map(|c| (c.blob_id, c.backend_ids)),
            );
            if let Some(prev_node) = self.committed_nodes.lock().remove(&target.inode) {
                self.record_gc_candidates(
                    prev_node
                        .chunks
                        .into_iter()
                        .map(|c| (c.blob_id, c.backend_ids)),
                );
            }
            self.cache.invalidate_file(target.file_id);
            self.cache.clear_dirty_inode(target.inode).await?;
            self.complete_inode_dirty_ops(target.inode).await?;
            self.meta
                .enqueue_dirty(target.inode, DirtyOpKind::Delete, &target.virtual_path)
                .await?;
            self.meta.delete_inode(target.inode).await?;
        }

        let old_vpath = entry.virtual_path.clone();
        let new_vpath = join_virtual_path(&new_parent.virtual_path, new_name);
        entry.parent_inode = new_parent_inode;
        entry.name = new_name.to_owned();
        entry.virtual_path = new_vpath.clone();
        entry.modified_at = Utc::now();
        entry.version = entry.version.saturating_add(1);

        let is_dir = entry.kind == EntryKind::Directory;
        let inode_id = entry.inode;
        let saved = self.meta.upsert_inode(entry).await?;

        if is_dir {
            rebase_descendant_paths(self.meta.as_ref(), inode_id, &old_vpath, &new_vpath).await?;
        }

        self.ensure_dirty_op_queued(inode_id, DirtyOpKind::UpsertMetadata, &new_vpath)
            .await?;
        Ok(saved)
    }

    async fn setattr(&self, inode: InodeId, attrs: SetAttrSpec) -> ZeroVaultResult<InodeRecord> {
        self.ensure_unlocked()?;
        let inode_lock = self.inode_lock(inode);
        let _inode_guard = inode_lock.lock().await;

        let mut rec = self.getattr(inode).await?;
        let mut content_modified = false;

        if let Some(new_size) = attrs.size {
            if rec.kind == EntryKind::Directory {
                return Err(ZeroVaultError::IsADirectory(inode));
            }
            if new_size < rec.size && new_size > 0 {
                let last_chunk = (new_size - 1) / (PLAINTEXT_CHUNK_SIZE as u64);
                let existing_chunks = self.meta.list_chunks(inode).await?;
                self.ensure_chunk_staged_for_partial_edit(&rec, &existing_chunks, last_chunk)
                    .await?;
            }
            self.cache.truncate_dirty_chunks(inode, new_size).await?;
            self.cache.invalidate_file(rec.file_id);
            rec.size = new_size;
            rec.hydration = HydrationState::DirtyLocal;
            content_modified = true;
        }
        if let Some(mode) = attrs.mode {
            rec.mode = mode;
        }
        if let Some(mtime) = attrs.modified_at {
            rec.modified_at = mtime;
        }
        rec.version = rec.version.saturating_add(1);
        let vpath = rec.virtual_path.clone();
        let saved = self.meta.upsert_inode(rec).await?;

        if content_modified {
            self.ensure_dirty_op_queued(inode, DirtyOpKind::UpsertFile, &vpath)
                .await?;
        } else if attrs.mode.is_some() || attrs.modified_at.is_some() {
            self.ensure_dirty_op_queued(inode, DirtyOpKind::UpsertMetadata, &vpath)
                .await?;
        }

        Ok(saved)
    }

    async fn flush(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        let rec = self.getattr(inode).await?;
        let has_dirty_parts = if rec.kind == EntryKind::File {
            self.cache.has_any_dirty_chunks(inode).await?
        } else {
            false
        };
        let has_dirty_ops = self
            .meta
            .list_dirty_ops()
            .await?
            .iter()
            .any(|op| op.inode == inode);

        if rec.hydration != HydrationState::DirtyLocal && !has_dirty_parts && !has_dirty_ops {
            return Ok(());
        }

        let _sync_guard = self.sync_lock.lock().await;
        let inode_lock = self.inode_lock(inode);
        let _inode_guard = inode_lock.lock().await;

        if rec.kind == EntryKind::File
            && let Err(err) = self.upload_dirty_inode_blobs(inode).await
        {
            self.mark_inode_dirty_retry(inode, &err.to_string()).await;
            return Err(err);
        }

        if let Err(err) = self.publish_manifest_locked(&[inode]).await {
            self.mark_inode_dirty_retry(inode, &err.to_string()).await;
            return Err(err);
        }

        if rec.kind == EntryKind::File {
            self.finalize_flushed_inode(inode).await?;
        }
        self.complete_inode_dirty_ops(inode).await?;
        Ok(())
    }

    async fn fsync(&self, inode: InodeId, _datasync: bool) -> ZeroVaultResult<()> {
        self.flush(inode).await
    }

    async fn pin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        let rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::File {
            let chunks = self.meta.list_chunks(inode).await?;
            if !chunks.is_empty() {
                let wrapped = rec.wrapped_dek.as_ref().ok_or_else(|| {
                    ZeroVaultError::CryptoTamperDetected(format!(
                        "missing wrapped DEK for inode {inode}"
                    ))
                })?;
                let dek = self.crypto.unwrap_dek(rec.file_id, wrapped)?;

                for desc in &chunks {
                    if self.cache.has_dirty_chunk(inode, desc.chunk_index).await {
                        continue;
                    }
                    if self.cache.get(rec.file_id, desc.chunk_index).is_some()
                        && desc.locally_hydrated
                    {
                        continue;
                    }
                    let _ = self.hydrate_single_chunk(&rec, &dek, desc).await?;
                }
            }
        }

        let next_hydration = if rec.hydration == HydrationState::DirtyLocal {
            HydrationState::DirtyLocal
        } else {
            HydrationState::Pinned
        };
        self.meta
            .set_hydration_and_pin(inode, next_hydration, true)
            .await
    }

    async fn unpin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        let rec = self.getattr(inode).await?;
        if rec.hydration == HydrationState::DirtyLocal {
            return self
                .meta
                .set_hydration_and_pin(inode, HydrationState::DirtyLocal, false)
                .await;
        }
        if rec.kind == EntryKind::Directory {
            return self
                .meta
                .set_hydration_and_pin(inode, HydrationState::Pinned, false)
                .await;
        }

        let chunks = self.meta.list_chunks(inode).await?;
        let all_hydrated = !chunks.is_empty() && chunks.iter().all(|c| c.locally_hydrated);
        let any_hydrated = chunks.iter().any(|c| c.locally_hydrated);
        let next = if all_hydrated {
            HydrationState::LocallyCached
        } else if any_hydrated {
            HydrationState::PartiallyHydrated
        } else {
            HydrationState::OnlineOnly
        };
        self.meta.set_hydration_and_pin(inode, next, false).await
    }

    async fn dehydrate(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.ensure_unlocked()?;
        let inode_lock = self.inode_lock(inode);
        let _inode_guard = inode_lock.lock().await;

        let rec = self.getattr(inode).await?;
        if rec.pinned {
            return Err(ZeroVaultError::PinnedDehydrationDenied(inode));
        }
        if rec.hydration == HydrationState::DirtyLocal {
            return Err(ZeroVaultError::VfsError(
                "cannot dehydrate dirty inode before flush".into(),
            ));
        }

        self.cache.invalidate_file(rec.file_id);
        let mut chunks = self.meta.list_chunks(inode).await?;
        if !chunks.is_empty() {
            for chunk in &mut chunks {
                chunk.locally_hydrated = false;
            }
            self.meta.replace_chunks(inode, chunks).await?;
        }
        self.meta
            .set_hydration_and_pin(inode, HydrationState::OnlineOnly, false)
            .await
    }

    async fn get_xattr_state(&self, inode: InodeId) -> ZeroVaultResult<HydrationState> {
        Ok(self.getattr(inode).await?.hydration)
    }

    async fn drive_stats(&self) -> ZeroVaultResult<DriveStats> {
        Ok(DriveStats {
            bytes_read: self.stats.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.stats.bytes_written.load(Ordering::Relaxed),
            chunks_hydrated: self.stats.chunks_hydrated.load(Ordering::Relaxed),
            cache_hits: self.stats.cache_hits.load(Ordering::Relaxed),
            open_handles: self.stats.open_handles.load(Ordering::Relaxed),
        })
    }
}

fn is_fatal_sync_error(err: &ZeroVaultError) -> bool {
    matches!(
        err,
        ZeroVaultError::CryptoTamperDetected(_)
            | ZeroVaultError::VaultLocked
            | ZeroVaultError::InvalidPassphrase
            | ZeroVaultError::HardwareAccelerationUnavailable(_)
            | ZeroVaultError::KdfPolicyViolation { .. }
            | ZeroVaultError::MetadataError(_)
    )
}

fn expected_chunk_plaintext_len(file_size: u64, chunk_index: u64) -> usize {
    if file_size == 0 {
        return 0;
    }
    let chunk_size = PLAINTEXT_CHUNK_SIZE as u64;
    let start = chunk_index.saturating_mul(chunk_size);
    if start >= file_size {
        0
    } else {
        (file_size - start).min(chunk_size) as usize
    }
}

fn validate_entry_name(name: &str) -> ZeroVaultResult<()> {
    validate_portable_entry_name(name, false)
}

fn is_symlink_or_reparse_meta(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn reject_if_existing_symlink_or_reparse(path: &Path) -> ZeroVaultResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse_meta(&meta) {
                return Err(ZeroVaultError::InvalidPath(
                    "refusing local export through symlink or NTFS reparse point".into(),
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn ensure_safe_export_parent_dir(dest_path: &Path) -> ZeroVaultResult<()> {
    let Some(parent) = dest_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    // Verify the deepest existing ancestor directory BEFORE creating any missing subdirectories
    // so we never traverse through a symlinked or NTFS-junctioned parent directory.
    let mut probe = Some(parent);
    while let Some(cur) = probe {
        if cur.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(cur) {
            Ok(meta) => {
                if is_symlink_or_reparse_meta(&meta) {
                    return Err(ZeroVaultError::InvalidPath(
                        "refusing local export into symlink or NTFS reparse directory".into(),
                    ));
                }
                if !meta.is_dir() {
                    return Err(ZeroVaultError::InvalidPath(
                        "export destination parent component is not a directory".into(),
                    ));
                }
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                probe = cur.parent();
            }
            Err(err) => return Err(err.into()),
        }
    }

    fs::create_dir_all(parent).await?;
    reject_if_existing_symlink_or_reparse(parent)
}

fn verify_pre_rename_destination(dest_path: &Path) -> ZeroVaultResult<()> {
    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        reject_if_existing_symlink_or_reparse(parent)?;
    }
    match std::fs::symlink_metadata(dest_path) {
        Ok(meta) => {
            if is_symlink_or_reparse_meta(&meta) {
                return Err(ZeroVaultError::InvalidPath(
                    "export destination became a symlink or reparse point before promotion".into(),
                ));
            }
            if meta.is_dir() {
                return Err(ZeroVaultError::InvalidPath(
                    "export destination is an existing directory".into(),
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}
