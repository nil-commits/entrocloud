//! Streaming 4 MiB chunk sync engine implementing [`zerovault_types::VfsBackend`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use dashmap::DashMap;
use futures::stream::{self, StreamExt, TryStreamExt};
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;
use zerovault_types::{
    BlobObjectKey, ChunkAad, ChunkDescriptor, ChunkRef, CreateEntrySpec, CryptoEngine, DekBytes,
    DirtyOpKind, DriveStats, EntryKind, HydrationState, InodeId, InodeRecord,
    MANIFEST_HEAD_OBJECT_KEY, ManifestNode, ManifestObjectKey, MetadataStore,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RemoteVersion, SetAttrSpec, StorageRouterTrait,
    ThroughputSnapshot, VAULT_HEADER_OBJECT_KEY, VaultHeader, VaultManifest, VfsBackend,
    ZeroVaultError, ZeroVaultResult, chunk_span_for_range,
};

use crate::cache::{ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES};
use crate::conflict::{ConflictResolver, join_virtual_path, rebase_descendant_paths};
use crate::pool::{BoundedBufferPool, DEFAULT_BUFFER_SLOTS};

/// Configuration parameters for [`SyncEngine`].
#[derive(Clone, PartialEq, Eq)]
pub struct SyncEngineConfig {
    /// Local staging directory used for per-4-MiB dirty `.part` chunk files.
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

/// Core zero-knowledge sync & virtual filesystem backend orchestrating SQLite WAL metadata,
/// bounded 4 MiB streaming crypto buffers, byte-bounded chunk caching, and multi-cloud storage.
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
    /// Constructs a new [`SyncEngine`] with bounded memory pools and disk dirty staging.
    pub fn new(
        config: SyncEngineConfig,
        meta: Arc<dyn MetadataStore>,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> ZeroVaultResult<Self> {
        let pool = BoundedBufferPool::new(config.max_concurrent_transfers.max(2));
        let cache = ChunkCache::new(&config.staging_dir, config.max_ram_cache_bytes)?;
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
        })
    }

    fn ensure_unlocked(&self) -> ZeroVaultResult<()> {
        if !self.crypto.is_unlocked() {
            self.cache.clear_ram();
            return Err(ZeroVaultError::VaultLocked);
        }
        Ok(())
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

    /// Downloads and validates the remote `ZVH1` [`VaultHeader`] from `vault/header.zvh`.
    pub async fn fetch_vault_header(router: &dyn StorageRouterTrait) -> ZeroVaultResult<VaultHeader> {
        let bytes = router.get_blob(VAULT_HEADER_OBJECT_KEY, &[]).await?;
        VaultHeader::decode(&bytes)
    }

    /// Synchronizes local state with remote cloud storage:
    /// 1. Pulls `manifests/head.zvm` (if present and newer/changed), verifies AEAD, and runs
    ///    [`ConflictResolver`] so dirty local conflicts are never overwritten silently.
    /// 2. Replays queued `dirty_ops` (`UpsertFile`, `UpsertMetadata`, `Delete`), recording
    ///    retries via `mark_dirty_retry` on transient failures.
    /// 3. Seals and atomically publishes a new manifest snapshot when local mutations succeeded.
    pub async fn sync_once(&self) -> ZeroVaultResult<SyncReport> {
        self.ensure_unlocked()?;

        let _sync_guard = self.sync_lock.lock().await;
        let mut report = SyncReport::default();

        // Phase 1: Pull remote manifest head if present.
        let mut pull_err: Option<ZeroVaultError> = None;
        match self.storage.stat_object(MANIFEST_HEAD_OBJECT_KEY, &[]).await {
            Ok(Some(remote_ver)) => {
                let (local_rev, local_etag) = self.meta.manifest_cursor().await?;
                let should_pull = local_rev == 0
                    || remote_ver.etag.is_none()
                    || remote_ver.etag.as_deref() != local_etag.as_deref();

                if should_pull {
                    match self.storage.get_blob(MANIFEST_HEAD_OBJECT_KEY, &[]).await {
                        Ok(sealed) => {
                            let manifest = self.crypto.open_manifest(&sealed)?;
                            if let Some(expected_vault_id) = self.crypto.vault_id()
                                && manifest.vault_id != expected_vault_id
                            {
                                return Err(ZeroVaultError::CryptoTamperDetected(
                                    "remote manifest vault_id mismatch".into(),
                                ));
                            }
                            if local_rev > 0 && manifest.revision < local_rev {
                                return Err(ZeroVaultError::CryptoTamperDetected(format!(
                                    "remote manifest revision rollback detected: local={local_rev}, remote={}",
                                    manifest.revision
                                )));
                            }

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

                            self.meta
                                .update_manifest_cursor(manifest.revision, remote_ver.etag.clone())
                                .await?;
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

        // Phase 2: Replay queued dirty operations in FIFO order.
        let dirty_ops = self.meta.list_dirty_ops().await?;
        let mut staged_finalize: Vec<(Option<InodeId>, i64)> = Vec::new();
        let mut last_op_err: Option<ZeroVaultError> = None;

        for op in dirty_ops {
            match op.kind {
                DirtyOpKind::UpsertFile => {
                    let inode_lock = self.inode_lock(op.inode);
                    let _inode_guard = inode_lock.lock().await;
                    match self.meta.get_inode(op.inode).await? {
                        None => {
                            // Inode was deleted locally; retire stale UpsertFile op.
                            self.meta.complete_dirty_op(op.id).await?;
                        }
                        Some(_) => match self.upload_dirty_inode_blobs(op.inode).await {
                            Ok(()) => {
                                staged_finalize.push((Some(op.inode), op.id));
                            }
                            Err(err) => {
                                if is_fatal_sync_error(&err) {
                                    return Err(err);
                                }
                                self.meta
                                    .mark_dirty_retry(op.id, &err.to_string())
                                    .await?;
                                report.failed_dirty_ops += 1;
                                last_op_err = Some(err);
                            }
                        },
                    }
                }
                DirtyOpKind::UpsertMetadata | DirtyOpKind::Delete => {
                    staged_finalize.push((None, op.id));
                }
            }
        }

        // Phase 3: Publish updated manifest snapshot if any dirty operations are ready to commit.
        if !staged_finalize.is_empty() {
            let uploaded_inodes: Vec<InodeId> = staged_finalize
                .iter()
                .filter_map(|(maybe_ino, _)| *maybe_ino)
                .collect();
            match self.publish_manifest_locked(&uploaded_inodes).await {
                Ok(new_rev) => {
                    report.published_revision = Some(new_rev);
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

        if let Some(err) = last_op_err {
            return Err(err);
        }
        if let Some(err) = pull_err {
            return Err(err);
        }

        Ok(report)
    }

    fn inode_lock(&self, inode: InodeId) -> Arc<AsyncMutex<()>> {
        self.inode_locks
            .entry(inode)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
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
        let wire = self
            .storage
            .get_blob(blob_key.as_str(), &desc.backend_ids)
            .await?;

        let mut pt_buf = self.pool.acquire_buffer().await?;
        let hdr = self.crypto.decrypt_chunk_into(
            dek,
            rec.file_id,
            Some(desc.chunk_index),
            &wire,
            &mut pt_buf,
        )?;

        if hdr.plaintext_len != desc.plaintext_len {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "chunk {} plaintext_len mismatch: header={}, metadata={}",
                desc.chunk_index, hdr.plaintext_len, desc.plaintext_len
            )));
        }

        if desc.blake3_plaintext != [0u8; 32] {
            let actual = blake3::hash(&pt_buf);
            if actual.as_bytes() != &desc.blake3_plaintext {
                return Err(ZeroVaultError::CryptoTamperDetected(format!(
                    "chunk {} BLAKE3 digest mismatch",
                    desc.chunk_index
                )));
            }
        }

        let pt_zero = Arc::new(Zeroizing::new(pt_buf.to_vec()));
        drop(pt_buf);

        self.cache
            .insert_zeroizing(rec.file_id, desc.chunk_index, Arc::clone(&pt_zero));
        self.meta
            .set_chunk_hydrated(rec.inode, desc.chunk_index, true)
            .await?;
        self.stats.chunks_hydrated.fetch_add(1, Ordering::Relaxed);
        self.stats.record_download(wire.len() as u64);

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
                && (op.kind == kind || (kind == DirtyOpKind::UpsertMetadata && op.kind == DirtyOpKind::UpsertFile))
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
            Some(existing) => (self.crypto.unwrap_dek(rec.file_id, existing)?, existing.clone(), true),
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
                    let hdr = self.crypto.encrypt_chunk_into(
                        &dek,
                        aad,
                        &pair.pt,
                        &mut pair.wire,
                    )?;
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

    async fn publish_manifest_locked(&self, just_uploaded: &[InodeId]) -> ZeroVaultResult<u64> {
        let vault_id = self
            .crypto
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?;
        let (cur_rev, cur_etag) = self.meta.manifest_cursor().await?;

        // Prevent overwriting an existing remote manifest before pulling it first.
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
        let next_rev = cur_rev.saturating_add(1);
        let all_inodes = self.meta.list_all_inodes().await?;
        let mut nodes = Vec::with_capacity(all_inodes.len());
        let mut next_committed = HashMap::with_capacity(all_inodes.len());

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
            } else if let Some(prev_node) = self.committed_nodes.lock().get(&rec.inode).cloned() {
                // Preserve the previously committed consistent snapshot for concurrently
                // modified files whose new chunks have not yet been uploaded.
                next_committed.insert(rec.inode, prev_node.clone());
                nodes.push(prev_node);
            }
        }

        let parent_manifest_id = *self.last_manifest_id.lock();
        let manifest = VaultManifest {
            vault_id,
            revision: next_rev,
            parent_manifest_id,
            device_id: self.config.device_id.clone(),
            created_at: Utc::now(),
            nodes,
        };

        let sealed = self.crypto.seal_manifest(&manifest)?;
        let snapshot_id = Uuid::new_v4();
        let snapshot_key = ManifestObjectKey::from_uuid(snapshot_id);
        self.storage
            .put_manifest_cas(snapshot_key.as_str(), sealed.clone(), None)
            .await?;

        let head_ver = self
            .storage
            .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed, cur_etag.as_deref())
            .await?;

        self.meta
            .update_manifest_cursor(next_rev, head_ver.etag)
            .await?;
        *self.last_manifest_id.lock() = Some(snapshot_id);
        *self.committed_nodes.lock() = next_committed;
        Ok(next_rev)
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
        self.meta
            .get_inode(inode)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(inode))
    }

    async fn lookup(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<InodeRecord> {
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
        let norm = normalize_virtual_path(virtual_path)?;
        self.meta
            .get_by_path(&norm)
            .await?
            .ok_or_else(|| ZeroVaultError::InvalidPath(format!("path not found: {norm}")))
    }

    async fn readdir(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
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

        self.cache.invalidate_file(entry.file_id);
        self.committed_nodes.lock().remove(&entry.inode);
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
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ZeroVaultError::InvalidPath(format!(
            "invalid entry name: {name}"
        )));
    }
    Ok(())
}

fn normalize_virtual_path(raw: &str) -> ZeroVaultResult<String> {
    if raw.contains('\\') || raw.contains('\0') {
        return Err(ZeroVaultError::InvalidPath(
            "invalid path separator or NUL byte".into(),
        ));
    }
    if raw.is_empty() || raw == "/" {
        return Ok("/".to_owned());
    }
    let mut parts = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." {
            return Err(ZeroVaultError::InvalidPath(
                "path traversal segments are disallowed".into(),
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use dashmap::DashSet;
    use tempfile::TempDir;
    use zerovault_types::mocks::{MockCryptoEngine, MockStorageRouter};
    use zerovault_types::{
        BackendHealth, BackendId, BackendQuota, BlobPlacement, KdfParams, RedactedSecret,
        RoutingPolicy,
    };

    use super::*;
    use crate::db::SqliteMetadataStore;

    /// Spy/fault-injecting wrapper around `MockStorageRouter` for verifying O(1) chunk fetches,
    /// AEAD tamper rejection, and offline dirty queue retry + recovery.
    #[derive(Debug)]
    struct SpyStorageRouter {
        inner: MockStorageRouter,
        fetched_keys: Mutex<Vec<String>>,
        fail_writes: AtomicBool,
        fail_reads: AtomicBool,
        corrupt_keys: DashSet<String>,
    }

    impl SpyStorageRouter {
        fn new() -> Self {
            Self {
                inner: MockStorageRouter::default(),
                fetched_keys: Mutex::new(Vec::new()),
                fail_writes: AtomicBool::new(false),
                fail_reads: AtomicBool::new(false),
                corrupt_keys: DashSet::new(),
            }
        }

        fn fetched_keys(&self) -> Vec<String> {
            self.fetched_keys.lock().clone()
        }

        fn clear_fetched_keys(&self) {
            self.fetched_keys.lock().clear();
        }
    }

    #[async_trait]
    impl StorageRouterTrait for SpyStorageRouter {
        async fn put_blob(
            &self,
            virtual_hint_path: &str,
            object_key: &str,
            ciphertext: Bytes,
        ) -> ZeroVaultResult<BlobPlacement> {
            if self.fail_writes.load(Ordering::Acquire) {
                return Err(ZeroVaultError::StorageBackendError(
                    "simulated network outage on put_blob".into(),
                ));
            }
            self.inner
                .put_blob(virtual_hint_path, object_key, ciphertext)
                .await
        }

        async fn get_blob(
            &self,
            object_key: &str,
            preferred_backends: &[BackendId],
        ) -> ZeroVaultResult<Bytes> {
            if self.fail_reads.load(Ordering::Acquire) {
                return Err(ZeroVaultError::StorageBackendError(
                    "simulated network outage on get_blob".into(),
                ));
            }
            self.fetched_keys.lock().push(object_key.to_owned());
            let mut bytes = self.inner.get_blob(object_key, preferred_backends).await?;
            if self.corrupt_keys.contains(object_key) && !bytes.is_empty() {
                let mut vec = bytes.to_vec();
                let last = vec.len() - 1;
                vec[last] ^= 0x55;
                bytes = Bytes::from(vec);
            }
            Ok(bytes)
        }

        async fn delete_blob(
            &self,
            object_key: &str,
            backends: &[BackendId],
        ) -> ZeroVaultResult<()> {
            self.inner.delete_blob(object_key, backends).await
        }

        async fn stat_object(
            &self,
            object_key: &str,
            preferred_backends: &[BackendId],
        ) -> ZeroVaultResult<Option<RemoteVersion>> {
            if self.fail_reads.load(Ordering::Acquire) {
                return Err(ZeroVaultError::StorageBackendError(
                    "simulated network outage on stat_object".into(),
                ));
            }
            self.inner.stat_object(object_key, preferred_backends).await
        }

        async fn put_manifest_cas(
            &self,
            object_key: &str,
            sealed_manifest: Bytes,
            expected_etag: Option<&str>,
        ) -> ZeroVaultResult<RemoteVersion> {
            if self.fail_writes.load(Ordering::Acquire) {
                return Err(ZeroVaultError::StorageBackendError(
                    "simulated network outage on put_manifest_cas".into(),
                ));
            }
            self.inner
                .put_manifest_cas(object_key, sealed_manifest, expected_etag)
                .await
        }

        async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
            self.inner.list_backend_health().await
        }

        async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
            self.inner.pooled_quota().await
        }

        fn routing_policy(&self) -> RoutingPolicy {
            self.inner.routing_policy()
        }
    }

    fn make_engine(
        dir: &TempDir,
        device_id: &str,
        crypto: Arc<dyn CryptoEngine>,
        storage: Arc<dyn StorageRouterTrait>,
    ) -> SyncEngine {
        let db_path = dir.path().join(format!("{device_id}.db"));
        let meta = Arc::new(SqliteMetadataStore::open(db_path).expect("sqlite"));
        let cfg = SyncEngineConfig {
            staging_dir: dir.path().join(format!("stage-{device_id}")),
            device_id: device_id.to_owned(),
            max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
            max_concurrent_transfers: 8,
        };
        SyncEngine::new(cfg, meta, crypto, storage).expect("engine")
    }

    #[tokio::test]
    async fn streaming_9_5_mib_write_flush_dehydrate_and_o1_cross_chunk_seek() {
        let dir = TempDir::new().expect("tempdir");
        let crypto = Arc::new(MockCryptoEngine::default());
        let spy = Arc::new(SpyStorageRouter::new());
        let engine = make_engine(&dir, "node-a", crypto.clone(), spy.clone());

        let rec = engine
            .create_entry(CreateEntrySpec {
                parent_inode: ROOT_INODE,
                name: "big-video.bin".to_owned(),
                mode: 0o644,
            })
            .await
            .expect("create");

        // Stream > 9 MiB (9.5 MiB = 3 chunks: 0, 1, 2) in 512 KiB increments.
        let total_size = 9 * 1024 * 1024 + 512 * 1024;
        let mut expected_data = vec![0u8; total_size];
        for (i, b) in expected_data.iter_mut().enumerate() {
            *b = ((i * 13 + (i >> 12)) & 0xFF) as u8;
        }

        let step = 512 * 1024;
        for off in (0..total_size).step_by(step) {
            let end = (off + step).min(total_size);
            engine
                .write_range(rec.inode, off as u64, &expected_data[off..end])
                .await
                .expect("write slice");
        }

        engine.flush(rec.inode).await.expect("flush 3 chunks");

        // Verify zero-knowledge object keys (no plaintext filename remotely!).
        for key in spy.inner.list_keys() {
            assert!(!key.contains("big-video"));
        }

        let chunks = engine.metadata().list_chunks(rec.inode).await.expect("chunks");
        assert_eq!(chunks.len(), 3);
        let chunk0_key = BlobObjectKey::from_uuid(chunks[0].blob_id).as_str().to_owned();
        let chunk1_key = BlobObjectKey::from_uuid(chunks[1].blob_id).as_str().to_owned();
        let chunk2_key = BlobObjectKey::from_uuid(chunks[2].blob_id).as_str().to_owned();

        // Dehydrate so RAM cache is cleared and chunks become OnlineOnly.
        engine.dehydrate(rec.inode).await.expect("dehydrate");
        assert_eq!(
            engine.get_xattr_state(rec.inode).await.expect("state"),
            HydrationState::OnlineOnly
        );

        // O(1) mid-file range seek crossing chunk 1 -> 2 boundary!
        spy.clear_fetched_keys();
        let seek_offset = (PLAINTEXT_CHUNK_SIZE as u64) * 2 - 2048;
        let seek_len = 8192;
        let slice = engine
            .read_range(rec.inode, seek_offset, seek_len)
            .await
            .expect("o1 seek read");
        assert_eq!(
            slice.as_ref(),
            &expected_data[seek_offset as usize..seek_offset as usize + seek_len]
        );

        let fetched = spy.fetched_keys();
        assert!(fetched.contains(&chunk1_key));
        assert!(fetched.contains(&chunk2_key));
        assert!(
            !fetched.contains(&chunk0_key),
            "chunk 0 MUST NOT be downloaded on chunk 1->2 seek!"
        );

        // Pinning hydrates remaining chunk 0 and blocks dehydration.
        engine.pin(rec.inode).await.expect("pin");
        assert!(matches!(
            engine.dehydrate(rec.inode).await,
            Err(ZeroVaultError::PinnedDehydrationDenied(_))
        ));
        engine.unpin(rec.inode).await.expect("unpin");
        assert_eq!(
            engine.get_xattr_state(rec.inode).await.expect("state"),
            HydrationState::LocallyCached
        );
        engine.dehydrate(rec.inode).await.expect("dehydrate after unpin");

        // Tamper detection fails closed!
        spy.corrupt_keys.insert(chunk1_key);
        let tamper_err = engine
            .read_range(rec.inode, seek_offset, seek_len)
            .await
            .expect_err("tampered chunk must fail closed");
        assert!(tamper_err.is_tamper());
    }

    #[tokio::test]
    async fn offline_dirty_queue_retries_and_recovers_on_sync_once() {
        let dir = TempDir::new().expect("tempdir");
        let crypto = Arc::new(MockCryptoEngine::default());
        let spy = Arc::new(SpyStorageRouter::new());
        let engine = make_engine(&dir, "offline-host", crypto, spy.clone());

        let rec = engine
            .create_entry(CreateEntrySpec {
                parent_inode: ROOT_INODE,
                name: "draft.txt".to_owned(),
                mode: 0o644,
            })
            .await
            .expect("create");
        engine
            .write_range(rec.inode, 0, b"offline durable payload")
            .await
            .expect("write");

        // Simulate cloud outage.
        spy.fail_writes.store(true, Ordering::Release);
        assert!(engine.flush(rec.inode).await.is_err());

        let ops_after_fail = engine.metadata().list_dirty_ops().await.expect("ops");
        assert_eq!(ops_after_fail.len(), 1);
        assert_eq!(ops_after_fail[0].retry_count, 1);
        assert!(ops_after_fail[0].last_error.is_some());

        // Second attempt via sync_once while still offline increments retry_count again.
        assert!(engine.sync_once().await.is_err());
        let ops_second = engine.metadata().list_dirty_ops().await.expect("ops");
        assert_eq!(ops_second[0].retry_count, 2);

        // Cloud comes back online -> sync_once recovers and flushes cleanly.
        spy.fail_writes.store(false, Ordering::Release);
        let report = engine.sync_once().await.expect("sync recovery");
        assert_eq!(report.replayed_dirty_ops, 1);
        assert!(report.published_revision.is_some());
        assert!(engine.metadata().list_dirty_ops().await.expect("ops").is_empty());

        engine.dehydrate(rec.inode).await.expect("dehydrate");
        let read_back = engine.read_range(rec.inode, 0, 64).await.expect("read");
        assert_eq!(read_back.as_ref(), b"offline durable payload");
    }

    #[tokio::test]
    async fn concurrent_conflict_preserves_both_versions_and_records_conflict() {
        let dir = TempDir::new().expect("tempdir");
        let shared_crypto = Arc::new(MockCryptoEngine::default());
        let header = shared_crypto
            .init_vault(
                &RedactedSecret::new("strong passphrase for conflict test"),
                KdfParams::interactive_production(),
            )
            .await
            .expect("init vault");

        let shared_storage = Arc::new(MockStorageRouter::default());
        let dev_a = make_engine(&dir, "device-a", shared_crypto.clone(), shared_storage.clone());
        let dev_b = make_engine(&dir, "device-b", shared_crypto.clone(), shared_storage.clone());

        dev_a
            .publish_vault_header(&header)
            .await
            .expect("publish header");
        let fetched_hdr = SyncEngine::fetch_vault_header(shared_storage.as_ref())
            .await
            .expect("fetch header");
        assert_eq!(fetched_hdr.vault_id, header.vault_id);

        // Device A creates and publishes `/report.pdf` with "remote-version-A".
        let a_file = dev_a
            .create_entry(CreateEntrySpec {
                parent_inode: ROOT_INODE,
                name: "report.pdf".to_owned(),
                mode: 0o644,
            })
            .await
            .expect("create a");
        dev_a
            .write_range(a_file.inode, 0, b"remote-version-A")
            .await
            .expect("write a");
        dev_a.flush(a_file.inode).await.expect("flush a");

        // Offline Device B creates `/report.pdf` locally with "local-version-B" (never pulled rev 1).
        let b_file = dev_b
            .create_entry(CreateEntrySpec {
                parent_inode: ROOT_INODE,
                name: "report.pdf".to_owned(),
                mode: 0o644,
            })
            .await
            .expect("create b");
        dev_b
            .write_range(b_file.inode, 0, b"local-version-B")
            .await
            .expect("write b");

        // Device B syncs: conflict resolver preserves both versions and publishes merged manifest!
        let report = dev_b.sync_once().await.expect("sync b");
        assert_eq!(report.conflicts_resolved, 1);

        let conflicts = dev_b.metadata().list_conflicts().await.expect("conflicts");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].original_path, "/report.pdf");
        assert!(conflicts[0]
            .conflict_path
            .starts_with("/report (conflict-device-b-"));
        assert!(conflicts[0].conflict_path.ends_with(").pdf"));

        // Verify both distinct payloads survive without data loss!
        let winning_node = dev_b.resolve_path("/report.pdf").await.expect("remote path");
        let conflict_node = dev_b
            .resolve_path(&conflicts[0].conflict_path)
            .await
            .expect("conflict path");
        assert_ne!(winning_node.file_id, conflict_node.file_id);

        let winning_bytes = dev_b
            .read_range(winning_node.inode, 0, 128)
            .await
            .expect("read winning");
        let conflict_bytes = dev_b
            .read_range(conflict_node.inode, 0, 128)
            .await
            .expect("read conflict");
        assert_eq!(winning_bytes.as_ref(), b"remote-version-A");
        assert_eq!(conflict_bytes.as_ref(), b"local-version-B");

        // Device A pulls merged manifest and sees both files intact!
        dev_a.sync_once().await.expect("sync a");
        let a_conflict_node = dev_a
            .resolve_path(&conflicts[0].conflict_path)
            .await
            .expect("dev_a sees conflict copy");
        let a_conflict_bytes = dev_a
            .read_range(a_conflict_node.inode, 0, 128)
            .await
            .expect("read on dev_a");
        assert_eq!(a_conflict_bytes.as_ref(), b"local-version-B");
    }

    #[tokio::test]
    async fn real_aws_lc_crypto_and_local_fs_router_end_to_end() {
        use zerovault_crypto::AwsLcCryptoEngine;
        use zerovault_storage::{CloudBackend, StorageRouter};
        use zerovault_types::{BackendConfig, BackendKind};

        let dir = TempDir::new().expect("tempdir");
        let cloud_root = dir.path().join("cloud-bucket");
        std::fs::create_dir_all(&cloud_root).expect("create cloud root");

        let backend_cfg = BackendConfig {
            id: "local-cloud".to_owned(),
            kind: BackendKind::LocalFs,
            root: cloud_root.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(512 * 1024 * 1024),
            min_free_reserve_bytes: 0,
            username: None,
            access_key_id: None,
            secret_access_key: None,
            secret_account_key: None,
        };
        let backend = CloudBackend::from_config(&backend_cfg).expect("cloud backend");
        let router = Arc::new(
            StorageRouter::new(
                [backend],
                RoutingPolicy::Targeted {
                    prefix_routes: Vec::new(),
                    default_backend: "local-cloud".to_owned(),
                },
            )
            .expect("router"),
        );

        let crypto_a = Arc::new(AwsLcCryptoEngine::new().expect("hw aes-ni/pclmul"));
        let passphrase = RedactedSecret::new("production-kdf-passphrase-123");
        let header = crypto_a
            .init_vault(&passphrase, KdfParams::interactive_production())
            .await
            .expect("init vault");

        let engine_a = make_engine(&dir, "real-a", crypto_a.clone(), router.clone());
        engine_a
            .publish_vault_header(&header)
            .await
            .expect("publish vault header");

        let docs = engine_a
            .mkdir(ROOT_INODE, "Finance", 0o755)
            .await
            .expect("mkdir");
        let file = engine_a
            .create_entry(CreateEntrySpec {
                parent_inode: docs.inode,
                name: "ledger.dat".to_owned(),
                mode: 0o644,
            })
            .await
            .expect("create");

        // Write 4.5 MiB spanning 2 real AES-256-GCM chunks, flush, partial patch, and truncate.
        let payload_len = PLAINTEXT_CHUNK_SIZE + 512 * 1024;
        let payload: Vec<u8> = (0..payload_len).map(|i| ((i * 7) & 0xFF) as u8).collect();
        engine_a
            .write_range(file.inode, 0, &payload)
            .await
            .expect("write 4.5 MiB");
        engine_a.flush(file.inode).await.expect("flush real crypto");

        // Verify zero plaintext filenames or payload substrings exist anywhere on cloud disk.
        fn walk_dir_paths(root: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(root).expect("readdir") {
                let p = entry.expect("entry").path();
                if p.is_dir() {
                    walk_dir_paths(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
        let mut remote_files = Vec::new();
        walk_dir_paths(&cloud_root, &mut remote_files);
        assert!(!remote_files.is_empty());
        for p in &remote_files {
            let s = p.to_string_lossy();
            assert!(!s.contains("Finance"));
            assert!(!s.contains("ledger"));
        }

        // Partial overwrite inside chunk 0 + directory rename.
        engine_a
            .write_range(file.inode, 1024, b"PATCHED-LEDGER")
            .await
            .expect("partial edit");
        engine_a
            .rename(ROOT_INODE, "Finance", ROOT_INODE, "Accounting")
            .await
            .expect("rename dir");
        engine_a.flush(file.inode).await.expect("flush patched");

        // Second fresh device unlocks from remote `vault/header.zvh` and pulls manifest.
        let crypto_b = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto b"));
        let fetched_hdr = SyncEngine::fetch_vault_header(router.as_ref())
            .await
            .expect("fetch header");
        crypto_b
            .unlock_with_passphrase(&fetched_hdr, &passphrase)
            .await
            .expect("unlock b");

        let engine_b = make_engine(&dir, "real-b", crypto_b, router.clone());
        let report = engine_b.sync_once().await.expect("sync b");
        assert!(report.pulled_revision.is_some());

        let remote_file = engine_b
            .resolve_path("/Accounting/ledger.dat")
            .await
            .expect("resolved renamed path");
        let patched_slice = engine_b
            .read_range(remote_file.inode, 1024, 14)
            .await
            .expect("read patch");
        assert_eq!(patched_slice.as_ref(), b"PATCHED-LEDGER");

        let cross_boundary = engine_b
            .read_range(remote_file.inode, (PLAINTEXT_CHUNK_SIZE - 16) as u64, 64)
            .await
            .expect("read boundary");
        assert_eq!(
            cross_boundary.as_ref(),
            &payload[PLAINTEXT_CHUNK_SIZE - 16..PLAINTEXT_CHUNK_SIZE + 48]
        );

        // Verify redaction on Debug output.
        let dbg = format!("{engine_b:?}");
        assert!(!dbg.contains("Accounting"));
        assert!(!dbg.contains("ledger.dat"));
        assert!(!dbg.contains("production-kdf-passphrase"));
    }
}
