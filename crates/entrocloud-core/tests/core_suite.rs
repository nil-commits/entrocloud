//! Comprehensive integration, security-gate, failover, sharing, and zero-knowledge verification
//! tests for `entrocloud-core`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chrono::{TimeZone, Utc};
use dashmap::{DashMap, DashSet};
use parking_lot::Mutex;
use tempfile::TempDir;
use uuid::Uuid;
use entrocloud_core::{
    BoundedBufferPool, ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES, EPOCH_SCOPE_KEYBOX,
    EPOCH_SCOPE_MANIFEST, SqliteMetadataStore, SyncEngine, SyncEngineConfig, compute_manifest_id,
    format_conflict_filename, reclaim_process_memory, sanitize_device_id,
};
use entrocloud_types::mocks::{MockCryptoEngine, MockStorageRouter};
use entrocloud_types::{
    BackendHealth, BackendId, BackendKind, BackendQuota, BlobObjectKey, BlobPlacement,
    ConflictRecord, CreateEntrySpec, CryptoEngine, DirtyOpKind, EntryKind, HydrationState,
    InodeRecord, KEYBOX_OBJECT_KEY, KdfParams, MANIFEST_HEAD_OBJECT_KEY, MetadataStore,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RedactedSecret, RemoteVersion, ReplicaTarget, RoutingPolicy,
    SetAttrSpec, StorageRouterTrait, VaultManifest, VfsBackend, WrappedDek, ZeroVaultError,
    ZeroVaultResult,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn scan_file_for_canary(path: &Path, canary: &str) -> Result<bool, std::io::Error> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = std::fs::read(path)?;
    let utf16 = utf16le_bytes(canary);
    Ok(contains_subslice(&raw, canary.as_bytes()) || contains_subslice(&raw, &utf16))
}

#[derive(Debug)]
struct SpyStorageRouter {
    inner: MockStorageRouter,
    fetched_keys: Mutex<Vec<String>>,
    deleted_keys: Mutex<Vec<String>>,
    fail_writes: AtomicBool,
    fail_reads: AtomicBool,
    corrupt_keys: DashSet<String>,
}

impl SpyStorageRouter {
    fn new() -> Self {
        Self {
            inner: MockStorageRouter::default(),
            fetched_keys: Mutex::new(Vec::new()),
            deleted_keys: Mutex::new(Vec::new()),
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

    fn deleted_keys(&self) -> Vec<String> {
        self.deleted_keys.lock().clone()
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
        self.deleted_keys.lock().push(object_key.to_owned());
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

/// Dual-replica router test double for verifying `NEW-M02` AEAD-verified mirror read failover.
#[derive(Debug)]
struct MirroredFailoverRouter {
    backends: HashMap<String, DashMap<String, (Bytes, String)>>,
    corrupt_on_backend: DashSet<(String, String)>,
}

impl MirroredFailoverRouter {
    fn new() -> Self {
        let mut backends = HashMap::new();
        backends.insert("mirror-0".to_owned(), DashMap::new());
        backends.insert("mirror-1".to_owned(), DashMap::new());
        Self {
            backends,
            corrupt_on_backend: DashSet::new(),
        }
    }

    fn corrupt_replica(&self, backend_id: &str, object_key: &str) {
        self.corrupt_on_backend
            .insert((backend_id.to_owned(), object_key.to_owned()));
    }
}

#[async_trait]
impl StorageRouterTrait for MirroredFailoverRouter {
    async fn put_blob(
        &self,
        _virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        let etag = Uuid::new_v4().to_string();
        let mut replicas = Vec::new();
        for (id, map) in &self.backends {
            map.insert(object_key.to_owned(), (ciphertext.clone(), etag.clone()));
            replicas.push(ReplicaTarget {
                backend_id: id.clone(),
                etag: Some(etag.clone()),
            });
        }
        Ok(BlobPlacement {
            object_key: object_key.to_owned(),
            replicas,
            bytes_written: ciphertext.len(),
        })
    }

    async fn get_blob(
        &self,
        object_key: &str,
        _preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        // Primary race always hits `mirror-0` first (which tests can corrupt!).
        self.get_blob_from_backend("mirror-0", object_key).await
    }

    async fn get_blob_from_backend(
        &self,
        backend_id: &str,
        object_key: &str,
    ) -> ZeroVaultResult<Bytes> {
        let map = self
            .backends
            .get(backend_id)
            .ok_or_else(|| ZeroVaultError::StorageNotFound(backend_id.to_owned()))?;
        let mut bytes = map
            .get(object_key)
            .map(|e| e.value().0.clone())
            .ok_or_else(|| ZeroVaultError::StorageNotFound(object_key.to_owned()))?;
        if self
            .corrupt_on_backend
            .contains(&(backend_id.to_owned(), object_key.to_owned()))
            && !bytes.is_empty()
        {
            let mut v = bytes.to_vec();
            let mid = v.len() / 2;
            v[mid] ^= 0xFF;
            bytes = Bytes::from(v);
        }
        Ok(bytes)
    }

    fn candidate_backends(&self, _preferred_backends: &[BackendId]) -> Vec<BackendId> {
        vec!["mirror-0".to_owned(), "mirror-1".to_owned()]
    }

    async fn delete_blob(
        &self,
        object_key: &str,
        _backends: &[BackendId],
    ) -> ZeroVaultResult<()> {
        for map in self.backends.values() {
            map.remove(object_key);
        }
        Ok(())
    }

    async fn stat_object(
        &self,
        object_key: &str,
        _preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>> {
        let Some(map) = self.backends.get("mirror-0") else {
            return Ok(None);
        };
        Ok(map.get(object_key).map(|entry| RemoteVersion {
            object_key: object_key.to_owned(),
            etag: Some(entry.value().1.clone()),
            content_length: entry.value().0.len() as u64,
            last_modified: Some(Utc::now()),
        }))
    }

    async fn put_manifest_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        _expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        let etag = Uuid::new_v4().to_string();
        let len = sealed_manifest.len() as u64;
        for map in self.backends.values() {
            map.insert(
                object_key.to_owned(),
                (sealed_manifest.clone(), etag.clone()),
            );
        }
        Ok(RemoteVersion {
            object_key: object_key.to_owned(),
            etag: Some(etag),
            content_length: len,
            last_modified: Some(Utc::now()),
        })
    }

    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        Ok(vec![BackendHealth {
            backend_id: "mirror-0".to_owned(),
            kind: BackendKind::Memory,
            healthy: true,
            latency_ms: Some(1),
            last_error: None,
            quota: BackendQuota {
                backend_id: "mirror-0".to_owned(),
                total_bytes: 1_000_000_000,
                used_bytes: 0,
                available_bytes: 1_000_000_000,
            },
        }])
    }

    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
        Ok(BackendQuota {
            backend_id: "pool".to_owned(),
            total_bytes: 1_000_000_000,
            used_bytes: 0,
            available_bytes: 1_000_000_000,
        })
    }

    fn routing_policy(&self) -> RoutingPolicy {
        RoutingPolicy::Mirrored {
            backends: vec!["mirror-0".to_owned(), "mirror-1".to_owned()],
            min_ack: 2,
        }
    }
}

fn make_engine(
    dir: &TempDir,
    device_id: &str,
    crypto: Arc<dyn CryptoEngine>,
    storage: Arc<dyn StorageRouterTrait>,
) -> ZeroVaultResult<SyncEngine> {
    let db_path = dir.path().join(format!("{device_id}.db"));
    let meta = Arc::new(SqliteMetadataStore::open(db_path, Arc::clone(&crypto))?);
    let cfg = SyncEngineConfig {
        staging_dir: dir.path().join(format!("stage-{device_id}")),
        device_id: device_id.to_owned(),
        max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
        max_concurrent_transfers: 8,
    };
    SyncEngine::new(cfg, meta, crypto, storage)
}

#[tokio::test]
async fn sqlite_wal_zero_knowledge_canary_inspection_proves_zero_plaintext_bytes() -> TestResult {
    let dir = TempDir::new()?;
    let db_path = dir.path().join("vault_meta.db");
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    let crypto = Arc::new(MockCryptoEngine::default());

    let store = SqliteMetadataStore::open(&db_path, crypto.clone())?;
    assert_eq!(store.journal_mode()?.to_lowercase(), "wal");
    assert_eq!(store.secure_delete_mode()?, 1);

    let now = Utc::now();
    let dir_ino = store.allocate_inode_id().await?;
    store
        .upsert_inode(InodeRecord {
            inode: dir_ino,
            parent_inode: ROOT_INODE,
            file_id: Uuid::new_v4(),
            name: "PROJECT_NIGHTFALL_DIR".to_owned(),
            virtual_path: "/PROJECT_NIGHTFALL_DIR".to_owned(),
            kind: EntryKind::Directory,
            size: 0,
            mode: 0o755,
            hydration: HydrationState::Pinned,
            pinned: true,
            version: 1,
            wrapped_dek: None,
            modified_at: now,
            created_at: now,
        })
        .await?;

    let file_ino = store.allocate_inode_id().await?;
    store
        .upsert_inode(InodeRecord {
            inode: file_ino,
            parent_inode: dir_ino,
            file_id: Uuid::new_v4(),
            name: "ULTRA_SECRET_CANARY_TAXES_2026.xlsx".to_owned(),
            virtual_path: "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx".to_owned(),
            kind: EntryKind::File,
            size: 16_384,
            mode: 0o644,
            hydration: HydrationState::DirtyLocal,
            pinned: false,
            version: 1,
            wrapped_dek: Some(WrappedDek {
                nonce: [0x22; 12],
                ciphertext_and_tag: vec![0x33; 48],
            }),
            modified_at: now,
            created_at: now,
        })
        .await?;

    store
        .enqueue_dirty(
            file_ino,
            DirtyOpKind::UpsertFile,
            "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx",
        )
        .await?;

    store
        .record_conflict(ConflictRecord {
            original_path: "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx".to_owned(),
            conflict_path:
                "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026 (conflict-dev-20261117).xlsx"
                    .to_owned(),
            remote_revision: 9,
            detected_at: now,
        })
        .await?;

    let canaries = [
        "ULTRA_SECRET_CANARY_TAXES_2026.xlsx",
        "ULTRA_SECRET_CANARY_TAXES_2026",
        "PROJECT_NIGHTFALL_DIR",
        "CANARY_TAXES",
        "NIGHTFALL",
    ];

    // Scan BOTH before WAL checkpoint (when pages live in `.db-wal`) AND after `PRAGMA wal_checkpoint(TRUNCATE)`.
    for canary in canaries {
        assert!(
            !scan_file_for_canary(&db_path, canary)?,
            "plaintext canary '{canary}' leaked into .db pre-checkpoint!"
        );
        assert!(
            !scan_file_for_canary(&wal_path, canary)?,
            "plaintext canary '{canary}' leaked into .db-wal pre-checkpoint!"
        );
    }

    store.wal_checkpoint_truncate()?;

    for canary in canaries {
        assert!(
            !scan_file_for_canary(&db_path, canary)?,
            "plaintext canary '{canary}' leaked into .db post-checkpoint!"
        );
        assert!(
            !scan_file_for_canary(&wal_path, canary)?,
            "plaintext canary '{canary}' leaked into .db-wal post-checkpoint!"
        );
    }

    // Reopen from disk and verify blind-index path lookup, dirty_ops, conflicts, cursor, and epochs!
    drop(store);
    let reopened = SqliteMetadataStore::open(&db_path, crypto.clone())?;
    let looked_up = reopened
        .get_by_path("/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx")
        .await?
        .ok_or("expected canary inode on reopen")?;
    assert_eq!(looked_up.inode, file_ino);
    assert_eq!(looked_up.name, "ULTRA_SECRET_CANARY_TAXES_2026.xlsx");

    let ops = reopened.list_dirty_ops().await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].virtual_path,
        "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx"
    );

    let conflicts = reopened.list_conflicts().await?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].original_path,
        "/PROJECT_NIGHTFALL_DIR/ULTRA_SECRET_CANARY_TAXES_2026.xlsx"
    );

    // Test manifest_cursor + parent_manifest_id + security_epochs rollback enforcement.
    let anchor = Uuid::new_v4();
    reopened
        .update_manifest_cursor(4, Some("etag-4".to_owned()))
        .await?;
    reopened.set_parent_manifest_id(Some(anchor)).await?;
    assert_eq!(
        reopened.manifest_cursor().await?,
        (4, Some("etag-4".to_owned()))
    );
    assert_eq!(reopened.parent_manifest_id().await?, Some(anchor));

    assert_eq!(reopened.epoch_floor("keybox").await?, 0);
    reopened.advance_epoch_floor("keybox", 3).await?;
    assert_eq!(reopened.epoch_floor("keybox").await?, 3);
    reopened.advance_epoch_floor("keybox", 3).await?;
    let rollback_res = reopened.advance_epoch_floor("keybox", 2).await;
    assert!(matches!(
        rollback_res,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Tamper `enc_meta` directly in SQLite and verify fail-closed `CryptoTamperDetected`.
    drop(reopened);
    {
        let raw_conn = rusqlite::Connection::open(&db_path)?;
        raw_conn.execute(
            "UPDATE inodes SET enc_meta = zeroblob(48) WHERE inode = ?1",
            rusqlite::params![file_ino as i64],
        )?;
    }
    let tampered_store = SqliteMetadataStore::open(&db_path, crypto)?;
    let tamper_res = tampered_store.get_inode(file_ino).await;
    assert!(matches!(
        tamper_res,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    Ok(())
}

#[tokio::test]
async fn encrypted_zvpart_staging_and_purge_all_leave_zero_plaintext_or_residual_files() -> TestResult
{
    let dir = TempDir::new()?;
    let crypto = Arc::new(MockCryptoEngine::default());
    let cache = ChunkCache::new(DEFAULT_MAX_RAM_CACHE_BYTES, dir.path(), crypto.clone())?;

    let canary = b"ULTRA_SENSITIVE_STAGED_CHUNK_CANARY_2026";
    cache.write_dirty_chunk_slice(42, 0, 16, canary).await?;

    let zvpart_path = cache.dirty_chunk_path(42, 0);
    assert!(zvpart_path.to_string_lossy().ends_with("0.zvpart"));
    assert!(!scan_file_for_canary(
        &zvpart_path,
        "ULTRA_SENSITIVE_STAGED_CHUNK_CANARY_2026"
    )?);

    let mut out = BytesMut::new();
    let read_len = cache
        .read_dirty_chunk_into(42, 0, &mut out)
        .await?
        .ok_or("expected staged chunk")?;
    assert_eq!(read_len, 16 + canary.len());
    assert_eq!(&out[..16], &[0u8; 16]);
    assert_eq!(&out[16..], canary);

    // Copying `0.zvpart` to `1.zvpart` (AAD chunk_index swap) MUST fail closed!
    let swapped_path = cache.dirty_chunk_path(42, 1);
    std::fs::copy(&zvpart_path, &swapped_path)?;
    let swap_res = cache.read_dirty_chunk_into(42, 1, &mut out).await;
    assert!(matches!(
        swap_res,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Bit-flipping `0.zvpart` on disk MUST fail closed!
    let mut raw_sealed = std::fs::read(&zvpart_path)?;
    let last_idx = raw_sealed.len() - 1;
    raw_sealed[last_idx] ^= 0x01;
    std::fs::write(&zvpart_path, &raw_sealed)?;
    let bitflip_res = cache.read_dirty_chunk_into(42, 0, &mut out).await;
    assert!(matches!(
        bitflip_res,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // `purge_all()` overwrites with zeros and deletes `staging_dir/dirty` completely!
    cache.insert(Uuid::new_v4(), 0, Bytes::from_static(b"ram-cached"));
    assert!(cache.used_ram_bytes() > 0);
    cache.purge_all().await?;
    assert_eq!(cache.used_ram_bytes(), 0);
    assert!(!dir.path().join("dirty").exists());

    Ok(())
}

#[tokio::test]
async fn buffer_pool_full_capacity_zeroization_and_mimalloc_reclamation() -> TestResult {
    let pool = Arc::new(BoundedBufferPool::with_buffer_capacity(2, 4096));
    assert_eq!(pool.max_slots(), 2);

    let ptr_first = {
        let mut b1 = pool.acquire_buffer().await?;
        // Fill full 4096 capacity with non-zero canary, then truncate to 16 so 16..4096 sits in spare capacity!
        b1.resize(4096, 0xCC);
        b1.truncate(16);
        assert_eq!(b1.len(), 16);
        assert!(b1.capacity() >= 4096);
        b1.as_ptr() as usize
    };

    assert_eq!(pool.pooled_buffers(), 1);
    {
        let b_recycled = pool.acquire_buffer().await?;
        assert_eq!(b_recycled.len(), 0);
        assert!(b_recycled.capacity() >= 4096);
        assert_eq!(b_recycled.as_ptr() as usize, ptr_first);
    }

    // `acquire_pair` requires >= 2 slots.
    let single_slot_pool = BoundedBufferPool::with_buffer_capacity(1, 1024);
    assert!(single_slot_pool.acquire_pair().await.is_err());

    let mut pair = pool.acquire_pair().await?;
    pair.pt.extend_from_slice(b"plaintext");
    pair.wire.extend_from_slice(b"ciphertext");
    assert_eq!(pool.in_use_slots(), 2);
    drop(pair);
    assert_eq!(pool.in_use_slots(), 0);

    pool.clear_idle_buffers();
    assert_eq!(pool.pooled_buffers(), 0);
    reclaim_process_memory().await;

    Ok(())
}

#[tokio::test]
async fn streaming_9_5_mib_seek_lock_purge_and_orphan_blob_gc() -> TestResult {
    let dir = TempDir::new()?;
    let crypto = Arc::new(MockCryptoEngine::default());
    let pass = entrocloud_types::RedactedSecret::new("streaming-test-passphrase");
    let vault_hdr = crypto
        .init_vault(&pass, entrocloud_types::KdfParams::default())
        .await?;
    let spy = Arc::new(SpyStorageRouter::new());
    let engine = make_engine(&dir, "node-a", crypto.clone(), spy.clone())?;

    let rec = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "big-video.bin".to_owned(),
            mode: 0o644,
        })
        .await?;

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
            .await?;
    }

    engine.flush(rec.inode).await?;

    for key in spy.inner.list_keys() {
        assert!(!key.contains("big-video"));
    }

    let chunks_v1 = engine.metadata().list_chunks(rec.inode).await?;
    assert_eq!(chunks_v1.len(), 3);
    let chunk0_v1_key = BlobObjectKey::from_uuid(chunks_v1[0].blob_id)
        .as_str()
        .to_owned();
    let chunk1_v1_key = BlobObjectKey::from_uuid(chunks_v1[1].blob_id)
        .as_str()
        .to_owned();
    let chunk2_v1_key = BlobObjectKey::from_uuid(chunks_v1[2].blob_id)
        .as_str()
        .to_owned();

    engine.dehydrate(rec.inode).await?;
    assert_eq!(
        engine.get_xattr_state(rec.inode).await?,
        HydrationState::OnlineOnly
    );

    // O(1) cross-chunk seek across chunk 1 -> 2 MUST NOT download chunk 0!
    spy.clear_fetched_keys();
    let seek_offset = (PLAINTEXT_CHUNK_SIZE as u64) * 2 - 2048;
    let seek_len = 8192;
    let slice = engine.read_range(rec.inode, seek_offset, seek_len).await?;
    assert_eq!(
        slice.as_ref(),
        &expected_data[seek_offset as usize..seek_offset as usize + seek_len]
    );
    let fetched = spy.fetched_keys();
    assert!(fetched.contains(&chunk1_v1_key));
    assert!(fetched.contains(&chunk2_v1_key));
    assert!(!fetched.contains(&chunk0_v1_key));

    // Pin -> deny dehydrate -> unpin -> dehydrate.
    engine.pin(rec.inode).await?;
    assert!(matches!(
        engine.dehydrate(rec.inode).await,
        Err(ZeroVaultError::PinnedDehydrationDenied(_))
    ));
    engine.unpin(rec.inode).await?;
    engine.dehydrate(rec.inode).await?;

    // Modify chunk 0 & flush rev 2 -> Orphan Blob GC (`NEW-L03`) MUST delete superseded `chunk0_v1_key`
    // while retaining `chunk1_v1_key` and `chunk2_v1_key`!
    engine.write_range(rec.inode, 0, b"UPDATED-HEADER").await?;
    engine.flush(rec.inode).await?;
    let deleted_after_update = spy.deleted_keys();
    assert!(deleted_after_update.contains(&chunk0_v1_key));
    assert!(!deleted_after_update.contains(&chunk1_v1_key));
    assert!(!deleted_after_update.contains(&chunk2_v1_key));

    // Unlink file & `sync_once()` -> Orphan Blob GC MUST delete all remaining chunk blobs of the file!
    let chunks_v2 = engine.metadata().list_chunks(rec.inode).await?;
    let v2_keys: Vec<String> = chunks_v2
        .iter()
        .map(|c| BlobObjectKey::from_uuid(c.blob_id).as_str().to_owned())
        .collect();
    engine.unlink(ROOT_INODE, "big-video.bin").await?;
    let gc_report = engine.sync_once().await?;
    assert!(gc_report.gc_deleted_blobs >= 3);
    let all_deleted = spy.deleted_keys();
    for k in &v2_keys {
        assert!(all_deleted.contains(k), "expected orphan blob {k} to be GC'd");
    }

    // Stage a new dirty write, plus a stray non-dirty temp file and an orphan dirty dir,
    // then call `lock_and_purge_cache()`:
    // - RAM LRU & stray/non-dirty staging files MUST be purged
    // - AEAD-encrypted `.zvpart` for inodes with pending `dirty_ops` MUST be preserved (B1)
    // - Reading while locked returns `VaultLocked`, and unlocking restores readable & syncable data!
    let temp_rec = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "ephemeral.txt".to_owned(),
            mode: 0o644,
        })
        .await?;
    engine
        .write_range(temp_rec.inode, 0, b"staged before lock")
        .await?;
    assert!(engine.cache().has_dirty_chunk(temp_rec.inode, 0).await);

    let stray_tmp = engine.config().staging_dir.join("stray.tmp");
    std::fs::write(&stray_tmp, b"stray temp data")?;
    let orphan_inode_dir = engine.config().staging_dir.join("dirty").join("999999");
    std::fs::create_dir_all(&orphan_inode_dir)?;
    std::fs::write(orphan_inode_dir.join("0.zvpart"), b"orphan staged bytes")?;

    engine.lock_and_purge_cache().await?;
    assert!(!engine.crypto().is_unlocked());
    assert_eq!(engine.cache().used_ram_bytes(), 0);
    assert!(!stray_tmp.exists(), "stray temp file must be purged on lock");
    assert!(
        !orphan_inode_dir.exists(),
        "non-dirty orphan staging dir must be purged on lock"
    );
    assert!(
        engine.cache().has_dirty_chunk(temp_rec.inode, 0).await,
        "AEAD-encrypted dirty .zvpart for pending dirty_ops must survive lock"
    );
    assert!(matches!(
        engine.read_range(temp_rec.inode, 0, 10).await,
        Err(ZeroVaultError::VaultLocked)
    ));

    // Unlock vault again and verify the staged dirty write survived intact and syncs cleanly!
    engine
        .crypto()
        .unlock_with_passphrase(&vault_hdr, &pass)
        .await?;
    assert!(engine.crypto().is_unlocked());
    let recovered = engine
        .read_range(temp_rec.inode, 0, b"staged before lock".len())
        .await?;
    assert_eq!(recovered.as_ref(), b"staged before lock");
    engine.sync_once().await?;
    assert!(
        !engine.cache().has_dirty_chunk(temp_rec.inode, 0).await,
        "dirty staging file must be cleared after sync"
    );

    Ok(())
}

#[tokio::test]
async fn verified_mirror_read_failover_recovers_from_corrupt_primary_and_fails_closed_when_all_bad()
-> TestResult {
    let dir = TempDir::new()?;
    let crypto = Arc::new(MockCryptoEngine::default());
    let mirror = Arc::new(MirroredFailoverRouter::new());

    let engine_a = make_engine(&dir, "mirror-writer", crypto.clone(), mirror.clone())?;
    let rec = engine_a
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "critical.db".to_owned(),
            mode: 0o644,
        })
        .await?;
    let payload = b"raid1-verified-mirror-payload-2026";
    engine_a.write_range(rec.inode, 0, payload).await?;
    engine_a.flush(rec.inode).await?;

    let chunks = engine_a.metadata().list_chunks(rec.inode).await?;
    let chunk_key = BlobObjectKey::from_uuid(chunks[0].blob_id)
        .as_str()
        .to_owned();

    // Corrupt BOTH `manifests/head.zvm` AND the data chunk on `mirror-0` (the fastest primary replica)!
    mirror.corrupt_replica("mirror-0", MANIFEST_HEAD_OBJECT_KEY);
    mirror.corrupt_replica("mirror-0", &chunk_key);

    // Second device pulls manifest and reads file: `mirror-0` fails AEAD, fails over to `mirror-1`, and succeeds!
    let engine_b = make_engine(&dir, "mirror-reader", crypto, mirror.clone())?;
    let report = engine_b.sync_once().await?;
    assert_eq!(report.pulled_revision, Some(1));

    let pulled = engine_b.resolve_path("/critical.db").await?;
    let read_bytes = engine_b.read_range(pulled.inode, 0, 128).await?;
    assert_eq!(read_bytes.as_ref(), payload);

    // Now corrupt `mirror-1` too -> all replicas corrupt -> MUST fail closed with `CryptoTamperDetected`!
    engine_b.dehydrate(pulled.inode).await?;
    mirror.corrupt_replica("mirror-1", &chunk_key);
    let all_bad_res = engine_b.read_range(pulled.inode, 0, 128).await;
    assert!(matches!(
        all_bad_res,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    Ok(())
}

#[tokio::test]
async fn manifest_epoch_rollback_and_forged_parent_manifest_id_are_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let crypto = Arc::new(MockCryptoEngine::default());
    let storage = Arc::new(MockStorageRouter::default());
    let dev_a = make_engine(&dir, "dev-a", crypto.clone(), storage.clone())?;
    let dev_b = make_engine(&dir, "dev-b", crypto.clone(), storage.clone())?;

    let f = dev_a
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "doc.txt".to_owned(),
            mode: 0o644,
        })
        .await?;
    dev_a.write_range(f.inode, 0, b"rev1").await?;
    dev_a.flush(f.inode).await?;

    let sealed_rev1 = storage.get_blob(MANIFEST_HEAD_OBJECT_KEY, &[]).await?;
    dev_b.sync_once().await?;
    assert_eq!(
        dev_b.metadata().epoch_floor(EPOCH_SCOPE_MANIFEST).await?,
        1
    );

    // Publish rev 2 from dev_a and pull on dev_b.
    dev_a.write_range(f.inode, 0, b"rev2").await?;
    dev_a.flush(f.inode).await?;
    dev_b.sync_once().await?;
    assert_eq!(
        dev_b.metadata().epoch_floor(EPOCH_SCOPE_MANIFEST).await?,
        2
    );
    let rev2_anchor = dev_b
        .metadata()
        .parent_manifest_id()
        .await?
        .ok_or("expected persisted parent_manifest_id")?;

    // Attack 1: Cloud server replays sealed rev 1 over `manifests/head.zvm`!
    storage
        .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed_rev1, None)
        .await?;
    let replay_err = dev_b.sync_once().await;
    assert!(matches!(
        replay_err,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Attack 2: Cloud server serves rev 3 with a forged `parent_manifest_id != rev2_anchor`!
    let vault_id = crypto.vault_id().ok_or("expected vault_id")?;
    let forged_rev3 = VaultManifest {
        vault_id,
        revision: 3,
        parent_manifest_id: Some(Uuid::new_v4()),
        device_id: "evil-dev".to_owned(),
        created_at: Utc::now(),
        nodes: Vec::new(),
    };
    assert_ne!(forged_rev3.parent_manifest_id, Some(rev2_anchor));
    assert!(compute_manifest_id(&forged_rev3).is_ok());
    let sealed_forged = crypto.seal_manifest(&forged_rev3)?;
    storage
        .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, sealed_forged, None)
        .await?;

    let lineage_err = dev_b.sync_once().await;
    assert!(matches!(
        lineage_err,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    Ok(())
}

#[tokio::test]
async fn serverless_keybox_epoch_revocation_capability_share_and_atomic_export() -> TestResult {
    let dir = TempDir::new()?;
    let owner_crypto = Arc::new(MockCryptoEngine::default());
    let header = owner_crypto
        .init_vault(
            &RedactedSecret::new("owner-vault-passphrase-2026"),
            KdfParams::interactive_production(),
        )
        .await?;
    let shared_storage = Arc::new(MockStorageRouter::default());
    let owner_engine = make_engine(&dir, "owner", owner_crypto.clone(), shared_storage.clone())?;
    owner_engine.publish_vault_header(&header).await?;
    assert_eq!(
        SyncEngine::fetch_vault_header(shared_storage.as_ref())
            .await?
            .vault_id,
        header.vault_id
    );

    // 1. Keybox `epoch=1` -> `epoch=2` revocation + stale replay attack rejection (`CryptoTamperDetected`).
    let owner_id = owner_crypto.generate_recipient_identity("owner")?;
    let alice_id = owner_crypto.generate_recipient_identity("alice")?;
    let bob_id = owner_crypto.generate_recipient_identity("bob")?;

    let frk1 = owner_crypto.export_folder_root_key()?;
    let kb1 = owner_crypto.seal_keybox(
        &owner_id,
        header.vault_id,
        1,
        &frk1,
        &[alice_id.public.clone(), bob_id.public.clone()],
    )?;
    owner_engine.publish_keybox(&kb1).await?;
    let raw_kb1 = shared_storage.get_blob(KEYBOX_OBJECT_KEY, &[]).await?;

    let alice_crypto = Arc::new(MockCryptoEngine::default());
    alice_crypto.lock_vault().await?;
    let alice_engine = make_engine(&dir, "alice", alice_crypto, shared_storage.clone())?;
    let (opened_kb1, alice_frk1) = alice_engine
        .fetch_and_open_keybox(Some(&owner_id.public.ed25519_pubkey), &alice_id)
        .await?;
    assert_eq!(opened_kb1.epoch, 1);
    assert_eq!(&*alice_frk1, &*frk1);
    assert!(alice_engine.crypto().is_unlocked());
    assert_eq!(
        alice_engine
            .metadata()
            .epoch_floor(EPOCH_SCOPE_KEYBOX)
            .await?,
        1
    );

    // Revoke Bob at `epoch=2` with rotated FRK2!
    let frk2 = [0x99u8; 32];
    let kb2 = owner_crypto.seal_keybox(
        &owner_id,
        header.vault_id,
        2,
        &frk2,
        std::slice::from_ref(&alice_id.public),
    )?;
    owner_engine.publish_keybox(&kb2).await?;

    let bob_crypto = Arc::new(MockCryptoEngine::default());
    bob_crypto.lock_vault().await?;
    let bob_engine = make_engine(&dir, "bob", bob_crypto, shared_storage.clone())?;
    assert!(matches!(
        bob_engine
            .fetch_and_open_keybox(Some(&owner_id.public.ed25519_pubkey), &bob_id)
            .await,
        Err(ZeroVaultError::UnauthorizedRecipient(_))
    ));

    let (opened_kb2, alice_frk2) = alice_engine
        .fetch_and_open_keybox(Some(&owner_id.public.ed25519_pubkey), &alice_id)
        .await?;
    assert_eq!(opened_kb2.epoch, 2);
    assert_eq!(&*alice_frk2, &frk2);
    assert_eq!(
        alice_engine
            .metadata()
            .epoch_floor(EPOCH_SCOPE_KEYBOX)
            .await?,
        2
    );

    // Replay `kb1` (`epoch=1`) on storage -> Alice MUST deterministically fail closed with `CryptoTamperDetected`!
    shared_storage
        .put_manifest_cas(KEYBOX_OBJECT_KEY, raw_kb1, None)
        .await?;
    assert!(matches!(
        alice_engine
            .fetch_and_open_keybox(Some(&owner_id.public.ed25519_pubkey), &alice_id)
            .await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2. `zv://` Capability Share roundtrip across 2 chunks (4.25 MiB).
    let shared_file = owner_engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "architecture.pdf".to_owned(),
            mode: 0o644,
        })
        .await?;
    let share_payload: Vec<u8> = (0..(PLAINTEXT_CHUNK_SIZE + 256 * 1024))
        .map(|i| ((i * 31 + 7) & 0xFF) as u8)
        .collect();
    owner_engine
        .write_range(shared_file.inode, 0, &share_payload)
        .await?;
    owner_engine.flush(shared_file.inode).await?;

    let (cap_uri, _env) = owner_engine
        .create_file_capability_share(&owner_id, "mock", "bucket-root", "/architecture.pdf")
        .await?;
    let encoded_uri = cap_uri.encode()?;

    // Recipient with an independent vault imports `zv://` capability URI!
    let rcpt_crypto = Arc::new(MockCryptoEngine::default());
    let rcpt_engine = make_engine(&dir, "cap-recipient", rcpt_crypto, shared_storage.clone())?;
    let imported = rcpt_engine
        .import_capability_share(&encoded_uri, "/SharedDocs/imported-arch.pdf")
        .await?;
    assert_eq!(imported.size, share_payload.len() as u64);

    // 3. Atomic Local Export (`export_file_atomic`) + `.partial` promotion + symlink/reparse guard!
    let export_dir = dir.path().join("exported");
    std::fs::create_dir_all(&export_dir)?;
    let exported_path = rcpt_engine
        .export_file_atomic("/SharedDocs/imported-arch.pdf", &export_dir)
        .await?;
    assert_eq!(exported_path, export_dir.join("imported-arch.pdf"));
    let disk_bytes = std::fs::read(&exported_path)?;
    assert_eq!(disk_bytes, share_payload);

    // Verify zero `.partial` files remain in `export_dir`!
    for entry in std::fs::read_dir(&export_dir)? {
        let p = entry?.path();
        assert!(
            !p.to_string_lossy().ends_with(".partial"),
            "leftover .partial file found: {}",
            p.display()
        );
    }

    // Test NTFS Junction / Symlink refusal on `export_file_atomic`:
    #[cfg(unix)]
    {
        let target = dir.path().join("outside_secret.txt");
        std::fs::write(&target, b"do-not-overwrite")?;
        let link_path = export_dir.join("evil_symlink.pdf");
        std::os::unix::fs::symlink(&target, &link_path)?;
        let res = rcpt_engine
            .export_file_atomic("/SharedDocs/imported-arch.pdf", &link_path)
            .await;
        assert!(matches!(res, Err(ZeroVaultError::InvalidPath(_))));
        assert_eq!(std::fs::read(&target)?, b"do-not-overwrite");
    }
    #[cfg(target_os = "windows")]
    {
        let outside_dir = dir.path().join("outside_target_dir");
        std::fs::create_dir_all(&outside_dir)?;
        let junction_dir = export_dir.join("evil_junction_dir");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_dir)
            .arg(&outside_dir)
            .output()?;
        if status.status.success() {
            let evil_dest = junction_dir.join("stolen.pdf");
            let res = rcpt_engine
                .export_file_atomic("/SharedDocs/imported-arch.pdf", &evil_dest)
                .await;
            assert!(
                matches!(res, Err(ZeroVaultError::InvalidPath(_))),
                "NTFS junction reparse point MUST be rejected by export_file_atomic!"
            );
            assert!(!outside_dir.join("stolen.pdf").exists());
        }
    }

    Ok(())
}

#[tokio::test]
async fn concurrent_conflict_and_offline_retry_preserve_all_data() -> TestResult {
    let ts = Utc
        .with_ymd_and_hms(2026, 11, 17, 15, 4, 31)
        .single()
        .ok_or("valid timestamp")?;
    assert_eq!(
        format_conflict_filename("report.pdf", "laptop-01", ts),
        "report (conflict-laptop-01-20261117-150431).pdf"
    );
    assert_eq!(
        format_conflict_filename(".env", "My/PC! #2", ts),
        ".env (conflict-My-PC-2-20261117-150431)"
    );
    assert_eq!(sanitize_device_id("...///"), "device");

    let dir = TempDir::new()?;
    let shared_crypto = Arc::new(MockCryptoEngine::default());
    let spy = Arc::new(SpyStorageRouter::new());
    let dev_a = make_engine(&dir, "device-a", shared_crypto.clone(), spy.clone())?;
    let dev_b = make_engine(&dir, "device-b", shared_crypto, spy.clone())?;

    let a_file = dev_a
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "report.pdf".to_owned(),
            mode: 0o644,
        })
        .await?;
    dev_a
        .write_range(a_file.inode, 0, b"remote-version-A")
        .await?;

    // Offline outage -> retry_count increments -> recovers when online!
    spy.fail_writes.store(true, Ordering::Release);
    assert!(dev_a.flush(a_file.inode).await.is_err());
    assert_eq!(dev_a.metadata().list_dirty_ops().await?[0].retry_count, 1);
    spy.fail_writes.store(false, Ordering::Release);
    dev_a.sync_once().await?;

    // Offline Device B creates conflicting `/report.pdf`.
    let b_file = dev_b
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "report.pdf".to_owned(),
            mode: 0o644,
        })
        .await?;
    dev_b
        .write_range(b_file.inode, 0, b"local-version-B")
        .await?;

    let report = dev_b.sync_once().await?;
    assert_eq!(report.conflicts_resolved, 1);
    let conflicts = dev_b.metadata().list_conflicts().await?;
    assert_eq!(conflicts.len(), 1);

    let win = dev_b.resolve_path("/report.pdf").await?;
    let preserved = dev_b.resolve_path(&conflicts[0].conflict_path).await?;
    assert_eq!(
        dev_b.read_range(win.inode, 0, 64).await?.as_ref(),
        b"remote-version-A"
    );
    assert_eq!(
        dev_b.read_range(preserved.inode, 0, 64).await?.as_ref(),
        b"local-version-B"
    );

    // Test setattr truncate as well.
    dev_b
        .setattr(
            preserved.inode,
            SetAttrSpec {
                size: Some(5),
                mode: None,
                modified_at: None,
            },
        )
        .await?;
    dev_b.flush(preserved.inode).await?;
    assert_eq!(
        dev_b.read_range(preserved.inode, 0, 64).await?.as_ref(),
        b"local"
    );

    Ok(())
}

#[tokio::test]
async fn fetch_keybox_rejects_forged_signature_without_advancing_epoch_and_fails_over()
-> TestResult {
    let dir = TempDir::new()?;
    let crypto = Arc::new(MockCryptoEngine::default());
    let vault_id = crypto.vault_id().ok_or("expected unlocked vault_id")?;
    let storage = Arc::new(MockStorageRouter::default());
    let engine = make_engine(&dir, "kb-guard", crypto.clone(), storage.clone())?;

    let owner = crypto.generate_recipient_identity("owner")?;
    let alice = crypto.generate_recipient_identity("alice")?;
    let frk = crypto.export_folder_root_key()?;

    let valid_kb1 =
        crypto.seal_keybox(&owner, vault_id, 1, &frk, std::slice::from_ref(&alice.public))?;
    engine.publish_keybox(&valid_kb1).await?;

    let verifier_engine = make_engine(&dir, "kb-reader", crypto.clone(), storage.clone())?;
    let fetched_kb1 = verifier_engine.fetch_keybox().await?;
    assert_eq!(fetched_kb1.epoch, 1);
    assert_eq!(
        verifier_engine
            .metadata()
            .epoch_floor(EPOCH_SCOPE_KEYBOX)
            .await?,
        1
    );

    // Construct a forged-signature `ZVK1` (`epoch = 999_999`, `owner_signature = vec![0xDE; 64]`).
    let mut forged = valid_kb1.clone();
    forged.epoch = 999_999;
    forged.owner_signature = vec![0xDEu8; 64];

    // 1. `publish_keybox` MUST reject forged keybox before upload or epoch advancement!
    assert!(matches!(
        engine.publish_keybox(&forged).await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert_eq!(
        engine.metadata().epoch_floor(EPOCH_SCOPE_KEYBOX).await?,
        1
    );

    // 2. Malicious remote overwrites `vault/keybox.zv` with forged `ZVK1` (`epoch = 999_999`):
    //    `fetch_keybox` MUST fail closed with `CryptoTamperDetected` and MUST NOT advance `epoch_floor`!
    let forged_wire = Bytes::from(forged.encode()?);
    storage
        .put_manifest_cas(KEYBOX_OBJECT_KEY, forged_wire.clone(), None)
        .await?;
    assert!(matches!(
        verifier_engine.fetch_keybox().await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert_eq!(
        verifier_engine
            .metadata()
            .epoch_floor(EPOCH_SCOPE_KEYBOX)
            .await?,
        1,
        "forged ZVK1 must never poison or advance epoch_floor(\"keybox\")"
    );

    // 3. Replica failover: if primary `mirror-0` serves forged `ZVK1` while `mirror-1` has valid `epoch = 2`,
    //    `fetch_keybox` rejects `mirror-0` via `verify_keybox_envelope` and fails over cleanly to `mirror-1`!
    let mirror = Arc::new(MirroredFailoverRouter::new());
    let mirror_engine = make_engine(&dir, "kb-mirror", crypto.clone(), mirror.clone())?;
    let valid_kb2 =
        crypto.seal_keybox(&owner, vault_id, 2, &frk, std::slice::from_ref(&alice.public))?;
    mirror_engine.publish_keybox(&valid_kb2).await?;

    if let Some(m0) = mirror.backends.get("mirror-0") {
        m0.insert(
            KEYBOX_OBJECT_KEY.to_owned(),
            (forged_wire, "forged-etag".to_owned()),
        );
    }

    let mirror_reader = make_engine(&dir, "kb-mirror-reader", crypto, mirror)?;
    let failover_kb = mirror_reader.fetch_keybox().await?;
    assert_eq!(failover_kb.epoch, 2);
    assert_eq!(
        mirror_reader
            .metadata()
            .epoch_floor(EPOCH_SCOPE_KEYBOX)
            .await?,
        2
    );

    Ok(())
}
