//! Test-only in-memory doubles implementing the `zerovault-types` trait contracts.
//!
//! **WARNING:** [`MockCryptoEngine`] uses a deterministic keyed simulation for fast unit-test
//! isolation of downstream crates and MUST NEVER be used for real encryption.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{ZeroVaultError, ZeroVaultResult};
use crate::traits::{
    BackendHealth, BackendId, BackendKind, BackendQuota, BlobPlacement, ChunkDescriptor,
    ConflictRecord, CreateEntrySpec, CryptoBenchmarkReport, CryptoEngine, DirtyOp, DirtyOpKind,
    DriveStats, EntryKind, HardwareCryptoCaps, HydrationState, InodeId, InodeRecord, MetadataStore,
    ROOT_INODE, RemoteVersion, ReplicaTarget, RoutingPolicy, SecretStore, SetAttrSpec,
    StorageRouterTrait, VfsBackend,
};
use crate::wire::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CHUNK_FORMAT_VERSION, CHUNK_HEADER_LEN, ChunkAad,
    ChunkHeader, DekBytes, KdfParams, MANIFEST_FORMAT_VERSION, MANIFEST_HEADER_LEN,
    ManifestWireHeader, RedactedSecret, VAULT_HEADER_VERSION, VaultHeader,
    VaultManifest, WrappedDek, chunk_span_for_range, validate_remote_object_key,
};

fn keyed_tag(key: &[u8; 32], aad: &[u8], payload: &[u8]) -> [u8; 16] {
    // Simple deterministic FNV-style keyed mixer strictly for unit-test mock tamper simulation.
    let mut state = [0xcbf2_9ce4_8422_2325u64, 0x9e37_79b9_7f4a_7c15u64];
    for (i, &b) in key
        .iter()
        .chain(aad.iter())
        .chain(payload.iter())
        .enumerate()
    {
        let lane = i & 1;
        state[lane] ^= u64::from(b).wrapping_add((i as u64).wrapping_mul(0x517c_c1b7_2722_0a95));
        state[lane] = state[lane].wrapping_mul(0x1000_0000_01b3).rotate_left(13);
        state[lane ^ 1] ^= state[lane].rotate_right(7);
    }
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&state[0].to_le_bytes());
    out[8..16].copy_from_slice(&state[1].to_le_bytes());
    out
}

fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (i, &b) in input.iter().enumerate() {
        let mask = key[i % 32] ^ nonce[i % 12] ^ ((i.wrapping_mul(31)) as u8);
        out.push(b ^ mask);
    }
    out
}

/// Test-only mock implementing [`CryptoEngine`] with AAD-bound tamper rejection.
#[derive(Debug)]
pub struct MockCryptoEngine {
    unlocked: AtomicBool,
    vault_id: RwLock<Option<Uuid>>,
    master_key: RwLock<Zeroizing<[u8; 32]>>,
    nonce_counter: AtomicU64,
}

impl Default for MockCryptoEngine {
    fn default() -> Self {
        Self::new_unlocked(Uuid::new_v4())
    }
}

impl MockCryptoEngine {
    /// Creates an already-unlocked mock crypto engine for isolated VFS/core unit tests.
    #[must_use]
    pub fn new_unlocked(vault_id: Uuid) -> Self {
        let mut key = [0xA5u8; 32];
        key[0..16].copy_from_slice(vault_id.as_bytes());
        Self {
            unlocked: AtomicBool::new(true),
            vault_id: RwLock::new(Some(vault_id)),
            master_key: RwLock::new(Zeroizing::new(key)),
            nonce_counter: AtomicU64::new(1),
        }
    }

    fn next_nonce(&self) -> [u8; AES_GCM_NONCE_LEN] {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce[4..12].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    fn require_unlocked(&self) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
        if !self.unlocked.load(Ordering::Acquire) {
            return Err(ZeroVaultError::VaultLocked);
        }
        Ok(self.master_key.read().clone())
    }
}

#[async_trait]
impl CryptoEngine for MockCryptoEngine {
    fn verify_hardware_acceleration(&self) -> ZeroVaultResult<HardwareCryptoCaps> {
        Ok(HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw: true,
            pclmul_hw: true,
            vaes_hw: false,
            avx2_hw: true,
            mandatory_satisfied: true,
            backend_name: "mock-test-crypto".to_owned(),
        })
    }

    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::Acquire)
    }

    fn vault_id(&self) -> Option<Uuid> {
        *self.vault_id.read()
    }

    async fn init_vault(
        &self,
        passphrase: &RedactedSecret,
        kdf: KdfParams,
    ) -> ZeroVaultResult<VaultHeader> {
        kdf.validate_production()?;
        let vault_id = Uuid::new_v4();
        let mut salt = [0u8; 32];
        salt[0..16].copy_from_slice(vault_id.as_bytes());
        let mut master = [0u8; 32];
        for (i, b) in passphrase.as_bytes().iter().enumerate() {
            master[i % 32] ^= b;
        }
        master[0..16].copy_from_slice(vault_id.as_bytes());
        *self.master_key.write() = Zeroizing::new(master);
        *self.vault_id.write() = Some(vault_id);
        self.unlocked.store(true, Ordering::Release);

        let nonce = self.next_nonce();
        let tag = keyed_tag(
            &master,
            &VaultHeader::verifier_aad(vault_id),
            vault_id.as_bytes(),
        );
        let mut verifier_tag = [0u8; 32];
        verifier_tag[0..16].copy_from_slice(vault_id.as_bytes());
        verifier_tag[16..32].copy_from_slice(&tag);

        Ok(VaultHeader {
            version: VAULT_HEADER_VERSION,
            vault_id,
            argon2_salt: salt,
            kdf,
            verifier_nonce: nonce,
            verifier_tag,
        })
    }

    async fn unlock_with_passphrase(
        &self,
        header: &VaultHeader,
        passphrase: &RedactedSecret,
    ) -> ZeroVaultResult<()> {
        header.kdf.validate_production()?;
        let mut master = [0u8; 32];
        for (i, b) in passphrase.as_bytes().iter().enumerate() {
            master[i % 32] ^= b;
        }
        master[0..16].copy_from_slice(header.vault_id.as_bytes());
        let expected_tag = keyed_tag(
            &master,
            &VaultHeader::verifier_aad(header.vault_id),
            header.vault_id.as_bytes(),
        );
        if header.verifier_tag[16..32] != expected_tag {
            return Err(ZeroVaultError::InvalidPassphrase);
        }
        *self.master_key.write() = Zeroizing::new(master);
        *self.vault_id.write() = Some(header.vault_id);
        self.unlocked.store(true, Ordering::Release);
        Ok(())
    }

    async fn lock_vault(&self) -> ZeroVaultResult<()> {
        *self.master_key.write() = Zeroizing::new([0u8; 32]);
        self.unlocked.store(false, Ordering::Release);
        Ok(())
    }

    async fn persist_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
    ) -> ZeroVaultResult<()> {
        let key = self.require_unlocked()?;
        let id = self
            .vault_id()
            .ok_or(ZeroVaultError::VaultLocked)?
            .to_string();
        store.set_secret(service, &id, key.as_ref()).await
    }

    async fn restore_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
        expected_vault_id: Uuid,
    ) -> ZeroVaultResult<bool> {
        let Some(bytes) = store
            .get_secret(service, &expected_vault_id.to_string())
            .await?
        else {
            return Ok(false);
        };
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            ZeroVaultError::InvalidWireFormat("invalid mock session length".into())
        })?;
        *self.master_key.write() = Zeroizing::new(arr);
        *self.vault_id.write() = Some(expected_vault_id);
        self.unlocked.store(true, Ordering::Release);
        Ok(true)
    }

    fn generate_dek(&self) -> ZeroVaultResult<DekBytes> {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut dek = [0x42u8; 32];
        dek[0..8].copy_from_slice(&n.to_le_bytes());
        Ok(DekBytes::from_array(dek))
    }

    fn wrap_dek(&self, file_id: Uuid, dek: &DekBytes) -> ZeroVaultResult<WrappedDek> {
        let master = self.require_unlocked()?;
        let nonce = self.next_nonce();
        let ct = xor_keystream(&master, &nonce, dek.as_bytes());
        let tag = keyed_tag(&master, &WrappedDek::dek_wrap_aad(file_id), &ct);
        let mut combined = Vec::with_capacity(48);
        combined.extend_from_slice(&ct);
        combined.extend_from_slice(&tag);
        Ok(WrappedDek {
            nonce,
            ciphertext_and_tag: combined,
        })
    }

    fn unwrap_dek(&self, file_id: Uuid, wrapped: &WrappedDek) -> ZeroVaultResult<DekBytes> {
        let master = self.require_unlocked()?;
        if wrapped.ciphertext_and_tag.len() != 48 {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wrapped DEK length mismatch".into(),
            ));
        }
        let (ct, tag) = wrapped.ciphertext_and_tag.split_at(32);
        let expected_tag = keyed_tag(&master, &WrappedDek::dek_wrap_aad(file_id), ct);
        if tag != expected_tag {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wrapped DEK tag mismatch".into(),
            ));
        }
        let pt = xor_keystream(&master, &wrapped.nonce, ct);
        DekBytes::from_slice(&pt)
    }

    fn encrypt_chunk_into(
        &self,
        dek: &DekBytes,
        aad: ChunkAad,
        plaintext: &[u8],
        out_wire: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader> {
        let _ = self.require_unlocked()?;
        let nonce = self.next_nonce();
        let header = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: aad.is_final_chunk,
            chunk_index: aad.chunk_index,
            plaintext_len: u32::try_from(plaintext.len()).map_err(|_| {
                ZeroVaultError::InvalidWireFormat("chunk exceeds u32::MAX".into())
            })?,
            nonce,
        };
        let header_bytes = header.encode()?;
        let ct = xor_keystream(dek.as_bytes(), &nonce, plaintext);
        let tag = keyed_tag(dek.as_bytes(), &aad.to_bytes(), &ct);

        out_wire.clear();
        out_wire.reserve(header.expected_wire_len());
        out_wire.put_slice(&header_bytes);
        out_wire.put_slice(&ct);
        out_wire.put_slice(&tag);
        Ok(header)
    }

    fn decrypt_chunk_into(
        &self,
        dek: &DekBytes,
        expected_file_id: Uuid,
        expected_chunk_index: Option<u64>,
        wire_chunk: &[u8],
        out_plaintext: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader> {
        let _ = self.require_unlocked()?;
        let header = ChunkHeader::decode(wire_chunk)?;
        if let Some(expected_idx) = expected_chunk_index
            && header.chunk_index != expected_idx
        {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "chunk index mismatch: expected {expected_idx}, got {}",
                header.chunk_index
            )));
        }
        if wire_chunk.len() != header.expected_wire_len() {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wire chunk length does not match header plaintext_len".into(),
            ));
        }

        let ct_end = CHUNK_HEADER_LEN + (header.plaintext_len as usize);
        let ct = &wire_chunk[CHUNK_HEADER_LEN..ct_end];
        let tag = &wire_chunk[ct_end..];
        let aad = ChunkAad {
            file_id: expected_file_id,
            chunk_index: header.chunk_index,
            is_final_chunk: header.is_final_chunk,
        };
        let expected_tag = keyed_tag(dek.as_bytes(), &aad.to_bytes(), ct);
        if tag != expected_tag {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "mock chunk AEAD tag mismatch".into(),
            ));
        }

        let pt = xor_keystream(dek.as_bytes(), &header.nonce, ct);
        out_plaintext.clear();
        out_plaintext.extend_from_slice(&pt);
        Ok(header)
    }

    fn seal_manifest(&self, manifest: &VaultManifest) -> ZeroVaultResult<Bytes> {
        let master = self.require_unlocked()?;
        let payload = postcard::to_allocvec(manifest)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?;
        let nonce = self.next_nonce();
        let hdr = ManifestWireHeader {
            version: MANIFEST_FORMAT_VERSION,
            vault_id: manifest.vault_id,
            revision: manifest.revision,
            nonce,
        };
        let ct = xor_keystream(&master, &nonce, &payload);
        let tag = keyed_tag(
            &master,
            &VaultManifest::manifest_aad(manifest.vault_id, manifest.revision),
            &ct,
        );
        let mut out = BytesMut::with_capacity(MANIFEST_HEADER_LEN + ct.len() + AES_GCM_TAG_LEN);
        out.put_slice(&hdr.encode());
        out.put_slice(&ct);
        out.put_slice(&tag);
        Ok(out.freeze())
    }

    fn open_manifest(&self, sealed_bytes: &[u8]) -> ZeroVaultResult<VaultManifest> {
        let master = self.require_unlocked()?;
        let hdr = ManifestWireHeader::decode(sealed_bytes)?;
        let ct_end = sealed_bytes.len() - AES_GCM_TAG_LEN;
        let ct = &sealed_bytes[MANIFEST_HEADER_LEN..ct_end];
        let tag = &sealed_bytes[ct_end..];
        let expected_tag = keyed_tag(
            &master,
            &VaultManifest::manifest_aad(hdr.vault_id, hdr.revision),
            ct,
        );
        if tag != expected_tag {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "mock manifest tag mismatch".into(),
            ));
        }
        let pt = xor_keystream(&master, &hdr.nonce, ct);
        postcard::from_bytes(&pt)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(format!("manifest decode error: {e}")))
    }

    fn wrap_token_payload(&self, plaintext: &[u8]) -> ZeroVaultResult<Vec<u8>> {
        let master = self.require_unlocked()?;
        let nonce = self.next_nonce();
        let ct = xor_keystream(&master, &nonce, plaintext);
        let tag = keyed_tag(&master, b"zerovault.v1.token-wrap", &ct);
        let mut out = Vec::with_capacity(AES_GCM_NONCE_LEN + ct.len() + AES_GCM_TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn unwrap_token_payload(&self, wrapped: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
        let master = self.require_unlocked()?;
        if wrapped.len() < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wrapped token too short".into(),
            ));
        }
        let nonce: [u8; 12] = wrapped[0..12]
            .try_into()
            .map_err(|_| ZeroVaultError::CryptoTamperDetected("invalid token nonce".into()))?;
        let ct_end = wrapped.len() - AES_GCM_TAG_LEN;
        let ct = &wrapped[12..ct_end];
        let tag = &wrapped[ct_end..];
        if tag != keyed_tag(&master, b"zerovault.v1.token-wrap", ct) {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wrapped token tag mismatch".into(),
            ));
        }
        Ok(Zeroizing::new(xor_keystream(&master, &nonce, ct)))
    }

    fn benchmark_aes256_gcm(&self, total_mib: usize) -> ZeroVaultResult<CryptoBenchmarkReport> {
        Ok(CryptoBenchmarkReport {
            caps: self.verify_hardware_acceleration()?,
            total_mib,
            encrypt_mib_per_sec: 1000.0,
            decrypt_mib_per_sec: 1000.0,
            encrypt_elapsed_ms: 1,
            decrypt_elapsed_ms: 1,
        })
    }
}

/// Thread-safe in-memory secret store for tests.
#[derive(Debug, Default)]
pub struct InMemorySecretStore {
    entries: DashMap<(String, String), Zeroizing<Vec<u8>>>,
}

#[async_trait]
impl SecretStore for InMemorySecretStore {
    async fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> ZeroVaultResult<()> {
        self.entries.insert(
            (service.to_owned(), account.to_owned()),
            Zeroizing::new(secret.to_vec()),
        );
        Ok(())
    }

    async fn get_secret(
        &self,
        service: &str,
        account: &str,
    ) -> ZeroVaultResult<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .entries
            .get(&(service.to_owned(), account.to_owned()))
            .map(|v| v.clone()))
    }

    async fn delete_secret(&self, service: &str, account: &str) -> ZeroVaultResult<()> {
        self.entries
            .remove(&(service.to_owned(), account.to_owned()));
        Ok(())
    }
}

/// Thread-safe in-memory multi-cloud storage router test double.
#[derive(Debug)]
pub struct MockStorageRouter {
    objects: DashMap<String, (Bytes, String)>,
    backend_id: BackendId,
    quota_total: u64,
    used: AtomicU64,
}

impl Default for MockStorageRouter {
    fn default() -> Self {
        Self::new("mock-cloud-0", 10 * 1024 * 1024 * 1024)
    }
}

impl MockStorageRouter {
    /// Creates an in-memory storage router double with the given ID and quota cap.
    #[must_use]
    pub fn new(backend_id: impl Into<String>, quota_total: u64) -> Self {
        Self {
            objects: DashMap::new(),
            backend_id: backend_id.into(),
            quota_total,
            used: AtomicU64::new(0),
        }
    }

    /// Lists all stored remote object keys (for verifying zero-knowledge paths in tests).
    #[must_use]
    pub fn list_keys(&self) -> Vec<String> {
        self.objects.iter().map(|e| e.key().clone()).collect()
    }
}

#[async_trait]
impl StorageRouterTrait for MockStorageRouter {
    async fn put_blob(
        &self,
        _virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement> {
        validate_remote_object_key(object_key)?;
        let len = ciphertext.len();
        let new_used = self.used.fetch_add(len as u64, Ordering::Relaxed) + len as u64;
        if new_used > self.quota_total {
            self.used.fetch_sub(len as u64, Ordering::Relaxed);
            return Err(ZeroVaultError::StorageQuotaExceeded(self.backend_id.clone()));
        }
        let etag = Uuid::new_v4().to_string();
        self.objects
            .insert(object_key.to_owned(), (ciphertext, etag.clone()));
        Ok(BlobPlacement {
            object_key: object_key.to_owned(),
            replicas: vec![ReplicaTarget {
                backend_id: self.backend_id.clone(),
                etag: Some(etag),
            }],
            bytes_written: len,
        })
    }

    async fn get_blob(
        &self,
        object_key: &str,
        _preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes> {
        validate_remote_object_key(object_key)?;
        self.objects
            .get(object_key)
            .map(|entry| entry.value().0.clone())
            .ok_or_else(|| ZeroVaultError::StorageNotFound(object_key.to_owned()))
    }

    async fn delete_blob(
        &self,
        object_key: &str,
        _backends: &[BackendId],
    ) -> ZeroVaultResult<()> {
        validate_remote_object_key(object_key)?;
        if let Some((_, (bytes, _))) = self.objects.remove(object_key) {
            self.used.fetch_sub(bytes.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn stat_object(
        &self,
        object_key: &str,
        _preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>> {
        validate_remote_object_key(object_key)?;
        Ok(self.objects.get(object_key).map(|entry| RemoteVersion {
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
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion> {
        validate_remote_object_key(object_key)?;
        if let Some(expected) = expected_etag
            && let Some(existing) = self.objects.get(object_key)
            && existing.value().1 != expected
        {
            return Err(ZeroVaultError::StorageConflict(format!(
                "manifest ETag mismatch for {object_key}"
            )));
        }
        let len = sealed_manifest.len() as u64;
        let etag = Uuid::new_v4().to_string();
        self.objects
            .insert(object_key.to_owned(), (sealed_manifest, etag.clone()));
        Ok(RemoteVersion {
            object_key: object_key.to_owned(),
            etag: Some(etag),
            content_length: len,
            last_modified: Some(Utc::now()),
        })
    }

    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>> {
        let used = self.used.load(Ordering::Relaxed);
        Ok(vec![BackendHealth {
            backend_id: self.backend_id.clone(),
            kind: BackendKind::Memory,
            healthy: true,
            latency_ms: Some(1),
            last_error: None,
            quota: BackendQuota {
                backend_id: self.backend_id.clone(),
                total_bytes: self.quota_total,
                used_bytes: used,
                available_bytes: self.quota_total.saturating_sub(used),
            },
        }])
    }

    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota> {
        let used = self.used.load(Ordering::Relaxed);
        Ok(BackendQuota {
            backend_id: "pool-total".to_owned(),
            total_bytes: self.quota_total,
            used_bytes: used,
            available_bytes: self.quota_total.saturating_sub(used),
        })
    }

    fn routing_policy(&self) -> RoutingPolicy {
        RoutingPolicy::Targeted {
            prefix_routes: Vec::new(),
            default_backend: self.backend_id.clone(),
        }
    }
}

/// Thread-safe in-memory metadata store double.
#[derive(Debug)]
pub struct MockMetadataStore {
    inodes: RwLock<BTreeMap<InodeId, InodeRecord>>,
    chunks: RwLock<HashMap<InodeId, Vec<ChunkDescriptor>>>,
    dirty: Mutex<Vec<DirtyOp>>,
    conflicts: Mutex<Vec<ConflictRecord>>,
    next_inode: AtomicU64,
    next_dirty_id: AtomicU64,
    manifest_cursor: RwLock<(u64, Option<String>)>,
}

impl Default for MockMetadataStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMetadataStore {
    /// Creates an initialized metadata store containing the root `/` directory at inode `1`.
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();
        let mut inodes = BTreeMap::new();
        inodes.insert(
            ROOT_INODE,
            InodeRecord {
                inode: ROOT_INODE,
                parent_inode: ROOT_INODE,
                file_id: Uuid::nil(),
                name: String::new(),
                virtual_path: "/".to_owned(),
                kind: EntryKind::Directory,
                size: 0,
                mode: 0o755,
                hydration: HydrationState::Pinned,
                pinned: true,
                version: 1,
                wrapped_dek: None,
                modified_at: now,
                created_at: now,
            },
        );
        Self {
            inodes: RwLock::new(inodes),
            chunks: RwLock::new(HashMap::new()),
            dirty: Mutex::new(Vec::new()),
            conflicts: Mutex::new(Vec::new()),
            next_inode: AtomicU64::new(ROOT_INODE + 1),
            next_dirty_id: AtomicU64::new(1),
            manifest_cursor: RwLock::new((0, None)),
        }
    }
}

#[async_trait]
impl MetadataStore for MockMetadataStore {
    async fn get_inode(&self, inode: InodeId) -> ZeroVaultResult<Option<InodeRecord>> {
        Ok(self.inodes.read().get(&inode).cloned())
    }

    async fn lookup_child(
        &self,
        parent_inode: InodeId,
        name: &str,
    ) -> ZeroVaultResult<Option<InodeRecord>> {
        Ok(self
            .inodes
            .read()
            .values()
            .find(|r| r.inode != ROOT_INODE && r.parent_inode == parent_inode && r.name == name)
            .cloned())
    }

    async fn get_by_path(&self, virtual_path: &str) -> ZeroVaultResult<Option<InodeRecord>> {
        Ok(self
            .inodes
            .read()
            .values()
            .find(|r| r.virtual_path == virtual_path)
            .cloned())
    }

    async fn list_children(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
        Ok(self
            .inodes
            .read()
            .values()
            .filter(|r| r.inode != ROOT_INODE && r.parent_inode == parent_inode)
            .cloned()
            .collect())
    }

    async fn upsert_inode(&self, record: InodeRecord) -> ZeroVaultResult<InodeRecord> {
        self.inodes.write().insert(record.inode, record.clone());
        Ok(record)
    }

    async fn allocate_inode_id(&self) -> ZeroVaultResult<InodeId> {
        Ok(self.next_inode.fetch_add(1, Ordering::Relaxed))
    }

    async fn delete_inode(&self, inode: InodeId) -> ZeroVaultResult<()> {
        self.inodes.write().remove(&inode);
        self.chunks.write().remove(&inode);
        Ok(())
    }

    async fn replace_chunks(
        &self,
        inode: InodeId,
        chunks: Vec<ChunkDescriptor>,
    ) -> ZeroVaultResult<()> {
        self.chunks.write().insert(inode, chunks);
        Ok(())
    }

    async fn list_chunks(&self, inode: InodeId) -> ZeroVaultResult<Vec<ChunkDescriptor>> {
        Ok(self.chunks.read().get(&inode).cloned().unwrap_or_default())
    }

    async fn set_chunk_hydrated(
        &self,
        inode: InodeId,
        chunk_index: u64,
        hydrated: bool,
    ) -> ZeroVaultResult<()> {
        let mut chunks_guard = self.chunks.write();
        let list = chunks_guard
            .get_mut(&inode)
            .ok_or(ZeroVaultError::InodeNotFound(inode))?;
        for c in list.iter_mut() {
            if c.chunk_index == chunk_index {
                c.locally_hydrated = hydrated;
            }
        }
        let all_hydrated = !list.is_empty() && list.iter().all(|c| c.locally_hydrated);
        let any_hydrated = list.iter().any(|c| c.locally_hydrated);
        drop(chunks_guard);

        let mut inodes_guard = self.inodes.write();
        if let Some(rec) = inodes_guard.get_mut(&inode)
            && !rec.pinned
            && rec.hydration != HydrationState::DirtyLocal
        {
            rec.hydration = if all_hydrated {
                HydrationState::LocallyCached
            } else if any_hydrated {
                HydrationState::PartiallyHydrated
            } else {
                HydrationState::OnlineOnly
            };
        }
        Ok(())
    }

    async fn set_hydration_and_pin(
        &self,
        inode: InodeId,
        hydration: HydrationState,
        pinned: bool,
    ) -> ZeroVaultResult<()> {
        let mut guard = self.inodes.write();
        let rec = guard
            .get_mut(&inode)
            .ok_or(ZeroVaultError::InodeNotFound(inode))?;
        rec.hydration = hydration;
        rec.pinned = pinned;
        Ok(())
    }

    async fn enqueue_dirty(
        &self,
        inode: InodeId,
        kind: DirtyOpKind,
        virtual_path: &str,
    ) -> ZeroVaultResult<i64> {
        let id = self.next_dirty_id.fetch_add(1, Ordering::Relaxed) as i64;
        self.dirty.lock().push(DirtyOp {
            id,
            inode,
            kind,
            virtual_path: virtual_path.to_owned(),
            retry_count: 0,
            last_error: None,
            queued_at: Utc::now(),
        });
        Ok(id)
    }

    async fn list_dirty_ops(&self) -> ZeroVaultResult<Vec<DirtyOp>> {
        Ok(self.dirty.lock().clone())
    }

    async fn complete_dirty_op(&self, id: i64) -> ZeroVaultResult<()> {
        self.dirty.lock().retain(|op| op.id != id);
        Ok(())
    }

    async fn mark_dirty_retry(&self, id: i64, error: &str) -> ZeroVaultResult<()> {
        if let Some(op) = self.dirty.lock().iter_mut().find(|o| o.id == id) {
            op.retry_count += 1;
            op.last_error = Some(error.to_owned());
        }
        Ok(())
    }

    async fn manifest_cursor(&self) -> ZeroVaultResult<(u64, Option<String>)> {
        Ok(self.manifest_cursor.read().clone())
    }

    async fn update_manifest_cursor(
        &self,
        revision: u64,
        remote_etag: Option<String>,
    ) -> ZeroVaultResult<()> {
        *self.manifest_cursor.write() = (revision, remote_etag);
        Ok(())
    }

    async fn list_all_inodes(&self) -> ZeroVaultResult<Vec<InodeRecord>> {
        Ok(self.inodes.read().values().cloned().collect())
    }

    async fn record_conflict(&self, conflict: ConflictRecord) -> ZeroVaultResult<()> {
        self.conflicts.lock().push(conflict);
        Ok(())
    }

    async fn list_conflicts(&self) -> ZeroVaultResult<Vec<ConflictRecord>> {
        Ok(self.conflicts.lock().clone())
    }
}

/// Thread-safe in-memory [`VfsBackend`] double for standalone Windows/Linux VFS adapter tests.
#[derive(Debug)]
pub struct MockVfsBackend {
    meta: MockMetadataStore,
    contents: RwLock<HashMap<InodeId, Vec<u8>>>,
    stats: RwLock<DriveStats>,
}

impl Default for MockVfsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockVfsBackend {
    /// Creates an empty virtual filesystem backend with `/` at inode `1`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            meta: MockMetadataStore::new(),
            contents: RwLock::new(HashMap::new()),
            stats: RwLock::new(DriveStats::default()),
        }
    }

    /// Seeds a synthetic remote online-only file for testing on-demand hydration in VFS adapters.
    pub async fn seed_remote_file(
        &self,
        parent_inode: InodeId,
        name: &str,
        data: &[u8],
    ) -> ZeroVaultResult<InodeRecord> {
        let parent = self
            .meta
            .get_inode(parent_inode)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(parent_inode))?;
        let inode = self.meta.allocate_inode_id().await?;
        let now = Utc::now();
        let vpath = if parent.virtual_path == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", parent.virtual_path)
        };
        let rec = InodeRecord {
            inode,
            parent_inode,
            file_id: Uuid::new_v4(),
            name: name.to_owned(),
            virtual_path: vpath,
            kind: EntryKind::File,
            size: data.len() as u64,
            mode: 0o644,
            hydration: HydrationState::OnlineOnly,
            pinned: false,
            version: 1,
            wrapped_dek: None,
            modified_at: now,
            created_at: now,
        };
        self.meta.upsert_inode(rec.clone()).await?;
        self.contents.write().insert(inode, data.to_vec());
        Ok(rec)
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

fn join_vpath(parent_path: &str, name: &str) -> String {
    if parent_path == "/" {
        format!("/{name}")
    } else {
        format!("{parent_path}/{name}")
    }
}

#[async_trait]
impl VfsBackend for MockVfsBackend {
    async fn getattr(&self, inode: InodeId) -> ZeroVaultResult<InodeRecord> {
        self.meta
            .get_inode(inode)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(inode))
    }

    async fn lookup(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<InodeRecord> {
        validate_entry_name(name)?;
        self.meta
            .lookup_child(parent_inode, name)
            .await?
            .ok_or(ZeroVaultError::InodeNotFound(parent_inode))
    }

    async fn resolve_path(&self, virtual_path: &str) -> ZeroVaultResult<InodeRecord> {
        let norm = if virtual_path.is_empty() {
            "/"
        } else {
            virtual_path
        };
        self.meta
            .get_by_path(norm)
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
        let rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(inode));
        }
        let Some(span) = chunk_span_for_range(offset, len, rec.size)? else {
            return Ok(Bytes::new());
        };
        let slice = {
            let guard = self.contents.read();
            let buf = guard.get(&inode).map(Vec::as_slice).unwrap_or(&[]);
            let start = offset as usize;
            let end = (start + span.readable_len).min(buf.len());
            Bytes::copy_from_slice(&buf[start..end])
        };
        {
            let mut stats = self.stats.write();
            stats.bytes_read += slice.len() as u64;
            stats.chunks_hydrated += span.slices.len() as u64;
        }
        if rec.hydration == HydrationState::OnlineOnly {
            let _ = self
                .meta
                .set_hydration_and_pin(inode, HydrationState::PartiallyHydrated, rec.pinned)
                .await;
        }
        Ok(slice)
    }

    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize> {
        let mut rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(inode));
        }
        let end = offset as usize + data.len();
        {
            let mut guard = self.contents.write();
            let buf = guard.entry(inode).or_default();
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[offset as usize..end].copy_from_slice(data);
            rec.size = buf.len() as u64;
        }
        rec.hydration = HydrationState::DirtyLocal;
        rec.modified_at = Utc::now();
        rec.version += 1;
        self.meta.upsert_inode(rec).await?;
        self.stats.write().bytes_written += data.len() as u64;
        Ok(data.len())
    }

    async fn create_entry(&self, spec: CreateEntrySpec) -> ZeroVaultResult<InodeRecord> {
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
        let rec = InodeRecord {
            inode,
            parent_inode: spec.parent_inode,
            file_id: Uuid::new_v4(),
            virtual_path: join_vpath(&parent.virtual_path, &spec.name),
            name: spec.name,
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
        self.contents.write().insert(inode, Vec::new());
        self.meta.upsert_inode(rec).await
    }

    async fn mkdir(
        &self,
        parent_inode: InodeId,
        name: &str,
        mode: u32,
    ) -> ZeroVaultResult<InodeRecord> {
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
        let rec = InodeRecord {
            inode,
            parent_inode,
            file_id: Uuid::new_v4(),
            virtual_path: join_vpath(&parent.virtual_path, name),
            name: name.to_owned(),
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
        self.meta.upsert_inode(rec).await
    }

    async fn unlink(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        let entry = self.lookup(parent_inode, name).await?;
        if entry.kind == EntryKind::Directory {
            return Err(ZeroVaultError::IsADirectory(entry.inode));
        }
        self.contents.write().remove(&entry.inode);
        self.meta.delete_inode(entry.inode).await
    }

    async fn rmdir(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()> {
        let entry = self.lookup(parent_inode, name).await?;
        if entry.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(entry.inode));
        }
        if !self.meta.list_children(entry.inode).await?.is_empty() {
            return Err(ZeroVaultError::DirectoryNotEmpty(entry.inode));
        }
        self.meta.delete_inode(entry.inode).await
    }

    async fn rename(
        &self,
        parent_inode: InodeId,
        name: &str,
        new_parent_inode: InodeId,
        new_name: &str,
    ) -> ZeroVaultResult<InodeRecord> {
        validate_entry_name(new_name)?;
        let new_parent = self.getattr(new_parent_inode).await?;
        if new_parent.kind != EntryKind::Directory {
            return Err(ZeroVaultError::NotADirectory(new_parent_inode));
        }
        let mut entry = self.lookup(parent_inode, name).await?;
        entry.parent_inode = new_parent_inode;
        entry.name = new_name.to_owned();
        entry.virtual_path = join_vpath(&new_parent.virtual_path, new_name);
        entry.modified_at = Utc::now();
        entry.version += 1;
        self.meta.upsert_inode(entry).await
    }

    async fn setattr(&self, inode: InodeId, attrs: SetAttrSpec) -> ZeroVaultResult<InodeRecord> {
        let mut rec = self.getattr(inode).await?;
        if let Some(new_size) = attrs.size {
            if rec.kind == EntryKind::Directory {
                return Err(ZeroVaultError::IsADirectory(inode));
            }
            let mut guard = self.contents.write();
            let buf = guard.entry(inode).or_default();
            buf.resize(new_size as usize, 0);
            rec.size = new_size;
            rec.hydration = HydrationState::DirtyLocal;
        }
        if let Some(mode) = attrs.mode {
            rec.mode = mode;
        }
        if let Some(mtime) = attrs.modified_at {
            rec.modified_at = mtime;
        }
        rec.version += 1;
        self.meta.upsert_inode(rec).await
    }

    async fn flush(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let mut rec = self.getattr(inode).await?;
        if rec.hydration == HydrationState::DirtyLocal {
            rec.hydration = if rec.pinned {
                HydrationState::Pinned
            } else {
                HydrationState::LocallyCached
            };
            self.meta.upsert_inode(rec).await?;
        }
        Ok(())
    }

    async fn fsync(&self, inode: InodeId, _datasync: bool) -> ZeroVaultResult<()> {
        self.flush(inode).await
    }

    async fn pin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let rec = self.getattr(inode).await?;
        if rec.kind == EntryKind::File {
            let _ = self.read_range(inode, 0, rec.size as usize).await?;
        }
        self.meta
            .set_hydration_and_pin(inode, HydrationState::Pinned, true)
            .await
    }

    async fn unpin(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let rec = self.getattr(inode).await?;
        let next = if rec.hydration == HydrationState::Pinned {
            if rec.size == 0 {
                HydrationState::OnlineOnly
            } else {
                HydrationState::LocallyCached
            }
        } else {
            rec.hydration
        };
        self.meta.set_hydration_and_pin(inode, next, false).await
    }

    async fn dehydrate(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let rec = self.getattr(inode).await?;
        if rec.pinned {
            return Err(ZeroVaultError::PinnedDehydrationDenied(inode));
        }
        self.meta
            .set_hydration_and_pin(inode, HydrationState::OnlineOnly, false)
            .await
    }

    async fn get_xattr_state(&self, inode: InodeId) -> ZeroVaultResult<HydrationState> {
        Ok(self.getattr(inode).await?.hydration)
    }

    async fn drive_stats(&self) -> ZeroVaultResult<DriveStats> {
        Ok(self.stats.read().clone())
    }
}
