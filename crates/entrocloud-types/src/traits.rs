use std::path::PathBuf;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ZeroVaultResult;
use crate::sharing::{
    CapabilityUri, RecipientPrivateIdentity, RecipientPublicBundle, ShareDescriptor, SignedKeybox,
    SignedShareEnvelope,
};
use crate::wire::{
    ChunkAad, ChunkHeader, DekBytes, KdfParams, RedactedSecret, VaultHeader, VaultManifest,
    WrappedDek,
};

/// Canonical virtual inode numeric identifier (`1` is always root `/`).
pub type InodeId = u64;

/// Root directory virtual inode identifier (matches FUSE `FUSE_ROOT_ID = 1`).
pub const ROOT_INODE: InodeId = 1;

/// Cloud backend identifier string (e.g. `"gdrive-personal"`, `"s3-archive"`).
pub type BackendId = String;

/// Runtime CPU hardware acceleration capabilities detected via CPUID / feature registers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareCryptoCaps {
    /// Target architecture string (e.g. `"x86_64"`, `"aarch64"`).
    pub arch: String,
    /// Hardware AES instructions present (`AES-NI` on x86_64; `AES` on ARMv8).
    pub aes_hw: bool,
    /// Hardware carry-less multiplication for GHASH (`PCLMULQDQ` on x86_64; `PMULL` on ARMv8).
    pub pclmul_hw: bool,
    /// Vector AES (`VAES`) present on x86_64.
    pub vaes_hw: bool,
    /// AVX2 support present on x86_64.
    pub avx2_hw: bool,
    /// Whether mandatory hardware crypto requirements are satisfied.
    pub mandatory_satisfied: bool,
    /// Active AEAD engine implementation label.
    pub backend_name: String,
}

/// Result of a 4 MiB AES-256-GCM hardware throughput benchmark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoBenchmarkReport {
    /// Detected CPU hardware capabilities.
    pub caps: HardwareCryptoCaps,
    /// Total MiB encrypted and decrypted during the benchmark.
    pub total_mib: usize,
    /// Encryption throughput in MiB/s.
    pub encrypt_mib_per_sec: f64,
    /// Decryption + tag verification throughput in MiB/s.
    pub decrypt_mib_per_sec: f64,
    /// Elapsed wall-clock milliseconds for encrypt phase.
    pub encrypt_elapsed_ms: u64,
    /// Elapsed wall-clock milliseconds for decrypt phase.
    pub decrypt_elapsed_ms: u64,
}

/// Cross-crate zero-knowledge cryptographic engine interface.
#[async_trait]
pub trait CryptoEngine: Send + Sync {
    /// Checks CPUID / OS registers for mandatory hardware AES + GHASH acceleration.
    fn verify_hardware_acceleration(&self) -> ZeroVaultResult<HardwareCryptoCaps>;

    /// Returns `true` while master key hierarchy is active in memory.
    fn is_unlocked(&self) -> bool;

    /// Returns the unlocked vault UUID if unlocked.
    fn vault_id(&self) -> Option<Uuid>;

    /// Initializes a brand-new vault header (`ZVH1`) and unlocks key material in memory.
    async fn init_vault(
        &self,
        passphrase: &RedactedSecret,
        kdf: KdfParams,
    ) -> ZeroVaultResult<VaultHeader>;

    /// Derives keys via Argon2id + HKDF-SHA256, verifies `header` tag, and unlocks in memory.
    async fn unlock_with_passphrase(
        &self,
        header: &VaultHeader,
        passphrase: &RedactedSecret,
    ) -> ZeroVaultResult<()>;

    /// Unlocks a vault directly from a 256-bit `FolderRootKey` unwrapped from `keybox.zv`.
    fn unlock_with_folder_key(&self, vault_id: Uuid, folder_root_key: &[u8; 32])
    -> ZeroVaultResult<()>;

    /// Exports the active 256-bit root seed/key for wrapping into `keybox.zv` stanzas.
    fn export_folder_root_key(&self) -> ZeroVaultResult<Zeroizing<[u8; 32]>>;

    /// Zeroizes all in-memory master keys immediately.
    async fn lock_vault(&self) -> ZeroVaultResult<()>;

    /// Persists AEAD-wrapped session key material (`ZVS2`) into the OS secret store.
    async fn persist_session(&self, store: &dyn SecretStore, service: &str)
    -> ZeroVaultResult<()>;

    /// Attempts to restore an unlocked session from the OS secret store.
    async fn restore_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
        expected_vault_id: Uuid,
    ) -> ZeroVaultResult<bool>;

    /// Generates a fresh 256-bit per-file DEK using a CSPRNG.
    fn generate_dek(&self) -> ZeroVaultResult<DekBytes>;

    /// Wraps a per-file DEK with the unlocked `MasterKek`, binding `file_id` into AAD.
    fn wrap_dek(&self, file_id: Uuid, dek: &DekBytes) -> ZeroVaultResult<WrappedDek>;

    /// Unwraps and authenticates a per-file DEK using `MasterKek` and `file_id` AAD.
    fn unwrap_dek(&self, file_id: Uuid, wrapped: &WrappedDek) -> ZeroVaultResult<DekBytes>;

    /// Encrypts a 4 MiB (or final) plaintext chunk into a reusable `BytesMut` wire buffer.
    fn encrypt_chunk_into(
        &self,
        dek: &DekBytes,
        aad: ChunkAad,
        plaintext: &[u8],
        out_wire: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader>;

    /// Convenience wrapper returning an immutable `Bytes` wire chunk.
    fn encrypt_chunk(
        &self,
        dek: &DekBytes,
        aad: ChunkAad,
        plaintext: &[u8],
    ) -> ZeroVaultResult<(ChunkHeader, Bytes)> {
        let mut buf = BytesMut::with_capacity(
            crate::wire::CHUNK_HEADER_LEN + plaintext.len() + crate::wire::AES_GCM_TAG_LEN,
        );
        let hdr = self.encrypt_chunk_into(dek, aad, plaintext, &mut buf)?;
        Ok((hdr, buf.freeze()))
    }

    /// Decrypts and verifies a `.zv` wire chunk into a reusable `BytesMut` plaintext buffer.
    /// MUST fail closed with [`crate::ZeroVaultError::CryptoTamperDetected`] on any mismatch.
    fn decrypt_chunk_into(
        &self,
        dek: &DekBytes,
        expected_file_id: Uuid,
        expected_chunk_index: Option<u64>,
        wire_chunk: &[u8],
        out_plaintext: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader>;

    /// Convenience wrapper returning decrypted plaintext bytes after AEAD verification.
    fn decrypt_chunk(
        &self,
        dek: &DekBytes,
        expected_file_id: Uuid,
        expected_chunk_index: Option<u64>,
        wire_chunk: &[u8],
    ) -> ZeroVaultResult<(ChunkHeader, Bytes)> {
        let mut out = BytesMut::new();
        let hdr = self.decrypt_chunk_into(
            dek,
            expected_file_id,
            expected_chunk_index,
            wire_chunk,
            &mut out,
        )?;
        Ok((hdr, out.freeze()))
    }

    /// Serializes and encrypts a [`VaultManifest`] into a `ZVM1` wire envelope.
    fn seal_manifest(&self, manifest: &VaultManifest) -> ZeroVaultResult<Bytes>;

    /// Verifies AEAD tag and deserializes a `ZVM1` wire envelope into a [`VaultManifest`].
    fn open_manifest(&self, sealed_bytes: &[u8]) -> ZeroVaultResult<VaultManifest>;

    /// Encrypts an arbitrary OAuth token payload under `TokenWrapKey`.
    fn wrap_token_payload(&self, plaintext: &[u8]) -> ZeroVaultResult<Vec<u8>>;

    /// Decrypts and authenticates an OAuth token payload under `TokenWrapKey`.
    fn unwrap_token_payload(&self, wrapped: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>>;

    /// Encrypts local SQLite metadata (filenames, conflict paths, dirty-op hints) under `MetadataKey`.
    fn seal_metadata(&self, aad: &[u8], plaintext: &[u8]) -> ZeroVaultResult<Vec<u8>>;

    /// Decrypts and authenticates local SQLite metadata under `MetadataKey`.
    fn open_metadata(&self, aad: &[u8], ciphertext: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>>;

    /// Computes a deterministic keyed `BLAKE3` blind index for `(parent_inode, name)` SQLite lookups.
    fn compute_blind_index(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<[u8; 32]>;

    /// Encrypts a local dirty chunk `.zvpart` file under `StagingKey` with `(inode, chunk_index)` AAD.
    fn seal_staging_chunk(
        &self,
        inode: InodeId,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> ZeroVaultResult<Vec<u8>>;

    /// Decrypts and verifies a local dirty chunk `.zvpart` file under `StagingKey`.
    fn open_staging_chunk(
        &self,
        inode: InodeId,
        chunk_index: u64,
        sealed: &[u8],
    ) -> ZeroVaultResult<Zeroizing<Vec<u8>>>;

    /// Generates a fresh post-quantum hybrid recipient identity (`Ed25519` + `X25519` + `ML-KEM-768`).
    fn generate_recipient_identity(&self, label: &str)
    -> ZeroVaultResult<RecipientPrivateIdentity>;

    /// Creates a signed `zv://` read-only capability share envelope + URI for a file.
    fn create_capability_share(
        &self,
        owner_identity: &RecipientPrivateIdentity,
        backend_hint: &str,
        root_locator: &str,
        file_dek: &DekBytes,
        descriptor: &ShareDescriptor,
    ) -> ZeroVaultResult<(CapabilityUri, SignedShareEnvelope)>;

    /// Verifies `Ed25519` signature + decrypts a `zv://` share envelope, returning `(ShareDescriptor, DekBytes)`.
    fn open_capability_share(
        &self,
        uri: &CapabilityUri,
        envelope: &SignedShareEnvelope,
    ) -> ZeroVaultResult<(ShareDescriptor, DekBytes)>;

    /// Seals and signs a multi-recipient `keybox.zv` (`Ed25519` + `X25519` + `ML-KEM-768`) at `epoch`.
    fn seal_keybox(
        &self,
        owner_identity: &RecipientPrivateIdentity,
        vault_id: Uuid,
        epoch: u64,
        folder_root_key: &[u8; 32],
        recipients: &[RecipientPublicBundle],
    ) -> ZeroVaultResult<SignedKeybox>;

    /// Verifies `Ed25519` signature, optional `expected_vault_id`, optional pinned
    /// `expected_owner_pubkey`, and `epoch >= min_epoch_floor` on a `SignedKeybox` without
    /// requiring recipient decapsulation (`W4-VETO-KEYBOX-SIG` remediation).
    fn verify_keybox_envelope(
        &self,
        keybox: &SignedKeybox,
        expected_vault_id: Option<Uuid>,
        expected_owner_pubkey: Option<&[u8; 32]>,
        min_epoch_floor: u64,
    ) -> ZeroVaultResult<()> {
        if keybox.epoch == 0 || keybox.epoch < min_epoch_floor {
            return Err(crate::error::ZeroVaultError::CryptoTamperDetected(format!(
                "keybox epoch rollback detected: got {}, floor {min_epoch_floor}",
                keybox.epoch
            )));
        }
        if let Some(vid) = expected_vault_id
            && keybox.vault_id != vid
        {
            return Err(crate::error::ZeroVaultError::CryptoTamperDetected(
                "keybox vault_id mismatch".into(),
            ));
        }
        if let Some(owner) = expected_owner_pubkey
            && &keybox.owner_ed25519_pubkey != owner
        {
            return Err(crate::error::ZeroVaultError::CryptoTamperDetected(
                "keybox owner Ed25519 pubkey mismatch".into(),
            ));
        }
        let _ = keybox.signing_transcript()?;
        for stanza in &keybox.stanzas {
            stanza.validate()?;
        }
        Ok(())
    }

    /// Verifies `Ed25519` signature, checks `epoch >= min_epoch_floor`, and decapsulates `FolderRootKey`.
    fn open_keybox(
        &self,
        keybox: &SignedKeybox,
        expected_owner_pubkey: Option<&[u8; 32]>,
        min_epoch_floor: u64,
        recipient_identity: &RecipientPrivateIdentity,
    ) -> ZeroVaultResult<Zeroizing<[u8; 32]>>;

    /// Benchmarks hardware-accelerated 4 MiB AES-256-GCM encryption/decryption throughput.
    fn benchmark_aes256_gcm(&self, total_mib: usize) -> ZeroVaultResult<CryptoBenchmarkReport>;
}

/// Abstract OS credential vault (Windows Credential Manager / Linux Secret Service / in-memory test).
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Stores a secret value under `(service, account)`.
    async fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> ZeroVaultResult<()>;

    /// Reads a secret value under `(service, account)`, returning `None` if absent.
    async fn get_secret(
        &self,
        service: &str,
        account: &str,
    ) -> ZeroVaultResult<Option<Zeroizing<Vec<u8>>>>;

    /// Deletes a stored secret if it exists.
    async fn delete_secret(&self, service: &str, account: &str) -> ZeroVaultResult<()>;
}

/// Supported cloud storage backend provider types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    /// Google Drive (`opendal::services::Gdrive`).
    GoogleDrive,
    /// Microsoft OneDrive (`opendal::services::Onedrive`).
    OneDrive,
    /// Dropbox (`opendal::services::Dropbox`).
    Dropbox,
    /// S3-compatible object storage (`opendal::services::S3`).
    S3,
    /// WebDAV server (`opendal::services::Webdav`).
    WebDav,
    /// Local directory backend (`opendal::services::Fs`, also used in integration tests).
    LocalFs,
    /// Volatile memory backend (`opendal::services::Memory`).
    Memory,
}

/// Declarative configuration for registering one cloud storage backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Stable user-assigned backend ID (e.g. `"gdrive-main"`).
    pub id: BackendId,
    /// Cloud provider type.
    pub kind: BackendKind,
    /// Optional root folder/prefix inside the remote bucket/drive.
    pub root: String,
    /// Optional endpoint URL (S3 / WebDAV).
    pub endpoint: Option<String>,
    /// Optional bucket / drive / region parameters.
    pub bucket: Option<String>,
    /// Optional region (S3).
    pub region: Option<String>,
    /// Optional hard quota limit in bytes (essential for Quota Pooling).
    pub quota_limit_bytes: Option<u64>,
    /// Minimum free headroom in bytes before spillover selects another backend.
    pub min_free_reserve_bytes: u64,
    /// Optional credentials / non-secret endpoint parameters; secrets belong in `SecretStore`.
    pub username: Option<String>,
    /// Redacted password or static access key if non-OAuth (S3/WebDAV).
    pub access_key_id: Option<String>,
    /// Secret access key wrapped in `RedactedSecret`.
    #[serde(skip)]
    pub secret_access_key: Option<RedactedSecret>,
    /// OAuth token account key inside `SecretStore`.
    pub secret_account_key: Option<String>,
}

/// Quota accounting snapshot for one storage backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendQuota {
    /// Backend identifier.
    pub backend_id: BackendId,
    /// Total configured or provider-reported capacity in bytes.
    pub total_bytes: u64,
    /// Estimated or provider-reported used bytes.
    pub used_bytes: u64,
    /// Remaining writable bytes (`total - used`).
    pub available_bytes: u64,
}

/// Health status of a configured storage backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendHealth {
    /// Backend identifier.
    pub backend_id: BackendId,
    /// Provider kind.
    pub kind: BackendKind,
    /// Whether recent requests succeeded.
    pub healthy: bool,
    /// Observed round-trip latency in milliseconds, if known.
    pub latency_ms: Option<u64>,
    /// Last non-sensitive error reason.
    pub last_error: Option<String>,
    /// Current quota view.
    pub quota: BackendQuota,
}

/// Multi-cloud placement policy controlling where encrypted blobs and manifests are written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingPolicy {
    /// Pin a virtual path prefix (or default subtree) to a single cloud backend.
    Targeted {
        /// Ordered prefix rules `(virtual_path_prefix, backend_id)`; longest match wins.
        prefix_routes: Vec<(String, BackendId)>,
        /// Fallback backend when no prefix matches.
        default_backend: BackendId,
    },
    /// RAID-1 mirroring: upload blobs concurrently to multiple clouds; read from fastest responder
    /// with automatic AEAD-verified replica failover.
    Mirrored {
        /// Replica cloud backends.
        backends: Vec<BackendId>,
        /// Minimum successful replica writes required to acknowledge `put_blob`.
        min_ack: usize,
    },
    /// Automatic spillover across multiple free-tier accounts based on remaining quota.
    QuotaPooled {
        /// Candidate pool backends ordered/ranked by free capacity.
        pool_backends: Vec<BackendId>,
    },
}

/// Target location of an uploaded remote blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaTarget {
    /// Owning backend identifier.
    pub backend_id: BackendId,
    /// Remote ETag or version string returned by the cloud provider, if any.
    pub etag: Option<String>,
}

/// Result returned by [`StorageRouterTrait::put_blob`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobPlacement {
    /// Canonical validated remote object key (`blobs/<2-hex>/<2-hex>/<uuid>.zv`).
    pub object_key: String,
    /// Replica targets that acknowledged the write.
    pub replicas: Vec<ReplicaTarget>,
    /// Encrypted byte size written.
    pub bytes_written: usize,
}

/// Metadata version information returned for optimistic manifest concurrency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteVersion {
    /// Remote object key.
    pub object_key: String,
    /// Provider ETag if supported.
    pub etag: Option<String>,
    /// Object length in bytes.
    pub content_length: u64,
    /// Provider last-modified timestamp if available.
    pub last_modified: Option<DateTime<Utc>>,
}

/// Multi-cloud storage router interface handling Targeted, Mirrored RAID-1, and Quota-Pooled I/O.
#[async_trait]
pub trait StorageRouterTrait: Send + Sync {
    /// Uploads an already-encrypted object matching strict zero-knowledge key rules.
    /// `virtual_hint_path` is used ONLY locally to evaluate Targeted prefix rules and is NEVER sent remotely.
    async fn put_blob(
        &self,
        virtual_hint_path: &str,
        object_key: &str,
        ciphertext: Bytes,
    ) -> ZeroVaultResult<BlobPlacement>;

    /// Downloads an encrypted object, racing healthy backends or using `preferred_backends` hints.
    async fn get_blob(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Bytes>;

    /// Downloads an encrypted object from a specific replica backend (enables AEAD-verified failover
    /// when the fastest mirror returns bit-rotted or tampered bytes — `NEW-M02` remediation).
    async fn get_blob_from_backend(
        &self,
        backend_id: &str,
        object_key: &str,
    ) -> ZeroVaultResult<Bytes> {
        self.get_blob(object_key, &[backend_id.to_owned()]).await
    }

    /// Returns ordered candidate replica backend IDs to try on AEAD verification failure.
    fn candidate_backends(&self, preferred_backends: &[BackendId]) -> Vec<BackendId> {
        preferred_backends.to_vec()
    }

    /// Deletes an encrypted object across specified or all configured backends.
    async fn delete_blob(
        &self,
        object_key: &str,
        backends: &[BackendId],
    ) -> ZeroVaultResult<()>;

    /// Reads object metadata (ETag / content length) without downloading full bytes.
    async fn stat_object(
        &self,
        object_key: &str,
        preferred_backends: &[BackendId],
    ) -> ZeroVaultResult<Option<RemoteVersion>>;

    /// Atomically publishes an encrypted manifest snapshot with optional expected ETag CAS guard.
    async fn put_manifest_cas(
        &self,
        object_key: &str,
        sealed_manifest: Bytes,
        expected_etag: Option<&str>,
    ) -> ZeroVaultResult<RemoteVersion>;

    /// Queries health and remaining quota across all configured backends.
    async fn list_backend_health(&self) -> ZeroVaultResult<Vec<BackendHealth>>;

    /// Queries total pooled capacity across all configured backends.
    async fn pooled_quota(&self) -> ZeroVaultResult<BackendQuota>;

    /// Returns the active routing policy.
    fn routing_policy(&self) -> RoutingPolicy;
}

/// Filesystem node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    /// Regular virtual file.
    File,
    /// Virtual directory.
    Directory,
}

/// On-demand hydration state for virtual files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HydrationState {
    /// Placeholder metadata only; zero chunks cached locally.
    OnlineOnly,
    /// Some 4 MiB chunks hydrated in local cache (e.g. partial seek/read).
    PartiallyHydrated,
    /// All chunks currently present in local cache, eligible for dehydration.
    LocallyCached,
    /// Explicitly pinned for offline availability; protected from auto-dehydration.
    Pinned,
    /// Local writes pending encryption/upload to remote backends.
    DirtyLocal,
}

impl HydrationState {
    /// Canonical string returned by Linux `user.zerovault.state` extended attribute.
    #[must_use]
    pub const fn as_xattr_str(self) -> &'static str {
        match self {
            Self::OnlineOnly => "online-only",
            Self::PartiallyHydrated => "partially-hydrated",
            Self::LocallyCached => "cached",
            Self::Pinned => "pinned",
            Self::DirtyLocal => "dirty",
        }
    }
}

/// Decrypted in-memory inode record returned by [`MetadataStore`] (stored encrypted on SQLite disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeRecord {
    /// Virtual inode number (`1` = root).
    pub inode: InodeId,
    /// Parent directory inode (`1` for root's parent).
    pub parent_inode: InodeId,
    /// Stable cryptographic file UUID.
    pub file_id: Uuid,
    /// Entry basename (encrypted in SQLite via `MetadataKey` + indexed via `BlindIndexKey`).
    pub name: String,
    /// Full normalized virtual path starting with `/` (e.g. `"/Finance/report.pdf"`).
    pub virtual_path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Plaintext byte size.
    pub size: u64,
    /// POSIX mode bits (`0o644` file, `0o755` dir).
    pub mode: u32,
    /// Current hydration state.
    pub hydration: HydrationState,
    /// Explicit offline pin flag.
    pub pinned: bool,
    /// Monotonic local/manifest node version.
    pub version: u64,
    /// Wrapped per-file DEK (for files).
    pub wrapped_dek: Option<WrappedDek>,
    /// Modification timestamp.
    pub modified_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Local SQLite metadata row mapping one 4 MiB chunk of a file inode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDescriptor {
    /// Owning virtual inode.
    pub inode: InodeId,
    /// Owning cryptographic file UUID.
    pub file_id: Uuid,
    /// Zero-based chunk ordinal.
    pub chunk_index: u64,
    /// Remote `.zv` blob UUID.
    pub blob_id: Uuid,
    /// Plaintext byte length of this chunk.
    pub plaintext_len: u32,
    /// Encrypted wire byte length of this chunk.
    pub ciphertext_len: u32,
    /// Plaintext BLAKE3 hash (encrypted in SQLite / manifest).
    pub blake3_plaintext: [u8; 32],
    /// Replica backend IDs holding this blob.
    pub backend_ids: Vec<BackendId>,
    /// Whether this chunk is currently hydrated in local disk/RAM cache.
    pub locally_hydrated: bool,
}

/// Pending offline/dirty mutation queued in SQLite WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirtyOpKind {
    /// File content created or modified and pending encrypted upload.
    UpsertFile,
    /// Directory created or entry metadata renamed/moved.
    UpsertMetadata,
    /// File or directory deleted locally.
    Delete,
}

/// Persistent queued sync operation row (virtual_path encrypted at rest in SQLite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyOp {
    /// Autoincrement queue row ID.
    pub id: i64,
    /// Affected virtual inode.
    pub inode: InodeId,
    /// Kind of mutation.
    pub kind: DirtyOpKind,
    /// Normalized virtual path at queue time.
    pub virtual_path: String,
    /// Retry attempt counter.
    pub retry_count: u32,
    /// Last error summary, if any.
    pub last_error: Option<String>,
    /// Enqueue timestamp.
    pub queued_at: DateTime<Utc>,
}

/// Recorded non-destructive conflict preservation event (paths encrypted at rest in SQLite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// Original virtual path where conflict occurred.
    pub original_path: String,
    /// Preserved conflict copy virtual path (`stem (conflict-<device>-<ts>).ext`).
    pub conflict_path: String,
    /// Winning manifest revision.
    pub remote_revision: u64,
    /// Timestamp recorded.
    pub detected_at: DateTime<Utc>,
}

/// Persistent zero-knowledge metadata store interface implemented by SQLite WAL in `entrocloud-core`.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    /// Fetches an inode by numeric ID.
    async fn get_inode(&self, inode: InodeId) -> ZeroVaultResult<Option<InodeRecord>>;

    /// Looks up a child inode by `(parent_inode, name)` using keyed `BLAKE3` blind index.
    async fn lookup_child(
        &self,
        parent_inode: InodeId,
        name: &str,
    ) -> ZeroVaultResult<Option<InodeRecord>>;

    /// Looks up an inode by normalized virtual path (e.g. `"/Docs/notes.txt"`).
    async fn get_by_path(&self, virtual_path: &str) -> ZeroVaultResult<Option<InodeRecord>>;

    /// Lists direct children of `parent_inode`.
    async fn list_children(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>>;

    /// Inserts or updates an inode record atomically (encrypting `name`/`virtual_path` in SQLite).
    async fn upsert_inode(&self, record: InodeRecord) -> ZeroVaultResult<InodeRecord>;

    /// Allocates the next unique virtual inode ID (`>= 2`).
    async fn allocate_inode_id(&self) -> ZeroVaultResult<InodeId>;

    /// Deletes an inode and its associated chunk rows.
    async fn delete_inode(&self, inode: InodeId) -> ZeroVaultResult<()>;

    /// Replaces the complete chunk map for `inode`.
    async fn replace_chunks(
        &self,
        inode: InodeId,
        chunks: Vec<ChunkDescriptor>,
    ) -> ZeroVaultResult<()>;

    /// Lists ordered chunk descriptors for `inode`.
    async fn list_chunks(&self, inode: InodeId) -> ZeroVaultResult<Vec<ChunkDescriptor>>;

    /// Marks one chunk's `locally_hydrated` bit and recomputes the inode's [`HydrationState`].
    async fn set_chunk_hydrated(
        &self,
        inode: InodeId,
        chunk_index: u64,
        hydrated: bool,
    ) -> ZeroVaultResult<()>;

    /// Updates hydration state and pin flag explicitly.
    async fn set_hydration_and_pin(
        &self,
        inode: InodeId,
        hydration: HydrationState,
        pinned: bool,
    ) -> ZeroVaultResult<()>;

    /// Enqueues a dirty mutation for background upload/sync.
    async fn enqueue_dirty(
        &self,
        inode: InodeId,
        kind: DirtyOpKind,
        virtual_path: &str,
    ) -> ZeroVaultResult<i64>;

    /// Lists queued dirty mutations ordered by `id ASC`.
    async fn list_dirty_ops(&self) -> ZeroVaultResult<Vec<DirtyOp>>;

    /// Removes a completed dirty operation from the queue.
    async fn complete_dirty_op(&self, id: i64) -> ZeroVaultResult<()>;

    /// Marks a failed dirty operation with incremented retry counter.
    async fn mark_dirty_retry(&self, id: i64, error: &str) -> ZeroVaultResult<()>;

    /// Returns `(latest_local_manifest_revision, remote_etag)`.
    async fn manifest_cursor(&self) -> ZeroVaultResult<(u64, Option<String>)>;

    /// Updates the persisted manifest revision and remote ETag cursor.
    async fn update_manifest_cursor(
        &self,
        revision: u64,
        remote_etag: Option<String>,
    ) -> ZeroVaultResult<()>;

    /// Reads the persisted `parent_manifest_id` snapshot chain anchor (`NEW-M01` fix).
    async fn parent_manifest_id(&self) -> ZeroVaultResult<Option<Uuid>> {
        Ok(None)
    }

    /// Persists the latest `parent_manifest_id` snapshot chain anchor.
    async fn set_parent_manifest_id(&self, _manifest_id: Option<Uuid>) -> ZeroVaultResult<()> {
        Ok(())
    }

    /// Reads the monotonic security `epoch` floor for a scope (e.g. `"keybox"` or `"manifest"`).
    async fn epoch_floor(&self, _scope: &str) -> ZeroVaultResult<u64> {
        Ok(0)
    }

    /// Monotonically advances `epoch` floor; rejects any rollback (`new_epoch < current_floor`).
    async fn advance_epoch_floor(&self, _scope: &str, _new_epoch: u64) -> ZeroVaultResult<()> {
        Ok(())
    }

    /// Lists all inodes in the store (used when sealing a full `VaultManifest` snapshot).
    async fn list_all_inodes(&self) -> ZeroVaultResult<Vec<InodeRecord>>;

    /// Records a conflict resolution event.
    async fn record_conflict(&self, conflict: ConflictRecord) -> ZeroVaultResult<()>;

    /// Lists recorded conflicts.
    async fn list_conflicts(&self) -> ZeroVaultResult<Vec<ConflictRecord>>;
}

/// Parameters for creating a new file through [`VfsBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateEntrySpec {
    /// Parent directory inode.
    pub parent_inode: InodeId,
    /// New file basename.
    pub name: String,
    /// POSIX mode bits.
    pub mode: u32,
}

/// Mutable attributes supported by `setattr`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetAttrSpec {
    /// Optional new file size (truncate/extend).
    pub size: Option<u64>,
    /// Optional POSIX mode bits.
    pub mode: Option<u32>,
    /// Optional modification timestamp.
    pub modified_at: Option<DateTime<Utc>>,
}

/// Live virtual drive telemetry counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveStats {
    /// Total hydrated bytes served from remote/cache.
    pub bytes_read: u64,
    /// Total bytes written through the virtual drive.
    pub bytes_written: u64,
    /// Number of 4 MiB chunks hydrated on demand.
    pub chunks_hydrated: u64,
    /// Number of cache-hit reads avoiding remote network I/O.
    pub cache_hits: u64,
    /// Number of active open virtual file handles.
    pub open_handles: u64,
}

/// Abstract virtual filesystem operations bridged by Windows `CfApi`, Linux `FUSE`, and `MockDrive`.
#[async_trait]
pub trait VfsBackend: Send + Sync {
    /// Fetches inode metadata.
    async fn getattr(&self, inode: InodeId) -> ZeroVaultResult<InodeRecord>;

    /// Looks up a child entry inside a directory inode.
    async fn lookup(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<InodeRecord>;

    /// Resolves an arbitrary normalized virtual path (`/a/b/c`) to its inode record.
    async fn resolve_path(&self, virtual_path: &str) -> ZeroVaultResult<InodeRecord>;

    /// Lists entries inside a directory inode.
    async fn readdir(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>>;

    /// Reads `[offset, offset + len)` plaintext bytes, hydrating only the required 4 MiB chunks on demand.
    async fn read_range(&self, inode: InodeId, offset: u64, len: usize) -> ZeroVaultResult<Bytes>;

    /// Writes `data` at `offset` into the encrypted dirty staging cache for `inode`.
    async fn write_range(&self, inode: InodeId, offset: u64, data: &[u8]) -> ZeroVaultResult<usize>;

    /// Creates a new empty virtual file under `spec.parent_inode`.
    async fn create_entry(&self, spec: CreateEntrySpec) -> ZeroVaultResult<InodeRecord>;

    /// Creates a new virtual directory.
    async fn mkdir(
        &self,
        parent_inode: InodeId,
        name: &str,
        mode: u32,
    ) -> ZeroVaultResult<InodeRecord>;

    /// Deletes a regular virtual file.
    async fn unlink(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()>;

    /// Deletes an empty virtual directory.
    async fn rmdir(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<()>;

    /// Moves or renames a virtual file or directory atomically.
    async fn rename(
        &self,
        parent_inode: InodeId,
        name: &str,
        new_parent_inode: InodeId,
        new_name: &str,
    ) -> ZeroVaultResult<InodeRecord>;

    /// Updates attributes such as truncated size or permissions.
    async fn setattr(&self, inode: InodeId, attrs: SetAttrSpec) -> ZeroVaultResult<InodeRecord>;

    /// Flushes dirty writes for `inode` through the 4 MiB chunk encryption + upload pipeline.
    async fn flush(&self, inode: InodeId) -> ZeroVaultResult<()>;

    /// Synchronizes dirty chunks and metadata manifest durably.
    async fn fsync(&self, inode: InodeId, datasync: bool) -> ZeroVaultResult<()>;

    /// Pins `inode` offline (hydrates all missing chunks if needed and protects against dehydration).
    async fn pin(&self, inode: InodeId) -> ZeroVaultResult<()>;

    /// Clears the offline pin flag so an inode becomes eligible for dehydration.
    async fn unpin(&self, inode: InodeId) -> ZeroVaultResult<()>;

    /// Dehydrates `inode` locally, reclaiming local disk/RAM cache unless pinned.
    async fn dehydrate(&self, inode: InodeId) -> ZeroVaultResult<()>;

    /// Returns the hydration state for `user.zerovault.state`.
    async fn get_xattr_state(&self, inode: InodeId) -> ZeroVaultResult<HydrationState>;

    /// Returns cumulative VFS I/O counters.
    async fn drive_stats(&self) -> ZeroVaultResult<DriveStats>;
}

/// Platform virtual filesystem mount lifecycle controller (`CfApi`, `fuser`, or `MockDrive`).
#[async_trait]
pub trait VirtualDrive: Send + Sync {
    /// Mounts or connects the virtual filesystem at `mount_point`.
    async fn mount(&self, mount_point: PathBuf) -> ZeroVaultResult<()>;

    /// Gracefully unmounts/disconnects the virtual filesystem.
    async fn unmount(&self) -> ZeroVaultResult<()>;

    /// Returns `true` when the drive is actively mounted/connected.
    fn is_mounted(&self) -> bool;

    /// Returns the active mount point path if mounted.
    fn mount_point(&self) -> Option<PathBuf>;

    /// Pins a virtual path (e.g. `"/Finance/tax.pdf"`) for offline availability.
    async fn pin_path(&self, virtual_path: &str) -> ZeroVaultResult<()>;

    /// Clears the offline pin attribute on a virtual path (`NEW-H02` / `VFS-3` fix).
    async fn unpin_path(&self, virtual_path: &str) -> ZeroVaultResult<()>;

    /// Dehydrates a virtual path back to online-only placeholder state.
    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()>;

    /// Notifies the OS VFS layer that a remote metadata change occurred under `virtual_path`.
    async fn notify_change(&self, virtual_path: &str) -> ZeroVaultResult<()>;

    /// Queries drive telemetry counters.
    async fn stats(&self) -> ZeroVaultResult<DriveStats>;
}
