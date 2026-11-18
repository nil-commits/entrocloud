//! Production zero-knowledge cryptographic engine combining `ring 0.17` hardware-accelerated
//! `AES-256-GCM` bulk encryption, `Argon2id` + 7-subkey `HKDF-SHA256`, `BLAKE3` keyed blind
//! indexing, `ZVS2` AEAD-wrapped keyring sessions, and `aws-lc-rs 1.19` post-quantum sharing.

use std::fmt;
use std::hint::black_box;
use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use entrocloud_types::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CHUNK_FORMAT_VERSION, CHUNK_HEADER_LEN, CapabilityUri,
    ChunkAad, ChunkHeader, CryptoBenchmarkReport, CryptoEngine, DekBytes, HKDF_INFO_KEK,
    HKDF_INFO_MANIFEST, HKDF_INFO_META_AEAD, HKDF_INFO_META_BLIND, HKDF_INFO_STAGING,
    HKDF_INFO_TOKEN_WRAP, HKDF_INFO_VERIFIER, HardwareCryptoCaps, InodeId, KdfParams,
    MANIFEST_FORMAT_VERSION, MANIFEST_HEADER_LEN, MAX_ENCRYPTED_CHUNK_SIZE, ManifestWireHeader,
    PLAINTEXT_CHUNK_SIZE, RecipientPrivateIdentity, RecipientPublicBundle, RedactedSecret,
    SecretStore, ShareDescriptor, SignedKeybox, SignedShareEnvelope, VAULT_HEADER_VERSION,
    VaultHeader, VaultManifest, WrappedDek, ZeroVaultError, ZeroVaultResult,
};

use crate::aead_ring::{
    fill_csprng, fill_csprng_zeroizing, hkdf_expand_256, open_in_place_detached,
    open_nonce_prefixed, seal_in_place_detached, seal_nonce_prefixed, seal_with_nonce,
};
use crate::hw::{ensure_hardware_acceleration, verify_hardware_acceleration};
use crate::sharing;

/// `ZVS2` AEAD-wrapped OS keyring session magic (`NEW-M03` remediation).
const SESSION_MAGIC: [u8; 4] = *b"ZVS2";
/// `ZVS2` wire length: `4B magic + 16B vault_id + 12B nonce + 32B ciphertext + 16B tag = 80B`.
const ZVS2_SESSION_BLOB_LEN: usize = 4 + 16 + AES_GCM_NONCE_LEN + 32 + AES_GCM_TAG_LEN;
/// Wrapped 256-bit DEK ciphertext + GCM tag length (`48` bytes).
const WRAPPED_DEK_LEN: usize = 32 + AES_GCM_TAG_LEN;

macro_rules! define_redacted_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name(Zeroizing<[u8; 32]>);

        impl $name {
            /// Constructs a key wrapper from a 32-byte array.
            #[must_use]
            pub fn from_array(bytes: [u8; 32]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
                Self(bytes)
            }

            /// Borrows the raw 256-bit key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_redacted_key!(
    MasterSeed,
    "256-bit vault root seed / `FolderRootKey` automatically zeroized on drop."
);
define_redacted_key!(
    MasterKek,
    "256-bit Key Encryption Key expanded via HKDF-SHA256 for wrapping per-file DEKs."
);
define_redacted_key!(
    ManifestKey,
    "256-bit key expanded via HKDF-SHA256 for sealing and opening `ZVM1` manifests."
);
define_redacted_key!(
    TokenWrapKey,
    "256-bit key expanded via HKDF-SHA256 for wrapping OAuth2 token bundles."
);
define_redacted_key!(
    HeaderVerifierKey,
    "256-bit key expanded via HKDF-SHA256 for authenticating `ZVH1` vault headers."
);
define_redacted_key!(
    MetadataKey,
    "256-bit key expanded via HKDF-SHA256 for encrypting local SQLite metadata columns."
);
define_redacted_key!(
    BlindIndexKey,
    "256-bit key expanded via HKDF-SHA256 for keyed `BLAKE3` SQLite blind indexes."
);
define_redacted_key!(
    StagingKey,
    "256-bit key expanded via HKDF-SHA256 for encrypting local `.zvpart` staging chunks."
);

/// Active in-memory 7-subkey hierarchy for an unlocked ZeroVault session.
///
/// All secret key material is scrubbed immediately on [`CryptoEngine::lock_vault`] or drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyRingState {
    #[zeroize(skip)]
    vault_id: Uuid,
    root_key: MasterSeed,
    master_kek: MasterKek,
    manifest_key: ManifestKey,
    token_wrap_key: TokenWrapKey,
    header_verifier_key: HeaderVerifierKey,
    metadata_key: MetadataKey,
    blind_index_key: BlindIndexKey,
    staging_key: StagingKey,
}

impl KeyRingState {
    /// Expands all 7 domain-separated 256-bit `HKDF-SHA256` subkeys from `root_key`
    /// using `vault_id.as_bytes()` as the HKDF salt.
    pub fn from_folder_root_key(vault_id: Uuid, root_key: MasterSeed) -> ZeroVaultResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), root_key.as_bytes());
        let master_kek = MasterKek::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_KEK)?);
        let manifest_key = ManifestKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_MANIFEST)?);
        let token_wrap_key =
            TokenWrapKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_TOKEN_WRAP)?);
        let header_verifier_key =
            HeaderVerifierKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_VERIFIER)?);
        let metadata_key =
            MetadataKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_META_AEAD)?);
        let blind_index_key =
            BlindIndexKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_META_BLIND)?);
        let staging_key = StagingKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_STAGING)?);

        Ok(Self {
            vault_id,
            root_key,
            master_kek,
            manifest_key,
            token_wrap_key,
            header_verifier_key,
            metadata_key,
            blind_index_key,
            staging_key,
        })
    }

    /// Compatibility constructor expanding the 7-subkey schedule from an Argon2id `MasterSeed`.
    pub fn from_master_seed(
        vault_id: Uuid,
        _argon2_salt: [u8; 32],
        master_seed: MasterSeed,
    ) -> ZeroVaultResult<Self> {
        Self::from_folder_root_key(vault_id, master_seed)
    }

    /// Returns the vault UUID bound to this keyring state.
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Borrows the derived `MasterKek`.
    #[must_use]
    pub fn master_kek(&self) -> &MasterKek {
        &self.master_kek
    }

    /// Borrows the derived `ManifestKey`.
    #[must_use]
    pub fn manifest_key(&self) -> &ManifestKey {
        &self.manifest_key
    }

    /// Borrows the derived `TokenWrapKey`.
    #[must_use]
    pub fn token_wrap_key(&self) -> &TokenWrapKey {
        &self.token_wrap_key
    }

    /// Borrows the derived `HeaderVerifierKey`.
    #[must_use]
    pub fn header_verifier_key(&self) -> &HeaderVerifierKey {
        &self.header_verifier_key
    }

    /// Borrows the derived `MetadataKey`.
    #[must_use]
    pub fn metadata_key(&self) -> &MetadataKey {
        &self.metadata_key
    }

    /// Borrows the derived `BlindIndexKey`.
    #[must_use]
    pub fn blind_index_key(&self) -> &BlindIndexKey {
        &self.blind_index_key
    }

    /// Borrows the derived `StagingKey`.
    #[must_use]
    pub fn staging_key(&self) -> &StagingKey {
        &self.staging_key
    }
}

impl fmt::Debug for KeyRingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRingState")
            .field("vault_id", &self.vault_id)
            .field("root_key", &self.root_key)
            .field("master_kek", &self.master_kek)
            .field("manifest_key", &self.manifest_key)
            .field("token_wrap_key", &self.token_wrap_key)
            .field("header_verifier_key", &self.header_verifier_key)
            .field("metadata_key", &self.metadata_key)
            .field("blind_index_key", &self.blind_index_key)
            .field("staging_key", &self.staging_key)
            .finish()
    }
}

/// Hardware-accelerated hybrid zero-knowledge [`CryptoEngine`]:
/// - `ring 0.17` stitched `VAES`+`VPCLMULQDQ` / `AES-NI` for all `AES-256-GCM` operations
/// - `argon2 0.5` + `hkdf 0.12` + `blake3 1.8` for key derivation and blind indexing
/// - `aws-lc-rs 1.19` for NIST FIPS 203 `ML-KEM-768` + `X25519` + `Ed25519` sharing
pub struct RingHybridCryptoEngine {
    caps: HardwareCryptoCaps,
    state: RwLock<Option<KeyRingState>>,
}

/// Default production [`CryptoEngine`] alias.
pub type DefaultCryptoEngine = RingHybridCryptoEngine;

/// Backwards-compatible engine alias for Wave 1/v0.1 callers.
pub type AwsLcCryptoEngine = RingHybridCryptoEngine;

impl RingHybridCryptoEngine {
    /// Verifies mandatory CPU hardware AES + GHASH acceleration and creates a locked engine.
    ///
    /// Fails closed with [`ZeroVaultError::HardwareAccelerationUnavailable`] when required
    /// hardware instructions are absent.
    pub fn new() -> ZeroVaultResult<Self> {
        let caps = verify_hardware_acceleration()?;
        Ok(Self {
            caps,
            state: RwLock::new(None),
        })
    }

    /// Returns the cached hardware capability profile detected at construction time.
    #[must_use]
    pub fn hardware_caps(&self) -> &HardwareCryptoCaps {
        &self.caps
    }

    fn install_keyring(&self, keyring: KeyRingState) {
        let mut guard = self.state.write();
        if let Some(mut previous) = guard.take() {
            previous.zeroize();
        }
        *guard = Some(keyring);
    }

    fn with_unlocked<T>(
        &self,
        f: impl FnOnce(&KeyRingState) -> ZeroVaultResult<T>,
    ) -> ZeroVaultResult<T> {
        let guard = self.state.read();
        let state = guard.as_ref().ok_or(ZeroVaultError::VaultLocked)?;
        f(state)
    }
}

impl fmt::Debug for RingHybridCryptoEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unlocked = self.state.read().is_some();
        f.debug_struct("RingHybridCryptoEngine")
            .field("caps", &self.caps)
            .field("unlocked", &unlocked)
            .finish()
    }
}

async fn derive_master_seed(
    passphrase: &RedactedSecret,
    salt: [u8; 32],
    kdf: KdfParams,
) -> ZeroVaultResult<MasterSeed> {
    // Enforce KDF floor AND anti-OOM DoS ceiling strictly BEFORE allocating Argon2id memory.
    kdf.validate_production()?;
    let passphrase_owned = passphrase.clone();

    tokio::task::spawn_blocking(move || {
        kdf.validate_production()?;
        let params =
            Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32)).map_err(|_| {
                ZeroVaultError::KdfPolicyViolation {
                    m_cost_kib: kdf.m_cost_kib,
                    t_cost: kdf.t_cost,
                    p_cost: kdf.p_cost,
                }
            })?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut seed = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(passphrase_owned.as_bytes(), &salt, &mut *seed)
            .map_err(|e| {
                ZeroVaultError::ConfigError(format!("Argon2id key derivation failed: {e}"))
            })?;
        Ok(MasterSeed::from_zeroizing(seed))
    })
    .await
    .map_err(|e| ZeroVaultError::ConfigError(format!("Argon2id worker task failed: {e}")))?
}

fn zvs2_session_aad(vault_id: Uuid) -> [u8; 20] {
    let mut aad = [0u8; 20];
    aad[0..4].copy_from_slice(&SESSION_MAGIC);
    aad[4..20].copy_from_slice(vault_id.as_bytes());
    aad
}

fn token_wrap_aad(vault_id: Uuid) -> [u8; 23 + 16] {
    let mut aad = [0u8; 39];
    aad[0..23].copy_from_slice(HKDF_INFO_TOKEN_WRAP);
    aad[23..39].copy_from_slice(vault_id.as_bytes());
    aad
}

fn staging_chunk_aad(vault_id: Uuid, inode: InodeId, chunk_index: u64) -> [u8; 13 + 16 + 8 + 8] {
    let mut aad = [0u8; 45];
    aad[0..13].copy_from_slice(b"ZV-STAGE-V2::");
    aad[13..29].copy_from_slice(vault_id.as_bytes());
    aad[29..37].copy_from_slice(&inode.to_le_bytes());
    aad[37..45].copy_from_slice(&chunk_index.to_le_bytes());
    aad
}

fn scrub_and_clear(buf: &mut BytesMut) {
    if !buf.is_empty() {
        buf.as_mut().zeroize();
        buf.clear();
    }
}

#[async_trait]
impl CryptoEngine for RingHybridCryptoEngine {
    fn verify_hardware_acceleration(&self) -> ZeroVaultResult<HardwareCryptoCaps> {
        verify_hardware_acceleration()
    }

    fn is_unlocked(&self) -> bool {
        self.state.read().is_some()
    }

    fn vault_id(&self) -> Option<Uuid> {
        self.state.read().as_ref().map(KeyRingState::vault_id)
    }

    async fn init_vault(
        &self,
        passphrase: &RedactedSecret,
        kdf: KdfParams,
    ) -> ZeroVaultResult<VaultHeader> {
        ensure_hardware_acceleration()?;
        kdf.validate_production()?;

        let vault_id = Uuid::new_v4();
        let argon2_salt = fill_csprng::<32>()?;
        let master_seed = derive_master_seed(passphrase, argon2_salt, kdf).await?;
        let keyring = KeyRingState::from_folder_root_key(vault_id, master_seed)?;

        let verifier_nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
        let mut verifier_tag = [0u8; 32];
        verifier_tag[0..16].copy_from_slice(vault_id.as_bytes());
        let tag = seal_in_place_detached(
            keyring.header_verifier_key.as_bytes(),
            verifier_nonce,
            &VaultHeader::verifier_aad(vault_id),
            &mut verifier_tag[0..16],
        )?;
        verifier_tag[16..32].copy_from_slice(&tag);

        self.install_keyring(keyring);

        Ok(VaultHeader {
            version: VAULT_HEADER_VERSION,
            vault_id,
            argon2_salt,
            kdf,
            verifier_nonce,
            verifier_tag,
        })
    }

    async fn unlock_with_passphrase(
        &self,
        header: &VaultHeader,
        passphrase: &RedactedSecret,
    ) -> ZeroVaultResult<()> {
        ensure_hardware_acceleration()?;
        if header.version != VAULT_HEADER_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported vault header version {}",
                header.version
            )));
        }
        // Enforce KDF bounds BEFORE Argon2id memory allocation.
        header.kdf.validate_production()?;

        let master_seed = derive_master_seed(passphrase, header.argon2_salt, header.kdf).await?;
        let candidate = KeyRingState::from_folder_root_key(header.vault_id, master_seed)?;

        let (ct, tag) = header.verifier_tag.split_at(16);
        let mut decrypted_vault_id = Zeroizing::new([0u8; 16]);
        decrypted_vault_id.copy_from_slice(ct);

        open_in_place_detached(
            candidate.header_verifier_key.as_bytes(),
            header.verifier_nonce,
            &VaultHeader::verifier_aad(header.vault_id),
            tag,
            &mut *decrypted_vault_id,
        )
        .map_err(|_| ZeroVaultError::InvalidPassphrase)?;

        if !bool::from(decrypted_vault_id.ct_eq(header.vault_id.as_bytes())) {
            return Err(ZeroVaultError::InvalidPassphrase);
        }

        self.install_keyring(candidate);
        Ok(())
    }

    fn unlock_with_folder_key(
        &self,
        vault_id: Uuid,
        folder_root_key: &[u8; 32],
    ) -> ZeroVaultResult<()> {
        ensure_hardware_acceleration()?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(folder_root_key);
        let keyring = KeyRingState::from_folder_root_key(vault_id, MasterSeed::from_zeroizing(seed))?;
        self.install_keyring(keyring);
        Ok(())
    }

    fn export_folder_root_key(&self) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let mut exported = Zeroizing::new([0u8; 32]);
            exported.copy_from_slice(state.root_key.as_bytes());
            Ok(exported)
        })
    }

    async fn lock_vault(&self) -> ZeroVaultResult<()> {
        let mut guard = self.state.write();
        if let Some(mut old) = guard.take() {
            old.zeroize();
        }
        Ok(())
    }

    async fn persist_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
    ) -> ZeroVaultResult<()> {
        ensure_hardware_acceleration()?;

        let (vault_id, root_key_bytes) = self.with_unlocked(|state| {
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(state.root_key.as_bytes());
            Ok((state.vault_id, copy))
        })?;

        let wrap_key_account = format!("{vault_id}:wrap-key");
        let session_account = format!("{vault_id}:session");

        let wrap_key = match store.get_secret(service, &wrap_key_account).await? {
            Some(existing) => {
                if existing.len() != 32 {
                    return Err(ZeroVaultError::CryptoTamperDetected(format!(
                        "corrupted session wrap-key length: expected 32, got {}",
                        existing.len()
                    )));
                }
                let mut wk = Zeroizing::new([0u8; 32]);
                wk.copy_from_slice(&existing);
                wk
            }
            None => {
                let fresh_wk = fill_csprng_zeroizing::<32>()?;
                store
                    .set_secret(service, &wrap_key_account, fresh_wk.as_ref())
                    .await?;
                fresh_wk
            }
        };

        let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
        let aad = zvs2_session_aad(vault_id);

        let mut blob = Zeroizing::new(vec![0u8; ZVS2_SESSION_BLOB_LEN]);
        blob[0..20].copy_from_slice(&aad);
        blob[20..32].copy_from_slice(&nonce);
        blob[32..64].copy_from_slice(&*root_key_bytes);
        let tag = seal_in_place_detached(&wrap_key, nonce, &aad, &mut blob[32..64])?;
        blob[64..80].copy_from_slice(&tag);

        store.set_secret(service, &session_account, &blob).await
    }

    async fn restore_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
        expected_vault_id: Uuid,
    ) -> ZeroVaultResult<bool> {
        ensure_hardware_acceleration()?;

        let session_account = format!("{expected_vault_id}:session");
        let Some(blob) = store.get_secret(service, &session_account).await? else {
            return Ok(false);
        };

        let wrap_key_account = format!("{expected_vault_id}:wrap-key");
        let wrap_key_raw = store
            .get_secret(service, &wrap_key_account)
            .await?
            .ok_or_else(|| {
                ZeroVaultError::CryptoTamperDetected(
                    "session wrap-key missing for persisted ZVS2 session".into(),
                )
            })?;
        if wrap_key_raw.len() != 32 {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "corrupted session wrap-key length: expected 32, got {}",
                wrap_key_raw.len()
            )));
        }
        let mut wrap_key = Zeroizing::new([0u8; 32]);
        wrap_key.copy_from_slice(&wrap_key_raw);

        if blob.len() != ZVS2_SESSION_BLOB_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "corrupted ZVS2 session length: expected {ZVS2_SESSION_BLOB_LEN}, got {}",
                blob.len()
            )));
        }
        if blob[0..4] != SESSION_MAGIC {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "invalid ZVS2 session header magic".into(),
            ));
        }

        let stored_vault_id = Uuid::from_slice(&blob[4..20]).map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("invalid vault_id in ZVS2 session".into())
        })?;
        if stored_vault_id != expected_vault_id {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "ZVS2 session vault_id mismatch".into(),
            ));
        }

        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&blob[20..32]);
        let aad = zvs2_session_aad(expected_vault_id);

        let mut root_key = Zeroizing::new([0u8; 32]);
        root_key.copy_from_slice(&blob[32..64]);
        open_in_place_detached(&wrap_key, nonce, &aad, &blob[64..80], &mut *root_key)?;

        let candidate = KeyRingState::from_folder_root_key(
            expected_vault_id,
            MasterSeed::from_zeroizing(root_key),
        )?;
        self.install_keyring(candidate);
        Ok(true)
    }

    fn generate_dek(&self) -> ZeroVaultResult<DekBytes> {
        ensure_hardware_acceleration()?;
        let raw = fill_csprng_zeroizing::<32>()?;
        DekBytes::from_slice(&*raw)
    }

    fn wrap_dek(&self, file_id: Uuid, dek: &DekBytes) -> ZeroVaultResult<WrappedDek> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
            let aad = WrappedDek::dek_wrap_aad(file_id);
            let ciphertext_and_tag =
                seal_with_nonce(state.master_kek.as_bytes(), nonce, &aad, dek.as_bytes())?;
            Ok(WrappedDek {
                nonce,
                ciphertext_and_tag,
            })
        })
    }

    fn unwrap_dek(&self, file_id: Uuid, wrapped: &WrappedDek) -> ZeroVaultResult<DekBytes> {
        ensure_hardware_acceleration()?;
        if wrapped.ciphertext_and_tag.len() != WRAPPED_DEK_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "wrapped DEK length mismatch: expected {WRAPPED_DEK_LEN}, got {}",
                wrapped.ciphertext_and_tag.len()
            )));
        }

        self.with_unlocked(|state| {
            let (ct, tag) = wrapped.ciphertext_and_tag.split_at(32);
            let aad = WrappedDek::dek_wrap_aad(file_id);
            let mut pt = Zeroizing::new([0u8; 32]);
            pt.copy_from_slice(ct);
            open_in_place_detached(
                state.master_kek.as_bytes(),
                wrapped.nonce,
                &aad,
                tag,
                &mut *pt,
            )?;
            DekBytes::from_slice(&*pt)
        })
    }

    fn encrypt_chunk_into(
        &self,
        dek: &DekBytes,
        aad: ChunkAad,
        plaintext: &[u8],
        out_wire: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader> {
        ensure_hardware_acceleration()?;

        let plaintext_len = u32::try_from(plaintext.len()).map_err(|_| {
            ZeroVaultError::InvalidWireFormat("chunk plaintext exceeds u32::MAX".into())
        })?;
        let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
        let header = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: aad.is_final_chunk,
            chunk_index: aad.chunk_index,
            plaintext_len,
            nonce,
        };
        let header_bytes = header.encode()?;
        let total_len = header.expected_wire_len();

        out_wire.clear();
        if out_wire.capacity() < total_len {
            out_wire.reserve(total_len);
        }
        out_wire.extend_from_slice(&header_bytes);
        out_wire.extend_from_slice(plaintext);

        let aad_bytes = aad.to_bytes();
        let ct_end = CHUNK_HEADER_LEN + plaintext.len();
        let tag = match seal_in_place_detached(
            dek.as_bytes(),
            nonce,
            &aad_bytes,
            &mut out_wire[CHUNK_HEADER_LEN..ct_end],
        ) {
            Ok(t) => t,
            Err(err) => {
                out_wire.as_mut().zeroize();
                out_wire.clear();
                return Err(err);
            }
        };
        out_wire.extend_from_slice(&tag);

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
        if let Err(err) = ensure_hardware_acceleration() {
            scrub_and_clear(out_plaintext);
            return Err(err);
        }

        let header = match ChunkHeader::decode(wire_chunk) {
            Ok(h) => h,
            Err(err) => {
                scrub_and_clear(out_plaintext);
                return Err(err);
            }
        };
        if let Some(expected_idx) = expected_chunk_index
            && header.chunk_index != expected_idx
        {
            scrub_and_clear(out_plaintext);
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "chunk index mismatch: expected {expected_idx}, got {}",
                header.chunk_index
            )));
        }
        if wire_chunk.len() != header.expected_wire_len() {
            scrub_and_clear(out_plaintext);
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "wire chunk length mismatch: expected {}, got {}",
                header.expected_wire_len(),
                wire_chunk.len()
            )));
        }

        let pt_len = header.plaintext_len as usize;
        let ct_end = CHUNK_HEADER_LEN + pt_len;
        let ct = &wire_chunk[CHUNK_HEADER_LEN..ct_end];
        let tag = &wire_chunk[ct_end..];
        let aad = ChunkAad {
            file_id: expected_file_id,
            chunk_index: header.chunk_index,
            is_final_chunk: header.is_final_chunk,
        };

        out_plaintext.clear();
        if out_plaintext.capacity() < pt_len {
            out_plaintext.reserve(pt_len);
        }
        out_plaintext.extend_from_slice(ct);

        if let Err(err) = open_in_place_detached(
            dek.as_bytes(),
            header.nonce,
            &aad.to_bytes(),
            tag,
            out_plaintext.as_mut(),
        ) {
            out_plaintext.as_mut().zeroize();
            out_plaintext.clear();
            return Err(err);
        }

        Ok(header)
    }

    fn seal_manifest(&self, manifest: &VaultManifest) -> ZeroVaultResult<Bytes> {
        ensure_hardware_acceleration()?;
        if manifest.revision == 0 {
            return Err(ZeroVaultError::InvalidWireFormat(
                "manifest revision must be >= 1".into(),
            ));
        }

        self.with_unlocked(|state| {
            let payload = Zeroizing::new(
                postcard::to_allocvec(manifest)
                    .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?,
            );
            let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
            let header = ManifestWireHeader {
                version: MANIFEST_FORMAT_VERSION,
                vault_id: manifest.vault_id,
                revision: manifest.revision,
                nonce,
            };
            let aad = VaultManifest::manifest_aad(manifest.vault_id, manifest.revision);
            let total_len = MANIFEST_HEADER_LEN + payload.len() + AES_GCM_TAG_LEN;

            let mut out = BytesMut::with_capacity(total_len);
            out.extend_from_slice(&header.encode());
            out.extend_from_slice(&payload);

            let ct_end = MANIFEST_HEADER_LEN + payload.len();
            let tag = seal_in_place_detached(
                state.manifest_key.as_bytes(),
                nonce,
                &aad,
                &mut out[MANIFEST_HEADER_LEN..ct_end],
            )?;
            out.extend_from_slice(&tag);

            Ok(out.freeze())
        })
    }

    fn open_manifest(&self, sealed_bytes: &[u8]) -> ZeroVaultResult<VaultManifest> {
        ensure_hardware_acceleration()?;
        let hdr = ManifestWireHeader::decode(sealed_bytes)?;
        let ct_end = sealed_bytes.len() - AES_GCM_TAG_LEN;
        let ct = &sealed_bytes[MANIFEST_HEADER_LEN..ct_end];
        let tag = &sealed_bytes[ct_end..];
        let aad = VaultManifest::manifest_aad(hdr.vault_id, hdr.revision);

        let pt = self.with_unlocked(|state| {
            let mut pt = Zeroizing::new(ct.to_vec());
            open_in_place_detached(state.manifest_key.as_bytes(), hdr.nonce, &aad, tag, &mut pt)?;
            Ok(pt)
        })?;

        let manifest: VaultManifest = postcard::from_bytes(&pt)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(format!("manifest decode error: {e}")))?;

        if manifest.vault_id != hdr.vault_id || manifest.revision != hdr.revision {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "manifest header metadata does not match decrypted payload".into(),
            ));
        }

        Ok(manifest)
    }

    fn wrap_token_payload(&self, plaintext: &[u8]) -> ZeroVaultResult<Vec<u8>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let aad = token_wrap_aad(state.vault_id);
            seal_nonce_prefixed(state.token_wrap_key.as_bytes(), &aad, plaintext)
        })
    }

    fn unwrap_token_payload(&self, wrapped: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let aad = token_wrap_aad(state.vault_id);
            open_nonce_prefixed(state.token_wrap_key.as_bytes(), &aad, wrapped)
        })
    }

    fn seal_metadata(&self, aad: &[u8], plaintext: &[u8]) -> ZeroVaultResult<Vec<u8>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            seal_nonce_prefixed(state.metadata_key.as_bytes(), aad, plaintext)
        })
    }

    fn open_metadata(&self, aad: &[u8], ciphertext: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            open_nonce_prefixed(state.metadata_key.as_bytes(), aad, ciphertext)
        })
    }

    fn compute_blind_index(&self, parent_inode: InodeId, name: &str) -> ZeroVaultResult<[u8; 32]> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let mut hasher = blake3::Hasher::new_keyed(state.blind_index_key.as_bytes());
            hasher.update(b"ZV-BLIND-IDX-V2");
            hasher.update(&parent_inode.to_le_bytes());
            hasher.update(name.as_bytes());
            Ok(*hasher.finalize().as_bytes())
        })
    }

    fn seal_staging_chunk(
        &self,
        inode: InodeId,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> ZeroVaultResult<Vec<u8>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let aad = staging_chunk_aad(state.vault_id, inode, chunk_index);
            seal_nonce_prefixed(state.staging_key.as_bytes(), &aad, plaintext)
        })
    }

    fn open_staging_chunk(
        &self,
        inode: InodeId,
        chunk_index: u64,
        sealed: &[u8],
    ) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
        ensure_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let aad = staging_chunk_aad(state.vault_id, inode, chunk_index);
            open_nonce_prefixed(state.staging_key.as_bytes(), &aad, sealed)
        })
    }

    fn generate_recipient_identity(
        &self,
        label: &str,
    ) -> ZeroVaultResult<RecipientPrivateIdentity> {
        sharing::generate_recipient_identity(label)
    }

    fn create_capability_share(
        &self,
        owner_identity: &RecipientPrivateIdentity,
        backend_hint: &str,
        root_locator: &str,
        file_dek: &DekBytes,
        descriptor: &ShareDescriptor,
    ) -> ZeroVaultResult<(CapabilityUri, SignedShareEnvelope)> {
        sharing::create_capability_share(
            owner_identity,
            backend_hint,
            root_locator,
            file_dek,
            descriptor,
        )
    }

    fn open_capability_share(
        &self,
        uri: &CapabilityUri,
        envelope: &SignedShareEnvelope,
    ) -> ZeroVaultResult<(ShareDescriptor, DekBytes)> {
        sharing::open_capability_share(uri, envelope)
    }

    fn seal_keybox(
        &self,
        owner_identity: &RecipientPrivateIdentity,
        vault_id: Uuid,
        epoch: u64,
        folder_root_key: &[u8; 32],
        recipients: &[RecipientPublicBundle],
    ) -> ZeroVaultResult<SignedKeybox> {
        sharing::seal_keybox(owner_identity, vault_id, epoch, folder_root_key, recipients)
    }

    fn verify_keybox_envelope(
        &self,
        keybox: &SignedKeybox,
        expected_vault_id: Option<Uuid>,
        expected_owner_pubkey: Option<&[u8; 32]>,
        min_epoch_floor: u64,
    ) -> ZeroVaultResult<()> {
        sharing::verify_keybox_envelope(
            keybox,
            expected_vault_id,
            expected_owner_pubkey,
            min_epoch_floor,
        )
    }

    fn open_keybox(
        &self,
        keybox: &SignedKeybox,
        expected_owner_pubkey: Option<&[u8; 32]>,
        min_epoch_floor: u64,
        recipient_identity: &RecipientPrivateIdentity,
    ) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
        sharing::open_keybox(
            keybox,
            expected_owner_pubkey,
            min_epoch_floor,
            recipient_identity,
        )
    }

    fn benchmark_aes256_gcm(&self, total_mib: usize) -> ZeroVaultResult<CryptoBenchmarkReport> {
        let caps = self.verify_hardware_acceleration()?;
        let chunks = total_mib.max(1).div_ceil(4);
        let measured_mib = chunks * 4;

        let dek = self.generate_dek()?;
        let file_id = Uuid::new_v4();

        let mut plaintext_buf = BytesMut::with_capacity(PLAINTEXT_CHUNK_SIZE);
        plaintext_buf.resize(PLAINTEXT_CHUNK_SIZE, 0);
        for (idx, byte) in plaintext_buf.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(31).wrapping_add(7);
        }
        let mut wire_buf = BytesMut::with_capacity(MAX_ENCRYPTED_CHUNK_SIZE);

        let enc_start = Instant::now();
        for chunk_idx in 0..chunks {
            let aad = ChunkAad {
                file_id,
                chunk_index: chunk_idx as u64,
                is_final_chunk: chunk_idx + 1 == chunks,
            };
            self.encrypt_chunk_into(&dek, aad, black_box(&plaintext_buf), &mut wire_buf)?;
            black_box(&wire_buf);
        }
        let enc_elapsed = enc_start.elapsed();

        let last_chunk_index = (chunks - 1) as u64;
        let dec_start = Instant::now();
        for _ in 0..chunks {
            self.decrypt_chunk_into(
                &dek,
                file_id,
                Some(last_chunk_index),
                black_box(&wire_buf),
                &mut plaintext_buf,
            )?;
            black_box(&plaintext_buf);
        }
        let dec_elapsed = dec_start.elapsed();

        plaintext_buf.as_mut().zeroize();

        let total_mib_f64 = measured_mib as f64;
        let encrypt_mib_per_sec = total_mib_f64 / enc_elapsed.as_secs_f64().max(1e-9);
        let decrypt_mib_per_sec = total_mib_f64 / dec_elapsed.as_secs_f64().max(1e-9);

        Ok(CryptoBenchmarkReport {
            caps,
            total_mib: measured_mib,
            encrypt_mib_per_sec,
            decrypt_mib_per_sec,
            encrypt_elapsed_ms: u64::try_from(enc_elapsed.as_millis()).unwrap_or(u64::MAX),
            decrypt_elapsed_ms: u64::try_from(dec_elapsed.as_millis()).unwrap_or(u64::MAX),
        })
    }
}
