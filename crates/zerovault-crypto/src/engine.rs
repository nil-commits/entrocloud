//! Production zero-knowledge cryptographic engine backed by `aws-lc-rs`,
//! `argon2`, `hkdf`, and `sha2`.

use std::fmt;
use std::hint::black_box;
use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use zerovault_types::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CHUNK_FORMAT_VERSION, CHUNK_HEADER_LEN, ChunkAad,
    ChunkHeader, CryptoBenchmarkReport, CryptoEngine, DekBytes, HKDF_INFO_KEK, HKDF_INFO_MANIFEST,
    HKDF_INFO_TOKEN_WRAP, HKDF_INFO_VERIFIER, HardwareCryptoCaps, KdfParams,
    MANIFEST_FORMAT_VERSION, MANIFEST_HEADER_LEN, MAX_ENCRYPTED_CHUNK_SIZE, ManifestWireHeader,
    PLAINTEXT_CHUNK_SIZE, RedactedSecret, SecretStore, VAULT_HEADER_VERSION, VaultHeader,
    VaultManifest, WrappedDek, ZeroVaultError, ZeroVaultResult,
};

use crate::hw::verify_hardware_acceleration;

const SESSION_MAGIC: [u8; 4] = *b"ZVS1";
const SESSION_FORMAT_VERSION: u8 = 1;
const SESSION_BLOB_LEN: usize = 4 + 1 + 16 + 32 + 32 + AES_GCM_NONCE_LEN + 32; // 129 bytes
const WRAPPED_DEK_LEN: usize = 32 + AES_GCM_TAG_LEN; // 48 bytes

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
    "256-bit master seed derived from Argon2id and automatically zeroized on drop."
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

/// Active in-memory key hierarchy for an unlocked Zerovault session.
///
/// All secret key material is scrubbed immediately on [`CryptoEngine::lock_vault`] or drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyRingState {
    #[zeroize(skip)]
    vault_id: Uuid,
    argon2_salt: [u8; 32],
    master_seed: MasterSeed,
    master_kek: MasterKek,
    manifest_key: ManifestKey,
    token_wrap_key: TokenWrapKey,
    header_verifier_key: HeaderVerifierKey,
}

impl KeyRingState {
    pub(crate) fn from_master_seed(
        vault_id: Uuid,
        argon2_salt: [u8; 32],
        master_seed: MasterSeed,
    ) -> ZeroVaultResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(&argon2_salt), master_seed.as_bytes());
        let master_kek = MasterKek::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_KEK)?);
        let manifest_key = ManifestKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_MANIFEST)?);
        let token_wrap_key =
            TokenWrapKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_TOKEN_WRAP)?);
        let header_verifier_key =
            HeaderVerifierKey::from_zeroizing(hkdf_expand_256(&hk, HKDF_INFO_VERIFIER)?);

        Ok(Self {
            vault_id,
            argon2_salt,
            master_seed,
            master_kek,
            manifest_key,
            token_wrap_key,
            header_verifier_key,
        })
    }

    /// Returns the vault UUID bound to this keyring state.
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }
}

impl fmt::Debug for KeyRingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRingState")
            .field("vault_id", &self.vault_id)
            .field("argon2_salt", &"[REDACTED]")
            .field("master_seed", &self.master_seed)
            .field("master_kek", &self.master_kek)
            .field("manifest_key", &self.manifest_key)
            .field("token_wrap_key", &self.token_wrap_key)
            .field("header_verifier_key", &self.header_verifier_key)
            .finish()
    }
}

/// Hardware-accelerated zero-knowledge [`CryptoEngine`] backed by `aws-lc-rs`.
pub struct AwsLcCryptoEngine {
    caps: HardwareCryptoCaps,
    state: RwLock<Option<KeyRingState>>,
}

impl AwsLcCryptoEngine {
    /// Verifies mandatory CPU hardware AES + GHASH acceleration and creates a locked engine.
    ///
    /// Fails closed with [`ZeroVaultError::HardwareAccelerationUnavailable`] when required
    /// hardware instructions are missing.
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

impl fmt::Debug for AwsLcCryptoEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unlocked = self.state.read().is_some();
        f.debug_struct("AwsLcCryptoEngine")
            .field("caps", &self.caps)
            .field("unlocked", &unlocked)
            .finish()
    }
}

fn fill_csprng<const N: usize>() -> ZeroVaultResult<[u8; N]> {
    let mut out = [0u8; N];
    aws_lc_rs::rand::fill(&mut out).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("CSPRNG entropy generation failed".into())
    })?;
    Ok(out)
}

fn hkdf_expand_256(hk: &Hkdf<Sha256>, info: &[u8]) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *okm)
        .map_err(|_| ZeroVaultError::CryptoTamperDetected("HKDF-SHA256 expansion failed".into()))?;
    Ok(okm)
}

async fn derive_master_seed(
    passphrase: &RedactedSecret,
    salt: [u8; 32],
    kdf: KdfParams,
) -> ZeroVaultResult<MasterSeed> {
    kdf.validate_production()?;
    let passphrase_owned = passphrase.clone();

    tokio::task::spawn_blocking(move || {
        let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32)).map_err(|_| {
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

fn new_aes256_gcm_key(key_bytes: &[u8; 32]) -> ZeroVaultResult<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("invalid AES-256-GCM key length".into())
    })?;
    Ok(LessSafeKey::new(unbound))
}

fn seal_aes256_gcm_detached(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out_ciphertext: &mut [u8],
    out_tag: &mut [u8],
) -> ZeroVaultResult<()> {
    let key = new_aes256_gcm_key(key_bytes)?;
    key.seal_out_of_place_scatter(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        plaintext,
        out_ciphertext,
        &[],
        out_tag,
    )
    .map_err(|_| ZeroVaultError::CryptoTamperDetected("AES-256-GCM encryption failed".into()))
}

fn open_aes256_gcm_detached(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    out_plaintext: &mut [u8],
) -> ZeroVaultResult<()> {
    let key = new_aes256_gcm_key(key_bytes)?;
    key.open_separate_gather(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        ciphertext,
        tag,
        out_plaintext,
    )
    .map_err(|_| {
        out_plaintext.zeroize();
        ZeroVaultError::CryptoTamperDetected("AES-256-GCM authentication tag mismatch".into())
    })
}

fn session_aad(vault_id: Uuid, argon2_salt: &[u8; 32]) -> [u8; 4 + 16 + 32] {
    let mut aad = [0u8; 52];
    aad[0..4].copy_from_slice(&SESSION_MAGIC);
    aad[4..20].copy_from_slice(vault_id.as_bytes());
    aad[20..52].copy_from_slice(argon2_salt);
    aad
}

fn token_wrap_aad(vault_id: Uuid) -> [u8; 23 + 16] {
    let mut aad = [0u8; 39];
    aad[0..23].copy_from_slice(HKDF_INFO_TOKEN_WRAP);
    aad[23..39].copy_from_slice(vault_id.as_bytes());
    aad
}

#[async_trait]
impl CryptoEngine for AwsLcCryptoEngine {
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
        self.verify_hardware_acceleration()?;
        kdf.validate_production()?;

        let vault_id = Uuid::new_v4();
        let argon2_salt = fill_csprng::<32>()?;
        let master_seed = derive_master_seed(passphrase, argon2_salt, kdf).await?;
        let keyring = KeyRingState::from_master_seed(vault_id, argon2_salt, master_seed)?;

        let verifier_nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
        let mut verifier_tag = [0u8; 32];
        let (out_ct, out_tag) = verifier_tag.split_at_mut(16);
        seal_aes256_gcm_detached(
            keyring.header_verifier_key.as_bytes(),
            verifier_nonce,
            &VaultHeader::verifier_aad(vault_id),
            vault_id.as_bytes(),
            out_ct,
            out_tag,
        )?;

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
        self.verify_hardware_acceleration()?;
        if header.version != VAULT_HEADER_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported vault header version {}",
                header.version
            )));
        }
        header.kdf.validate_production()?;

        let master_seed = derive_master_seed(passphrase, header.argon2_salt, header.kdf).await?;
        let candidate =
            KeyRingState::from_master_seed(header.vault_id, header.argon2_salt, master_seed)?;

        let mut decrypted_vault_id = [0u8; 16];
        let (ct, tag) = header.verifier_tag.split_at(16);
        open_aes256_gcm_detached(
            candidate.header_verifier_key.as_bytes(),
            header.verifier_nonce,
            &VaultHeader::verifier_aad(header.vault_id),
            ct,
            tag,
            &mut decrypted_vault_id,
        )
        .map_err(|_| ZeroVaultError::InvalidPassphrase)?;

        if !bool::from(decrypted_vault_id.ct_eq(header.vault_id.as_bytes())) {
            return Err(ZeroVaultError::InvalidPassphrase);
        }

        self.install_keyring(candidate);
        Ok(())
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
        self.verify_hardware_acceleration()?;

        let (vault_id, payload) = self.with_unlocked(|state| {
            let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
            let aad = session_aad(state.vault_id, &state.argon2_salt);

            let mut buf = Zeroizing::new(vec![0u8; SESSION_BLOB_LEN]);
            buf[0..4].copy_from_slice(&SESSION_MAGIC);
            buf[4] = SESSION_FORMAT_VERSION;
            buf[5..21].copy_from_slice(state.vault_id.as_bytes());
            buf[21..53].copy_from_slice(&state.argon2_salt);
            buf[53..85].copy_from_slice(state.master_seed.as_bytes());
            buf[85..97].copy_from_slice(&nonce);

            let (out_ct, out_tag) = buf[97..SESSION_BLOB_LEN].split_at_mut(16);
            seal_aes256_gcm_detached(
                state.header_verifier_key.as_bytes(),
                nonce,
                &aad,
                state.vault_id.as_bytes(),
                out_ct,
                out_tag,
            )?;
            Ok((state.vault_id, buf))
        })?;

        store
            .set_secret(service, &vault_id.to_string(), &payload)
            .await
    }

    async fn restore_session(
        &self,
        store: &dyn SecretStore,
        service: &str,
        expected_vault_id: Uuid,
    ) -> ZeroVaultResult<bool> {
        self.verify_hardware_acceleration()?;

        let Some(blob) = store
            .get_secret(service, &expected_vault_id.to_string())
            .await?
        else {
            return Ok(false);
        };

        if blob.len() != SESSION_BLOB_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "corrupted session secret length: expected {SESSION_BLOB_LEN}, got {}",
                blob.len()
            )));
        }
        if blob[0..4] != SESSION_MAGIC || blob[4] != SESSION_FORMAT_VERSION {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "invalid session secret header".into(),
            ));
        }

        let stored_vault_id = Uuid::from_slice(&blob[5..21]).map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("invalid vault_id in session".into())
        })?;
        if stored_vault_id != expected_vault_id {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "session secret vault_id mismatch".into(),
            ));
        }

        let mut argon2_salt = [0u8; 32];
        argon2_salt.copy_from_slice(&blob[21..53]);

        let mut seed_arr = Zeroizing::new([0u8; 32]);
        seed_arr.copy_from_slice(&blob[53..85]);
        let master_seed = MasterSeed::from_zeroizing(seed_arr);

        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&blob[85..97]);
        let (ct, tag) = blob[97..SESSION_BLOB_LEN].split_at(16);

        let candidate =
            KeyRingState::from_master_seed(expected_vault_id, argon2_salt, master_seed)?;
        let aad = session_aad(expected_vault_id, &argon2_salt);
        let mut decrypted_vault_id = [0u8; 16];
        open_aes256_gcm_detached(
            candidate.header_verifier_key.as_bytes(),
            nonce,
            &aad,
            ct,
            tag,
            &mut decrypted_vault_id,
        )?;
        if !bool::from(decrypted_vault_id.ct_eq(expected_vault_id.as_bytes())) {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "session secret verifier payload mismatch".into(),
            ));
        }

        self.install_keyring(candidate);
        Ok(true)
    }

    fn generate_dek(&self) -> ZeroVaultResult<DekBytes> {
        self.verify_hardware_acceleration()?;
        let mut raw = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut *raw).map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("CSPRNG entropy generation failed".into())
        })?;
        Ok(DekBytes::from_array(*raw))
    }

    fn wrap_dek(&self, file_id: Uuid, dek: &DekBytes) -> ZeroVaultResult<WrappedDek> {
        self.verify_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
            let aad = WrappedDek::dek_wrap_aad(file_id);
            let mut ciphertext_and_tag = vec![0u8; WRAPPED_DEK_LEN];
            let (out_ct, out_tag) = ciphertext_and_tag.split_at_mut(32);

            seal_aes256_gcm_detached(
                state.master_kek.as_bytes(),
                nonce,
                &aad,
                dek.as_bytes(),
                out_ct,
                out_tag,
            )?;

            Ok(WrappedDek {
                nonce,
                ciphertext_and_tag,
            })
        })
    }

    fn unwrap_dek(&self, file_id: Uuid, wrapped: &WrappedDek) -> ZeroVaultResult<DekBytes> {
        self.verify_hardware_acceleration()?;
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

            open_aes256_gcm_detached(
                state.master_kek.as_bytes(),
                wrapped.nonce,
                &aad,
                ct,
                tag,
                &mut *pt,
            )?;

            Ok(DekBytes::from_array(*pt))
        })
    }

    fn encrypt_chunk_into(
        &self,
        dek: &DekBytes,
        aad: ChunkAad,
        plaintext: &[u8],
        out_wire: &mut BytesMut,
    ) -> ZeroVaultResult<ChunkHeader> {
        self.verify_hardware_acceleration()?;

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
        out_wire.resize(total_len, 0);
        out_wire[..CHUNK_HEADER_LEN].copy_from_slice(&header_bytes);

        let (out_ct, out_tag) = out_wire[CHUNK_HEADER_LEN..].split_at_mut(plaintext.len());
        if let Err(err) = seal_aes256_gcm_detached(
            dek.as_bytes(),
            nonce,
            &aad.to_bytes(),
            plaintext,
            out_ct,
            out_tag,
        ) {
            out_wire.clear();
            return Err(err);
        }

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
        self.verify_hardware_acceleration()?;

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
        out_plaintext.resize(pt_len, 0);

        if let Err(err) = open_aes256_gcm_detached(
            dek.as_bytes(),
            header.nonce,
            &aad.to_bytes(),
            ct,
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
        self.verify_hardware_acceleration()?;
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
            out.resize(total_len, 0);
            out[..MANIFEST_HEADER_LEN].copy_from_slice(&header.encode());

            let (out_ct, out_tag) = out[MANIFEST_HEADER_LEN..].split_at_mut(payload.len());
            seal_aes256_gcm_detached(
                state.manifest_key.as_bytes(),
                nonce,
                &aad,
                &payload,
                out_ct,
                out_tag,
            )?;

            Ok(out.freeze())
        })
    }

    fn open_manifest(&self, sealed_bytes: &[u8]) -> ZeroVaultResult<VaultManifest> {
        self.verify_hardware_acceleration()?;
        let hdr = ManifestWireHeader::decode(sealed_bytes)?;
        let ct_end = sealed_bytes.len() - AES_GCM_TAG_LEN;
        let ct = &sealed_bytes[MANIFEST_HEADER_LEN..ct_end];
        let tag = &sealed_bytes[ct_end..];
        let aad = VaultManifest::manifest_aad(hdr.vault_id, hdr.revision);

        let pt = self.with_unlocked(|state| {
            let mut pt = Zeroizing::new(vec![0u8; ct.len()]);
            open_aes256_gcm_detached(
                state.manifest_key.as_bytes(),
                hdr.nonce,
                &aad,
                ct,
                tag,
                &mut pt,
            )?;
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
        self.verify_hardware_acceleration()?;
        self.with_unlocked(|state| {
            let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
            let aad = token_wrap_aad(state.vault_id);
            let mut out = vec![0u8; AES_GCM_NONCE_LEN + plaintext.len() + AES_GCM_TAG_LEN];
            out[..AES_GCM_NONCE_LEN].copy_from_slice(&nonce);

            let (out_ct, out_tag) = out[AES_GCM_NONCE_LEN..].split_at_mut(plaintext.len());
            seal_aes256_gcm_detached(
                state.token_wrap_key.as_bytes(),
                nonce,
                &aad,
                plaintext,
                out_ct,
                out_tag,
            )?;
            Ok(out)
        })
    }

    fn unwrap_token_payload(&self, wrapped: &[u8]) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
        self.verify_hardware_acceleration()?;
        if wrapped.len() < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "wrapped token payload too short".into(),
            ));
        }

        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&wrapped[..AES_GCM_NONCE_LEN]);
        let ct_end = wrapped.len() - AES_GCM_TAG_LEN;
        let ct = &wrapped[AES_GCM_NONCE_LEN..ct_end];
        let tag = &wrapped[ct_end..];

        self.with_unlocked(|state| {
            let aad = token_wrap_aad(state.vault_id);
            let mut pt = Zeroizing::new(vec![0u8; ct.len()]);
            open_aes256_gcm_detached(
                state.token_wrap_key.as_bytes(),
                nonce,
                &aad,
                ct,
                tag,
                &mut pt,
            )?;
            Ok(pt)
        })
    }

    fn benchmark_aes256_gcm(&self, total_mib: usize) -> ZeroVaultResult<CryptoBenchmarkReport> {
        let caps = self.verify_hardware_acceleration()?;
        let chunks = total_mib.max(1).div_ceil(4);
        let measured_mib = chunks * 4;

        let dek = self.generate_dek()?;
        let file_id = Uuid::new_v4();

        // Exactly ONE reusable 4 MiB plaintext buffer and ONE reusable wire BytesMut buffer.
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
