//! Serverless Zero-Knowledge E2E Sharing wire models (`zv://` Capability URIs & `keybox.zv`).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ZeroVaultError, ZeroVaultResult};
use crate::wire::{AES_GCM_NONCE_LEN, ChunkRef, WrappedDek};

/// Wire magic for `vault/keybox.zv` (`ZVK1`).
pub const KEYBOX_MAGIC: [u8; 4] = *b"ZVK1";
/// Current `keybox.zv` format version.
pub const KEYBOX_VERSION: u8 = 1;

/// Wire magic for `shares/<aa>/<bb>/<uuid>.zvs` (`ZVS1`).
pub const SHARE_ENVELOPE_MAGIC: [u8; 4] = *b"ZVS1";
/// Current share envelope format version.
pub const SHARE_ENVELOPE_VERSION: u8 = 1;

/// NIST FIPS 203 `ML-KEM-768` public encapsulation key length (`1,184` bytes).
pub const ML_KEM_768_ENCAPS_KEY_LEN: usize = 1184;
/// NIST FIPS 203 `ML-KEM-768` private decapsulation key length (`2,400` bytes).
pub const ML_KEM_768_DECAPS_KEY_LEN: usize = 2400;
/// NIST FIPS 203 `ML-KEM-768` ciphertext length (`1,088` bytes).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// `Ed25519` public key length (`32` bytes).
pub const ED25519_PUBKEY_LEN: usize = 32;
/// `Ed25519` signature length (`64` bytes).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// `X25519` public/private key length (`32` bytes).
pub const X25519_KEY_LEN: usize = 32;

/// Primary capability URI scheme for EntroCloud (`ec://`).
pub const CAPABILITY_URI_SCHEME: &str = "ec";
/// Legacy backward-compatible capability URI scheme (`zv://`).
pub const LEGACY_CAPABILITY_URI_SCHEME: &str = "zv";

/// Parsed `ec://` (and legacy `zv://`) 1-click read-only capability URI.
///
/// Format:
/// `ec://share/v1/<backend_id>?root=<encoded_root>&share=<share_uuid>#<base64url(srk_32b || ed25519_pubkey_32b)>`
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CapabilityUri {
    /// Logical backend identifier or provider tag (`fs`, `s3`, `gdrive`, etc.).
    #[zeroize(skip)]
    pub backend_hint: String,
    /// Optional root/bucket locator needed by recipient to reach public/shared object store.
    #[zeroize(skip)]
    pub root_locator: String,
    /// Share descriptor UUID (`shares/<aa>/<bb>/<share_id>.zvs`).
    #[zeroize(skip)]
    pub share_id: Uuid,
    /// 256-bit Share Root Key (`SRK`) carried exclusively in the client-only URL `#fragment`.
    pub share_root_key: Zeroizing<[u8; 32]>,
    /// Owner's 32-byte `Ed25519` public verification key pinned in the client-only `#fragment`.
    #[zeroize(skip)]
    pub owner_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
}

impl fmt::Debug for CapabilityUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityUri")
            .field("backend_hint", &self.backend_hint)
            .field("root_locator", &self.root_locator)
            .field("share_id", &self.share_id)
            .field("share_root_key", &"[REDACTED]")
            .field(
                "owner_ed25519_pubkey",
                &hex::encode(self.owner_ed25519_pubkey),
            )
            .finish()
    }
}

impl CapabilityUri {
    /// Encodes the capability URI using the primary `ec://` scheme with `#<base64url(SRK || PubKey)>` fragment.
    pub fn encode(&self) -> ZeroVaultResult<String> {
        self.encode_with_scheme(CAPABILITY_URI_SCHEME)
    }

    /// Encodes the capability URI using either `"ec"` or legacy `"zv"`.
    pub fn encode_with_scheme(&self, scheme: &str) -> ZeroVaultResult<String> {
        if scheme != CAPABILITY_URI_SCHEME && scheme != LEGACY_CAPABILITY_URI_SCHEME {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported capability URI scheme: {scheme:?}"
            )));
        }
        if self.backend_hint.is_empty()
            || self
                .backend_hint
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "invalid capability URI backend_hint: {:?}",
                self.backend_hint
            )));
        }
        let mut url = Url::parse(&format!("{scheme}://share/v1/{}", self.backend_hint)).map_err(
            |e| ZeroVaultError::InvalidWireFormat(format!("invalid {scheme}:// base: {e}")),
        )?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("root", &self.root_locator);
            qp.append_pair("share", &self.share_id.hyphenated().to_string());
        }
        let mut frag_raw = Zeroizing::new([0u8; 64]);
        frag_raw[0..32].copy_from_slice(&*self.share_root_key);
        frag_raw[32..64].copy_from_slice(&self.owner_ed25519_pubkey);
        let frag_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(*frag_raw));
        url.set_fragment(Some(frag_b64.as_str()));
        Ok(url.into())
    }

    /// Parses and validates an `ec://` or backward-compatible `zv://` capability URI.
    pub fn parse(uri: &str) -> ZeroVaultResult<Self> {
        let url = Url::parse(uri).map_err(|e| {
            ZeroVaultError::InvalidWireFormat(format!("malformed capability URI: {e}"))
        })?;
        let scheme = url.scheme();
        if (scheme != CAPABILITY_URI_SCHEME && scheme != LEGACY_CAPABILITY_URI_SCHEME)
            || url.host_str() != Some("share")
        {
            return Err(ZeroVaultError::InvalidWireFormat(
                "capability URI must start with ec://share/v1/ (or zv://share/v1/)".into(),
            ));
        }
        let segments: Vec<&str> = url
            .path_segments()
            .map(|s| s.collect())
            .unwrap_or_default();
        if segments.len() != 2 || segments[0] != "v1" || segments[1].is_empty() {
            return Err(ZeroVaultError::InvalidWireFormat(
                "capability URI path must match /v1/<backend_hint>".into(),
            ));
        }
        let backend_hint = segments[1].to_owned();

        let mut root_locator = None;
        let mut share_id = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "root" => root_locator = Some(v.into_owned()),
                "share" => {
                    let parsed = Uuid::parse_str(&v).map_err(|e| {
                        ZeroVaultError::InvalidWireFormat(format!("invalid share UUID: {e}"))
                    })?;
                    share_id = Some(parsed);
                }
                _ => {}
            }
        }
        let share_id = share_id.ok_or_else(|| {
            ZeroVaultError::InvalidWireFormat("capability URI missing ?share=<uuid>".into())
        })?;
        let fragment = url.fragment().ok_or_else(|| {
            ZeroVaultError::InvalidWireFormat("capability URI missing #<SRK+PubKey> fragment".into())
        })?;
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(fragment).map_err(|e| {
            ZeroVaultError::InvalidWireFormat(format!("invalid base64url capability fragment: {e}"))
        })?);
        if decoded.len() != 64 {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "capability fragment must decode to 64 bytes (32B SRK + 32B Ed25519 pubkey), got {}",
                decoded.len()
            )));
        }
        let mut srk = Zeroizing::new([0u8; 32]);
        srk.copy_from_slice(&decoded[0..32]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&decoded[32..64]);

        Ok(Self {
            backend_hint,
            root_locator: root_locator.unwrap_or_default(),
            share_id,
            share_root_key: srk,
            owner_ed25519_pubkey: pubkey,
        })
    }
}

/// Encrypted inner payload of a read-only `zv://` share descriptor (`shares/<aa>/<bb>/<uuid>.zvs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareDescriptor {
    /// Share UUID matching the remote object key and URI query parameter.
    pub share_id: Uuid,
    /// Shared file cryptographic UUID (used in `ChunkAad`).
    pub file_id: Uuid,
    /// Original filename (decrypted only by holders of `SRK`).
    pub filename: String,
    /// Logical plaintext file byte length.
    pub size: u64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Per-file `DEK` wrapped under `HKDF(SRK, "zerovault.v2.share-kek")`.
    pub wrapped_dek: WrappedDek,
    /// Ordered 4 MiB chunk references.
    pub chunks: Vec<ChunkRef>,
}

/// Outer wire envelope (`ZVS1`) for a signed, AEAD-sealed `zv://` share descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedShareEnvelope {
    /// Format version (`1`).
    pub version: u8,
    /// Share UUID.
    pub share_id: Uuid,
    /// Owner's 32-byte `Ed25519` public key.
    pub owner_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// 96-bit AES-256-GCM nonce.
    pub nonce: [u8; AES_GCM_NONCE_LEN],
    /// AES-256-GCM ciphertext + 16B tag of `postcard(ShareDescriptor)`.
    pub ciphertext_and_tag: Vec<u8>,
    /// 64-byte `Ed25519` signature over [`Self::signing_transcript`].
    pub ed25519_signature: Vec<u8>,
}

impl SignedShareEnvelope {
    /// Canonical domain-separated transcript signed by `owner_ed25519_pubkey`.
    #[must_use]
    pub fn signing_transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.ciphertext_and_tag.len());
        out.extend_from_slice(b"ZV-SHARE-SIG-V1");
        out.push(self.version);
        out.extend_from_slice(self.share_id.as_bytes());
        out.extend_from_slice(&self.owner_ed25519_pubkey);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext_and_tag.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.ciphertext_and_tag);
        out
    }

    /// Encodes the `ZVS1` envelope to wire bytes (`b"ZVS1" || postcard`).
    pub fn encode(&self) -> ZeroVaultResult<Vec<u8>> {
        if self.version != SHARE_ENVELOPE_VERSION
            || self.ed25519_signature.len() != ED25519_SIGNATURE_LEN
        {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid share envelope version or signature length".into(),
            ));
        }
        let body = postcard::to_allocvec(self)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&SHARE_ENVELOPE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes a `ZVS1` envelope from wire bytes.
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() < 8 || bytes[0..4] != SHARE_ENVELOPE_MAGIC {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid ZVS1 share envelope magic".into(),
            ));
        }
        let env: Self = postcard::from_bytes(&bytes[4..]).map_err(|e| {
            ZeroVaultError::InvalidWireFormat(format!("share envelope decode failed: {e}"))
        })?;
        if env.version != SHARE_ENVELOPE_VERSION
            || env.ed25519_signature.len() != ED25519_SIGNATURE_LEN
        {
            return Err(ZeroVaultError::InvalidWireFormat(
                "unsupported share envelope version or malformed signature".into(),
            ));
        }
        Ok(env)
    }
}

/// Public hybrid post-quantum identity bundle shared out-of-band by a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientPublicBundle {
    /// Deterministic 32-hex recipient fingerprint (`BLAKE3` of public keys).
    pub recipient_id: String,
    /// Human-readable label (local display hint only).
    pub label: String,
    /// `Ed25519` public signing/identity key (`32` bytes).
    pub ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// Static `X25519` public key (`32` bytes).
    pub x25519_pubkey: [u8; X25519_KEY_LEN],
    /// NIST FIPS 203 `ML-KEM-768` encapsulation public key (`1,184` bytes).
    pub mlkem768_encaps_key: Vec<u8>,
}

impl RecipientPublicBundle {
    /// Computes the canonical 32-hex recipient fingerprint from the three public keys.
    #[must_use]
    pub fn compute_id(
        ed25519_pubkey: &[u8; ED25519_PUBKEY_LEN],
        x25519_pubkey: &[u8; X25519_KEY_LEN],
        mlkem768_encaps_key: &[u8],
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZV-RCPT-ID-V1");
        hasher.update(ed25519_pubkey);
        hasher.update(x25519_pubkey);
        hasher.update(&(mlkem768_encaps_key.len() as u32).to_le_bytes());
        hasher.update(mlkem768_encaps_key);
        let digest = hasher.finalize();
        hex::encode(&digest.as_bytes()[0..16])
    }

    /// Validates key sizes and verifies `recipient_id` matches the cryptographic fingerprint.
    pub fn validate(&self) -> ZeroVaultResult<()> {
        if self.mlkem768_encaps_key.len() != ML_KEM_768_ENCAPS_KEY_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "ML-KEM-768 encaps key must be {ML_KEM_768_ENCAPS_KEY_LEN} bytes, got {}",
                self.mlkem768_encaps_key.len()
            )));
        }
        let expected = Self::compute_id(
            &self.ed25519_pubkey,
            &self.x25519_pubkey,
            &self.mlkem768_encaps_key,
        );
        if self.recipient_id != expected {
            return Err(ZeroVaultError::CryptoTamperDetected(format!(
                "recipient_id fingerprint mismatch: expected {expected}, got {}",
                self.recipient_id
            )));
        }
        Ok(())
    }

    /// Encodes the public bundle as compact URL-safe Base64 for easy sharing.
    pub fn to_base64(&self) -> ZeroVaultResult<String> {
        self.validate()?;
        let raw = postcard::to_allocvec(self)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Decodes and validates a Base64-encoded public bundle.
    pub fn from_base64(encoded: &str) -> ZeroVaultResult<Self> {
        let raw = URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|e| {
            ZeroVaultError::InvalidWireFormat(format!("invalid recipient bundle base64: {e}"))
        })?;
        let bundle: Self = postcard::from_bytes(&raw).map_err(|e| {
            ZeroVaultError::InvalidWireFormat(format!("invalid recipient bundle payload: {e}"))
        })?;
        bundle.validate()?;
        Ok(bundle)
    }
}

/// Private hybrid post-quantum recipient identity (`Ed25519` + `X25519` + `ML-KEM-768`),
/// automatically zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RecipientPrivateIdentity {
    /// Public bundle (kept alongside private keys because `aws-lc-rs` `DecapsulationKey::new`
    /// requires separate `EncapsulationKey` serialization).
    #[zeroize(skip)]
    pub public: RecipientPublicBundle,
    /// 32-byte `Ed25519` private seed (or PKCS#8 v1 raw seed).
    pub ed25519_seed: Zeroizing<[u8; 32]>,
    /// 32-byte static `X25519` private scalar.
    pub x25519_private: Zeroizing<[u8; X25519_KEY_LEN]>,
    /// 2,400-byte NIST FIPS 203 `ML-KEM-768` private decapsulation key.
    pub mlkem768_decaps_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RecipientPrivateIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientPrivateIdentity")
            .field("recipient_id", &self.public.recipient_id)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

/// One recipient key-wrapping stanza inside `vault/keybox.zv` (`ZVK1`),
/// combining classical `X25519` ECDH and post-quantum `ML-KEM-768`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridRecipientStanza {
    /// Target recipient 32-hex fingerprint.
    pub recipient_id: String,
    /// Sender's ephemeral `X25519` public key (`32` bytes).
    pub ephemeral_x25519_pubkey: [u8; X25519_KEY_LEN],
    /// `ML-KEM-768` KEM ciphertext (`1,088` bytes).
    pub mlkem768_ciphertext: Vec<u8>,
    /// 96-bit salt/nonce used for `HKDF-SHA256` and `AES-256-GCM` wrapping.
    pub wrap_nonce: [u8; AES_GCM_NONCE_LEN],
    /// `AES-256-GCM` wrapped 32-byte `FolderRootKey` + 16B tag (`48` bytes).
    pub wrapped_folder_key: Vec<u8>,
}

impl HybridRecipientStanza {
    /// Canonical AAD bound into `wrapped_folder_key` AEAD:
    /// `b"ZV-KEYBOX-STANZA-V1" || vault_id || epoch_le || recipient_id`.
    #[must_use]
    pub fn stanza_aad(vault_id: Uuid, epoch: u64, recipient_id: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(19 + 16 + 8 + recipient_id.len());
        aad.extend_from_slice(b"ZV-KEYBOX-STANZA-V1");
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(recipient_id.as_bytes());
        aad
    }

    /// Validates stanza field sizes before cryptographic operations.
    pub fn validate(&self) -> ZeroVaultResult<()> {
        if self.mlkem768_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "stanza ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_LEN} bytes, got {}",
                self.mlkem768_ciphertext.len()
            )));
        }
        if self.wrapped_folder_key.len() != 48 {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "stanza wrapped_folder_key must be 48 bytes, got {}",
                self.wrapped_folder_key.len()
            )));
        }
        Ok(())
    }
}

/// Signed multi-recipient post-quantum Cloud Keybox (`vault/keybox.zv` — `ZVK1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeybox {
    /// Format version (`1`).
    pub version: u8,
    /// Shared folder / vault UUID.
    pub vault_id: Uuid,
    /// Monotonic security epoch (`>= 1`). Incremented with fresh `FolderRootKey` on every revocation.
    pub epoch: u64,
    /// Folder owner's 32-byte `Ed25519` public key.
    pub owner_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// Keybox publication timestamp.
    pub created_at: DateTime<Utc>,
    /// Authorized recipient stanzas for this `epoch`.
    pub stanzas: Vec<HybridRecipientStanza>,
    /// 64-byte owner `Ed25519` signature over [`Self::signing_transcript`].
    pub owner_signature: Vec<u8>,
}

impl SignedKeybox {
    /// Canonical domain-separated byte transcript authenticated by `owner_signature`.
    pub fn signing_transcript(&self) -> ZeroVaultResult<Vec<u8>> {
        let stanzas_bytes = postcard::to_allocvec(&self.stanzas)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?;
        let mut out = Vec::with_capacity(96 + stanzas_bytes.len());
        out.extend_from_slice(b"ZV-KEYBOX-SIG-V1");
        out.push(self.version);
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.owner_ed25519_pubkey);
        out.extend_from_slice(&self.created_at.timestamp_millis().to_le_bytes());
        out.extend_from_slice(&(stanzas_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&stanzas_bytes);
        Ok(out)
    }

    /// Encodes the `ZVK1` keybox to wire bytes (`b"ZVK1" || postcard`).
    pub fn encode(&self) -> ZeroVaultResult<Vec<u8>> {
        if self.version != KEYBOX_VERSION || self.epoch == 0 {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid keybox version or zero epoch".into(),
            ));
        }
        if self.owner_signature.len() != ED25519_SIGNATURE_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(
                "keybox owner_signature must be 64 bytes".into(),
            ));
        }
        for stanza in &self.stanzas {
            stanza.validate()?;
        }
        let body = postcard::to_allocvec(self)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&KEYBOX_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes and structurally validates a `ZVK1` keybox from wire bytes.
    /// (Cryptographic `Ed25519` signature + SQLite `epoch` floor verification is performed by `entrocloud-crypto` / `entrocloud-core`.)
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() < 8 || bytes[0..4] != KEYBOX_MAGIC {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "invalid ZVK1 keybox magic".into(),
            ));
        }
        let kb: Self = postcard::from_bytes(&bytes[4..]).map_err(|e| {
            ZeroVaultError::CryptoTamperDetected(format!("corrupted keybox payload: {e}"))
        })?;
        if kb.version != KEYBOX_VERSION || kb.epoch == 0 {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "invalid keybox version or zero epoch".into(),
            ));
        }
        if kb.owner_signature.len() != ED25519_SIGNATURE_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "missing or malformed 64-byte Ed25519 keybox signature".into(),
            ));
        }
        for stanza in &kb.stanzas {
            stanza.validate()?;
        }
        Ok(kb)
    }
}
