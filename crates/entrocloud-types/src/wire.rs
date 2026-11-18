use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ZeroVaultError, ZeroVaultResult};
use crate::traits::EntryKind;

/// Fixed plaintext chunk size: exactly 4 MiB (`4_194_304` bytes).
pub const PLAINTEXT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Fixed wire size of a chunk header (`ZVC1`).
pub const CHUNK_HEADER_LEN: usize = 32;
/// Fixed AES-256-GCM authentication tag length.
pub const AES_GCM_TAG_LEN: usize = 16;
/// Fixed AES-256-GCM 96-bit nonce length.
pub const AES_GCM_NONCE_LEN: usize = 12;
/// Maximum encrypted wire chunk size (`32 + 4_194_304 + 16`).
pub const MAX_ENCRYPTED_CHUNK_SIZE: usize =
    CHUNK_HEADER_LEN + PLAINTEXT_CHUNK_SIZE + AES_GCM_TAG_LEN;

/// Chunk wire header magic bytes.
pub const CHUNK_MAGIC: [u8; 4] = *b"ZVC1";
/// Current chunk wire format version.
pub const CHUNK_FORMAT_VERSION: u8 = 1;
/// Flag bit marking the final chunk of a file.
pub const CHUNK_FLAG_FINAL: u8 = 0x01;

/// Vault header magic bytes.
pub const VAULT_HEADER_MAGIC: [u8; 4] = *b"ZVH1";
/// Current vault header format version.
pub const VAULT_HEADER_VERSION: u8 = 1;
/// Fixed size of an encoded `VaultHeader` (`ZVH1`).
pub const VAULT_HEADER_LEN: usize = 112;

/// Encrypted manifest wire magic bytes.
pub const MANIFEST_MAGIC: [u8; 4] = *b"ZVM1";
/// Current encrypted manifest format version.
pub const MANIFEST_FORMAT_VERSION: u8 = 1;
/// Fixed length of the unencrypted prefix header on a sealed manifest blob.
pub const MANIFEST_HEADER_LEN: usize = 44;

/// Minimum Argon2id memory parameter in KiB (64 MiB).
pub const MIN_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Maximum Argon2id memory parameter in KiB (256 MiB — pre-allocation DoS ceiling ported from CloudBridge).
pub const MAX_ARGON2_MEMORY_KIB: u32 = 262_144;
/// Minimum Argon2id time cost (iterations).
pub const MIN_ARGON2_ITERATIONS: u32 = 3;
/// Maximum Argon2id time cost (iterations).
pub const MAX_ARGON2_ITERATIONS: u32 = 10;
/// Minimum Argon2id parallelism lanes.
pub const MIN_ARGON2_PARALLELISM: u32 = 4;
/// Maximum Argon2id parallelism lanes.
pub const MAX_ARGON2_PARALLELISM: u32 = 16;

/// Extended attribute exposing the current hydration state on Linux FUSE mounts.
pub const XATTR_ENTROCLOUD_STATE: &str = "user.entrocloud.state";
/// Extended attribute for pinning (`"1"`) or dehydrating (`"0"`) via Linux xattrs.
pub const XATTR_ENTROCLOUD_PIN: &str = "user.entrocloud.pin";
/// Extended attribute exposing the cryptographic `file_id` UUID on Linux FUSE mounts.
pub const XATTR_ENTROCLOUD_FILE_ID: &str = "user.entrocloud.file_id";

/// Backward-compatible Linux xattr state constant.
pub const XATTR_ZEROVAULT_STATE: &str = "user.zerovault.state";
/// Backward-compatible Linux xattr pin constant.
pub const XATTR_ZEROVAULT_PIN: &str = "user.zerovault.pin";
/// Backward-compatible Linux xattr file_id constant.
pub const XATTR_ZEROVAULT_FILE_ID: &str = "user.zerovault.file_id";

/// Fixed remote object key for the vault bootstrap header.
pub const VAULT_HEADER_OBJECT_KEY: &str = "vault/header.zvh";
/// Fixed remote object key for the post-quantum multi-recipient folder keybox.
pub const KEYBOX_OBJECT_KEY: &str = "vault/keybox.zv";
/// Fixed remote object key for the latest encrypted manifest pointer.
pub const MANIFEST_HEAD_OBJECT_KEY: &str = "manifests/head.zvm";

/// HKDF domain separation context for wrapping per-file DEKs.
pub const HKDF_INFO_KEK: &[u8] = b"zerovault.v1.kek";
/// HKDF domain separation context for sealing/opening manifests.
pub const HKDF_INFO_MANIFEST: &[u8] = b"zerovault.v1.manifest";
/// HKDF domain separation context for wrapping OAuth tokens before keyring persistence.
pub const HKDF_INFO_TOKEN_WRAP: &[u8] = b"zerovault.v1.token-wrap";
/// HKDF domain separation context for vault passphrase header verification.
pub const HKDF_INFO_VERIFIER: &[u8] = b"zerovault.v1.verifier";
/// HKDF domain separation context for encrypting local SQLite metadata columns.
pub const HKDF_INFO_META_AEAD: &[u8] = b"zerovault.v2.meta-aead";
/// HKDF domain separation context for keyed BLAKE3 SQLite blind indexes.
pub const HKDF_INFO_META_BLIND: &[u8] = b"zerovault.v2.meta-blind";
/// HKDF domain separation context for encrypting local `.zvpart` dirty chunk staging files.
pub const HKDF_INFO_STAGING: &[u8] = b"zerovault.v2.staging";

/// Redacted 256-bit Data Encryption Key wrapper with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DekBytes(Zeroizing<[u8; 32]>);

impl DekBytes {
    /// Construct from a 32-byte key array.
    #[must_use]
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Construct from a 32-byte slice.
    pub fn from_slice(slice: &[u8]) -> ZeroVaultResult<Self> {
        let arr: [u8; 32] = slice.try_into().map_err(|_| {
            ZeroVaultError::InvalidWireFormat(format!(
                "expected 32-byte DEK, got {} bytes",
                slice.len()
            ))
        })?;
        Ok(Self(Zeroizing::new(arr)))
    }

    /// Borrow the raw 256-bit key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DekBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DekBytes([REDACTED])")
    }
}

/// Redacted UTF-8 secret wrapper (passphrases, OAuth tokens, API secrets).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    /// Wrap a plaintext secret string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrow the secret slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&str> for RedactedSecret {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl From<String> for RedactedSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactedSecret([REDACTED])")
    }
}

/// Argon2id key derivation parameters persisted inside [`VaultHeader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB (`65_536..=262_144`).
    pub m_cost_kib: u32,
    /// Iteration count (`3..=10`).
    pub t_cost: u32,
    /// Parallelism lanes (`4..=16`).
    pub p_cost: u32,
}

impl KdfParams {
    /// Standard production Argon2id parameters: 64 MiB RAM, 3 iterations, 4 lanes.
    #[must_use]
    pub const fn interactive_production() -> Self {
        Self {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB,
            t_cost: MIN_ARGON2_ITERATIONS,
            p_cost: MIN_ARGON2_PARALLELISM,
        }
    }

    /// Enforces both the minimum security floor and pre-allocation anti-OOM DoS ceiling.
    pub fn validate_production(&self) -> ZeroVaultResult<()> {
        if self.m_cost_kib < MIN_ARGON2_MEMORY_KIB
            || self.m_cost_kib > MAX_ARGON2_MEMORY_KIB
            || self.t_cost < MIN_ARGON2_ITERATIONS
            || self.t_cost > MAX_ARGON2_ITERATIONS
            || self.p_cost < MIN_ARGON2_PARALLELISM
            || self.p_cost > MAX_ARGON2_PARALLELISM
        {
            return Err(ZeroVaultError::KdfPolicyViolation {
                m_cost_kib: self.m_cost_kib,
                t_cost: self.t_cost,
                p_cost: self.p_cost,
            });
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::interactive_production()
    }
}

/// Remote bootstrap header (`vault/header.zvh`) containing salt, KDF params, and verifier tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Wire format version (must be [`VAULT_HEADER_VERSION`]).
    pub version: u8,
    /// Unique vault identifier.
    pub vault_id: Uuid,
    /// Random 256-bit Argon2id salt.
    pub argon2_salt: [u8; 32],
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// 96-bit nonce used to authenticate `vault_id`.
    pub verifier_nonce: [u8; AES_GCM_NONCE_LEN],
    /// AES-256-GCM ciphertext (16B `vault_id`) + 16B tag under `HeaderVerifierKey`.
    pub verifier_tag: [u8; 32],
}

impl VaultHeader {
    /// Returns the 20-byte canonical AAD (`b"ZVH1" || vault_id`) for verifier authentication.
    #[must_use]
    pub fn verifier_aad(vault_id: Uuid) -> [u8; 20] {
        let mut aad = [0u8; 20];
        aad[..4].copy_from_slice(&VAULT_HEADER_MAGIC);
        aad[4..20].copy_from_slice(vault_id.as_bytes());
        aad
    }

    /// Encodes the vault header to its exact 112-byte wire representation.
    #[must_use]
    pub fn encode(&self) -> [u8; VAULT_HEADER_LEN] {
        let mut out = [0u8; VAULT_HEADER_LEN];
        out[0..4].copy_from_slice(&VAULT_HEADER_MAGIC);
        out[4] = self.version;
        out[8..24].copy_from_slice(self.vault_id.as_bytes());
        out[24..56].copy_from_slice(&self.argon2_salt);
        out[56..60].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        out[60..64].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[64..68].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        out[68..80].copy_from_slice(&self.verifier_nonce);
        out[80..112].copy_from_slice(&self.verifier_tag);
        out
    }

    /// Decodes a 112-byte vault header, validating magic, version, reserved bytes, and KDF bounds.
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() != VAULT_HEADER_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "vault header length must be {VAULT_HEADER_LEN}, got {}",
                bytes.len()
            )));
        }
        if bytes[0..4] != VAULT_HEADER_MAGIC {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid vault header magic".into(),
            ));
        }
        if bytes[4] != VAULT_HEADER_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported vault header version {}",
                bytes[4]
            )));
        }
        if bytes[5..8] != [0, 0, 0] {
            return Err(ZeroVaultError::InvalidWireFormat(
                "non-zero reserved bytes in vault header".into(),
            ));
        }

        let vault_id = Uuid::from_slice(&bytes[8..24])
            .map_err(|e| ZeroVaultError::InvalidWireFormat(format!("invalid vault_id: {e}")))?;
        let mut argon2_salt = [0u8; 32];
        argon2_salt.copy_from_slice(&bytes[24..56]);
        let kdf = KdfParams {
            m_cost_kib: u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]),
            t_cost: u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]),
            p_cost: u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]),
        };
        kdf.validate_production()?;

        let mut verifier_nonce = [0u8; AES_GCM_NONCE_LEN];
        verifier_nonce.copy_from_slice(&bytes[68..80]);
        let mut verifier_tag = [0u8; 32];
        verifier_tag.copy_from_slice(&bytes[80..112]);

        Ok(Self {
            version: bytes[4],
            vault_id,
            argon2_salt,
            kdf,
            verifier_nonce,
            verifier_tag,
        })
    }
}

/// Encrypted per-file Data Encryption Key wrapped by `MasterKek` (or `FolderRootKey`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDek {
    /// Fresh 96-bit nonce used to wrap the DEK.
    pub nonce: [u8; AES_GCM_NONCE_LEN],
    /// AES-256-GCM ciphertext (32B DEK) + tag (16B) = 48 bytes.
    pub ciphertext_and_tag: Vec<u8>,
}

impl WrappedDek {
    /// Returns the 25-byte canonical AAD (`b"ZV-DEK-V1" || file_id`) for DEK wrapping.
    #[must_use]
    pub fn dek_wrap_aad(file_id: Uuid) -> [u8; 25] {
        let mut aad = [0u8; 25];
        aad[..9].copy_from_slice(b"ZV-DEK-V1");
        aad[9..25].copy_from_slice(file_id.as_bytes());
        aad
    }
}

/// Canonical 25-byte Additional Authenticated Data bound into every encrypted 4 MiB chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkAad {
    /// Logical encrypted file identifier.
    pub file_id: Uuid,
    /// Zero-based chunk ordinal within the file.
    pub chunk_index: u64,
    /// Whether this chunk is the terminal chunk of the file.
    pub is_final_chunk: bool,
}

impl ChunkAad {
    /// Encodes the exact 25-byte wire AAD: `file_id (16B) || chunk_index (u64 LE) || is_final (u8)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 25] {
        let mut out = [0u8; 25];
        out[0..16].copy_from_slice(self.file_id.as_bytes());
        out[16..24].copy_from_slice(&self.chunk_index.to_le_bytes());
        out[24] = u8::from(self.is_final_chunk);
        out
    }
}

/// Fixed 32-byte wire header at the start of every encrypted `.zv` chunk blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkHeader {
    /// Wire format version (must be [`CHUNK_FORMAT_VERSION`]).
    pub version: u8,
    /// True if this chunk terminates the file.
    pub is_final_chunk: bool,
    /// Zero-based chunk index.
    pub chunk_index: u64,
    /// Exact plaintext payload length in bytes (`0..=PLAINTEXT_CHUNK_SIZE`).
    pub plaintext_len: u32,
    /// Unique 96-bit AES-256-GCM nonce.
    pub nonce: [u8; AES_GCM_NONCE_LEN],
}

impl ChunkHeader {
    /// Validates chunk size invariants and encodes the header to 32 bytes.
    pub fn encode(&self) -> ZeroVaultResult<[u8; CHUNK_HEADER_LEN]> {
        self.validate_invariants()?;
        let mut out = [0u8; CHUNK_HEADER_LEN];
        out[0..4].copy_from_slice(&CHUNK_MAGIC);
        out[4] = self.version;
        out[5] = if self.is_final_chunk {
            CHUNK_FLAG_FINAL
        } else {
            0
        };
        out[8..16].copy_from_slice(&self.chunk_index.to_le_bytes());
        out[16..20].copy_from_slice(&self.plaintext_len.to_le_bytes());
        out[20..32].copy_from_slice(&self.nonce);
        Ok(out)
    }

    /// Decodes a 32-byte chunk header and validates magic, version, flags, and chunk sizing rules.
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() < CHUNK_HEADER_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "chunk header too short: {} bytes",
                bytes.len()
            )));
        }
        if bytes[0..4] != CHUNK_MAGIC {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid chunk header magic".into(),
            ));
        }
        let version = bytes[4];
        if version != CHUNK_FORMAT_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported chunk format version {version}"
            )));
        }
        let flags = bytes[5];
        if (flags & !CHUNK_FLAG_FINAL) != 0 {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unknown chunk flags: {flags:#04x}"
            )));
        }
        if bytes[6..8] != [0, 0] {
            return Err(ZeroVaultError::InvalidWireFormat(
                "non-zero reserved bytes in chunk header".into(),
            ));
        }

        let chunk_index = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let plaintext_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&bytes[20..32]);

        let header = Self {
            version,
            is_final_chunk: (flags & CHUNK_FLAG_FINAL) != 0,
            chunk_index,
            plaintext_len,
            nonce,
        };
        header.validate_invariants()?;
        Ok(header)
    }

    /// Validates non-final chunk fixed 4 MiB sizing and zero-length file boundaries.
    pub fn validate_invariants(&self) -> ZeroVaultResult<()> {
        if self.version != CHUNK_FORMAT_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported chunk format version {}",
                self.version
            )));
        }
        let len = self.plaintext_len as usize;
        if len > PLAINTEXT_CHUNK_SIZE {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "chunk plaintext_len {len} exceeds {PLAINTEXT_CHUNK_SIZE}"
            )));
        }
        if !self.is_final_chunk && len != PLAINTEXT_CHUNK_SIZE {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "non-final chunk {} must be {PLAINTEXT_CHUNK_SIZE} bytes, got {len}",
                self.chunk_index
            )));
        }
        if self.is_final_chunk && len == 0 && self.chunk_index > 0 {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "empty final chunk is only allowed at chunk_index 0, got {}",
                self.chunk_index
            )));
        }
        Ok(())
    }

    /// Expected total encrypted wire size (32B header + ciphertext + 16B GCM tag).
    #[must_use]
    pub fn expected_wire_len(&self) -> usize {
        CHUNK_HEADER_LEN + (self.plaintext_len as usize) + AES_GCM_TAG_LEN
    }
}

/// Fixed 44-byte header prefix for encrypted manifest blobs (`ZVM1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestWireHeader {
    /// Format version (must be [`MANIFEST_FORMAT_VERSION`]).
    pub version: u8,
    /// Owning vault UUID.
    pub vault_id: Uuid,
    /// Monotonic manifest revision counter (`>= 1`).
    pub revision: u64,
    /// Fresh 96-bit GCM nonce.
    pub nonce: [u8; AES_GCM_NONCE_LEN],
}

impl ManifestWireHeader {
    /// Encodes the 44-byte header prefix.
    #[must_use]
    pub fn encode(&self) -> [u8; MANIFEST_HEADER_LEN] {
        let mut out = [0u8; MANIFEST_HEADER_LEN];
        out[0..4].copy_from_slice(&MANIFEST_MAGIC);
        out[4] = self.version;
        out[8..24].copy_from_slice(self.vault_id.as_bytes());
        out[24..32].copy_from_slice(&self.revision.to_le_bytes());
        out[32..44].copy_from_slice(&self.nonce);
        out
    }

    /// Decodes and validates the 44-byte manifest wire header.
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() < MANIFEST_HEADER_LEN + AES_GCM_TAG_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "sealed manifest too short: {} bytes",
                bytes.len()
            )));
        }
        if bytes[0..4] != MANIFEST_MAGIC {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid manifest magic".into(),
            ));
        }
        let version = bytes[4];
        if version != MANIFEST_FORMAT_VERSION {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "unsupported manifest version {version}"
            )));
        }
        if bytes[5..8] != [0, 0, 0] {
            return Err(ZeroVaultError::InvalidWireFormat(
                "non-zero reserved bytes in manifest header".into(),
            ));
        }
        let vault_id = Uuid::from_slice(&bytes[8..24])
            .map_err(|e| ZeroVaultError::InvalidWireFormat(format!("invalid vault_id: {e}")))?;
        let revision = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        if revision == 0 {
            return Err(ZeroVaultError::InvalidWireFormat(
                "manifest revision must be >= 1".into(),
            ));
        }
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&bytes[32..44]);
        Ok(Self {
            version,
            vault_id,
            revision,
            nonce,
        })
    }
}

fn parse_sharded_object_key(prefix: &str, suffix: &str, key: &str) -> ZeroVaultResult<Uuid> {
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 4 || parts[0] != prefix {
        return Err(ZeroVaultError::InvalidPath(format!(
            "object key must match {prefix}/<2-hex>/<2-hex>/<uuid>{suffix}: {key}"
        )));
    }
    let filename = parts[3]
        .strip_suffix(suffix)
        .ok_or_else(|| ZeroVaultError::InvalidPath(format!("missing {suffix} suffix: {key}")))?;
    let uuid = Uuid::parse_str(filename).map_err(|_| {
        ZeroVaultError::InvalidPath(format!("filename must be a valid UUID: {key}"))
    })?;
    let hex_str = uuid.as_simple().to_string();
    let expected = format!(
        "{prefix}/{}/{}/{}{suffix}",
        &hex_str[0..2],
        &hex_str[2..4],
        uuid.hyphenated()
    );
    if expected != key {
        return Err(ZeroVaultError::InvalidPath(format!(
            "non-canonical sharded object key: {key}"
        )));
    }
    Ok(uuid)
}

/// Strict obfuscated remote object key for encrypted 4 MiB chunks:
/// `blobs/<2-hex>/<2-hex>/<uuid>.zv`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobObjectKey(String);

impl BlobObjectKey {
    /// Constructs a canonical sharded blob key from a UUID.
    #[must_use]
    pub fn from_uuid(blob_id: Uuid) -> Self {
        let hex_str = blob_id.as_simple().to_string();
        Self(format!(
            "blobs/{}/{}/{}.zv",
            &hex_str[0..2],
            &hex_str[2..4],
            blob_id.hyphenated()
        ))
    }

    /// Parses and strictly validates that a key matches `blobs/<2-hex>/<2-hex>/<uuid>.zv`.
    pub fn parse(key: &str) -> ZeroVaultResult<Self> {
        let uuid = parse_sharded_object_key("blobs", ".zv", key)?;
        Ok(Self::from_uuid(uuid))
    }

    /// Returns the relative remote object path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Strict obfuscated remote object key for encrypted manifests:
/// `manifests/head.zvm` or `manifests/<2-hex>/<2-hex>/<uuid>.zvm`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestObjectKey(String);

impl ManifestObjectKey {
    /// Returns the canonical head manifest key (`manifests/head.zvm`).
    #[must_use]
    pub fn head() -> Self {
        Self(MANIFEST_HEAD_OBJECT_KEY.to_owned())
    }

    /// Constructs a canonical historical snapshot manifest key from a UUID.
    #[must_use]
    pub fn from_uuid(manifest_id: Uuid) -> Self {
        let hex_str = manifest_id.as_simple().to_string();
        Self(format!(
            "manifests/{}/{}/{}.zvm",
            &hex_str[0..2],
            &hex_str[2..4],
            manifest_id.hyphenated()
        ))
    }

    /// Parses and validates a manifest object key.
    pub fn parse(key: &str) -> ZeroVaultResult<Self> {
        if key == MANIFEST_HEAD_OBJECT_KEY {
            return Ok(Self::head());
        }
        let uuid = parse_sharded_object_key("manifests", ".zvm", key)?;
        Ok(Self::from_uuid(uuid))
    }

    /// Returns the relative remote object path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManifestObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Strict obfuscated remote object key for `zv://` capability share descriptors:
/// `shares/<2-hex>/<2-hex>/<uuid>.zvs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareObjectKey(String);

impl ShareObjectKey {
    /// Constructs a canonical sharded share descriptor key from a UUID.
    #[must_use]
    pub fn from_uuid(share_id: Uuid) -> Self {
        let hex_str = share_id.as_simple().to_string();
        Self(format!(
            "shares/{}/{}/{}.zvs",
            &hex_str[0..2],
            &hex_str[2..4],
            share_id.hyphenated()
        ))
    }

    /// Parses and validates a share object key.
    pub fn parse(key: &str) -> ZeroVaultResult<Self> {
        let uuid = parse_sharded_object_key("shares", ".zvs", key)?;
        Ok(Self::from_uuid(uuid))
    }

    /// Returns the relative remote object path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShareObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validates that ANY remote object key sent to cloud storage conforms strictly to
/// zero-knowledge UUID/header naming rules (never leaking plaintext filenames/paths).
pub fn validate_remote_object_key(key: &str) -> ZeroVaultResult<()> {
    if key == VAULT_HEADER_OBJECT_KEY || key == KEYBOX_OBJECT_KEY {
        return Ok(());
    }
    if BlobObjectKey::parse(key).is_ok()
        || ManifestObjectKey::parse(key).is_ok()
        || ShareObjectKey::parse(key).is_ok()
    {
        return Ok(());
    }
    Err(ZeroVaultError::InvalidPath(format!(
        "remote object key violates zero-knowledge naming policy: {key}"
    )))
}

/// Cross-platform filename validator ported from Legacy CloudBridge (`BackupEngine.cs:185-226`)
/// with Linux case-sensitivity preservation (`CB-03` fix).
///
/// Always rejects empty names, `.`, `..`, path separators (`/`, `\`), NUL, control characters,
/// and NTFS Alternate Data Stream colons (`:`). When `enforce_windows_device_rules` is `true`,
/// also rejects Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`,
/// superscript `COM¹..³`) and trailing dots/spaces.
pub fn validate_portable_entry_name(
    name: &str,
    enforce_windows_device_rules: bool,
) -> ZeroVaultResult<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(ZeroVaultError::InvalidPath(format!(
            "invalid entry name: {name:?}"
        )));
    }
    if name.len() > 255 {
        return Err(ZeroVaultError::InvalidPath(
            "entry name exceeds 255 UTF-8 bytes".into(),
        ));
    }
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c == ':' || (c as u32) < 0x20)
    {
        return Err(ZeroVaultError::InvalidPath(format!(
            "entry name contains forbidden control/separator/ADS character: {name:?}"
        )));
    }
    if enforce_windows_device_rules {
        if name.ends_with(' ') || name.ends_with('.') {
            return Err(ZeroVaultError::InvalidPath(format!(
                "entry name cannot end with space or dot under Windows rules: {name:?}"
            )));
        }
        if name
            .chars()
            .any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
        {
            return Err(ZeroVaultError::InvalidPath(format!(
                "entry name contains Windows-invalid wildcard/quote char: {name:?}"
            )));
        }
        let stem = name.split('.').next().unwrap_or(name);
        let upper = stem.to_uppercase();
        let reserved = matches!(
            upper.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "COM\u{00B9}"
                | "COM\u{00B2}"
                | "COM\u{00B3}"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
                | "LPT\u{00B9}"
                | "LPT\u{00B2}"
                | "LPT\u{00B3}"
        );
        if reserved {
            return Err(ZeroVaultError::InvalidPath(format!(
                "entry name uses Windows reserved device stem: {name:?}"
            )));
        }
    }
    Ok(())
}

/// Normalizes a virtual vault path to canonical leading-slash form (`"/"` or `"/a/b/c"`),
/// preserving exact case (`Ordinal`) and rejecting `..` traversal or invalid segments.
pub fn normalize_virtual_path(path: &str) -> ZeroVaultResult<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok("/".to_owned());
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        validate_portable_entry_name(seg, false)?;
        parts.push(seg);
    }
    if parts.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

/// Metadata pointer for a single encrypted 4 MiB chunk stored remotely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Zero-based chunk ordinal.
    pub chunk_index: u64,
    /// Random UUID identifying the remote `.zv` blob.
    pub blob_id: Uuid,
    /// Exact plaintext length of this chunk.
    pub plaintext_len: u32,
    /// Exact ciphertext wire length (including 32B header and 16B tag).
    pub ciphertext_len: u32,
    /// BLAKE3 digest of the plaintext chunk (never transmitted unencrypted; sealed inside manifest).
    pub blake3_plaintext: [u8; 32],
    /// Cloud backend IDs storing replicas of this blob.
    pub backend_ids: Vec<String>,
}

/// Encrypted directory/file entry stored inside [`VaultManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestNode {
    /// Local/virtual inode ID.
    pub inode: u64,
    /// Parent directory inode ID.
    pub parent_inode: u64,
    /// Cryptographic file UUID used in chunk AAD and DEK wrap AAD.
    pub file_id: Uuid,
    /// Plaintext basename (never stored unencrypted remotely; sealed inside `ZVM1`).
    pub name: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Logical plaintext byte length.
    pub size: u64,
    /// POSIX permission bits (e.g. `0o644` or `0o755`).
    pub mode: u32,
    /// Last modification timestamp.
    pub modified_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Monotonic node revision counter.
    pub version: u64,
    /// Per-file wrapped DEK (present for regular files).
    pub wrapped_dek: Option<WrappedDek>,
    /// Ordered 4 MiB chunk references for regular files.
    pub chunks: Vec<ChunkRef>,
}

/// Entire encrypted directory snapshot sealed into `.zvm` remote manifest objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    /// Vault UUID.
    pub vault_id: Uuid,
    /// Monotonic manifest revision used for optimistic concurrency control.
    pub revision: u64,
    /// Previous manifest snapshot UUID, if any.
    pub parent_manifest_id: Option<Uuid>,
    /// Originating device identifier for conflict tracking.
    pub device_id: String,
    /// Snapshot creation timestamp.
    pub created_at: DateTime<Utc>,
    /// All virtual directory and file nodes in the vault.
    pub nodes: Vec<ManifestNode>,
}

impl VaultManifest {
    /// Returns the canonical 28-byte AAD (`b"ZVM1" || vault_id || revision LE`) for manifest AEAD.
    #[must_use]
    pub fn manifest_aad(vault_id: Uuid, revision: u64) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[0..4].copy_from_slice(&MANIFEST_MAGIC);
        out[4..20].copy_from_slice(vault_id.as_bytes());
        out[20..28].copy_from_slice(&revision.to_le_bytes());
        out
    }
}

/// Slice coordinates within one 4 MiB chunk for an arbitrary byte range read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSlice {
    /// Zero-based chunk index.
    pub chunk_index: u64,
    /// Byte offset inside the decrypted chunk plaintext.
    pub in_chunk_offset: usize,
    /// Number of bytes to copy from this chunk.
    pub len: usize,
}

/// Inclusive range of 4 MiB chunks covering a requested byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRangeSpan {
    /// Total readable bytes clamped to EOF.
    pub readable_len: usize,
    /// Per-chunk sub-slices in ascending `chunk_index` order.
    pub slices: Vec<ChunkSlice>,
}

/// Computes the exact 4 MiB chunk slices needed to satisfy `[offset, offset + len)` against `file_size`.
pub fn chunk_span_for_range(
    offset: u64,
    len: usize,
    file_size: u64,
) -> ZeroVaultResult<Option<ChunkRangeSpan>> {
    if len == 0 || offset >= file_size {
        return Ok(None);
    }

    let available = file_size - offset;
    let readable_u64 = available.min(len as u64);
    let readable_len = usize::try_from(readable_u64).map_err(|_| ZeroVaultError::InvalidRange {
        offset,
        len,
        size: file_size,
    })?;
    if readable_len == 0 {
        return Ok(None);
    }

    let chunk_size = PLAINTEXT_CHUNK_SIZE as u64;
    let end_exclusive = offset
        .checked_add(readable_u64)
        .ok_or(ZeroVaultError::InvalidRange {
            offset,
            len,
            size: file_size,
        })?;

    let first_chunk = offset / chunk_size;
    let last_chunk = (end_exclusive - 1) / chunk_size;

    let mut slices = Vec::with_capacity((last_chunk - first_chunk + 1) as usize);
    for chunk_index in first_chunk..=last_chunk {
        let chunk_start = chunk_index * chunk_size;
        let chunk_end = chunk_start + chunk_size;
        let slice_start = offset.max(chunk_start);
        let slice_end = end_exclusive.min(chunk_end);

        slices.push(ChunkSlice {
            chunk_index,
            in_chunk_offset: (slice_start - chunk_start) as usize,
            len: (slice_end - slice_start) as usize,
        });
    }

    Ok(Some(ChunkRangeSpan {
        readable_len,
        slices,
    }))
}
