use thiserror::Error;

/// Canonical domain error enum shared across all Zerovault crates.
#[derive(Debug, Error)]
pub enum ZeroVaultError {
    /// AEAD authentication failed or cryptographic integrity check did not match.
    #[error("cryptographic tamper detected: {0}")]
    CryptoTamperDetected(String),

    /// Operation requires an unlocked vault session.
    #[error("vault is locked")]
    VaultLocked,

    /// Passphrase verification against the vault header failed.
    #[error("invalid vault passphrase")]
    InvalidPassphrase,

    /// Mandatory CPU hardware AES acceleration instructions are absent.
    #[error("hardware AES acceleration unavailable: {0}")]
    HardwareAccelerationUnavailable(String),

    /// Wire format header, magic bytes, or payload bounds are invalid.
    #[error("invalid wire format: {0}")]
    InvalidWireFormat(String),

    /// Argon2id parameters do not satisfy the minimum security policy floor.
    #[error(
        "KDF parameters below security policy floor (m_cost_kib={m_cost_kib}, t_cost={t_cost}, p_cost={p_cost})"
    )]
    KdfPolicyViolation {
        /// Memory cost in KiB.
        m_cost_kib: u32,
        /// Iteration count.
        t_cost: u32,
        /// Parallelism lanes.
        p_cost: u32,
    },

    /// OS credential manager / keyring error.
    #[error("OS keyring error: {0}")]
    KeyringError(String),

    /// OAuth2 / PKCE authentication flow error.
    #[error("OAuth2 error: {0}")]
    OAuthError(String),

    /// Remote object or blob was not found.
    #[error("remote storage object not found: {0}")]
    StorageNotFound(String),

    /// Remote storage quota or free-headroom reserve is exhausted.
    #[error("storage quota exceeded: {0}")]
    StorageQuotaExceeded(String),

    /// Optimistic concurrency version or ETag mismatch on remote storage.
    #[error("remote storage concurrency conflict: {0}")]
    StorageConflict(String),

    /// Underlying cloud backend transport or API error.
    #[error("storage backend error: {0}")]
    StorageBackendError(String),

    /// Requested virtual inode does not exist.
    #[error("inode not found: {0}")]
    InodeNotFound(u64),

    /// Target virtual path or entry name already exists.
    #[error("entry already exists: {0}")]
    AlreadyExists(String),

    /// Operation requires a directory inode.
    #[error("inode {0} is not a directory")]
    NotADirectory(u64),

    /// Operation cannot be applied to a directory inode.
    #[error("inode {0} is a directory")]
    IsADirectory(u64),

    /// Directory cannot be removed while it still contains children.
    #[error("directory inode {0} is not empty")]
    DirectoryNotEmpty(u64),

    /// Byte range is invalid or overflows addressable offsets.
    #[error("invalid byte range: offset={offset}, len={len}, size={size}")]
    InvalidRange {
        /// Byte offset requested.
        offset: u64,
        /// Byte length requested.
        len: usize,
        /// Logical size of the target file.
        size: u64,
    },

    /// Virtual path violates path canonicalization rules.
    #[error("invalid virtual path: {0}")]
    InvalidPath(String),

    /// File is pinned offline and cannot be dehydrated.
    #[error("cannot dehydrate pinned inode {0}")]
    PinnedDehydrationDenied(u64),

    /// Platform virtual filesystem error (Windows CfApi or Linux FUSE).
    #[error("VFS error: {0}")]
    VfsError(String),

    /// SQLite metadata store failure.
    #[error("metadata store error: {0}")]
    MetadataError(String),

    /// Local IPC transport or protocol error.
    #[error("IPC error: {0}")]
    IpcError(String),

    /// Configuration validation or parsing error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Local OS I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ZeroVaultError {
    /// Returns `true` when this error indicates cryptographic tamper or corruption.
    #[must_use]
    pub fn is_tamper(&self) -> bool {
        matches!(self, Self::CryptoTamperDetected(_))
    }

    /// Returns `true` when the requested object or inode does not exist.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::StorageNotFound(_) | Self::InodeNotFound(_))
    }
}

/// Convenience result alias used throughout Zerovault.
pub type ZeroVaultResult<T> = Result<T, ZeroVaultError>;
