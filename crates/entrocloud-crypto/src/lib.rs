//! Hardware-accelerated zero-knowledge hybrid cryptography for ZeroVault v0.2.
//!
//! Combines:
//! - [`RingHybridCryptoEngine`] (aliased as [`DefaultCryptoEngine`] and [`AwsLcCryptoEngine`]):
//!   `ring 0.17` stitched `VAES`+`VPCLMULQDQ` / `AES-NI` `AES-256-GCM` symmetric bulk crypto,
//!   `Argon2id` + 7-subkey `HKDF-SHA256` key derivation, `BLAKE3` keyed blind indexes,
//!   `ZVS2` AEAD-wrapped keyring sessions, and `aws-lc-rs 1.19` post-quantum (`ML-KEM-768` +
//!   `X25519` + `Ed25519`) cloud keyboxes & `zv://` capability shares.
//! - [`OsKeyringSecretStore`]: native OS credential store adapter via `keyring`.
//! - [`verify_hardware_acceleration`] & [`detect_hardware_capabilities`]: runtime CPUID /
//!   register verification failing closed on absent hardware AES + GHASH instructions.

pub(crate) mod aead_ring;
pub mod engine;
pub mod hw;
pub mod keyring_store;
pub mod sharing;

pub use engine::{
    AwsLcCryptoEngine, BlindIndexKey, DefaultCryptoEngine, HeaderVerifierKey, KeyRingState,
    ManifestKey, MasterKek, MasterSeed, MetadataKey, RingHybridCryptoEngine, StagingKey,
    TokenWrapKey,
};
pub use hw::{
    CRYPTO_BACKEND_AARCH64, CRYPTO_BACKEND_AESNI, CRYPTO_BACKEND_NAME, CRYPTO_BACKEND_UNSUPPORTED,
    CRYPTO_BACKEND_VAES_AVX2, detect_hardware_capabilities, validate_hardware_caps,
    verify_hardware_acceleration,
};
pub use keyring_store::OsKeyringSecretStore;
pub use entrocloud_types;
