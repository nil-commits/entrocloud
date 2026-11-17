//! Hardware-accelerated zero-knowledge cryptography for Zerovault.
//!
//! Provides:
//! - [`AwsLcCryptoEngine`]: `aws-lc-rs` AES-256-GCM + Argon2id + HKDF-SHA256 engine
//! - [`OsKeyringSecretStore`]: native OS credential store adapter via `keyring`
//! - [`verify_hardware_acceleration`]: runtime CPUID / register check failing closed on absent AES/GHASH
//! - Zeroizing redacted key wrappers (`MasterSeed`, `MasterKek`, `ManifestKey`, `TokenWrapKey`, `HeaderVerifierKey`, `KeyRingState`)

pub mod engine;
pub mod hw;
pub mod keyring_store;
#[cfg(test)]
mod tests;

pub use engine::{
    AwsLcCryptoEngine, HeaderVerifierKey, KeyRingState, ManifestKey, MasterKek, MasterSeed,
    TokenWrapKey,
};
pub use hw::{CRYPTO_BACKEND_NAME, detect_hardware_capabilities, verify_hardware_acceleration};
pub use keyring_store::OsKeyringSecretStore;
pub use zerovault_types;
