//! Runtime CPUID / hardware register verification for mandatory AES + GHASH acceleration.

use std::sync::{Once, OnceLock};

use tracing::{debug, warn};
use entrocloud_types::{HardwareCryptoCaps, ZeroVaultError, ZeroVaultResult};

/// Active AEAD backend label on x86/x86_64 CPUs with stitched `VAES` + `AVX2` (`ring 0.17`).
pub const CRYPTO_BACKEND_VAES_AVX2: &str = "ring-0.17-aes256gcm-vaes-avx2";

/// Active AEAD backend label on x86/x86_64 CPUs with baseline `AES-NI` + `PCLMULQDQ` (`ring 0.17`).
pub const CRYPTO_BACKEND_AESNI: &str = "ring-0.17-aes256gcm-aesni";

/// Active AEAD backend label on ARMv8 `aarch64` CPUs with `AES` + `PMULL` (`ring 0.17`).
pub const CRYPTO_BACKEND_AARCH64: &str = "ring-0.17-aes256gcm-armv8";

/// Fallback label reported before failing closed on unsupported architectures.
pub const CRYPTO_BACKEND_UNSUPPORTED: &str = "ring-0.17-aes256gcm-unsupported";

/// Canonical AEAD backend family prefix.
pub const CRYPTO_BACKEND_NAME: &str = "ring-0.17-aes256gcm";

static DETECTED_CAPS: OnceLock<HardwareCryptoCaps> = OnceLock::new();
static LOG_CAPS_ONCE: Once = Once::new();

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod platform_caps {
    use entrocloud_types::HardwareCryptoCaps;

    use super::{CRYPTO_BACKEND_AESNI, CRYPTO_BACKEND_VAES_AVX2};

    pub(super) fn detect() -> HardwareCryptoCaps {
        let aes_hw = std::arch::is_x86_feature_detected!("aes");
        let pclmul_hw = std::arch::is_x86_feature_detected!("pclmulqdq");
        let vaes_hw = std::arch::is_x86_feature_detected!("vaes");
        let avx2_hw = std::arch::is_x86_feature_detected!("avx2");
        let mandatory_satisfied = aes_hw && pclmul_hw;
        let backend_name = if vaes_hw && avx2_hw {
            CRYPTO_BACKEND_VAES_AVX2
        } else {
            CRYPTO_BACKEND_AESNI
        };

        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw,
            pclmul_hw,
            vaes_hw,
            avx2_hw,
            mandatory_satisfied,
            backend_name: backend_name.to_owned(),
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod platform_caps {
    use entrocloud_types::HardwareCryptoCaps;

    use super::CRYPTO_BACKEND_AARCH64;

    pub(super) fn detect() -> HardwareCryptoCaps {
        let aes_hw = std::arch::is_aarch64_feature_detected!("aes");
        let pclmul_hw = std::arch::is_aarch64_feature_detected!("pmull");
        let mandatory_satisfied = aes_hw && pclmul_hw;

        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw,
            pclmul_hw,
            vaes_hw: false,
            avx2_hw: false,
            mandatory_satisfied,
            backend_name: CRYPTO_BACKEND_AARCH64.to_owned(),
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
mod platform_caps {
    use entrocloud_types::HardwareCryptoCaps;

    use super::CRYPTO_BACKEND_UNSUPPORTED;

    pub(super) fn detect() -> HardwareCryptoCaps {
        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw: false,
            pclmul_hw: false,
            vaes_hw: false,
            avx2_hw: false,
            mandatory_satisfied: false,
            backend_name: CRYPTO_BACKEND_UNSUPPORTED.to_owned(),
        }
    }
}

fn cached_capabilities() -> &'static HardwareCryptoCaps {
    DETECTED_CAPS.get_or_init(platform_caps::detect)
}

/// Inspects runtime CPU features without failing closed.
#[must_use]
pub fn detect_hardware_capabilities() -> HardwareCryptoCaps {
    cached_capabilities().clone()
}

/// Validates a [`HardwareCryptoCaps`] descriptor, failing closed with
/// [`ZeroVaultError::HardwareAccelerationUnavailable`] if mandatory instructions are absent.
pub fn validate_hardware_caps(caps: HardwareCryptoCaps) -> ZeroVaultResult<HardwareCryptoCaps> {
    if !caps.mandatory_satisfied || !caps.aes_hw || !caps.pclmul_hw {
        warn!(
            arch = %caps.arch,
            aes_hw = caps.aes_hw,
            pclmul_hw = caps.pclmul_hw,
            "mandatory hardware AES/GHASH acceleration unavailable"
        );
        return Err(ZeroVaultError::HardwareAccelerationUnavailable(format!(
            "architecture {} lacks mandatory hardware AES/GHASH support (aes_hw={}, pclmul_hw={})",
            caps.arch, caps.aes_hw, caps.pclmul_hw
        )));
    }
    Ok(caps)
}

/// Fast zero-allocation gate used on cryptographic hot paths.
#[inline]
pub(crate) fn ensure_hardware_acceleration() -> ZeroVaultResult<()> {
    let caps = cached_capabilities();
    if !caps.mandatory_satisfied || !caps.aes_hw || !caps.pclmul_hw {
        return Err(ZeroVaultError::HardwareAccelerationUnavailable(format!(
            "architecture {} lacks mandatory hardware AES/GHASH support (aes_hw={}, pclmul_hw={})",
            caps.arch, caps.aes_hw, caps.pclmul_hw
        )));
    }
    Ok(())
}

/// Verifies mandatory hardware AES and carry-less multiplication (GHASH) instructions.
///
/// Fails closed with [`ZeroVaultError::HardwareAccelerationUnavailable`] if mandatory
/// CPU instructions (`aes` + `pclmulqdq` on x86/x86_64; `aes` + `pmull` on aarch64)
/// are absent at runtime.
pub fn verify_hardware_acceleration() -> ZeroVaultResult<HardwareCryptoCaps> {
    let caps = validate_hardware_caps(cached_capabilities().clone())?;

    LOG_CAPS_ONCE.call_once(|| {
        debug!(
            arch = %caps.arch,
            aes_hw = caps.aes_hw,
            pclmul_hw = caps.pclmul_hw,
            vaes_hw = caps.vaes_hw,
            avx2_hw = caps.avx2_hw,
            backend = %caps.backend_name,
            "verified hardware cryptographic acceleration"
        );
    });

    Ok(caps)
}
