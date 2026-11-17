//! Runtime CPUID / hardware register verification for mandatory AES + GHASH acceleration.

use std::sync::Once;

use tracing::{debug, warn};
use zerovault_types::{HardwareCryptoCaps, ZeroVaultError, ZeroVaultResult};

/// Canonical AEAD backend identifier reported in [`HardwareCryptoCaps`].
pub const CRYPTO_BACKEND_NAME: &str = "aws-lc-rs-aes-256-gcm";

static LOG_CAPS_ONCE: Once = Once::new();

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[allow(unsafe_op_in_unsafe_fn)]
mod platform_caps {
    use super::CRYPTO_BACKEND_NAME;
    use zerovault_types::HardwareCryptoCaps;

    cpufeatures::new!(x86_aes_caps, "aes", "pclmulqdq");
    cpufeatures::new!(x86_aes_only, "aes");
    cpufeatures::new!(x86_pclmul_only, "pclmulqdq");
    cpufeatures::new!(x86_avx2_caps, "avx2");
    cpufeatures::new!(x86_vaes_caps, "vaes");

    pub(super) fn detect() -> HardwareCryptoCaps {
        let aes_hw = x86_aes_only::get();
        let pclmul_hw = x86_pclmul_only::get();
        let avx2_hw = x86_avx2_caps::get();
        // `cpufeatures` gates `"vaes"` on AVX-512 ZMM OS state; fall back to CPUID
        // detection via `std::arch` so AVX2-width VAES CPUs are also detected.
        let vaes_hw = x86_vaes_caps::get() || std::arch::is_x86_feature_detected!("vaes");
        let mandatory_satisfied = x86_aes_caps::get() && aes_hw && pclmul_hw;

        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw,
            pclmul_hw,
            vaes_hw,
            avx2_hw,
            mandatory_satisfied,
            backend_name: CRYPTO_BACKEND_NAME.to_owned(),
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_op_in_unsafe_fn)]
mod platform_caps {
    use super::CRYPTO_BACKEND_NAME;
    use zerovault_types::HardwareCryptoCaps;

    // `cpufeatures` 0.2 on aarch64 checks both HWCAP_AES and HWCAP_PMULL under `"aes"`.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    cpufeatures::new!(aarch64_aes_caps, "aes");

    pub(super) fn detect() -> HardwareCryptoCaps {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        let cpufeatures_ok = aarch64_aes_caps::get();
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        let cpufeatures_ok = true;

        let aes_hw = std::arch::is_aarch64_feature_detected!("aes") && cpufeatures_ok;
        let pclmul_hw = std::arch::is_aarch64_feature_detected!("pmull") && cpufeatures_ok;
        let mandatory_satisfied = aes_hw && pclmul_hw;

        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw,
            pclmul_hw,
            vaes_hw: false,
            avx2_hw: false,
            mandatory_satisfied,
            backend_name: CRYPTO_BACKEND_NAME.to_owned(),
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
mod platform_caps {
    use super::CRYPTO_BACKEND_NAME;
    use zerovault_types::HardwareCryptoCaps;

    pub(super) fn detect() -> HardwareCryptoCaps {
        HardwareCryptoCaps {
            arch: std::env::consts::ARCH.to_owned(),
            aes_hw: false,
            pclmul_hw: false,
            vaes_hw: false,
            avx2_hw: false,
            mandatory_satisfied: false,
            backend_name: CRYPTO_BACKEND_NAME.to_owned(),
        }
    }
}

/// Inspects runtime CPU features without failing closed.
#[must_use]
pub fn detect_hardware_capabilities() -> HardwareCryptoCaps {
    platform_caps::detect()
}

/// Verifies mandatory hardware AES and carry-less multiplication (GHASH) instructions.
///
/// Fails closed with [`ZeroVaultError::HardwareAccelerationUnavailable`] if mandatory
/// CPU instructions (`aes` + `pclmulqdq` on x86/x86_64; `aes` + `pmull` on aarch64)
/// are absent at runtime.
pub fn verify_hardware_acceleration() -> ZeroVaultResult<HardwareCryptoCaps> {
    let caps = platform_caps::detect();
    if !caps.mandatory_satisfied {
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
