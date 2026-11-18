//! Internal `ring 0.17` AES-256-GCM, CSPRNG, and HKDF-SHA256 primitives.

use hkdf::Hkdf;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, Tag, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
use entrocloud_types::{AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, ZeroVaultError, ZeroVaultResult};

/// Fills a fixed-size byte array from the OS CSPRNG via `ring::rand::SystemRandom`.
#[inline]
pub(crate) fn fill_csprng<const N: usize>() -> ZeroVaultResult<[u8; N]> {
    let mut out = [0u8; N];
    let rng = SystemRandom::new();
    rng.fill(&mut out).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("CSPRNG entropy generation failed".into())
    })?;
    Ok(out)
}

/// Fills a zeroizing fixed-size secret array directly from the OS CSPRNG.
#[inline]
pub(crate) fn fill_csprng_zeroizing<const N: usize>() -> ZeroVaultResult<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    let rng = SystemRandom::new();
    rng.fill(&mut *out).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("CSPRNG entropy generation failed".into())
    })?;
    Ok(out)
}

/// Expands a 256-bit subkey via `HKDF-SHA256` directly into a [`Zeroizing`] buffer.
#[inline]
pub(crate) fn hkdf_expand_256(
    hk: &Hkdf<Sha256>,
    info: &[u8],
) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *okm)
        .map_err(|_| ZeroVaultError::CryptoTamperDetected("HKDF-SHA256 expansion failed".into()))?;
    Ok(okm)
}

/// Constructs a `ring 0.17` `AES-256-GCM` key schedule from a 256-bit key.
#[inline]
pub(crate) fn new_aes256_gcm_key(key_bytes: &[u8; 32]) -> ZeroVaultResult<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("invalid AES-256-GCM key length".into())
    })?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypts `in_out` in place under `ring::aead::AES_256_GCM` and returns the 16-byte tag.
#[inline]
pub(crate) fn seal_in_place_detached(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
) -> ZeroVaultResult<[u8; AES_GCM_TAG_LEN]> {
    let key = new_aes256_gcm_key(key_bytes)?;
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            in_out,
        )
        .map_err(|_| {
            in_out.zeroize();
            ZeroVaultError::CryptoTamperDetected("AES-256-GCM encryption failed".into())
        })?;
    let mut tag_out = [0u8; AES_GCM_TAG_LEN];
    tag_out.copy_from_slice(tag.as_ref());
    Ok(tag_out)
}

/// Verifies `tag_bytes` and decrypts `in_out` in place under `ring::aead::AES_256_GCM`.
///
/// Immediately zeroizes `in_out` on any tag verification failure before returning
/// [`ZeroVaultError::CryptoTamperDetected`].
#[inline]
pub(crate) fn open_in_place_detached(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    tag_bytes: &[u8],
    in_out: &mut [u8],
) -> ZeroVaultResult<()> {
    let key = match new_aes256_gcm_key(key_bytes) {
        Ok(k) => k,
        Err(err) => {
            in_out.zeroize();
            return Err(err);
        }
    };
    let received_tag = match Tag::try_from(tag_bytes) {
        Ok(t) => t,
        Err(_) => {
            in_out.zeroize();
            return Err(ZeroVaultError::CryptoTamperDetected(
                "invalid AES-256-GCM authentication tag length".into(),
            ));
        }
    };
    if key
        .open_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            received_tag,
            in_out,
            0..,
        )
        .is_err()
    {
        in_out.zeroize();
        return Err(ZeroVaultError::CryptoTamperDetected(
            "AES-256-GCM authentication tag mismatch".into(),
        ));
    }
    Ok(())
}

/// Encrypts `plaintext` with an explicit `nonce`, returning `ciphertext || tag`.
pub(crate) fn seal_with_nonce(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> ZeroVaultResult<Vec<u8>> {
    let mut out = Vec::with_capacity(plaintext.len() + AES_GCM_TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = seal_in_place_detached(key_bytes, nonce, aad, &mut out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts `ciphertext || tag` with an explicit `nonce` into a [`Zeroizing`] plaintext buffer.
pub(crate) fn open_with_nonce(
    key_bytes: &[u8; 32],
    nonce: [u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
    if ciphertext_and_tag.len() < AES_GCM_TAG_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "ciphertext_and_tag shorter than 16-byte GCM tag".into(),
        ));
    }
    let ct_len = ciphertext_and_tag.len() - AES_GCM_TAG_LEN;
    let (ct, tag) = ciphertext_and_tag.split_at(ct_len);
    let mut pt = Zeroizing::new(ct.to_vec());
    open_in_place_detached(key_bytes, nonce, aad, tag, &mut pt)?;
    Ok(pt)
}

/// Encrypts `plaintext` with a fresh 96-bit CSPRNG nonce, returning `nonce || ciphertext || tag`.
pub(crate) fn seal_nonce_prefixed(
    key_bytes: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> ZeroVaultResult<Vec<u8>> {
    let nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
    let mut out = Vec::with_capacity(AES_GCM_NONCE_LEN + plaintext.len() + AES_GCM_TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = seal_in_place_detached(key_bytes, nonce, aad, &mut out[AES_GCM_NONCE_LEN..])?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens `nonce || ciphertext || tag` into a [`Zeroizing`] plaintext buffer.
pub(crate) fn open_nonce_prefixed(
    key_bytes: &[u8; 32],
    aad: &[u8],
    sealed: &[u8],
) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
    if sealed.len() < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "sealed AEAD payload shorter than nonce + tag".into(),
        ));
    }
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(&sealed[..AES_GCM_NONCE_LEN]);
    open_with_nonce(key_bytes, nonce, aad, &sealed[AES_GCM_NONCE_LEN..])
}
