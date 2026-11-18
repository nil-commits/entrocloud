//! Serverless Post-Quantum (`ML-KEM-768` + `X25519` + `Ed25519`) Cloud Keyboxes (`keybox.zv`)
//! and `zv://` Capability URI sharing using `aws-lc-rs 1.19` + `ring 0.17` `AES-256-GCM`.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey as KemAgreementPubKey, X25519};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand::SystemRandom as AwsSystemRandom;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey as SigVerifyPubKey};
use chrono::Utc;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;
use entrocloud_types::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, CapabilityUri, DekBytes, ED25519_PUBKEY_LEN,
    ED25519_SIGNATURE_LEN, HybridRecipientStanza, KEYBOX_VERSION, ML_KEM_768_CIPHERTEXT_LEN,
    ML_KEM_768_DECAPS_KEY_LEN, ML_KEM_768_ENCAPS_KEY_LEN, RecipientPrivateIdentity,
    RecipientPublicBundle, SHARE_ENVELOPE_MAGIC, SHARE_ENVELOPE_VERSION, ShareDescriptor,
    SignedKeybox, SignedShareEnvelope, WrappedDek, X25519_KEY_LEN, ZeroVaultError, ZeroVaultResult,
};

use crate::aead_ring::{
    fill_csprng, fill_csprng_zeroizing, hkdf_expand_256, open_in_place_detached, open_with_nonce,
    seal_with_nonce,
};
use crate::hw::ensure_hardware_acceleration;

const WRAPPED_KEY_LEN: usize = 32 + AES_GCM_TAG_LEN;
const PQ_STANZA_INFO_PREFIX: &[u8] = b"zerovault.v2.pq-stanza";
const HKDF_INFO_SHARE_KEK: &[u8] = b"zerovault.v2.share-kek";
const HKDF_INFO_SHARE_DESC: &[u8] = b"zerovault.v2.share-desc";

struct StanzaKdfInput<'a> {
    ss_x25519: &'a [u8; 32],
    ss_mlkem: &'a [u8],
    ephemeral_x25519_pubkey: &'a [u8; X25519_KEY_LEN],
    recipient_x25519_pubkey: &'a [u8; X25519_KEY_LEN],
    wrap_nonce: &'a [u8; AES_GCM_NONCE_LEN],
    vault_id: Uuid,
    epoch: u64,
    recipient_id: &'a str,
}

struct ShareDerivedKeys {
    share_kek: Zeroizing<[u8; 32]>,
    share_desc_key: Zeroizing<[u8; 32]>,
}

fn derive_hybrid_stanza_key(input: StanzaKdfInput<'_>) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
    if input.ss_mlkem.len() != 32 {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "invalid ML-KEM-768 shared secret length".into(),
        ));
    }

    let mut ikm = Zeroizing::new([0u8; 128]);
    ikm[0..32].copy_from_slice(input.ss_x25519);
    ikm[32..64].copy_from_slice(input.ss_mlkem);
    ikm[64..96].copy_from_slice(input.ephemeral_x25519_pubkey);
    ikm[96..128].copy_from_slice(input.recipient_x25519_pubkey);

    let mut info = Vec::with_capacity(
        PQ_STANZA_INFO_PREFIX.len() + 16 + 8 + input.recipient_id.len(),
    );
    info.extend_from_slice(PQ_STANZA_INFO_PREFIX);
    info.extend_from_slice(input.vault_id.as_bytes());
    info.extend_from_slice(&input.epoch.to_le_bytes());
    info.extend_from_slice(input.recipient_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(input.wrap_nonce), &*ikm);
    hkdf_expand_256(&hk, &info)
}

fn derive_share_keys(share_id: Uuid, srk: &[u8; 32]) -> ZeroVaultResult<ShareDerivedKeys> {
    let hk = Hkdf::<Sha256>::new(Some(share_id.as_bytes()), srk);
    let share_kek = hkdf_expand_256(&hk, HKDF_INFO_SHARE_KEK)?;
    let share_desc_key = hkdf_expand_256(&hk, HKDF_INFO_SHARE_DESC)?;
    Ok(ShareDerivedKeys {
        share_kek,
        share_desc_key,
    })
}

fn share_envelope_aad(
    share_id: Uuid,
    owner_ed25519_pubkey: &[u8; ED25519_PUBKEY_LEN],
) -> [u8; 4 + 1 + 16 + ED25519_PUBKEY_LEN] {
    let mut aad = [0u8; 53];
    aad[0..4].copy_from_slice(&SHARE_ENVELOPE_MAGIC);
    aad[4] = SHARE_ENVELOPE_VERSION;
    aad[5..21].copy_from_slice(share_id.as_bytes());
    aad[21..53].copy_from_slice(owner_ed25519_pubkey);
    aad
}

/// Generates a fresh post-quantum hybrid recipient identity (`Ed25519` + `X25519` + `ML-KEM-768`).
pub(crate) fn generate_recipient_identity(label: &str) -> ZeroVaultResult<RecipientPrivateIdentity> {
    ensure_hardware_acceleration()?;

    let ed25519_seed = fill_csprng_zeroizing::<32>()?;
    let ed_kp = Ed25519KeyPair::from_seed_unchecked(&*ed25519_seed).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("Ed25519 key generation failed".into())
    })?;
    let ed_pub_bytes = ed_kp.public_key().as_ref();
    if ed_pub_bytes.len() != ED25519_PUBKEY_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "unexpected Ed25519 public key length".into(),
        ));
    }
    let mut ed25519_pubkey = [0u8; ED25519_PUBKEY_LEN];
    ed25519_pubkey.copy_from_slice(ed_pub_bytes);

    let x25519_private = fill_csprng_zeroizing::<X25519_KEY_LEN>()?;
    let x_priv = PrivateKey::from_private_key(&X25519, &*x25519_private).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("X25519 private key generation failed".into())
    })?;
    let x_pub = x_priv.compute_public_key().map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("X25519 public key derivation failed".into())
    })?;
    let x_pub_bytes = x_pub.as_ref();
    if x_pub_bytes.len() != X25519_KEY_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "unexpected X25519 public key length".into(),
        ));
    }
    let mut x25519_pubkey = [0u8; X25519_KEY_LEN];
    x25519_pubkey.copy_from_slice(x_pub_bytes);

    let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("ML-KEM-768 key generation failed".into())
    })?;
    let dk_bytes = dk.key_bytes().map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("ML-KEM-768 decapsulation key export failed".into())
    })?;
    if dk_bytes.as_ref().len() != ML_KEM_768_DECAPS_KEY_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "unexpected ML-KEM-768 decapsulation key length".into(),
        ));
    }
    let mut mlkem768_decaps_key = Zeroizing::new(Vec::with_capacity(ML_KEM_768_DECAPS_KEY_LEN));
    mlkem768_decaps_key.extend_from_slice(dk_bytes.as_ref());

    let ek = dk.encapsulation_key().map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("ML-KEM-768 encapsulation key derivation failed".into())
    })?;
    let ek_bytes = ek.key_bytes().map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("ML-KEM-768 encapsulation key export failed".into())
    })?;
    if ek_bytes.as_ref().len() != ML_KEM_768_ENCAPS_KEY_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "unexpected ML-KEM-768 encapsulation key length".into(),
        ));
    }
    let mlkem768_encaps_key = ek_bytes.as_ref().to_vec();

    let recipient_id =
        RecipientPublicBundle::compute_id(&ed25519_pubkey, &x25519_pubkey, &mlkem768_encaps_key);
    let public = RecipientPublicBundle {
        recipient_id,
        label: label.to_owned(),
        ed25519_pubkey,
        x25519_pubkey,
        mlkem768_encaps_key,
    };
    public.validate()?;

    Ok(RecipientPrivateIdentity {
        public,
        ed25519_seed,
        x25519_private,
        mlkem768_decaps_key,
    })
}

/// Seals and signs a multi-recipient `keybox.zv` (`Ed25519` + `X25519` + `ML-KEM-768`) at `epoch`.
pub(crate) fn seal_keybox(
    owner_identity: &RecipientPrivateIdentity,
    vault_id: Uuid,
    epoch: u64,
    folder_root_key: &[u8; 32],
    recipients: &[RecipientPublicBundle],
) -> ZeroVaultResult<SignedKeybox> {
    ensure_hardware_acceleration()?;
    if epoch == 0 {
        return Err(ZeroVaultError::InvalidWireFormat(
            "keybox epoch must be >= 1".into(),
        ));
    }
    owner_identity.public.validate()?;

    let owner_kp = Ed25519KeyPair::from_seed_and_public_key(
        &*owner_identity.ed25519_seed,
        &owner_identity.public.ed25519_pubkey,
    )
    .map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("owner Ed25519 identity inconsistent".into())
    })?;

    let aws_rng = AwsSystemRandom::new();
    let mut stanzas = Vec::with_capacity(recipients.len());

    for rcpt in recipients {
        rcpt.validate()?;

        let eph_priv = EphemeralPrivateKey::generate(&X25519, &aws_rng).map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("ephemeral X25519 key generation failed".into())
        })?;
        let eph_pub = eph_priv.compute_public_key().map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("ephemeral X25519 pubkey derivation failed".into())
        })?;
        if eph_pub.as_ref().len() != X25519_KEY_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "unexpected ephemeral X25519 public key length".into(),
            ));
        }
        let mut ephemeral_x25519_pubkey = [0u8; X25519_KEY_LEN];
        ephemeral_x25519_pubkey.copy_from_slice(eph_pub.as_ref());

        let peer_pub = KemAgreementPubKey::new(&X25519, &rcpt.x25519_pubkey);
        let ss_x25519 = agreement::agree_ephemeral(
            eph_priv,
            peer_pub,
            ZeroVaultError::CryptoTamperDetected("X25519 ephemeral key agreement failed".into()),
            |secret| {
                if secret.len() != 32 {
                    return Err(ZeroVaultError::CryptoTamperDetected(
                        "unexpected X25519 shared secret length".into(),
                    ));
                }
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(secret);
                Ok(out)
            },
        )?;

        let encaps_key =
            EncapsulationKey::new(&ML_KEM_768, &rcpt.mlkem768_encaps_key).map_err(|_| {
                ZeroVaultError::InvalidWireFormat(
                    "invalid recipient ML-KEM-768 encapsulation key".into(),
                )
            })?;
        let (kem_ct, ss_mlkem) = encaps_key.encapsulate().map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("ML-KEM-768 encapsulation failed".into())
        })?;
        if kem_ct.as_ref().len() != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(ZeroVaultError::CryptoTamperDetected(
                "unexpected ML-KEM-768 ciphertext length".into(),
            ));
        }

        let wrap_nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
        let stanza_wrap_key = derive_hybrid_stanza_key(StanzaKdfInput {
            ss_x25519: &ss_x25519,
            ss_mlkem: ss_mlkem.as_ref(),
            ephemeral_x25519_pubkey: &ephemeral_x25519_pubkey,
            recipient_x25519_pubkey: &rcpt.x25519_pubkey,
            wrap_nonce: &wrap_nonce,
            vault_id,
            epoch,
            recipient_id: &rcpt.recipient_id,
        })?;

        let aad = HybridRecipientStanza::stanza_aad(vault_id, epoch, &rcpt.recipient_id);
        let wrapped_folder_key =
            seal_with_nonce(&stanza_wrap_key, wrap_nonce, &aad, folder_root_key)?;

        stanzas.push(HybridRecipientStanza {
            recipient_id: rcpt.recipient_id.clone(),
            ephemeral_x25519_pubkey,
            mlkem768_ciphertext: kem_ct.as_ref().to_vec(),
            wrap_nonce,
            wrapped_folder_key,
        });
    }

    let mut keybox = SignedKeybox {
        version: KEYBOX_VERSION,
        vault_id,
        epoch,
        owner_ed25519_pubkey: owner_identity.public.ed25519_pubkey,
        created_at: Utc::now(),
        stanzas,
        owner_signature: Vec::new(),
    };
    let transcript = keybox.signing_transcript()?;
    let sig = owner_kp.sign(&transcript);
    keybox.owner_signature = sig.as_ref().to_vec();
    Ok(keybox)
}

/// Verifies `version`, `epoch >= 1`, `epoch >= min_epoch_floor`, optional `expected_vault_id`,
/// optional `expected_owner_pubkey`, stanza structural invariants, and the 64-byte `Ed25519`
/// `owner_signature` over [`SignedKeybox::signing_transcript`] (`W4-VETO-KEYBOX-SIG` remediation).
pub(crate) fn verify_keybox_envelope(
    keybox: &SignedKeybox,
    expected_vault_id: Option<Uuid>,
    expected_owner_pubkey: Option<&[u8; 32]>,
    min_epoch_floor: u64,
) -> ZeroVaultResult<()> {
    ensure_hardware_acceleration()?;

    if keybox.version != KEYBOX_VERSION {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "unsupported keybox version {}",
            keybox.version
        )));
    }
    if keybox.epoch == 0 || keybox.epoch < min_epoch_floor {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "keybox epoch rollback detected: got {}, minimum floor is {min_epoch_floor}",
            keybox.epoch
        )));
    }
    if let Some(expected_vid) = expected_vault_id
        && keybox.vault_id != expected_vid
    {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "keybox vault_id mismatch: expected {expected_vid}, got {}",
            keybox.vault_id
        )));
    }
    if let Some(expected_owner) = expected_owner_pubkey
        && !bool::from(keybox.owner_ed25519_pubkey.ct_eq(expected_owner))
    {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "keybox owner Ed25519 public key mismatch".into(),
        ));
    }

    for stanza in &keybox.stanzas {
        stanza.validate()?;
    }

    if keybox.owner_signature.len() != ED25519_SIGNATURE_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "invalid keybox Ed25519 signature length".into(),
        ));
    }
    let transcript = keybox.signing_transcript()?;
    SigVerifyPubKey::new(&ED25519, &keybox.owner_ed25519_pubkey)
        .verify(&transcript, &keybox.owner_signature)
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected(
                "keybox Ed25519 signature verification failed".into(),
            )
        })?;

    Ok(())
}

/// Verifies `epoch >= min_epoch_floor`, checks `Ed25519` owner signature, and decapsulates `FolderRootKey`.
pub(crate) fn open_keybox(
    keybox: &SignedKeybox,
    expected_owner_pubkey: Option<&[u8; 32]>,
    min_epoch_floor: u64,
    recipient_identity: &RecipientPrivateIdentity,
) -> ZeroVaultResult<Zeroizing<[u8; 32]>> {
    verify_keybox_envelope(keybox, None, expected_owner_pubkey, min_epoch_floor)?;

    recipient_identity.public.validate()?;

    // Locate recipient's hybrid stanza (fail with UnauthorizedRecipient if absent/revoked).
    let stanza = keybox
        .stanzas
        .iter()
        .find(|s| s.recipient_id == recipient_identity.public.recipient_id)
        .ok_or_else(|| {
            ZeroVaultError::UnauthorizedRecipient(recipient_identity.public.recipient_id.clone())
        })?;

    if stanza.mlkem768_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN
        || stanza.wrapped_folder_key.len() != WRAPPED_KEY_LEN
    {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "corrupted keybox recipient stanza lengths".into(),
        ));
    }

    // 5. Decapsulate ML-KEM-768 + static X25519 ECDH.
    let decaps_key = DecapsulationKey::new(&ML_KEM_768, &recipient_identity.mlkem768_decaps_key)
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected(
                "invalid recipient ML-KEM-768 decapsulation key".into(),
            )
        })?;
    let ss_mlkem = decaps_key
        .decapsulate(Ciphertext::from(stanza.mlkem768_ciphertext.as_slice()))
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected("ML-KEM-768 decapsulation failed".into())
        })?;

    let x_priv =
        PrivateKey::from_private_key(&X25519, &*recipient_identity.x25519_private).map_err(
            |_| ZeroVaultError::CryptoTamperDetected("invalid recipient X25519 private key".into()),
        )?;
    let peer_epk = KemAgreementPubKey::new(&X25519, &stanza.ephemeral_x25519_pubkey);
    let ss_x25519 = agreement::agree(
        &x_priv,
        peer_epk,
        ZeroVaultError::CryptoTamperDetected("X25519 static key agreement failed".into()),
        |secret| {
            if secret.len() != 32 {
                return Err(ZeroVaultError::CryptoTamperDetected(
                    "unexpected X25519 shared secret length".into(),
                ));
            }
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(secret);
            Ok(out)
        },
    )?;

    // 6. Derive stanza wrapping key via HKDF-SHA256 and unwrap FolderRootKey under ring AES-256-GCM.
    let stanza_wrap_key = derive_hybrid_stanza_key(StanzaKdfInput {
        ss_x25519: &ss_x25519,
        ss_mlkem: ss_mlkem.as_ref(),
        ephemeral_x25519_pubkey: &stanza.ephemeral_x25519_pubkey,
        recipient_x25519_pubkey: &recipient_identity.public.x25519_pubkey,
        wrap_nonce: &stanza.wrap_nonce,
        vault_id: keybox.vault_id,
        epoch: keybox.epoch,
        recipient_id: &stanza.recipient_id,
    })?;

    let aad =
        HybridRecipientStanza::stanza_aad(keybox.vault_id, keybox.epoch, &stanza.recipient_id);
    let (ct, tag) = stanza.wrapped_folder_key.split_at(32);
    let mut frk = Zeroizing::new([0u8; 32]);
    frk.copy_from_slice(ct);
    open_in_place_detached(&stanza_wrap_key, stanza.wrap_nonce, &aad, tag, &mut *frk)?;
    Ok(frk)
}

/// Creates a signed `zv://` read-only capability share envelope + URI for a file.
pub(crate) fn create_capability_share(
    owner_identity: &RecipientPrivateIdentity,
    backend_hint: &str,
    root_locator: &str,
    file_dek: &DekBytes,
    descriptor: &ShareDescriptor,
) -> ZeroVaultResult<(CapabilityUri, SignedShareEnvelope)> {
    ensure_hardware_acceleration()?;
    owner_identity.public.validate()?;

    let owner_kp = Ed25519KeyPair::from_seed_and_public_key(
        &*owner_identity.ed25519_seed,
        &owner_identity.public.ed25519_pubkey,
    )
    .map_err(|_| {
        ZeroVaultError::CryptoTamperDetected("owner Ed25519 identity inconsistent".into())
    })?;

    let srk = fill_csprng_zeroizing::<32>()?;
    let uri = CapabilityUri {
        backend_hint: backend_hint.to_owned(),
        root_locator: root_locator.to_owned(),
        share_id: descriptor.share_id,
        share_root_key: srk.clone(),
        owner_ed25519_pubkey: owner_identity.public.ed25519_pubkey,
    };
    // Validate URI syntax (e.g. backend_hint rules) upfront before sealing.
    let _ = Zeroizing::new(uri.encode()?);

    let ShareDerivedKeys {
        share_kek,
        share_desc_key,
    } = derive_share_keys(descriptor.share_id, &srk)?;

    let dek_nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
    let dek_aad = WrappedDek::dek_wrap_aad(descriptor.file_id);
    let dek_ct_and_tag = seal_with_nonce(&share_kek, dek_nonce, &dek_aad, file_dek.as_bytes())?;

    let mut sealed_desc = descriptor.clone();
    sealed_desc.wrapped_dek = WrappedDek {
        nonce: dek_nonce,
        ciphertext_and_tag: dek_ct_and_tag,
    };

    let raw_desc = Zeroizing::new(
        postcard::to_allocvec(&sealed_desc)
            .map_err(|e| ZeroVaultError::InvalidWireFormat(e.to_string()))?,
    );
    let env_nonce = fill_csprng::<AES_GCM_NONCE_LEN>()?;
    let env_aad = share_envelope_aad(descriptor.share_id, &owner_identity.public.ed25519_pubkey);
    let ciphertext_and_tag = seal_with_nonce(&share_desc_key, env_nonce, &env_aad, &raw_desc)?;

    let mut envelope = SignedShareEnvelope {
        version: SHARE_ENVELOPE_VERSION,
        share_id: descriptor.share_id,
        owner_ed25519_pubkey: owner_identity.public.ed25519_pubkey,
        nonce: env_nonce,
        ciphertext_and_tag,
        ed25519_signature: Vec::new(),
    };
    let transcript = envelope.signing_transcript();
    let sig = owner_kp.sign(&transcript);
    envelope.ed25519_signature = sig.as_ref().to_vec();

    Ok((uri, envelope))
}

/// Verifies `Ed25519` signature + decrypts a `zv://` share envelope, returning `(ShareDescriptor, DekBytes)`.
pub(crate) fn open_capability_share(
    uri: &CapabilityUri,
    envelope: &SignedShareEnvelope,
) -> ZeroVaultResult<(ShareDescriptor, DekBytes)> {
    ensure_hardware_acceleration()?;

    if envelope.version != SHARE_ENVELOPE_VERSION {
        return Err(ZeroVaultError::CryptoTamperDetected(format!(
            "unsupported share envelope version {}",
            envelope.version
        )));
    }
    if envelope.share_id != uri.share_id {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "share envelope share_id mismatch with capability URI".into(),
        ));
    }
    if !bool::from(
        envelope
            .owner_ed25519_pubkey
            .ct_eq(&uri.owner_ed25519_pubkey),
    ) {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "share envelope owner Ed25519 pubkey mismatch with capability URI".into(),
        ));
    }
    if envelope.ed25519_signature.len() != ED25519_SIGNATURE_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "invalid share envelope Ed25519 signature length".into(),
        ));
    }

    let transcript = envelope.signing_transcript();
    SigVerifyPubKey::new(&ED25519, &uri.owner_ed25519_pubkey)
        .verify(&transcript, &envelope.ed25519_signature)
        .map_err(|_| {
            ZeroVaultError::CryptoTamperDetected(
                "share envelope Ed25519 signature verification failed".into(),
            )
        })?;

    let ShareDerivedKeys {
        share_kek,
        share_desc_key,
    } = derive_share_keys(uri.share_id, &uri.share_root_key)?;
    let env_aad = share_envelope_aad(uri.share_id, &uri.owner_ed25519_pubkey);
    let pt_desc = open_with_nonce(
        &share_desc_key,
        envelope.nonce,
        &env_aad,
        &envelope.ciphertext_and_tag,
    )?;

    let desc: ShareDescriptor = postcard::from_bytes(&pt_desc)
        .map_err(|e| ZeroVaultError::InvalidWireFormat(format!("share descriptor decode: {e}")))?;
    if desc.share_id != uri.share_id {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "decrypted ShareDescriptor share_id mismatch".into(),
        ));
    }
    if desc.wrapped_dek.ciphertext_and_tag.len() != WRAPPED_KEY_LEN {
        return Err(ZeroVaultError::CryptoTamperDetected(
            "share descriptor wrapped_dek length mismatch".into(),
        ));
    }

    let (dek_ct, dek_tag) = desc.wrapped_dek.ciphertext_and_tag.split_at(32);
    let dek_aad = WrappedDek::dek_wrap_aad(desc.file_id);
    let mut dek_raw = Zeroizing::new([0u8; 32]);
    dek_raw.copy_from_slice(dek_ct);
    open_in_place_detached(&share_kek, desc.wrapped_dek.nonce, &dek_aad, dek_tag, &mut *dek_raw)?;

    let dek = DekBytes::from_slice(&*dek_raw)?;
    Ok((desc, dek))
}
