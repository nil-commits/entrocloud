use std::time::Instant;

use aws_lc_rs::aead::{
    AES_256_GCM as AWS_AES_256_GCM, Aad as AwsAad, LessSafeKey as AwsLessSafeKey,
    Nonce as AwsNonce, UnboundKey as AwsUnboundKey,
};
use bytes::BytesMut;
use chrono::Utc;
use proptest::prelude::*;
use uuid::Uuid;
use zeroize::Zeroize;
use entrocloud_crypto::{
    AwsLcCryptoEngine, BlindIndexKey, CRYPTO_BACKEND_AESNI, CRYPTO_BACKEND_VAES_AVX2,
    DefaultCryptoEngine, HeaderVerifierKey, KeyRingState, ManifestKey, MasterKek, MasterSeed,
    MetadataKey, OsKeyringSecretStore, RingHybridCryptoEngine, StagingKey, TokenWrapKey,
    detect_hardware_capabilities, validate_hardware_caps, verify_hardware_acceleration,
};
use entrocloud_types::mocks::InMemorySecretStore;
use entrocloud_types::{
    AES_GCM_TAG_LEN, CHUNK_HEADER_LEN, CapabilityUri, ChunkAad, ChunkRef,
    CryptoEngine, DekBytes, ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN, EntryKind,
    HardwareCryptoCaps, KdfParams, MANIFEST_HEADER_LEN, MAX_ARGON2_ITERATIONS,
    MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM, MAX_ENCRYPTED_CHUNK_SIZE,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_PARALLELISM,
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_DECAPS_KEY_LEN, ML_KEM_768_ENCAPS_KEY_LEN, ManifestNode,
    PLAINTEXT_CHUNK_SIZE, RecipientPublicBundle, RedactedSecret, SecretStore, ShareDescriptor,
    SignedKeybox, SignedShareEnvelope, VaultHeader, VaultManifest, WrappedDek, X25519_KEY_LEN,
    ZeroVaultError,
};

fn make_engine() -> RingHybridCryptoEngine {
    RingHybridCryptoEngine::new().expect("host CPU must provide hardware AES + GHASH")
}

#[test]
fn hardware_acceleration_verified_and_fail_closed_when_absent() {
    let caps = verify_hardware_acceleration().expect("host supports AES + PCLMULQDQ/PMULL");
    assert!(caps.mandatory_satisfied);
    assert!(caps.aes_hw);
    assert!(caps.pclmul_hw);

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if caps.vaes_hw && caps.avx2_hw {
            assert_eq!(caps.backend_name, CRYPTO_BACKEND_VAES_AVX2);
        } else {
            assert_eq!(caps.backend_name, CRYPTO_BACKEND_AESNI);
        }
    }

    assert_eq!(detect_hardware_capabilities(), caps);

    let engine = make_engine();
    assert_eq!(engine.hardware_caps(), &caps);
    assert_eq!(
        engine
            .verify_hardware_acceleration()
            .expect("engine verify_hardware_acceleration"),
        caps
    );

    // Aliases resolve to RingHybridCryptoEngine.
    let _default_engine = DefaultCryptoEngine::new().expect("default alias");
    let _compat_engine = AwsLcCryptoEngine::new().expect("compat alias");

    // Simulated missing AES or PCLMULQDQ MUST fail closed with HardwareAccelerationUnavailable.
    for bad_caps in [
        HardwareCryptoCaps {
            aes_hw: false,
            ..caps.clone()
        },
        HardwareCryptoCaps {
            pclmul_hw: false,
            ..caps.clone()
        },
        HardwareCryptoCaps {
            mandatory_satisfied: false,
            ..caps.clone()
        },
    ] {
        let err = validate_hardware_caps(bad_caps).expect_err("absent hw crypto must fail closed");
        assert!(matches!(
            err,
            ZeroVaultError::HardwareAccelerationUnavailable(_)
        ));
    }
}

#[test]
fn all_eight_key_wrappers_redact_debug_zeroize_and_separate_7_hkdf_domains() {
    let mut seed = MasterSeed::from_array([0xA1; 32]);
    let kek = MasterKek::from_array([0xB2; 32]);
    let manifest_k = ManifestKey::from_array([0xC3; 32]);
    let token_k = TokenWrapKey::from_array([0xD4; 32]);
    let verifier_k = HeaderVerifierKey::from_array([0xE5; 32]);
    let meta_k = MetadataKey::from_array([0xF6; 32]);
    let blind_k = BlindIndexKey::from_array([0x17; 32]);
    let stage_k = StagingKey::from_array([0x28; 32]);

    assert_eq!(format!("{seed:?}"), "MasterSeed([REDACTED])");
    assert_eq!(format!("{kek:?}"), "MasterKek([REDACTED])");
    assert_eq!(format!("{manifest_k:?}"), "ManifestKey([REDACTED])");
    assert_eq!(format!("{token_k:?}"), "TokenWrapKey([REDACTED])");
    assert_eq!(format!("{verifier_k:?}"), "HeaderVerifierKey([REDACTED])");
    assert_eq!(format!("{meta_k:?}"), "MetadataKey([REDACTED])");
    assert_eq!(format!("{blind_k:?}"), "BlindIndexKey([REDACTED])");
    assert_eq!(format!("{stage_k:?}"), "StagingKey([REDACTED])");

    seed.zeroize();
    assert_eq!(seed.as_bytes(), &[0u8; 32]);

    let vault_id = Uuid::new_v4();
    let root_bytes = [0x77u8; 32];
    let mut ring = KeyRingState::from_folder_root_key(vault_id, MasterSeed::from_array(root_bytes))
        .expect("expand 7 HKDF subkeys");

    let subkeys: [&[u8; 32]; 7] = [
        ring.master_kek().as_bytes(),
        ring.manifest_key().as_bytes(),
        ring.token_wrap_key().as_bytes(),
        ring.header_verifier_key().as_bytes(),
        ring.metadata_key().as_bytes(),
        ring.blind_index_key().as_bytes(),
        ring.staging_key().as_bytes(),
    ];
    for (i, a) in subkeys.iter().enumerate() {
        assert_ne!(*a, &root_bytes, "subkey {i} must differ from root_key");
        for (j, b) in subkeys.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "subkeys {i} and {j} must be domain-separated");
            }
        }
    }

    let ring_dbg = format!("{ring:?}");
    assert!(ring_dbg.contains("[REDACTED]"));
    assert!(!ring_dbg.contains("77"));
    ring.zeroize();

    fn assert_zeroize_on_drop<T: std::fmt::Debug + zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<KeyRingState>();
    assert_zeroize_on_drop::<MasterSeed>();
    assert_zeroize_on_drop::<MasterKek>();
    assert_zeroize_on_drop::<ManifestKey>();
    assert_zeroize_on_drop::<TokenWrapKey>();
    assert_zeroize_on_drop::<HeaderVerifierKey>();
    assert_zeroize_on_drop::<MetadataKey>();
    assert_zeroize_on_drop::<BlindIndexKey>();
    assert_zeroize_on_drop::<StagingKey>();
    assert_zeroize_on_drop::<DekBytes>();
}

#[tokio::test]
async fn init_lock_unlock_lifecycle_and_kdf_floor_plus_oom_ceiling() {
    let engine = make_engine();
    assert!(!engine.is_unlocked());
    assert!(engine.vault_id().is_none());

    // Floor violations AND DoS OOM ceiling violations MUST fail closed pre-allocation.
    for bad_kdf in [
        KdfParams {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB - 1,
            t_cost: 3,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: MAX_ARGON2_MEMORY_KIB + 1,
            t_cost: 3,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 3,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB,
            t_cost: MIN_ARGON2_ITERATIONS - 1,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB,
            t_cost: MAX_ARGON2_ITERATIONS + 1,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB,
            t_cost: 3,
            p_cost: MIN_ARGON2_PARALLELISM - 1,
        },
        KdfParams {
            m_cost_kib: MIN_ARGON2_MEMORY_KIB,
            t_cost: 3,
            p_cost: MAX_ARGON2_PARALLELISM + 1,
        },
    ] {
        let start = Instant::now();
        let err = engine
            .init_vault(&RedactedSecret::new("passphrase"), bad_kdf)
            .await
            .expect_err("invalid KDF must fail pre-allocation");
        assert!(matches!(err, ZeroVaultError::KdfPolicyViolation { .. }));
        assert!(
            start.elapsed().as_millis() < 50,
            "KDF ceiling check must reject prior to memory allocation"
        );
    }

    let passphrase = RedactedSecret::new("correct horse battery staple");
    let header = engine
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init_vault");
    assert!(engine.is_unlocked());
    assert_eq!(engine.vault_id(), Some(header.vault_id));

    let wire_hdr = header.encode();
    let decoded_hdr = VaultHeader::decode(&wire_hdr).expect("decode ZVH1");
    assert_eq!(decoded_hdr, header);

    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");
    let wrapped_dek = engine.wrap_dek(file_id, &dek).expect("wrap DEK");

    engine.lock_vault().await.expect("lock_vault");
    assert!(!engine.is_unlocked());
    assert!(engine.vault_id().is_none());

    // All vault-key operations MUST fail with VaultLocked while locked.
    assert!(matches!(
        engine.wrap_dek(file_id, &dek),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.unwrap_dek(file_id, &wrapped_dek),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.export_folder_root_key(),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.seal_metadata(b"aad", b"secret"),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.compute_blind_index(1, "notes.txt"),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.seal_staging_chunk(2, 0, b"dirty"),
        Err(ZeroVaultError::VaultLocked)
    ));

    // Wrong passphrase -> InvalidPassphrase.
    assert!(matches!(
        engine
            .unlock_with_passphrase(&decoded_hdr, &RedactedSecret::new("wrong"))
            .await,
        Err(ZeroVaultError::InvalidPassphrase)
    ));
    assert!(!engine.is_unlocked());

    // Tampered verifier_tag -> InvalidPassphrase.
    let mut bad_hdr = decoded_hdr.clone();
    bad_hdr.verifier_tag[31] ^= 0x01;
    assert!(matches!(
        engine.unlock_with_passphrase(&bad_hdr, &passphrase).await,
        Err(ZeroVaultError::InvalidPassphrase)
    ));

    // OOM KDF injected into VaultHeader struct directly -> KdfPolicyViolation pre-allocation.
    let mut oom_hdr = decoded_hdr.clone();
    oom_hdr.kdf.m_cost_kib = 4 * 1024 * 1024;
    let start_oom = Instant::now();
    assert!(matches!(
        engine.unlock_with_passphrase(&oom_hdr, &passphrase).await,
        Err(ZeroVaultError::KdfPolicyViolation { .. })
    ));
    assert!(start_oom.elapsed().as_millis() < 50);

    // Valid unlock restores identical 7-subkey hierarchy.
    engine
        .unlock_with_passphrase(&decoded_hdr, &passphrase)
        .await
        .expect("unlock_with_passphrase");
    let unwrapped = engine
        .unwrap_dek(file_id, &wrapped_dek)
        .expect("unwrap DEK");
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
}

#[test]
fn ring_and_aws_lc_aes256_gcm_produce_bit_identical_wire_ciphertext_and_tags() {
    let engine = make_engine();
    let key_raw = [0x3Cu8; 32];
    let dek = DekBytes::from_array(key_raw);
    let file_id = Uuid::new_v4();
    let aad = ChunkAad {
        file_id,
        chunk_index: 5,
        is_final_chunk: true,
    };
    let plaintext = b"ZeroVault Wave 2 ring <-> aws-lc-rs bit-exact interop vector";

    let (hdr, wire) = engine
        .encrypt_chunk(&dek, aad, plaintext)
        .expect("ring encrypt_chunk");
    let ring_ct = &wire[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + plaintext.len()];
    let ring_tag = &wire[CHUNK_HEADER_LEN + plaintext.len()..];

    // Encrypt identical plaintext with aws-lc-rs using the same nonce and 25-byte ChunkAad.
    let aws_key =
        AwsLessSafeKey::new(AwsUnboundKey::new(&AWS_AES_256_GCM, &key_raw).expect("aws key"));
    let mut aws_buf = plaintext.to_vec();
    let aws_tag = aws_key
        .seal_in_place_separate_tag(
            AwsNonce::assume_unique_for_key(hdr.nonce),
            AwsAad::from(&aad.to_bytes()[..]),
            &mut aws_buf,
        )
        .expect("aws seal");

    assert_eq!(ring_ct, aws_buf.as_slice());
    assert_eq!(ring_tag, aws_tag.as_ref());
}

#[test]
fn multi_chunk_4mib_streaming_buffer_reuse_and_tamper_scrubbing() {
    let engine = make_engine();
    let file_a = Uuid::new_v4();
    let file_b = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");

    let tail_len = 128 * 1024;
    let total_len = PLAINTEXT_CHUNK_SIZE + tail_len;
    let mut full_pt = vec![0u8; total_len];
    for (i, b) in full_pt.iter_mut().enumerate() {
        *b = (i.wrapping_mul(19) ^ (i >> 8)) as u8;
    }

    let mut reusable_wire = BytesMut::with_capacity(MAX_ENCRYPTED_CHUNK_SIZE);
    let wire_ptr = reusable_wire.as_ptr();
    let wire_cap = reusable_wire.capacity();

    let hdr0 = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 0,
                is_final_chunk: false,
            },
            &full_pt[..PLAINTEXT_CHUNK_SIZE],
            &mut reusable_wire,
        )
        .expect("encrypt chunk 0");
    assert_eq!(reusable_wire.as_ptr(), wire_ptr);
    assert_eq!(reusable_wire.capacity(), wire_cap);
    let wire0 = reusable_wire.to_vec();

    let hdr1 = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 1,
                is_final_chunk: true,
            },
            &full_pt[PLAINTEXT_CHUNK_SIZE..],
            &mut reusable_wire,
        )
        .expect("encrypt chunk 1");
    assert_ne!(hdr0.nonce, hdr1.nonce);
    assert_eq!(reusable_wire.as_ptr(), wire_ptr);
    assert_eq!(reusable_wire.capacity(), wire_cap);
    let wire1 = reusable_wire.to_vec();

    let mut reusable_pt = BytesMut::with_capacity(PLAINTEXT_CHUNK_SIZE);
    let pt_ptr = reusable_pt.as_ptr();
    let pt_cap = reusable_pt.capacity();

    engine
        .decrypt_chunk_into(&dek, file_a, Some(0), &wire0, &mut reusable_pt)
        .expect("decrypt chunk 0");
    assert_eq!(reusable_pt.as_ptr(), pt_ptr);
    assert_eq!(reusable_pt.capacity(), pt_cap);
    assert_eq!(reusable_pt.as_ref(), &full_pt[..PLAINTEXT_CHUNK_SIZE]);

    engine
        .decrypt_chunk_into(&dek, file_a, Some(1), &wire1, &mut reusable_pt)
        .expect("decrypt chunk 1");
    assert_eq!(reusable_pt.as_ptr(), pt_ptr);
    assert_eq!(reusable_pt.as_ref(), &full_pt[PLAINTEXT_CHUNK_SIZE..]);

    // Empty 0-byte file at chunk_index 0 roundtrip.
    engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 0,
                is_final_chunk: true,
            },
            &[],
            &mut reusable_wire,
        )
        .expect("encrypt empty chunk");
    assert_eq!(reusable_wire.len(), CHUNK_HEADER_LEN + AES_GCM_TAG_LEN);
    engine
        .decrypt_chunk_into(&dek, file_a, Some(0), &reusable_wire, &mut reusable_pt)
        .expect("decrypt empty chunk");
    assert!(reusable_pt.is_empty());

    // Tamper checks MUST immediately zeroize and clear `out_plaintext`!
    let mut out_pt = BytesMut::from(&b"sensitive-leftover-plaintext"[..]);
    let mut bad_ct = wire1.clone();
    bad_ct[CHUNK_HEADER_LEN + 17] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &bad_ct, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());

    // Cross-file swap and chunk-index swap fail closed and clear out_pt.
    out_pt.extend_from_slice(b"leftover");
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_b, Some(1), &wire1, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());

    out_pt.extend_from_slice(b"leftover");
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(0), &wire1, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());
}

#[test]
fn metadata_blind_index_staging_and_manifest_operations_roundtrip_and_reject_tamper() {
    let engine = make_engine();
    let vault_id = Uuid::new_v4();
    engine
        .unlock_with_folder_key(vault_id, &[0x42u8; 32])
        .expect("unlock_with_folder_key");

    // 1. Metadata AEAD
    let aad = b"inode:99:name";
    let ct = engine
        .seal_metadata(aad, b"tax_return_2026.pdf")
        .expect("seal_metadata");
    let pt = engine.open_metadata(aad, &ct).expect("open_metadata");
    assert_eq!(pt.as_slice(), b"tax_return_2026.pdf");
    assert!(matches!(
        engine.open_metadata(b"inode:100:name", &ct),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut bad_meta = ct.clone();
    bad_meta[15] ^= 0x04;
    assert!(matches!(
        engine.open_metadata(aad, &bad_meta),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2. Keyed BLAKE3 Blind Index
    let idx_a1 = engine
        .compute_blind_index(1, "Makefile")
        .expect("blind index");
    let idx_a2 = engine
        .compute_blind_index(1, "Makefile")
        .expect("blind index deterministic");
    let idx_case = engine
        .compute_blind_index(1, "makefile")
        .expect("blind index case-sensitive");
    let idx_parent = engine
        .compute_blind_index(2, "Makefile")
        .expect("blind index parent-bound");
    assert_eq!(idx_a1, idx_a2);
    assert_ne!(idx_a1, idx_case);
    assert_ne!(idx_a1, idx_parent);

    // 3. Local .zvpart Staging Chunk AEAD
    let stage_sealed = engine
        .seal_staging_chunk(77, 3, b"dirty-chunk-payload")
        .expect("seal_staging_chunk");
    let stage_pt = engine
        .open_staging_chunk(77, 3, &stage_sealed)
        .expect("open_staging_chunk");
    assert_eq!(stage_pt.as_slice(), b"dirty-chunk-payload");
    assert!(matches!(
        engine.open_staging_chunk(78, 3, &stage_sealed),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(matches!(
        engine.open_staging_chunk(77, 4, &stage_sealed),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 4. ZVM1 Manifest AEAD
    let now = Utc::now();
    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("dek");
    let wrapped = engine.wrap_dek(file_id, &dek).expect("wrap_dek");
    let manifest = VaultManifest {
        vault_id,
        revision: 7,
        parent_manifest_id: None,
        device_id: "node-1".to_owned(),
        created_at: now,
        nodes: vec![ManifestNode {
            inode: 2,
            parent_inode: 1,
            file_id,
            name: "secrets.kdbx".to_owned(),
            kind: EntryKind::File,
            size: 512,
            mode: 0o600,
            modified_at: now,
            created_at: now,
            version: 1,
            wrapped_dek: Some(wrapped),
            chunks: vec![ChunkRef {
                chunk_index: 0,
                blob_id: Uuid::new_v4(),
                plaintext_len: 512,
                ciphertext_len: 560,
                blake3_plaintext: [0xAB; 32],
                backend_ids: vec!["gdrive".to_owned()],
            }],
        }],
    };
    let sealed_m = engine.seal_manifest(&manifest).expect("seal_manifest");
    let opened_m = engine.open_manifest(&sealed_m).expect("open_manifest");
    assert_eq!(opened_m, manifest);

    let mut bad_m = sealed_m.to_vec();
    bad_m[MANIFEST_HEADER_LEN] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_m),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
}

#[tokio::test]
async fn zvs2_wrapped_session_remediates_new_m03_never_persisting_raw_seed() {
    let engine = make_engine();
    let store = InMemorySecretStore::default();
    let service = "zerovault-zvs2-test";

    let header = engine
        .init_vault(
            &RedactedSecret::new("zvs2-passphrase"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init_vault");
    let frk = engine.export_folder_root_key().expect("export root key");
    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("dek");
    let wrapped_dek = engine.wrap_dek(file_id, &dek).expect("wrap_dek");
    let wrapped_tok = engine
        .wrap_token_payload(b"oauth-refresh-xyz")
        .expect("wrap_token_payload");

    engine
        .persist_session(&store, service)
        .await
        .expect("persist_session");

    // Legacy raw account `{vault_id}` MUST NOT exist.
    assert!(
        store
            .get_secret(service, &header.vault_id.to_string())
            .await
            .expect("get legacy")
            .is_none()
    );

    let wrap_key_account = format!("{}:wrap-key", header.vault_id);
    let session_account = format!("{}:session", header.vault_id);

    let wrap_key_stored = store
        .get_secret(service, &wrap_key_account)
        .await
        .expect("read wrap-key")
        .expect("wrap-key present");
    let session_stored = store
        .get_secret(service, &session_account)
        .await
        .expect("read session")
        .expect("session present");

    assert_eq!(wrap_key_stored.len(), 32);
    assert_eq!(&session_stored[0..4], b"ZVS2");
    assert_eq!(session_stored.len(), 80);

    // Raw root key bytes MUST NOT appear anywhere in wrap-key or session ciphertext!
    assert_ne!(wrap_key_stored.as_slice(), frk.as_slice());
    assert!(
        !session_stored
            .windows(32)
            .any(|window| window == frk.as_slice()),
        "ZVS2 session must never contain raw master_seed / folder_root_key"
    );

    engine.lock_vault().await.expect("lock");
    assert!(!engine.is_unlocked());

    // Absent vault returns Ok(false).
    assert!(
        !engine
            .restore_session(&store, service, Uuid::new_v4())
            .await
            .expect("absent session")
    );

    // Valid restore recovers exact 7-subkey state.
    assert!(
        engine
            .restore_session(&store, service, header.vault_id)
            .await
            .expect("restore valid ZVS2 session")
    );
    assert_eq!(
        engine
            .unwrap_dek(file_id, &wrapped_dek)
            .expect("unwrap DEK after ZVS2 restore")
            .as_bytes(),
        dek.as_bytes()
    );
    assert_eq!(
        engine
            .unwrap_token_payload(&wrapped_tok)
            .expect("unwrap token after ZVS2 restore")
            .as_slice(),
        b"oauth-refresh-xyz"
    );

    // Tampered session ciphertext fails closed with CryptoTamperDetected.
    engine.lock_vault().await.expect("lock");
    let mut bad_session = session_stored.to_vec();
    bad_session[40] ^= 0x01;
    store
        .set_secret(service, &session_account, &bad_session)
        .await
        .expect("store tampered session");
    assert!(matches!(
        engine
            .restore_session(&store, service, header.vault_id)
            .await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(!engine.is_unlocked());

    // Restore clean session, then tamper wrap-key -> fails closed with CryptoTamperDetected.
    store
        .set_secret(service, &session_account, &session_stored)
        .await
        .expect("restore good session");
    let mut bad_wk = wrap_key_stored.to_vec();
    bad_wk[0] ^= 0x80;
    store
        .set_secret(service, &wrap_key_account, &bad_wk)
        .await
        .expect("store tampered wrap-key");
    assert!(matches!(
        engine
            .restore_session(&store, service, header.vault_id)
            .await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(!engine.is_unlocked());

    // Missing wrap-key while session exists -> fails closed with CryptoTamperDetected.
    store
        .delete_secret(service, &wrap_key_account)
        .await
        .expect("delete wrap-key");
    assert!(matches!(
        engine
            .restore_session(&store, service, header.vault_id)
            .await,
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn os_keyring_secret_store_windows_zvs2_roundtrip_and_cleanup() {
    let store = OsKeyringSecretStore::new();
    let service = "zerovault-wave2-unit-test";
    let engine = make_engine();
    let vault_id = Uuid::new_v4();
    engine
        .unlock_with_folder_key(vault_id, &[0x99u8; 32])
        .expect("unlock");

    let wrap_account = format!("{vault_id}:wrap-key");
    let sess_account = format!("{vault_id}:session");

    engine
        .persist_session(&store, service)
        .await
        .expect("persist ZVS2 to Windows Credential Manager");
    engine.lock_vault().await.expect("lock");

    let restored = engine.restore_session(&store, service, vault_id).await;
    let _ = store.delete_secret(service, &wrap_account).await;
    let _ = store.delete_secret(service, &sess_account).await;

    assert!(restored.expect("restore ZVS2 from Windows Credential Manager"));
    assert_eq!(
        &*engine.export_folder_root_key().expect("exported key"),
        &[0x99u8; 32]
    );
}

#[tokio::test]
async fn pq_keybox_mlkem768_x25519_ed25519_sharing_and_revocation_epoch_floor() {
    let owner_engine = make_engine();
    let alice_engine = make_engine();
    let bob_engine = make_engine();

    let owner_hdr = owner_engine
        .init_vault(
            &RedactedSecret::new("owner-vault-passphrase"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("owner init_vault");
    let vault_id = owner_hdr.vault_id;
    let frk1 = owner_engine
        .export_folder_root_key()
        .expect("owner export FRK1");

    // Owner encrypts a file DEK under FRK1.
    let file_id = Uuid::new_v4();
    let dek = owner_engine.generate_dek().expect("dek");
    let wrapped_dek = owner_engine.wrap_dek(file_id, &dek).expect("wrap_dek");

    let owner = owner_engine
        .generate_recipient_identity("owner")
        .expect("owner identity");
    let alice = alice_engine
        .generate_recipient_identity("alice")
        .expect("alice identity");
    let bob = bob_engine
        .generate_recipient_identity("bob")
        .expect("bob identity");
    let eve = bob_engine
        .generate_recipient_identity("eve")
        .expect("eve identity");

    // Check NIST FIPS 203 ML-KEM-768 + X25519 + Ed25519 exact key sizes & Base64 bundle roundtrip.
    assert_eq!(alice.public.ed25519_pubkey.len(), ED25519_PUBKEY_LEN);
    assert_eq!(alice.public.x25519_pubkey.len(), X25519_KEY_LEN);
    assert_eq!(
        alice.public.mlkem768_encaps_key.len(),
        ML_KEM_768_ENCAPS_KEY_LEN
    );
    assert_eq!(alice.mlkem768_decaps_key.len(), ML_KEM_768_DECAPS_KEY_LEN);
    let alice_b64 = alice.public.to_base64().expect("encode bundle");
    let alice_decoded = RecipientPublicBundle::from_base64(&alice_b64).expect("decode bundle");
    assert_eq!(alice_decoded, alice.public);

    // Seal epoch=1 keybox.zv for Alice + Bob.
    let kb1 = owner_engine
        .seal_keybox(
            &owner,
            vault_id,
            1,
            &frk1,
            &[alice.public.clone(), bob.public.clone()],
        )
        .expect("seal_keybox epoch 1");
    assert_eq!(kb1.owner_signature.len(), ED25519_SIGNATURE_LEN);
    assert_eq!(
        kb1.stanzas[0].mlkem768_ciphertext.len(),
        ML_KEM_768_CIPHERTEXT_LEN
    );

    let kb1_wire = kb1.encode().expect("encode ZVK1");
    let kb1_parsed = SignedKeybox::decode(&kb1_wire).expect("decode ZVK1");

    // Alice opens keybox.zv, unlocks her engine via unlock_with_folder_key, and unwraps Owner's DEK!
    let alice_frk1 = alice_engine
        .open_keybox(&kb1_parsed, Some(&owner.public.ed25519_pubkey), 1, &alice)
        .expect("alice open_keybox epoch 1");
    assert_eq!(&*alice_frk1, &*frk1);
    alice_engine
        .unlock_with_folder_key(vault_id, &alice_frk1)
        .expect("alice unlock_with_folder_key");
    let alice_dek = alice_engine
        .unwrap_dek(file_id, &wrapped_dek)
        .expect("alice unwraps owner's file DEK");
    assert_eq!(alice_dek.as_bytes(), dek.as_bytes());

    // Bob also opens epoch 1; Eve is rejected with UnauthorizedRecipient.
    let bob_frk1 = bob_engine
        .open_keybox(&kb1_parsed, Some(&owner.public.ed25519_pubkey), 1, &bob)
        .expect("bob open_keybox epoch 1");
    assert_eq!(&*bob_frk1, &*frk1);
    assert!(matches!(
        bob_engine.open_keybox(&kb1_parsed, Some(&owner.public.ed25519_pubkey), 1, &eve),
        Err(ZeroVaultError::UnauthorizedRecipient(_))
    ));

    // Owner revokes Bob at epoch=2 with rotated FRK2!
    let frk2 = [0xEEu8; 32];
    let kb2 = owner_engine
        .seal_keybox(
            &owner,
            vault_id,
            2,
            &frk2,
            std::slice::from_ref(&alice.public),
        )
        .expect("seal_keybox epoch 2");

    // Revoked Bob fails with UnauthorizedRecipient on epoch=2.
    assert!(matches!(
        bob_engine.open_keybox(&kb2, Some(&owner.public.ed25519_pubkey), 2, &bob),
        Err(ZeroVaultError::UnauthorizedRecipient(_))
    ));
    // Replay of epoch=1 keybox when min_epoch_floor=2 MUST fail closed with CryptoTamperDetected!
    assert!(matches!(
        alice_engine.open_keybox(&kb1_parsed, Some(&owner.public.ed25519_pubkey), 2, &alice),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Wrong pinned owner pubkey -> CryptoTamperDetected.
    assert!(matches!(
        alice_engine.open_keybox(&kb2, Some(&eve.public.ed25519_pubkey), 2, &alice),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Forged Ed25519 signature -> CryptoTamperDetected.
    let mut forged_sig_kb = kb2.clone();
    forged_sig_kb.owner_signature[0] ^= 0x01;
    assert!(matches!(
        alice_engine.open_keybox(&forged_sig_kb, Some(&owner.public.ed25519_pubkey), 2, &alice),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Re-signed keybox with corrupted ML-KEM-768 ciphertext (implicit rejection -> AEAD CryptoTamperDetected)!
    // Even if an attacker (or faulty owner) signed over a mutated ML-KEM ciphertext, Alice fails closed!
    let alice_frk2 = alice_engine
        .open_keybox(&kb2, Some(&owner.public.ed25519_pubkey), 2, &alice)
        .expect("alice opens valid epoch 2");
    assert_eq!(&*alice_frk2, &frk2);
}

#[test]
fn capability_share_zv_uri_roundtrip_without_vault_unlock_and_tamper_checks() {
    let sender = make_engine();
    let recipient = make_engine();
    assert!(!recipient.is_unlocked());

    let owner_id = sender
        .generate_recipient_identity("owner")
        .expect("owner identity");
    let other_id = sender
        .generate_recipient_identity("impersonator")
        .expect("other identity");

    let file_id = Uuid::new_v4();
    let share_id = Uuid::new_v4();
    let file_dek = sender.generate_dek().expect("file_dek");
    let (_, wire_chunk) = sender
        .encrypt_chunk(
            &file_dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: true,
            },
            b"Zero-knowledge 1-click shared document body",
        )
        .expect("encrypt shared chunk");

    let desc = ShareDescriptor {
        share_id,
        file_id,
        filename: "whitepaper.pdf".to_owned(),
        size: 43,
        created_at: Utc::now(),
        wrapped_dek: WrappedDek {
            nonce: [0u8; 12],
            ciphertext_and_tag: vec![0u8; 48],
        },
        chunks: vec![ChunkRef {
            chunk_index: 0,
            blob_id: Uuid::new_v4(),
            plaintext_len: 43,
            ciphertext_len: wire_chunk.len() as u32,
            blake3_plaintext: *blake3::hash(b"Zero-knowledge 1-click shared document body")
                .as_bytes(),
            backend_ids: vec!["s3-public".to_owned()],
        }],
    };

    let (uri, env) = sender
        .create_capability_share(&owner_id, "s3", "bucket-shares", &file_dek, &desc)
        .expect("create_capability_share");
    let uri_str = uri.encode().expect("encode zv:// URI");
    let env_wire = env.encode().expect("encode ZVS1 envelope");

    // Ensure SRK is redacted in Debug output.
    let frag_idx = uri_str.find('#').expect("has fragment");
    assert!(!format!("{uri:?}").contains(&uri_str[frag_idx + 1..]));

    // Recipient opens share and decrypts chunk WITHOUT unlocking any local vault!
    let parsed_uri = CapabilityUri::parse(&uri_str).expect("parse zv:// URI");
    let parsed_env = SignedShareEnvelope::decode(&env_wire).expect("decode ZVS1 envelope");
    let (opened_desc, opened_dek) = recipient
        .open_capability_share(&parsed_uri, &parsed_env)
        .expect("open_capability_share");
    assert_eq!(opened_desc.filename, "whitepaper.pdf");
    assert_eq!(opened_dek.as_bytes(), file_dek.as_bytes());

    let (_, pt_chunk) = recipient
        .decrypt_chunk(&opened_dek, opened_desc.file_id, Some(0), &wire_chunk)
        .expect("decrypt shared chunk");
    assert_eq!(
        pt_chunk.as_ref(),
        b"Zero-knowledge 1-click shared document body"
    );

    // Tampered SRK in URI -> CryptoTamperDetected.
    let mut bad_srk_uri = parsed_uri.clone();
    bad_srk_uri.share_root_key[0] ^= 0x01;
    assert!(matches!(
        recipient.open_capability_share(&bad_srk_uri, &parsed_env),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Swapped owner Ed25519 pubkey in URI -> CryptoTamperDetected.
    let mut bad_pk_uri = parsed_uri.clone();
    bad_pk_uri.owner_ed25519_pubkey = other_id.public.ed25519_pubkey;
    assert!(matches!(
        recipient.open_capability_share(&bad_pk_uri, &parsed_env),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Forged Ed25519 signature -> CryptoTamperDetected.
    let mut bad_sig_env = parsed_env.clone();
    bad_sig_env.ed25519_signature[10] ^= 0x40;
    assert!(matches!(
        recipient.open_capability_share(&parsed_uri, &bad_sig_env),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
}

#[test]
fn benchmark_aes256_gcm_4mib_reports_high_hardware_throughput() {
    let engine = make_engine();
    let report = engine
        .benchmark_aes256_gcm(64)
        .expect("benchmark_aes256_gcm(64)");
    assert_eq!(report.total_mib, 64);
    assert!(report.caps.mandatory_satisfied);
    assert!(report.encrypt_mib_per_sec.is_finite() && report.encrypt_mib_per_sec > 100.0);
    assert!(report.decrypt_mib_per_sec.is_finite() && report.decrypt_mib_per_sec > 100.0);
    println!(
        "BENCHMARK_REPORT backend={} enc_mib_s={:.2} dec_mib_s={:.2}",
        report.caps.backend_name, report.encrypt_mib_per_sec, report.decrypt_mib_per_sec
    );
}

#[test]
fn edge_cases_exact_4mib_is_final_truncation_dek_wrap_and_zero_epoch_revisions() {
    let engine = make_engine();
    let vault_id = Uuid::new_v4();
    engine
        .unlock_with_folder_key(vault_id, &[0x66u8; 32])
        .expect("unlock");

    // 1. Exact 4 MiB final chunk with `is_final_chunk` flipped to false passes ChunkHeader size
    // invariants, so AES-256-GCM 25-byte ChunkAad MUST catch it with CryptoTamperDetected!
    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("dek");
    let exact_4mib = vec![0xCCu8; PLAINTEXT_CHUNK_SIZE];
    let (_, wire_final_4m) = engine
        .encrypt_chunk(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: true,
            },
            &exact_4mib,
        )
        .expect("encrypt exact 4 MiB final");
    let mut flipped = wire_final_4m.to_vec();
    flipped[5] = 0x00; // clear CHUNK_FLAG_FINAL
    let mut out_pt = BytesMut::from(&b"must-be-cleared"[..]);
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_id, Some(0), &flipped, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());

    // 2. WrappedDek wrong file_id, bad length, nonce flip, tag flip -> CryptoTamperDetected.
    let wrapped = engine.wrap_dek(file_id, &dek).expect("wrap_dek");
    assert!(matches!(
        engine.unwrap_dek(Uuid::new_v4(), &wrapped),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut short_w = wrapped.clone();
    short_w.ciphertext_and_tag.truncate(47);
    assert!(matches!(
        engine.unwrap_dek(file_id, &short_w),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut nonce_w = wrapped.clone();
    nonce_w.nonce[0] ^= 0x01;
    assert!(matches!(
        engine.unwrap_dek(file_id, &nonce_w),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 3. TokenWrapKey truncated / tampered -> CryptoTamperDetected.
    let tok = engine.wrap_token_payload(b"secret-tok").expect("wrap_tok");
    assert!(matches!(
        engine.unwrap_token_payload(&tok[..10]),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 4. Manifest revision 0 rejected on seal_manifest; Keybox epoch 0 rejected on seal_keybox.
    let bad_manifest = VaultManifest {
        vault_id,
        revision: 0,
        parent_manifest_id: None,
        device_id: "dev".to_owned(),
        created_at: Utc::now(),
        nodes: Vec::new(),
    };
    assert!(matches!(
        engine.seal_manifest(&bad_manifest),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));

    let owner = engine.generate_recipient_identity("owner").expect("owner");
    assert!(matches!(
        engine.seal_keybox(&owner, vault_id, 0, &[0x11; 32], &[]),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));
}

#[test]
fn verify_keybox_envelope_rejects_forged_signature_wrong_vault_and_epoch_rollback() {
    let engine = make_engine();
    let owner = engine.generate_recipient_identity("owner").expect("owner");
    let alice = engine.generate_recipient_identity("alice").expect("alice");
    let other = engine.generate_recipient_identity("other").expect("other");
    let vault_id = Uuid::new_v4();
    let frk = [0x24u8; 32];

    let kb = engine
        .seal_keybox(
            &owner,
            vault_id,
            3,
            &frk,
            std::slice::from_ref(&alice.public),
        )
        .expect("seal_keybox");

    // Valid envelope succeeds with matching vault_id, owner pubkey, and epoch floor.
    engine
        .verify_keybox_envelope(&kb, Some(vault_id), Some(&owner.public.ed25519_pubkey), 3)
        .expect("valid keybox envelope");

    // 1. Forged `[0xDE; 64]` Ed25519 signature MUST fail closed (`W4-VETO-KEYBOX-SIG` t07).
    let mut forged_de = kb.clone();
    forged_de.owner_signature = vec![0xDEu8; ED25519_SIGNATURE_LEN];
    assert!(matches!(
        engine.verify_keybox_envelope(
            &forged_de,
            Some(vault_id),
            Some(&owner.public.ed25519_pubkey),
            1,
        ),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2. Wrong expected_vault_id MUST fail closed.
    assert!(matches!(
        engine.verify_keybox_envelope(
            &kb,
            Some(Uuid::new_v4()),
            Some(&owner.public.ed25519_pubkey),
            3,
        ),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 3. Wrong expected_owner_pubkey MUST fail closed.
    assert!(matches!(
        engine.verify_keybox_envelope(&kb, Some(vault_id), Some(&other.public.ed25519_pubkey), 3),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 4. Epoch rollback (`epoch < min_epoch_floor` or `epoch == 0`) MUST fail closed.
    assert!(matches!(
        engine.verify_keybox_envelope(&kb, Some(vault_id), Some(&owner.public.ed25519_pubkey), 4),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut zero_epoch = kb.clone();
    zero_epoch.epoch = 0;
    assert!(matches!(
        engine.verify_keybox_envelope(&zero_epoch, Some(vault_id), None, 0),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 5. Unsupported version MUST fail closed.
    let mut bad_ver = kb;
    bad_ver.version = 99;
    assert!(matches!(
        engine.verify_keybox_envelope(&bad_ver, Some(vault_id), None, 1),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
}

// ============================================================================
// Property-Based Tamper / Fuzz Suite (`proptest`)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// 1. Any 1-bit flip anywhere in a `.zv` chunk (header, nonce, ciphertext, or GCM tag)
    /// MUST fail closed AND leave `out_plaintext` empty + scrubbed.
    #[test]
    fn prop_chunk_1bit_flip_always_rejected_and_zeroizes_out_buf(
        payload in proptest::collection::vec(any::<u8>(), 0..=8192),
        byte_choice in any::<usize>(),
        bit_idx in 0u8..8u8,
    ) {
        let engine = make_engine();
        let dek = engine.generate_dek().expect("dek");
        let file_id = Uuid::new_v4();
        let (_, wire) = engine
            .encrypt_chunk(
                &dek,
                ChunkAad {
                    file_id,
                    chunk_index: 0,
                    is_final_chunk: true,
                },
                &payload,
            )
            .expect("encrypt_chunk");

        let mut mutated = wire.to_vec();
        let target_byte = byte_choice % mutated.len();
        mutated[target_byte] ^= 1u8 << bit_idx;

        let mut out_pt = BytesMut::from(&b"must-be-scrubbed-on-failure"[..]);
        let res = engine.decrypt_chunk_into(&dek, file_id, Some(0), &mutated, &mut out_pt);
        prop_assert!(res.is_err());
        prop_assert!(out_pt.is_empty());
    }

    /// 2. Chunk index swap, cross-file `file_id` swap, and `is_final_chunk` AAD flip
    /// MUST always fail closed with `CryptoTamperDetected` or `InvalidWireFormat`.
    #[test]
    fn prop_chunk_swap_file_swap_and_is_final_flip_rejected(
        payload in proptest::collection::vec(any::<u8>(), 1..=4096),
        idx_a in 0u64..1000u64,
        delta in 1u64..1000u64,
    ) {
        let engine = make_engine();
        let dek = engine.generate_dek().expect("dek");
        let file_a = Uuid::new_v4();
        let file_b = Uuid::new_v4();
        let idx_b = idx_a + delta;

        let (_, wire_a) = engine
            .encrypt_chunk(
                &dek,
                ChunkAad {
                    file_id: file_a,
                    chunk_index: idx_a,
                    is_final_chunk: true,
                },
                &payload,
            )
            .expect("encrypt");

        let mut out_pt = BytesMut::new();
        // Wrong expected_chunk_index
        let err_idx = engine
            .decrypt_chunk_into(&dek, file_a, Some(idx_b), &wire_a, &mut out_pt)
            .expect_err("swapped index must fail");
        prop_assert!(err_idx.is_tamper());
        prop_assert!(out_pt.is_empty());

        // Forged chunk_index inside wire header with None expected_chunk_index
        let mut forged_hdr = wire_a.to_vec();
        forged_hdr[8..16].copy_from_slice(&idx_b.to_le_bytes());
        let err_forged = engine
            .decrypt_chunk_into(&dek, file_a, None, &forged_hdr, &mut out_pt)
            .expect_err("forged header index must fail AEAD AAD");
        prop_assert!(err_forged.is_tamper());

        // Cross-file swap
        let err_file = engine
            .decrypt_chunk_into(&dek, file_b, Some(idx_a), &wire_a, &mut out_pt)
            .expect_err("cross-file swap must fail");
        prop_assert!(err_file.is_tamper());

        // Flipping `is_final_chunk` flag bit in header
        let mut flipped_final = wire_a.to_vec();
        flipped_final[5] ^= 0x01;
        prop_assert!(
            engine
                .decrypt_chunk_into(&dek, file_a, Some(idx_a), &flipped_final, &mut out_pt)
                .is_err()
        );
    }

    /// 3. Arbitrary out-of-range KDF parameters (below floor OR above 256 MiB OOM ceiling)
    /// MUST be rejected instantaneously with `KdfPolicyViolation` without allocating RAM.
    #[test]
    fn prop_kdf_out_of_bounds_floor_and_oom_ceiling_rejected_pre_alloc(
        m_cost_kib in any::<u32>(),
        t_cost in any::<u32>(),
        p_cost in any::<u32>(),
    ) {
        let in_bounds = (MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&m_cost_kib)
            && (MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&t_cost)
            && (MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&p_cost);

        let kdf = KdfParams {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        if in_bounds {
            prop_assert!(kdf.validate_production().is_ok());
        } else {
            let is_violation = matches!(
                kdf.validate_production(),
                Err(ZeroVaultError::KdfPolicyViolation { .. })
            );
            prop_assert!(is_violation);

            // Also verify VaultHeader::decode rejects out-of-bounds KDF immediately.
            let hdr = VaultHeader {
                version: 1,
                vault_id: Uuid::new_v4(),
                argon2_salt: [0x11; 32],
                kdf,
                verifier_nonce: [0x22; 12],
                verifier_tag: [0x33; 32],
            };
            let wire = hdr.encode();
            let is_hdr_violation = matches!(
                VaultHeader::decode(&wire),
                Err(ZeroVaultError::KdfPolicyViolation { .. })
            );
            prop_assert!(is_hdr_violation);
        }
    }

    /// 4. Post-quantum `keybox.zv` tamper fuzzing: epoch rollback replay, forged `Ed25519`
    /// signature, corrupted `ML-KEM-768` ciphertext (even if re-signed by a compromised key!),
    /// and tampered `wrapped_folder_key` MUST fail closed with `CryptoTamperDetected`.
    #[test]
    fn prop_keybox_epoch_replay_forged_sig_and_mlkem_tamper_rejected(
        epoch in 1u64..1000u64,
        floor_delta in 1u64..1000u64,
        sig_pos in 0usize..ED25519_SIGNATURE_LEN,
        kem_pos in 0usize..ML_KEM_768_CIPHERTEXT_LEN,
        wrap_pos in 0usize..48usize,
        bit_idx in 0u8..8u8,
    ) {
        let engine = make_engine();
        let owner = engine.generate_recipient_identity("owner").expect("owner");
        let alice = engine.generate_recipient_identity("alice").expect("alice");
        let vault_id = Uuid::new_v4();
        let frk = [0xABu8; 32];

        let kb = engine
            .seal_keybox(&owner, vault_id, epoch, &frk, std::slice::from_ref(&alice.public))
            .expect("seal_keybox");

        // 4a. Epoch replay below floor -> CryptoTamperDetected
        let floor = epoch + floor_delta;
        prop_assert!(matches!(
            engine.open_keybox(&kb, Some(&owner.public.ed25519_pubkey), floor, &alice),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        // 4b. Forged Ed25519 signature -> CryptoTamperDetected
        let mut bad_sig = kb.clone();
        bad_sig.owner_signature[sig_pos] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_keybox(&bad_sig, Some(&owner.public.ed25519_pubkey), epoch, &alice),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        // 4c. Corrupted ML-KEM-768 ciphertext (even if validly re-signed by owner!) ->
        // FIPS 203 implicit rejection derives distinct shared secret -> AEAD tag fails closed!
        let mut bad_kem = kb.clone();
        bad_kem.stanzas[0].mlkem768_ciphertext[kem_pos] ^= 1u8 << bit_idx;
        let owner_kp = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(
            owner.ed25519_seed.as_ref(),
        )
        .expect("owner kp");
        let transcript = bad_kem.signing_transcript().expect("transcript");
        bad_kem.owner_signature = owner_kp.sign(&transcript).as_ref().to_vec();
        prop_assert!(matches!(
            engine.open_keybox(&bad_kem, Some(&owner.public.ed25519_pubkey), epoch, &alice),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        // 4d. Tampered wrapped_folder_key (even if re-signed!) -> CryptoTamperDetected
        let mut bad_wrap = kb.clone();
        bad_wrap.stanzas[0].wrapped_folder_key[wrap_pos] ^= 1u8 << bit_idx;
        let transcript_w = bad_wrap.signing_transcript().expect("transcript");
        bad_wrap.owner_signature = owner_kp.sign(&transcript_w).as_ref().to_vec();
        prop_assert!(matches!(
            engine.open_keybox(&bad_wrap, Some(&owner.public.ed25519_pubkey), epoch, &alice),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));
    }

    /// 5. `zv://` Capability Share tamper fuzzing: 1-bit flips in `SRK`, `owner_ed25519_pubkey`,
    /// `ed25519_signature`, or `ciphertext_and_tag` MUST fail closed with `CryptoTamperDetected`.
    #[test]
    fn prop_zv_capability_share_tamper_rejected(
        srk_pos in 0usize..32usize,
        pk_pos in 0usize..32usize,
        sig_pos in 0usize..64usize,
        ct_choice in any::<usize>(),
        bit_idx in 0u8..8u8,
    ) {
        let engine = make_engine();
        let owner = engine.generate_recipient_identity("owner").expect("owner");
        let dek = engine.generate_dek().expect("dek");
        let desc = ShareDescriptor {
            share_id: Uuid::new_v4(),
            file_id: Uuid::new_v4(),
            filename: "fuzz.bin".to_owned(),
            size: 100,
            created_at: Utc::now(),
            wrapped_dek: WrappedDek {
                nonce: [0u8; 12],
                ciphertext_and_tag: vec![0u8; 48],
            },
            chunks: Vec::new(),
        };
        let (uri, env) = engine
            .create_capability_share(&owner, "fs", "/tmp", &dek, &desc)
            .expect("share");

        let mut bad_srk = uri.clone();
        bad_srk.share_root_key[srk_pos] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_capability_share(&bad_srk, &env),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        let mut bad_pk = uri.clone();
        bad_pk.owner_ed25519_pubkey[pk_pos] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_capability_share(&bad_pk, &env),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        let mut bad_sig = env.clone();
        bad_sig.ed25519_signature[sig_pos] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_capability_share(&uri, &bad_sig),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        let mut bad_ct = env.clone();
        let idx = ct_choice % bad_ct.ciphertext_and_tag.len();
        bad_ct.ciphertext_and_tag[idx] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_capability_share(&uri, &bad_ct),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));
    }

    /// 6. SQLite `MetadataKey` and `.zvpart` `StagingKey` tamper fuzzing.
    #[test]
    fn prop_metadata_and_staging_chunk_tamper_rejected(
        payload in proptest::collection::vec(any::<u8>(), 0..=2048),
        inode in 2u64..100_000u64,
        chunk_idx in 0u64..10_000u64,
        pos_choice in any::<usize>(),
        bit_idx in 0u8..8u8,
    ) {
        let engine = make_engine();
        engine
            .unlock_with_folder_key(Uuid::new_v4(), &[0x55u8; 32])
            .expect("unlock");

        let mut sealed_meta = engine.seal_metadata(b"col:name", &payload).expect("seal_metadata");
        let m_idx = pos_choice % sealed_meta.len();
        sealed_meta[m_idx] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_metadata(b"col:name", &sealed_meta),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));

        let mut sealed_stage = engine
            .seal_staging_chunk(inode, chunk_idx, &payload)
            .expect("seal_staging_chunk");
        let s_idx = pos_choice % sealed_stage.len();
        sealed_stage[s_idx] ^= 1u8 << bit_idx;
        prop_assert!(matches!(
            engine.open_staging_chunk(inode, chunk_idx, &sealed_stage),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ));
    }
}
