use bytes::BytesMut;
use chrono::Utc;
use uuid::Uuid;
use zeroize::Zeroize;
use zerovault_types::mocks::InMemorySecretStore;
use zerovault_types::{
    AES_GCM_TAG_LEN, CHUNK_HEADER_LEN, ChunkAad, ChunkHeader, ChunkRef, CryptoEngine, DekBytes,
    EntryKind, KdfParams, MANIFEST_HEADER_LEN, ManifestNode, PLAINTEXT_CHUNK_SIZE,
    RedactedSecret, SecretStore, VaultHeader, VaultManifest, ZeroVaultError,
};

use crate::{
    AwsLcCryptoEngine, CRYPTO_BACKEND_NAME, HeaderVerifierKey, KeyRingState, ManifestKey,
    MasterKek, MasterSeed, OsKeyringSecretStore, TokenWrapKey, verify_hardware_acceleration,
};

fn make_engine() -> AwsLcCryptoEngine {
    AwsLcCryptoEngine::new().expect("host CPU must provide hardware AES + GHASH")
}

#[test]
fn hardware_acceleration_detected_and_reported() {
    let caps = verify_hardware_acceleration().expect("host supports AES + PCLMULQDQ/PMULL");
    assert!(caps.mandatory_satisfied);
    assert!(caps.aes_hw);
    assert!(caps.pclmul_hw);
    assert_eq!(caps.backend_name, CRYPTO_BACKEND_NAME);
    assert_eq!(caps.backend_name, "aws-lc-rs-aes-256-gcm");

    let engine = make_engine();
    let engine_caps = engine
        .verify_hardware_acceleration()
        .expect("engine hardware verification");
    assert_eq!(engine_caps, caps);
}

#[test]
fn key_wrappers_redact_debug_and_zeroize() {
    let raw = [0xA7u8; 32];
    let mut seed = MasterSeed::from_array(raw);
    let kek = MasterKek::from_array([0xB8u8; 32]);
    let manifest_key = ManifestKey::from_array([0xC9u8; 32]);
    let token_key = TokenWrapKey::from_array([0xDAu8; 32]);
    let verifier_key = HeaderVerifierKey::from_array([0xEBu8; 32]);

    assert_eq!(format!("{seed:?}"), "MasterSeed([REDACTED])");
    assert_eq!(format!("{kek:?}"), "MasterKek([REDACTED])");
    assert_eq!(format!("{manifest_key:?}"), "ManifestKey([REDACTED])");
    assert_eq!(format!("{token_key:?}"), "TokenWrapKey([REDACTED])");
    assert_eq!(
        format!("{verifier_key:?}"),
        "HeaderVerifierKey([REDACTED])"
    );

    seed.zeroize();
    assert_eq!(seed.as_bytes(), &[0u8; 32]);

    let engine = make_engine();
    let dbg = format!("{engine:?}");
    assert!(dbg.contains("AwsLcCryptoEngine"));
    assert!(!dbg.contains("a7"));

    let mut ring = KeyRingState::from_master_seed(
        Uuid::from_bytes([0xAB; 16]),
        [0x55u8; 32],
        MasterSeed::from_array([0x44u8; 32]),
    )
    .expect("construct keyring");
    let ring_dbg = format!("{ring:?}");
    assert!(ring_dbg.contains("[REDACTED]"));
    assert!(!ring_dbg.contains("85"));
    assert!(!ring_dbg.contains("68"));
    assert!(!ring_dbg.contains("55"));
    assert!(!ring_dbg.contains("44"));
    ring.zeroize();
}

#[tokio::test]
async fn init_lock_unlock_lifecycle_and_kdf_policy() {
    let engine = make_engine();
    assert!(!engine.is_unlocked());
    assert!(engine.vault_id().is_none());

    // Weak KDF parameters MUST be rejected before derivation.
    for weak_kdf in [
        KdfParams {
            m_cost_kib: 65_535,
            t_cost: 3,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: 65_536,
            t_cost: 2,
            p_cost: 4,
        },
        KdfParams {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 3,
        },
    ] {
        let err = engine
            .init_vault(&RedactedSecret::new("correct horse battery staple"), weak_kdf)
            .await
            .expect_err("weak KDF must fail closed");
        assert!(matches!(err, ZeroVaultError::KdfPolicyViolation { .. }));
    }

    let passphrase = RedactedSecret::new("correct horse battery staple");
    let header = engine
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init_vault");
    assert!(engine.is_unlocked());
    assert_eq!(engine.vault_id(), Some(header.vault_id));

    // Wire roundtrip of ZVH1 header.
    let encoded_header = header.encode();
    let decoded_header = VaultHeader::decode(&encoded_header).expect("decode ZVH1 header");
    assert_eq!(decoded_header, header);

    // Wrap a DEK while unlocked so we verify same keys are restored after unlock.
    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");
    let wrapped_dek = engine.wrap_dek(file_id, &dek).expect("wrap DEK");

    // Lock vault and ensure all secret operations fail with VaultLocked.
    engine.lock_vault().await.expect("lock vault");
    assert!(!engine.is_unlocked());
    assert!(engine.vault_id().is_none());
    assert!(matches!(
        engine.wrap_dek(file_id, &dek),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.unwrap_dek(file_id, &wrapped_dek),
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.wrap_token_payload(b"oauth-token"),
        Err(ZeroVaultError::VaultLocked)
    ));

    // Wrong passphrase fails closed with InvalidPassphrase and stays locked.
    let wrong_err = engine
        .unlock_with_passphrase(&decoded_header, &RedactedSecret::new("wrong passphrase"))
        .await
        .expect_err("wrong passphrase must fail");
    assert!(matches!(wrong_err, ZeroVaultError::InvalidPassphrase));
    assert!(!engine.is_unlocked());

    // Tampered header verifier tag fails with InvalidPassphrase.
    let mut tampered_header = decoded_header.clone();
    tampered_header.verifier_tag[31] ^= 0x01;
    let tamper_err = engine
        .unlock_with_passphrase(&tampered_header, &passphrase)
        .await
        .expect_err("tampered header verifier must fail");
    assert!(matches!(tamper_err, ZeroVaultError::InvalidPassphrase));
    assert!(!engine.is_unlocked());

    // Tampered header KDF policy below production floor fails with KdfPolicyViolation.
    let mut weak_header = decoded_header.clone();
    weak_header.kdf.m_cost_kib = 32_768;
    let weak_unlock = engine
        .unlock_with_passphrase(&weak_header, &passphrase)
        .await
        .expect_err("weak header KDF must fail");
    assert!(matches!(
        weak_unlock,
        ZeroVaultError::KdfPolicyViolation { .. }
    ));

    // Correct passphrase restores identical key hierarchy.
    engine
        .unlock_with_passphrase(&decoded_header, &passphrase)
        .await
        .expect("unlock with correct passphrase");
    assert!(engine.is_unlocked());
    assert_eq!(engine.vault_id(), Some(header.vault_id));

    let unwrapped = engine
        .unwrap_dek(file_id, &wrapped_dek)
        .expect("unwrap DEK after unlock");
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
}

#[test]
fn multi_chunk_encrypt_decrypt_roundtrip_unique_nonces_and_buffer_reuse() {
    let engine = make_engine();
    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");

    let tail_len = 128 * 1024;
    let total_len = PLAINTEXT_CHUNK_SIZE + tail_len;
    let mut full_plaintext = Vec::with_capacity(total_len);
    for i in 0..total_len {
        full_plaintext.push((i.wrapping_mul(17) ^ (i >> 8)) as u8);
    }

    let chunk0_pt = &full_plaintext[..PLAINTEXT_CHUNK_SIZE];
    let chunk1_pt = &full_plaintext[PLAINTEXT_CHUNK_SIZE..];

    let mut reusable_wire = BytesMut::with_capacity(PLAINTEXT_CHUNK_SIZE + CHUNK_HEADER_LEN + AES_GCM_TAG_LEN);
    let wire_initial_ptr = reusable_wire.as_ptr();
    let wire_initial_cap = reusable_wire.capacity();

    let hdr0 = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: false,
            },
            chunk0_pt,
            &mut reusable_wire,
        )
        .expect("encrypt chunk 0");
    assert_eq!(reusable_wire.as_ptr(), wire_initial_ptr);
    assert_eq!(reusable_wire.capacity(), wire_initial_cap);
    assert_eq!(reusable_wire.len(), hdr0.expected_wire_len());
    let wire0 = reusable_wire.to_vec();

    // Encrypting chunk 0 again must yield a distinct CSPRNG nonce.
    let hdr0_again = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: false,
            },
            chunk0_pt,
            &mut reusable_wire,
        )
        .expect("re-encrypt chunk 0");
    assert_ne!(hdr0.nonce, hdr0_again.nonce);
    assert_eq!(reusable_wire.as_ptr(), wire_initial_ptr);

    let hdr1 = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 1,
                is_final_chunk: true,
            },
            chunk1_pt,
            &mut reusable_wire,
        )
        .expect("encrypt chunk 1 (final 128 KiB)");
    assert_ne!(hdr0.nonce, hdr1.nonce);
    assert_eq!(reusable_wire.as_ptr(), wire_initial_ptr);
    assert_eq!(reusable_wire.len(), hdr1.expected_wire_len());
    let wire1 = reusable_wire.to_vec();

    // Decrypt both chunks reusing a single 4 MiB plaintext BytesMut buffer.
    let mut reusable_pt = BytesMut::with_capacity(PLAINTEXT_CHUNK_SIZE);
    let pt_initial_ptr = reusable_pt.as_ptr();
    let pt_initial_cap = reusable_pt.capacity();

    let dhdr0 = engine
        .decrypt_chunk_into(&dek, file_id, Some(0), &wire0, &mut reusable_pt)
        .expect("decrypt chunk 0");
    assert_eq!(dhdr0, hdr0);
    assert_eq!(reusable_pt.as_ptr(), pt_initial_ptr);
    assert_eq!(reusable_pt.capacity(), pt_initial_cap);
    assert_eq!(reusable_pt.as_ref(), chunk0_pt);

    let dhdr1 = engine
        .decrypt_chunk_into(&dek, file_id, Some(1), &wire1, &mut reusable_pt)
        .expect("decrypt chunk 1");
    assert_eq!(dhdr1, hdr1);
    assert_eq!(reusable_pt.as_ptr(), pt_initial_ptr);
    assert_eq!(reusable_pt.capacity(), pt_initial_cap);
    assert_eq!(reusable_pt.as_ref(), chunk1_pt);

    // Empty 0-byte file at chunk_index 0 must also roundtrip cleanly.
    let empty_hdr = engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: true,
            },
            &[],
            &mut reusable_wire,
        )
        .expect("encrypt empty chunk 0");
    assert_eq!(empty_hdr.plaintext_len, 0);
    assert_eq!(reusable_wire.len(), CHUNK_HEADER_LEN + AES_GCM_TAG_LEN);
    engine
        .decrypt_chunk_into(&dek, file_id, Some(0), &reusable_wire, &mut reusable_pt)
        .expect("decrypt empty chunk 0");
    assert!(reusable_pt.is_empty());
}

#[tokio::test]
async fn tamper_resistance_rejects_all_mutations_fail_closed() {
    let engine = make_engine();
    let vault_hdr = engine
        .init_vault(
            &RedactedSecret::new("tamper-test-passphrase"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init_vault");

    let file_a = Uuid::new_v4();
    let file_b = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");

    // 1. Wrapped DEK tamper checks
    let wrapped = engine.wrap_dek(file_a, &dek).expect("wrap DEK");
    assert!(matches!(
        engine.unwrap_dek(file_b, &wrapped),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut bad_wrapped_ct = wrapped.clone();
    bad_wrapped_ct.ciphertext_and_tag[0] ^= 0x01;
    assert!(matches!(
        engine.unwrap_dek(file_a, &bad_wrapped_ct),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut bad_wrapped_tag = wrapped.clone();
    bad_wrapped_tag.ciphertext_and_tag[47] ^= 0x01;
    assert!(matches!(
        engine.unwrap_dek(file_a, &bad_wrapped_tag),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut bad_wrapped_nonce = wrapped.clone();
    bad_wrapped_nonce.nonce[0] ^= 0x01;
    assert!(matches!(
        engine.unwrap_dek(file_a, &bad_wrapped_nonce),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2. Chunk tamper checks
    let chunk0_pt = vec![0x5Au8; PLAINTEXT_CHUNK_SIZE];
    let chunk1_pt = vec![0x3Cu8; 128 * 1024];

    let mut wire0 = BytesMut::new();
    engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 0,
                is_final_chunk: false,
            },
            &chunk0_pt,
            &mut wire0,
        )
        .expect("encrypt chunk 0");

    let mut wire1 = BytesMut::new();
    engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 1,
                is_final_chunk: true,
            },
            &chunk1_pt,
            &mut wire1,
        )
        .expect("encrypt chunk 1");

    // Also test an exact 4 MiB final chunk to check AAD `is_final_chunk` flip with valid size.
    let mut wire_exact_final = BytesMut::new();
    engine
        .encrypt_chunk_into(
            &dek,
            ChunkAad {
                file_id: file_a,
                chunk_index: 0,
                is_final_chunk: true,
            },
            &chunk0_pt,
            &mut wire_exact_final,
        )
        .expect("encrypt exact 4 MiB final chunk");

    let mut out_pt = BytesMut::from(&b"stale-secret-bytes"[..]);

    // 2a. 1-bit flip in ciphertext -> CryptoTamperDetected and out_pt cleared.
    let mut flip_ct = wire1.clone();
    flip_ct[CHUNK_HEADER_LEN + 42] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_ct, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());

    // 2b. 1-bit flip in GCM tag -> CryptoTamperDetected and out_pt cleared.
    let mut flip_tag = wire1.clone();
    let last_idx = flip_tag.len() - 1;
    flip_tag[last_idx] ^= 0x80;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_tag, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(out_pt.is_empty());

    // 2c. 1-bit flip in header (magic, reserved, nonce, plaintext_len).
    let mut flip_magic = wire1.clone();
    flip_magic[0] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_magic, &mut out_pt),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));

    let mut flip_reserved = wire1.clone();
    flip_reserved[6] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_reserved, &mut out_pt),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));

    let mut flip_nonce = wire1.clone();
    flip_nonce[20] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_nonce, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    let mut flip_len = wire1.clone();
    flip_len[16] ^= 0x01;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_len, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2d. Chunk index reorder (0 <-> 1) both via expected_chunk_index and header mutation.
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &wire0, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(0), &wire1, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    let mut forged_idx = wire0.clone();
    forged_idx[8..16].copy_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, None, &forged_idx, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2e. Cross-file file_id swap -> CryptoTamperDetected.
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_b, Some(0), &wire0, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // 2f. Final-chunk truncation (is_final_chunk flipped to false).
    // Short final chunk (< 4 MiB) -> InvalidWireFormat by ChunkHeader size invariant.
    let mut flip_final_short = wire1.clone();
    flip_final_short[5] = 0x00;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(1), &flip_final_short, &mut out_pt),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));
    // Exact 4 MiB final chunk -> ChunkHeader size valid, AAD rejects with CryptoTamperDetected.
    let mut flip_final_exact = wire_exact_final.clone();
    flip_final_exact[5] = 0x00;
    assert!(matches!(
        engine.decrypt_chunk_into(&dek, file_a, Some(0), &flip_final_exact, &mut out_pt),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Verify unmodified wire_exact_final still decrypts cleanly.
    let hdr_ok = engine
        .decrypt_chunk_into(&dek, file_a, Some(0), &wire_exact_final, &mut out_pt)
        .expect("unmodified 4 MiB final chunk");
    assert!(hdr_ok.is_final_chunk);
    assert_eq!(out_pt.len(), PLAINTEXT_CHUNK_SIZE);

    // 3. Sealed manifest (ZVM1) roundtrip and tamper resistance.
    let now = Utc::now();
    let manifest = VaultManifest {
        vault_id: vault_hdr.vault_id,
        revision: 42,
        parent_manifest_id: Some(Uuid::new_v4()),
        device_id: "workstation-1".to_owned(),
        created_at: now,
        nodes: vec![ManifestNode {
            inode: 2,
            parent_inode: 1,
            file_id: file_a,
            name: "secret-report.pdf".to_owned(),
            kind: EntryKind::File,
            size: (PLAINTEXT_CHUNK_SIZE + 128 * 1024) as u64,
            mode: 0o644,
            modified_at: now,
            created_at: now,
            version: 1,
            wrapped_dek: Some(wrapped),
            chunks: vec![ChunkRef {
                chunk_index: 0,
                blob_id: Uuid::new_v4(),
                plaintext_len: PLAINTEXT_CHUNK_SIZE as u32,
                ciphertext_len: wire0.len() as u32,
                blake3_plaintext: [0x11; 32],
                backend_ids: vec!["s3-primary".to_owned()],
            }],
        }],
    };

    let sealed_manifest = engine.seal_manifest(&manifest).expect("seal manifest");
    let opened_manifest = engine
        .open_manifest(&sealed_manifest)
        .expect("open manifest");
    assert_eq!(opened_manifest, manifest);

    // Tamper manifest ciphertext, tag, revision AAD, vault_id AAD, and magic.
    let mut bad_manifest_ct = sealed_manifest.to_vec();
    bad_manifest_ct[MANIFEST_HEADER_LEN] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_manifest_ct),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    let mut bad_manifest_tag = sealed_manifest.to_vec();
    let m_last = bad_manifest_tag.len() - 1;
    bad_manifest_tag[m_last] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_manifest_tag),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    let mut bad_manifest_rev = sealed_manifest.to_vec();
    bad_manifest_rev[24] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_manifest_rev),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    let mut bad_manifest_vault = sealed_manifest.to_vec();
    bad_manifest_vault[8] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_manifest_vault),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    let mut bad_manifest_magic = sealed_manifest.to_vec();
    bad_manifest_magic[0] ^= 0x01;
    assert!(matches!(
        engine.open_manifest(&bad_manifest_magic),
        Err(ZeroVaultError::InvalidWireFormat(_))
    ));

    // 4. TokenWrapKey wrap/unwrap + tamper check.
    let token_pt = br#"{"access_token":"tok123","refresh_token":"ref456"}"#;
    let wrapped_token = engine
        .wrap_token_payload(token_pt)
        .expect("wrap token payload");
    let unwrapped_token = engine
        .unwrap_token_payload(&wrapped_token)
        .expect("unwrap token payload");
    assert_eq!(unwrapped_token.as_slice(), token_pt);

    let mut bad_token = wrapped_token.clone();
    let t_last = bad_token.len() - 1;
    bad_token[t_last] ^= 0x01;
    assert!(matches!(
        engine.unwrap_token_payload(&bad_token),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
}

#[tokio::test]
async fn persist_and_restore_session_in_memory_store() {
    let engine = make_engine();
    let store = InMemorySecretStore::default();
    let service = "zerovault-unit-test";

    let header = engine
        .init_vault(
            &RedactedSecret::new("session-passphrase-123"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init_vault");

    let file_id = Uuid::new_v4();
    let dek = engine.generate_dek().expect("generate DEK");
    let wrapped_dek = engine.wrap_dek(file_id, &dek).expect("wrap DEK");
    let wrapped_token = engine
        .wrap_token_payload(b"refresh_token=xyz")
        .expect("wrap token");

    engine
        .persist_session(&store, service)
        .await
        .expect("persist session");

    engine.lock_vault().await.expect("lock vault");
    assert!(!engine.is_unlocked());

    // Unknown vault returns Ok(false).
    assert!(
        !engine
            .restore_session(&store, service, Uuid::new_v4())
            .await
            .expect("restore absent session")
    );
    assert!(!engine.is_unlocked());

    // Restore valid session.
    assert!(
        engine
            .restore_session(&store, service, header.vault_id)
            .await
            .expect("restore valid session")
    );
    assert!(engine.is_unlocked());
    assert_eq!(engine.vault_id(), Some(header.vault_id));

    // Restored session holds identical derived keys.
    let unwrapped_dek = engine
        .unwrap_dek(file_id, &wrapped_dek)
        .expect("unwrap DEK after session restore");
    assert_eq!(unwrapped_dek.as_bytes(), dek.as_bytes());
    let unwrapped_token = engine
        .unwrap_token_payload(&wrapped_token)
        .expect("unwrap token after session restore");
    assert_eq!(unwrapped_token.as_slice(), b"refresh_token=xyz");

    // Corrupted session blob fails closed and does not unlock engine.
    engine.lock_vault().await.expect("lock vault");
    let account = header.vault_id.to_string();
    let mut stored = store
        .get_secret(service, &account)
        .await
        .expect("read stored session")
        .expect("session exists")
        .to_vec();
    stored[60] ^= 0x01; // Flip a bit inside master_seed.
    store
        .set_secret(service, &account, &stored)
        .await
        .expect("write tampered session");

    let err = engine
        .restore_session(&store, service, header.vault_id)
        .await
        .expect_err("tampered session must fail closed");
    assert!(matches!(err, ZeroVaultError::CryptoTamperDetected(_)));
    assert!(!engine.is_unlocked());
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn os_keyring_secret_store_windows_roundtrip_and_cleanup() {
    let store = OsKeyringSecretStore::new();
    let service = "zerovault-unit-test";
    let account = format!("zv-test-{}", Uuid::new_v4());

    // Ensure clean baseline.
    store.delete_secret(service, &account).await.expect("delete");
    assert!(
        store
            .get_secret(service, &account)
            .await
            .expect("get absent")
            .is_none()
    );

    let engine = make_engine();
    let header = engine
        .init_vault(
            &RedactedSecret::new("win-keyring-passphrase"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init_vault");

    let vault_account = header.vault_id.to_string();
    match engine.persist_session(&store, service).await {
        Ok(()) => {
            engine.lock_vault().await.expect("lock");
            let restored = engine
                .restore_session(&store, service, header.vault_id)
                .await;
            let _ = store.delete_secret(service, &vault_account).await;
            assert!(restored.expect("restore from Windows Credential Manager"));
            assert_eq!(engine.vault_id(), Some(header.vault_id));
        }
        Err(err) => {
            let _ = store.delete_secret(service, &vault_account).await;
            panic!("Windows Credential Manager persist_session failed: {err}");
        }
    }

    // Raw binary secret roundtrip with cleanup.
    let payload = b"\x00\x01\xfe\xffzerovault-win-cred-test";
    store
        .set_secret(service, &account, payload)
        .await
        .expect("set_secret");
    let loaded = store
        .get_secret(service, &account)
        .await
        .expect("get_secret");
    store
        .delete_secret(service, &account)
        .await
        .expect("cleanup delete_secret");
    assert_eq!(loaded.as_deref().map(Vec::as_slice), Some(&payload[..]));
    assert!(
        store
            .get_secret(service, &account)
            .await
            .expect("get after delete")
            .is_none()
    );
}

#[test]
fn benchmark_aes256_gcm_reports_positive_throughput() {
    let engine = make_engine();
    let report = engine
        .benchmark_aes256_gcm(32)
        .expect("benchmark_aes256_gcm(32)");
    assert_eq!(report.total_mib, 32);
    assert!(report.caps.mandatory_satisfied);
    assert_eq!(report.caps.backend_name, "aws-lc-rs-aes-256-gcm");
    assert!(report.encrypt_mib_per_sec.is_finite() && report.encrypt_mib_per_sec > 0.0);
    assert!(report.decrypt_mib_per_sec.is_finite() && report.decrypt_mib_per_sec > 0.0);

    // 0 MiB rounds up to at least 1 chunk of 4 MiB.
    let min_report = engine
        .benchmark_aes256_gcm(0)
        .expect("benchmark_aes256_gcm(0)");
    assert_eq!(min_report.total_mib, 4);
    assert!(min_report.encrypt_mib_per_sec.is_finite() && min_report.encrypt_mib_per_sec > 0.0);
    assert!(min_report.decrypt_mib_per_sec.is_finite() && min_report.decrypt_mib_per_sec > 0.0);
}

#[test]
fn keyring_state_debug_is_redacted() {
    let engine = make_engine();
    let dek = engine.generate_dek().expect("dek");
    let dek_dbg = format!("{dek:?}");
    assert_eq!(dek_dbg, "DekBytes([REDACTED])");
    // Ensure KeyRingState symbol is exported and implements Debug safely via type check.
    fn _assert_debug_and_zeroize<T: std::fmt::Debug + zeroize::ZeroizeOnDrop>() {}
    _assert_debug_and_zeroize::<KeyRingState>();
    _assert_debug_and_zeroize::<MasterSeed>();
    _assert_debug_and_zeroize::<MasterKek>();
    _assert_debug_and_zeroize::<ManifestKey>();
    _assert_debug_and_zeroize::<TokenWrapKey>();
    _assert_debug_and_zeroize::<HeaderVerifierKey>();
    _assert_debug_and_zeroize::<DekBytes>();
    let _ = std::any::type_name::<ChunkHeader>();
}
