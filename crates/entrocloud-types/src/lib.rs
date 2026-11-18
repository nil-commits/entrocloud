//! Shared contract crate for `EntroCloud v1.0`.
//!
//! Defines domain errors, 4 MiB wire formats, canonical AAD builders, post-quantum `keybox.zv`
//! & `ec://` (plus backward-compatible `zv://`) capability URI models, cross-crate async trait
//! boundaries, daemon IPC protocol types, automatic folder backup job models, and thread-safe
//! in-memory mocks for parallel swarm builds.

pub mod error;
pub mod ipc;
pub mod mocks;
pub mod sharing;
pub mod traits;
pub mod wire;

pub use error::{EntroCloudError, EntroCloudResult, ZeroVaultError, ZeroVaultResult};
pub use ipc::{
    AddRemoteParams, BackupJobSpec, BackupJobSummary, BackupRunReport, DaemonRequest,
    DaemonResponse, DetectedCloudFolder, KeyboxSummary, MAX_IPC_FRAME_BYTES, OAuthLoginParams,
    RemoteAccountSummary, RemoteTestReport, ThroughputSnapshot, VaultEntrySummary,
    VaultStatusReport,
};
pub use sharing::{
    CAPABILITY_URI_SCHEME, CapabilityUri, ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN,
    HybridRecipientStanza, KEYBOX_MAGIC, KEYBOX_VERSION, LEGACY_CAPABILITY_URI_SCHEME,
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_DECAPS_KEY_LEN, ML_KEM_768_ENCAPS_KEY_LEN,
    RecipientPrivateIdentity, RecipientPublicBundle, SHARE_ENVELOPE_MAGIC,
    SHARE_ENVELOPE_VERSION, ShareDescriptor, SignedKeybox, SignedShareEnvelope, X25519_KEY_LEN,
};
pub use traits::{
    BackendConfig, BackendHealth, BackendId, BackendKind, BackendQuota, BlobPlacement,
    ChunkDescriptor, ConflictRecord, CreateEntrySpec, CryptoBenchmarkReport, CryptoEngine,
    DirtyOp, DirtyOpKind, DriveStats, EntryKind, HardwareCryptoCaps, HydrationState, InodeId,
    InodeRecord, MetadataStore, ROOT_INODE, RemoteVersion, ReplicaTarget, RoutingPolicy,
    SecretStore, SetAttrSpec, StorageRouterTrait, VfsBackend, VirtualDrive,
};
pub use wire::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, BlobObjectKey, CHUNK_FLAG_FINAL, CHUNK_FORMAT_VERSION,
    CHUNK_HEADER_LEN, CHUNK_MAGIC, ChunkAad, ChunkHeader, ChunkRangeSpan, ChunkRef, ChunkSlice,
    DekBytes, HKDF_INFO_KEK, HKDF_INFO_MANIFEST, HKDF_INFO_META_AEAD, HKDF_INFO_META_BLIND,
    HKDF_INFO_STAGING, HKDF_INFO_TOKEN_WRAP, HKDF_INFO_VERIFIER, KEYBOX_OBJECT_KEY, KdfParams,
    MANIFEST_FORMAT_VERSION, MANIFEST_HEAD_OBJECT_KEY, MANIFEST_HEADER_LEN, MANIFEST_MAGIC,
    MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM,
    MAX_ENCRYPTED_CHUNK_SIZE, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_PARALLELISM,
    ManifestNode, ManifestObjectKey, ManifestWireHeader, PLAINTEXT_CHUNK_SIZE, RedactedSecret,
    ShareObjectKey, VAULT_HEADER_LEN, VAULT_HEADER_MAGIC, VAULT_HEADER_OBJECT_KEY,
    VAULT_HEADER_VERSION, VaultHeader, VaultManifest, WrappedDek, XATTR_ENTROCLOUD_FILE_ID,
    XATTR_ENTROCLOUD_PIN, XATTR_ENTROCLOUD_STATE, XATTR_ZEROVAULT_FILE_ID, XATTR_ZEROVAULT_PIN,
    XATTR_ZEROVAULT_STATE, chunk_span_for_range, normalize_virtual_path,
    validate_portable_entry_name, validate_remote_object_key,
};

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use proptest::prelude::*;
    use uuid::Uuid;

    use super::*;
    use crate::mocks::{MockCryptoEngine, MockVfsBackend};

    #[test]
    fn chunk_header_roundtrip_and_invariants() {
        let hdr = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: false,
            chunk_index: 7,
            plaintext_len: PLAINTEXT_CHUNK_SIZE as u32,
            nonce: [0x11; 12],
        };
        let encoded = hdr.encode().expect("valid non-final 4 MiB chunk");
        let decoded = ChunkHeader::decode(&encoded).expect("decode valid header");
        assert_eq!(hdr, decoded);

        let bad = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: false,
            chunk_index: 0,
            plaintext_len: 1024,
            nonce: [0u8; 12],
        };
        assert!(bad.encode().is_err());

        let empty_zero = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: true,
            chunk_index: 0,
            plaintext_len: 0,
            nonce: [1u8; 12],
        };
        assert!(empty_zero.encode().is_ok());

        let empty_non_zero = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: true,
            chunk_index: 1,
            plaintext_len: 0,
            nonce: [1u8; 12],
        };
        assert!(empty_non_zero.encode().is_err());
    }

    #[test]
    fn vault_header_enforces_kdf_floor_and_dos_ceiling() {
        let vault_id = Uuid::new_v4();
        let hdr = VaultHeader {
            version: VAULT_HEADER_VERSION,
            vault_id,
            argon2_salt: [0x22; 32],
            kdf: KdfParams::interactive_production(),
            verifier_nonce: [0x33; 12],
            verifier_tag: [0x44; 32],
        };
        let wire = hdr.encode();
        let decoded = VaultHeader::decode(&wire).expect("valid vault header");
        assert_eq!(hdr, decoded);

        // Below floor (< 64 MiB) rejected.
        let mut weak_wire = wire;
        weak_wire[56..60].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(
            VaultHeader::decode(&weak_wire),
            Err(ZeroVaultError::KdfPolicyViolation { .. })
        ));

        // Above ceiling (> 256 MiB OOM DoS attack) rejected BEFORE allocation!
        let mut oom_wire = wire;
        oom_wire[56..60].copy_from_slice(&(4 * 1024 * 1024u32).to_le_bytes());
        assert!(matches!(
            VaultHeader::decode(&oom_wire),
            Err(ZeroVaultError::KdfPolicyViolation { .. })
        ));
    }

    #[test]
    fn zero_knowledge_remote_keys_accept_keybox_and_shares_but_reject_plaintext() {
        let id = Uuid::new_v4();
        let blob_key = BlobObjectKey::from_uuid(id);
        let share_key = ShareObjectKey::from_uuid(id);
        assert!(validate_remote_object_key(blob_key.as_str()).is_ok());
        assert!(validate_remote_object_key(share_key.as_str()).is_ok());
        assert!(validate_remote_object_key(VAULT_HEADER_OBJECT_KEY).is_ok());
        assert!(validate_remote_object_key(KEYBOX_OBJECT_KEY).is_ok());
        assert!(validate_remote_object_key(MANIFEST_HEAD_OBJECT_KEY).is_ok());
        assert!(validate_remote_object_key("Finance/taxes_2026.pdf").is_err());
        assert!(validate_remote_object_key("blobs/aa/bb/secret.pdf").is_err());
    }

    #[test]
    fn portable_filename_sanitizer_preserves_linux_case_and_blocks_windows_devices() {
        assert!(validate_portable_entry_name("Makefile", true).is_ok());
        assert!(validate_portable_entry_name("makefile", true).is_ok());
        assert!(validate_portable_entry_name("../etc/passwd", false).is_err());
        assert!(validate_portable_entry_name("stream:ads", false).is_err());
        assert!(validate_portable_entry_name("CON.txt", true).is_err());
        assert!(validate_portable_entry_name("COM\u{00B9}", true).is_err());
        assert!(validate_portable_entry_name("trailing.", true).is_err());
    }

    #[test]
    fn capability_uri_and_mock_keybox_revocation_roundtrip() {
        let crypto = MockCryptoEngine::default();
        let owner = crypto.generate_recipient_identity("owner").expect("owner");
        let alice = crypto.generate_recipient_identity("alice").expect("alice");
        let bob = crypto.generate_recipient_identity("bob").expect("bob");

        let vault_id = Uuid::new_v4();
        let frk1 = [0x11u8; 32];
        let kb1 = crypto
            .seal_keybox(
                &owner,
                vault_id,
                1,
                &frk1,
                &[alice.public.clone(), bob.public.clone()],
            )
            .expect("kb1");
        let wire_kb1 = kb1.encode().expect("encode kb1");
        let decoded_kb1 = SignedKeybox::decode(&wire_kb1).expect("decode kb1");

        let bob_frk1 = crypto
            .open_keybox(&decoded_kb1, Some(&owner.public.ed25519_pubkey), 1, &bob)
            .expect("bob opens epoch 1");
        assert_eq!(&*bob_frk1, &frk1);

        // Revoke Bob at epoch 2 with rotated FRK2.
        let frk2 = [0x22u8; 32];
        let kb2 = crypto
            .seal_keybox(&owner, vault_id, 2, &frk2, std::slice::from_ref(&alice.public))
            .expect("kb2");
        assert!(
            crypto
                .open_keybox(&kb2, Some(&owner.public.ed25519_pubkey), 2, &bob)
                .is_err()
        );
        // Replay of epoch 1 when floor is 2 MUST fail closed!
        assert!(
            crypto
                .open_keybox(&decoded_kb1, Some(&owner.public.ed25519_pubkey), 2, &alice)
                .is_err()
        );

        // Capability URI roundtrip.
        let dek = crypto.generate_dek().expect("dek");
        let desc = ShareDescriptor {
            share_id: Uuid::new_v4(),
            file_id: Uuid::new_v4(),
            filename: "blueprint.pdf".to_owned(),
            size: 1234,
            created_at: Utc::now(),
            wrapped_dek: WrappedDek {
                nonce: [0; 12],
                ciphertext_and_tag: vec![0; 48],
            },
            chunks: Vec::new(),
        };
        let (uri, env) = crypto
            .create_capability_share(&owner, "s3", "bucket-a", &dek, &desc)
            .expect("share");
        let encoded_uri = uri.encode().expect("encode uri");
        assert!(encoded_uri.starts_with("ec://share/v1/"));
        assert!(!format!("{uri:?}").contains(&encoded_uri[encoded_uri.find('#').unwrap() + 1..]));
        let parsed_uri = CapabilityUri::parse(&encoded_uri).expect("parse ec:// uri");
        let legacy_zv = uri.encode_with_scheme("zv").expect("encode legacy zv://");
        assert!(legacy_zv.starts_with("zv://share/v1/"));
        let parsed_legacy = CapabilityUri::parse(&legacy_zv).expect("parse legacy zv:// uri");
        assert_eq!(parsed_legacy.share_id, parsed_uri.share_id);
        let (opened_desc, opened_dek) = crypto
            .open_capability_share(&parsed_uri, &env)
            .expect("open share");
        assert_eq!(opened_desc.filename, "blueprint.pdf");
        assert_eq!(opened_dek.as_bytes(), dek.as_bytes());
    }

    #[tokio::test]
    async fn mock_vfs_unpin_then_dehydrate_succeeds() {
        let vfs = MockVfsBackend::new();
        let seeded = vfs
            .seed_remote_file(ROOT_INODE, "video.mp4", b"0123456789")
            .await
            .expect("seed");
        vfs.pin(seeded.inode).await.expect("pin");
        assert!(vfs.dehydrate(seeded.inode).await.is_err());
        vfs.unpin(seeded.inode).await.expect("unpin");
        vfs.dehydrate(seeded.inode)
            .await
            .expect("dehydrate after unpin");
    }

    proptest! {
        #[test]
        fn prop_chunk_span_covers_exact_requested_range(
            file_size in 1u64..(20 * 1024 * 1024),
            offset in 0u64..(22 * 1024 * 1024),
            len in 0usize..(10 * 1024 * 1024),
        ) {
            let res = chunk_span_for_range(offset, len, file_size).expect("valid span calc");
            if len == 0 || offset >= file_size {
                prop_assert!(res.is_none());
            } else {
                let span = res.expect("some span");
                let expected = ((file_size - offset) as usize).min(len);
                prop_assert_eq!(span.readable_len, expected);
                let total_sliced: usize = span.slices.iter().map(|s| s.len).sum();
                prop_assert_eq!(total_sliced, expected);
            }
        }
    }
}
