//! Shared contract crate for `cloud.entropy.rs / Zerovault`.
//!
//! Defines domain errors, 4 MiB wire formats, canonical AAD builders, cross-crate async trait
//! boundaries, daemon IPC protocol types, and thread-safe in-memory mocks for parallel swarm builds.

pub mod error;
pub mod ipc;
pub mod mocks;
pub mod traits;
pub mod wire;

pub use error::{ZeroVaultError, ZeroVaultResult};
pub use ipc::{
    DaemonRequest, DaemonResponse, MAX_IPC_FRAME_BYTES, RemoteAccountSummary, ThroughputSnapshot,
    VaultStatusReport,
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
    DekBytes, HKDF_INFO_KEK, HKDF_INFO_MANIFEST, HKDF_INFO_TOKEN_WRAP, HKDF_INFO_VERIFIER,
    KdfParams, MANIFEST_FORMAT_VERSION, MANIFEST_HEAD_OBJECT_KEY, MANIFEST_HEADER_LEN,
    MANIFEST_MAGIC, MAX_ENCRYPTED_CHUNK_SIZE, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
    MIN_ARGON2_PARALLELISM, ManifestNode, ManifestObjectKey, ManifestWireHeader,
    PLAINTEXT_CHUNK_SIZE, RedactedSecret, VAULT_HEADER_LEN, VAULT_HEADER_MAGIC,
    VAULT_HEADER_OBJECT_KEY, VAULT_HEADER_VERSION, VaultHeader, VaultManifest, WrappedDek,
    XATTR_ZEROVAULT_PIN, XATTR_ZEROVAULT_STATE, chunk_span_for_range, validate_remote_object_key,
};

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::mocks::{
        InMemorySecretStore, MockCryptoEngine, MockMetadataStore, MockStorageRouter, MockVfsBackend,
    };

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

        // Non-final chunk shorter than 4 MiB must fail.
        let bad = ChunkHeader {
            version: CHUNK_FORMAT_VERSION,
            is_final_chunk: false,
            chunk_index: 0,
            plaintext_len: 1024,
            nonce: [0u8; 12],
        };
        assert!(bad.encode().is_err());

        // Empty chunk allowed only at index 0 when final.
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
    fn vault_header_roundtrip_and_kdf_policy_floor() {
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

        let mut weak_wire = wire;
        // Corrupt m_cost_kib to 1024 KiB (< 65536 KiB).
        weak_wire[56..60].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(
            VaultHeader::decode(&weak_wire),
            Err(ZeroVaultError::KdfPolicyViolation { .. })
        ));
    }

    #[test]
    fn blob_and_manifest_keys_reject_plaintext_names() {
        let id = Uuid::new_v4();
        let blob_key = BlobObjectKey::from_uuid(id);
        assert!(BlobObjectKey::parse(blob_key.as_str()).is_ok());
        assert!(validate_remote_object_key(blob_key.as_str()).is_ok());
        assert!(validate_remote_object_key(VAULT_HEADER_OBJECT_KEY).is_ok());
        assert!(validate_remote_object_key(MANIFEST_HEAD_OBJECT_KEY).is_ok());
        assert!(validate_remote_object_key("Finance/taxes_2026.pdf").is_err());
        assert!(validate_remote_object_key("blobs/aa/bb/secret.pdf").is_err());
    }

    #[test]
    fn chunk_span_computes_cross_boundary_slices() {
        let file_size = (PLAINTEXT_CHUNK_SIZE as u64) * 2 + 500;
        let offset = (PLAINTEXT_CHUNK_SIZE as u64) - 100;
        let span = chunk_span_for_range(offset, 250, file_size)
            .expect("valid range")
            .expect("non-empty span");
        assert_eq!(span.readable_len, 250);
        assert_eq!(span.slices.len(), 2);
        assert_eq!(span.slices[0].chunk_index, 0);
        assert_eq!(span.slices[0].in_chunk_offset, PLAINTEXT_CHUNK_SIZE - 100);
        assert_eq!(span.slices[0].len, 100);
        assert_eq!(span.slices[1].chunk_index, 1);
        assert_eq!(span.slices[1].in_chunk_offset, 0);
        assert_eq!(span.slices[1].len, 150);
    }

    #[test]
    fn secrets_and_requests_redact_debug_output() {
        let dek = DekBytes::from_array([0x99; 32]);
        let secret = RedactedSecret::new("super-secret-passphrase");
        let req = DaemonRequest::InitVault {
            passphrase: "super-secret-passphrase".to_owned(),
        };
        assert!(!format!("{dek:?}").contains("99"));
        assert!(!format!("{secret:?}").contains("super-secret"));
        assert!(!format!("{req:?}").contains("super-secret"));
    }

    #[tokio::test]
    async fn mock_crypto_storage_and_vfs_work_together() {
        let crypto = MockCryptoEngine::default();
        let header = crypto
            .init_vault(
                &RedactedSecret::new("correct horse battery staple"),
                KdfParams::interactive_production(),
            )
            .await
            .expect("init vault");

        let file_id = Uuid::new_v4();
        let dek = crypto.generate_dek().expect("dek");
        let wrapped = crypto.wrap_dek(file_id, &dek).expect("wrap dek");
        let unwrapped = crypto.unwrap_dek(file_id, &wrapped).expect("unwrap dek");
        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());

        let aad = ChunkAad {
            file_id,
            chunk_index: 0,
            is_final_chunk: true,
        };
        let (_hdr, wire) = crypto
            .encrypt_chunk(&dek, aad, b"hello zero-knowledge world")
            .expect("encrypt");
        let (_dhdr, pt) = crypto
            .decrypt_chunk(&dek, file_id, Some(0), &wire)
            .expect("decrypt");
        assert_eq!(pt.as_ref(), b"hello zero-knowledge world");

        // Flip 1 bit -> fail closed.
        let mut tampered = wire.to_vec();
        tampered[CHUNK_HEADER_LEN] ^= 0x01;
        assert!(
            crypto
                .decrypt_chunk(&dek, file_id, Some(0), &tampered)
                .is_err()
        );

        // Wrong file_id AAD -> fail closed.
        assert!(
            crypto
                .decrypt_chunk(&dek, Uuid::new_v4(), Some(0), &wire)
                .is_err()
        );

        let storage = MockStorageRouter::default();
        let blob_key = BlobObjectKey::from_uuid(Uuid::new_v4());
        storage
            .put_blob("/Docs/a.txt", blob_key.as_str(), bytes::Bytes::from_static(b"enc"))
            .await
            .expect("put blob");
        assert_eq!(
            storage
                .get_blob(blob_key.as_str(), &[])
                .await
                .expect("get blob")
                .as_ref(),
            b"enc"
        );

        let manifest = VaultManifest {
            vault_id: header.vault_id,
            revision: 1,
            parent_manifest_id: None,
            device_id: "test-host".to_owned(),
            created_at: Utc::now(),
            nodes: Vec::new(),
        };
        let sealed = crypto.seal_manifest(&manifest).expect("seal");
        let opened = crypto.open_manifest(&sealed).expect("open");
        assert_eq!(opened.revision, 1);

        let secrets = InMemorySecretStore::default();
        crypto
            .persist_session(&secrets, "zerovault-test")
            .await
            .expect("persist");
        crypto.lock_vault().await.expect("lock");
        assert!(!crypto.is_unlocked());
        assert!(
            crypto
                .restore_session(&secrets, "zerovault-test", header.vault_id)
                .await
                .expect("restore")
        );

        let meta = MockMetadataStore::new();
        assert!(meta.get_inode(ROOT_INODE).await.expect("root").is_some());

        let vfs = MockVfsBackend::new();
        let seeded = vfs
            .seed_remote_file(ROOT_INODE, "notes.txt", b"abcdef")
            .await
            .expect("seed");
        let slice = vfs.read_range(seeded.inode, 2, 3).await.expect("read");
        assert_eq!(slice.as_ref(), b"cde");
    }
}
