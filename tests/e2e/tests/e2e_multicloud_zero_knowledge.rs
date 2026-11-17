//! End-to-end zero-knowledge multi-cloud integration tests for Zerovault.
//!
//! All tests use real production implementations with zero mock crypto and zero mock storage:
//! - `AwsLcCryptoEngine` (`aws-lc-rs` AES-256-GCM + Argon2id >= 64 MiB + HKDF-SHA256)
//! - `SqliteMetadataStore` (on-disk SQLite WAL with foreign keys)
//! - `StorageRouter` backed by real `CloudBackend` (`BackendKind::LocalFs` OpenDAL `Fs` roots)
//! - `SyncEngine`, `MockDrive`, `DaemonRuntime` + `CoreSyncEngineFactory` + `IpcServer`/`IpcClient`

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use zerovault_core::{
    DEFAULT_MAX_RAM_CACHE_BYTES, SqliteMetadataStore, SyncEngine, SyncEngineConfig,
};
use zerovault_crypto::AwsLcCryptoEngine;
use zerovault_daemon::{
    CoreSyncEngineFactory, DaemonRuntime, DaemonStateConfig, IpcClient, IpcEndpoint, IpcServer,
};
use zerovault_storage::{CloudBackend, StorageRouter};
use zerovault_types::mocks::InMemorySecretStore;
use zerovault_types::{
    AddRemoteParams, BackendConfig, BackendKind, BlobObjectKey, CHUNK_HEADER_LEN, CreateEntrySpec,
    CryptoEngine, DaemonRequest, DaemonResponse, HydrationState, KdfParams,
    MANIFEST_HEAD_OBJECT_KEY, MANIFEST_HEADER_LEN, PLAINTEXT_CHUNK_SIZE, ROOT_INODE,
    RedactedSecret, RoutingPolicy, StorageRouterTrait, VfsBackend, VirtualDrive,
    validate_remote_object_key,
};
use zerovault_vfs::MockDrive;

fn local_fs_backend_config(id: &str, root: &Path, quota_limit_bytes: Option<u64>) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: root.to_string_lossy().into_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes,
        min_free_reserve_bytes: 0,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

fn make_sync_engine(
    base_dir: &Path,
    device_id: &str,
    crypto: Arc<dyn CryptoEngine>,
    storage: Arc<dyn StorageRouterTrait>,
) -> Arc<SyncEngine> {
    let db_path = base_dir.join(format!("{device_id}-meta.db"));
    let meta = Arc::new(SqliteMetadataStore::open(&db_path).expect("open sqlite WAL metadata db"));
    assert_eq!(
        meta.journal_mode().expect("journal_mode").to_lowercase(),
        "wal"
    );

    let cfg = SyncEngineConfig {
        staging_dir: base_dir.join(format!("{device_id}-staging")),
        device_id: device_id.to_owned(),
        max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
        max_concurrent_transfers: 8,
    };
    Arc::new(SyncEngine::new(cfg, meta, crypto, storage).expect("construct SyncEngine"))
}

fn collect_relative_files(root: &Path) -> Vec<(String, PathBuf)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
        for entry in std::fs::read_dir(dir).expect("read_dir on remote cloud root") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .expect("strip cloud root prefix")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
    }

    let mut out = Vec::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

async fn read_entire_file_via_drive(
    drive: &MockDrive,
    inode: u64,
    total_size: u64,
) -> zerovault_types::ZeroVaultResult<Vec<u8>> {
    let mut out = Vec::with_capacity(usize::try_from(total_size).unwrap_or(0));
    let mut offset = 0u64;
    let slice_len = 512 * 1024;

    while offset < total_size {
        let want = usize::try_from((total_size - offset).min(slice_len as u64)).unwrap_or(slice_len);
        let chunk = drive.backend().read_range(inode, offset, want).await?;
        assert!(!chunk.is_empty(), "unexpected empty read before EOF");
        out.extend_from_slice(&chunk);
        offset += chunk.len() as u64;
    }
    Ok(out)
}

async fn stream_write_file(
    backend: &dyn VfsBackend,
    inode: u64,
    payload: &[u8],
    step_bytes: usize,
) {
    for off in (0..payload.len()).step_by(step_bytes) {
        let end = (off + step_bytes).min(payload.len());
        let written = backend
            .write_range(inode, off as u64, &payload[off..end])
            .await
            .expect("stream write_range");
        assert_eq!(written, end - off);
    }
}

fn build_deterministic_payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            ((i.wrapping_mul(29) ^ (i >> 9) ^ (i >> 17)) as u8).wrapping_add(seed)
        })
        .collect()
}

#[tokio::test]
async fn e2e_zero_knowledge_remote_audit_and_o1_cross_chunk_hydration() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_a_dir = tmp.path().join("cloud-a");
    let cloud_b_dir = tmp.path().join("cloud-b");
    let mount_dir = tmp.path().join("mount");
    std::fs::create_dir_all(&mount_dir).expect("create mount dir");

    let backend_a =
        CloudBackend::from_config(&local_fs_backend_config("cloud-a", &cloud_a_dir, None))
            .expect("build cloud-a");
    let backend_b =
        CloudBackend::from_config(&local_fs_backend_config("cloud-b", &cloud_b_dir, None))
            .expect("build cloud-b");

    let router = Arc::new(
        StorageRouter::new(
            [backend_a, backend_b],
            RoutingPolicy::Mirrored {
                backends: vec!["cloud-a".to_owned(), "cloud-b".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored StorageRouter"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("HW AES-NI + PCLMULQDQ/PMULL required"));
    let kdf = KdfParams::interactive_production();
    assert!(kdf.m_cost_kib >= 65_536);
    assert!(kdf.t_cost >= 3);
    assert!(kdf.p_cost >= 4);

    let passphrase = RedactedSecret::new("e2e-zero-knowledge-audit-passphrase-2026");
    let header = crypto.init_vault(&passphrase, kdf).await.expect("init_vault");

    let engine = make_sync_engine(tmp.path(), "audit-device", crypto, router);
    engine
        .publish_vault_header(&header)
        .await
        .expect("publish vault/header.zvh");

    let drive = MockDrive::new(Arc::clone(&engine) as Arc<dyn VfsBackend>);
    drive.mount(mount_dir).await.expect("mount MockDrive");

    // Create /Finance/Confidential/TopSecret_TaxReturn_2026.pdf
    let finance = drive
        .backend()
        .mkdir(ROOT_INODE, "Finance", 0o755)
        .await
        .expect("mkdir /Finance");
    let confidential = drive
        .backend()
        .mkdir(finance.inode, "Confidential", 0o755)
        .await
        .expect("mkdir /Finance/Confidential");
    let file = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: confidential.inode,
            name: "TopSecret_TaxReturn_2026.pdf".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create TopSecret_TaxReturn_2026.pdf");

    // > 9 MiB (3 chunks: 4 MiB + 4 MiB + 1.5 MiB)
    let total_len = 9 * 1024 * 1024 + 512 * 1024;
    let mut payload = build_deterministic_payload(total_len, 0x11);
    let marker = b"SSN-999-00-1234-CONFIDENTIAL-PAYLOAD";

    let marker_offsets = [
        1024usize,                       // inside chunk 0
        PLAINTEXT_CHUNK_SIZE - 16,       // straddling chunk 0 -> chunk 1 boundary
        PLAINTEXT_CHUNK_SIZE + 256,      // inside chunk 1
        PLAINTEXT_CHUNK_SIZE * 2 - 12,   // straddling chunk 1 -> chunk 2 boundary
        9 * 1024 * 1024 + 64 * 1024,     // inside chunk 2 tail
    ];
    for &off in &marker_offsets {
        payload[off..off + marker.len()].copy_from_slice(marker);
    }

    stream_write_file(drive.backend().as_ref(), file.inode, &payload, 512 * 1024).await;
    drive
        .backend()
        .flush(file.inode)
        .await
        .expect("flush 3-chunk encrypted payload");

    // Zero-Knowledge Remote Storage Audit across BOTH mirrors
    let forbidden_strings = [
        "topsecret",
        "taxreturn",
        ".pdf",
        "finance",
        "confidential",
        "ssn-999-00-1234",
    ];
    let forbidden_bytes: [&[u8]; 6] = [
        b"TopSecret",
        b"TaxReturn",
        b".pdf",
        b"Finance",
        b"Confidential",
        b"SSN-999-00-1234",
    ];

    for (cloud_name, cloud_dir) in [("cloud-a", &cloud_a_dir), ("cloud-b", &cloud_b_dir)] {
        let remote_files = collect_relative_files(cloud_dir);
        assert!(
            remote_files.len() >= 6,
            "{cloud_name} should contain header, head manifest, snapshot manifest, and 3 blobs, got {}",
            remote_files.len()
        );

        let mut blob_count = 0usize;
        for (rel_key, abs_path) in &remote_files {
            validate_remote_object_key(rel_key).unwrap_or_else(|e| {
                panic!("{cloud_name} leaked non-canonical remote key '{rel_key}': {e}")
            });
            if rel_key.starts_with("blobs/") {
                blob_count += 1;
            }

            let raw = std::fs::read(abs_path).expect("read remote cloud object bytes");
            for needle in forbidden_bytes {
                assert!(
                    !contains_subslice(&raw, needle),
                    "{cloud_name} object '{rel_key}' contained forbidden plaintext bytes {:?}",
                    String::from_utf8_lossy(needle)
                );
            }
            let lossy_lower = String::from_utf8_lossy(&raw).to_ascii_lowercase();
            for s in forbidden_strings {
                assert!(
                    !lossy_lower.contains(s),
                    "{cloud_name} object '{rel_key}' leaked case-insensitive plaintext token '{s}'"
                );
            }
        }
        assert_eq!(blob_count, 3, "{cloud_name} must hold exactly 3 encrypted .zv blobs");
    }

    // Dehydrate file and perform O(1) cross-chunk hydration across the 4 MiB boundary
    drive
        .dehydrate_path("/Finance/Confidential/TopSecret_TaxReturn_2026.pdf")
        .await
        .expect("dehydrate file");
    assert_eq!(
        drive
            .backend()
            .get_xattr_state(file.inode)
            .await
            .expect("xattr state"),
        HydrationState::OnlineOnly
    );
    assert_eq!(engine.cache().used_ram_bytes(), 0);

    let read_offset = 4_194_000u64;
    let read_len = 65_536usize;
    let hydrated_slice = drive
        .backend()
        .read_range(file.inode, read_offset, read_len)
        .await
        .expect("O(1) cross-chunk read");
    assert_eq!(
        hydrated_slice.as_ref(),
        &payload[read_offset as usize..read_offset as usize + read_len]
    );

    // Verify chunk 2 was NOT downloaded/hydrated during chunk 0->1 boundary read
    let chunks_after = engine
        .metadata()
        .list_chunks(file.inode)
        .await
        .expect("list_chunks");
    assert_eq!(chunks_after.len(), 3);
    assert!(chunks_after[0].locally_hydrated);
    assert!(chunks_after[1].locally_hydrated);
    assert!(
        !chunks_after[2].locally_hydrated,
        "chunk 2 must remain unhydrated during 4 MiB boundary read"
    );
    assert_eq!(
        drive
            .backend()
            .get_xattr_state(file.inode)
            .await
            .expect("partial hydration state"),
        HydrationState::PartiallyHydrated
    );

    drive.unmount().await.expect("unmount");
}

#[tokio::test]
async fn e2e_fail_closed_aead_tamper_bitflip_swap_and_manifest_corruption() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_a_dir = tmp.path().join("cloud-a");
    let cloud_b_dir = tmp.path().join("cloud-b");

    let backend_a =
        CloudBackend::from_config(&local_fs_backend_config("cloud-a", &cloud_a_dir, None))
            .expect("cloud-a");
    let backend_b =
        CloudBackend::from_config(&local_fs_backend_config("cloud-b", &cloud_b_dir, None))
            .expect("cloud-b");

    let router = Arc::new(
        StorageRouter::new(
            [backend_a, backend_b],
            RoutingPolicy::Mirrored {
                backends: vec!["cloud-a".to_owned(), "cloud-b".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let passphrase = RedactedSecret::new("e2e-tamper-audit-passphrase-2026");
    let header = crypto
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init_vault");

    let engine = make_sync_engine(tmp.path(), "tamper-device", crypto.clone(), router.clone());
    engine
        .publish_vault_header(&header)
        .await
        .expect("publish vault header");

    let drive = MockDrive::new(Arc::clone(&engine) as Arc<dyn VfsBackend>);

    // Create two multi-chunk files in one manifest sync so Test A & Test B operate cleanly
    // over Mirrored storage without triggering Mirrored multi-rev CAS limitation.
    let file_a = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "bitflip_target.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create file_a");
    let payload_a = build_deterministic_payload(PLAINTEXT_CHUNK_SIZE + 128 * 1024, 0x33);
    stream_write_file(drive.backend().as_ref(), file_a.inode, &payload_a, 512 * 1024).await;

    let file_b = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "swap_target.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create file_b");
    let payload_b = build_deterministic_payload(PLAINTEXT_CHUNK_SIZE * 2, 0x77);
    stream_write_file(drive.backend().as_ref(), file_b.inode, &payload_b, 512 * 1024).await;

    let sync_report = engine.sync_once().await.expect("initial sync_once");
    assert_eq!(sync_report.published_revision, Some(1));

    // --- Test A: Flip 1 bit in a remote .zv chunk payload across mirrors ---
    let chunks_a = engine.metadata().list_chunks(file_a.inode).await.expect("chunks_a");
    assert_eq!(chunks_a.len(), 2);
    let target_blob_key = BlobObjectKey::from_uuid(chunks_a[1].blob_id);
    for dir in [&cloud_a_dir, &cloud_b_dir] {
        let p = dir.join(target_blob_key.as_str());
        let mut bytes = std::fs::read(&p).expect("read remote .zv blob");
        bytes[CHUNK_HEADER_LEN + 100] ^= 0x01;
        std::fs::write(&p, &bytes).expect("write bitflipped .zv blob");
    }

    drive
        .dehydrate_path("/bitflip_target.bin")
        .await
        .expect("dehydrate file_a");
    let err_a = drive
        .backend()
        .read_range(file_a.inode, PLAINTEXT_CHUNK_SIZE as u64, 4096)
        .await
        .expect_err("bit-flipped chunk MUST fail closed");
    assert!(
        err_a.is_tamper(),
        "expected CryptoTamperDetected on 1-bit flip, got {err_a:?}"
    );

    // --- Test B: Swap chunk 0 .zv and chunk 1 .zv contents across mirrors ---
    let chunks_b = engine.metadata().list_chunks(file_b.inode).await.expect("chunks_b");
    assert_eq!(chunks_b.len(), 2);
    let key_b0 = BlobObjectKey::from_uuid(chunks_b[0].blob_id);
    let key_b1 = BlobObjectKey::from_uuid(chunks_b[1].blob_id);
    for dir in [&cloud_a_dir, &cloud_b_dir] {
        let p0 = dir.join(key_b0.as_str());
        let p1 = dir.join(key_b1.as_str());
        let b0 = std::fs::read(&p0).expect("read chunk 0 blob");
        let b1 = std::fs::read(&p1).expect("read chunk 1 blob");
        std::fs::write(&p0, &b1).expect("overwrite chunk 0 with chunk 1");
        std::fs::write(&p1, &b0).expect("overwrite chunk 1 with chunk 0");
    }

    drive
        .dehydrate_path("/swap_target.bin")
        .await
        .expect("dehydrate file_b");
    let err_b = drive
        .backend()
        .read_range(file_b.inode, 0, 4096)
        .await
        .expect_err("swapped chunk 0 <-> chunk 1 MUST fail closed");
    assert!(
        err_b.is_tamper(),
        "expected CryptoTamperDetected on chunk swap, got {err_b:?}"
    );

    // --- Test C: Corrupt 1 byte inside remote manifests/head.zvm -> sync_once fails closed ---
    tokio::time::sleep(Duration::from_millis(25)).await;
    for dir in [&cloud_a_dir, &cloud_b_dir] {
        let head_path = dir.join(MANIFEST_HEAD_OBJECT_KEY);
        let mut raw_manifest = std::fs::read(&head_path).expect("read head.zvm");
        let target_idx = MANIFEST_HEADER_LEN + 4;
        raw_manifest[target_idx] ^= 0x01;
        std::fs::write(&head_path, &raw_manifest).expect("write corrupted head.zvm");
    }

    // Verify both an existing synced engine (via changed mtime/etag) AND a fresh peer engine fail closed.
    let err_c_existing = engine
        .sync_once()
        .await
        .expect_err("corrupted head.zvm must fail closed on existing engine");
    assert!(
        err_c_existing.is_tamper(),
        "expected CryptoTamperDetected on corrupted head.zvm, got {err_c_existing:?}"
    );

    let peer_engine = make_sync_engine(tmp.path(), "peer-verifier", crypto, router);
    let err_c_peer = peer_engine
        .sync_once()
        .await
        .expect_err("corrupted head.zvm must fail closed on fresh peer");
    assert!(
        err_c_peer.is_tamper(),
        "expected CryptoTamperDetected on peer sync_once, got {err_c_peer:?}"
    );
}

#[tokio::test]
async fn e2e_mirrored_raid1_outage_failover() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_a_dir = tmp.path().join("cloud-a");
    let cloud_b_dir = tmp.path().join("cloud-b");

    let backend_a =
        CloudBackend::from_config(&local_fs_backend_config("cloud-a", &cloud_a_dir, None))
            .expect("cloud-a");
    let backend_b =
        CloudBackend::from_config(&local_fs_backend_config("cloud-b", &cloud_b_dir, None))
            .expect("cloud-b");

    let router = Arc::new(
        StorageRouter::new(
            [backend_a, backend_b],
            RoutingPolicy::Mirrored {
                backends: vec!["cloud-a".to_owned(), "cloud-b".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let passphrase = RedactedSecret::new("e2e-raid1-failover-passphrase-2026");
    let header = crypto
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init_vault");

    let engine = make_sync_engine(tmp.path(), "raid1-device", crypto, router);
    engine
        .publish_vault_header(&header)
        .await
        .expect("publish header");

    let drive = MockDrive::new(Arc::clone(&engine) as Arc<dyn VfsBackend>);
    let dir = drive
        .backend()
        .mkdir(ROOT_INODE, "Backups", 0o755)
        .await
        .expect("mkdir /Backups");
    let file = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: dir.inode,
            name: "vault_snapshot.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create snapshot");

    let total_len = 8 * 1024 * 1024 + 321_000;
    let payload = build_deterministic_payload(total_len, 0x55);
    stream_write_file(drive.backend().as_ref(), file.inode, &payload, 512 * 1024).await;
    drive.backend().flush(file.inode).await.expect("flush");

    // Confirm both mirrors hold the encrypted blobs before outage
    assert!(
        collect_relative_files(&cloud_a_dir)
            .iter()
            .filter(|(k, _)| k.starts_with("blobs/"))
            .count()
            == 3
    );
    assert!(
        collect_relative_files(&cloud_b_dir)
            .iter()
            .filter(|(k, _)| k.starts_with("blobs/"))
            .count()
            == 3
    );

    // Wipe ALL files inside cloud-a to simulate complete primary cloud outage
    std::fs::remove_dir_all(&cloud_a_dir).expect("wipe cloud-a");
    std::fs::create_dir_all(&cloud_a_dir).expect("recreate empty cloud-a root");
    assert!(collect_relative_files(&cloud_a_dir).is_empty());

    // Dehydrate local cache and read entire multi-chunk file back from surviving cloud-b
    drive
        .dehydrate_path("/Backups/vault_snapshot.bin")
        .await
        .expect("dehydrate");
    assert_eq!(engine.cache().used_ram_bytes(), 0);

    let recovered = read_entire_file_via_drive(&drive, file.inode, total_len as u64)
        .await
        .expect("seamless failover recovery from surviving cloud-b");
    assert_eq!(recovered, payload);
}

#[tokio::test]
async fn e2e_quota_pooled_spillover_reassembly() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_c_dir = tmp.path().join("cloud-c");
    let cloud_d_dir = tmp.path().join("cloud-d");

    let cap_c = 9 * 1024 * 1024u64;
    let cap_d = 20 * 1024 * 1024u64;

    let backend_c =
        CloudBackend::from_config(&local_fs_backend_config("cloud-c", &cloud_c_dir, Some(cap_c)))
            .expect("cloud-c");
    let backend_d =
        CloudBackend::from_config(&local_fs_backend_config("cloud-d", &cloud_d_dir, Some(cap_d)))
            .expect("cloud-d");

    let router = Arc::new(
        StorageRouter::new(
            [backend_c, backend_d],
            RoutingPolicy::QuotaPooled {
                pool_backends: vec!["cloud-c".to_owned(), "cloud-d".to_owned()],
            },
        )
        .expect("quota pooled router"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let passphrase = RedactedSecret::new("e2e-quota-pooled-passphrase-2026");
    let header = crypto
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init_vault");

    let engine = make_sync_engine(tmp.path(), "pooled-device", crypto, router.clone());
    engine
        .publish_vault_header(&header)
        .await
        .expect("publish header");

    let drive = MockDrive::new(Arc::clone(&engine) as Arc<dyn VfsBackend>);
    let file = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "pooled_archive.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create pooled_archive.bin");

    // > 9.5 MiB (3 chunks: 4 MiB + 4 MiB + ~1.75 MiB) -> forces spillover from 9 MiB cloud-c to cloud-d
    let total_len = 9 * 1024 * 1024 + 768 * 1024;
    let payload = build_deterministic_payload(total_len, 0x99);
    stream_write_file(drive.backend().as_ref(), file.inode, &payload, 512 * 1024).await;
    drive.backend().flush(file.inode).await.expect("flush pooled");

    let c_blobs: Vec<_> = collect_relative_files(&cloud_c_dir)
        .into_iter()
        .filter(|(k, _)| k.starts_with("blobs/"))
        .collect();
    let d_blobs: Vec<_> = collect_relative_files(&cloud_d_dir)
        .into_iter()
        .filter(|(k, _)| k.starts_with("blobs/"))
        .collect();

    assert!(
        !c_blobs.is_empty(),
        "cloud-c must hold initial encrypted blobs before hitting 9 MiB cap"
    );
    assert!(
        !d_blobs.is_empty(),
        "cloud-d must receive spillover .zv blob(s) when cloud-c fills up"
    );
    assert_eq!(c_blobs.len() + d_blobs.len(), 3);
    assert!(
        router.backend("cloud-c").expect("cloud-c").used_bytes() <= cap_c,
        "cloud-c must strictly respect its 9 MiB quota cap"
    );

    drive
        .dehydrate_path("/pooled_archive.bin")
        .await
        .expect("dehydrate");
    let reassembled = read_entire_file_via_drive(&drive, file.inode, total_len as u64)
        .await
        .expect("reassemble spilled file across cloud-c and cloud-d");
    assert_eq!(reassembled, payload);
}

#[tokio::test]
async fn e2e_concurrent_device_conflict_preservation() {
    let tmp = TempDir::new().expect("tempdir");
    let shared_cloud_dir = tmp.path().join("shared-cloud");

    let backend = CloudBackend::from_config(&local_fs_backend_config(
        "shared-fs",
        &shared_cloud_dir,
        None,
    ))
    .expect("shared-fs");
    let shared_router = Arc::new(
        StorageRouter::new(
            [backend],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "shared-fs".to_owned(),
            },
        )
        .expect("shared router"),
    );

    let passphrase = RedactedSecret::new("e2e-multi-device-conflict-passphrase-2026");

    // Device 1: device-win initializes vault and uploads /Shared/budget.xlsx (v1)
    let crypto_win = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto win"));
    let header = crypto_win
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .expect("init vault on device-win");

    let dev_win = make_sync_engine(tmp.path(), "device-win", crypto_win, shared_router.clone());
    dev_win
        .publish_vault_header(&header)
        .await
        .expect("publish vault/header.zvh");

    // Device 2: device-arch fetches remote vault/header.zvh and unlocks independently
    let fetched_header = SyncEngine::fetch_vault_header(shared_router.as_ref())
        .await
        .expect("fetch vault/header.zvh");
    let crypto_arch = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto arch"));
    crypto_arch
        .unlock_with_passphrase(&fetched_header, &passphrase)
        .await
        .expect("unlock device-arch with passphrase");
    let dev_arch = make_sync_engine(tmp.path(), "device-arch", crypto_arch, shared_router.clone());

    // device-win creates /Shared/budget.xlsx (v1) and pushes remotely
    let shared_dir_win = dev_win
        .mkdir(ROOT_INODE, "Shared", 0o755)
        .await
        .expect("mkdir /Shared");
    let budget_win = dev_win
        .create_entry(CreateEntrySpec {
            parent_inode: shared_dir_win.inode,
            name: "budget.xlsx".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create /Shared/budget.xlsx");
    let v1_payload = b"Q1-2026-BUDGET-V1-INITIAL-BASELINE";
    dev_win
        .write_range(budget_win.inode, 0, v1_payload)
        .await
        .expect("write v1");
    dev_win.flush(budget_win.inode).await.expect("flush v1");

    // device-arch pulls v1 manifest
    let pull_report = dev_arch.sync_once().await.expect("device-arch pulls v1");
    assert_eq!(pull_report.pulled_revision, Some(1));
    let budget_arch_v1 = dev_arch
        .resolve_path("/Shared/budget.xlsx")
        .await
        .expect("resolve /Shared/budget.xlsx on device-arch");

    // device-arch edits locally offline (DirtyLocal, not pushed yet)
    let arch_local_payload = b"ARCH-OFFLINE-EDIT-2026-DO-NOT-LOSE-THIS-VERSION!";
    dev_arch
        .write_range(budget_arch_v1.inode, 0, arch_local_payload)
        .await
        .expect("offline local edit on device-arch");
    assert_eq!(
        dev_arch
            .get_xattr_state(budget_arch_v1.inode)
            .await
            .expect("dirty state"),
        HydrationState::DirtyLocal
    );

    // Meanwhile device-win updates and pushes v2 remotely
    let win_v2_payload = b"WIN-AUTHORITATIVE-V2-UPDATED-SPREADSHEET-DATA";
    dev_win
        .write_range(budget_win.inode, 0, win_v2_payload)
        .await
        .expect("write v2 on device-win");
    dev_win.flush(budget_win.inode).await.expect("flush v2 on device-win");

    // device-arch runs sync_once() -> conflict resolution preserves both versions!
    let conflict_report = dev_arch.sync_once().await.expect("device-arch sync_once");
    assert_eq!(conflict_report.conflicts_resolved, 1);
    assert!(conflict_report.published_revision.is_some());

    let conflicts = dev_arch
        .metadata()
        .list_conflicts()
        .await
        .expect("list_conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].original_path, "/Shared/budget.xlsx");
    assert!(
        conflicts[0]
            .conflict_path
            .starts_with("/Shared/budget (conflict-device-arch-"),
        "unexpected conflict path: {}",
        conflicts[0].conflict_path
    );
    assert!(conflicts[0].conflict_path.ends_with(").xlsx"));

    // Verify both copies on device-arch after dehydration
    let arch_winner = dev_arch
        .resolve_path("/Shared/budget.xlsx")
        .await
        .expect("winner path on arch");
    let arch_conflict = dev_arch
        .resolve_path(&conflicts[0].conflict_path)
        .await
        .expect("conflict copy on arch");
    assert_ne!(arch_winner.file_id, arch_conflict.file_id);

    dev_arch.dehydrate(arch_winner.inode).await.expect("dehydrate winner");
    dev_arch
        .dehydrate(arch_conflict.inode)
        .await
        .expect("dehydrate conflict copy");

    assert_eq!(
        dev_arch
            .read_range(arch_winner.inode, 0, 256)
            .await
            .expect("read remote v2 on arch")
            .as_ref(),
        win_v2_payload
    );
    assert_eq!(
        dev_arch
            .read_range(arch_conflict.inode, 0, 256)
            .await
            .expect("read conflict copy on arch")
            .as_ref(),
        arch_local_payload
    );

    // Verify device-win pulls the merged manifest and can decrypt the preserved conflict copy from remote storage
    let win_pull = dev_win.sync_once().await.expect("device-win pulls merged manifest");
    assert!(win_pull.pulled_revision.is_some());

    let win_v2_node = dev_win
        .resolve_path("/Shared/budget.xlsx")
        .await
        .expect("budget.xlsx on win");
    let win_conflict_node = dev_win
        .resolve_path(&conflicts[0].conflict_path)
        .await
        .expect("conflict copy on win");

    dev_win.dehydrate(win_v2_node.inode).await.expect("dehydrate win v2");
    dev_win
        .dehydrate(win_conflict_node.inode)
        .await
        .expect("dehydrate win conflict copy");

    assert_eq!(
        dev_win
            .read_range(win_v2_node.inode, 0, 256)
            .await
            .expect("read v2 on win")
            .as_ref(),
        win_v2_payload
    );
    assert_eq!(
        dev_win
            .read_range(win_conflict_node.inode, 0, 256)
            .await
            .expect("read conflict copy on win")
            .as_ref(),
        arch_local_payload
    );
}

#[tokio::test]
async fn e2e_full_daemon_ipc_production_stack_lifecycle() {
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("daemon-state");
    let remote_dir = tmp.path().join("remote-cloud");
    let mount_dir = tmp.path().join("mount-root");
    std::fs::create_dir_all(&mount_dir).expect("create mount_dir");

    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(true))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .with_sync_factory(Arc::new(CoreSyncEngineFactory::new()))
            .build()
            .expect("build production DaemonRuntime"),
    );

    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("parse loopback addr");
    let server = IpcServer::bind(IpcEndpoint::TcpLoopback(loopback))
        .await
        .expect("bind TCP loopback IPC server");
    let endpoint = server.endpoint().clone();

    let rt_handler = Arc::clone(&runtime);
    let server_task = tokio::spawn(async move {
        server
            .serve_with_shutdown(
                move |req| {
                    let rt = Arc::clone(&rt_handler);
                    async move { rt.handle_request(req).await }
                },
                std::future::pending::<()>(),
            )
            .await
            .expect("IPC server exits cleanly");
    });

    let client = IpcClient::new(endpoint);
    client.ping().await.expect("Ping");

    // 1. InitVault
    let passphrase = "daemon-e2e-production-passphrase-2026".to_owned();
    let init_resp = client
        .request(&DaemonRequest::InitVault {
            passphrase: passphrase.clone(),
        })
        .await
        .expect("InitVault IPC");
    assert!(
        matches!(init_resp, DaemonResponse::Ok { .. }),
        "unexpected InitVault response: {init_resp:?}"
    );
    assert!(state_dir.join("vault.zvh").exists());
    assert!(state_dir.join("metadata.db").exists());

    // 2. AddRemote
    let add_resp = client
        .request(&DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "cloud-local".to_owned(),
            kind: "fs".to_owned(),
            root: remote_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(128 * 1024 * 1024),
            policy: Some("pooled".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await
        .expect("AddRemote IPC");
    assert!(
        matches!(add_resp, DaemonResponse::Ok { .. }),
        "unexpected AddRemote response: {add_resp:?}"
    );
    let remotes_json =
        std::fs::read_to_string(state_dir.join("remotes.json")).expect("read remotes.json");
    assert!(!remotes_json.contains(&passphrase));

    // 3. Mount
    let mount_resp = client
        .request(&DaemonRequest::Mount {
            mount_point: mount_dir.to_string_lossy().into_owned(),
        })
        .await
        .expect("Mount IPC");
    assert!(
        matches!(mount_resp, DaemonResponse::Ok { .. }),
        "unexpected Mount response: {mount_resp:?}"
    );

    // 4. Status
    let status_resp = client
        .request(&DaemonRequest::Status)
        .await
        .expect("Status IPC");
    match status_resp {
        DaemonResponse::Status(report) => {
            assert!(report.vault_id.is_some());
            assert!(report.unlocked);
            assert!(report.mounted);
            assert_eq!(report.remotes.len(), 1);
            assert_eq!(report.remotes[0].id, "cloud-local");
            assert_eq!(
                report.pooled_quota.as_ref().map(|q| q.total_bytes),
                Some(128 * 1024 * 1024)
            );
        }
        other => panic!("unexpected Status response: {other:?}"),
    }

    // 5. SyncNow
    let sync_resp = client
        .request(&DaemonRequest::SyncNow)
        .await
        .expect("SyncNow IPC");
    assert!(
        matches!(sync_resp, DaemonResponse::Ok { .. }),
        "unexpected SyncNow response: {sync_resp:?}"
    );

    // 6. LockVault
    let lock_resp = client
        .request(&DaemonRequest::LockVault)
        .await
        .expect("LockVault IPC");
    assert!(
        matches!(lock_resp, DaemonResponse::Ok { .. }),
        "unexpected LockVault response: {lock_resp:?}"
    );

    let locked_status = client
        .request(&DaemonRequest::Status)
        .await
        .expect("Status after LockVault");
    match locked_status {
        DaemonResponse::Status(report) => {
            assert!(!report.unlocked);
            assert!(!report.mounted);
        }
        other => panic!("unexpected locked Status response: {other:?}"),
    }

    // 7. Shutdown
    let shutdown_resp = client
        .request(&DaemonRequest::Shutdown)
        .await
        .expect("Shutdown IPC");
    assert!(
        matches!(shutdown_resp, DaemonResponse::Ok { .. }),
        "unexpected Shutdown response: {shutdown_resp:?}"
    );

    server_task.await.expect("IPC server task join");
}
