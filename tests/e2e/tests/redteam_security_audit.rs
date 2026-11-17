//! Red-team adversarial security & protocol-invariant tests for Zerovault.
//!
//! Uses real `AwsLcCryptoEngine`, `SqliteMetadataStore`, `CloudBackend`/`StorageRouter`,
//! `SyncEngine`, `OAuthPkceAuthenticator`, and `DaemonRuntime` IPC servers.

use std::io::Cursor;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use zerovault_core::{
    DEFAULT_MAX_RAM_CACHE_BYTES, SqliteMetadataStore, SyncEngine, SyncEngineConfig,
};
use zerovault_crypto::AwsLcCryptoEngine;
use zerovault_daemon::{
    CoreSyncEngineFactory, DaemonRuntime, DaemonStateConfig, IpcClient, IpcEndpoint, IpcServer,
    read_frame, validate_frame_len,
};
use zerovault_storage::{
    CloudBackend, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenBundle, StorageRouter,
    build_ssrf_safe_http_client, constant_time_csrf_eq,
};
use zerovault_types::mocks::InMemorySecretStore;
use zerovault_types::{
    AddRemoteParams, BackendConfig, BackendKind, BlobObjectKey, CreateEntrySpec, CryptoEngine,
    DaemonRequest, DaemonResponse, DekBytes, KdfParams, MAX_IPC_FRAME_BYTES,
    MANIFEST_HEAD_OBJECT_KEY, MetadataStore, PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RedactedSecret,
    RoutingPolicy, StorageRouterTrait, VAULT_HEADER_LEN, VaultHeader, VaultManifest, VfsBackend,
    ZeroVaultError,
};

fn fs_cfg(id: &str, root: &Path) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: root.to_string_lossy().into_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes: None,
        min_free_reserve_bytes: 0,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

fn make_engine(
    dir: &Path,
    device: &str,
    crypto: Arc<dyn CryptoEngine>,
    storage: Arc<dyn StorageRouterTrait>,
) -> Arc<SyncEngine> {
    let meta = Arc::new(
        SqliteMetadataStore::open(dir.join(format!("{device}.db"))).expect("open sqlite WAL"),
    );
    let cfg = SyncEngineConfig {
        staging_dir: dir.join(format!("stage-{device}")),
        device_id: device.to_owned(),
        max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
        max_concurrent_transfers: 8,
    };
    Arc::new(SyncEngine::new(cfg, meta, crypto, storage).expect("SyncEngine"))
}

#[tokio::test]
async fn redteam_cross_file_chunk_and_dek_transplant_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_dir = tmp.path().join("cloud");
    let backend = CloudBackend::from_config(&fs_cfg("cloud", &cloud_dir)).expect("backend");
    let router = Arc::new(
        StorageRouter::new(
            [backend],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "cloud".to_owned(),
            },
        )
        .expect("router"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let _hdr = crypto
        .init_vault(
            &RedactedSecret::new("redteam-transplant-passphrase-2026"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init vault");

    // 1. Cross-file WrappedDek transplant fails closed via ZV-DEK-V1 || file_id AAD.
    let file_id_a = Uuid::new_v4();
    let file_id_b = Uuid::new_v4();
    let dek_a = crypto.generate_dek().expect("dek");
    let wrapped_a = crypto.wrap_dek(file_id_a, &dek_a).expect("wrap dek");
    let dek_err = crypto
        .unwrap_dek(file_id_b, &wrapped_a)
        .expect_err("transplanted WrappedDek must fail");
    assert!(dek_err.is_tamper());

    // 2. Cross-file remote .zv chunk transplant fails closed via ChunkAad.file_id binding.
    let engine = make_engine(tmp.path(), "rt-transplant", crypto, router);
    let f_a = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "alpha.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create alpha");
    let f_b = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "beta.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create beta");

    engine
        .write_range(f_a.inode, 0, b"ALPHA-SECRET-BYTES")
        .await
        .expect("write alpha");
    engine
        .write_range(f_b.inode, 0, b"BETA-SECRET-BYTES!")
        .await
        .expect("write beta");
    engine.sync_once().await.expect("sync both files");

    let chunks_a = engine.metadata().list_chunks(f_a.inode).await.expect("chunks a");
    let chunks_b = engine.metadata().list_chunks(f_b.inode).await.expect("chunks b");
    let key_a = BlobObjectKey::from_uuid(chunks_a[0].blob_id);
    let key_b = BlobObjectKey::from_uuid(chunks_b[0].blob_id);

    // Replace beta's remote blob with alpha's valid encrypted chunk 0 blob.
    let alpha_blob = std::fs::read(cloud_dir.join(key_a.as_str())).expect("read alpha blob");
    std::fs::write(cloud_dir.join(key_b.as_str()), &alpha_blob).expect("transplant blob");

    engine.dehydrate(f_b.inode).await.expect("dehydrate beta");
    let read_err = engine
        .read_range(f_b.inode, 0, 64)
        .await
        .expect_err("transplanted cross-file chunk must fail closed");
    assert!(read_err.is_tamper());
}

#[tokio::test]
async fn redteam_kdf_downgrade_exact_4mib_final_flag_and_manifest_rev_tamper_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_dir = tmp.path().join("cloud");
    let backend = CloudBackend::from_config(&fs_cfg("cloud", &cloud_dir)).expect("backend");
    let router = Arc::new(
        StorageRouter::new(
            [backend],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "cloud".to_owned(),
            },
        )
        .expect("router"),
    );

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let header = crypto
        .init_vault(
            &RedactedSecret::new("redteam-downgrade-passphrase-2026"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init vault");

    // 1. KDF policy floor downgrade in wire ZVH1 header must fail closed.
    let raw_hdr = header.encode();
    assert_eq!(raw_hdr.len(), VAULT_HEADER_LEN);
    for (offset, weak_val) in [(56usize, 32_768u32), (60, 2u32), (64, 2u32)] {
        let mut bad_hdr = raw_hdr;
        bad_hdr[offset..offset + 4].copy_from_slice(&weak_val.to_le_bytes());
        assert!(matches!(
            VaultHeader::decode(&bad_hdr),
            Err(ZeroVaultError::KdfPolicyViolation { .. })
        ));
    }

    // 2. Exact 4 MiB single-chunk file: flipping `is_final_chunk` flag bit (0x01 -> 0x00)
    // leaves ChunkHeader size invariants valid (4 MiB non-final is valid size), forcing
    // ChunkAad GCM tag verification to detect the tail-truncation attempt!
    let engine = make_engine(tmp.path(), "rt-flags", crypto.clone(), router.clone());
    let file = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "exact_4mib.bin".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create exact_4mib");
    let exact_4mib = vec![0xA5u8; PLAINTEXT_CHUNK_SIZE];
    engine
        .write_range(file.inode, 0, &exact_4mib)
        .await
        .expect("write 4 MiB");
    engine.flush(file.inode).await.expect("flush 4 MiB");

    let chunks = engine.metadata().list_chunks(file.inode).await.expect("chunks");
    assert_eq!(chunks.len(), 1);
    let blob_path = cloud_dir.join(BlobObjectKey::from_uuid(chunks[0].blob_id).as_str());
    let mut blob_bytes = std::fs::read(&blob_path).expect("read blob");
    assert_eq!(blob_bytes[5], 0x01, "expected final chunk flag bit set");
    blob_bytes[5] = 0x00; // clear is_final_chunk flag
    std::fs::write(&blob_path, &blob_bytes).expect("write tampered flag blob");

    engine.dehydrate(file.inode).await.expect("dehydrate");
    let flag_err = engine
        .read_range(file.inode, 0, 4096)
        .await
        .expect_err("clearing is_final_chunk on 4 MiB chunk must fail AEAD");
    assert!(flag_err.is_tamper());

    // 3. Tampering unencrypted revision field in ZVM1 manifest header fails AAD verification.
    let head_bytes = router
        .get_blob(MANIFEST_HEAD_OBJECT_KEY, &[])
        .await
        .expect("get sealed head manifest");
    let mut tampered_rev = head_bytes.to_vec();
    tampered_rev[24] ^= 0x01; // offset 24..32 is revision LE in ZVM1
    let rev_err = crypto
        .open_manifest(&tampered_rev)
        .expect_err("tampered ZVM1 revision AAD must fail");
    assert!(rev_err.is_tamper());
    let _ = std::any::type_name::<VaultManifest>();
}

#[tokio::test]
async fn redteam_storage_router_and_vfs_path_traversal_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let cloud_dir = tmp.path().join("cloud");
    let backend = CloudBackend::from_config(&fs_cfg("cloud", &cloud_dir)).expect("backend");
    let router = Arc::new(
        StorageRouter::new(
            [backend],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "cloud".to_owned(),
            },
        )
        .expect("router"),
    );

    let malicious_keys = [
        "../vault/header.zvh",
        "Finance/Confidential/tax.pdf",
        "blobs/aa/bb/tax.pdf",
        "manifests/secret_name.zvm",
        "blobs/aa/bb/../../vault/header.zvh",
        "blobs/AA/BB/00000000-0000-0000-0000-000000000000.zv",
        "manifests/head.zvm\0",
    ];
    for key in malicious_keys {
        assert!(matches!(
            router.put_blob("/hint", key, bytes::Bytes::from_static(b"x")).await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
        assert!(matches!(
            router.get_blob(key, &[]).await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
        assert!(matches!(
            router.stat_object(key, &[]).await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
        assert!(matches!(
            router.delete_blob(key, &[]).await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
        assert!(matches!(
            router
                .put_manifest_cas(key, bytes::Bytes::from_static(b"x"), None)
                .await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
    }

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let _ = crypto
        .init_vault(
            &RedactedSecret::new("redteam-path-passphrase-2026"),
            KdfParams::interactive_production(),
        )
        .await
        .expect("init");
    let engine = make_engine(tmp.path(), "rt-paths", crypto, router);

    for bad_name in ["", ".", "..", "a/b", r"a\b", "bad\0file"] {
        assert!(matches!(
            engine
                .create_entry(CreateEntrySpec {
                    parent_inode: ROOT_INODE,
                    name: bad_name.to_owned(),
                    mode: 0o644,
                })
                .await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
        assert!(matches!(
            engine.mkdir(ROOT_INODE, bad_name, 0o755).await,
            Err(ZeroVaultError::InvalidPath(_))
        ));
    }
    assert!(matches!(
        engine.resolve_path("/Finance/../../etc/passwd").await,
        Err(ZeroVaultError::InvalidPath(_))
    ));
}

#[tokio::test]
async fn redteam_secret_redaction_and_oauth_ssrf_csrf_guards() {
    let secret_pass = "UltraSecretPassphrase_999!";
    let secret_tok = "ya29.super_secret_oauth_access_token";
    let secret_ref = "1//super_secret_oauth_refresh_token";
    let secret_csec = "GOCSPX-super_secret_client_secret";

    let rs = RedactedSecret::new(secret_pass);
    let dek = DekBytes::from_array([0x5Cu8; 32]);
    let add_params = AddRemoteParams {
        id: "gdrive-1".to_owned(),
        kind: "gdrive".to_owned(),
        root: "/".to_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes: None,
        policy: None,
        prefix: None,
        username: None,
        secret: Some(secret_tok.to_owned()),
    };
    let req_init = DaemonRequest::InitVault {
        passphrase: secret_pass.to_owned(),
    };
    let req_add = DaemonRequest::AddRemote(Box::new(add_params.clone()));
    let oauth_cfg = OAuthProviderConfig::for_preset(
        OAuthProviderPreset::GoogleDrive,
        "public-client-id",
        Some(RedactedSecret::new(secret_csec)),
    );
    let bundle = OAuthTokenBundle {
        provider: OAuthProviderPreset::GoogleDrive,
        access_token: RedactedSecret::new(secret_tok),
        refresh_token: Some(RedactedSecret::new(secret_ref)),
        token_type: "bearer".to_owned(),
        expires_at: None,
        scopes: vec![],
        client_id: Some("public-client-id".to_owned()),
        client_secret: Some(RedactedSecret::new(secret_csec)),
    };

    for dbg_str in [
        format!("{rs:?}"),
        format!("{dek:?}"),
        format!("{add_params:?}"),
        format!("{req_init:?}"),
        format!("{req_add:?}"),
        format!("{oauth_cfg:?}"),
        format!("{bundle:?}"),
    ] {
        assert!(!dbg_str.contains(secret_pass));
        assert!(!dbg_str.contains(secret_tok));
        assert!(!dbg_str.contains(secret_ref));
        assert!(!dbg_str.contains(secret_csec));
        assert!(!dbg_str.contains("5c"));
        assert!(dbg_str.contains("[REDACTED]"));
    }

    // Constant-time CSRF verification
    assert!(constant_time_csrf_eq("csrf-state-abc", "csrf-state-abc"));
    assert!(!constant_time_csrf_eq("csrf-state-abc", "csrf-state-abC"));
    assert!(!constant_time_csrf_eq("csrf-state-abc", "csrf"));

    // SSRF-safe HTTP client must NOT follow 302 redirects
    let trap_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind trap");
    let trap_addr = trap_listener.local_addr().expect("trap addr");
    let trap_hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trap_hit_bg = Arc::clone(&trap_hit);
    let _trap_task = tokio::spawn(async move {
        if let Ok((mut s, _)) = trap_listener.accept().await {
            trap_hit_bg.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let redir_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind redir");
    let redir_addr = redir_listener.local_addr().expect("redir addr");
    let redir_task = tokio::spawn(async move {
        let (mut s, _) = redir_listener.accept().await.expect("accept redir");
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).await;
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{trap_addr}/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        s.write_all(resp.as_bytes()).await.expect("write 302");
        let _ = s.shutdown().await;
    });

    let client = build_ssrf_safe_http_client().expect("build ssrf safe client");
    let res = client
        .get(format!("http://{redir_addr}/oauth"))
        .send()
        .await
        .expect("302 response returned without following");
    assert_eq!(res.status().as_u16(), 302);
    redir_task.await.expect("redir task");
    assert!(
        !trap_hit.load(std::sync::atomic::Ordering::SeqCst),
        "SSRF redirect target must never be contacted"
    );
}

#[tokio::test]
async fn redteam_daemon_ipc_frame_bounds_and_os_native_pipe_or_uds_lifecycle() {
    // 1. Frame length bounds fail closed before buffer allocation
    assert!(validate_frame_len(0).is_err());
    assert!(validate_frame_len(MAX_IPC_FRAME_BYTES + 1).is_err());
    assert!(validate_frame_len(MAX_IPC_FRAME_BYTES).is_ok());

    let mut oversized_hdr = Cursor::new(((MAX_IPC_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec());
    assert!(matches!(
        read_frame(&mut oversized_hdr).await,
        Err(ZeroVaultError::IpcError(_))
    ));

    // 2. Non-loopback TCP IPC addresses must be rejected fail-closed
    assert!(IpcEndpoint::parse("tcp://0.0.0.0:9000").is_err());
    assert!(IpcEndpoint::parse("tcp://10.0.0.5:9000").is_err());

    // 3. OS-native Named Pipe (Windows) or 0700/0600 UDS (Unix) full auth/lock/shutdown check
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("state");

    #[cfg(target_os = "windows")]
    let endpoint = IpcEndpoint::NamedPipe(format!(r"\\.\pipe\zerovaultd-rt-{}", Uuid::new_v4().as_simple()));
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(tmp.path().join("run").join("zerovaultd.sock"));
    #[cfg(not(any(target_os = "windows", unix)))]
    let endpoint = IpcEndpoint::TcpLoopback("127.0.0.1:0".parse::<SocketAddr>().expect("addr"));

    let _unused_addr: Option<SocketAddr> = None;

    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(state_dir).with_mock_vfs(true))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .with_sync_factory(Arc::new(CoreSyncEngineFactory::new()))
            .build()
            .expect("build runtime"),
    );

    let server = IpcServer::bind(endpoint).await.expect("bind native IPC");
    let bound_ep = server.endpoint().clone();

    let rt_dispatch = Arc::clone(&runtime);
    let server_task = tokio::spawn(async move {
        server
            .serve_with_shutdown(
                move |req| {
                    let rt = Arc::clone(&rt_dispatch);
                    async move { rt.handle_request(req).await }
                },
                std::future::pending::<()>(),
            )
            .await
            .expect("serve");
    });

    let client = IpcClient::new(bound_ep);
    client.ping().await.expect("ping");

    let pass = "native-ipc-passphrase-2026".to_owned();
    assert!(matches!(
        client
            .request(&DaemonRequest::InitVault {
                passphrase: pass.clone(),
            })
            .await
            .expect("init"),
        DaemonResponse::Ok { .. }
    ));

    assert!(matches!(
        client.request(&DaemonRequest::LockVault).await.expect("lock"),
        DaemonResponse::Ok { .. }
    ));

    // Wrong passphrase must fail closed with invalid_passphrase
    let bad_unlock = client
        .request(&DaemonRequest::UnlockVault {
            passphrase: "wrong-password".to_owned(),
        })
        .await
        .expect("bad unlock");
    assert!(matches!(
        bad_unlock,
        DaemonResponse::Error { ref code, .. } if code == "invalid_passphrase"
    ));

    // Correct passphrase succeeds
    assert!(matches!(
        client
            .request(&DaemonRequest::UnlockVault { passphrase: pass })
            .await
            .expect("good unlock"),
        DaemonResponse::Ok { .. }
    ));

    assert!(matches!(
        client.request(&DaemonRequest::Shutdown).await.expect("shutdown"),
        DaemonResponse::Ok { .. }
    ));
    server_task.await.expect("join server");
}

#[tokio::test]
async fn redteam_remediation_mirrored_cas_rollback_locked_cache_pool_and_bounded_get() {
    let tmp = TempDir::new().expect("tempdir");
    let mirror_a = tmp.path().join("mirror-a");
    let mirror_b = tmp.path().join("mirror-b");
    let staging = tmp.path().join("staging");

    let crypto = Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"));
    let pass = RedactedSecret::new("remediation-passphrase-2026");
    let _hdr = crypto
        .init_vault(&pass, KdfParams::interactive_production())
        .await
        .expect("init");

    let backend_a = CloudBackend::from_config(&fs_cfg("mirror-a", &mirror_a))
        .expect("backend a");
    let backend_b = CloudBackend::from_config(&fs_cfg("mirror-b", &mirror_b))
        .expect("backend b");
    let router = Arc::new(
        StorageRouter::new(
            vec![backend_a, backend_b],
            RoutingPolicy::Mirrored {
                backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router"),
    );

    let meta = Arc::new(SqliteMetadataStore::open_in_memory().expect("meta"));
    let engine = Arc::new(
        SyncEngine::new(
            SyncEngineConfig {
                staging_dir: staging,
                device_id: "remediation-host".to_owned(),
                max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
                // [M-02] Verify max_concurrent_transfers == 1 does NOT deadlock!
                max_concurrent_transfers: 1,
            },
            meta.clone(),
            crypto.clone(),
            router.clone(),
        )
        .expect("engine"),
    );

    // 1. [H-02] & [M-01] & [M-02]: Mirrored multi-revision manifest CAS (rev 1 -> 2 -> 3)
    // plus concurrently dirty sibling file (`unflushed.txt`) must not leak incomplete chunks.
    let file_a = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "ledger.txt".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create ledger");
    let file_b = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "unflushed.txt".to_owned(),
            mode: 0o644,
        })
        .await
        .expect("create unflushed");

    engine
        .write_range(file_a.inode, 0, b"rev1-data")
        .await
        .expect("write rev1");
    engine
        .write_range(file_b.inode, 0, b"still-dirty-in-staging")
        .await
        .expect("write dirty b");
    engine.flush(file_a.inode).await.expect("flush rev 1");

    // Capture sealed rev 1 manifest from mirror-a before advancing to rev 2 & 3.
    let rev1_manifest_bytes = std::fs::read(mirror_a.join(MANIFEST_HEAD_OBJECT_KEY))
        .expect("read rev1 head.zvm");
    let rev1_opened = crypto
        .open_manifest(&rev1_manifest_bytes)
        .expect("open rev1");
    assert_eq!(rev1_opened.revision, 1);
    // [M-01]: unflushed sibling `unflushed.txt` was NOT prematurely leaked with empty chunks!
    assert!(!rev1_opened.nodes.iter().any(|n| n.name == "unflushed.txt"));

    engine
        .write_range(file_a.inode, 0, b"rev2-data")
        .await
        .expect("write rev2");
    engine.flush(file_a.inode).await.expect("flush rev 2");

    // [M-01]: Also flush file_b as rev 3 over Mirrored RAID-1!
    engine.flush(file_b.inode).await.expect("flush rev 3");
    let (cur_rev, _etag) = meta.manifest_cursor().await.expect("cursor");
    assert_eq!(cur_rev, 3, "Mirrored CAS must advance cleanly to rev 3");

    // Stale CAS write must still fail with StorageConflict.
    let stale_res = router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            bytes::Bytes::from_static(b"stale"),
            Some("zv-mirror-cas:{\"mirror-a\":\"dead\",\"mirror-b\":\"beef\"}"),
        )
        .await;
    assert!(matches!(stale_res, Err(ZeroVaultError::StorageConflict(_))));

    // 2. [H-01] Rollback attack: adversary replaces remote head.zvm with genuine old rev 1 manifest.
    std::fs::write(mirror_a.join(MANIFEST_HEAD_OBJECT_KEY), &rev1_manifest_bytes)
        .expect("rollback mirror a");
    std::fs::write(mirror_b.join(MANIFEST_HEAD_OBJECT_KEY), &rev1_manifest_bytes)
        .expect("rollback mirror b");
    let rollback_err = engine.sync_once().await.expect_err("rollback must fail closed");
    assert!(matches!(rollback_err, ZeroVaultError::CryptoTamperDetected(_)));
    let (after_rev, _) = meta.manifest_cursor().await.expect("cursor intact");
    assert_eq!(after_rev, 3, "local cursor must not rewind on rollback");

    // 3. [M-03] Bounded get_object rejects oversized remote header (> 112 B for header.zvh).
    std::fs::create_dir_all(mirror_a.join("vault")).expect("mkdir vault");
    std::fs::write(mirror_a.join("vault/header.zvh"), vec![0xAAu8; 4096])
        .expect("oversized header");
    let header_backend = CloudBackend::from_config(&fs_cfg("mirror-a", &mirror_a))
        .expect("reopen a");
    let oversize_err = header_backend
        .get_object("vault/header.zvh")
        .await
        .expect_err("oversized header must fail before buffering");
    assert!(matches!(oversize_err, ZeroVaultError::InvalidWireFormat(_)));

    // 4. [H-03] Post-lock read_range / write_range MUST fail closed even on warm RAM cache.
    let warm = engine
        .read_range(file_a.inode, 0, 9)
        .await
        .expect("warm read while unlocked");
    assert_eq!(warm.as_ref(), b"rev2-data");

    crypto.lock_vault().await.expect("lock vault");
    assert!(matches!(
        engine.read_range(file_a.inode, 0, 9).await,
        Err(ZeroVaultError::VaultLocked)
    ));
    assert!(matches!(
        engine.write_range(file_a.inode, 0, b"nope").await,
        Err(ZeroVaultError::VaultLocked)
    ));
    assert_eq!(engine.cache().used_ram_bytes(), 0);
}
