use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing_subscriber::fmt::MakeWriter;
#[cfg(target_os = "windows")]
use uuid::Uuid;
use zerovault_crypto::AwsLcCryptoEngine;
use zerovault_types::mocks::{InMemorySecretStore, MockCryptoEngine, MockMetadataStore, MockVfsBackend};
use zerovault_types::{
    AddRemoteParams, ConflictRecord, DaemonRequest, DaemonResponse, EntryKind, HydrationState,
    MAX_IPC_FRAME_BYTES, MetadataStore, OAuthLoginParams, ROOT_INODE, RoutingPolicy, SecretStore,
    VfsBackend, ZeroVaultError,
};

use crate::{
    DaemonRuntime, DaemonStateConfig, IpcClient, IpcEndpoint, IpcServer, MockSyncEngineFactory,
    read_frame, validate_frame_len, write_frame,
};

#[derive(Clone, Default)]
struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedLogBuffer {
    fn contents(&self) -> String {
        let guard = self.0.lock().expect("log lock");
        String::from_utf8_lossy(&guard).into_owned()
    }
}

struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().expect("log lock");
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogBuffer {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter(Arc::clone(&self.0))
    }
}

async fn run_full_lifecycle_test(
    endpoint: IpcEndpoint,
    use_real_crypto: bool,
) -> (IpcEndpoint, TempDir, SharedLogBuffer) {
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let remote_dir = tmp.path().join("remote_fs");
    let mount_dir = tmp.path().join("mount");
    std::fs::create_dir_all(&mount_dir).expect("mkdir mount");

    let meta = Arc::new(MockMetadataStore::new());
    let vfs = Arc::new(MockVfsBackend::new());
    let seeded = vfs
        .seed_remote_file(ROOT_INODE, "secret-taxes.pdf", b"0123456789abcdef")
        .await
        .expect("seed remote file");
    assert_eq!(seeded.virtual_path, "/secret-taxes.pdf");

    let sync_factory = Arc::new(MockSyncEngineFactory::with_mocks(
        Arc::clone(&meta),
        Arc::clone(&vfs),
    ));
    let secret_store = Arc::new(InMemorySecretStore::default());
    let crypto: Arc<dyn zerovault_types::CryptoEngine> = if use_real_crypto {
        Arc::new(AwsLcCryptoEngine::new().expect("hw crypto"))
    } else {
        Arc::new(MockCryptoEngine::default())
    };

    let cfg = DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(true);
    let runtime = Arc::new(
        DaemonRuntime::builder(cfg)
            .with_crypto(crypto)
            .with_secret_store(secret_store)
            .with_sync_factory(sync_factory)
            .build()
            .expect("build runtime"),
    );

    let server = IpcServer::bind(endpoint).await.expect("bind ipc server");
    let bound_endpoint = server.endpoint().clone();

    let log_buf = SharedLogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _log_guard = tracing::subscriber::set_default(subscriber);

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
            .expect("serve ipc");
    });

    let client = IpcClient::new(bound_endpoint.clone());

    // 1. Ping
    client.ping().await.expect("ping");

    // 2. InitVault
    let passphrase = "correct-horse-super-secret-passphrase";
    let init_resp = client
        .request(&DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await
        .expect("init req");
    assert!(matches!(init_resp, DaemonResponse::Ok { .. }));
    assert!(state_dir.join("vault.zvh").exists());

    // 3. AddRemote (LocalFs + S3 with secret)
    let add_fs = client
        .request(&DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "local-1".to_owned(),
            kind: "fs".to_owned(),
            root: remote_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(512 * 1024 * 1024),
            policy: Some("pooled".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await
        .expect("add fs remote");
    assert!(matches!(add_fs, DaemonResponse::Ok { .. }));

    let secret_key = "ultra-secret-s3-key-do-not-leak";
    let add_s3 = client
        .request(&DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "s3-archive".to_owned(),
            kind: "s3".to_owned(),
            root: "vault".to_owned(),
            endpoint: Some("http://127.0.0.1:9000".to_owned()),
            bucket: Some("zerovault-bucket".to_owned()),
            region: Some("us-east-1".to_owned()),
            quota_limit_bytes: Some(1024 * 1024 * 1024),
            policy: Some("pooled".to_owned()),
            prefix: None,
            username: Some("AKIAEXAMPLE".to_owned()),
            secret: Some(secret_key.to_owned()),
        })))
        .await
        .expect("add s3 remote");
    assert!(matches!(add_s3, DaemonResponse::Ok { .. }));

    // Verify secrets and passphrases are NEVER persisted in plaintext inside remotes.json
    let remotes_json =
        std::fs::read_to_string(state_dir.join("remotes.json")).expect("read remotes.json");
    assert!(!remotes_json.contains(secret_key));
    assert!(!remotes_json.contains(passphrase));

    // 4. ListRemotes
    let list_resp = client
        .request(&DaemonRequest::ListRemotes)
        .await
        .expect("list remotes");
    match list_resp {
        DaemonResponse::Remotes(remotes) => {
            assert_eq!(remotes.len(), 2);
            assert_eq!(remotes[0].id, "local-1");
            assert_eq!(remotes[1].id, "s3-archive");
        }
        other => panic!("unexpected list remotes response: {other:?}"),
    }

    // 5. Mount via MockDrive
    let mount_resp = client
        .request(&DaemonRequest::Mount {
            mount_point: mount_dir.to_string_lossy().into_owned(),
        })
        .await
        .expect("mount");
    assert!(matches!(mount_resp, DaemonResponse::Ok { .. }));

    // 6. Pin
    let pin_resp = client
        .request(&DaemonRequest::Pin {
            virtual_path: "/secret-taxes.pdf".to_owned(),
        })
        .await
        .expect("pin");
    assert!(matches!(pin_resp, DaemonResponse::Ok { .. }));
    let attr_after_pin = vfs.getattr(seeded.inode).await.expect("getattr");
    assert!(attr_after_pin.pinned);
    assert_eq!(attr_after_pin.hydration, HydrationState::Pinned);

    // Dehydrate while pinned must fail cleanly
    let dehydrate_pinned = client
        .request(&DaemonRequest::Dehydrate {
            virtual_path: "/secret-taxes.pdf".to_owned(),
        })
        .await
        .expect("dehydrate pinned");
    assert!(matches!(
        dehydrate_pinned,
        DaemonResponse::Error { ref code, .. } if code == "pinned_dehydration_denied"
    ));

    // Unpin, then Dehydrate succeeds
    vfs.unpin(seeded.inode).await.expect("unpin");
    let dehydrate_resp = client
        .request(&DaemonRequest::Dehydrate {
            virtual_path: "/secret-taxes.pdf".to_owned(),
        })
        .await
        .expect("dehydrate");
    assert!(matches!(dehydrate_resp, DaemonResponse::Ok { .. }));
    let attr_after_dehydrate = vfs.getattr(seeded.inode).await.expect("getattr");
    assert_eq!(attr_after_dehydrate.hydration, HydrationState::OnlineOnly);

    // 7. SyncNow & Status
    let sync_resp = client
        .request(&DaemonRequest::SyncNow)
        .await
        .expect("sync now");
    assert!(matches!(sync_resp, DaemonResponse::Ok { .. }));

    let status_resp = client.request(&DaemonRequest::Status).await.expect("status");
    match status_resp {
        DaemonResponse::Status(report) => {
            assert!(report.vault_id.is_some());
            assert!(report.unlocked);
            assert!(report.mounted);
            assert_eq!(report.remotes.len(), 2);
            assert_eq!(
                report.pooled_quota.as_ref().map(|q| q.total_bytes),
                Some(512 * 1024 * 1024 + 1024 * 1024 * 1024)
            );
        }
        other => panic!("unexpected status response: {other:?}"),
    }

    // 8. LockVault
    let lock_resp = client
        .request(&DaemonRequest::LockVault)
        .await
        .expect("lock");
    assert!(matches!(lock_resp, DaemonResponse::Ok { .. }));

    let locked_status = client.request(&DaemonRequest::Status).await.expect("status");
    match locked_status {
        DaemonResponse::Status(report) => {
            assert!(!report.unlocked);
            assert!(!report.mounted);
        }
        other => panic!("unexpected locked status: {other:?}"),
    }

    // Unlock with wrong passphrase must fail closed
    let bad_unlock = client
        .request(&DaemonRequest::UnlockVault {
            passphrase: "wrong-passphrase".to_owned(),
        })
        .await
        .expect("bad unlock");
    assert!(matches!(
        bad_unlock,
        DaemonResponse::Error { ref code, .. } if code == "invalid_passphrase"
    ));

    // Unlock with valid passphrase succeeds
    let good_unlock = client
        .request(&DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await
        .expect("good unlock");
    assert!(matches!(good_unlock, DaemonResponse::Ok { .. }));

    // 9. Shutdown
    let shutdown_resp = client
        .request(&DaemonRequest::Shutdown)
        .await
        .expect("shutdown");
    assert!(matches!(shutdown_resp, DaemonResponse::Ok { .. }));

    server_task.await.expect("server join");

    let logs = log_buf.contents();
    assert!(!logs.contains(passphrase), "passphrase leaked into logs");
    assert!(!logs.contains(secret_key), "remote secret leaked into logs");
    assert!(
        !logs.contains("secret-taxes.pdf"),
        "plaintext vault path leaked into logs"
    );

    (bound_endpoint, tmp, log_buf)
}

#[tokio::test]
async fn tcp_loopback_full_daemon_lifecycle_and_real_crypto() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let _ = run_full_lifecycle_test(IpcEndpoint::TcpLoopback(addr), true).await;
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_named_pipe_full_daemon_lifecycle() {
    let pipe_name = format!(r"\\.\pipe\zerovaultd-test-{}", Uuid::new_v4().as_simple());
    let _ = run_full_lifecycle_test(IpcEndpoint::NamedPipe(pipe_name), false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn unix_domain_socket_permissions_and_lifecycle() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().expect("tempdir");
    let sock_dir = tmp.path().join("run");
    let sock_path = sock_dir.join("zerovaultd.sock");
    let endpoint = IpcEndpoint::UnixSocket(sock_path.clone());

    let runtime = Arc::new(
        DaemonRuntime::builder(
            DaemonStateConfig::new(tmp.path().join("state")).with_mock_vfs(true),
        )
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()
        .expect("runtime"),
    );

    let server = IpcServer::bind(endpoint.clone()).await.expect("bind uds");
    let dir_mode = std::fs::metadata(&sock_dir)
        .expect("dir meta")
        .permissions()
        .mode()
        & 0o777;
    let sock_mode = std::fs::metadata(&sock_path)
        .expect("sock meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(sock_mode, 0o600);

    let rt_dispatch = Arc::clone(&runtime);
    let task = tokio::spawn(async move {
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

    let client = IpcClient::new(endpoint);
    client.ping().await.expect("ping");
    let resp = client
        .request(&DaemonRequest::Shutdown)
        .await
        .expect("shutdown");
    assert!(matches!(resp, DaemonResponse::Ok { .. }));
    task.await.expect("join");
}

#[tokio::test]
async fn framing_rejects_zero_and_oversized_frames_fail_closed() {
    assert!(matches!(
        validate_frame_len(0),
        Err(ZeroVaultError::IpcError(_))
    ));
    assert!(matches!(
        validate_frame_len(MAX_IPC_FRAME_BYTES + 1),
        Err(ZeroVaultError::IpcError(_))
    ));
    assert!(validate_frame_len(MAX_IPC_FRAME_BYTES).is_ok());

    let zero_hdr = 0u32.to_be_bytes();
    let mut cursor = Cursor::new(zero_hdr.to_vec());
    assert!(matches!(
        read_frame(&mut cursor).await,
        Err(ZeroVaultError::IpcError(_))
    ));

    let oversized_hdr = ((MAX_IPC_FRAME_BYTES + 1) as u32).to_be_bytes();
    let mut oversized_cursor = Cursor::new(oversized_hdr.to_vec());
    assert!(matches!(
        read_frame(&mut oversized_cursor).await,
        Err(ZeroVaultError::IpcError(_))
    ));

    let mut sink = Vec::new();
    let huge = vec![0u8; MAX_IPC_FRAME_BYTES + 1];
    assert!(matches!(
        write_frame(&mut sink, &huge).await,
        Err(ZeroVaultError::IpcError(_))
    ));

    // Also verify a live IpcServer drops/rejects an oversized frame header without OOM.
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let server = IpcServer::bind(IpcEndpoint::TcpLoopback(addr))
        .await
        .expect("bind");
    let bound = server.endpoint().clone();

    let tmp = TempDir::new().expect("tempdir");
    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(tmp.path().join("s")).with_mock_vfs(true))
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()
            .expect("runtime"),
    );

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

    if let IpcEndpoint::TcpLoopback(bound_addr) = bound {
        let mut raw_stream = TcpStream::connect(bound_addr).await.expect("connect");
        raw_stream
            .write_all(&((MAX_IPC_FRAME_BYTES + 1024) as u32).to_be_bytes())
            .await
            .expect("write oversized hdr");
        raw_stream.flush().await.expect("flush");
        drop(raw_stream);
    }

    // Server remains healthy for valid subsequent clients.
    let client = IpcClient::new(bound);
    client.ping().await.expect("ping after rejected frame");
    let _ = client
        .request(&DaemonRequest::Shutdown)
        .await
        .expect("shutdown");
    server_task.await.expect("join");
}

#[test]
fn debug_formatting_redacts_secrets_and_rejects_non_loopback_tcp() {
    let params = AddRemoteParams {
        id: "s3".to_owned(),
        kind: "s3".to_owned(),
        root: "vault".to_owned(),
        endpoint: None,
        bucket: Some("bkt".to_owned()),
        region: None,
        quota_limit_bytes: None,
        policy: None,
        prefix: None,
        username: Some("access".to_owned()),
        secret: Some("super-secret-token-xyz".to_owned()),
    };
    let req = DaemonRequest::AddRemote(Box::new(params.clone()));
    assert!(!format!("{params:?}").contains("super-secret-token-xyz"));
    assert!(!format!("{req:?}").contains("super-secret-token-xyz"));

    let init = DaemonRequest::InitVault {
        passphrase: "my-secret-passphrase-123".to_owned(),
    };
    assert!(!format!("{init:?}").contains("my-secret-passphrase-123"));

    assert!(IpcEndpoint::parse("tcp://0.0.0.0:9000").is_err());
    assert!(IpcEndpoint::parse("tcp://192.168.1.50:9000").is_err());
    assert!(IpcEndpoint::parse("tcp://127.0.0.1:9000").is_ok());
}

#[tokio::test]
async fn default_runtime_wires_core_sync_engine_and_sqlite_wal() {
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let remote_dir = tmp.path().join("remote_fs");
    let mount_dir = tmp.path().join("mount");
    std::fs::create_dir_all(&mount_dir).expect("mkdir mount");

    let cfg = DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(true);
    let runtime = Arc::new(
        DaemonRuntime::builder(cfg)
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()
            .expect("build production default runtime"),
    );

    let init = runtime
        .handle_request(DaemonRequest::InitVault {
            passphrase: "gate2-production-passphrase".to_owned(),
        })
        .await;
    assert!(matches!(init, DaemonResponse::Ok { .. }));
    assert!(state_dir.join("metadata.db").exists());

    let add = runtime
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "local-cloud".to_owned(),
            kind: "fs".to_owned(),
            root: remote_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(64 * 1024 * 1024),
            policy: Some("pooled".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await;
    assert!(matches!(add, DaemonResponse::Ok { .. }));

    let mount = runtime
        .handle_request(DaemonRequest::Mount {
            mount_point: mount_dir.to_string_lossy().into_owned(),
        })
        .await;
    assert!(matches!(mount, DaemonResponse::Ok { .. }));

    let sync = runtime.handle_request(DaemonRequest::SyncNow).await;
    assert!(matches!(sync, DaemonResponse::Ok { .. }));

    let status = runtime.handle_request(DaemonRequest::Status).await;
    match status {
        DaemonResponse::Status(report) => {
            assert!(report.unlocked);
            assert!(report.mounted);
            assert_eq!(report.remotes.len(), 1);
        }
        other => panic!("expected Status response, got {other:?}"),
    }

    let lock = runtime.handle_request(DaemonRequest::LockVault).await;
    assert!(matches!(lock, DaemonResponse::Ok { .. }));
}

#[tokio::test]
async fn gui_file_manager_remote_policy_and_conflict_rpcs_end_to_end() {
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let cloud_a = tmp.path().join("cloud_a");
    let cloud_b = tmp.path().join("cloud_b");
    let auto_mount_dir = tmp.path().join("auto_created_mount");
    let src_file = tmp.path().join("payload_5mib.bin");
    let exported_file = tmp.path().join("exported/payload_out.bin");

    // 5 MiB deterministic payload spanning two encrypted 4 MiB chunks.
    let payload: Vec<u8> = (0usize..(5 * 1024 * 1024 + 137))
        .map(|i| ((i.wrapping_mul(31)) ^ (i >> 8)) as u8)
        .collect();
    std::fs::write(&src_file, &payload).expect("write 5 MiB fixture");

    let secret_store = Arc::new(InMemorySecretStore::default());
    let cfg = DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(false);
    let runtime = Arc::new(
        DaemonRuntime::builder(cfg)
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::clone(&secret_store) as Arc<dyn SecretStore>)
            .build()
            .expect("runtime"),
    );

    // Lock mock crypto engine first, then verify OAuthLogin rejects cleanly while locked.
    assert!(matches!(
        runtime.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));
    let oauth_locked = runtime
        .handle_request(DaemonRequest::OAuthLogin(Box::new(OAuthLoginParams {
            id: "gdrive-1".to_owned(),
            kind: "gdrive".to_owned(),
            root: "/zerovault".to_owned(),
            client_id: "client-id".to_owned(),
            client_secret: Some("super-oauth-client-secret".to_owned()),
            auth_url: None,
            token_url: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            timeout_secs: Some(5),
            open_browser: false,
        })))
        .await;
    assert!(matches!(
        oauth_locked,
        DaemonResponse::Error { ref code, .. } if code == "vault_locked"
    ));

    // Init vault
    let init = runtime
        .handle_request(DaemonRequest::InitVault {
            passphrase: "desktop-gui-passphrase".to_owned(),
        })
        .await;
    assert!(matches!(init, DaemonResponse::Ok { .. }));

    // Add two local-fs cloud remotes
    for (id, dir) in [("cloud-a", &cloud_a), ("cloud-b", &cloud_b)] {
        let resp = runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: id.to_owned(),
                kind: "fs".to_owned(),
                root: dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(64 * 1024 * 1024),
                policy: Some("pooled".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await;
        assert!(matches!(resp, DaemonResponse::Ok { .. }));
    }

    // Create nested virtual directories
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::CreateDirectory {
                virtual_path: "/Projects".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::CreateDirectory {
                virtual_path: "/Projects/Sub".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Import 5 MiB file into /Projects
    let import_resp = runtime
        .handle_request(DaemonRequest::ImportLocalFile {
            local_path: src_file.to_string_lossy().into_owned(),
            virtual_dest_path: "/Projects".to_owned(),
        })
        .await;
    assert!(matches!(import_resp, DaemonResponse::Ok { .. }));

    // List /Projects directory
    let list_resp = runtime
        .handle_request(DaemonRequest::ListDirectory {
            virtual_path: "/Projects".to_owned(),
        })
        .await;
    match list_resp {
        DaemonResponse::DirectoryEntries {
            virtual_path,
            entries,
        } => {
            assert_eq!(virtual_path, "/Projects");
            assert_eq!(entries.len(), 2);
            // Directories sorted before files
            assert_eq!(entries[0].kind, EntryKind::Directory);
            assert_eq!(entries[0].name, "Sub");
            assert_eq!(entries[1].kind, EntryKind::File);
            assert_eq!(entries[1].name, "payload_5mib.bin");
            assert_eq!(entries[1].size, payload.len() as u64);
        }
        other => panic!("expected DirectoryEntries, got {other:?}"),
    }

    // Pin -> Unpin -> Dehydrate -> Export byte-for-byte verified
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Pin {
                virtual_path: "/Projects/payload_5mib.bin".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Unpin {
                virtual_path: "/Projects/payload_5mib.bin".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Dehydrate {
                virtual_path: "/Projects/payload_5mib.bin".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Rename in place and re-verify export hydrates cleanly from encrypted cloud chunks
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::RenameEntry {
                virtual_path: "/Projects/payload_5mib.bin".to_owned(),
                new_virtual_path: "renamed_payload.bin".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let export_resp = runtime
        .handle_request(DaemonRequest::ExportVaultFile {
            virtual_path: "/Projects/renamed_payload.bin".to_owned(),
            local_dest_path: exported_file.to_string_lossy().into_owned(),
        })
        .await;
    assert!(matches!(export_resp, DaemonResponse::Ok { .. }));
    let read_back = std::fs::read(&exported_file).expect("read exported 5 MiB");
    assert_eq!(read_back, payload);

    // Switch routing policy to Mirrored RAID-1, then Targeted, then reject unknown backend
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SetRoutingPolicy {
                policy: RoutingPolicy::Mirrored {
                    backends: vec!["cloud-a".to_owned(), "cloud-b".to_owned()],
                    min_ack: 2,
                },
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SetRoutingPolicy {
                policy: RoutingPolicy::Targeted {
                    prefix_routes: vec![("/Projects".to_owned(), "cloud-a".to_owned())],
                    default_backend: "cloud-b".to_owned(),
                },
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SetRoutingPolicy {
                policy: RoutingPolicy::QuotaPooled {
                    pool_backends: vec!["nonexistent".to_owned()],
                },
            })
            .await,
        DaemonResponse::Error { ref code, .. } if code == "invalid_config"
    ));

    // Remove remote cloud-b and verify Targeted policy default fell back to cloud-a
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::RemoveRemote {
                id: "cloud-b".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    match runtime.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(report) => {
            assert_eq!(report.remotes.len(), 1);
            assert_eq!(report.remotes[0].id, "cloud-a");
            assert_eq!(
                report.routing_policy,
                Some(RoutingPolicy::Targeted {
                    prefix_routes: vec![("/Projects".to_owned(), "cloud-a".to_owned())],
                    default_backend: "cloud-a".to_owned(),
                })
            );
        }
        other => panic!("expected Status, got {other:?}"),
    }

    // Recursive delete removes /Projects and its children
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::DeleteEntry {
                virtual_path: "/Projects".to_owned(),
                recursive: true,
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    match runtime
        .handle_request(DaemonRequest::ListDirectory {
            virtual_path: "/".to_owned(),
        })
        .await
    {
        DaemonResponse::DirectoryEntries { entries, .. } => assert!(entries.is_empty()),
        other => panic!("expected empty root, got {other:?}"),
    }

    // MountWithOptions auto-creates mount directory & mounts MockDrive cleanly
    assert!(!auto_mount_dir.exists());
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::MountWithOptions {
                mount_point: auto_mount_dir.to_string_lossy().into_owned(),
                use_mock_vfs: true,
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(auto_mount_dir.is_dir());
    assert!(matches!(
        runtime.handle_request(DaemonRequest::Unmount).await,
        DaemonResponse::Ok { .. }
    ));

    // ListConflicts returns recorded conflicts sorted newest-first
    let direct_meta = zerovault_core::SqliteMetadataStore::open(state_dir.join("metadata.db"))
        .expect("open sqlite metadata");
    let now = chrono::Utc::now();
    direct_meta
        .record_conflict(ConflictRecord {
            original_path: "/a.txt".to_owned(),
            conflict_path: "/a (conflict-dev-1).txt".to_owned(),
            remote_revision: 1,
            detected_at: now - chrono::Duration::seconds(10),
        })
        .await
        .expect("record older conflict");
    direct_meta
        .record_conflict(ConflictRecord {
            original_path: "/b.txt".to_owned(),
            conflict_path: "/b (conflict-dev-2).txt".to_owned(),
            remote_revision: 2,
            detected_at: now,
        })
        .await
        .expect("record newer conflict");
    match runtime.handle_request(DaemonRequest::ListConflicts).await {
        DaemonResponse::Conflicts(conflicts) => {
            assert_eq!(conflicts.len(), 2);
            assert_eq!(conflicts[0].original_path, "/b.txt");
            assert_eq!(conflicts[1].original_path, "/a.txt");
        }
        other => panic!("expected Conflicts, got {other:?}"),
    }

    // OAuthLogin redaction + non-OAuth kind rejection
    let oauth_dbg = format!(
        "{:?}",
        OAuthLoginParams {
            id: "g1".to_owned(),
            kind: "gdrive".to_owned(),
            root: "/zv".to_owned(),
            client_id: "cid".to_owned(),
            client_secret: Some("super-secret-oauth-client".to_owned()),
            auth_url: None,
            token_url: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            timeout_secs: None,
            open_browser: false,
        }
    );
    assert!(!oauth_dbg.contains("super-secret-oauth-client"));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::OAuthLogin(Box::new(OAuthLoginParams {
                id: "s3-bad".to_owned(),
                kind: "s3".to_owned(),
                root: "/zv".to_owned(),
                client_id: "cid".to_owned(),
                client_secret: None,
                auth_url: None,
                token_url: None,
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                timeout_secs: Some(5),
                open_browser: false,
            })))
            .await,
        DaemonResponse::Error { ref code, .. } if code == "invalid_config"
    ));

    // Register a gdrive backend with token secret, then verify RemoveRemote cleans secret_store
    let tok_json = serde_json::json!({
        "access_token": "secret-access-token-123",
        "refresh_token": "secret-refresh-token-456",
        "client_id": "test-client"
    })
    .to_string();
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "gdrive-tok".to_owned(),
                kind: "gdrive".to_owned(),
                root: "/zerovault".to_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                username: Some("test-client".to_owned()),
                secret: Some(tok_json),
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(
        secret_store
            .get_secret(&runtime.config().secret_service, "remote:gdrive-tok")
            .await
            .expect("get secret")
            .is_some()
    );
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::RemoveRemote {
                id: "gdrive-tok".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(
        secret_store
            .get_secret(&runtime.config().secret_service, "remote:gdrive-tok")
            .await
            .expect("get secret after remove")
            .is_none()
    );

    assert!(matches!(
        runtime.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));
}
