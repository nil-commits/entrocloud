//! Comprehensive integration tests for `entrocloud-daemon` (`zerovaultd`).
//!
//! Covers:
//! 1. Multi-device `vault/header.zvh` cloud bootstrap (`NEW-C01`).
//! 2. Mounted `Pin` -> `Unpin` -> `Dehydrate` (`VFS-3` calling both `sync.unpin` and `drive.unpin_path`).
//! 3. Serverless `zv://` capability share & post-quantum `keybox.zv` `epoch = 1 -> 2` revocation
//!    (`FolderRootKey` rotation, DEK/manifest re-wrapping, stale epoch replay rejection, lock/unlock survival).
//! 4. Cancellable periodic background sync loop (`NEW-H03`) + `mimalloc` idle reclamation.
//! 5. Symlink/reparse-safe `ImportLocalFile` & atomic `.partial` `ExportVaultFile` (`NEW-D03`),
//!    `ReadTextNote`/`SaveTextNote` `2 MiB` UTF-8 bounds, `DetectLocalClouds`, and `BenchCrypto`.
//! 6. IPC framing bounds (`<= 1 MiB`), `64`-connection semaphore burst, Windows Named Pipe
//!    `D:P(A;;GA;;;SY)(A;;GA;;;OW)` + `state_dir`/`staging_dir` `PROTECTED_DACL` verification,
//!    and zero secret/filename log leakage.

use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing_subscriber::fmt::MakeWriter;
#[cfg(target_os = "windows")]
use uuid::Uuid;
use entrocloud_crypto::AwsLcCryptoEngine;
use entrocloud_daemon::{
    CoreSyncEngineFactory, DaemonRuntime, DaemonStateConfig, DriveFactory, IpcClient, IpcEndpoint,
    IpcServer, MAX_TEXT_NOTE_BYTES, read_frame, validate_frame_len, write_frame,
};
use entrocloud_types::mocks::{InMemorySecretStore, MockCryptoEngine};
use entrocloud_types::{
    AddRemoteParams, CryptoEngine, DaemonRequest, DaemonResponse, DriveStats, HydrationState,
    KEYBOX_OBJECT_KEY, MAX_IPC_FRAME_BYTES, RecipientPrivateIdentity, RoutingPolicy, SignedKeybox,
    VAULT_HEADER_OBJECT_KEY, VfsBackend, VirtualDrive, ZeroVaultError, ZeroVaultResult,
};
use entrocloud_vfs::MockDrive;

#[derive(Clone, Default)]
struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedLogBuffer {
    fn contents(&self) -> String {
        match self.0.lock() {
            Ok(guard) => String::from_utf8_lossy(&guard).into_owned(),
            Err(poisoned) => String::from_utf8_lossy(&poisoned.into_inner()).into_owned(),
        }
    }
}

struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut guard) = self.0.lock() {
            guard.extend_from_slice(buf);
        }
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

/// Spy `VirtualDrive` wrapper verifying `VFS-3` (`drive.unpin_path` + `sync.unpin` both called).
struct SpyDrive {
    inner: MockDrive,
    pin_calls: Arc<AtomicUsize>,
    unpin_calls: Arc<AtomicUsize>,
    dehydrate_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl VirtualDrive for SpyDrive {
    async fn mount(&self, mount_point: PathBuf) -> ZeroVaultResult<()> {
        self.inner.mount(mount_point).await
    }

    async fn unmount(&self) -> ZeroVaultResult<()> {
        self.inner.unmount().await
    }

    fn is_mounted(&self) -> bool {
        self.inner.is_mounted()
    }

    fn mount_point(&self) -> Option<PathBuf> {
        self.inner.mount_point()
    }

    async fn pin_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        self.pin_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.pin_path(virtual_path).await
    }

    async fn unpin_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        self.unpin_calls.fetch_add(1, Ordering::SeqCst);
        // Intentionally do NOT delegate to `inner.unpin_path` here to prove `DaemonRuntime::unpin_path`
        // ALSO directly invoked `bundle.vfs.unpin(inode)` BEFORE calling `drive.unpin_path` (`VFS-3`)!
        let _ = virtual_path;
        Ok(())
    }

    async fn dehydrate_path(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        self.dehydrate_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.dehydrate_path(virtual_path).await
    }

    async fn notify_change(&self, virtual_path: &str) -> ZeroVaultResult<()> {
        self.inner.notify_change(virtual_path).await
    }

    async fn stats(&self) -> ZeroVaultResult<DriveStats> {
        self.inner.stats().await
    }
}

#[derive(Default)]
struct SpyDriveFactory {
    pin_calls: Arc<AtomicUsize>,
    unpin_calls: Arc<AtomicUsize>,
    dehydrate_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DriveFactory for SpyDriveFactory {
    async fn create_drive(
        &self,
        backend: Arc<dyn VfsBackend>,
        _use_mock: bool,
    ) -> ZeroVaultResult<Arc<dyn VirtualDrive>> {
        Ok(Arc::new(SpyDrive {
            inner: MockDrive::new(backend),
            pin_calls: Arc::clone(&self.pin_calls),
            unpin_calls: Arc::clone(&self.unpin_calls),
            dehydrate_calls: Arc::clone(&self.dehydrate_calls),
        }))
    }
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_named_pipe_and_state_staging_dacl_hardening() -> Result<(), Box<dyn std::error::Error>> {
    use entrocloud_daemon::dacl::win_acl::query_path_dacl_sddl;

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let staging_dir = state_dir.join("staging");

    let cfg = DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(true);
    let runtime = Arc::new(
        DaemonRuntime::builder(cfg)
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()?,
    );

    // Verify `state_dir` and `staging_dir` have PROTECTED_DACL (`D:P`) with only SY and OW ACEs!
    for dir in [&state_dir, &staging_dir] {
        let sddl = query_path_dacl_sddl(dir)?;
        assert!(
            sddl.starts_with("D:P"),
            "expected PROTECTED_DACL ('D:P') on {}, got {sddl}",
            dir.display()
        );
        assert!(sddl.contains("SY"), "expected SYSTEM ACE in {sddl}");
        assert!(sddl.contains("OW"), "expected OWNER RIGHTS ACE in {sddl}");
        assert!(!sddl.contains("WD"), "Everyone ('WD') must not appear in {sddl}");
        assert!(
            !sddl.contains("BU"),
            "BUILTIN\\Users ('BU') must not appear in {sddl}"
        );
        assert!(
            !sddl.contains("AU"),
            "Authenticated Users ('AU') must not appear in {sddl}"
        );
    }

    let pipe_name = format!(r"\\.\pipe\zerovaultd-test-{}", Uuid::new_v4().as_simple());
    let server = IpcServer::bind(IpcEndpoint::NamedPipe(pipe_name.clone())).await?;

    // `first_pipe_instance(true)` must reject a second concurrent server bind on the same pipe!
    let duplicate_bind = IpcServer::bind(IpcEndpoint::NamedPipe(pipe_name.clone())).await;
    assert!(
        duplicate_bind.is_err(),
        "second IpcServer::bind on active Windows named pipe must fail closed"
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
    });

    let client = IpcClient::new(IpcEndpoint::NamedPipe(pipe_name));
    client.ping().await?;

    let init_resp = client
        .request(&DaemonRequest::InitVault {
            passphrase: "win32-named-pipe-passphrase".to_owned(),
        })
        .await?;
    assert!(matches!(init_resp, DaemonResponse::Ok { .. }));

    // Verify `vault.zvh` and `metadata.db` also carry strict owner-only DACLs!
    for file in [state_dir.join("vault.zvh"), state_dir.join("metadata.db")] {
        let sddl = query_path_dacl_sddl(&file)?;
        assert!(sddl.contains("SY"), "expected SY ACE on {}, got {sddl}", file.display());
        assert!(sddl.contains("OW"), "expected OW ACE on {}, got {sddl}", file.display());
        assert!(!sddl.contains("WD") && !sddl.contains("BU"));
    }

    let shutdown_resp = client.request(&DaemonRequest::Shutdown).await?;
    assert!(matches!(shutdown_resp, DaemonResponse::Ok { .. }));
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn multi_device_cloud_bootstrap_device1_to_device2_and_reverse_init()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let shared_cloud = tmp.path().join("shared_cloud");
    let state_dev1 = tmp.path().join("dev1_state");
    let state_dev2 = tmp.path().join("dev2_state");
    let src_5mib = tmp.path().join("design_5mib.bin");
    let dst_export = tmp.path().join("dev2_exported/design_out.bin");

    let payload: Vec<u8> = (0usize..(5 * 1024 * 1024 + 321))
        .map(|i| ((i.wrapping_mul(73)) ^ (i >> 9)) as u8)
        .collect();
    std::fs::write(&src_5mib, &payload)?;

    // --- Device 1: InitVault -> AddRemote -> Import 5 MiB + SaveNote ---
    let dev1 = DaemonRuntime::builder(DaemonStateConfig::new(state_dev1.clone()).with_mock_vfs(true))
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .with_sync_factory(Arc::new(CoreSyncEngineFactory::with_device_id("dev-1")))
        .build()?;

    let passphrase = "multi-device-zero-knowledge-passphrase";
    let init_resp = dev1
        .handle_request(DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(matches!(init_resp, DaemonResponse::Ok { .. }));

    let add_remote_dev1 = dev1
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "shared-fs".to_owned(),
            kind: "fs".to_owned(),
            root: shared_cloud.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(256 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await;
    assert!(matches!(add_remote_dev1, DaemonResponse::Ok { .. }));

    // `NEW-C01`: `vault/header.zvh` MUST be automatically published to `shared_cloud`!
    let remote_header_file = shared_cloud.join(VAULT_HEADER_OBJECT_KEY);
    assert!(
        remote_header_file.exists(),
        "AddRemote on initialized vault must publish vault/header.zvh"
    );

    assert!(matches!(
        dev1.handle_request(DaemonRequest::ImportLocalFile {
            local_path: src_5mib.to_string_lossy().into_owned(),
            virtual_dest_path: "/Engineering/design.bin".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        dev1.handle_request(DaemonRequest::SaveTextNote {
            virtual_path: "/Notes/welcome.md".to_owned(),
            content: "Hello from Device 1!".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));

    // --- Device 2: Empty `state_dir` (no local `vault.zvh`) -> AddRemote -> UnlockVault ---
    let dev2_crypto = Arc::new(MockCryptoEngine::default());
    dev2_crypto.lock_vault().await?;
    let dev2 = DaemonRuntime::builder(DaemonStateConfig::new(state_dev2.clone()).with_mock_vfs(true))
        .with_crypto(dev2_crypto)
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .with_sync_factory(Arc::new(CoreSyncEngineFactory::with_device_id("dev-2")))
        .build()?;

    assert!(!state_dev2.join("vault.zvh").exists());

    // Unlock before AddRemote must fail cleanly since neither local nor remote header is available.
    let premature_unlock = dev2
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(matches!(
        premature_unlock,
        DaemonResponse::Error { ref code, .. } if code == "invalid_config"
    ));

    // Register shared cloud remote on Device 2 while locked.
    assert!(matches!(
        dev2.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "shared-fs".to_owned(),
            kind: "fs".to_owned(),
            root: shared_cloud.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(256 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));

    // Wrong passphrase must fail closed with `invalid_passphrase` AND NOT persist `vault.zvh`!
    let bad_unlock = dev2
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: "wrong-passphrase".to_owned(),
        })
        .await;
    assert!(matches!(
        bad_unlock,
        DaemonResponse::Error { ref code, .. } if code == "invalid_passphrase"
    ));
    assert!(!state_dev2.join("vault.zvh").exists());

    // Correct passphrase fetches `vault/header.zvh`, verifies tag, persists locally, unlocks, and syncs!
    let good_unlock = dev2
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(
        matches!(good_unlock, DaemonResponse::Ok { .. }),
        "expected Device 2 bootstrap unlock Ok, got {good_unlock:?}"
    );
    assert!(state_dev2.join("vault.zvh").exists());

    // Verify Device 2 immediately sees `/Notes/welcome.md` and `/Engineering/design.bin`!
    match dev2
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Notes/welcome.md".to_owned(),
        })
        .await
    {
        DaemonResponse::TextNote { content, .. } => {
            assert_eq!(content, "Hello from Device 1!");
        }
        other => return Err(format!("unexpected ReadTextNote response: {other:?}").into()),
    }

    assert!(matches!(
        dev2.handle_request(DaemonRequest::ExportVaultFile {
            virtual_path: "/Engineering/design.bin".to_owned(),
            local_dest_path: dst_export.to_string_lossy().into_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert_eq!(std::fs::read(&dst_export)?, payload);

    // --- Part B: AddRemote BEFORE InitVault also publishes `vault/header.zvh` ---
    let cloud_b = tmp.path().join("cloud_b");
    let state_dev3 = tmp.path().join("dev3_state");
    let dev3_crypto = Arc::new(MockCryptoEngine::default());
    dev3_crypto.lock_vault().await?;
    let dev3 = DaemonRuntime::builder(DaemonStateConfig::new(state_dev3).with_mock_vfs(true))
        .with_crypto(dev3_crypto)
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?;

    assert!(matches!(
        dev3.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "cloud-b".to_owned(),
            kind: "fs".to_owned(),
            root: cloud_b.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            username: None,
            secret: None,
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        dev3.handle_request(DaemonRequest::InitVault {
            passphrase: "dev3-reverse-bootstrap".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(
        cloud_b.join(VAULT_HEADER_OBJECT_KEY).exists(),
        "InitVault when remotes are already registered must publish vault/header.zvh"
    );

    Ok(())
}

#[tokio::test]
async fn mounted_pin_unpin_dehydrate_vfs3_and_file_ops_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");
    let mount_dir = tmp.path().join("mount");

    let spy_factory = Arc::new(SpyDriveFactory::default());
    let runtime = DaemonRuntime::builder(DaemonStateConfig::new(state_dir).with_mock_vfs(true))
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .with_drive_factory(Arc::clone(&spy_factory) as Arc<dyn DriveFactory>)
        .build()?;

    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::InitVault {
                passphrase: "vfs3-pin-unpin-passphrase".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "cloud".to_owned(),
                kind: "fs".to_owned(),
                root: cloud_dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(64 * 1024 * 1024),
                policy: Some("pooled".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::MountWithOptions {
                mount_point: mount_dir.to_string_lossy().into_owned(),
                use_mock_vfs: true,
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SaveTextNote {
                virtual_path: "/Docs/spec.md".to_owned(),
                content: "ZeroVault VFS-3 test payload".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Pin while mounted
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Pin {
                virtual_path: "/Docs/spec.md".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert_eq!(spy_factory.pin_calls.load(Ordering::SeqCst), 1);

    // Dehydrate while pinned must fail closed
    let dehydrate_denied = runtime
        .handle_request(DaemonRequest::Dehydrate {
            virtual_path: "/Docs/spec.md".to_owned(),
        })
        .await;
    assert!(matches!(
        dehydrate_denied,
        DaemonResponse::Error { ref code, .. } if code == "pinned_dehydration_denied"
    ));

    assert_eq!(spy_factory.dehydrate_calls.load(Ordering::SeqCst), 1);

    // Unpin (`VFS-3`): `SpyDrive::unpin_path` is a no-op stub, so `Dehydrate` succeeding proves
    // `DaemonRuntime::unpin_path` called BOTH `bundle.vfs.unpin` AND `drive.unpin_path`!
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Unpin {
                virtual_path: "/Docs/spec.md".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert_eq!(spy_factory.unpin_calls.load(Ordering::SeqCst), 1);

    // Dehydrate now succeeds and marks `/Docs/spec.md` `OnlineOnly`!
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::Dehydrate {
                virtual_path: "/Docs/spec.md".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert_eq!(spy_factory.dehydrate_calls.load(Ordering::SeqCst), 2);

    match runtime
        .handle_request(DaemonRequest::ListDirectory {
            virtual_path: "/Docs".to_owned(),
        })
        .await
    {
        DaemonResponse::DirectoryEntries { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert!(!entries[0].pinned);
            assert_eq!(entries[0].hydration, HydrationState::OnlineOnly);
        }
        other => return Err(format!("unexpected ListDirectory response: {other:?}").into()),
    }

    // On-demand hydration via ReadTextNote restores exact plaintext!
    match runtime
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Docs/spec.md".to_owned(),
        })
        .await
    {
        DaemonResponse::TextNote { content, .. } => {
            assert_eq!(content, "ZeroVault VFS-3 test payload");
        }
        other => return Err(format!("unexpected ReadTextNote response: {other:?}").into()),
    }

    Ok(())
}

#[tokio::test]
async fn capability_uri_share_and_post_quantum_keybox_epoch_1_to_2_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let owner_state = tmp.path().join("owner_state");
    let carol_state = tmp.path().join("carol_state");
    let shared_cloud = tmp.path().join("pq_cloud");

    let real_crypto_owner = Arc::new(AwsLcCryptoEngine::new()?);
    let owner_rt = DaemonRuntime::builder(DaemonStateConfig::new(owner_state).with_mock_vfs(true))
        .with_crypto(Arc::clone(&real_crypto_owner) as Arc<dyn CryptoEngine>)
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?;

    let owner_passphrase = "owner-pq-passphrase-ryzen-vaes";
    assert!(matches!(
        owner_rt
            .handle_request(DaemonRequest::InitVault {
                passphrase: owner_passphrase.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        owner_rt
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "pq-cloud".to_owned(),
                kind: "fs".to_owned(),
                root: shared_cloud.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(128 * 1024 * 1024),
                policy: Some("targeted".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Save encrypted report on Owner vault
    let secret_report = "Confidential Post-Quantum Roadmap Q4 2026";
    assert!(matches!(
        owner_rt
            .handle_request(DaemonRequest::SaveTextNote {
                virtual_path: "/Reports/roadmap.txt".to_owned(),
                content: secret_report.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // --- Part A: 1-Click `ec://` Read-Only Capability Share (+ Legacy `zv://` Compatibility) ---
    let share_uri = match owner_rt
        .handle_request(DaemonRequest::CreateCapabilityShare {
            virtual_path: "/Reports/roadmap.txt".to_owned(),
        })
        .await
    {
        DaemonResponse::ShareUriCreated { uri, .. } => uri,
        other => return Err(format!("expected ShareUriCreated, got {other:?}").into()),
    };
    assert!(
        share_uri.starts_with("ec://share/v1/fs?"),
        "expected primary ec:// capability URI, got {share_uri}"
    );

    // Independent recipient `Carol` (separate vault, NO remotes configured) imports via `ec://` AND legacy `zv://`!
    let carol_rt = DaemonRuntime::builder(DaemonStateConfig::new(carol_state).with_mock_vfs(true))
        .with_crypto(Arc::new(AwsLcCryptoEngine::new()?))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?;
    assert!(matches!(
        carol_rt
            .handle_request(DaemonRequest::InitVault {
                passphrase: "carol-independent-vault-pass".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Tampered `ec://` fragment must fail closed!
    let mut tampered_uri = share_uri.clone();
    let last_ch = if tampered_uri.ends_with('A') { 'B' } else { 'A' };
    tampered_uri.pop();
    tampered_uri.push(last_ch);
    let tampered_import = carol_rt
        .handle_request(DaemonRequest::ImportCapabilityShare {
            uri: tampered_uri,
            dest_virtual_path: "/Inbox/bad.txt".to_owned(),
        })
        .await;
    assert!(matches!(tampered_import, DaemonResponse::Error { .. }));

    // Authentic `ec://` share imports cleanly!
    let legacy_zv_uri = entrocloud_types::CapabilityUri::parse(&share_uri)?
        .encode_with_scheme(entrocloud_types::LEGACY_CAPABILITY_URI_SCHEME)?;
    assert!(legacy_zv_uri.starts_with("zv://share/v1/fs?"));

    assert!(matches!(
        carol_rt
            .handle_request(DaemonRequest::ImportCapabilityShare {
                uri: share_uri,
                dest_virtual_path: "/Inbox/roadmap_copy.txt".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    match carol_rt
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Inbox/roadmap_copy.txt".to_owned(),
        })
        .await
    {
        DaemonResponse::TextNote { content, .. } => assert_eq!(content, secret_report),
        other => return Err(format!("expected TextNote, got {other:?}").into()),
    }

    // Legacy `zv://` share URI ALSO imports cleanly!
    assert!(matches!(
        carol_rt
            .handle_request(DaemonRequest::ImportCapabilityShare {
                uri: legacy_zv_uri,
                dest_virtual_path: "/Inbox/roadmap_legacy_zv.txt".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    match carol_rt
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Inbox/roadmap_legacy_zv.txt".to_owned(),
        })
        .await
    {
        DaemonResponse::TextNote { content, .. } => assert_eq!(content, secret_report),
        other => return Err(format!("expected TextNote from zv:// import, got {other:?}").into()),
    }

    // --- Part B: Post-Quantum `keybox.zv` (`ML-KEM-768 + X25519 + Ed25519`) Epoch 1 -> 2 Revocation ---
    // Export Owner's bundle (verifying persistence idempotence)
    let (owner_rcpt_id, owner_b64_first) = match owner_rt
        .handle_request(DaemonRequest::ExportRecipientBundle {
            label: "owner".to_owned(),
        })
        .await
    {
        DaemonResponse::RecipientBundle {
            recipient_id,
            bundle_b64,
        } => (recipient_id, bundle_b64),
        other => return Err(format!("expected RecipientBundle, got {other:?}").into()),
    };
    match owner_rt
        .handle_request(DaemonRequest::ExportRecipientBundle {
            label: "owner".to_owned(),
        })
        .await
    {
        DaemonResponse::RecipientBundle {
            recipient_id,
            bundle_b64,
        } => {
            assert_eq!(recipient_id, owner_rcpt_id);
            assert_eq!(bundle_b64, owner_b64_first);
        }
        other => return Err(format!("expected RecipientBundle, got {other:?}").into()),
    }

    // Generate real ML-KEM-768 + X25519 + Ed25519 identities for Alice & Bob
    let pq_engine = AwsLcCryptoEngine::new()?;
    let alice_id: RecipientPrivateIdentity = pq_engine.generate_recipient_identity("alice")?;
    let bob_id: RecipientPrivateIdentity = pq_engine.generate_recipient_identity("bob")?;
    let alice_b64 = alice_id.public.to_base64()?;
    let bob_b64 = bob_id.public.to_base64()?;

    // 1. `InitKeybox` -> epoch = 1
    let kb_init = match owner_rt.handle_request(DaemonRequest::InitKeybox).await {
        DaemonResponse::KeyboxInfo(info) => info,
        other => return Err(format!("expected KeyboxInfo on InitKeybox, got {other:?}").into()),
    };
    assert_eq!(kb_init.epoch, 1);
    assert!(kb_init.recipient_ids.contains(&owner_rcpt_id));

    // 2. Grant Alice & Bob at epoch = 1
    for b64 in [&alice_b64, &bob_b64] {
        let granted = match owner_rt
            .handle_request(DaemonRequest::GrantKeyboxRecipient {
                recipient_bundle_b64: b64.clone(),
            })
            .await
        {
            DaemonResponse::KeyboxInfo(info) => info,
            other => return Err(format!("expected KeyboxInfo on Grant, got {other:?}").into()),
        };
        assert_eq!(granted.epoch, 1);
    }

    let kb_path = shared_cloud.join(KEYBOX_OBJECT_KEY);
    let raw_kb_epoch1 = std::fs::read(&kb_path)?;
    let decoded_kb1 = SignedKeybox::decode(&raw_kb_epoch1)?;
    let frk_alice_ep1 = pq_engine.open_keybox(&decoded_kb1, None, 1, &alice_id)?;
    let frk_bob_ep1 = pq_engine.open_keybox(&decoded_kb1, None, 1, &bob_id)?;
    assert_eq!(&*frk_alice_ep1, &*frk_bob_ep1);

    // 3. Revoke Bob -> rotates `FolderRootKey`, advances `epoch = 1 -> 2`, re-wraps DEKs & manifest!
    let kb_revoked = match owner_rt
        .handle_request(DaemonRequest::RevokeKeyboxRecipient {
            recipient_id: bob_id.public.recipient_id.clone(),
        })
        .await
    {
        DaemonResponse::KeyboxInfo(info) => info,
        other => return Err(format!("expected KeyboxInfo on Revoke, got {other:?}").into()),
    };
    assert_eq!(kb_revoked.epoch, 2);
    assert!(kb_revoked.recipient_ids.contains(&alice_id.public.recipient_id));
    assert!(!kb_revoked.recipient_ids.contains(&bob_id.public.recipient_id));

    let raw_kb_epoch2 = std::fs::read(&kb_path)?;
    let decoded_kb2 = SignedKeybox::decode(&raw_kb_epoch2)?;
    assert_eq!(decoded_kb2.epoch, 2);

    // Bob MUST be denied at epoch 2 (`UnauthorizedRecipient`)!
    assert!(matches!(
        pq_engine.open_keybox(&decoded_kb2, None, 2, &bob_id),
        Err(ZeroVaultError::UnauthorizedRecipient(_))
    ));

    // Alice opens epoch 2 and receives a NEW rotated FolderRootKey (`FRK_2 != FRK_1`)!
    let frk_alice_ep2 = pq_engine.open_keybox(&decoded_kb2, None, 2, &alice_id)?;
    assert_ne!(&*frk_alice_ep2, &*frk_alice_ep1);

    // `Status` reports `keybox_epoch == 2`!
    match owner_rt.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(report) => {
            assert_eq!(report.keybox_epoch, 2);
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    // 4. Stale Epoch Replay Attack: cloud adversary overwrites `vault/keybox.zv` with `epoch = 1`!
    std::fs::write(&kb_path, &raw_kb_epoch1)?;
    let replay_status = owner_rt.handle_request(DaemonRequest::KeyboxStatus).await;
    assert!(
        matches!(replay_status, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "replaying epoch=1 keybox after advancing floor to 2 must fail closed with crypto_tamper, got {replay_status:?}"
    );
    // Restore authentic epoch 2 keybox
    std::fs::write(&kb_path, &raw_kb_epoch2)?;

    // 5. LockVault + UnlockVault with passphrase reconciles rotated `FRK_2` from `keybox.zv`
    //    and continues reading re-wrapped files seamlessly!
    assert!(matches!(
        owner_rt.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));
    let re_unlock = owner_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: owner_passphrase.to_owned(),
        })
        .await;
    assert!(
        matches!(re_unlock, DaemonResponse::Ok { .. }),
        "expected UnlockVault after keybox rotation to succeed, got {re_unlock:?}"
    );
    match owner_rt
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Reports/roadmap.txt".to_owned(),
        })
        .await
    {
        DaemonResponse::TextNote { content, .. } => assert_eq!(content, secret_report),
        other => return Err(format!("expected TextNote after rotation re-unlock, got {other:?}").into()),
    }

    Ok(())
}

#[tokio::test]
async fn periodic_background_sync_loop_flushes_offline_dirty_ops_and_cancels_cleanly()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");

    let runtime = Arc::new(
        DaemonRuntime::builder(
            DaemonStateConfig::new(state_dir)
                .with_mock_vfs(true)
                .with_sync_interval(Duration::from_millis(50)),
        )
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?,
    );

    // Initialize vault offline (0 remotes) and stage dirty mutations locally.
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::InitVault {
                passphrase: "bg-sync-loop-passphrase".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SaveTextNote {
                virtual_path: "/Offline/queued.txt".to_owned(),
                content: "queued while offline".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    match runtime.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(report) => {
            assert_eq!(report.manifest_revision, 0);
            assert!(report.throughput.pending_dirty_ops > 0);
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    // Register cloud remote (do NOT call SyncNow manually!) and start background sync loop!
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "bg-cloud".to_owned(),
                kind: "fs".to_owned(),
                root: cloud_dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Disabled interval (`0`) returns `None`.
    assert!(runtime.spawn_background_sync(Duration::ZERO).is_none());

    let bg_handle = runtime
        .spawn_background_sync(Duration::from_millis(50))
        .ok_or("expected Some(BackgroundSyncHandle)")?;

    let mut synced = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(40)).await;
        if let DaemonResponse::Status(report) = runtime.handle_request(DaemonRequest::Status).await
            && report.manifest_revision >= 1
            && report.throughput.pending_dirty_ops == 0
        {
            synced = true;
            break;
        }
    }
    assert!(
        synced,
        "periodic background sync loop failed to flush dirty queue and publish manifest"
    );

    bg_handle.stop().await;
    Ok(())
}

#[tokio::test]
async fn symlink_safe_import_export_note_bounds_framing_64_conn_and_redaction()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");

    let log_buf = SharedLogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _log_guard = tracing::subscriber::set_default(subscriber);

    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(state_dir.clone()).with_mock_vfs(true))
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()?,
    );

    let secret_pass = "ultra-secret-passphrase-never-log-999";
    let secret_s3 = "ultra-secret-s3-access-token-888";

    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::InitVault {
                passphrase: secret_pass.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "local-cloud".to_owned(),
                kind: "fs".to_owned(),
                root: cloud_dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(64 * 1024 * 1024),
                policy: Some("pooled".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "s3-sec".to_owned(),
                kind: "s3".to_owned(),
                root: "vault".to_owned(),
                endpoint: Some("http://127.0.0.1:9000".to_owned()),
                bucket: Some("bkt".to_owned()),
                region: Some("us-east-1".to_owned()),
                quota_limit_bytes: Some(64 * 1024 * 1024),
                policy: Some("targeted".to_owned()),
                prefix: Some("/Archive".to_owned()),
                username: Some("AKIA".to_owned()),
                secret: Some(secret_s3.to_owned()),
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::SetRoutingPolicy {
                policy: RoutingPolicy::Targeted {
                    prefix_routes: Vec::new(),
                    default_backend: "local-cloud".to_owned(),
                },
            })
            .await,
        DaemonResponse::Ok { .. }
    ));

    // 1. `DetectLocalClouds` & `BenchCrypto`
    match runtime.handle_request(DaemonRequest::DetectLocalClouds).await {
        DaemonResponse::DetectedClouds(clouds) => {
            assert!(!clouds.is_empty());
            assert!(clouds.iter().any(|c| c.provider == "Local Backup"));
        }
        other => return Err(format!("expected DetectedClouds, got {other:?}").into()),
    }
    match runtime
        .handle_request(DaemonRequest::BenchCrypto { total_mib: 4 })
        .await
    {
        DaemonResponse::CryptoBench(report) => {
            assert_eq!(report.total_mib, 4);
        }
        other => return Err(format!("expected CryptoBench, got {other:?}").into()),
    }

    // 2. `SaveTextNote` & `ReadTextNote` `<= 2 MiB` UTF-8 enforcement
    let oversized_note = "x".repeat(MAX_TEXT_NOTE_BYTES + 1);
    let save_oversized = runtime
        .handle_request(DaemonRequest::SaveTextNote {
            virtual_path: "/Notes/huge.txt".to_owned(),
            content: oversized_note,
        })
        .await;
    assert!(matches!(
        save_oversized,
        DaemonResponse::Error { ref code, .. } if code == "invalid_range"
    ));

    // Non-UTF-8 binary file rejected by `ReadTextNote`
    let bin_src = tmp.path().join("non_utf8.bin");
    std::fs::write(&bin_src, [0xff, 0xfe, 0x00, 0x81])?;
    assert!(matches!(
        runtime
            .handle_request(DaemonRequest::ImportLocalFile {
                local_path: bin_src.to_string_lossy().into_owned(),
                virtual_dest_path: "/SecretFinance2026/non_utf8.bin".to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let bad_note_read = runtime
        .handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/SecretFinance2026/non_utf8.bin".to_owned(),
        })
        .await;
    assert!(matches!(
        bad_note_read,
        DaemonResponse::Error { ref code, .. } if code == "invalid_wire_format"
    ));

    // 3. `NEW-D03` symlink / NTFS junction rejection on ImportLocalFile
    #[cfg(target_os = "windows")]
    {
        let real_dir = tmp.path().join("real_target_dir");
        std::fs::create_dir_all(&real_dir)?;
        std::fs::write(real_dir.join("inside.txt"), b"junction-secret")?;
        let junction_dir = tmp.path().join("junction_link_dir");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction_dir.to_string_lossy(),
                &real_dir.to_string_lossy(),
            ])
            .output()?;
        if status.status.success() {
            let import_via_junction = runtime
                .handle_request(DaemonRequest::ImportLocalFile {
                    local_path: junction_dir.join("inside.txt").to_string_lossy().into_owned(),
                    virtual_dest_path: "/imported_from_junction.txt".to_owned(),
                })
                .await;
            assert!(
                matches!(import_via_junction, DaemonResponse::Error { ref code, .. } if code == "invalid_path"),
                "ImportLocalFile through NTFS junction must fail closed, got {import_via_junction:?}"
            );

            let export_via_junction = runtime
                .handle_request(DaemonRequest::ExportVaultFile {
                    virtual_path: "/SecretFinance2026/non_utf8.bin".to_owned(),
                    local_dest_path: junction_dir.join("out.bin").to_string_lossy().into_owned(),
                })
                .await;
            assert!(
                matches!(export_via_junction, DaemonResponse::Error { ref code, .. } if code == "invalid_path"),
                "ExportVaultFile into NTFS junction must fail closed, got {export_via_junction:?}"
            );
        }
    }

    // 4. IPC `1 MiB` pre-alloc frame bounds + `64`-connection semaphore burst test
    assert!(validate_frame_len(0).is_err());
    assert!(validate_frame_len(MAX_IPC_FRAME_BYTES).is_ok());
    assert!(validate_frame_len(MAX_IPC_FRAME_BYTES + 1).is_err());

    let mut bad_cursor = Cursor::new(((MAX_IPC_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec());
    assert!(read_frame(&mut bad_cursor).await.is_err());
    let mut sink = Vec::new();
    assert!(write_frame(&mut sink, &vec![0u8; MAX_IPC_FRAME_BYTES + 1]).await.is_err());

    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = IpcServer::bind(IpcEndpoint::TcpLoopback(addr)).await?;
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
    });

    // Oversized header over raw TCP drops cleanly without crashing server
    if let IpcEndpoint::TcpLoopback(sock_addr) = bound_ep {
        let mut raw = TcpStream::connect(sock_addr).await?;
        raw.write_all(&((MAX_IPC_FRAME_BYTES + 4096) as u32).to_be_bytes())
            .await?;
        raw.flush().await?;
        drop(raw);
    }

    // Concurrent burst of 72 clients (> 64 semaphore slots) all complete cleanly!
    let mut burst_handles = Vec::with_capacity(72);
    for _ in 0..72 {
        let ep_clone = bound_ep.clone();
        burst_handles.push(tokio::spawn(async move {
            let c = IpcClient::new(ep_clone);
            c.ping().await
        }));
    }
    for h in burst_handles {
        h.await??;
    }

    let client = IpcClient::new(bound_ep);
    assert!(matches!(
        client.request(&DaemonRequest::Shutdown).await?,
        DaemonResponse::Ok { .. }
    ));
    server_task.await??;

    // 5. Verify zero plaintext secret or virtual path leakage in logs & remotes.json!
    let remotes_json = std::fs::read_to_string(state_dir.join("remotes.json"))?;
    assert!(!remotes_json.contains(secret_pass));
    assert!(!remotes_json.contains(secret_s3));

    let logs = log_buf.contents();
    assert!(!logs.contains(secret_pass), "passphrase leaked into logs");
    assert!(!logs.contains(secret_s3), "remote secret leaked into logs");
    assert!(
        !logs.contains("SecretFinance2026"),
        "plaintext virtual path leaked into logs"
    );

    Ok(())
}

#[tokio::test]
async fn w4_veto_keybox_sig_forged_and_rogue_epoch_poisoning_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    Box::pin(run_w4_veto_keybox_sig_audit()).await
}

async fn run_w4_veto_keybox_sig_audit() -> Result<(), Box<dyn std::error::Error>> {
    use entrocloud_core::{EPOCH_SCOPE_KEYBOX, SqliteMetadataStore};
    use entrocloud_types::MetadataStore;

    let tmp = TempDir::new()?;
    let owner_state = tmp.path().join("owner_state");
    let cloud_dir = tmp.path().join("cloud");
    std::fs::create_dir_all(&cloud_dir)?;

    let owner_crypto = Arc::new(AwsLcCryptoEngine::new()?);
    let owner_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(owner_state.clone())
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>)
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;

    let passphrase = "w4-veto-keybox-sig-passphrase";
    assert!(matches!(
        owner_rt
            .handle_request(DaemonRequest::InitVault {
                passphrase: passphrase.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let owner_vault_id = owner_crypto
        .vault_id()
        .ok_or("missing unlocked owner vault_id")?;

    assert!(matches!(
        owner_rt
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "cloud".to_owned(),
                kind: "fs".to_owned(),
                root: cloud_dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));

    // Legitimate `InitKeybox` at `epoch = 1` pins `owner_ed25519_pubkey` locally.
    match owner_rt.handle_request(DaemonRequest::InitKeybox).await {
        DaemonResponse::KeyboxInfo(kb) => assert_eq!(kb.epoch, 1),
        other => return Err(format!("InitKeybox failed: {other:?}").into()),
    }

    let kb_path = cloud_dir.join(KEYBOX_OBJECT_KEY);
    let legit_ep1_bytes = std::fs::read(&kb_path)?;
    let mut forged_poison_kb = SignedKeybox::decode(&legit_ep1_bytes)?;
    forged_poison_kb.epoch = 999_999;
    forged_poison_kb.owner_signature = vec![0xDE; 64];
    std::fs::write(&kb_path, forged_poison_kb.encode()?)?;

    // Vector A1: Forged `[0xDE; 64]` signature on `KeyboxStatus` MUST fail closed without poisoning SQLite!
    let status_resp = owner_rt.handle_request(DaemonRequest::KeyboxStatus).await;
    assert!(
        matches!(status_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "expected crypto_tamper on forged ZVK1 KeyboxStatus, got {status_resp:?}"
    );

    // Vector A2: Validly self-signed ROGUE Ed25519 keypair at `epoch = 777_777` MUST ALSO fail closed!
    let rogue_id = owner_crypto.generate_recipient_identity("rogue-attacker")?;
    let rogue_kb = owner_crypto.seal_keybox(
        &rogue_id,
        owner_vault_id,
        777_777,
        &[0x55; 32],
        std::slice::from_ref(&rogue_id.public),
    )?;
    std::fs::write(&kb_path, rogue_kb.encode()?)?;
    let rogue_status_resp = owner_rt.handle_request(DaemonRequest::KeyboxStatus).await;
    assert!(
        matches!(rogue_status_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "expected crypto_tamper on rogue-signed ZVK1 KeyboxStatus, got {rogue_status_resp:?}"
    );

    let sqlite_probe = SqliteMetadataStore::open(
        owner_state.join("metadata.db"),
        Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>,
    )?;
    let persisted_floor = sqlite_probe.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
    drop(sqlite_probe);
    assert_eq!(
        persisted_floor, 1,
        "SQLite security_epochs('keybox') must remain 1 after forged/rogue ZVK1 probes"
    );

    // Restoring legitimate `epoch = 1` keybox + `LockVault -> UnlockVault` MUST succeed cleanly!
    std::fs::write(&kb_path, &legit_ep1_bytes)?;
    assert!(matches!(
        owner_rt.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));
    let re_unlock_resp = owner_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(
        matches!(re_unlock_resp, DaemonResponse::Ok { .. }),
        "expected legitimate UnlockVault Ok after restoring epoch=1 ZVK1, got {re_unlock_resp:?}"
    );

    // Vector B: Single-user vault (no `recipient_identity.zvi` & no pinned keybox owner) unlocks
    // while a forged `[0xDE; 64]` OR rogue self-signed `ZVK1` (`epoch = 888_888`) is planted!
    let single_state = tmp.path().join("single_user_state");
    let single_cloud = tmp.path().join("single_user_cloud");
    std::fs::create_dir_all(&single_cloud)?;
    let single_crypto = Arc::new(AwsLcCryptoEngine::new()?);
    let single_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(single_state.clone())
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::clone(&single_crypto) as Arc<dyn CryptoEngine>)
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;

    assert!(matches!(
        single_rt
            .handle_request(DaemonRequest::InitVault {
                passphrase: passphrase.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let single_vault_id = single_crypto.vault_id().ok_or("missing single_vault_id")?;
    assert!(matches!(
        single_rt
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "single-cloud".to_owned(),
                kind: "fs".to_owned(),
                root: single_cloud.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                username: None,
                secret: None,
            })))
            .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        single_rt.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));

    // Vector B1: Forged `[0xDE; 64]` signature at `epoch = 888_888`
    let mut single_forged_kb = forged_poison_kb.clone();
    single_forged_kb.vault_id = single_vault_id;
    single_forged_kb.epoch = 888_888;
    single_forged_kb.owner_signature = vec![0xDE; 64];
    std::fs::create_dir_all(single_cloud.join("vault"))?;
    std::fs::write(
        single_cloud.join(KEYBOX_OBJECT_KEY),
        single_forged_kb.encode()?,
    )?;

    let single_unlock_resp = single_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(
        matches!(single_unlock_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "expected crypto_tamper on Vector B forged ZVK1, got {single_unlock_resp:?}"
    );
    assert!(
        !single_crypto.is_unlocked(),
        "single_crypto must be locked back up after Vector B tamper detection"
    );

    // Vector B2: Rogue validly-self-signed `ZVK1` at `epoch = 888_888` on single-user vault
    let single_rogue_kb = single_crypto.seal_keybox(
        &rogue_id,
        single_vault_id,
        888_888,
        &[0x66; 32],
        std::slice::from_ref(&rogue_id.public),
    )?;
    std::fs::write(
        single_cloud.join(KEYBOX_OBJECT_KEY),
        single_rogue_kb.encode()?,
    )?;
    let single_rogue_unlock = single_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    assert!(
        matches!(single_rogue_unlock, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "expected crypto_tamper on Vector B rogue self-signed ZVK1, got {single_rogue_unlock:?}"
    );
    assert!(!single_crypto.is_unlocked());

    // Remove the unauthenticated remote keybox and verify clean single-user unlock still has `epoch_floor == 0`!
    std::fs::remove_file(single_cloud.join(KEYBOX_OBJECT_KEY))?;
    assert!(matches!(
        single_rt
            .handle_request(DaemonRequest::UnlockVault {
                passphrase: passphrase.to_owned(),
            })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let sp = SqliteMetadataStore::open(
        single_state.join("metadata.db"),
        Arc::clone(&single_crypto) as Arc<dyn CryptoEngine>,
    )?;
    assert_eq!(sp.epoch_floor(EPOCH_SCOPE_KEYBOX).await?, 0);
    drop(sp);

    owner_rt.graceful_shutdown().await?;
    single_rt.graceful_shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pre_vault_remote_onboarding_test_remote_and_cancel_oauth()
-> Result<(), Box<dyn std::error::Error>> {
    Box::pin(run_pre_vault_remote_onboarding_test()).await
}

async fn run_pre_vault_remote_onboarding_test() -> Result<(), Box<dyn std::error::Error>> {
    use entrocloud_types::{OAuthLoginParams, SecretStore};

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_fs = tmp.path().join("pre_vault_cloud");

    let crypto = Arc::new(MockCryptoEngine::default());
    crypto.lock_vault().await?;
    let secret_store = Arc::new(InMemorySecretStore::default());

    let rt = Arc::new(
        DaemonRuntime::builder(
            DaemonStateConfig::new(state_dir.clone())
                .with_mock_vfs(true)
                .with_sync_interval(Duration::ZERO),
        )
        .with_crypto(Arc::clone(&crypto) as Arc<dyn CryptoEngine>)
        .with_secret_store(Arc::clone(&secret_store) as Arc<dyn SecretStore>)
        .build()?,
    );

    assert!(!crypto.is_unlocked());

    // 1. DetectLocalClouds works before InitVault and uses EntroCloud naming
    match rt.handle_request(DaemonRequest::DetectLocalClouds).await {
        DaemonResponse::DetectedClouds(clouds) => {
            assert!(!clouds.is_empty());
            for c in &clouds {
                if c.provider != "Local Backup" {
                    assert!(
                        c.path.ends_with("EntroCloud"),
                        "detected cloud path must end with EntroCloud, got {}",
                        c.path
                    );
                } else {
                    assert!(c.path.contains("EntroCloudBackup"));
                }
            }
        }
        other => return Err(format!("expected DetectedClouds, got {other:?}").into()),
    }

    // 2. AddRemote (both fs AND credentialed S3) BEFORE InitVault!
    assert!(matches!(
        rt.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "pre-fs".to_owned(),
            kind: "fs".to_owned(),
            root: cloud_fs.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(64 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));

    assert!(matches!(
        rt.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "pre-s3".to_owned(),
            kind: "s3".to_owned(),
            root: "vault".to_owned(),
            endpoint: Some("http://127.0.0.1:9".to_owned()),
            bucket: Some("preinit-bucket".to_owned()),
            region: Some("us-east-1".to_owned()),
            quota_limit_bytes: Some(64 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: Some("/Archive".to_owned()),
            username: Some("AKIA_PREINIT".to_owned()),
            secret: Some("preinit-s3-secret-key".to_owned()),
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));

    // 3. ListRemotes & TestRemote BEFORE InitVault!
    match rt.handle_request(DaemonRequest::ListRemotes).await {
        DaemonResponse::Remotes(remotes) => assert_eq!(remotes.len(), 2),
        other => return Err(format!("expected Remotes, got {other:?}").into()),
    }

    match rt
        .handle_request(DaemonRequest::TestRemote {
            id: "pre-fs".to_owned(),
        })
        .await
    {
        DaemonResponse::RemoteTest(rep) => {
            assert_eq!(rep.id, "pre-fs");
            assert_eq!(rep.kind, "fs");
            assert!(rep.healthy);
            assert_eq!(rep.quota.total_bytes, 64 * 1024 * 1024);
        }
        other => return Err(format!("expected RemoteTest, got {other:?}").into()),
    }

    // Remove the unreachable S3 remote before InitVault so targeted routing stays on `pre-fs`
    assert!(matches!(
        rt.handle_request(DaemonRequest::RemoveRemote {
            id: "pre-s3".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));

    // Add a second credentialed WebDAV remote with secret BEFORE InitVault to verify secret promotion on InitVault!
    assert!(matches!(
        rt.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "pre-dav".to_owned(),
            kind: "webdav".to_owned(),
            root: "/ec".to_owned(),
            endpoint: Some("http://127.0.0.1:9".to_owned()),
            bucket: None,
            region: None,
            quota_limit_bytes: Some(32 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: Some("/Cold".to_owned()),
            username: Some("davuser".to_owned()),
            secret: Some("dav-preunlock-pass".to_owned()),
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(
        secret_store
            .get_secret("entrocloud", "remote:pre-dav:preunlock")
            .await?
            .is_some()
    );

    // 4. CancelOAuth aborts an in-flight OAuthLogin immediately (even before InitVault!)
    let rt_oauth = Arc::clone(&rt);
    let oauth_handle = tokio::spawn(async move {
        rt_oauth
            .handle_request(DaemonRequest::OAuthLogin(Box::new(OAuthLoginParams {
                id: "gdrive-cancel-test".to_owned(),
                kind: "gdrive".to_owned(),
                root: "/EntroCloud".to_owned(),
                client_id: "test-client-id".to_owned(),
                client_secret: None,
                auth_url: Some("http://127.0.0.1:9/auth".to_owned()),
                token_url: Some("http://127.0.0.1:9/token".to_owned()),
                quota_limit_bytes: None,
                policy: None,
                prefix: None,
                timeout_secs: Some(60),
                open_browser: false,
            })))
            .await
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(matches!(
        rt.handle_request(DaemonRequest::CancelOAuth).await,
        DaemonResponse::Ok { .. }
    ));

    let oauth_resp = tokio::time::timeout(Duration::from_secs(3), oauth_handle).await??;
    match oauth_resp {
        DaemonResponse::Error { code, message } => {
            assert_eq!(code, "oauth_error");
            assert!(
                message.contains("OAuth sign-in cancelled by user"),
                "unexpected CancelOAuth message: {message}"
            );
        }
        other => return Err(format!("expected cancelled OAuthError, got {other:?}").into()),
    }

    // 5. InitVault promotes `:preunlock` credentials to `TokenWrapKey` and publishes `vault/header.zvh`!
    assert!(matches!(
        rt.handle_request(DaemonRequest::InitVault {
            passphrase: "pre-vault-onboarding-passphrase".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(cloud_fs.join(VAULT_HEADER_OBJECT_KEY).exists());
    assert!(
        secret_store
            .get_secret("entrocloud", "remote:pre-dav:preunlock")
            .await?
            .is_none(),
        "preunlock secret must be deleted after promotion"
    );
    assert!(
        secret_store
            .get_secret("entrocloud", "remote:pre-dav")
            .await?
            .is_some(),
        "wrapped secret must be persisted under TokenWrapKey after InitVault"
    );

    rt.graceful_shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cloudbridge_pc_folder_backup_incremental_preview_retention_restore_and_scheduler()
-> Result<(), Box<dyn std::error::Error>> {
    Box::pin(run_cloudbridge_backup_lifecycle_test()).await
}

async fn run_cloudbridge_backup_lifecycle_test() -> Result<(), Box<dyn std::error::Error>> {
    use entrocloud_types::BackupJobSpec;

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");
    let mount_dir = tmp.path().join("mount");
    let docs_src = tmp.path().join("MyDocuments");
    let restore_parent = tmp.path().join("Restores");

    std::fs::create_dir_all(docs_src.join("Projects"))?;
    std::fs::write(docs_src.join("tax_2026.pdf"), b"Tax return 2026 payload")?;
    std::fs::write(docs_src.join("Projects").join("notes.md"), b"Project architecture v1")?;
    // Excluded temporary / OS metadata files that must be skipped!
    std::fs::write(docs_src.join("desktop.ini"), b"[.ShellClassInfo]")?;
    std::fs::write(docs_src.join("Thumbs.db"), b"thumbs-junk")?;
    std::fs::write(docs_src.join("~$lockfile.docx"), b"word-lock")?;
    std::fs::write(docs_src.join("scratch.tmp"), b"temp-file")?;

    let rt = Arc::new(
        DaemonRuntime::builder(
            DaemonStateConfig::new(state_dir.clone())
                .with_mock_vfs(true)
                .with_sync_interval(Duration::ZERO),
        )
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?,
    );

    assert!(matches!(
        rt.handle_request(DaemonRequest::InitVault {
            passphrase: "backup-engine-passphrase".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        rt.handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "backup-cloud".to_owned(),
            kind: "fs".to_owned(),
            root: cloud_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(128 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        rt.handle_request(DaemonRequest::MountWithOptions {
            mount_point: mount_dir.to_string_lossy().into_owned(),
            use_mock_vfs: true,
        })
        .await,
        DaemonResponse::Ok { .. }
    ));

    // 1. Path Overlap Guard: reject `state_dir`, `staging_dir`, `mount_dir`, and missing folder!
    for bad_src in [
        state_dir.clone(),
        state_dir.join("staging"),
        mount_dir.clone(),
        tmp.path().join("does_not_exist"),
    ] {
        let bad_resp = rt
            .handle_request(DaemonRequest::UpsertBackupJob(Box::new(BackupJobSpec {
                id: None,
                name: "BadJob".to_owned(),
                source_path: bad_src.to_string_lossy().into_owned(),
                vault_folder: "/Backups/Bad".to_owned(),
                interval_minutes: 15,
                enabled: true,
                excludes: Vec::new(),
            })))
            .await;
        assert!(
            matches!(bad_resp, DaemonResponse::Error { .. }),
            "expected overlap/missing source rejection for {}, got {bad_resp:?}",
            bad_src.display()
        );
    }

    // 2. Register legitimate `Documents` backup job
    assert!(matches!(
        rt.handle_request(DaemonRequest::UpsertBackupJob(Box::new(BackupJobSpec {
            id: Some("docs-job".to_owned()),
            name: "Documents".to_owned(),
            source_path: docs_src.to_string_lossy().into_owned(),
            vault_folder: "/Backups/Documents".to_owned(),
            interval_minutes: 15,
            enabled: true,
            excludes: vec![
                "desktop.ini".to_owned(),
                "Thumbs.db".to_owned(),
                "~$*".to_owned(),
                "*.tmp".to_owned(),
                ".DS_Store".to_owned(),
            ],
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));

    #[cfg(target_os = "windows")]
    {
        use entrocloud_daemon::dacl::win_acl::query_path_dacl_sddl;
        let sddl = query_path_dacl_sddl(&state_dir.join("backup_jobs.json"))?;
        assert!(sddl.contains("SY") && sddl.contains("OW") && !sddl.contains("WD"));
    }

    // Check initial job status == "Ready"
    match rt.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(st) => {
            assert!(!st.backups_paused);
            assert_eq!(st.backup_jobs.len(), 1);
            assert_eq!(st.backup_jobs[0].status, "Ready");
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    // 3. Initial live backup uploads 2 real files and skips all 4 excluded files!
    match rt
        .handle_request(DaemonRequest::RunBackupJob {
            id: "docs-job".to_owned(),
            preview: false,
        })
        .await
    {
        DaemonResponse::BackupReport(rep) => {
            assert!(!rep.preview);
            assert_eq!(rep.files_scanned, 2);
            assert_eq!(rep.files_uploaded, 2);
            assert_eq!(rep.files_unchanged, 0);
            assert_eq!(
                rep.bytes_uploaded,
                (b"Tax return 2026 payload".len() + b"Project architecture v1".len()) as u64
            );
        }
        other => return Err(format!("expected BackupReport, got {other:?}").into()),
    }

    // Status now reports `"Backed up"`!
    match rt.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(st) => {
            assert_eq!(st.backup_jobs[0].status, "Backed up");
            assert_eq!(st.backup_jobs[0].last_files_synced, 2);
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    // 4. Second backup with zero local changes skips all 2 files in O(1) (`files_uploaded == 0`)!
    match rt
        .handle_request(DaemonRequest::RunBackupJob {
            id: "docs-job".to_owned(),
            preview: false,
        })
        .await
    {
        DaemonResponse::BackupReport(rep) => {
            assert_eq!(rep.files_scanned, 2);
            assert_eq!(rep.files_uploaded, 0);
            assert_eq!(rep.files_unchanged, 2);
            assert_eq!(rep.bytes_uploaded, 0);
        }
        other => return Err(format!("expected BackupReport, got {other:?}").into()),
    }

    // 5. Modify `Projects/notes.md` + add `receipt.txt` -> Dry-Run Preview (`preview: true`)
    std::fs::write(
        docs_src.join("Projects").join("notes.md"),
        b"Project architecture v2 - expanded!",
    )?;
    std::fs::write(docs_src.join("receipt.txt"), b"Hardware receipt $499")?;

    let expected_preview_bytes =
        (b"Project architecture v2 - expanded!".len() + b"Hardware receipt $499".len()) as u64;
    match rt
        .handle_request(DaemonRequest::RunBackupJob {
            id: "docs-job".to_owned(),
            preview: true,
        })
        .await
    {
        DaemonResponse::BackupReport(rep) => {
            assert!(rep.preview);
            assert_eq!(rep.files_scanned, 3);
            assert_eq!(rep.files_uploaded, 2);
            assert_eq!(rep.files_unchanged, 1);
            assert_eq!(rep.bytes_uploaded, expected_preview_bytes);
            assert_eq!(
                rep.message,
                format!(
                    "Preview complete: 2 new/changed file(s) ({expected_preview_bytes} B) to upload, 1 unchanged skipped. No cloud files modified."
                )
            );
        }
        other => return Err(format!("expected preview BackupReport, got {other:?}").into()),
    }

    // Prove preview performed ZERO writes to vault (`/Backups/Documents/receipt.txt` does not exist yet)!
    assert!(matches!(
        rt.handle_request(DaemonRequest::ReadTextNote {
            virtual_path: "/Backups/Documents/receipt.txt".to_owned(),
        })
        .await,
        DaemonResponse::Error { .. }
    ));

    // 6. Commit incremental changes via `RunAllBackups { preview: false }`
    match rt
        .handle_request(DaemonRequest::RunAllBackups { preview: false })
        .await
    {
        DaemonResponse::BackupReport(rep) => {
            assert_eq!(rep.job_id, "*");
            assert_eq!(rep.files_uploaded, 2);
            assert_eq!(rep.files_unchanged, 1);
        }
        other => return Err(format!("expected RunAllBackups report, got {other:?}").into()),
    }

    // 7. Non-destructive delete retention: delete `tax_2026.pdf` locally -> re-run backup -> still retained in vault!
    std::fs::remove_file(docs_src.join("tax_2026.pdf"))?;
    match rt
        .handle_request(DaemonRequest::RunBackupJob {
            id: "docs-job".to_owned(),
            preview: false,
        })
        .await
    {
        DaemonResponse::BackupReport(rep) => {
            assert_eq!(rep.files_scanned, 2);
            assert_eq!(rep.files_uploaded, 0);
            assert_eq!(rep.files_unchanged, 2);
        }
        other => return Err(format!("expected BackupReport, got {other:?}").into()),
    }

    // 8. Restore Overlap Guard: reject restore into `docs_src`, `state_dir`, or `mount_dir`!
    for bad_dest in [&docs_src, &state_dir, &mount_dir] {
        let bad_restore = rt
            .handle_request(DaemonRequest::RestoreBackupJob {
                id: "docs-job".to_owned(),
                destination_parent: bad_dest.to_string_lossy().into_owned(),
            })
            .await;
        assert!(
            matches!(bad_restore, DaemonResponse::Error { .. }),
            "expected restore overlap rejection for {}",
            bad_dest.display()
        );
    }

    // 9. 1-Click `RestoreBackupJob` restores ALL 3 files (including locally deleted `tax_2026.pdf`)!
    let restored_dir = match rt
        .handle_request(DaemonRequest::RestoreBackupJob {
            id: "docs-job".to_owned(),
            destination_parent: restore_parent.to_string_lossy().into_owned(),
        })
        .await
    {
        DaemonResponse::RestoreCompleted {
            restored_folder,
            files_restored,
            bytes_restored,
        } => {
            assert_eq!(files_restored, 3);
            assert_eq!(
                bytes_restored,
                (b"Tax return 2026 payload".len()
                    + b"Project architecture v2 - expanded!".len()
                    + b"Hardware receipt $499".len()) as u64
            );
            PathBuf::from(restored_folder)
        }
        other => return Err(format!("expected RestoreCompleted, got {other:?}").into()),
    };

    let folder_leaf = restored_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing restored_dir leaf")?;
    assert!(
        folder_leaf.starts_with("EntroCloud Restore "),
        "unexpected restore folder leaf: {folder_leaf}"
    );
    assert_eq!(
        std::fs::read(restored_dir.join("tax_2026.pdf"))?,
        b"Tax return 2026 payload"
    );
    assert_eq!(
        std::fs::read(restored_dir.join("Projects").join("notes.md"))?,
        b"Project architecture v2 - expanded!"
    );
    assert_eq!(
        std::fs::read(restored_dir.join("receipt.txt"))?,
        b"Hardware receipt $499"
    );

    // 10. `CancelActiveBackup` pauses scheduling (`status == "Paused"`), and `LockVault` sets `"Locked"`!
    assert!(matches!(
        rt.handle_request(DaemonRequest::CancelActiveBackup).await,
        DaemonResponse::Ok { .. }
    ));
    match rt.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(st) => {
            assert!(st.backups_paused);
            assert_eq!(st.backup_jobs[0].status, "Paused");
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    assert!(matches!(
        rt.handle_request(DaemonRequest::LockVault).await,
        DaemonResponse::Ok { .. }
    ));
    match rt.handle_request(DaemonRequest::Status).await {
        DaemonResponse::Status(st) => {
            assert!(!st.unlocked);
            assert_eq!(st.backup_jobs[0].status, "Locked");
        }
        other => return Err(format!("expected Status, got {other:?}").into()),
    }

    // 11. Background scheduler runs newly added due job automatically when unlocked & unpaused!
    assert!(matches!(
        rt.handle_request(DaemonRequest::UnlockVault {
            passphrase: "backup-engine-passphrase".to_owned(),
        })
        .await,
        DaemonResponse::Ok { .. }
    ));
    assert!(matches!(
        rt.handle_request(DaemonRequest::SetBackupsPaused { paused: false })
            .await,
        DaemonResponse::Ok { .. }
    ));
    let sched_src = tmp.path().join("ScheduledFolder");
    std::fs::create_dir_all(&sched_src)?;
    std::fs::write(sched_src.join("auto.txt"), b"scheduled-background-backup")?;
    assert!(matches!(
        rt.handle_request(DaemonRequest::UpsertBackupJob(Box::new(BackupJobSpec {
            id: Some("sched-job".to_owned()),
            name: "Scheduled".to_owned(),
            source_path: sched_src.to_string_lossy().into_owned(),
            vault_folder: "/Backups/Scheduled".to_owned(),
            interval_minutes: 5,
            enabled: true,
            excludes: Vec::new(),
        })))
        .await,
        DaemonResponse::Ok { .. }
    ));

    let bg = rt
        .spawn_background_sync(Duration::from_millis(50))
        .ok_or("expected background sync handle")?;
    let mut auto_backed_up = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(40)).await;
        if let DaemonResponse::Status(st) = rt.handle_request(DaemonRequest::Status).await
            && let Some(j) = st.backup_jobs.iter().find(|j| j.id == "sched-job")
            && j.last_success_at.is_some()
        {
            auto_backed_up = true;
            break;
        }
    }
    bg.stop().await;
    assert!(
        auto_backed_up,
        "background scheduler failed to run due backup job automatically"
    );

    rt.graceful_shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn debug_entrocloudd_binary_boots_and_answers_ping_without_stack_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    use std::process::Stdio;
    use tokio::time::Instant;

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("subproc_state");

    // Verify `DaemonRuntime::handle_request` outer Future footprint is strictly 16 bytes (2 * usize).
    {
        let probe_rt = DaemonRuntime::builder(
            DaemonStateConfig::new(tmp.path().join("probe_state")).with_mock_vfs(true),
        )
        .with_crypto(Arc::new(MockCryptoEngine::default()))
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?;
        let fut = probe_rt.handle_request(DaemonRequest::Ping);
        assert_eq!(
            std::mem::size_of_val(&fut),
            2 * std::mem::size_of::<usize>(),
            "handle_request outer Future must be a 16-byte Pin<Box<dyn Future>>"
        );
        let resp = fut.await;
        assert!(matches!(resp, DaemonResponse::Ok { .. }));
    }

    #[cfg(target_os = "windows")]
    let ipc_str = format!(r"\\.\pipe\entrocloudd-subproc-{}", Uuid::new_v4().as_simple());
    #[cfg(not(target_os = "windows"))]
    let ipc_str = tmp
        .path()
        .join("entrocloudd-subproc.sock")
        .to_string_lossy()
        .into_owned();

    let daemon_bin = env!("CARGO_BIN_EXE_entrocloudd");
    let mut child = tokio::process::Command::new(daemon_bin)
        .args([
            "--state-dir",
            &state_dir.to_string_lossy(),
            "--ipc",
            &ipc_str,
            "--mock-vfs",
            "--sync-interval-secs",
            "0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let endpoint = IpcEndpoint::parse(&ipc_str)?;
    let client = IpcClient::new(endpoint);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(exited) = child.try_wait()? {
            return Err(format!(
                "entrocloudd subprocess exited prematurely before IPC Ping with status: {exited} (code={:?})",
                exited.code()
            )
            .into());
        }
        if client.ping().await.is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill().await;
            return Err("timed out waiting for entrocloudd subprocess IPC Ping".into());
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // 1. Explicit Ping request
    match client.request(&DaemonRequest::Ping).await? {
        DaemonResponse::Ok { message } => assert_eq!(message, "pong"),
        other => return Err(format!("unexpected Ping response: {other:?}").into()),
    }

    // 2. Status request over real Named Pipe / Unix Socket
    match client.request(&DaemonRequest::Status).await? {
        DaemonResponse::Status(report) => {
            assert!(!report.unlocked);
            assert!(report.vault_id.is_none());
        }
        other => return Err(format!("unexpected Status response: {other:?}").into()),
    }

    // 3. Clean Shutdown request + exit code == Some(0)
    match client.request(&DaemonRequest::Shutdown).await? {
        DaemonResponse::Ok { .. } => {}
        other => return Err(format!("unexpected Shutdown response: {other:?}").into()),
    }

    let exit_status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    assert_eq!(
        exit_status.code(),
        Some(0),
        "expected entrocloudd subprocess clean exit code 0, got {exit_status}"
    );
    Ok(())
}
