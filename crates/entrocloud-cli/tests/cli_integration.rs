//! Comprehensive CLI parser and end-to-end IPC integration tests for `ec` (`entrocloud-cli`).

use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use entrocloud_cli::{
    BackupCommands, Commands, NoteCommands, OAuthKindArg, RemoteCommands, RemoteKindArg,
    RoutingPolicyArg, ShareCommands, parse_cli_from, run_cli_with_io,
};
use entrocloud_daemon::{DaemonRuntime, DaemonStateConfig, IpcEndpoint, IpcServer};
use entrocloud_types::mocks::{InMemorySecretStore, MockCryptoEngine};
use entrocloud_types::{
    BackupJobSummary, BackupRunReport, CapabilityUri, CryptoEngine, KeyboxSummary,
    LEGACY_CAPABILITY_URI_SCHEME, RecipientPublicBundle, RemoteTestReport, VaultStatusReport,
};

async fn exec_ec<I, S>(args: I, stdin_bytes: &[u8]) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = parse_cli_from(args)?;
    let input = stdin_bytes.to_vec();
    Box::pin(async move {
        let mut stdin = Cursor::new(input);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        run_cli_with_io(cli, &mut stdin, &mut stdout, &mut stderr).await?;
        Ok(String::from_utf8(stdout)?)
    })
    .await
}

#[test]
fn parses_all_required_ec_subcommands_and_global_flags() -> Result<(), Box<dyn std::error::Error>> {
    let init = parse_cli_from(["ec", "--ipc", "tcp://127.0.0.1:4444", "init", "--passphrase-stdin"])?;
    assert_eq!(init.ipc.as_deref(), Some("tcp://127.0.0.1:4444"));
    assert_eq!(
        init.command,
        Commands::Init {
            passphrase_stdin: true
        }
    );

    let unlock = parse_cli_from(["ec", "--json", "unlock", "--passphrase-stdin"])?;
    assert!(unlock.json);
    assert_eq!(
        unlock.command,
        Commands::Unlock {
            passphrase_stdin: true
        }
    );

    assert_eq!(parse_cli_from(["ec", "lock"])?.command, Commands::Lock);
    assert_eq!(parse_cli_from(["ec", "status"])?.command, Commands::Status);
    assert_eq!(parse_cli_from(["ec", "sync"])?.command, Commands::Sync);
    assert_eq!(parse_cli_from(["ec", "unmount"])?.command, Commands::Unmount);
    assert_eq!(parse_cli_from(["ec", "conflicts"])?.command, Commands::Conflicts);
    assert_eq!(parse_cli_from(["ec", "shutdown"])?.command, Commands::Shutdown);

    let remote_add = parse_cli_from([
        "ec",
        "remote",
        "add",
        "s3-main",
        "--kind",
        "s3",
        "--root",
        "vault",
        "--quota-mib",
        "512",
        "--policy",
        "pooled",
        "--secret-stdin",
    ])?;
    match remote_add.command {
        Commands::Remote {
            action: RemoteCommands::Add(a),
        } => {
            assert_eq!(a.id, "s3-main");
            assert_eq!(a.kind, RemoteKindArg::S3);
            assert_eq!(a.policy, Some(RoutingPolicyArg::Pooled));
            assert!(a.secret_stdin);
        }
        other => return Err(format!("unexpected remote add: {other:?}").into()),
    }

    assert_eq!(
        parse_cli_from(["ec", "remote", "remove", "s3-main"])?.command,
        Commands::Remote {
            action: RemoteCommands::Remove {
                id: "s3-main".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "remote", "test", "s3-main"])?.command,
        Commands::Remote {
            action: RemoteCommands::Test {
                id: "s3-main".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "remote", "list"])?.command,
        Commands::Remote {
            action: RemoteCommands::List
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "remote", "detect-clouds"])?.command,
        Commands::Remote {
            action: RemoteCommands::DetectClouds
        }
    );

    let set_policy = parse_cli_from([
        "ec",
        "remote",
        "set-policy",
        "--mode",
        "targeted",
        "--default-backend",
        "cloud-a",
        "--route",
        "/Docs=cloud-b",
    ])?;
    match set_policy.command {
        Commands::Remote {
            action: RemoteCommands::SetPolicy(p),
        } => {
            assert_eq!(p.mode, RoutingPolicyArg::Targeted);
            assert_eq!(p.default_backend.as_deref(), Some("cloud-a"));
            assert_eq!(p.routes, vec!["/Docs=cloud-b".to_owned()]);
        }
        other => return Err(format!("unexpected set-policy: {other:?}").into()),
    }

    let oauth = parse_cli_from([
        "ec",
        "remote",
        "oauth",
        "gd-1",
        "--kind",
        "gdrive",
        "--client-id",
        "cid-123",
        "--no-browser",
    ])?;
    match oauth.command {
        Commands::Remote {
            action: RemoteCommands::OAuth(o),
        } => {
            assert_eq!(o.id, "gd-1");
            assert_eq!(o.kind, OAuthKindArg::Gdrive);
            assert_eq!(o.root, "/EntroCloud");
            assert!(o.no_browser);
        }
        other => return Err(format!("unexpected oauth: {other:?}").into()),
    }

    assert_eq!(
        parse_cli_from(["ec", "backup", "list"])?.command,
        Commands::Backup {
            action: BackupCommands::List
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "remove", "job-1"])?.command,
        Commands::Backup {
            action: BackupCommands::Remove {
                id: "job-1".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "run", "job-1"])?.command,
        Commands::Backup {
            action: BackupCommands::Run {
                id: Some("job-1".to_owned()),
                all: false
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "preview", "--all"])?.command,
        Commands::Backup {
            action: BackupCommands::Preview {
                id: None,
                all: true
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "restore", "job-1", "/tmp/restores"])?.command,
        Commands::Backup {
            action: BackupCommands::Restore {
                id: "job-1".to_owned(),
                destination_parent: "/tmp/restores".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "pause"])?.command,
        Commands::Backup {
            action: BackupCommands::Pause
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "resume"])?.command,
        Commands::Backup {
            action: BackupCommands::Resume
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "backup", "stop"])?.command,
        Commands::Backup {
            action: BackupCommands::Stop
        }
    );

    assert_eq!(
        parse_cli_from(["ec", "mount", "/mnt/ec", "--mock-vfs"])?.command,
        Commands::Mount {
            path: "/mnt/ec".to_owned(),
            mock_vfs: true
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "pin", "/a.txt"])?.command,
        Commands::Pin {
            virtual_path: "/a.txt".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "unpin", "/a.txt"])?.command,
        Commands::Unpin {
            virtual_path: "/a.txt".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "dehydrate", "/a.txt"])?.command,
        Commands::Dehydrate {
            virtual_path: "/a.txt".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "ls"])?.command,
        Commands::Ls {
            virtual_path: "/".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "mkdir", "/Docs"])?.command,
        Commands::Mkdir {
            virtual_path: "/Docs".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "import", "./local.bin", "/Docs"])?.command,
        Commands::Import {
            local_path: "./local.bin".to_owned(),
            virtual_dest_path: "/Docs".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "export", "/Docs/local.bin", "./out.bin"])?.command,
        Commands::Export {
            virtual_path: "/Docs/local.bin".to_owned(),
            local_dest_path: "./out.bin".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "rm", "/Docs", "-r"])?.command,
        Commands::Rm {
            virtual_path: "/Docs".to_owned(),
            recursive: true
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "mv", "/a.txt", "/b.txt"])?.command,
        Commands::Mv {
            virtual_path: "/a.txt".to_owned(),
            new_virtual_path: "/b.txt".to_owned()
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "note", "read", "/n.md"])?.command,
        Commands::Note {
            action: NoteCommands::Read {
                virtual_path: "/n.md".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "note", "save", "/n.md", "--stdin"])?.command,
        Commands::Note {
            action: NoteCommands::Save {
                virtual_path: "/n.md".to_owned(),
                content: None,
                stdin: true
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "id", "--label", "alice"])?.command,
        Commands::Share {
            action: ShareCommands::Id {
                label: "alice".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "create-uri", "/n.md"])?.command,
        Commands::Share {
            action: ShareCommands::CreateUri {
                virtual_path: "/n.md".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "import-uri", "ec://share/v1/fs?share=123#abc", "/Shared"])?
            .command,
        Commands::Share {
            action: ShareCommands::ImportUri {
                uri: "ec://share/v1/fs?share=123#abc".to_owned(),
                dest_virtual_path: "/Shared".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "keybox-init"])?.command,
        Commands::Share {
            action: ShareCommands::KeyboxInit
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "keybox-grant", "BUNDLEB64"])?.command,
        Commands::Share {
            action: ShareCommands::KeyboxGrant {
                recipient_bundle_b64: "BUNDLEB64".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "keybox-revoke", "deadbeef"])?.command,
        Commands::Share {
            action: ShareCommands::KeyboxRevoke {
                recipient_id: "deadbeef".to_owned()
            }
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "share", "keybox-status"])?.command,
        Commands::Share {
            action: ShareCommands::KeyboxStatus
        }
    );
    assert_eq!(
        parse_cli_from(["ec", "bench-crypto", "--mib", "8"])?.command,
        Commands::BenchCrypto {
            mib: 8,
            daemon: false
        }
    );

    Ok(())
}

#[tokio::test]
async fn local_and_json_bench_crypto_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let human = exec_ec(["ec", "bench-crypto", "--mib", "4"], b"").await?;
    assert!(human.contains("EntroCloud Hardware Crypto Benchmark"));
    assert!(human.contains("MiB/s"));

    let json = exec_ec(["ec", "--json", "bench-crypto", "--mib", "4"], b"").await?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    assert_eq!(parsed.get("total_mib").and_then(|v| v.as_u64()), Some(4));
    Ok(())
}

#[tokio::test]
async fn cli_full_end_to_end_workflow_over_ipc() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_a = tmp.path().join("cloud_a");
    let cloud_b = tmp.path().join("cloud_b");
    let mount_dir = tmp.path().join("mount");
    let local_src = tmp.path().join("local_input.txt");
    let local_dst = tmp.path().join("local_exported.txt");
    let backup_src = tmp.path().join("pc_backup_folder");
    let restore_parent = tmp.path().join("pc_restores");

    std::fs::write(&local_src, b"CLI end-to-end encrypted payload")?;
    std::fs::create_dir_all(&backup_src)?;
    std::fs::write(backup_src.join("report.txt"), b"Backup report v1")?;
    std::fs::write(backup_src.join("desktop.ini"), b"ignored")?;

    let mock_crypto = Arc::new(MockCryptoEngine::default());
    mock_crypto.lock_vault().await?;
    let bob_identity = mock_crypto.generate_recipient_identity("bob")?;
    let bob_bundle_b64: String = RecipientPublicBundle::to_base64(&bob_identity.public)?;

    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(state_dir).with_mock_vfs(true))
            .with_crypto(mock_crypto)
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()?,
    );

    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = IpcServer::bind(IpcEndpoint::TcpLoopback(addr)).await?;
    let ep = server.endpoint().to_string();

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

    // 1. Pre-vault onboarding: `ec remote detect-clouds`, `ec remote add`, and `ec remote test` BEFORE `ec init`!
    let clouds_out = exec_ec(["ec", "--ipc", &ep, "remote", "detect-clouds"], b"").await?;
    assert!(clouds_out.contains("Local Backup"));

    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "remote",
            "add",
            "cloud-a",
            "--kind",
            "fs",
            "--root",
            &cloud_a.to_string_lossy(),
            "--quota-mib",
            "128",
            "--policy",
            "pooled",
        ],
        b"",
    )
    .await?;

    let test_json = exec_ec(["ec", "--ipc", &ep, "--json", "remote", "test", "cloud-a"], b"").await?;
    let test_rep: RemoteTestReport = serde_json::from_str(&test_json)?;
    assert!(test_rep.healthy);
    assert_eq!(test_rep.id, "cloud-a");

    // 2. init (--passphrase-stdin) -> publishes header.zvh to `cloud-a`!
    exec_ec(
        ["ec", "--ipc", &ep, "init", "--passphrase-stdin"],
        b"cli-full-passphrase\n",
    )
    .await?;

    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "remote",
            "add",
            "cloud-b",
            "--kind",
            "fs",
            "--root",
            &cloud_b.to_string_lossy(),
            "--quota-mib",
            "128",
            "--policy",
            "pooled",
        ],
        b"",
    )
    .await?;

    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "remote",
            "set-policy",
            "--mode",
            "mirrored",
            "--backends",
            "cloud-a,cloud-b",
            "--min-ack",
            "2",
        ],
        b"",
    )
    .await?;
    exec_ec(["ec", "--ipc", &ep, "remote", "remove", "cloud-b"], b"").await?;
    let remotes_txt = exec_ec(["ec", "--ipc", &ep, "remote", "list"], b"").await?;
    assert!(remotes_txt.contains("cloud-a"));
    assert!(!remotes_txt.contains("cloud-b"));

    // 3. `ec backup {add, list, preview, run, pause, resume, stop, restore, remove}`
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "backup",
            "add",
            "WorkDocs",
            &backup_src.to_string_lossy(),
            "--id",
            "work-docs",
            "--interval",
            "15",
        ],
        b"",
    )
    .await?;

    let jobs_json = exec_ec(["ec", "--ipc", &ep, "--json", "backup", "list"], b"").await?;
    let jobs: Vec<BackupJobSummary> = serde_json::from_str(&jobs_json)?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, "work-docs");

    let preview_json = exec_ec(
        ["ec", "--ipc", &ep, "--json", "backup", "preview", "work-docs"],
        b"",
    )
    .await?;
    let preview_rep: BackupRunReport = serde_json::from_str(&preview_json)?;
    assert!(preview_rep.preview);
    assert_eq!(preview_rep.files_uploaded, 1);

    let run_json = exec_ec(
        ["ec", "--ipc", &ep, "--json", "backup", "run", "work-docs"],
        b"",
    )
    .await?;
    let run_rep: BackupRunReport = serde_json::from_str(&run_json)?;
    assert!(!run_rep.preview);
    assert_eq!(run_rep.files_uploaded, 1);

    exec_ec(["ec", "--ipc", &ep, "backup", "pause"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "backup", "resume"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "backup", "stop"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "backup", "resume"], b"").await?;

    let restore_out = exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "--json",
            "backup",
            "restore",
            "work-docs",
            &restore_parent.to_string_lossy(),
        ],
        b"",
    )
    .await?;
    let restore_val: serde_json::Value = serde_json::from_str(&restore_out)?;
    let restored_folder = restore_val
        .get("RestoreCompleted")
        .and_then(|o| o.get("restored_folder"))
        .and_then(|v| v.as_str())
        .ok_or("missing RestoreCompleted.restored_folder")?;
    assert_eq!(
        std::fs::read(PathBuf::from(restored_folder).join("report.txt"))?,
        b"Backup report v1"
    );

    exec_ec(["ec", "--ipc", &ep, "backup", "remove", "work-docs"], b"").await?;

    // 4. mount -> mkdir -> import -> ls -> mv -> pin -> unpin -> dehydrate -> export -> note -> rm -> unmount
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "mount",
            &mount_dir.to_string_lossy(),
            "--mock-vfs",
        ],
        b"",
    )
    .await?;
    exec_ec(["ec", "--ipc", &ep, "mkdir", "/Docs"], b"").await?;
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "import",
            &local_src.to_string_lossy(),
            "/Docs",
        ],
        b"",
    )
    .await?;
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "mv",
            "/Docs/local_input.txt",
            "/Docs/renamed.txt",
        ],
        b"",
    )
    .await?;
    exec_ec(["ec", "--ipc", &ep, "pin", "/Docs/renamed.txt"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "unpin", "/Docs/renamed.txt"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "dehydrate", "/Docs/renamed.txt"], b"").await?;
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "export",
            "/Docs/renamed.txt",
            &local_dst.to_string_lossy(),
        ],
        b"",
    )
    .await?;
    assert_eq!(
        std::fs::read(&local_dst)?,
        b"CLI end-to-end encrypted payload"
    );

    exec_ec(
        ["ec", "--ipc", &ep, "note", "save", "/Docs/memo.md", "--stdin"],
        b"Top secret CLI note",
    )
    .await?;
    let note_out = exec_ec(["ec", "--ipc", &ep, "note", "read", "/Docs/memo.md"], b"").await?;
    assert_eq!(note_out.trim_end(), "Top secret CLI note");

    let ls_out = exec_ec(["ec", "--ipc", &ep, "ls", "/Docs"], b"").await?;
    assert!(ls_out.contains("renamed.txt"));
    assert!(ls_out.contains("memo.md"));

    // 5. share {id, create-uri (ec://), import-uri (ec:// AND legacy zv://), keybox-*}
    let id_json = exec_ec(["ec", "--ipc", &ep, "--json", "share", "id", "--label", "owner"], b"").await?;
    assert!(id_json.contains("recipient_id"));

    let uri_json = exec_ec(
        ["ec", "--ipc", &ep, "--json", "share", "create-uri", "/Docs/memo.md"],
        b"",
    )
    .await?;
    let parsed_uri_resp: serde_json::Value = serde_json::from_str(&uri_json)?;
    let share_uri = parsed_uri_resp
        .get("ShareUriCreated")
        .and_then(|o| o.get("uri"))
        .and_then(|v| v.as_str())
        .ok_or("missing ShareUriCreated.uri")?
        .to_owned();
    assert!(
        share_uri.starts_with("ec://share/v1/"),
        "expected primary ec:// URI, got {share_uri}"
    );

    // Import primary `ec://` URI
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "share",
            "import-uri",
            &share_uri,
            "/Docs/memo_imported.md",
        ],
        b"",
    )
    .await?;
    let imported_note =
        exec_ec(["ec", "--ipc", &ep, "note", "read", "/Docs/memo_imported.md"], b"").await?;
    assert_eq!(imported_note.trim_end(), "Top secret CLI note");

    // Import legacy `zv://` URI
    let legacy_zv_uri = CapabilityUri::parse(&share_uri)?
        .encode_with_scheme(LEGACY_CAPABILITY_URI_SCHEME)?;
    assert!(legacy_zv_uri.starts_with("zv://share/v1/"));
    exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "share",
            "import-uri",
            &legacy_zv_uri,
            "/Docs/memo_legacy_zv.md",
        ],
        b"",
    )
    .await?;
    let imported_legacy =
        exec_ec(["ec", "--ipc", &ep, "note", "read", "/Docs/memo_legacy_zv.md"], b"").await?;
    assert_eq!(imported_legacy.trim_end(), "Top secret CLI note");

    exec_ec(["ec", "--ipc", &ep, "share", "keybox-init"], b"").await?;
    exec_ec(
        ["ec", "--ipc", &ep, "share", "keybox-grant", &bob_bundle_b64],
        b"",
    )
    .await?;
    let kb_after_revoke = exec_ec(
        [
            "ec",
            "--ipc",
            &ep,
            "--json",
            "share",
            "keybox-revoke",
            &bob_identity.public.recipient_id,
        ],
        b"",
    )
    .await?;
    let kb_summary: KeyboxSummary = serde_json::from_str(&kb_after_revoke)?;
    assert_eq!(kb_summary.epoch, 2);
    assert!(!kb_summary.recipient_ids.contains(&bob_identity.public.recipient_id));

    let kb_status_txt = exec_ec(["ec", "--ipc", &ep, "share", "keybox-status"], b"").await?;
    assert!(kb_status_txt.contains("Keybox Epoch:    2"));

    // 6. sync, conflicts, daemon bench-crypto, status --json, rm -r, unmount, lock, unlock, shutdown
    exec_ec(["ec", "--ipc", &ep, "sync"], b"").await?;
    let conflicts_txt = exec_ec(["ec", "--ipc", &ep, "conflicts"], b"").await?;
    assert!(conflicts_txt.contains("Conflicts (0):"));

    let daemon_bench = exec_ec(
        ["ec", "--ipc", &ep, "bench-crypto", "--mib", "4", "--daemon"],
        b"",
    )
    .await?;
    assert!(daemon_bench.contains("EntroCloud Hardware Crypto Benchmark"));

    let status_json = exec_ec(["ec", "--ipc", &ep, "--json", "status"], b"").await?;
    let status: VaultStatusReport = serde_json::from_str(&status_json)?;
    assert!(status.unlocked);
    assert!(status.mounted);
    assert_eq!(status.keybox_epoch, 2);

    exec_ec(["ec", "--ipc", &ep, "rm", "/Docs", "-r"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "unmount"], b"").await?;
    exec_ec(["ec", "--ipc", &ep, "lock"], b"").await?;
    exec_ec(
        ["ec", "--ipc", &ep, "unlock", "--passphrase-stdin"],
        b"cli-full-passphrase\n",
    )
    .await?;
    exec_ec(["ec", "--ipc", &ep, "shutdown"], b"").await?;

    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn ec_binary_subprocess_handles_ec_passphrase_and_legacy_zv_passphrase()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");

    let runtime = Arc::new(
        DaemonRuntime::builder(DaemonStateConfig::new(state_dir).with_mock_vfs(true))
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()?,
    );

    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = IpcServer::bind(IpcEndpoint::TcpLoopback(addr)).await?;
    let ep = server.endpoint().to_string();

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

    let ec_bin = env!("CARGO_BIN_EXE_ec");

    // 1. `ec init` reading passphrase from primary `EC_PASSPHRASE` env var (`Zeroizing<String>`)
    let init_out = tokio::process::Command::new(ec_bin)
        .args(["--ipc", &ep, "init"])
        .env("EC_PASSPHRASE", "subprocess-env-secret-passphrase")
        .env_remove("ZV_PASSPHRASE")
        .output()
        .await?;
    assert!(
        init_out.status.success(),
        "ec init with EC_PASSPHRASE failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // 2. `ec lock` then `ec unlock` falling back cleanly to legacy `ZV_PASSPHRASE`!
    let lock_out = tokio::process::Command::new(ec_bin)
        .args(["--ipc", &ep, "lock"])
        .output()
        .await?;
    assert!(lock_out.status.success());

    let unlock_out = tokio::process::Command::new(ec_bin)
        .args(["--ipc", &ep, "unlock"])
        .env_remove("EC_PASSPHRASE")
        .env("ZV_PASSPHRASE", "subprocess-env-secret-passphrase")
        .output()
        .await?;
    assert!(
        unlock_out.status.success(),
        "ec unlock with fallback ZV_PASSPHRASE failed: {}",
        String::from_utf8_lossy(&unlock_out.stderr)
    );

    let shutdown_out = tokio::process::Command::new(ec_bin)
        .args(["--ipc", &ep, "shutdown"])
        .output()
        .await?;
    assert!(shutdown_out.status.success());

    server_task.await??;
    Ok(())
}
