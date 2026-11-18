//! Unit and mock-IPC integration tests for `entrocloud` and `entrocloud-tray`.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use entrocloud_types::{
    BackendHealth, BackendKind, BackendQuota, BackupJobSpec, BackupJobSummary, BackupRunReport,
    CapabilityUri, ConflictRecord, CryptoBenchmarkReport, DaemonRequest, DaemonResponse,
    DetectedCloudFolder, DriveStats, EntryKind, HardwareCryptoCaps, HydrationState, KeyboxSummary,
    MAX_IPC_FRAME_BYTES, OAuthLoginParams, RemoteAccountSummary, RemoteTestReport, RoutingPolicy,
    ThroughputSnapshot, VaultEntrySummary, VaultStatusReport,
};
use entrocloud_ui::{
    ColdBenchReport, DEFAULT_WINDOWS_PIPE_NAME, DialogOutcome, DialogPurpose, EntroCloudApp, Icon,
    IpcClient, IpcEndpoint, MockDaemonServer, NavPage, S3Preset, ThemePreference, TrayBenchReport,
    UiCliArgs, UiCommand, UiWorkerHandle, WizardProvider, WizardStep, count_session_preview_files,
    detect_loaded_webview_modules, export_for_secure_preview, generate_entrocloud_rgba_icon,
    import_local_paths_recursive, install_os_fonts, locate_executable_in_dir, paint_icon,
    read_json_frame, read_raw_frame, scrub_session_dir, unix_socket_path_from_env,
    validate_frame_len, write_json_frame, zero_wipe_and_remove_file,
};
use parking_lot::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

fn sample_unlocked_status() -> VaultStatusReport {
    let gdrive_quota = BackendQuota {
        backend_id: "GoogleDrive".to_owned(),
        total_bytes: 100 * 1024 * 1024 * 1024,
        used_bytes: 18 * 1024 * 1024 * 1024,
        available_bytes: 82 * 1024 * 1024 * 1024,
    };
    VaultStatusReport {
        vault_id: Some(Uuid::new_v4()),
        unlocked: true,
        mounted: true,
        mount_point: Some(r"C:\Users\Alex\EntroCloud".to_owned()),
        manifest_revision: 7,
        keybox_epoch: 2,
        routing_policy: Some(RoutingPolicy::QuotaPooled {
            pool_backends: vec!["GoogleDrive".to_owned()],
        }),
        remotes: vec![RemoteAccountSummary {
            id: "GoogleDrive".to_owned(),
            kind: "gdrive".to_owned(),
            root: "/EntroCloud".to_owned(),
            health: BackendHealth {
                backend_id: "GoogleDrive".to_owned(),
                kind: BackendKind::GoogleDrive,
                healthy: true,
                latency_ms: Some(32),
                last_error: None,
                quota: gdrive_quota.clone(),
            },
        }],
        pooled_quota: Some(gdrive_quota),
        throughput: ThroughputSnapshot {
            upload_bytes_per_sec: 64 * 1024 * 1024,
            download_bytes_per_sec: 128 * 1024 * 1024,
            pending_dirty_ops: 0,
            cache_bytes_used: 32 * 1024 * 1024,
            sampled_at: Some(Utc::now()),
        },
        drive_stats: DriveStats {
            bytes_read: 1024 * 1024 * 50,
            bytes_written: 1024 * 1024 * 12,
            chunks_hydrated: 14,
            cache_hits: 92,
            open_handles: 1,
        },
        conflict_count: 0,
        backups_paused: false,
        backup_jobs: vec![BackupJobSummary {
            id: "job-1".to_owned(),
            name: "Documents".to_owned(),
            source_path: r"C:\Users\Alex\Documents".to_owned(),
            vault_folder: "/Backups/Documents".to_owned(),
            interval_minutes: 15,
            enabled: true,
            excludes: vec!["desktop.ini".to_owned()],
            status: "Backed up".to_owned(),
            last_attempt_at: Some(Utc::now()),
            last_success_at: Some(Utc::now()),
            last_error: None,
            last_files_synced: 42,
            last_bytes_synced: 10 * 1024 * 1024,
        }],
        active_activity: None,
    }
}

fn build_valid_test_ec_uri() -> Result<String> {
    let uri = CapabilityUri {
        backend_hint: "GoogleDrive".to_owned(),
        root_locator: "/EntroCloud".to_owned(),
        share_id: Uuid::new_v4(),
        share_root_key: Zeroizing::new([0x42u8; 32]),
        owner_ed25519_pubkey: [0x99u8; 32],
    };
    Ok(uri.encode()?)
}

fn build_valid_legacy_zv_uri() -> Result<String> {
    let uri = CapabilityUri {
        backend_hint: "s3".to_owned(),
        root_locator: "bucket-alpha/prefix".to_owned(),
        share_id: Uuid::new_v4(),
        share_root_key: Zeroizing::new([0x24u8; 32]),
        owner_ed25519_pubkey: [0x77u8; 32],
    };
    Ok(uri.encode_with_scheme("zv")?)
}

#[test]
fn ipc_frame_encoding_and_prealloc_dos_bounds() -> Result<()> {
    if validate_frame_len(0).is_ok() {
        bail!("zero-length IPC frame must fail closed");
    }
    if validate_frame_len(MAX_IPC_FRAME_BYTES + 1).is_ok() {
        bail!("oversized IPC frame must fail closed");
    }

    let mut forged = Vec::new();
    forged.extend_from_slice(&(0x7FFF_FFFFu32).to_be_bytes());
    forged.extend_from_slice(b"{}");
    let mut cursor = Cursor::new(forged);
    if read_raw_frame(&mut cursor).is_ok() {
        bail!("2 GiB forged frame header must be rejected pre-allocation");
    }

    let mut wire = Vec::new();
    let req = DaemonRequest::BenchCrypto { total_mib: 64 };
    write_json_frame(&mut wire, &req)?;

    let declared_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    if declared_len + 4 != wire.len() {
        bail!(
            "expected 4-byte BE header ({declared_len}) + payload == {}",
            wire.len()
        );
    }

    let mut reader = Cursor::new(wire);
    let decoded: DaemonRequest = read_json_frame(&mut reader)?;
    if !matches!(decoded, DaemonRequest::BenchCrypto { total_mib: 64 }) {
        bail!("decoded DaemonRequest did not match BenchCrypto(64)");
    }

    Ok(())
}

#[test]
fn ipc_endpoint_defaults_to_entrocloudd_and_rejects_lan_tcp() -> Result<()> {
    if DEFAULT_WINDOWS_PIPE_NAME != r"\\.\pipe\entrocloudd" {
        bail!("expected default pipe \\\\.\\pipe\\entrocloudd, got {DEFAULT_WINDOWS_PIPE_NAME}");
    }
    if IpcEndpoint::parse("tcp://192.168.1.50:9000").is_ok() {
        bail!("LAN IP must be rejected by IpcEndpoint::parse");
    }
    if IpcEndpoint::parse("tcp://0.0.0.0:9000").is_ok() {
        bail!("0.0.0.0 must be rejected by IpcEndpoint::parse");
    }
    let lo = IpcEndpoint::parse("tcp://127.0.0.1:44123")?;
    if lo.to_string() != "tcp://127.0.0.1:44123" {
        bail!("unexpected loopback Display: {lo}");
    }

    let xdg_sock = unix_socket_path_from_env(Some(Path::new("/run/user/1000")), 1000);
    if xdg_sock
        != Path::new("/run/user/1000")
            .join("entrocloud")
            .join("entrocloudd.sock")
    {
        bail!("unexpected XDG socket path: {}", xdg_sock.display());
    }
    let fallback_sock = unix_socket_path_from_env(None, 1000);
    if fallback_sock != Path::new("/tmp/entrocloud-1000").join("entrocloudd.sock") {
        bail!("unexpected fallback socket path: {}", fallback_sock.display());
    }

    Ok(())
}

#[test]
fn mock_ipc_server_and_windows_named_pipe_roundtrip() -> Result<()> {
    let server = MockDaemonServer::spawn_tcp(|req| match req {
        DaemonRequest::Ping => DaemonResponse::Ok {
            message: "pong".to_owned(),
        },
        DaemonRequest::Status => DaemonResponse::Status(Box::new(sample_unlocked_status())),
        DaemonRequest::ReadTextNote { virtual_path } => DaemonResponse::TextNote {
            virtual_path,
            content: "zero-temp-file secret note".to_owned(),
        },
        other => DaemonResponse::Error {
            code: "unexpected".to_owned(),
            message: format!("{other:?}"),
        },
    })?;

    let client = IpcClient::new(server.endpoint().clone());
    client.ping()?;

    match client.request(&DaemonRequest::ReadTextNote {
        virtual_path: "/Notes/alpha.md".to_owned(),
    })? {
        DaemonResponse::TextNote {
            virtual_path,
            content,
        } => {
            if virtual_path != "/Notes/alpha.md" || content != "zero-temp-file secret note" {
                bail!("unexpected TextNote payload");
            }
        }
        other => bail!("expected TextNote response, got {other:?}"),
    }

    #[cfg(target_os = "windows")]
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(
            r"\\.\pipe\entrocloud-ui-test-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let pipe_for_server = pipe_name.clone();
        let server_thread = std::thread::spawn(move || -> Result<()> {
            rt.block_on(async move {
                let mut pipe_server = ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(&pipe_for_server)?;
                pipe_server.connect().await?;

                let mut len_hdr = [0u8; 4];
                pipe_server.read_exact(&mut len_hdr).await?;
                let len = u32::from_be_bytes(len_hdr) as usize;
                let mut payload = vec![0u8; len];
                pipe_server.read_exact(&mut payload).await?;
                let req: DaemonRequest = serde_json::from_slice(&payload)?;
                let resp = match req {
                    DaemonRequest::Ping => DaemonResponse::Ok {
                        message: "named-pipe-pong".to_owned(),
                    },
                    _ => DaemonResponse::Error {
                        code: "bad_req".to_owned(),
                        message: "expected Ping".to_owned(),
                    },
                };
                let resp_bytes = serde_json::to_vec(&resp)?;
                let resp_len = u32::try_from(resp_bytes.len())?;
                pipe_server.write_all(&resp_len.to_be_bytes()).await?;
                pipe_server.write_all(&resp_bytes).await?;
                pipe_server.flush().await?;
                Ok(())
            })
        });

        std::thread::sleep(Duration::from_millis(30));
        let np_client = IpcClient::new(IpcEndpoint::parse(&pipe_name)?);
        np_client.ping()?;
        server_thread
            .join()
            .map_err(|_| anyhow::anyhow!("named pipe server thread failed"))??;
    }

    Ok(())
}

#[test]
fn ec_and_legacy_zv_open_uri_plus_passphrase_zeroize_and_async_dialogs() -> Result<()> {
    let ec_uri = build_valid_test_ec_uri()?;
    let zv_uri = build_valid_legacy_zv_uri()?;

    let cli_ec = UiCliArgs::parse_from_iter(["entrocloud", "--open-uri", &ec_uri])?;
    let val_ec = cli_ec
        .validate_open_uri()?
        .context("expected validated ec:// tuple")?;
    if val_ec.0 != ec_uri || !val_ec.1.starts_with("/Shared/share_") {
        bail!("unexpected validated ec:// tuple: {val_ec:?}");
    }

    let quoted_zv = format!("\"{zv_uri}\"");
    let cli_zv = UiCliArgs::parse_from_iter(["entrocloud", &quoted_zv])?;
    let val_zv = cli_zv
        .validate_open_uri()?
        .context("expected validated legacy zv:// tuple")?;
    if val_zv.0 != zv_uri || !val_zv.1.starts_with("/Shared/share_") {
        bail!("unexpected validated zv:// tuple: {val_zv:?}");
    }

    let temp = tempfile::tempdir()?;
    let mock = MockDaemonServer::spawn_tcp(|_| DaemonResponse::Ok {
        message: "ok".to_owned(),
    })?;
    let worker = UiWorkerHandle::spawn(
        IpcClient::new(mock.endpoint().clone()),
        temp.path().join("ui_session"),
        Some(sample_unlocked_status()),
        true,
        false,
        false,
    );
    let bench_slot = Arc::new(Mutex::new(None));
    let mut app = EntroCloudApp::new(None, worker, Some(val_ec.clone()), None, bench_slot);

    let (modal_open, dest_path, has_uri) = app.share_import_modal_summary();
    if !modal_open || !has_uri || dest_path != val_ec.1 {
        bail!("expected ImportCapabilityShare modal open & populated on startup");
    }

    // Verify immediate passphrase zeroization on submit!
    app.set_passphrase_inputs_for_test(
        "correct-horse-battery-staple",
        "correct-horse-battery-staple",
        true,
    );
    if app.are_passphrase_buffers_empty() {
        bail!("passphrase buffers should contain input prior to submit");
    }
    app.submit_passphrase_action("/")
        .map_err(|e| anyhow::anyhow!(e))?;
    if !app.are_passphrase_buffers_empty() {
        bail!("passphrase input buffers MUST be zeroized immediately upon submit!");
    }

    // Verify non-blocking AsyncDialogs channel routing updates BackupJobModal without blocking UI!
    let picked_dir = PathBuf::from(r"C:\Users\Alex\Pictures");
    app.dialogs().inject_for_test(DialogOutcome::FolderPicked {
        purpose: DialogPurpose::BackupJobSourceFolder,
        path: picked_dir.clone(),
    });
    let egui_ctx = eframe::egui::Context::default();
    install_os_fonts(&egui_ctx);
    let _ = egui_ctx.run(eframe::egui::RawInput::default(), |ctx| {
        app.render_headless_frame(ctx);
    });
    if app.backup_modal_source_path() != picked_dir.display().to_string() {
        bail!(
            "AsyncDialogs folder selection did not populate BackupJobModalState: got {}",
            app.backup_modal_source_path()
        );
    }

    Ok(())
}

#[test]
fn recursive_import_walks_nested_dirs_and_skips_symlinks() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let src_root = temp.path().join("ProjectAlpha");
    let sub_dir = src_root.join("Specs");
    std::fs::create_dir_all(&sub_dir)?;
    std::fs::write(src_root.join("readme.txt"), b"top-level doc")?;
    std::fs::write(sub_dir.join("design.md"), b"nested spec")?;

    let outside_secret = temp.path().join("outside_secret.txt");
    std::fs::write(&outside_secret, b"DO NOT IMPORT")?;
    let link_path = sub_dir.join("sneaky_link.txt");
    let symlink_created = create_test_file_symlink(&outside_secret, &link_path);

    let recorded_ops: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let ops_for_server = Arc::clone(&recorded_ops);

    let server = MockDaemonServer::spawn_tcp(move |req| match req {
        DaemonRequest::CreateDirectory { virtual_path } => {
            ops_for_server
                .lock()
                .push(("mkdir".to_owned(), virtual_path));
            DaemonResponse::Ok {
                message: "dir created".to_owned(),
            }
        }
        DaemonRequest::ImportLocalFile {
            local_path,
            virtual_dest_path,
        } => {
            ops_for_server
                .lock()
                .push((format!("import:{local_path}"), virtual_dest_path));
            DaemonResponse::Ok {
                message: "imported".to_owned(),
            }
        }
        other => DaemonResponse::Error {
            code: "unexpected".to_owned(),
            message: format!("{other:?}"),
        },
    })?;

    let client = IpcClient::new(server.endpoint().clone());
    let summary = import_local_paths_recursive(&client, std::slice::from_ref(&src_root), "/VaultDocs")
        .map_err(|e| anyhow::anyhow!(e))?;

    if summary.created_dirs != 2 || summary.imported_files != 2 {
        bail!("expected 2 dirs and 2 files imported, got {summary:?}");
    }
    if symlink_created && summary.skipped_symlinks != 1 {
        bail!("expected 1 skipped symlink, got {summary:?}");
    }

    let ops = recorded_ops.lock().clone();
    let vpaths: Vec<&str> = ops.iter().map(|(_, vp)| vp.as_str()).collect();
    if vpaths.iter().any(|vp| vp.contains("sneaky_link")) {
        bail!("symlink MUST NEVER be imported into vault!");
    }

    Ok(())
}

#[test]
fn secure_preview_and_zero_wipe_scrubber_overwrites_and_deletes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let session_root = temp.path().join("ui_session");

    std::fs::create_dir_all(&session_root)?;
    let direct_file = session_root.join("sensitive.bin");
    let secret_bytes = vec![0xAAu8; 90_000];
    std::fs::write(&direct_file, &secret_bytes)?;
    zero_wipe_and_remove_file(&direct_file, secret_bytes.len() as u64, &[0u8; 16 * 1024]);
    if direct_file.exists() {
        bail!("zero_wipe_and_remove_file failed to unlink sensitive.bin");
    }

    let server = MockDaemonServer::spawn_tcp(|req| match req {
        DaemonRequest::ExportVaultFile {
            local_dest_path, ..
        } => {
            if let Err(err) = std::fs::write(&local_dest_path, b"TOP SECRET PREVIEW PAYLOAD") {
                return DaemonResponse::Error {
                    code: "io_error".to_owned(),
                    message: err.to_string(),
                };
            }
            DaemonResponse::Ok {
                message: "exported".to_owned(),
            }
        }
        other => DaemonResponse::Error {
            code: "unexpected".to_owned(),
            message: format!("{other:?}"),
        },
    })?;

    let client = IpcClient::new(server.endpoint().clone());
    let exported_path = export_for_secure_preview(&client, &session_root, "/Finance/q4_tax.pdf")
        .map_err(|e| anyhow::anyhow!(e))?;
    if !exported_path.is_file() || count_session_preview_files(&session_root) != 1 {
        bail!("expected 1 exported preview file on disk");
    }

    let outside_target = temp.path().join("keep_intact.txt");
    std::fs::write(&outside_target, b"MUST SURVIVE")?;
    let _ = create_test_file_symlink(&outside_target, &session_root.join("ext_link.txt"));

    let wiped = scrub_session_dir(&session_root);
    if wiped != 1 || session_root.exists() {
        bail!("expected scrub_session_dir to wipe 1 file and remove session_root");
    }
    if std::fs::read(&outside_target)? != b"MUST SURVIVE" {
        bail!("scrubber followed symlink outside session_root!");
    }

    Ok(())
}

#[test]
fn wizard_light_dark_themes_backup_views_grid_list_and_nonblocking_oauth() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let temp_dir_str = temp.path().display().to_string();
    let temp_for_srv = temp_dir_str.clone();
    let session_dir = temp.path().join("ui_session");
    std::fs::create_dir_all(&session_dir)?;
    let preview_file = session_dir.join("preview_doc.pdf");
    std::fs::write(&preview_file, b"decrypted preview bytes")?;

    let fake_bin_name = if cfg!(target_os = "windows") {
        "entrocloudd.exe"
    } else {
        "entrocloudd"
    };
    std::fs::write(temp.path().join(fake_bin_name), b"stub")?;
    if locate_executable_in_dir(temp.path(), "entrocloudd").is_none() {
        bail!("expected locate_executable_in_dir to find sibling entrocloudd");
    }

    let rgba_icon = generate_entrocloud_rgba_icon(32, 32);
    if rgba_icon.len() != 32 * 32 * 4 {
        bail!("expected 4096 RGBA bytes for 32x32 brand icon");
    }

    let call_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_for_srv = Arc::clone(&call_log);
    let oauth_gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let oauth_gate_srv = Arc::clone(&oauth_gate);

    let server = MockDaemonServer::spawn_tcp(move |req| {
        let tag = match &req {
            DaemonRequest::Status => "status",
            DaemonRequest::ListDirectory { .. } => "listdir",
            DaemonRequest::UpsertBackupJob(_) => "upsert_backup",
            DaemonRequest::RunBackupJob { .. } => "run_backup",
            DaemonRequest::RunAllBackups { .. } => "run_all_backups",
            DaemonRequest::RestoreBackupJob { .. } => "restore_backup",
            DaemonRequest::SetBackupsPaused { .. } => "pause_backups",
            DaemonRequest::CancelActiveBackup => "cancel_backup",
            DaemonRequest::TestRemote { .. } => "test_remote",
            DaemonRequest::OAuthLogin(_) => "oauth_login",
            DaemonRequest::CancelOAuth => "cancel_oauth",
            DaemonRequest::SaveTextNote { .. } => "save_note",
            DaemonRequest::ReadTextNote { .. } => "read_note",
            DaemonRequest::Unpin { .. } => "unpin",
            DaemonRequest::Dehydrate { .. } => "dehydrate",
            DaemonRequest::InitKeybox => "init_keybox",
            DaemonRequest::RevokeKeyboxRecipient { .. } => "revoke_keybox",
            DaemonRequest::ListConflicts => "conflicts",
            DaemonRequest::BenchCrypto { .. } => "bench_crypto",
            _ => "other",
        };
        log_for_srv.lock().push(tag.to_owned());

        match req {
            DaemonRequest::Status => DaemonResponse::Status(Box::new(sample_unlocked_status())),
            DaemonRequest::ListDirectory { virtual_path } => DaemonResponse::DirectoryEntries {
                virtual_path,
                entries: vec![
                    VaultEntrySummary {
                        inode: 2,
                        name: "Contracts".to_owned(),
                        virtual_path: "/Contracts".to_owned(),
                        kind: EntryKind::Directory,
                        size: 0,
                        hydration: HydrationState::OnlineOnly,
                        pinned: false,
                        version: 1,
                        modified_at: Utc::now(),
                    },
                    VaultEntrySummary {
                        inode: 3,
                        name: "report.md".to_owned(),
                        virtual_path: "/report.md".to_owned(),
                        kind: EntryKind::File,
                        size: 128,
                        hydration: HydrationState::Pinned,
                        pinned: true,
                        version: 1,
                        modified_at: Utc::now(),
                    },
                ],
            },
            DaemonRequest::OAuthLogin(_) => {
                // Block until `CancelOAuth` arrives on a separate connection — proving `OAuthLogin`
                // runs on its own short-lived thread and NEVER blocks `worker_loop`!
                let start = Instant::now();
                while !oauth_gate_srv.load(std::sync::atomic::Ordering::Relaxed)
                    && start.elapsed() < Duration::from_secs(3)
                {
                    std::thread::sleep(Duration::from_millis(15));
                }
                DaemonResponse::Error {
                    code: "cancelled".to_owned(),
                    message: "OAuth sign-in cancelled".to_owned(),
                }
            }
            DaemonRequest::CancelOAuth => {
                oauth_gate_srv.store(true, std::sync::atomic::Ordering::Relaxed);
                DaemonResponse::Ok {
                    message: "cancelled".to_owned(),
                }
            }
            DaemonRequest::TestRemote { id } => DaemonResponse::RemoteTest(RemoteTestReport {
                id,
                kind: "gdrive".to_owned(),
                healthy: true,
                latency_ms: 29,
                quota: BackendQuota {
                    backend_id: "GoogleDrive".to_owned(),
                    total_bytes: 100 * 1024 * 1024 * 1024,
                    used_bytes: 18 * 1024 * 1024 * 1024,
                    available_bytes: 82 * 1024 * 1024 * 1024,
                },
                message: "Healthy".to_owned(),
            }),
            DaemonRequest::RunBackupJob { id, preview } => {
                DaemonResponse::BackupReport(BackupRunReport {
                    job_id: id,
                    preview,
                    files_scanned: 10,
                    files_uploaded: 2,
                    files_unchanged: 8,
                    bytes_uploaded: 4096,
                    elapsed_ms: 45,
                    message: "Backed up 2 changed files".to_owned(),
                })
            }
            DaemonRequest::RestoreBackupJob {
                destination_parent, ..
            } => DaemonResponse::RestoreCompleted {
                restored_folder: format!("{destination_parent}\\Documents_Restored"),
                files_restored: 10,
                bytes_restored: 4096,
            },
            DaemonRequest::ReadTextNote { virtual_path } => DaemonResponse::TextNote {
                virtual_path,
                content: "# Private Note\nStored in RAM.".to_owned(),
            },
            DaemonRequest::DetectLocalClouds => {
                DaemonResponse::DetectedClouds(vec![DetectedCloudFolder {
                    provider: "OneDrive".to_owned(),
                    suggested_id: "onedrive-local".to_owned(),
                    path: temp_for_srv.clone(),
                }])
            }
            DaemonRequest::InitKeybox | DaemonRequest::RevokeKeyboxRecipient { .. } => {
                DaemonResponse::KeyboxInfo(KeyboxSummary {
                    vault_id: Uuid::new_v4(),
                    epoch: 3,
                    owner_pubkey_hex: "aa".repeat(32),
                    recipient_ids: vec!["bb".repeat(16)],
                })
            }
            DaemonRequest::ListConflicts => DaemonResponse::Conflicts(vec![ConflictRecord {
                original_path: "/Notes/todo.md".to_owned(),
                conflict_path: "/Notes/todo (conflict).md".to_owned(),
                remote_revision: 5,
                detected_at: Utc::now(),
            }]),
            DaemonRequest::BenchCrypto { total_mib } => {
                DaemonResponse::CryptoBench(CryptoBenchmarkReport {
                    caps: HardwareCryptoCaps {
                        arch: "x86_64".to_owned(),
                        aes_hw: true,
                        pclmul_hw: true,
                        vaes_hw: true,
                        avx2_hw: true,
                        mandatory_satisfied: true,
                        backend_name: "ring VAES+VPCLMULQDQ".to_owned(),
                    },
                    total_mib,
                    encrypt_mib_per_sec: 4850.0,
                    decrypt_mib_per_sec: 5120.0,
                    encrypt_elapsed_ms: 13,
                    decrypt_elapsed_ms: 12,
                })
            }
            _ => DaemonResponse::Ok {
                message: "ok".to_owned(),
            },
        }
    })?;

    let worker = UiWorkerHandle::spawn(
        IpcClient::new(server.endpoint().clone()),
        session_dir.clone(),
        Some(sample_unlocked_status()),
        true,
        false,
        true,
    );

    // Start OAuthLogin (which blocks on `oauth_gate` on its dedicated short-lived thread),
    // then immediately send `CancelOAuth` through `worker`!
    worker.send(UiCommand::OAuthLogin {
        params: Box::new(OAuthLoginParams {
            id: "GoogleDrive".to_owned(),
            kind: "gdrive".to_owned(),
            root: "/EntroCloud".to_owned(),
            client_id: "test-client".to_owned(),
            client_secret: Some("test-secret".to_owned()),
            auth_url: None,
            token_url: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            timeout_secs: Some(30),
            open_browser: false,
        }),
    });
    std::thread::sleep(Duration::from_millis(40));
    worker.send(UiCommand::CancelOAuth);

    worker.send(UiCommand::UpsertBackupJob {
        spec: Box::new(BackupJobSpec {
            id: None,
            name: "Pictures".to_owned(),
            source_path: temp_dir_str.clone(),
            vault_folder: "/Backups/Pictures".to_owned(),
            interval_minutes: 60,
            enabled: true,
            excludes: Vec::new(),
        }),
    });
    worker.send(UiCommand::RunBackupJob {
        id: "job-1".to_owned(),
        preview: true,
    });
    worker.send(UiCommand::RestoreBackupJob {
        id: "job-1".to_owned(),
        destination_parent: temp_dir_str,
    });
    worker.send(UiCommand::SetBackupsPaused { paused: true });
    worker.send(UiCommand::CancelActiveBackup);
    worker.send(UiCommand::TestRemote {
        id: "GoogleDrive".to_owned(),
    });
    worker.send(UiCommand::SaveTextNote {
        virtual_path: "/Notes/secret.md".to_owned(),
        content: Zeroizing::new("hello zero temp".to_owned()),
        refresh_dir: "/".to_owned(),
    });
    worker.send(UiCommand::ReadTextNote {
        virtual_path: "/Notes/secret.md".to_owned(),
    });
    worker.send(UiCommand::FreeUpSpace {
        virtual_path: "/report.md".to_owned(),
        refresh_dir: "/".to_owned(),
    });
    worker.send(UiCommand::InitKeybox);
    worker.send(UiCommand::RevokeKeyboxRecipient {
        recipient_id: "bb".repeat(16),
    });
    worker.send(UiCommand::RefreshConflicts);
    worker.send(UiCommand::RunCryptoBench { total_mib: 64 });

    let wait_start = Instant::now();
    while wait_start.elapsed() < Duration::from_secs(4) {
        if worker.state.lock().crypto_bench.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if worker.state.lock().crypto_bench.is_none() {
        bail!("worker did not finish queued commands (OAuth may have blocked worker_loop!)");
    }

    // Exercise headless egui layout across BOTH Light and Dark themes, ALL 4 Wizard steps & ALL 6 Cloud Guides,
    // ALL 6 Workspace pages (including Grid & List explorer), and all vector Icons!
    let bench_slot = Arc::new(Mutex::new(None));
    let mut app = EntroCloudApp::new(
        None,
        worker,
        Some((build_valid_test_ec_uri()?, "/Shared/test_doc".to_owned())),
        None,
        bench_slot,
    );
    let egui_ctx = eframe::egui::Context::default();
    install_os_fonts(&egui_ctx);

    for theme in [ThemePreference::Light, ThemePreference::Dark, ThemePreference::System] {
        app.set_theme_preference(theme);

        // Step through all 4 Wizard steps & all 6 providers + S3 presets
        for step in [
            WizardStep::Welcome,
            WizardStep::ConnectCloud,
            WizardStep::MasterPassword,
            WizardStep::Ready,
        ] {
            app.wizard_mut().open_full(step);
            if step == WizardStep::ConnectCloud {
                for prov in [
                    WizardProvider::SyncedFolder,
                    WizardProvider::GoogleDrive,
                    WizardProvider::OneDrive,
                    WizardProvider::Dropbox,
                    WizardProvider::S3,
                    WizardProvider::WebDav,
                ] {
                    app.wizard_mut().select_provider(prov);
                    if prov == WizardProvider::S3 {
                        for preset in [
                            S3Preset::CloudflareR2,
                            S3Preset::BackblazeB2,
                            S3Preset::AmazonS3,
                            S3Preset::Wasabi,
                            S3Preset::CustomMinio,
                        ] {
                            app.wizard_mut().apply_s3_preset(preset);
                        }
                    }
                    let _ = egui_ctx.run(eframe::egui::RawInput::default(), |ctx| {
                        app.render_headless_frame(ctx);
                    });
                }
            } else {
                let _ = egui_ctx.run(eframe::egui::RawInput::default(), |ctx| {
                    app.render_headless_frame(ctx);
                });
            }
        }
        app.wizard_mut().open = false;

        // Render all 6 Workspace pages (testing both Grid and List view on MyFiles)
        for page in [
            NavPage::Backups,
            NavPage::MyFiles,
            NavPage::CloudConnections,
            NavPage::ComputerDrive,
            NavPage::Sharing,
            NavPage::Settings,
        ] {
            app.set_active_tab(page);
            for grid_mode in [true, false] {
                app.set_file_view_grid(grid_mode);
                let _ = egui_ctx.run(eframe::egui::RawInput::default(), |ctx| {
                    app.render_headless_frame(ctx);
                    // Also exercise every single vector icon in `src/icons.rs`!
                    egui::CentralPanel::default().show(ctx, |ui| {
                        for ic in [
                            Icon::BrandShieldCloud,
                            Icon::HomeBackups,
                            Icon::Folder,
                            Icon::FolderOpen,
                            Icon::File,
                            Icon::FileText,
                            Icon::Cloud,
                            Icon::CloudPlus,
                            Icon::HardDrive,
                            Icon::ShareLink,
                            Icon::Users,
                            Icon::Settings,
                            Icon::Lock,
                            Icon::Unlock,
                            Icon::Plus,
                            Icon::Upload,
                            Icon::Download,
                            Icon::Search,
                            Icon::Grid,
                            Icon::List,
                            Icon::Pin,
                            Icon::Check,
                            Icon::Alert,
                            Icon::Refresh,
                            Icon::ExternalLink,
                            Icon::Trash,
                            Icon::Edit,
                            Icon::Play,
                            Icon::Pause,
                            Icon::Stop,
                            Icon::Sun,
                            Icon::Moon,
                            Icon::Eye,
                            Icon::EyeOff,
                            Icon::Copy,
                            Icon::ChevronRight,
                            Icon::ArrowLeft,
                            Icon::Sparkles,
                            Icon::BookOpen,
                            Icon::Close,
                            Icon::MoreHorizontal,
                            Icon::SortAsc,
                            Icon::SortDesc,
                        ] {
                            let (r, _) = ui.allocate_exact_size(
                                eframe::egui::Vec2::splat(18.0),
                                eframe::egui::Sense::hover(),
                            );
                            paint_icon(ui.painter(), r, ic, eframe::egui::Color32::WHITE);
                        }
                    });
                });
            }
        }
    }

    drop(app);
    if preview_file.exists() || session_dir.exists() {
        bail!("closing EntroCloudApp MUST zero-wipe and remove session_dir preview files");
    }

    let recorded = call_log.lock().clone();
    for expected in [
        "oauth_login",
        "cancel_oauth",
        "upsert_backup",
        "run_backup",
        "restore_backup",
        "pause_backups",
        "cancel_backup",
        "test_remote",
        "save_note",
        "read_note",
        "unpin",
        "dehydrate",
        "init_keybox",
        "revoke_keybox",
        "conflicts",
        "bench_crypto",
    ] {
        if !recorded.iter().any(|item| item == expected) {
            bail!("missing expected IPC call '{expected}' in {recorded:?}");
        }
    }

    Ok(())
}

#[test]
fn source_audit_zero_emojis_zero_dingbats_and_zero_sync_rfd_outside_dialogs() -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut stack = vec![src_dir];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;

            // 1. Verify ZERO synchronous `rfd::FileDialog` calls outside `src/dialogs.rs`!
            let is_dialogs_mod = path.file_name().and_then(|s| s.to_str()) == Some("dialogs.rs");
            if !is_dialogs_mod && content.contains("FileDialog") {
                bail!(
                    "Found forbidden synchronous FileDialog usage outside src/dialogs.rs in {}",
                    path.display()
                );
            }

            // 2. Verify ZERO Unicode emojis, dingbats, box-drawing, or geometric tofu-box symbols!
            for (line_no, line) in content.lines().enumerate() {
                for ch in line.chars() {
                    let cp = ch as u32;
                    let is_forbidden_symbol = (0x2500..=0x27BF).contains(&cp)
                        || (0x1F000..=0x1FFFF).contains(&cp)
                        || cp == 0xFF0B; // fullwidth plus `＋`
                    if is_forbidden_symbol {
                        bail!(
                            "Forbidden Unicode emoji/dingbat U+{cp:04X} ('{ch}') in {}:{}",
                            path.display(),
                            line_no + 1
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[test]
fn bench_cold_and_bench_tray_executables_render_and_verify_zero_webview2() -> Result<()> {
    if !detect_loaded_webview_modules().is_empty() {
        bail!("unexpected browser module in test runner");
    }

    let server = MockDaemonServer::spawn_tcp(|req| match req {
        DaemonRequest::Status => DaemonResponse::Status(Box::new(sample_unlocked_status())),
        DaemonRequest::Ping => DaemonResponse::Ok {
            message: "pong".to_owned(),
        },
        _ => DaemonResponse::Ok {
            message: "ok".to_owned(),
        },
    })?;

    let ui_exe = env!("CARGO_BIN_EXE_entrocloud");
    let ep_str = server.endpoint().to_string();

    let out = Command::new(ui_exe)
        .args(["--bench-cold", "--ipc", &ep_str])
        .output()
        .context("failed spawning entrocloud --bench-cold")?;

    if !out.status.success() {
        bail!(
            "entrocloud --bench-cold failed (status {:?}): stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let json_line = stdout_str
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .with_context(|| format!("missing JSON line in --bench-cold stdout: {stdout_str}"))?;
    let report: ColdBenchReport = serde_json::from_str(json_line)
        .with_context(|| format!("invalid ColdBenchReport JSON: {json_line}"))?;

    if report.mode != "bench-cold" || report.renderer != "glow" {
        bail!("unexpected bench-cold mode/renderer: {report:?}");
    }
    if !report.ipc_connected {
        bail!("expected bench-cold to connect to MockDaemonServer over --ipc");
    }
    if report.webview2_modules != 0 || report.webview2_detected {
        bail!("WebView2 module detected in entrocloud: {report:?}");
    }
    if report.cold_open_latency_ms <= 0.0 || report.working_set_64 == 0 {
        bail!("expected positive cold_open_latency_ms and working_set_64: {report:?}");
    }

    let tray_exe = env!("CARGO_BIN_EXE_entrocloud-tray");
    let tray_out = Command::new(tray_exe)
        .args(["--bench-tray", "--settle-ms", "80", "--ipc", &ep_str])
        .output()
        .context("failed spawning entrocloud-tray --bench-tray")?;

    if !tray_out.status.success() {
        bail!(
            "entrocloud-tray --bench-tray failed (status {:?}): stderr={}",
            tray_out.status.code(),
            String::from_utf8_lossy(&tray_out.stderr)
        );
    }

    let tray_stdout = String::from_utf8_lossy(&tray_out.stdout);
    let tray_json = tray_stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .with_context(|| format!("missing JSON line in --bench-tray stdout: {tray_stdout}"))?;
    let tray_report: TrayBenchReport = serde_json::from_str(tray_json)
        .with_context(|| format!("invalid TrayBenchReport JSON: {tray_json}"))?;

    if tray_report.closed_window_ui_process_rss_bytes != 0 || tray_report.webview2_modules != 0 {
        bail!("unexpected tray benchmark report: {tray_report:?}");
    }

    for bad in [
        "EmbeddedBrowserWebView.dll",
        "WebView2Loader.dll",
        "msedgewebview2.exe",
        "libwebkit2gtk-4.1.so",
        "libcef.dll",
        "CefSharp.Core.dll",
    ] {
        if !entrocloud_ui::is_forbidden_browser_module_name(bad) {
            bail!("expected is_forbidden_browser_module_name to flag {bad}");
        }
    }
    for clean in [
        "opengl32.dll",
        "kernel32.dll",
        "uiautomationcore.dll",
        "entrocloud.exe",
    ] {
        if entrocloud_ui::is_forbidden_browser_module_name(clean) {
            bail!("unexpected false positive on clean module {clean}");
        }
    }

    for bin_path in [ui_exe, tray_exe] {
        let raw_bytes = std::fs::read(bin_path)?;
        let lower_ascii: Vec<u8> = raw_bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
        for forbidden_marker in [
            &b"webview2loader"[..],
            &b"embeddedbrowserwebview"[..],
            &b"microsoft.webview2runtime"[..],
            &b"msedgewebview2"[..],
            &b"__tauri_internals__"[..],
            &b"tauri_runtime_wry"[..],
            &b"webkit2gtk"[..],
            &b"libcef"[..],
            &b"cefsharp"[..],
        ] {
            if lower_ascii
                .windows(forbidden_marker.len())
                .any(|w| w == forbidden_marker)
            {
                bail!(
                    "binary {bin_path} contains forbidden .rdata marker {:?}",
                    String::from_utf8_lossy(forbidden_marker)
                );
            }
        }
    }

    Ok(())
}

fn create_test_file_symlink(original: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(original, link).is_ok()
    }
    #[cfg(target_os = "windows")]
    {
        std::os::windows::fs::symlink_file(original, link).is_ok()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (original, link);
        false
    }
}
