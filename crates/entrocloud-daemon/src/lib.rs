//! EntroCloud v1.0 background synchronization & PC folder backup daemon library and owner-only local IPC transport.
//!
//! Exposes:
//! - [`backup`]: CloudBridge-inspired automatic PC folder backup, `O(1)` incremental skip, dry-run preview,
//!   path-overlap guards, 1-click AEAD restore, and `SchedulePolicy` background cadence.
//! - [`dacl`]: owner-only `PROTECTED_DACL` (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`) and POSIX `0700`/`0600`
//!   enforcement for Named Pipes, `state_dir`, `staging_dir`, and state files.
//! - [`ipc`]: 4-byte BE length-prefixed (`<= 1 MiB` pre-alloc check) UTF-8 JSON IPC with `64`-connection
//!   semaphore, `30s` frame I/O deadlines, owner-ACL Windows Named Pipes (`\\.\pipe\entrocloudd`),
//!   and safe `NEW-L02` Unix Domain Socket binding (`$XDG_RUNTIME_DIR/entrocloud/entrocloudd.sock`).
//! - [`service`]: [`DaemonRuntime`] orchestrating pre-vault remote onboarding, multi-device cloud bootstrap,
//!   cancellable periodic background sync & backup scheduling, symlink-safe bounded `4 MiB` import/export,
//!   `Unpin` VFS sync, `ec://` (and legacy `zv://`) capability shares, and `keybox.zv` post-quantum epoch rotation.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod backup;
pub mod dacl;
pub mod ipc;
pub mod service;

pub use backup::{
    DEFAULT_BACKUP_EXCLUDES, MAX_BACKUP_INTERVAL_MINUTES, PersistedBackupState, SchedulePolicy,
    StoredBackupJob, clean_local_path_display, compute_job_status, make_restore_folder_name,
    paths_overlap, should_exclude, wildcard_match,
};
pub use dacl::{
    OWNER_ONLY_DIR_SDDL, OWNER_ONLY_FILE_SDDL, OWNER_ONLY_PIPE_SDDL, ensure_owner_only_dir,
    ensure_owner_only_file, is_symlink_or_reparse,
};
pub use ipc::{
    DEFAULT_WINDOWS_PIPE_NAME, IPC_FRAME_IO_TIMEOUT, IpcClient, IpcEndpoint, IpcServer,
    MAX_CONCURRENT_IPC_CONNECTIONS, default_unix_socket_path_for_uid, read_frame, read_json_frame,
    validate_frame_len, write_frame, write_json_frame,
};
pub use service::{
    BackgroundSyncHandle, CoreSyncEngineFactory, DEFAULT_SECRET_SERVICE, DEFAULT_SYNC_INTERVAL,
    DaemonRuntime, DaemonRuntimeBuilder, DaemonStateConfig, DefaultDriveFactory, DriveFactory,
    DynamicStorageRouter, MAX_TEXT_NOTE_BYTES, MockSyncEngineFactory, SyncBackendBundle,
    SyncBackendProvider, SyncEngineFactory, SyncRunner, SyncTelemetryProvider, backend_kind_label,
    detect_local_cloud_folders, normalize_vault_virtual_path, parse_backend_kind,
};
pub use entrocloud_types;

/// Dedicated 8 MiB thread stack size for host and Tokio worker threads (prevents 1 MiB PE stack overflow in `dev` builds).
pub const DAEMON_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Runs the EntroCloud background synchronization, backup, and virtual drive daemon until a
/// shutdown signal (`Ctrl-C` / `SIGTERM`) is received.
///
/// Shared by the standalone `entrocloudd` binary and the self-contained single-executable
/// `EntroCloud.exe --daemon` mode.
pub fn run_daemon_blocking(
    state_dir: Option<std::path::PathBuf>,
    ipc: Option<String>,
    mock_vfs: bool,
    sync_interval_secs: u64,
) -> anyhow::Result<()> {
    use anyhow::{Context, anyhow};

    let join_handle = std::thread::Builder::new()
        .name("entrocloudd-main".to_owned())
        .stack_size(DAEMON_THREAD_STACK_BYTES)
        .spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .thread_name("entrocloudd-worker")
                .thread_stack_size(DAEMON_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .context("failed building Tokio multi-thread runtime")?;
            rt.block_on(Box::pin(async_daemon_main(
                state_dir,
                ipc,
                mock_vfs,
                sync_interval_secs,
            )))
        })
        .context("failed spawning 8 MiB entrocloudd-main thread")?;

    match join_handle.join() {
        Ok(res) => res,
        Err(_) => Err(anyhow!("entrocloudd-main thread panicked unexpectedly")),
    }
}

async fn async_daemon_main(
    state_dir: Option<std::path::PathBuf>,
    ipc: Option<String>,
    mock_vfs: bool,
    sync_interval_secs: u64,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context;
    use entrocloud_core::reclaim_process_memory;

    let sync_interval = Duration::from_secs(sync_interval_secs);
    let config = match state_dir {
        Some(dir) => DaemonStateConfig::new(dir),
        None => DaemonStateConfig::default(),
    }
    .with_mock_vfs(mock_vfs)
    .with_sync_interval(sync_interval);

    let endpoint = match ipc {
        Some(raw) => IpcEndpoint::parse(&raw).context("invalid --ipc / --endpoint value")?,
        None => IpcEndpoint::from_env_or_default().context("failed resolving IPC endpoint")?,
    };

    let runtime = Arc::new(
        DaemonRuntime::new_default(config).context("failed initializing EntroCloud daemon runtime")?,
    );
    let server = IpcServer::bind(endpoint)
        .await
        .context("failed binding EntroCloud IPC server")?;

    let bg_sync = runtime.spawn_background_sync(sync_interval);
    reclaim_process_memory().await;

    tracing::info!(
        endpoint = %server.endpoint(),
        mock_vfs,
        sync_interval_secs,
        "entrocloudd listening"
    );

    let shutdown_runtime = Arc::clone(&runtime);
    let signal_shutdown = Box::pin(async move {
        let signal_name = wait_for_daemon_shutdown_signal().await;
        tracing::info!(
            signal = signal_name,
            "received shutdown signal, locking vault and unmounting virtual drive"
        );
        if let Err(err) = shutdown_runtime.graceful_shutdown().await {
            tracing::warn!(error = %err, "error during graceful shutdown");
        }
    });

    let dispatch_runtime = Arc::clone(&runtime);
    let serve_res = server
        .serve_with_shutdown(
            move |req| {
                let rt = Arc::clone(&dispatch_runtime);
                Box::pin(async move { rt.handle_request(req).await })
            },
            signal_shutdown,
        )
        .await;

    if let Some(bg) = bg_sync {
        bg.stop().await;
    }
    let _ = runtime.graceful_shutdown().await;

    serve_res.context("IPC server exited with error")?;
    tracing::info!("entrocloudd exited cleanly");
    Ok(())
}

async fn wait_for_daemon_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    res = tokio::signal::ctrl_c() => {
                        if let Err(err) = res {
                            tracing::warn!(error = %err, "failed awaiting ctrl-c signal");
                        }
                        "SIGINT"
                    }
                    _ = sigterm.recv() => "SIGTERM",
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed registering SIGTERM handler; falling back to Ctrl-C only");
                if let Err(ctrl_err) = tokio::signal::ctrl_c().await {
                    tracing::warn!(error = %ctrl_err, "failed awaiting ctrl-c signal");
                }
                "SIGINT"
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "failed awaiting ctrl-c signal");
        }
        "Ctrl-C"
    }
}

#[cfg(test)]
mod unit_tests {
    use std::path::Path;

    use entrocloud_types::{BackendKind, MAX_IPC_FRAME_BYTES};

    use super::*;

    #[test]
    fn entrocloud_rebrand_defaults_match_contract() -> Result<(), String> {
        if DEFAULT_WINDOWS_PIPE_NAME != r"\\.\pipe\entrocloudd" {
            return Err(format!("unexpected pipe name: {DEFAULT_WINDOWS_PIPE_NAME}"));
        }
        if DEFAULT_SECRET_SERVICE != "entrocloud" {
            return Err(format!("unexpected secret service: {DEFAULT_SECRET_SERVICE}"));
        }
        let xdg_sock = default_unix_socket_path_for_uid(Some(Path::new("/run/user/1000")), 1000);
        if xdg_sock != Path::new("/run/user/1000/entrocloud/entrocloudd.sock") {
            return Err(format!("unexpected xdg socket path: {}", xdg_sock.display()));
        }
        let fallback_sock = default_unix_socket_path_for_uid(None, 1000);
        if fallback_sock != Path::new("/tmp/entrocloud-1000").join("entrocloudd.sock") {
            return Err(format!(
                "unexpected fallback socket path: {}",
                fallback_sock.display()
            ));
        }
        let mp = DaemonStateConfig::default_mount_point();
        if mp.file_name().and_then(|s| s.to_str()) != Some("EntroCloud") {
            return Err(format!("unexpected default mount point: {}", mp.display()));
        }
        let cfg = DaemonStateConfig::default();
        if cfg.secret_service != "entrocloud" {
            return Err("expected default secret_service == entrocloud".into());
        }
        Ok(())
    }

    #[test]
    fn normalizes_paths_and_rejects_traversal() -> Result<(), String> {
        if normalize_vault_virtual_path(r"\Docs\2026\.\tax.pdf").map_err(|e| e.to_string())?
            != "/Docs/2026/tax.pdf"
        {
            return Err("unexpected normalized virtual path".into());
        }
        if normalize_vault_virtual_path("/").map_err(|e| e.to_string())? != "/" {
            return Err("root normalization failed".into());
        }
        if normalize_vault_virtual_path("/Docs/../etc/passwd").is_ok() {
            return Err("expected traversal '..' rejection".into());
        }
        if normalize_vault_virtual_path("").is_ok() {
            return Err("expected empty path rejection".into());
        }
        Ok(())
    }

    #[test]
    fn parses_backend_kinds_and_ipc_endpoints() -> Result<(), String> {
        if parse_backend_kind("gdrive").map_err(|e| e.to_string())? != BackendKind::GoogleDrive {
            return Err("gdrive kind mismatch".into());
        }
        if parse_backend_kind("onedrive").map_err(|e| e.to_string())? != BackendKind::OneDrive {
            return Err("onedrive kind mismatch".into());
        }
        if parse_backend_kind("s3").map_err(|e| e.to_string())? != BackendKind::S3 {
            return Err("s3 kind mismatch".into());
        }
        if parse_backend_kind("unknown-cloud").is_ok() {
            return Err("expected unknown cloud rejection".into());
        }
        if IpcEndpoint::parse("tcp://0.0.0.0:9000").is_ok() {
            return Err("expected non-loopback TCP rejection".into());
        }
        if IpcEndpoint::parse("tcp://127.0.0.1:9000").is_err() {
            return Err("expected loopback TCP acceptance".into());
        }
        if validate_frame_len(0).is_ok() || validate_frame_len(MAX_IPC_FRAME_BYTES + 1).is_ok() {
            return Err("expected frame length bound enforcement".into());
        }
        validate_frame_len(MAX_IPC_FRAME_BYTES).map_err(|e| e.to_string())
    }
}
