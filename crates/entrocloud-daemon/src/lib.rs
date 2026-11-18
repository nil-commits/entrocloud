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
        if fallback_sock != Path::new("/run/user/1000/entrocloud/entrocloudd.sock") {
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
