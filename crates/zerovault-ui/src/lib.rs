//! Zerovault Tauri v2 tray UI view-models, formatting helpers, and daemon IPC commands.

use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager, State, WindowEvent,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use zerovault_daemon::IpcClient;
use zerovault_types::{
    BackendQuota, DaemonRequest, DaemonResponse, RoutingPolicy, VaultStatusReport,
};

/// Shared Tauri application state holding the local [`IpcClient`] connection settings.
#[derive(Debug, Clone, Default)]
pub struct UiAppState {
    /// IPC client targeting `zerovaultd` (Named Pipe / Unix Domain Socket / `ZEROVAULT_ENDPOINT`).
    pub ipc_client: IpcClient,
}

/// Formatted remote account badge data rendered in the system tray popup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteBadgeViewModel {
    /// Backend identifier.
    pub id: String,
    /// Provider kind (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`).
    pub kind: String,
    /// Whether recent requests succeeded.
    pub healthy: bool,
    /// Formatted latency indicator (e.g. `"12 ms"` or `"--"`).
    pub latency_label: String,
    /// Formatted per-remote quota summary.
    pub quota_label: String,
    /// Non-sensitive error message, if unhealthy.
    pub last_error: Option<String>,
}

/// Complete tray popup dashboard view-model derived from [`VaultStatusReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrayStatusViewModel {
    /// Whether `zerovaultd` answered the status request.
    pub daemon_reachable: bool,
    /// Active vault UUID string, if initialized.
    pub vault_id: Option<String>,
    /// Whether master keys are currently unlocked in daemon memory.
    pub unlocked: bool,
    /// Whether the virtual drive is mounted.
    pub mounted: bool,
    /// Active mount point path string, if mounted.
    pub mount_point: Option<String>,
    /// Human-readable sync state (`"Idle"`, `"Syncing (3 pending)"`, `"Locked"`, `"Daemon Offline"`).
    pub sync_state: String,
    /// Formatted upload throughput (e.g. `"12.50 MiB/s"`).
    pub upload_rate: String,
    /// Formatted download throughput (e.g. `"48.00 MiB/s"`).
    pub download_rate: String,
    /// Raw upload throughput in bytes/sec.
    pub upload_bytes_per_sec: u64,
    /// Raw download throughput in bytes/sec.
    pub download_bytes_per_sec: u64,
    /// Number of queued dirty sync operations.
    pub pending_dirty_ops: usize,
    /// Number of non-destructive conflicts recorded.
    pub conflict_count: usize,
    /// Current encrypted manifest revision.
    pub manifest_revision: u64,
    /// Formatted pooled cloud storage quota summary.
    pub quota_summary: String,
    /// Pooled quota fill percentage (`0.0..=100.0`).
    pub quota_used_percent: f64,
    /// Raw pooled used bytes.
    pub quota_used_bytes: u64,
    /// Raw pooled total bytes.
    pub quota_total_bytes: u64,
    /// Active routing policy label.
    pub routing_policy: String,
    /// Per-remote health & quota badges.
    pub remotes: Vec<RemoteBadgeViewModel>,
    /// Optional non-sensitive status/connectivity error banner.
    pub error_message: Option<String>,
}

/// Formats an arbitrary byte count using binary IEC units (`B`, `KiB`, `MiB`, `GiB`, `TiB`).
#[must_use]
pub fn format_bytes_human(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.2} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.2} MiB", b / MIB)
    } else if b < TIB {
        format!("{:.2} GiB", b / GIB)
    } else {
        format!("{:.2} TiB", b / TIB)
    }
}

/// Formats a byte-per-second throughput rate for tray UI display (e.g. `"24.50 MiB/s"`).
#[must_use]
pub fn format_bytes_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes_human(bytes_per_sec))
}

/// Formats a [`BackendQuota`] into a concise pooled storage meter summary string.
#[must_use]
pub fn format_quota_summary(quota: Option<&BackendQuota>) -> String {
    let Some(q) = quota else {
        return "No cloud quota configured".to_owned();
    };

    if q.total_bytes == 0 {
        return format!(
            "{} / 0 B (0.0% used, 0 B free)",
            format_bytes_human(q.used_bytes)
        );
    }

    let pct = ((q.used_bytes as f64) / (q.total_bytes as f64) * 100.0).clamp(0.0, 100.0);
    format!(
        "{} / {} ({pct:.1}% used, {} free)",
        format_bytes_human(q.used_bytes),
        format_bytes_human(q.total_bytes),
        format_bytes_human(q.available_bytes),
    )
}

/// Converts a [`VaultStatusReport`] returned by `zerovaultd` into a [`TrayStatusViewModel`].
#[must_use]
pub fn build_status_view_model(report: &VaultStatusReport) -> TrayStatusViewModel {
    let sync_state = if !report.unlocked {
        "Locked".to_owned()
    } else if report.throughput.pending_dirty_ops > 0 {
        format!("Syncing ({} pending)", report.throughput.pending_dirty_ops)
    } else if report.mounted {
        "Idle (Mounted)".to_owned()
    } else {
        "Unlocked (Unmounted)".to_owned()
    };

    let (quota_used_bytes, quota_total_bytes, quota_used_percent) = match report.pooled_quota.as_ref()
    {
        Some(q) if q.total_bytes > 0 => {
            let pct = ((q.used_bytes as f64) / (q.total_bytes as f64) * 100.0).clamp(0.0, 100.0);
            (q.used_bytes, q.total_bytes, pct)
        }
        Some(q) => (q.used_bytes, 0, 0.0),
        None => (0, 0, 0.0),
    };

    let routing_policy = match report.routing_policy.as_ref() {
        None => "Unconfigured".to_owned(),
        Some(RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        }) => format!("Targeted ({default_backend}, {} rules)", prefix_routes.len()),
        Some(RoutingPolicy::Mirrored { backends, min_ack }) => {
            format!("Mirrored RAID-1 ({}x, ack>={min_ack})", backends.len())
        }
        Some(RoutingPolicy::QuotaPooled { pool_backends }) => {
            format!("Quota-Pooled ({} accounts)", pool_backends.len())
        }
    };

    let remotes = report
        .remotes
        .iter()
        .map(|r| RemoteBadgeViewModel {
            id: r.id.clone(),
            kind: r.kind.clone(),
            healthy: r.health.healthy,
            latency_label: r
                .health
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "--".to_owned()),
            quota_label: format!(
                "{} / {}",
                format_bytes_human(r.health.quota.used_bytes),
                format_bytes_human(r.health.quota.total_bytes)
            ),
            last_error: r.health.last_error.clone(),
        })
        .collect();

    TrayStatusViewModel {
        daemon_reachable: true,
        vault_id: report.vault_id.map(|id| id.to_string()),
        unlocked: report.unlocked,
        mounted: report.mounted,
        mount_point: report.mount_point.clone(),
        sync_state,
        upload_rate: format_bytes_rate(report.throughput.upload_bytes_per_sec),
        download_rate: format_bytes_rate(report.throughput.download_bytes_per_sec),
        upload_bytes_per_sec: report.throughput.upload_bytes_per_sec,
        download_bytes_per_sec: report.throughput.download_bytes_per_sec,
        pending_dirty_ops: report.throughput.pending_dirty_ops,
        conflict_count: report.conflict_count,
        manifest_revision: report.manifest_revision,
        quota_summary: format_quota_summary(report.pooled_quota.as_ref()),
        quota_used_percent,
        quota_used_bytes,
        quota_total_bytes,
        routing_policy,
        remotes,
        error_message: None,
    }
}

/// Builds a graceful offline view-model when `zerovaultd` is unreachable or returns an error.
#[must_use]
pub fn offline_status_view_model(error: &str) -> TrayStatusViewModel {
    TrayStatusViewModel {
        daemon_reachable: false,
        vault_id: None,
        unlocked: false,
        mounted: false,
        mount_point: None,
        sync_state: "Daemon Offline".to_owned(),
        upload_rate: format_bytes_rate(0),
        download_rate: format_bytes_rate(0),
        upload_bytes_per_sec: 0,
        download_bytes_per_sec: 0,
        pending_dirty_ops: 0,
        conflict_count: 0,
        manifest_revision: 0,
        quota_summary: format_quota_summary(None),
        quota_used_percent: 0.0,
        quota_used_bytes: 0,
        quota_total_bytes: 0,
        routing_policy: "Unconfigured".to_owned(),
        remotes: Vec::new(),
        error_message: Some(error.to_owned()),
    }
}

/// Tauri IPC command handlers wired into [`tauri::generate_handler!`].
pub mod commands {
    use super::*;

    /// Tauri IPC command fetching current daemon status for the tray popup UI.
    #[tauri::command]
    pub async fn fetch_status(state: State<'_, UiAppState>) -> Result<TrayStatusViewModel, String> {
        match state.ipc_client.request(&DaemonRequest::Status).await {
            Ok(DaemonResponse::Status(report)) => Ok(build_status_view_model(&report)),
            Ok(DaemonResponse::Error { code, message }) => {
                Ok(offline_status_view_model(&format!("[{code}] {message}")))
            }
            Ok(other) => Ok(offline_status_view_model(&format!(
                "unexpected status response: {other:?}"
            ))),
            Err(err) => Ok(offline_status_view_model(&err.to_string())),
        }
    }

    /// Tauri IPC command triggering an immediate daemon sync (`DaemonRequest::SyncNow`).
    #[tauri::command]
    pub async fn sync_now(state: State<'_, UiAppState>) -> Result<String, String> {
        send_ok_command(&state.ipc_client, DaemonRequest::SyncNow).await
    }

    /// Tauri IPC command immediately locking the vault and zeroizing RAM keys (`DaemonRequest::LockVault`).
    #[tauri::command]
    pub async fn lock_vault(state: State<'_, UiAppState>) -> Result<String, String> {
        send_ok_command(&state.ipc_client, DaemonRequest::LockVault).await
    }
}

pub use commands::{fetch_status, lock_vault, sync_now};

async fn send_ok_command(client: &IpcClient, req: DaemonRequest) -> Result<String, String> {
    match client.request(&req).await {
        Ok(DaemonResponse::Ok { message }) => Ok(message),
        Ok(DaemonResponse::Error { code, message }) => Err(format!("[{code}] {message}")),
        Ok(other) => Err(format!("unexpected daemon response: {other:?}")),
        Err(err) => Err(err.to_string()),
    }
}

fn toggle_tray_popup(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("tray_popup") {
        let visible = window.is_visible().unwrap_or(false);
        if visible {
            let _ = window.hide();
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn show_tray_popup(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("tray_popup") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Configures the Tauri v2 system tray icon, popup toggle behavior, and menu actions.
pub fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open_item = MenuItem::with_id(app, "open_dashboard", "Open Dashboard", true, None::<&str>)?;
    let sync_item = MenuItem::with_id(app, "sync_now", "Sync Now", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock_vault", "Lock Vault", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open_item, &sync_item, &lock_item, &quit_item])?;

    let mut tray_builder = TrayIconBuilder::with_id("zerovault-tray")
        .menu(&menu)
        .tooltip("Zerovault — Zero-Knowledge Multi-Cloud Drive")
        .show_menu_on_left_click(false);

    if let Some(icon) = app.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    }

    tray_builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open_dashboard" => show_tray_popup(app),
            "sync_now" => {
                let client = app.state::<UiAppState>().ipc_client.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = send_ok_command(&client, DaemonRequest::SyncNow).await {
                        tracing::warn!(error = %err, "tray menu sync_now failed");
                    }
                });
            }
            "lock_vault" => {
                let client = app.state::<UiAppState>().ipc_client.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = send_ok_command(&client, DaemonRequest::LockVault).await {
                        tracing::warn!(error = %err, "tray menu lock_vault failed");
                    }
                });
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_tray_popup(tray.app_handle());
            }
        })
        .build(app)?;

    if let Some(popup) = app.get_webview_window("tray_popup") {
        let popup_clone = popup.clone();
        popup.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = popup_clone.hide();
            }
        });
    }

    Ok(())
}

/// Runs the Zerovault Tauri v2 system tray application.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .manage(UiAppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::fetch_status,
            commands::sync_now,
            commands::lock_vault
        ])
        .setup(|app| setup_tray(app))
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use zerovault_types::{
        BackendHealth, BackendKind, BackendQuota, DriveStats, RemoteAccountSummary, RoutingPolicy,
        ThroughputSnapshot, VaultStatusReport,
    };

    use super::*;

    #[test]
    fn formats_bytes_rates_and_quota_summaries() {
        assert_eq!(format_bytes_rate(0), "0 B/s");
        assert_eq!(format_bytes_rate(512), "512 B/s");
        assert_eq!(format_bytes_rate(1536), "1.50 KiB/s");
        assert_eq!(format_bytes_rate(10 * 1024 * 1024), "10.00 MiB/s");
        assert_eq!(format_bytes_rate(2 * 1024 * 1024 * 1024), "2.00 GiB/s");

        assert_eq!(format_quota_summary(None), "No cloud quota configured");

        let zero_quota = BackendQuota {
            backend_id: "pool".to_owned(),
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
        };
        assert_eq!(
            format_quota_summary(Some(&zero_quota)),
            "0 B / 0 B (0.0% used, 0 B free)"
        );

        let quota = BackendQuota {
            backend_id: "pool-total".to_owned(),
            total_bytes: 15 * 1024 * 1024 * 1024,
            used_bytes: 3 * 1024 * 1024 * 1024,
            available_bytes: 12 * 1024 * 1024 * 1024,
        };
        assert_eq!(
            format_quota_summary(Some(&quota)),
            "3.00 GiB / 15.00 GiB (20.0% used, 12.00 GiB free)"
        );
    }

    #[test]
    fn builds_tray_status_view_model_from_report() {
        let report = VaultStatusReport {
            vault_id: None,
            unlocked: true,
            mounted: true,
            mount_point: Some("/mnt/zerovault".to_owned()),
            manifest_revision: 42,
            routing_policy: Some(RoutingPolicy::QuotaPooled {
                pool_backends: vec!["gdrive-1".to_owned(), "s3-2".to_owned()],
            }),
            remotes: vec![RemoteAccountSummary {
                id: "gdrive-1".to_owned(),
                kind: "gdrive".to_owned(),
                root: "/zerovault".to_owned(),
                health: BackendHealth {
                    backend_id: "gdrive-1".to_owned(),
                    kind: BackendKind::GoogleDrive,
                    healthy: true,
                    latency_ms: Some(18),
                    last_error: None,
                    quota: BackendQuota {
                        backend_id: "gdrive-1".to_owned(),
                        total_bytes: 15 * 1024 * 1024 * 1024,
                        used_bytes: 5 * 1024 * 1024 * 1024,
                        available_bytes: 10 * 1024 * 1024 * 1024,
                    },
                },
            }],
            pooled_quota: Some(BackendQuota {
                backend_id: "pool-total".to_owned(),
                total_bytes: 20 * 1024 * 1024 * 1024,
                used_bytes: 5 * 1024 * 1024 * 1024,
                available_bytes: 15 * 1024 * 1024 * 1024,
            }),
            throughput: ThroughputSnapshot {
                upload_bytes_per_sec: 16 * 1024 * 1024,
                download_bytes_per_sec: 64 * 1024 * 1024,
                pending_dirty_ops: 2,
                cache_bytes_used: 8 * 1024 * 1024,
                sampled_at: None,
            },
            drive_stats: DriveStats::default(),
            conflict_count: 1,
        };

        let vm = build_status_view_model(&report);
        assert!(vm.daemon_reachable);
        assert!(vm.unlocked);
        assert!(vm.mounted);
        assert_eq!(vm.sync_state, "Syncing (2 pending)");
        assert_eq!(vm.upload_rate, "16.00 MiB/s");
        assert_eq!(vm.download_rate, "64.00 MiB/s");
        assert!((vm.quota_used_percent - 25.0).abs() < 0.01);
        assert_eq!(vm.routing_policy, "Quota-Pooled (2 accounts)");
        assert_eq!(vm.remotes.len(), 1);
        assert_eq!(vm.remotes[0].latency_label, "18 ms");
        assert_eq!(vm.conflict_count, 1);

        let offline = offline_status_view_model("pipe not found");
        assert!(!offline.daemon_reachable);
        assert_eq!(offline.sync_state, "Daemon Offline");
        assert_eq!(offline.error_message.as_deref(), Some("pipe not found"));
    }
}
