//! `entrocloud-tray` ultra-lightweight native system tray companion (`tray-icon 0.26.1`).
//!
//! Zero `eframe`/`egui`/`WebView2`/`tokio` dependencies so `entrocloud-tray` stays compact on disk
//! and ~5-10 MiB RSS while `entrocloud` consumes `0 bytes` when closed.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

#[allow(dead_code)]
#[path = "../ipc_client.rs"]
mod ipc_client;

#[allow(dead_code)]
#[path = "../metrics.rs"]
mod metrics;

#[allow(dead_code)]
#[path = "../tray_common.rs"]
mod tray_common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use entrocloud_types::DaemonRequest;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use zeroize::Zeroizing;

use crate::ipc_client::{
    IpcClient, IpcEndpoint, locate_sibling_executable, spawn_detached_process,
};
use crate::metrics::{
    TrayBenchReport, detect_loaded_webview_modules, elapsed_ms, now_ticks,
    sample_current_process_memory,
};
use crate::tray_common::generate_entrocloud_rgba_icon;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct TrayCli {
    ipc: Option<String>,
    bench_tray: bool,
    settle_ms: u64,
}

fn parse_tray_cli() -> TrayCli {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ipc = None;
    let mut bench_tray = false;
    let mut settle_ms = 400u64;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--bench-tray" => bench_tray = true,
            "--ipc" => {
                if let Some(val) = args.get(i + 1) {
                    ipc = Some(val.clone());
                    i += 1;
                }
            }
            "--settle-ms" => {
                if let Some(val) = args.get(i + 1) {
                    if let Ok(parsed) = val.parse::<u64>() {
                        settle_ms = parsed;
                    }
                    i += 1;
                }
            }
            arg if arg.starts_with("--ipc=") => {
                ipc = arg.strip_prefix("--ipc=").map(str::to_owned);
            }
            _ => {}
        }
        i += 1;
    }

    TrayCli {
        ipc,
        bench_tray,
        settle_ms,
    }
}

fn main() {
    let cli = parse_tray_cli();
    if let Err(err) = run_tray(cli) {
        eprintln!("entrocloud-tray error: {err}");
        std::process::exit(1);
    }
}

fn run_tray(cli: TrayCli) -> Result<(), String> {
    let start_ticks = now_ticks();

    let (endpoint, is_default_ep) =
        IpcEndpoint::resolve(cli.ipc.as_deref()).map_err(|e| e.to_string())?;
    let client = IpcClient::new(endpoint);

    let icon_rgba = generate_entrocloud_rgba_icon(32, 32);
    let icon = Icon::from_rgba(icon_rgba, 32, 32)
        .map_err(|err| format!("Failed building 32x32 RGBA tray icon: {err}"))?;

    let menu = Menu::new();
    let item_open = MenuItem::new("Open EntroCloud", true, None);
    let item_sync = MenuItem::new("Sync / Back Up Now", true, None);
    let item_lock = MenuItem::new("Lock Vault", true, None);
    let item_quit = MenuItem::new("Quit", true, None);

    menu.append(&item_open)
        .map_err(|e| format!("Failed appending Open EntroCloud menu item: {e}"))?;
    menu.append(&item_sync)
        .map_err(|e| format!("Failed appending Sync / Back Up Now menu item: {e}"))?;
    menu.append(&item_lock)
        .map_err(|e| format!("Failed appending Lock Vault menu item: {e}"))?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| format!("Failed appending menu separator: {e}"))?;
    menu.append(&item_quit)
        .map_err(|e| format!("Failed appending Quit menu item: {e}"))?;

    let open_id = item_open.id().clone();
    let sync_id = item_sync.id().clone();
    let lock_id = item_lock.id().clone();
    let quit_id = item_quit.id().clone();

    let tray_icon = TrayIconBuilder::new()
        .with_id("entrocloud")
        .with_title("EntroCloud")
        .with_tooltip("EntroCloud — Private Cloud Vault")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()
        .map_err(|err| format!("TrayIconBuilder failed: {err}"))?;

    let tray_init_ms = elapsed_ms(start_ticks, now_ticks());
    let bench_deadline = if cli.bench_tray {
        Some(Instant::now() + Duration::from_millis(cli.settle_ms))
    } else {
        None
    };
    let sync_inflight = Arc::new(AtomicBool::new(false));

    loop {
        pump_platform_messages();

        while let Ok(tray_ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = tray_ev
            {
                let _ = spawn_ui_window(cli.ipc.as_deref());
            }
        }

        while let Ok(menu_ev) = MenuEvent::receiver().try_recv() {
            if menu_ev.id == open_id {
                let _ = spawn_ui_window(cli.ipc.as_deref());
            } else if menu_ev.id == sync_id {
                if sync_inflight
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    let bg_client = client.clone();
                    let bg_flag = Arc::clone(&sync_inflight);
                    let spawn_res = thread::Builder::new()
                        .name("ec-tray-sync".to_owned())
                        .spawn(move || {
                            let _ = bg_client
                                .ensure_daemon_running(is_default_ep, Duration::from_millis(1500));
                            let _ =
                                bg_client.request(&DaemonRequest::RunAllBackups { preview: false });
                            let _ = bg_client.request(&DaemonRequest::SyncNow);
                            bg_flag.store(false, Ordering::SeqCst);
                        });
                    if spawn_res.is_err() {
                        sync_inflight.store(false, Ordering::SeqCst);
                    }
                }
            } else if menu_ev.id == lock_id {
                let bg_client = client.clone();
                let _ = thread::Builder::new()
                    .name("ec-tray-lock".to_owned())
                    .spawn(move || {
                        scrub_default_ui_session();
                        let _ = bg_client.request(&DaemonRequest::LockVault);
                    });
            } else if menu_ev.id == quit_id {
                drop(tray_icon);
                pump_platform_messages();
                return Ok(());
            }
        }

        if let Some(deadline) = bench_deadline
            && Instant::now() >= deadline
        {
            let mem = sample_current_process_memory();
            let webview_mods = detect_loaded_webview_modules();
            drop(tray_icon);
            pump_platform_messages();
            if !webview_mods.is_empty() {
                return Err(format!(
                    "Forbidden browser runtime modules loaded in entrocloud-tray: {webview_mods:?}"
                ));
            }
            let report = TrayBenchReport {
                mode: "bench-tray".to_owned(),
                binary_role: "entrocloud-tray".to_owned(),
                closed_window_ui_process_rss_bytes: 0,
                tray_init_ms,
                settle_duration_ms: cli.settle_ms,
                working_set_64: mem.working_set_bytes,
                working_set_mib: mem.working_set_mib,
                webview2_modules: 0,
                memory: mem,
            };
            let json = serde_json::to_string(&report)
                .map_err(|err| format!("Failed serializing TrayBenchReport JSON: {err}"))?;
            println!("{json}");
            return Ok(());
        }

        thread::sleep(Duration::from_millis(12));
    }
}

#[cfg(target_os = "windows")]
fn focus_existing_ui_window() -> bool {
    use std::ptr::null;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };

    // Null-terminated UTF-16 "EntroCloud"
    const TITLE_W: &[u16] = &[
        b'E' as u16,
        b'n' as u16,
        b't' as u16,
        b'r' as u16,
        b'o' as u16,
        b'C' as u16,
        b'l' as u16,
        b'o' as u16,
        b'u' as u16,
        b'd' as u16,
        0,
    ];
    // SAFETY: `TITLE_W` is a valid null-terminated UTF-16 string; Win32 handles null class name safely.
    unsafe {
        let hwnd = FindWindowW(null(), TITLE_W.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn is_ui_process_running_for_current_user() -> bool {
    use std::os::unix::fs::MetadataExt;

    let my_pid = std::process::id();
    let Ok(my_uid) = std::fs::metadata("/proc/self").map(|m| m.uid()) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };

    for entry in entries.flatten() {
        let Ok(pid_str) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == my_pid {
            continue;
        }
        let proc_dir = entry.path();
        let Ok(meta) = std::fs::metadata(&proc_dir) else {
            continue;
        };
        if meta.uid() != my_uid {
            continue;
        }

        let comm_matches = std::fs::read_to_string(proc_dir.join("comm"))
            .ok()
            .is_some_and(|raw| {
                matches!(
                    raw.trim(),
                    "entrocloud" | "entrocloud-ui" | "EntroCloud"
                )
            });
        let exe_matches = !comm_matches
            && std::fs::read_link(proc_dir.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "entrocloud" | "entrocloud-ui" | "EntroCloud"
                    )
                });
        if comm_matches || exe_matches {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn focus_existing_ui_window() -> bool {
    use std::process::{Command, Stdio};

    if !is_ui_process_running_for_current_user() {
        return false;
    }

    // Best-effort raise of the existing EntroCloud window on X11/XWayland desktops.
    // Even on Wayland compositors that restrict programmatic focus stealing, returning `true`
    // prevents spawning a duplicate GUI instance that would clobber `ui_session`.
    let focused = Command::new("wmctrl")
        .args(["-a", "EntroCloud"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !focused {
        let _ = Command::new("xdotool")
            .args([
                "search",
                "--onlyvisible",
                "--name",
                "EntroCloud",
                "windowactivate",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    true
}

fn spawn_ui_window(custom_ipc: Option<&str>) -> Result<(), String> {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if focus_existing_ui_window() {
        return Ok(());
    }

    let ui_exe = locate_sibling_executable("EntroCloud")
        .or_else(|| locate_sibling_executable("entrocloud"))
        .or_else(|| locate_sibling_executable("entrocloud-ui"));

    let Some(ui_exe) = ui_exe else {
        return Err("Sibling EntroCloud executable not found".to_owned());
    };
    match custom_ipc.map(str::trim).filter(|s| !s.is_empty()) {
        Some(ep) => spawn_detached_process(&ui_exe, &["--ipc", ep], &[]).map_err(|e| e.to_string()),
        None => spawn_detached_process(&ui_exe, &[], &[]).map_err(|e| e.to_string()),
    }
}

fn default_tray_session_dir() -> PathBuf {
    #[cfg(unix)]
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
        && !rt.is_empty()
    {
        return PathBuf::from(rt).join("entrocloud").join("ui_session");
    }

    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("EntroCloud").join("ui_session")
}

fn scrub_default_ui_session() {
    let root = default_tray_session_dir();
    if !root.exists() {
        return;
    }
    let Ok(rmeta) = std::fs::symlink_metadata(&root) else {
        return;
    };
    if rmeta.file_type().is_symlink() {
        let _ = std::fs::remove_file(&root);
        return;
    }
    let zero_buf = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for item in rd.flatten() {
            let p = item.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_file(&p);
            } else if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file() {
                wipe_file(&p, meta.len(), &zero_buf);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn wipe_file(path: &Path, len: u64, zero_buf: &[u8]) {
    #[cfg(target_os = "windows")]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    #[cfg(unix)]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o200 == 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o200));
        }
    }

    if len > 0
        && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path)
    {
        let mut rem = len;
        while rem > 0 {
            let n = usize::try_from(rem).unwrap_or(usize::MAX).min(zero_buf.len());
            if f.write_all(&zero_buf[..n]).is_err() {
                break;
            }
            rem = rem.saturating_sub(n as u64);
        }
        let _ = f.sync_data();
    }
    let _ = std::fs::remove_file(path);
}

fn pump_platform_messages() {
    #[cfg(target_os = "windows")]
    {
        use std::mem::zeroed;
        use std::ptr::null_mut;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
        };

        // SAFETY: Standard non-blocking thread message queue pump required by Win32 `Shell_NotifyIconW`.
        unsafe {
            let mut msg: MSG = zeroed();
            while PeekMessageW(&raw mut msg, null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
        }
    }
    // On Linux, `tray-icon` uses the pure-Rust `ksni` (StatusNotifierItem over D-Bus) backend,
    // which runs its own background D-Bus service thread and delivers `TrayIconEvent` / `MenuEvent`
    // directly into crossbeam channels without requiring a GTK main loop.
}
