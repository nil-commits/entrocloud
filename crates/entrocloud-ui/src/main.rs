//! `entrocloud` native GPU desktop executable (`eframe 0.29.1` + `glow` + `AccessKit`).
//!
//! Closing the window cleanly exits the UI process (`0 bytes` of background UI surface RAM)
//! while `entrocloudd` (and optional `entrocloud-tray`) remains resident.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use eframe::egui;
use entrocloud_types::{DaemonRequest, DaemonResponse};
use entrocloud_ui::{
    ColdBenchConfig, ColdBenchReport, EntroCloudApp, IpcClient, IpcEndpoint, TOUR_STEPS,
    UiCliArgs, UiWorkerHandle, default_session_preview_dir, elapsed_ms,
    generate_entrocloud_rgba_icon, now_ticks,
};
use parking_lot::Mutex;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let main_entry_ticks = now_ticks();

    let cli = UiCliArgs::parse();

    if !cli.bench_cold && cli.screenshot_tour.is_none() {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
    }

    if let Err(code) = run_ui(main_entry_ticks, cli) {
        std::process::exit(code);
    }
}

fn run_ui(main_entry_ticks: i64, cli: UiCliArgs) -> Result<(), i32> {
    let is_tour = cli.screenshot_tour.is_some();

    let (endpoint, is_default_endpoint) = match IpcEndpoint::resolve(cli.ipc.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("Invalid --ipc endpoint: {err}");
            return Err(2);
        }
    };

    let initial_open_uri = match cli.validate_open_uri() {
        Ok(val) => val,
        Err(err) => {
            if cli.bench_cold {
                eprintln!("Invalid --open-uri capability link: {err}");
                return Err(2);
            }
            cli.resolved_open_uri()
                .map(|raw| (raw, "/Shared/received_file".to_owned()))
        }
    };

    let client = if cli.bench_cold || is_tour {
        IpcClient::new(endpoint).with_pipe_wait_ms(40)
    } else {
        IpcClient::new(endpoint)
    };

    let allow_autostart =
        is_default_endpoint && !cli.no_autostart && !cli.bench_cold && !is_tour;
    let ipc_probe_start = now_ticks();
    let (initial_status, daemon_connected) = if is_tour {
        (None, true)
    } else {
        probe_or_autostart_daemon(&client, allow_autostart)
    };
    let ipc_probe_ms = elapsed_ms(ipc_probe_start, now_ticks());

    let session_dir = default_session_preview_dir();
    let worker = UiWorkerHandle::spawn(
        client,
        session_dir,
        initial_status,
        daemon_connected,
        allow_autostart,
        !cli.bench_cold && !is_tour,
    );

    let cold_bench = if cli.bench_cold {
        Some(ColdBenchConfig {
            main_entry_ticks,
            ipc_probe_ms,
            spawn_qpc: cli.spawn_qpc,
        })
    } else {
        None
    };

    let bench_output: Arc<Mutex<Option<ColdBenchReport>>> = Arc::new(Mutex::new(None));
    let bench_slot_for_app = Arc::clone(&bench_output);

    let tour_result: Arc<Mutex<Result<usize, String>>> =
        Arc::new(Mutex::new(Err("screenshot tour did not finish".to_owned())));
    let tour_slot_for_app = Arc::clone(&tour_result);
    let tour_dir = cli.screenshot_tour.clone();

    let icon_rgba = generate_entrocloud_rgba_icon(32, 32);
    let icon_data = Arc::new(egui::IconData {
        rgba: icon_rgba,
        width: 32,
        height: 32,
    });

    let inner_size = if is_tour {
        [1280.0, 820.0]
    } else {
        [1180.0, 780.0]
    };

    let viewport = egui::ViewportBuilder::default()
        .with_title("EntroCloud — Private Cloud Backup & Encrypted Drive")
        .with_inner_size(inner_size)
        .with_min_inner_size([920.0, 640.0])
        .with_icon(icon_data)
        .with_visible(true);

    let native_options = eframe::NativeOptions {
        viewport,
        vsync: !cli.bench_cold && !is_tour,
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    let run_res = eframe::run_native(
        "EntroCloud",
        native_options,
        Box::new(move |cc| {
            let mut app = EntroCloudApp::new(
                Some(cc),
                worker,
                initial_open_uri,
                cold_bench,
                bench_slot_for_app,
            );
            if let Some(dir) = tour_dir {
                app = app.with_screenshot_tour(dir, tour_slot_for_app);
            }
            Ok(Box::new(app))
        }),
    );

    if let Err(err) = run_res {
        eprintln!("EntroCloud desktop window error: {err}");
        return Err(1);
    }

    if is_tour {
        let guard = tour_result.lock();
        match &*guard {
            Ok(count) if *count == TOUR_STEPS.len() => {
                println!(
                    "Captured {count} EntroCloud tour screenshots into {}",
                    cli.screenshot_tour
                        .as_deref()
                        .map_or_else(String::new, |p| p.display().to_string())
                );
            }
            Ok(count) => {
                eprintln!(
                    "Expected {} tour screenshots, captured {count}",
                    TOUR_STEPS.len()
                );
                return Err(1);
            }
            Err(err) => {
                eprintln!("Screenshot tour failed: {err}");
                return Err(1);
            }
        }
    }

    if cli.bench_cold {
        let guard = bench_output.lock();
        let Some(ref report) = *guard else {
            eprintln!("bench-cold failed to capture Frame #1 telemetry");
            return Err(1);
        };
        if report.webview2_detected || report.webview2_modules > 0 {
            eprintln!(
                "FATAL: forbidden browser runtime modules detected: {:?}",
                report.loaded_webview_modules
            );
            return Err(3);
        }
        match serde_json::to_string(report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("Failed serializing bench-cold JSON: {err}");
                return Err(1);
            }
        }
    }

    Ok(())
}

fn probe_or_autostart_daemon(
    client: &IpcClient,
    allow_autostart: bool,
) -> (Option<entrocloud_types::VaultStatusReport>, bool) {
    if let Ok(resp) = client.request(&DaemonRequest::Status) {
        if let DaemonResponse::Status(report) = resp {
            return (Some(*report), true);
        }
        return (None, true);
    }

    if allow_autostart
        && client
            .ensure_daemon_running(true, Duration::from_millis(2000))
            .is_ok()
    {
        if let Ok(DaemonResponse::Status(report)) = client.request(&DaemonRequest::Status) {
            return (Some(*report), true);
        }
        return (None, true);
    }

    (None, false)
}
