mod ipc;
mod tray;
mod ui;
mod win32_metrics;

use eframe::egui;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::ipc::{connect_ipc_with_first_frame, run_mock_server, DEFAULT_PIPE_NAME};
use crate::tray::TrayBenchResult;
use crate::ui::{BenchMode, BenchOutputSlot, ColdBenchResult, Fps60BenchResult, ZeroVaultApp};
use crate::win32_metrics::{qpc_elapsed_ms, qpc_now, round3, DistributionStats};

fn active_backend_name() -> &'static str {
    #[cfg(all(feature = "backend-wgpu", not(feature = "backend-glow")))]
    {
        "wgpu"
    }
    #[cfg(feature = "backend-glow")]
    {
        "glow"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSuiteReport {
    pub backend: String,
    pub exe_path: String,
    pub exe_size_bytes: u64,
    pub exe_size_mib: f64,
    pub cold_runs_count: usize,
    pub cold_external_spawn_to_frame1_ms: DistributionStats,
    pub cold_internal_main_to_frame1_ms: DistributionStats,
    pub cold_external_total_exit_ms: DistributionStats,
    pub cold_working_set_mib: DistributionStats,
    pub cold_peak_working_set_mib: DistributionStats,
    pub cold_private_usage_mib: DistributionStats,
    pub cold_raw_runs: Vec<ColdBenchResult>,
    pub bench_60fps_5s: Fps60BenchResult,
    pub tray_same_binary_mode: TrayBenchResult,
    pub tray_dedicated_helper_exe: Option<DedicatedTrayInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedTrayInfo {
    pub exe_path: String,
    pub exe_size_bytes: u64,
    pub exe_size_mib: f64,
    pub result: TrayBenchResult,
}

fn main() {
    // Capture QPC at the very first instruction of main() for zero-bias internal cold-start timing.
    let main_entry_qpc = qpc_now();

    let args: Vec<String> = std::env::args().collect();
    let pipe_arg = get_flag_value(&args, "--pipe");
    let hz: u32 = get_flag_value(&args, "--hz")
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    if has_flag(&args, "--mock-server") {
        let pipe = pipe_arg.as_deref().unwrap_or(DEFAULT_PIPE_NAME);
        let max_clients = get_flag_value(&args, "--max-clients").and_then(|v| v.parse().ok());
        let stop = Arc::new(AtomicBool::new(false));
        if let Err(err) = run_mock_server(pipe, hz, max_clients, None, stop) {
            eprintln!("mock-server error: {err}");
            std::process::exit(1);
        }
        return;
    }

    if has_flag(&args, "--bench-tray") {
        let interactive = has_flag(&args, "--interactive");
        match tray::run_tray_benchmark("single_exe_tray_mode", 400, interactive) {
            Ok(res) => {
                println!("{}", serde_json::to_string(&res).unwrap_or_default());
                return;
            }
            Err(err) => {
                eprintln!("bench-tray error: {err}");
                std::process::exit(1);
            }
        }
    }

    if has_flag(&args, "--bench-suite") {
        let cold_runs: usize = get_flag_value(&args, "--cold-runs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let out_path = get_flag_value(&args, "--out").map(PathBuf::from);
        let pipe = pipe_arg.as_deref().unwrap_or(DEFAULT_PIPE_NAME);
        match execute_full_suite(pipe, cold_runs, out_path) {
            Ok(()) => return,
            Err(err) => {
                eprintln!("bench-suite error: {err}");
                std::process::exit(1);
            }
        }
    }

    let is_cold = has_flag(&args, "--bench-cold") || has_flag(&args, "--bench-cold-exit");
    let is_60fps = has_flag(&args, "--bench-60fps") || has_flag(&args, "--bench-60fps-5s");
    let force_vsync = has_flag(&args, "--vsync");

    let spawn_qpc: Option<i64> = get_flag_value(&args, "--spawn-qpc").and_then(|v| v.parse().ok());
    let target_frames: u32 = get_flag_value(&args, "--frames")
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    // Connect over Windows Named Pipe and receive Frame #1 before rendering first UI frame.
    let ipc_client = match connect_ipc_with_first_frame(pipe_arg.as_deref(), true, hz) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("IPC connection failed: {err}");
            std::process::exit(1);
        }
    };
    let ipc_ready_qpc = qpc_now();

    let bench_mode = if is_cold {
        BenchMode::Cold {
            main_entry_qpc,
            ipc_ready_qpc,
            spawn_qpc,
        }
    } else if is_60fps {
        BenchMode::Fps60 {
            main_entry_qpc,
            target_frames,
        }
    } else {
        BenchMode::Interactive
    };

    let backend_name = active_backend_name().to_owned();
    let output_slot = Arc::new(Mutex::new(BenchOutputSlot::default()));
    let slot_for_app = output_slot.clone();

    let vsync = if is_cold || is_60fps {
        force_vsync
    } else {
        true
    };

    let mut native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!(
                "ZeroVault Status & Settings [eframe 0.29.1 • {}]",
                backend_name
            ))
            .with_inner_size([1040.0, 680.0])
            .with_min_inner_size([860.0, 560.0])
            .with_visible(true),
        vsync,
        ..Default::default()
    };

    #[cfg(all(feature = "backend-wgpu", not(feature = "backend-glow")))]
    {
        native_options.renderer = eframe::Renderer::Wgpu;
    }
    #[cfg(feature = "backend-glow")]
    {
        native_options.renderer = eframe::Renderer::Glow;
    }

    let backend_for_creator = backend_name.clone();
    let run_res = eframe::run_native(
        "ZeroVault Status & Settings",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(ZeroVaultApp::new(
                cc,
                ipc_client,
                backend_for_creator,
                bench_mode,
                slot_for_app,
            )))
        }),
    );

    if let Err(err) = run_res {
        eprintln!("eframe::run_native error: {err}");
        std::process::exit(1);
    }

    let guard = output_slot.lock();
    if let Some(ref cold_res) = guard.cold {
        println!("{}", serde_json::to_string(cold_res).unwrap_or_default());
    } else if let Some(ref fps_res) = guard.fps60 {
        println!("{}", serde_json::to_string(fps_res).unwrap_or_default());
    }
}

fn execute_full_suite(
    pipe_name: &str,
    cold_runs: usize,
    out_path: Option<PathBuf>,
) -> Result<(), String> {
    let exe_path = std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let exe_meta = std::fs::metadata(&exe_path).map_err(|e| format!("metadata failed: {e}"))?;
    let exe_size_bytes = exe_meta.len();
    let exe_size_mib = round3(exe_size_bytes as f64 / (1024.0 * 1024.0));

    // 1. Spawn dedicated external Windows Named Pipe telemetry server process
    let mut server_child = Command::new(&exe_path)
        .args(["--mock-server", "--pipe", pipe_name, "--hz", "60"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed spawning --mock-server: {e}"))?;

    thread::sleep(Duration::from_millis(120));

    // 2. Execute N cold launches (default 20) as fresh OS processes
    let mut cold_raw_runs = Vec::with_capacity(cold_runs);
    let mut total_exit_samples_ms = Vec::with_capacity(cold_runs);

    for i in 0..cold_runs {
        let spawn_qpc = qpc_now();
        let out = Command::new(&exe_path)
            .args([
                "--bench-cold",
                "--pipe",
                pipe_name,
                "--spawn-qpc",
                &spawn_qpc.to_string(),
            ])
            .output()
            .map_err(|e| format!("Cold run #{} spawn failed: {e}", i + 1))?;
        let exit_qpc = qpc_now();

        if !out.status.success() {
            let _ = server_child.kill();
            return Err(format!(
                "Cold run #{} exited with {:?}: {}",
                i + 1,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }

        total_exit_samples_ms.push(qpc_elapsed_ms(spawn_qpc, exit_qpc));

        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let json_line = stdout_str
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with('{'))
            .ok_or_else(|| format!("Cold run #{} missing JSON stdout: {stdout_str}", i + 1))?;
        let parsed: ColdBenchResult = serde_json::from_str(json_line)
            .map_err(|e| format!("Cold run #{} invalid JSON `{json_line}`: {e}", i + 1))?;
        cold_raw_runs.push(parsed);
    }

    // 3. Execute 60 FPS live IPC stream benchmark (300 frames = 5.0 seconds)
    let fps_out = Command::new(&exe_path)
        .args(["--bench-60fps", "--pipe", pipe_name, "--frames", "300"])
        .output()
        .map_err(|e| format!("bench-60fps spawn failed: {e}"))?;

    let _ = server_child.kill();
    let _ = server_child.wait();

    if !fps_out.status.success() {
        return Err(format!(
            "bench-60fps failed: {}",
            String::from_utf8_lossy(&fps_out.stderr)
        ));
    }
    let fps_stdout = String::from_utf8_lossy(&fps_out.stdout);
    let fps_line = fps_stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("bench-60fps missing JSON stdout: {fps_stdout}"))?;
    let bench_60fps_5s: Fps60BenchResult = serde_json::from_str(fps_line)
        .map_err(|e| format!("bench-60fps invalid JSON `{fps_line}`: {e}"))?;

    // 4. Execute Closed-Window Tray Daemon RSS measurement (same binary + dedicated helper if built)
    let tray_out = Command::new(&exe_path)
        .arg("--bench-tray")
        .output()
        .map_err(|e| format!("bench-tray spawn failed: {e}"))?;
    if !tray_out.status.success() {
        return Err(format!(
            "bench-tray failed: {}",
            String::from_utf8_lossy(&tray_out.stderr)
        ));
    }
    let tray_stdout = String::from_utf8_lossy(&tray_out.stdout);
    let tray_line = tray_stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("bench-tray missing JSON stdout: {tray_stdout}"))?;
    let tray_same_binary_mode: TrayBenchResult =
        serde_json::from_str(tray_line).map_err(|e| format!("bench-tray JSON error: {e}"))?;

    let helper_path = exe_path.with_file_name("zerovault_tray_egui.exe");
    let tray_dedicated_helper_exe = if helper_path.exists() {
        let h_meta = std::fs::metadata(&helper_path).ok();
        let h_out = Command::new(&helper_path).output().ok();
        if let (Some(meta), Some(out)) = (h_meta, h_out) {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(l) = s.lines().rev().find(|l| l.trim_start().starts_with('{')) {
                    serde_json::from_str::<TrayBenchResult>(l).ok().map(|res| {
                        let b = meta.len();
                        DedicatedTrayInfo {
                            exe_path: helper_path.display().to_string(),
                            exe_size_bytes: b,
                            exe_size_mib: round3(b as f64 / (1024.0 * 1024.0)),
                            result: res,
                        }
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let ext_samples: Vec<f64> = cold_raw_runs
        .iter()
        .filter_map(|r| r.external_cold_start_ms)
        .collect();
    let int_samples: Vec<f64> = cold_raw_runs
        .iter()
        .map(|r| r.internal_cold_start_ms)
        .collect();
    let ws_samples: Vec<f64> = cold_raw_runs
        .iter()
        .map(|r| r.memory.working_set_mib)
        .collect();
    let peak_ws_samples: Vec<f64> = cold_raw_runs
        .iter()
        .map(|r| r.memory.peak_working_set_mib)
        .collect();
    let priv_samples: Vec<f64> = cold_raw_runs
        .iter()
        .map(|r| r.memory.private_usage_mib)
        .collect();

    let report = BackendSuiteReport {
        backend: active_backend_name().to_owned(),
        exe_path: exe_path.display().to_string(),
        exe_size_bytes,
        exe_size_mib,
        cold_runs_count: cold_raw_runs.len(),
        cold_external_spawn_to_frame1_ms: DistributionStats::from_samples(&ext_samples),
        cold_internal_main_to_frame1_ms: DistributionStats::from_samples(&int_samples),
        cold_external_total_exit_ms: DistributionStats::from_samples(&total_exit_samples_ms),
        cold_working_set_mib: DistributionStats::from_samples(&ws_samples),
        cold_peak_working_set_mib: DistributionStats::from_samples(&peak_ws_samples),
        cold_private_usage_mib: DistributionStats::from_samples(&priv_samples),
        cold_raw_runs,
        bench_60fps_5s,
        tray_same_binary_mode,
        tray_dedicated_helper_exe,
    };

    let pretty = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Failed serializing suite JSON: {e}"))?;
    if let Some(path) = out_path {
        std::fs::write(&path, &pretty)
            .map_err(|e| format!("Failed writing {}: {e}", path.display()))?;
    }
    println!("{pretty}");
    Ok(())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().skip(1).any(|a| a == flag)
}

fn get_flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}
