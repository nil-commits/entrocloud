use iced::futures::SinkExt;
use iced::widget::{
    button, canvas, column, container, horizontal_space, pick_list, progress_bar, row,
    scrollable, slider, text, Column,
};
use iced::{
    border, color, mouse, time, window, Alignment, Background, Border, Color, Element,
    Fill, FillPortion, Font, Length, Padding, Point, Rectangle, Renderer, Shrink, Size,
    Subscription, Task, Theme,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;

const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\zerovault-bakeoff-iced";
const MAX_WAVEFORM_SAMPLES: usize = 120;

// ============================================================================
// Win32 FFI: Process Memory Telemetry & High-Precision Named Pipe Mock Server
// ============================================================================

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessMemoryCountersEx {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_usage: usize,
}

type Handle = *mut c_void;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const ERROR_PIPE_CONNECTED: u32 = 535;
const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x0000_0002;
const TIMER_ALL_ACCESS: u32 = 0x001F_0003;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn K32GetProcessMemoryInfo(
        process: Handle,
        ppsmem_counters: *mut ProcessMemoryCountersEx,
        cb: u32,
    ) -> i32;
    fn CreateNamedPipeW(
        lp_name: *const u16,
        dw_open_mode: u32,
        dw_pipe_mode: u32,
        n_max_instances: u32,
        n_out_buffer_size: u32,
        n_in_buffer_size: u32,
        n_default_time_out: u32,
        lp_security_attributes: *const c_void,
    ) -> Handle;
    fn ConnectNamedPipe(h_named_pipe: Handle, lp_overlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(h_named_pipe: Handle) -> i32;
    fn WriteFile(
        h_file: Handle,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(h_object: Handle) -> i32;
    fn GetLastError() -> u32;
    fn WaitNamedPipeW(lp_named_pipe_name: *const u16, n_time_out: u32) -> i32;
    fn CreateWaitableTimerExW(
        lp_timer_attributes: *const c_void,
        lp_timer_name: *const u16,
        dw_flags: u32,
        dw_desired_access: u32,
    ) -> Handle;
    fn SetWaitableTimer(
        h_timer: Handle,
        lp_due_time: *const i64,
        l_period: i32,
        pfn_completion_routine: *const c_void,
        lp_arg_to_completion_routine: *const c_void,
        f_resume: i32,
    ) -> i32;
    fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: u32) -> u32;
}

#[derive(Debug, Clone, Copy, Serialize)]
struct MemorySnapshot {
    working_set_bytes: usize,
    peak_working_set_bytes: usize,
    private_usage_bytes: usize,
    working_set_mib: f64,
    peak_working_set_mib: f64,
    private_usage_mib: f64,
}

fn query_process_memory() -> MemorySnapshot {
    let mut pmc = ProcessMemoryCountersEx {
        cb: std::mem::size_of::<ProcessMemoryCountersEx>() as u32,
        ..Default::default()
    };
    unsafe {
        let _ = K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc as *mut ProcessMemoryCountersEx,
            pmc.cb,
        );
    }
    const MIB: f64 = 1024.0 * 1024.0;
    MemorySnapshot {
        working_set_bytes: pmc.working_set_size,
        peak_working_set_bytes: pmc.peak_working_set_size,
        private_usage_bytes: pmc.private_usage,
        working_set_mib: round3(pmc.working_set_size as f64 / MIB),
        peak_working_set_mib: round3(pmc.peak_working_set_size as f64 / MIB),
        private_usage_mib: round3(pmc.private_usage as f64 / MIB),
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn active_renderer_backend() -> String {
    #[cfg(all(feature = "gpu-wgpu", not(feature = "cpu-tiny-skia")))]
    {
        match std::env::var("WGPU_BACKEND") {
            Ok(val) if !val.is_empty() => format!("wgpu({val})"),
            _ => "wgpu(all)".to_string(),
        }
    }
    #[cfg(all(feature = "cpu-tiny-skia", not(feature = "gpu-wgpu")))]
    {
        "tiny-skia".to_string()
    }
    #[cfg(all(feature = "gpu-wgpu", feature = "cpu-tiny-skia"))]
    {
        match std::env::var("ICED_BACKEND") {
            Ok(val) if !val.is_empty() => format!("hybrid({val})"),
            _ => "wgpu+tiny-skia-fallback".to_string(),
        }
    }
    #[cfg(not(any(feature = "gpu-wgpu", feature = "cpu-tiny-skia")))]
    {
        "custom".to_string()
    }
}

/// Creates a Win32 Named Pipe synchronously in the kernel namespace before returning,
/// then spawns a high-precision 60Hz telemetry producer thread.
fn spawn_embedded_mock_server(pipe_name: &str, max_frames: Option<u64>) -> Result<(), String> {
    let mut wide_name: Vec<u16> = pipe_name.encode_utf16().collect();
    wide_name.push(0);

    let raw_handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65_536,
            65_536,
            0,
            ptr::null(),
        )
    };

    if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(format!("CreateNamedPipeW failed with Win32 error {err}"));
    }

    let handle_addr = raw_handle as usize;
    std::thread::Builder::new()
        .name("zv-mock-ipc-server".into())
        .spawn(move || unsafe {
            let pipe = handle_addr as Handle;
            let connected = ConnectNamedPipe(pipe, ptr::null_mut());
            if connected == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
                CloseHandle(pipe);
                return;
            }

            let timer = CreateWaitableTimerExW(
                ptr::null(),
                ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            );

            let tick = Duration::from_nanos(16_666_667); // 60.000 Hz
            let start = Instant::now();
            let mut seq: u64 = 1;

            loop {
                let phase = (seq as f64) * 0.085;
                let up_mib_s = 165.0 + 95.0 * phase.sin() + 18.0 * (phase * 2.7).cos();
                let down_mib_s = 340.0 + 120.0 * (phase * 0.75).cos() + 24.0 * (phase * 1.9).sin();
                let progress = ((seq % 300) as f64 / 300.0).clamp(0.02, 1.0);
                let active_chunks = 16 + ((seq * 3) % 33) as u32;

                let payload = format!(
                    "{{\"seq\":{},\"up_mib_s\":{:.2},\"down_mib_s\":{:.2},\"progress\":{:.4},\"active_chunks\":{}}}\n",
                    seq, up_mib_s, down_mib_s, progress, active_chunks
                );

                let mut written: u32 = 0;
                let ok = WriteFile(
                    pipe,
                    payload.as_ptr(),
                    payload.len() as u32,
                    &mut written as *mut u32,
                    ptr::null_mut(),
                );
                if ok == 0 {
                    break;
                }

                if let Some(limit) = max_frames {
                    if seq >= limit {
                        // Keep pipe alive briefly so client reads final frame cleanly before EOF
                        std::thread::sleep(Duration::from_millis(600));
                        break;
                    }
                }

                let target = start + tick.saturating_mul(seq as u32);
                seq += 1;

                // High-resolution hybrid wait + sub-millisecond spin for exact 16.6667ms pacing
                loop {
                    let now = Instant::now();
                    if now >= target {
                        break;
                    }
                    let rem = target - now;
                    if rem > Duration::from_micros(650) && !timer.is_null() {
                        let wait_ns = (rem - Duration::from_micros(450)).as_nanos() as i64;
                        let due_100ns = -(wait_ns / 100).max(1);
                        if SetWaitableTimer(
                            timer,
                            &due_100ns as *const i64,
                            0,
                            ptr::null(),
                            ptr::null(),
                            0,
                        ) != 0
                        {
                            WaitForSingleObject(timer, 50);
                        }
                    } else if rem > Duration::from_millis(2) {
                        std::thread::sleep(Duration::from_millis(1));
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }

            if !timer.is_null() {
                CloseHandle(timer);
            }
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        })
        .map_err(|e| format!("Failed to spawn mock server thread: {e}"))?;

    Ok(())
}

// ============================================================================
// CLI & Benchmark Telemetry Structures
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Interactive,
    BenchCold,
    Bench60Fps,
    ServeOnly,
}

#[derive(Debug, Clone)]
struct CliConfig {
    mode: RunMode,
    mock_server: bool,
    pipe_name: String,
    target_frames: u64,
    #[allow(dead_code)]
    wgpu_backend_override: Option<String>,
}

impl CliConfig {
    fn from_args() -> Self {
        let mut mode = RunMode::Interactive;
        let mut mock_server = false;
        let mut pipe_name = DEFAULT_PIPE_NAME.to_string();
        let mut target_frames: u64 = 300;
        let mut wgpu_backend_override: Option<String> = None;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bench-cold" | "--bench-cold-exit" => mode = RunMode::BenchCold,
                "--bench-60fps" | "--bench-60fps-5s" => mode = RunMode::Bench60Fps,
                "--mock-server" => mock_server = true,
                "--serve-only" | "--mock-server-only" => mode = RunMode::ServeOnly,
                "--pipe" => {
                    if let Some(p) = args.next() {
                        pipe_name = p;
                    }
                }
                "--frames" => {
                    if let Some(n) = args.next() {
                        if let Ok(parsed) = n.parse::<u64>() {
                            target_frames = parsed.max(2);
                        }
                    }
                }
                "--wgpu-backend" => {
                    if let Some(b) = args.next() {
                        wgpu_backend_override = Some(b);
                    }
                }
                _ => {}
            }
        }

        Self {
            mode,
            mock_server,
            pipe_name,
            target_frames,
            wgpu_backend_override,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TelemetryFrame {
    pub seq: u64,
    pub up_mib_s: f64,
    pub down_mib_s: f64,
    pub progress: f64,
    pub active_chunks: u32,
}

impl Default for TelemetryFrame {
    fn default() -> Self {
        Self {
            seq: 0,
            up_mib_s: 0.0,
            down_mib_s: 0.0,
            progress: 0.0,
            active_chunks: 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct ColdBenchOutput {
    candidate: &'static str,
    framework: &'static str,
    renderer_backend: String,
    mode: &'static str,
    pipe_name: String,
    ipc_source: &'static str,
    window_open_ms: f64,
    first_gpu_draw_ms: f64,
    first_ipc_message_ms: f64,
    internal_cold_to_interactive_ms: f64,
    first_ipc_seq: u64,
    memory: MemorySnapshot,
}

#[derive(Debug, Serialize)]
struct FpsBenchOutput {
    candidate: &'static str,
    framework: &'static str,
    renderer_backend: String,
    mode: &'static str,
    pipe_name: String,
    ipc_source: &'static str,
    ipc_frames_received: u64,
    rendered_frames: usize,
    elapsed_wall_ms: f64,
    effective_fps: f64,
    frame_time_min_ms: f64,
    frame_time_p50_ms: f64,
    frame_time_p95_ms: f64,
    frame_time_p99_ms: f64,
    frame_time_max_ms: f64,
    frame_time_mean_ms: f64,
    memory: MemorySnapshot,
}

#[derive(Default)]
struct DrawTelemetryInner {
    first_draw_at: Option<Instant>,
    last_recorded_seq: Option<u64>,
    ipc_draw_timestamps: Vec<Instant>,
}

#[derive(Clone, Default)]
struct DrawTelemetryRecorder {
    inner: Arc<Mutex<DrawTelemetryInner>>,
}

impl DrawTelemetryRecorder {
    fn record_draw(&self, seq: u64) {
        let now = Instant::now();
        if let Ok(mut guard) = self.inner.lock() {
            if guard.first_draw_at.is_none() {
                guard.first_draw_at = Some(now);
            }
            if seq >= 1 && guard.last_recorded_seq != Some(seq) {
                guard.last_recorded_seq = Some(seq);
                guard.ipc_draw_timestamps.push(now);
            }
        }
    }

    fn first_draw_instant(&self) -> Option<Instant> {
        self.inner.lock().ok().and_then(|g| g.first_draw_at)
    }

    fn last_seq(&self) -> Option<u64> {
        self.inner.lock().ok().and_then(|g| g.last_recorded_seq)
    }

    fn snapshot_timestamps(&self) -> Vec<Instant> {
        self.inner
            .lock()
            .map(|g| g.ipc_draw_timestamps.clone())
            .unwrap_or_default()
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * ((sorted.len() - 1) as f64);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - (lo as f64);
    sorted[lo] + (sorted[hi] - sorted[lo]) * frac
}

// ============================================================================
// Domain & UI State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutingPolicy {
    Targeted,
    MirroredRaid1,
    QuotaPooled,
}

impl RoutingPolicy {
    const ALL: [RoutingPolicy; 3] = [
        RoutingPolicy::Targeted,
        RoutingPolicy::MirroredRaid1,
        RoutingPolicy::QuotaPooled,
    ];

    fn description(self) -> &'static str {
        match self {
            RoutingPolicy::Targeted => {
                "Pin encrypted shards deterministically to primary low-latency cloud region."
            }
            RoutingPolicy::MirroredRaid1 => {
                "Synchronous 2-of-3 multi-cloud replication for zero-RPO fault tolerance."
            }
            RoutingPolicy::QuotaPooled => {
                "Stripe AEAD chunks dynamically across Google Drive, OneDrive, and S3 free capacity."
            }
        }
    }
}

impl std::fmt::Display for RoutingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingPolicy::Targeted => write!(f, "Targeted"),
            RoutingPolicy::MirroredRaid1 => write!(f, "Mirrored RAID-1"),
            RoutingPolicy::QuotaPooled => write!(f, "Quota-Pooled"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Unified,
    Transfers,
    Settings,
}

#[derive(Debug, Clone)]
enum Message {
    WindowOpened(window::Id),
    IpcConnected,
    IpcFrame(TelemetryFrame, Instant),
    IpcDisconnected,
    PostPresentCheck(time::Instant),
    SelectTab(ActiveTab),
    RoutingPolicySelected(RoutingPolicy),
    CacheLimitChanged(f32),
    ToggleVaultLock,
}

struct ZeroVaultApp {
    process_start: Instant,
    config: CliConfig,
    ipc_source: &'static str,

    // UI Functional State
    active_tab: ActiveTab,
    vault_locked: bool,
    mount_path: &'static str,
    cipher_suite: &'static str,
    routing_policy: RoutingPolicy,
    cache_limit_gib: f32,

    // Live Transfer Telemetry State
    ipc_connected: bool,
    latest_frame: TelemetryFrame,
    waveform_history: VecDeque<(f32, f32)>,

    // Benchmark Lifecycle State
    window_opened_at: Option<Instant>,
    first_ipc_at: Option<Instant>,
    bench_60fps_started_at: Option<Instant>,
    ipc_frames_received: u64,
    awaiting_post_present_exit: bool,
    exited: bool,
    draw_recorder: DrawTelemetryRecorder,
}

impl ZeroVaultApp {
    fn boot(
        process_start: Instant,
        config: CliConfig,
        ipc_source: &'static str,
    ) -> (Self, Task<Message>) {
        let mut history = VecDeque::with_capacity(MAX_WAVEFORM_SAMPLES);
        for _ in 0..MAX_WAVEFORM_SAMPLES {
            history.push_back((0.0, 0.0));
        }

        let app = Self {
            process_start,
            config,
            ipc_source,
            active_tab: ActiveTab::Unified,
            vault_locked: false,
            mount_path: r"Z:\ZeroVault",
            cipher_suite: "AES-256-GCM VAES + ML-KEM-768",
            routing_policy: RoutingPolicy::QuotaPooled,
            cache_limit_gib: 16.0,
            ipc_connected: false,
            latest_frame: TelemetryFrame::default(),
            waveform_history: history,
            window_opened_at: None,
            first_ipc_at: None,
            bench_60fps_started_at: None,
            ipc_frames_received: 0,
            awaiting_post_present_exit: false,
            exited: false,
            draw_recorder: DrawTelemetryRecorder::default(),
        };

        (app, Task::none())
    }

    fn title(&self) -> String {
        let lock_tag = if self.vault_locked { "LOCKED" } else { "UNLOCKED" };
        format!("ZeroVault Status & Settings [{lock_tag}] — Native iced GPU")
    }

    fn theme(&self) -> Theme {
        Theme::TokyoNightStorm
    }

    fn check_benchmark_ready(&mut self) {
        if self.exited || self.awaiting_post_present_exit {
            return;
        }
        match self.config.mode {
            RunMode::BenchCold => {
                if self.window_opened_at.is_some() && self.ipc_frames_received >= 1 {
                    self.awaiting_post_present_exit = true;
                }
            }
            RunMode::Bench60Fps => {
                if self.window_opened_at.is_some()
                    && self.ipc_frames_received >= self.config.target_frames
                {
                    self.awaiting_post_present_exit = true;
                }
            }
            _ => {}
        }
    }

    fn finalize_and_exit(&mut self) -> Task<Message> {
        if self.exited {
            return Task::none();
        }
        self.exited = true;
        let now = Instant::now();
        let memory = query_process_memory();

        match self.config.mode {
            RunMode::BenchCold => {
                let window_open_ms = self
                    .window_opened_at
                    .map(|t| t.duration_since(self.process_start).as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                let first_gpu_draw_ms = self
                    .draw_recorder
                    .first_draw_instant()
                    .map(|t| t.duration_since(self.process_start).as_secs_f64() * 1000.0)
                    .unwrap_or(window_open_ms);
                let first_ipc_ms = self
                    .first_ipc_at
                    .map(|t| t.duration_since(self.process_start).as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                let total_cold_ms =
                    now.duration_since(self.process_start).as_secs_f64() * 1000.0;

                let out = ColdBenchOutput {
                    candidate: "B1",
                    framework: "iced 0.13.1",
                    renderer_backend: active_renderer_backend(),
                    mode: "bench-cold",
                    pipe_name: self.config.pipe_name.clone(),
                    ipc_source: self.ipc_source,
                    window_open_ms: round3(window_open_ms),
                    first_gpu_draw_ms: round3(first_gpu_draw_ms),
                    first_ipc_message_ms: round3(first_ipc_ms),
                    internal_cold_to_interactive_ms: round3(total_cold_ms),
                    first_ipc_seq: self.latest_frame.seq,
                    memory,
                };
                if let Ok(json) = serde_json::to_string(&out) {
                    println!("{json}");
                }
            }
            RunMode::Bench60Fps => {
                let stamps = self.draw_recorder.snapshot_timestamps();
                let mut deltas_ms: Vec<f64> = Vec::with_capacity(stamps.len());
                for pair in stamps.windows(2) {
                    deltas_ms.push(pair[1].duration_since(pair[0]).as_secs_f64() * 1000.0);
                }
                deltas_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

                let min_ms = deltas_ms.first().copied().unwrap_or(0.0);
                let max_ms = deltas_ms.last().copied().unwrap_or(0.0);
                let mean_ms = if deltas_ms.is_empty() {
                    0.0
                } else {
                    deltas_ms.iter().sum::<f64>() / (deltas_ms.len() as f64)
                };
                let p50_ms = percentile_sorted(&deltas_ms, 50.0);
                let p95_ms = percentile_sorted(&deltas_ms, 95.0);
                let p99_ms = percentile_sorted(&deltas_ms, 99.0);

                let wall_ms = if stamps.len() >= 2 {
                    stamps
                        .last()
                        .unwrap()
                        .duration_since(stamps[0])
                        .as_secs_f64()
                        * 1000.0
                } else {
                    self.bench_60fps_started_at
                        .map(|t| now.duration_since(t).as_secs_f64() * 1000.0)
                        .unwrap_or(0.0)
                };
                let effective_fps = if wall_ms > 0.0 && stamps.len() >= 2 {
                    ((stamps.len() - 1) as f64) / (wall_ms / 1000.0)
                } else {
                    0.0
                };

                let out = FpsBenchOutput {
                    candidate: "B1",
                    framework: "iced 0.13.1",
                    renderer_backend: active_renderer_backend(),
                    mode: "bench-60fps",
                    pipe_name: self.config.pipe_name.clone(),
                    ipc_source: self.ipc_source,
                    ipc_frames_received: self.ipc_frames_received,
                    rendered_frames: stamps.len(),
                    elapsed_wall_ms: round3(wall_ms),
                    effective_fps: round3(effective_fps),
                    frame_time_min_ms: round3(min_ms),
                    frame_time_p50_ms: round3(p50_ms),
                    frame_time_p95_ms: round3(p95_ms),
                    frame_time_p99_ms: round3(p99_ms),
                    frame_time_max_ms: round3(max_ms),
                    frame_time_mean_ms: round3(mean_ms),
                    memory,
                };
                if let Ok(json) = serde_json::to_string(&out) {
                    println!("{json}");
                }
            }
            _ => {}
        }

        iced::exit()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::WindowOpened(_id) => {
                if self.window_opened_at.is_none() {
                    self.window_opened_at = Some(Instant::now());
                }
                self.check_benchmark_ready();
                Task::none()
            }
            Message::IpcConnected => {
                self.ipc_connected = true;
                Task::none()
            }
            Message::IpcFrame(frame, received_at) => {
                self.ipc_connected = true;
                if self.first_ipc_at.is_none() {
                    self.first_ipc_at = Some(received_at);
                    self.bench_60fps_started_at = Some(received_at);
                }
                self.ipc_frames_received += 1;
                if self.waveform_history.len() >= MAX_WAVEFORM_SAMPLES {
                    self.waveform_history.pop_front();
                }
                self.waveform_history
                    .push_back((frame.up_mib_s as f32, frame.down_mib_s as f32));
                self.latest_frame = frame;
                self.check_benchmark_ready();
                Task::none()
            }
            Message::IpcDisconnected => {
                self.ipc_connected = false;
                if self.config.mode == RunMode::Bench60Fps && self.ipc_frames_received > 0 {
                    self.awaiting_post_present_exit = true;
                }
                Task::none()
            }
            Message::PostPresentCheck(_at) => {
                if self.awaiting_post_present_exit {
                    let required_seq = self.latest_frame.seq.max(1);
                    if self.draw_recorder.last_seq().unwrap_or(0) >= required_seq {
                        return self.finalize_and_exit();
                    }
                }
                Task::none()
            }
            Message::SelectTab(tab) => {
                self.active_tab = tab;
                Task::none()
            }
            Message::RoutingPolicySelected(policy) => {
                self.routing_policy = policy;
                Task::none()
            }
            Message::CacheLimitChanged(limit) => {
                self.cache_limit_gib = (limit * 2.0).round() / 2.0;
                Task::none()
            }
            Message::ToggleVaultLock => {
                self.vault_locked = !self.vault_locked;
                Task::none()
            }
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let win_open = window::open_events().map(Message::WindowOpened);

        let allow_ipc = match self.config.mode {
            RunMode::Bench60Fps => self.window_opened_at.is_some(),
            _ => true,
        };

        let ipc_sub = if allow_ipc {
            let pipe_name = self.config.pipe_name.clone();
            Subscription::run_with_id(
                "zerovault-named-pipe-ipc",
                iced::stream::channel(128, move |mut output| async move {
                    loop {
                        let open_res = ClientOptions::new()
                            .read(true)
                            .write(false)
                            .open(&pipe_name)
                            .or_else(|_| {
                                ClientOptions::new().read(true).write(true).open(&pipe_name)
                            });

                        match open_res {
                            Ok(client) => {
                                let _ = output.send(Message::IpcConnected).await;
                                let mut lines = BufReader::new(client).lines();
                                while let Ok(Some(line)) = lines.next_line().await {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() {
                                        continue;
                                    }
                                    if let Ok(frame) =
                                        serde_json::from_str::<TelemetryFrame>(trimmed)
                                    {
                                        let _ = output
                                            .send(Message::IpcFrame(frame, Instant::now()))
                                            .await;
                                    }
                                }
                                let _ = output.send(Message::IpcDisconnected).await;
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(2)).await;
                            }
                        }
                    }
                }),
            )
        } else {
            Subscription::none()
        };

        if self.awaiting_post_present_exit && !self.exited {
            Subscription::batch([
                win_open,
                ipc_sub,
                window::frames().map(Message::PostPresentCheck),
            ])
        } else {
            Subscription::batch([win_open, ipc_sub])
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let header = self.view_header();
        let nav = self.view_tabs();

        let mut body: Column<'_, Message> = column![].spacing(14);

        if matches!(self.active_tab, ActiveTab::Unified | ActiveTab::Transfers) {
            body = body
                .push(self.view_transfer_meter_panel())
                .push(self.view_quota_cards());
        }

        if matches!(self.active_tab, ActiveTab::Unified | ActiveTab::Settings) {
            body = body.push(self.view_settings_panel());
        }

        let content = column![header, nav, scrollable(body).height(Fill)]
            .spacing(14)
            .padding(20);

        container(content)
            .width(Fill)
            .height(Fill)
            .style(|_theme| container::Style {
                background: Some(Background::Color(color!(0x0B0F17))),
                text_color: Some(color!(0xE2E8F0)),
                ..Default::default()
            })
            .into()
    }

    fn view_header(&self) -> Element<'_, Message> {
        let (status_label, status_bg, status_fg, status_border) = if self.vault_locked {
            (
                "● VAULT LOCKED",
                color!(0x2B1219),
                color!(0xF87171),
                color!(0x991B1B),
            )
        } else {
            (
                "● VAULT UNLOCKED",
                color!(0x0D281E),
                color!(0x34D399),
                color!(0x059669),
            )
        };

        let mount_display = if self.vault_locked {
            "MOUNT: OFFLINE (SEALED)"
        } else {
            "MOUNT: Z:\\ZeroVault"
        };

        let lock_badge = badge_pill(status_label, status_bg, status_fg, status_border);
        let mount_badge = badge_pill(
            mount_display,
            color!(0x111C2D),
            color!(0x38BDF8),
            color!(0x0284C7),
        );
        let crypto_badge = badge_pill(
            self.cipher_suite,
            color!(0x1B1736),
            color!(0xA5B4FC),
            color!(0x4F46E5),
        );

        let title_col = column![
            row![
                text("ZEROVAULT")
                    .size(22)
                    .font(Font {
                        weight: iced::font::Weight::Bold,
                        ..Font::DEFAULT
                    })
                    .color(color!(0xF8FAFC)),
                text("STATUS & SETTINGS")
                    .size(13)
                    .color(color!(0x94A3B8)),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            text(format!(
                "Pure Rust Native GPU Surface ({}) • Mount {}",
                active_renderer_backend(),
                self.mount_path
            ))
            .size(12)
            .color(color!(0x64748B)),
        ]
        .spacing(4);

        let badges = row![lock_badge, mount_badge, crypto_badge]
            .spacing(8)
            .align_y(Alignment::Center);

        card_container(
            row![title_col, horizontal_space(), badges]
                .align_y(Alignment::Center)
                .into(),
        )
    }

    fn view_tabs(&self) -> Element<'_, Message> {
        let tab_btn = |label: &'static str, tab: ActiveTab| {
            let active = self.active_tab == tab;
            button(text(label).size(13).color(if active {
                color!(0xF8FAFC)
            } else {
                color!(0x94A3B8)
            }))
            .padding([7, 14])
            .on_press(Message::SelectTab(tab))
            .style(move |_theme, _status| button::Style {
                background: Some(Background::Color(if active {
                    color!(0x1E293B)
                } else {
                    color!(0x0F1623)
                })),
                text_color: if active {
                    color!(0xF8FAFC)
                } else {
                    color!(0x94A3B8)
                },
                border: Border {
                    color: if active {
                        color!(0x38BDF8)
                    } else {
                        color!(0x1E293B)
                    },
                    width: 1.0,
                    radius: 6.0.into(),
                },
                ..Default::default()
            })
        };

        let ipc_indicator = if self.ipc_connected {
            format!(
                "IPC Connected: {}  •  Seq #{}",
                self.config.pipe_name, self.latest_frame.seq
            )
        } else {
            format!("IPC Connecting: {}", self.config.pipe_name)
        };

        row![
            tab_btn("Unified Dashboard", ActiveTab::Unified),
            tab_btn("Live Transfer Meter", ActiveTab::Transfers),
            tab_btn("Vault Settings", ActiveTab::Settings),
            horizontal_space(),
            text(ipc_indicator).size(12).color(if self.ipc_connected {
                color!(0x34D399)
            } else {
                color!(0xFBBF24)
            }),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    }

    fn view_transfer_meter_panel(&self) -> Element<'_, Message> {
        let up_val = if self.vault_locked {
            0.0
        } else {
            self.latest_frame.up_mib_s as f32
        };
        let down_val = if self.vault_locked {
            0.0
        } else {
            self.latest_frame.down_mib_s as f32
        };
        let prog_val = if self.vault_locked {
            0.0
        } else {
            (self.latest_frame.progress as f32).clamp(0.0, 1.0)
        };
        let chunks = if self.vault_locked {
            0
        } else {
            self.latest_frame.active_chunks
        };

        let up_meter = column![
            row![
                text("▲ ENCRYPTED UPLOAD").size(12).color(color!(0x94A3B8)),
                horizontal_space(),
                text(format!("{up_val:6.1} MiB/s"))
                    .size(18)
                    .color(color!(0x34D399)),
            ]
            .align_y(Alignment::Center),
            styled_bar(0.0..=500.0, up_val, color!(0x10B981)),
        ]
        .spacing(6)
        .width(FillPortion(1));

        let down_meter = column![
            row![
                text("▼ DECRYPTED DOWNLOAD").size(12).color(color!(0x94A3B8)),
                horizontal_space(),
                text(format!("{down_val:6.1} MiB/s"))
                    .size(18)
                    .color(color!(0x38BDF8)),
            ]
            .align_y(Alignment::Center),
            styled_bar(0.0..=600.0, down_val, color!(0x0EA5E9)),
        ]
        .spacing(6)
        .width(FillPortion(1));

        let sync_row = column![
            row![
                text("AEAD Chunk Pipeline Progress")
                    .size(12)
                    .color(color!(0x94A3B8)),
                horizontal_space(),
                text(format!(
                    "{:5.1}%   |   Active Chunks: {:02}   |   Policy: {}",
                    prog_val * 100.0,
                    chunks,
                    self.routing_policy
                ))
                .size(12)
                .color(color!(0xCBD5E1)),
            ]
            .align_y(Alignment::Center),
            styled_bar(0.0..=1.0, prog_val, color!(0x818CF8)),
        ]
        .spacing(6);

        let waveform = canvas(ThroughputWaveform {
            samples: self.waveform_history.iter().copied().collect(),
            seq: self.latest_frame.seq,
            recorder: self.draw_recorder.clone(),
        })
        .width(Fill)
        .height(Length::Fixed(96.0));

        card_container(
            column![
                row![
                    text("LIVE TRANSFER TELEMETRY")
                        .size(13)
                        .color(color!(0xE2E8F0)),
                    horizontal_space(),
                    text("60Hz Named Pipe Stream")
                        .size(11)
                        .color(color!(0x64748B)),
                ]
                .align_y(Alignment::Center),
                row![up_meter, down_meter].spacing(20),
                sync_row,
                waveform,
            ]
            .spacing(12)
            .into(),
        )
    }

    fn view_quota_cards(&self) -> Element<'_, Message> {
        let delta_gib = (self.latest_frame.progress as f32) * 4.8;
        let gdrive = quota_card(
            "Google Drive",
            "TLS 1.3 • Chunk Shard A",
            412.6 + delta_gib,
            2048.0,
            color!(0x34D399),
        );
        let onedrive = quota_card(
            "Microsoft OneDrive",
            "TLS 1.3 • Chunk Shard B",
            684.2 + delta_gib * 0.7,
            1024.0,
            color!(0x38BDF8),
        );
        let s3 = quota_card(
            "Amazon S3",
            "eu-central-1 • Chunk Shard C",
            1290.4 + delta_gib * 1.4,
            4096.0,
            color!(0xF59E0B),
        );

        row![gdrive, onedrive, s3].spacing(14).into()
    }

    fn view_settings_panel(&self) -> Element<'_, Message> {
        let policy_picker = pick_list(
            &RoutingPolicy::ALL[..],
            Some(self.routing_policy),
            Message::RoutingPolicySelected,
        )
        .padding([6, 12])
        .text_size(13);

        let policy_pills = row(RoutingPolicy::ALL.iter().map(|&policy| {
            let selected = self.routing_policy == policy;
            button(text(policy.to_string()).size(12))
                .padding([6, 12])
                .on_press(Message::RoutingPolicySelected(policy))
                .style(move |_theme, _status| button::Style {
                    background: Some(Background::Color(if selected {
                        color!(0x312E81)
                    } else {
                        color!(0x0F172A)
                    })),
                    text_color: if selected {
                        color!(0xE0E7FF)
                    } else {
                        color!(0x94A3B8)
                    },
                    border: Border {
                        color: if selected {
                            color!(0x6366F1)
                        } else {
                            color!(0x1E293B)
                        },
                        width: 1.0,
                        radius: 5.0.into(),
                    },
                    ..Default::default()
                })
                .into()
        }))
        .spacing(8);

        let routing_col = column![
            text("Multi-Cloud Routing Policy")
                .size(13)
                .color(color!(0xCBD5E1)),
            row![policy_picker, policy_pills]
                .spacing(12)
                .align_y(Alignment::Center),
            text(self.routing_policy.description())
                .size(11)
                .color(color!(0x64748B)),
        ]
        .spacing(6)
        .width(FillPortion(3));

        let cache_col = column![
            row![
                text("Local Encrypted NVMe Cache Limit")
                    .size(13)
                    .color(color!(0xCBD5E1)),
                horizontal_space(),
                text(format!("{:.1} GiB", self.cache_limit_gib))
                    .size(13)
                    .color(color!(0x38BDF8)),
            ],
            slider(1.0..=64.0, self.cache_limit_gib, Message::CacheLimitChanged).step(0.5),
            text("Zero-knowledge staging buffer with automatic LRU eviction.")
                .size(11)
                .color(color!(0x64748B)),
        ]
        .spacing(6)
        .width(FillPortion(2));

        let (lock_btn_text, btn_bg, btn_border) = if self.vault_locked {
            ("Unlock ZeroVault", color!(0x065F46), color!(0x10B981))
        } else {
            ("Lock Vault Immediately", color!(0x7F1D1D), color!(0xEF4444))
        };

        let lock_btn = button(
            text(lock_btn_text)
                .size(13)
                .color(color!(0xF8FAFC)),
        )
        .padding([10, 18])
        .on_press(Message::ToggleVaultLock)
        .style(move |_theme, _status| button::Style {
            background: Some(Background::Color(btn_bg)),
            text_color: color!(0xF8FAFC),
            border: Border {
                color: btn_border,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        });

        let action_col = column![
            text("Master Keyring Control")
                .size(13)
                .color(color!(0xCBD5E1)),
            lock_btn,
            text("Zeroizes ML-KEM-768 + VAES session keys.")
                .size(11)
                .color(color!(0x64748B)),
        ]
        .spacing(6)
        .width(Shrink);

        card_container(
            column![
                text("VAULT SECURITY & ROUTING SETTINGS")
                    .size(13)
                    .color(color!(0xE2E8F0)),
                row![routing_col, cache_col, action_col]
                    .spacing(22)
                    .align_y(Alignment::Center),
            ]
            .spacing(12)
            .into(),
        )
    }
}

// ============================================================================
// Custom GPU Canvas Waveform + Frame Draw Telemetry Probe
// ============================================================================

struct ThroughputWaveform {
    samples: Vec<(f32, f32)>,
    seq: u64,
    recorder: DrawTelemetryRecorder,
}

impl<Message> canvas::Program<Message> for ThroughputWaveform {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        // Record exact GPU renderer ui.draw() timestamp right before compositor.present()
        self.recorder.record_draw(self.seq);

        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let w = bounds.width.max(1.0);
        let h = bounds.height.max(1.0);

        let bg = canvas::Path::rectangle(Point::ORIGIN, frame.size());
        frame.fill(&bg, color!(0x090D16));

        for i in 1..4 {
            let y = (h / 4.0) * (i as f32);
            let grid_line = canvas::Path::line(Point::new(0.0, y), Point::new(w, y));
            frame.stroke(
                &grid_line,
                canvas::Stroke::default()
                    .with_color(color!(0x162032))
                    .with_width(1.0),
            );
        }

        if self.samples.len() >= 2 {
            let step_x = w / ((self.samples.len() - 1) as f32);
            let max_scale = 600.0_f32;

            let up_path = canvas::Path::new(|builder| {
                for (idx, (up, _)) in self.samples.iter().enumerate() {
                    let x = (idx as f32) * step_x;
                    let y = h - ((up / max_scale).clamp(0.0, 1.0) * (h - 10.0) + 5.0);
                    if idx == 0 {
                        builder.move_to(Point::new(x, y));
                    } else {
                        builder.line_to(Point::new(x, y));
                    }
                }
            });

            let down_path = canvas::Path::new(|builder| {
                for (idx, (_, down)) in self.samples.iter().enumerate() {
                    let x = (idx as f32) * step_x;
                    let y = h - ((down / max_scale).clamp(0.0, 1.0) * (h - 10.0) + 5.0);
                    if idx == 0 {
                        builder.move_to(Point::new(x, y));
                    } else {
                        builder.line_to(Point::new(x, y));
                    }
                }
            });

            frame.stroke(
                &down_path,
                canvas::Stroke::default()
                    .with_color(color!(0x38BDF8))
                    .with_width(2.0),
            );
            frame.stroke(
                &up_path,
                canvas::Stroke::default()
                    .with_color(color!(0x34D399))
                    .with_width(2.0),
            );
        }

        let border_rect = canvas::Path::rectangle(Point::ORIGIN, frame.size());
        frame.stroke(
            &border_rect,
            canvas::Stroke::default()
                .with_color(color!(0x1E293B))
                .with_width(1.0),
        );

        vec![frame.into_geometry()]
    }
}

// ============================================================================
// Reusable Dark Theme Styled Components
// ============================================================================

fn card_container(content: Element<'_, Message>) -> Element<'_, Message> {
    container(content)
        .width(Fill)
        .padding(Padding::from([14, 18]))
        .style(|_theme| container::Style {
            background: Some(Background::Color(color!(0x121926))),
            border: Border {
                color: color!(0x1E293B),
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn badge_pill<'a>(
    label: &'a str,
    bg: Color,
    fg: Color,
    border_color: Color,
) -> Element<'a, Message> {
    container(text(label).size(11).color(fg))
        .padding(Padding::from([5, 10]))
        .style(move |_theme| container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 999.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn styled_bar<'a>(
    range: std::ops::RangeInclusive<f32>,
    value: f32,
    fill_color: Color,
) -> Element<'a, Message> {
    progress_bar(range, value)
        .height(Length::Fixed(10.0))
        .style(move |_theme| progress_bar::Style {
            background: Background::Color(color!(0x090D16)),
            bar: Background::Color(fill_color),
            border: border::rounded(5),
        })
        .into()
}

fn quota_card<'a>(
    provider: &'a str,
    endpoint_meta: &'a str,
    used_gib: f32,
    total_gib: f32,
    accent: Color,
) -> Element<'a, Message> {
    let pct = ((used_gib / total_gib) * 100.0).clamp(0.0, 100.0);
    container(
        column![
            row![
                text(provider).size(14).color(color!(0xF1F5F9)),
                horizontal_space(),
                text(format!("{pct:.1}%")).size(13).color(accent),
            ]
            .align_y(Alignment::Center),
            text(endpoint_meta).size(11).color(color!(0x64748B)),
            styled_bar(0.0..=total_gib, used_gib, accent),
            row![
                text(format!("{used_gib:.1} GiB used"))
                    .size(11)
                    .color(color!(0x94A3B8)),
                horizontal_space(),
                text(format!("{total_gib:.0} GiB quota"))
                    .size(11)
                    .color(color!(0x64748B)),
            ],
        ]
        .spacing(7),
    )
    .width(FillPortion(1))
    .padding(Padding::from([12, 16]))
    .style(|_theme| container::Style {
        background: Some(Background::Color(color!(0x121926))),
        border: Border {
            color: color!(0x1E293B),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .into()
}

// ============================================================================
// Entrypoint
// ============================================================================

fn pipe_currently_listening(pipe_name: &str) -> bool {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let mut wide: Vec<u16> = pipe_name.encode_utf16().collect();
    wide.push(0);
    unsafe {
        if WaitNamedPipeW(wide.as_ptr(), 1) != 0 {
            return true;
        }
        GetLastError() != ERROR_FILE_NOT_FOUND
    }
}

fn main() -> iced::Result {
    let process_start = Instant::now();
    let config = CliConfig::from_args();

    #[cfg(feature = "gpu-wgpu")]
    {
        if let Some(ref backend) = config.wgpu_backend_override {
            if backend.eq_ignore_ascii_case("all") {
                std::env::remove_var("WGPU_BACKEND");
            } else {
                std::env::set_var("WGPU_BACKEND", backend);
            }
        } else if std::env::var_os("WGPU_BACKEND").is_none() {
            // Avoid wgpu probing legacy OpenGL WGL + redundant multi-API drivers on Windows cold boot
            if std::path::Path::new(r"C:\Windows\System32\vulkan-1.dll").exists() {
                std::env::set_var("WGPU_BACKEND", "vulkan");
            } else {
                std::env::set_var("WGPU_BACKEND", "dx12");
            }
        }
    }

    if config.mode == RunMode::ServeOnly {
        spawn_embedded_mock_server(&config.pipe_name, None)
            .expect("Failed to start standalone Named Pipe mock server");
        println!(
            "{{\"status\":\"listening\",\"pipe\":\"{}\"}}",
            config.pipe_name.replace('\\', "\\\\")
        );
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Start embedded mock server when --mock-server is passed, or auto-provision in benchmark
    // modes if no external Agent-Judge server has created the Named Pipe yet.
    let should_spawn_mock = config.mock_server
        || (matches!(config.mode, RunMode::BenchCold | RunMode::Bench60Fps)
            && !pipe_currently_listening(&config.pipe_name));

    let ipc_source = if should_spawn_mock {
        let max_frames = match config.mode {
            RunMode::BenchCold => Some(1),
            RunMode::Bench60Fps => Some(config.target_frames + 15),
            _ => None,
        };
        if spawn_embedded_mock_server(&config.pipe_name, max_frames).is_ok() {
            "embedded-win32-named-pipe-server"
        } else {
            "external-win32-named-pipe-server"
        }
    } else {
        "external-win32-named-pipe-server"
    };

    let cfg_for_boot = config.clone();
    iced::application(
        ZeroVaultApp::title,
        ZeroVaultApp::update,
        ZeroVaultApp::view,
    )
    .subscription(ZeroVaultApp::subscription)
    .theme(ZeroVaultApp::theme)
    .window_size(Size::new(1120.0, 760.0))
    .centered()
    .antialiasing(true)
    .run_with(move || ZeroVaultApp::boot(process_start, cfg_for_boot, ipc_source))
}
