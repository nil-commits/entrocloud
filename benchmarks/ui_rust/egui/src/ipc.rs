use eframe::egui;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\zerovault-bakeoff-egui";
pub const FALLBACK_PIPE_NAME: &str = r"\\.\pipe\zerovault-bakeoff-ipc";
const HISTORY_CAPACITY: usize = 72;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryFrame {
    pub seq: u64,
    pub up_mib_s: f64,
    pub down_mib_s: f64,
    pub progress: f32,
    pub active_chunks: u32,
}

impl Default for TelemetryFrame {
    fn default() -> Self {
        Self::synthetic(0)
    }
}

impl TelemetryFrame {
    pub fn synthetic(seq: u64) -> Self {
        let t = seq as f64;
        let up = 395.0 + 72.5 * (t * 0.11).sin() + 18.0 * (t * 0.29).cos();
        let down = 865.0 + 95.0 * (t * 0.08).cos() + 24.0 * (t * 0.21).sin();
        let cycle = ((seq % 300) as f32 + 1.0) / 300.0;
        let progress = (0.12 + cycle * 0.88).clamp(0.0, 1.0);
        let active_chunks = 18 + ((seq % 22) as u32);
        Self {
            seq,
            up_mib_s: (up * 10.0).round() / 10.0,
            down_mib_s: (down * 10.0).round() / 10.0,
            progress: (progress * 1000.0).round() / 1000.0,
            active_chunks,
        }
    }
}

pub struct SharedIpcInner {
    pub latest: TelemetryFrame,
    pub frames_received: u64,
    pub connected: bool,
    pub pipe_name: String,
    pub ipc_mode: String,
    pub peak_up_mib_s: f64,
    pub peak_down_mib_s: f64,
    pub up_history: VecDeque<f32>,
    pub down_history: VecDeque<f32>,
    pub egui_ctx: Option<egui::Context>,
}

impl SharedIpcInner {
    pub fn record_frame(&mut self, frame: TelemetryFrame) {
        if frame.up_mib_s > self.peak_up_mib_s {
            self.peak_up_mib_s = frame.up_mib_s;
        }
        if frame.down_mib_s > self.peak_down_mib_s {
            self.peak_down_mib_s = frame.down_mib_s;
        }
        if self.up_history.len() >= HISTORY_CAPACITY {
            self.up_history.pop_front();
        }
        if self.down_history.len() >= HISTORY_CAPACITY {
            self.down_history.pop_front();
        }
        self.up_history.push_back(frame.up_mib_s as f32);
        self.down_history.push_back(frame.down_mib_s as f32);
        self.latest = frame;
        self.frames_received += 1;
    }
}

pub type SharedIpcState = Arc<Mutex<SharedIpcInner>>;

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_server_pipe_instance(wide_name: &[u16]) -> Result<HANDLE, String> {
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        let err = unsafe { GetLastError() };
        Err(format!("CreateNamedPipeW failed with Win32 error {err}"))
    } else {
        Ok(handle)
    }
}

fn stream_telemetry_to_client(raw_handle: usize, hz: u32, stop_flag: Arc<AtomicBool>) {
    let handle = raw_handle as HANDLE;
    // Wrap handle in File; File::drop calls CloseHandle automatically.
    let mut pipe_file = unsafe { File::from_raw_handle(handle) };
    let period = Duration::from_nanos(1_000_000_000 / hz.max(1) as u64);
    let start = Instant::now();
    let mut seq: u64 = 1;

    while !stop_flag.load(Ordering::Relaxed) {
        let frame = TelemetryFrame::synthetic(seq);
        let mut line = match serde_json::to_string(&frame) {
            Ok(s) => s,
            Err(_) => break,
        };
        line.push('\n');

        if pipe_file.write_all(line.as_bytes()).is_err() {
            break;
        }

        // Schedule next frame at exact wall-clock deadline so 60 Hz is immune to 15.6ms Sleep jitter.
        let next_deadline = start + period.saturating_mul(seq as u32);
        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            if now >= next_deadline {
                break;
            }
            let rem = next_deadline - now;
            if rem > Duration::from_micros(2200) {
                thread::sleep(Duration::from_millis(1));
            } else {
                std::hint::spin_loop();
            }
        }
        seq += 1;
    }

    unsafe {
        let _ = DisconnectNamedPipe(raw_handle as HANDLE);
    }
    // `pipe_file` drops here and invokes CloseHandle cleanly.
}

/// Multi-instance Windows Named Pipe telemetry server.
/// Pre-allocates the next pipe instance immediately after each client connects so
/// rapid back-to-back cold launches never observe ERROR_FILE_NOT_FOUND.
pub fn run_mock_server(
    pipe_name: &str,
    hz: u32,
    max_clients: Option<usize>,
    ready_tx: Option<SyncSender<()>>,
    stop_flag: Arc<AtomicBool>,
) -> Result<(), String> {
    let wide = to_wide_null(pipe_name);
    let mut current_handle = create_server_pipe_instance(&wide)?;

    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    let mut served: usize = 0;
    let mut workers = Vec::new();

    while !stop_flag.load(Ordering::Relaxed) {
        let connected = unsafe { ConnectNamedPipe(current_handle, null_mut()) != 0 };
        let err = if connected {
            0
        } else {
            unsafe { GetLastError() }
        };

        if connected || err == ERROR_PIPE_CONNECTED {
            served += 1;
            let reached_limit = max_clients.map(|m| served >= m).unwrap_or(false);

            // Pre-create next instance BEFORE handing off current client so pipe stays continuously available.
            let next_handle = if !reached_limit && !stop_flag.load(Ordering::Relaxed) {
                Some(create_server_pipe_instance(&wide)?)
            } else {
                None
            };

            let client_raw = current_handle as usize;
            let worker_stop = stop_flag.clone();
            workers.push(thread::spawn(move || {
                stream_telemetry_to_client(client_raw, hz, worker_stop);
            }));

            if let Some(nh) = next_handle {
                current_handle = nh;
            } else {
                break;
            }
        } else {
            unsafe {
                CloseHandle(current_handle);
            }
            return Err(format!("ConnectNamedPipe failed with Win32 error {err}"));
        }
    }

    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

fn try_open_pipe_client(pipe_name: &str, timeout_ms: u32) -> Result<File, u32> {
    let wide = to_wide_null(pipe_name);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

    loop {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            return Ok(unsafe { File::from_raw_handle(handle) });
        }

        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_BUSY && Instant::now() < deadline {
            unsafe {
                let _ = WaitNamedPipeW(wide.as_ptr(), 15);
            }
            continue;
        }
        return Err(err);
    }
}

pub struct ConnectedIpcClient {
    pub state: SharedIpcState,
    pub stop_flag: Arc<AtomicBool>,
}

impl ConnectedIpcClient {
    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

/// Connects to the Windows Named Pipe, synchronously reads Frame #1 so the very first
/// rendered GPU frame displays genuine live IPC telemetry, and spawns a background reader
/// thread that wakes `egui::Context::request_repaint()` on every 60 Hz frame.
pub fn connect_ipc_with_first_frame(
    requested_pipe: Option<&str>,
    allow_self_hosted_fallback: bool,
    hz: u32,
) -> Result<ConnectedIpcClient, String> {
    let primary = requested_pipe.unwrap_or(DEFAULT_PIPE_NAME);
    let stop_flag = Arc::new(AtomicBool::new(false));

    let (pipe_file, active_pipe_name, ipc_mode) = match try_open_pipe_client(primary, 150) {
        Ok(f) => (f, primary.to_owned(), "external_named_pipe".to_owned()),
        Err(primary_err) => {
            if requested_pipe.is_none() {
                if let Ok(f2) = try_open_pipe_client(FALLBACK_PIPE_NAME, 50) {
                    (
                        f2,
                        FALLBACK_PIPE_NAME.to_owned(),
                        "external_named_pipe".to_owned(),
                    )
                } else if allow_self_hosted_fallback {
                    spawn_self_hosted_and_connect(hz, stop_flag.clone())?
                } else {
                    return Err(format!(
                        "Failed to open Named Pipe {primary} (Win32 err {primary_err})"
                    ));
                }
            } else if allow_self_hosted_fallback {
                spawn_self_hosted_and_connect(hz, stop_flag.clone())?
            } else {
                return Err(format!(
                    "Failed to open Named Pipe {primary} (Win32 err {primary_err})"
                ));
            }
        }
    };

    let mut reader = BufReader::new(pipe_file);
    let mut first_line = String::with_capacity(160);
    let bytes = reader
        .read_line(&mut first_line)
        .map_err(|e| format!("Failed reading initial IPC frame from {active_pipe_name}: {e}"))?;
    if bytes == 0 {
        return Err(format!("EOF reading initial IPC frame from {active_pipe_name}"));
    }
    let first_frame: TelemetryFrame = serde_json::from_str(first_line.trim())
        .map_err(|e| format!("Invalid JSON in initial IPC frame `{}`: {e}", first_line.trim()))?;

    let mut inner = SharedIpcInner {
        latest: first_frame.clone(),
        frames_received: 0,
        connected: true,
        pipe_name: active_pipe_name,
        ipc_mode,
        peak_up_mib_s: 0.0,
        peak_down_mib_s: 0.0,
        up_history: VecDeque::with_capacity(HISTORY_CAPACITY),
        down_history: VecDeque::with_capacity(HISTORY_CAPACITY),
        egui_ctx: None,
    };
    inner.record_frame(first_frame);

    let state = Arc::new(Mutex::new(inner));
    let reader_state = state.clone();
    let reader_stop = stop_flag.clone();

    thread::spawn(move || {
        let mut line = String::with_capacity(160);
        while !reader_stop.load(Ordering::Relaxed) {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    reader_state.lock().connected = false;
                    break;
                }
                Ok(_) => {
                    if let Ok(frame) = serde_json::from_str::<TelemetryFrame>(line.trim()) {
                        let ctx_opt = {
                            let mut guard = reader_state.lock();
                            guard.record_frame(frame);
                            guard.egui_ctx.clone()
                        };
                        if let Some(ctx) = ctx_opt {
                            ctx.request_repaint();
                        }
                    }
                }
                Err(_) => {
                    reader_state.lock().connected = false;
                    break;
                }
            }
        }
    });

    Ok(ConnectedIpcClient { state, stop_flag })
}

fn spawn_self_hosted_and_connect(
    hz: u32,
    stop_flag: Arc<AtomicBool>,
) -> Result<(File, String, String), String> {
    let auto_pipe = format!(r"\\.\pipe\zerovault-bakeoff-egui-auto-{}", std::process::id());
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let server_pipe = auto_pipe.clone();
    let server_stop = stop_flag;

    thread::spawn(move || {
        let _ = run_mock_server(&server_pipe, hz, Some(1), Some(ready_tx), server_stop);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|e| format!("Timed out waiting for local Named Pipe server: {e}"))?;

    let file = try_open_pipe_client(&auto_pipe, 500)
        .map_err(|err| format!("Failed connecting to self-hosted pipe {auto_pipe}: Win32 {err}"))?;
    Ok((file, auto_pipe, "self_hosted_named_pipe".to_owned()))
}
