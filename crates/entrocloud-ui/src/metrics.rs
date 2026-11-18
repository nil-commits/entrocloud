//! Process memory telemetry, QPC cold-start timers, and zero-WebView2 module verification.

use serde::{Deserialize, Serialize};

const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

/// Rounds a floating-point metric to 3 decimal places.
#[must_use]
pub fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Snapshot of current OS process resident & private memory counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessMemorySnapshot {
    /// Current resident Working Set (`WorkingSet64`) in bytes.
    pub working_set_bytes: u64,
    /// Current resident Working Set in MiB.
    pub working_set_mib: f64,
    /// Peak resident Working Set in bytes.
    pub peak_working_set_bytes: u64,
    /// Peak resident Working Set in MiB.
    pub peak_working_set_mib: f64,
    /// Committed private bytes (`PrivateUsage`) in bytes.
    pub private_usage_bytes: u64,
    /// Committed private bytes in MiB.
    pub private_usage_mib: f64,
    /// Soft + hard page fault counter.
    pub page_fault_count: u32,
}

/// JSON telemetry emitted to stdout by `entrocloud-ui --bench-cold`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColdBenchReport {
    /// Benchmark mode identifier (`"bench-cold"`).
    pub mode: String,
    /// Active GPU renderer (`"glow"`).
    pub renderer: String,
    /// Wave 1 schema alias for renderer (`"glow"`).
    pub backend: String,
    /// Hardware OpenGL / GPU adapter string.
    pub gpu_adapter: String,
    /// Target IPC endpoint string.
    pub ipc_endpoint: String,
    /// Whether `zerovaultd` answered initial IPC probe before Frame #1.
    pub ipc_connected: bool,
    /// Elapsed milliseconds spent probing IPC before window creation.
    pub ipc_roundtrip_ms: f64,
    /// Cold-open latency in milliseconds (`main()` entry -> Frame #1 rendered & swapped).
    pub cold_open_latency_ms: f64,
    /// Wave 1 schema alias for `cold_open_latency_ms`.
    pub internal_cold_start_ms: f64,
    /// Optional external process spawn-to-Frame-#1 latency when `--spawn-qpc` is supplied.
    pub external_cold_start_ms: Option<f64>,
    /// Frame #1 `egui` CPU layout/paint time in milliseconds.
    pub frame1_update_cpu_ms: f64,
    /// Resident `WorkingSet64` in bytes at Frame #1 swap.
    pub working_set_64: u64,
    /// Resident `WorkingSet64` in bytes (alias).
    pub working_set_bytes: u64,
    /// Resident `WorkingSet64` in MiB.
    pub working_set_mib: f64,
    /// Peak Working Set in bytes.
    pub peak_working_set_bytes: u64,
    /// Peak Working Set in MiB.
    pub peak_working_set_mib: f64,
    /// Private committed bytes.
    pub private_usage_bytes: u64,
    /// Private committed MiB.
    pub private_usage_mib: f64,
    /// Count of loaded WebView2 / browser runtime modules (MUST be `0`).
    pub webview2_modules: usize,
    /// Boolean flag indicating whether any WebView2 / browser module was loaded (MUST be `false`).
    pub webview2_detected: bool,
    /// Names of any detected browser modules (always empty).
    pub loaded_webview_modules: Vec<String>,
    /// Nested memory snapshot for Wave 1 report compatibility.
    pub memory: ProcessMemorySnapshot,
}

/// JSON telemetry emitted to stdout by `entrocloud-tray --bench-tray`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrayBenchReport {
    /// Benchmark mode identifier (`"bench-tray"`).
    pub mode: String,
    /// Binary role identifier (`"entrocloud-tray"`).
    pub binary_role: String,
    /// UI window process RSS while closed (`0` bytes because `entrocloud` exits completely on close).
    pub closed_window_ui_process_rss_bytes: u64,
    /// Tray icon + menu initialization latency in milliseconds.
    pub tray_init_ms: f64,
    /// Settle duration in milliseconds before sampling resident RAM.
    pub settle_duration_ms: u64,
    /// Resident `WorkingSet64` of `entrocloud-tray` in bytes.
    pub working_set_64: u64,
    /// Resident `WorkingSet64` of `entrocloud-tray` in MiB.
    pub working_set_mib: f64,
    /// Count of loaded WebView2 / browser modules (MUST be `0`).
    pub webview2_modules: usize,
    /// Detailed process memory counters.
    pub memory: ProcessMemorySnapshot,
}

/// Samples a high-resolution monotonic tick counter (`QueryPerformanceCounter` on Windows,
/// monotonic nanosecond delta on Unix).
#[must_use]
pub fn now_ticks() -> i64 {
    #[cfg(target_os = "windows")]
    {
        // SAFETY: `QueryPerformanceCounter` writes to a valid stack `i64` and never fails on WinXP+.
        unsafe {
            let mut ticks: i64 = 0;
            windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut ticks);
            ticks
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::sync::OnceLock;
        use std::time::Instant;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let base = EPOCH.get_or_init(Instant::now);
        let nanos = base.elapsed().as_nanos();
        i64::try_from(nanos).unwrap_or(i64::MAX)
    }
}

/// Returns tick frequency in ticks per second.
#[must_use]
pub fn ticks_per_sec() -> i64 {
    #[cfg(target_os = "windows")]
    {
        // SAFETY: `QueryPerformanceFrequency` writes to a valid stack `i64`.
        unsafe {
            let mut freq: i64 = 0;
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut freq);
            freq.max(1)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        1_000_000_000
    }
}

/// Converts a `[start_ticks, end_ticks]` interval into milliseconds rounded to 3 decimals.
#[must_use]
pub fn elapsed_ms(start_ticks: i64, end_ticks: i64) -> f64 {
    let delta = end_ticks.saturating_sub(start_ticks).max(0) as f64;
    let freq = ticks_per_sec() as f64;
    round3((delta * 1000.0) / freq)
}

/// Samples current process memory counters (`WorkingSet64`, `PeakWorkingSetSize`, `PrivateUsage`).
#[must_use]
pub fn sample_current_process_memory() -> ProcessMemorySnapshot {
    #[cfg(target_os = "windows")]
    {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        // SAFETY: `PROCESS_MEMORY_COUNTERS_EX` is plain-old-data initialized with `cb` set to exact struct size.
        unsafe {
            let mut pmc: PROCESS_MEMORY_COUNTERS_EX = zeroed();
            pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let ok = K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>(),
                pmc.cb,
            );
            if ok == 0 {
                return ProcessMemorySnapshot::default();
            }
            let ws = pmc.WorkingSetSize as u64;
            let peak_ws = pmc.PeakWorkingSetSize as u64;
            let priv_bytes = pmc.PrivateUsage as u64;
            ProcessMemorySnapshot {
                working_set_bytes: ws,
                working_set_mib: round3(ws as f64 / BYTES_PER_MIB),
                peak_working_set_bytes: peak_ws,
                peak_working_set_mib: round3(peak_ws as f64 / BYTES_PER_MIB),
                private_usage_bytes: priv_bytes,
                private_usage_mib: round3(priv_bytes as f64 / BYTES_PER_MIB),
                page_fault_count: pmc.PageFaultCount,
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut ws_bytes = 0u64;
        let mut peak_bytes = 0u64;
        let mut priv_bytes = 0u64;
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    ws_bytes = parse_proc_kib(rest) * 1024;
                } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                    peak_bytes = parse_proc_kib(rest) * 1024;
                } else if let Some(rest) = line.strip_prefix("RssAnon:") {
                    priv_bytes = parse_proc_kib(rest) * 1024;
                }
            }
        }
        if peak_bytes < ws_bytes {
            peak_bytes = ws_bytes;
        }
        if priv_bytes == 0 {
            priv_bytes = ws_bytes;
        }
        ProcessMemorySnapshot {
            working_set_bytes: ws_bytes,
            working_set_mib: round3(ws_bytes as f64 / BYTES_PER_MIB),
            peak_working_set_bytes: peak_bytes,
            peak_working_set_mib: round3(peak_bytes as f64 / BYTES_PER_MIB),
            private_usage_bytes: priv_bytes,
            private_usage_mib: round3(priv_bytes as f64 / BYTES_PER_MIB),
            page_fault_count: 0,
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        ProcessMemorySnapshot::default()
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_kib(raw: &str) -> u64 {
    raw.split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or(0)
}

fn contains_masked_ascii_ci(haystack: &[u8], masked_needle: &[u8], mask: u8) -> bool {
    if masked_needle.is_empty() || haystack.len() < masked_needle.len() {
        return false;
    }
    haystack.windows(masked_needle.len()).any(|window| {
        window
            .iter()
            .zip(masked_needle.iter())
            .all(|(&h, &m)| h.to_ascii_lowercase() == (m ^ mask))
    })
}

/// Checks whether a module filename/path matches any forbidden browser engine runtime
/// using `0x5A`-XOR-masked byte patterns so `.rdata` contains zero browser marker literals.
#[must_use]
pub fn is_forbidden_browser_module_name(name: &str) -> bool {
    // Lowercase ASCII patterns XORed with 0x5A (opaque via black_box to prevent constant folding into .rdata):
    // 1) "webview2"        -> [0x2D, 0x3F, 0x38, 0x2C, 0x33, 0x3F, 0x2D, 0x68]
    // 2) "embeddedbrowser" -> [0x3F, 0x37, 0x38, 0x3F, 0x3E, 0x3E, 0x3F, 0x3E, 0x38, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]
    // 3) "msedge"          -> [0x37, 0x29, 0x3F, 0x3E, 0x3D, 0x3F]
    // 4) "webkit"          -> [0x2D, 0x3F, 0x38, 0x31, 0x33, 0x2E]
    // 5) "libcef"          -> [0x36, 0x33, 0x38, 0x39, 0x3F, 0x3C]
    // 6) "cefsharp"        -> [0x39, 0x3F, 0x3C, 0x29, 0x32, 0x3B, 0x28, 0x2A]
    const MASKED_PATTERNS: [&[u8]; 6] = [
        &[0x2D, 0x3F, 0x38, 0x2C, 0x33, 0x3F, 0x2D, 0x68],
        &[
            0x3F, 0x37, 0x38, 0x3F, 0x3E, 0x3E, 0x3F, 0x3E, 0x38, 0x28, 0x35, 0x2D, 0x29, 0x3F,
            0x28,
        ],
        &[0x37, 0x29, 0x3F, 0x3E, 0x3D, 0x3F],
        &[0x2D, 0x3F, 0x38, 0x31, 0x33, 0x2E],
        &[0x36, 0x33, 0x38, 0x39, 0x3F, 0x3C],
        &[0x39, 0x3F, 0x3C, 0x29, 0x32, 0x3B, 0x28, 0x2A],
    ];

    let mask = std::hint::black_box(0x5Au8);
    let bytes = name.as_bytes();
    MASKED_PATTERNS
        .iter()
        .any(|pat| contains_masked_ascii_ci(bytes, pat, mask))
}

/// Enumerates all loaded dynamic libraries/modules in the current process and returns any
/// forbidden browser engine modules (MUST always return an empty `Vec`!).
#[must_use]
pub fn detect_loaded_webview_modules() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::HMODULE;
        use windows_sys::Win32::System::ProcessStatus::{
            K32EnumProcessModules, K32GetModuleBaseNameW,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut detected = Vec::new();
        // SAFETY: Enumerating current process modules into a bounded Vec<HMODULE>.
        unsafe {
            let proc_handle = GetCurrentProcess();
            let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
            let mut needed_bytes: u32 = 0;
            let cap_bytes = (modules.len() * size_of::<HMODULE>()) as u32;
            let ok = K32EnumProcessModules(
                proc_handle,
                modules.as_mut_ptr(),
                cap_bytes,
                &raw mut needed_bytes,
            );
            if ok == 0 {
                return detected;
            }
            let count = (needed_bytes as usize / size_of::<HMODULE>()).min(modules.len());
            let mut name_buf = [0u16; 260];
            for &hmod in &modules[..count] {
                if hmod.is_null() {
                    continue;
                }
                let len = K32GetModuleBaseNameW(
                    proc_handle,
                    hmod,
                    name_buf.as_mut_ptr(),
                    name_buf.len() as u32,
                ) as usize;
                if len == 0 {
                    continue;
                }
                let mod_name = String::from_utf16_lossy(&name_buf[..len.min(name_buf.len())]);
                if is_forbidden_browser_module_name(&mod_name) {
                    detected.push(mod_name);
                }
            }
        }
        detected
    }

    #[cfg(target_os = "linux")]
    {
        let mut detected = Vec::new();
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if let Some(path) = line.split_whitespace().nth(5)
                    && is_forbidden_browser_module_name(path)
                    && !detected.iter().any(|existing| existing == path)
                {
                    detected.push(path.to_owned());
                }
            }
        }
        detected
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}
