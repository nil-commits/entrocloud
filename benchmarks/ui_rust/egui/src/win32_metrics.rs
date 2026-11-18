#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::mem::{size_of, zeroed};
use windows_sys::Win32::System::Performance::{
    QueryPerformanceCounter, QueryPerformanceFrequency,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ProcessMemorySnapshot {
    pub working_set_bytes: u64,
    pub working_set_mib: f64,
    pub peak_working_set_bytes: u64,
    pub peak_working_set_mib: f64,
    pub private_usage_bytes: u64,
    pub private_usage_mib: f64,
    pub page_fault_count: u32,
}

pub fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

pub fn sample_current_process_memory() -> ProcessMemorySnapshot {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = zeroed();
        pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let ok = K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
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

#[inline]
pub fn qpc_now() -> i64 {
    unsafe {
        let mut ticks: i64 = 0;
        QueryPerformanceCounter(&mut ticks);
        ticks
    }
}

#[inline]
pub fn qpc_freq() -> i64 {
    unsafe {
        let mut freq: i64 = 0;
        QueryPerformanceFrequency(&mut freq);
        freq.max(1)
    }
}

#[inline]
pub fn qpc_elapsed_ms(start_ticks: i64, end_ticks: i64) -> f64 {
    let delta = (end_ticks - start_ticks).max(0) as f64;
    let freq = qpc_freq() as f64;
    round3((delta * 1000.0) / freq)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DistributionStats {
    pub count: usize,
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
    pub mean: f64,
}

impl DistributionStats {
    pub fn from_samples(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let sum: f64 = sorted.iter().sum();
        Self {
            count: n,
            min: round3(sorted[0]),
            p50: round3(percentile_sorted(&sorted, 0.50)),
            p95: round3(percentile_sorted(&sorted, 0.95)),
            p99: round3(percentile_sorted(&sorted, 0.99)),
            max: round3(sorted[n - 1]),
            mean: round3(sum / n as f64),
        }
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = p.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = idx - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}
