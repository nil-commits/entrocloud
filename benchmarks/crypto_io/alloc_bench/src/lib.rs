use std::collections::VecDeque;
use std::hint::black_box;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const TOTAL_STREAM_BYTES: usize = 2 * 1024 * 1024 * 1024; // 2 GiB exact (2,147,483,648 B)
pub const METADATA_FRAMES_PER_CHUNK: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct MemorySnapshot {
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub private_usage_bytes: u64,
    pub pagefile_usage_bytes: u64,
    pub peak_pagefile_usage_bytes: u64,
    pub page_fault_count: u32,
    pub working_set_mib: f64,
    pub peak_working_set_mib: f64,
    pub private_usage_mib: f64,
}

impl MemorySnapshot {
    pub fn capture() -> Self {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::ProcessStatus::{
                K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
            };
            use windows_sys::Win32::System::Threading::GetCurrentProcess;

            let mut pmc: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let ok = K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut pmc as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
                pmc.cb,
            );
            assert!(ok != 0, "K32GetProcessMemoryInfo failed");
            let mib = 1024.0 * 1024.0;
            Self {
                working_set_bytes: pmc.WorkingSetSize as u64,
                peak_working_set_bytes: pmc.PeakWorkingSetSize as u64,
                private_usage_bytes: pmc.PrivateUsage as u64,
                pagefile_usage_bytes: pmc.PagefileUsage as u64,
                peak_pagefile_usage_bytes: pmc.PeakPagefileUsage as u64,
                page_fault_count: pmc.PageFaultCount,
                working_set_mib: (pmc.WorkingSetSize as f64) / mib,
                peak_working_set_mib: (pmc.PeakWorkingSetSize as f64) / mib,
                private_usage_mib: (pmc.PrivateUsage as f64) / mib,
            }
        }
        #[cfg(not(windows))]
        {
            // Linux /proc/self/statm + /proc/self/status fallback for cross-target compatibility
            let mut rss_bytes = 0u64;
            let mut peak_rss_bytes = 0u64;
            let mut vmsize_bytes = 0u64;
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("VmRSS:") {
                        if let Some(kb) = rest.split_whitespace().next() {
                            rss_bytes = kb.parse::<u64>().unwrap_or(0) * 1024;
                        }
                    } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                        if let Some(kb) = rest.split_whitespace().next() {
                            peak_rss_bytes = kb.parse::<u64>().unwrap_or(0) * 1024;
                        }
                    } else if let Some(rest) = line.strip_prefix("VmData:") {
                        if let Some(kb) = rest.split_whitespace().next() {
                            vmsize_bytes = kb.parse::<u64>().unwrap_or(0) * 1024;
                        }
                    }
                }
            }
            let mib = 1024.0 * 1024.0;
            Self {
                working_set_bytes: rss_bytes,
                peak_working_set_bytes: peak_rss_bytes,
                private_usage_bytes: vmsize_bytes,
                pagefile_usage_bytes: vmsize_bytes,
                peak_pagefile_usage_bytes: peak_rss_bytes,
                page_fault_count: 0,
                working_set_mib: rss_bytes as f64 / mib,
                peak_working_set_mib: peak_rss_bytes as f64 / mib,
                private_usage_mib: vmsize_bytes as f64 / mib,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFeatures {
    pub arch: String,
    pub aes: bool,
    pub pclmulqdq: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub sha: bool,
    pub bmi2: bool,
}

impl CpuFeatures {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                arch: "x86_64".to_string(),
                aes: std::is_x86_feature_detected!("aes"),
                pclmulqdq: std::is_x86_feature_detected!("pclmulqdq"),
                avx2: std::is_x86_feature_detected!("avx2"),
                avx512f: std::is_x86_feature_detected!("avx512f"),
                avx512bw: std::is_x86_feature_detected!("avx512bw"),
                avx512vl: std::is_x86_feature_detected!("avx512vl"),
                vaes: std::is_x86_feature_detected!("vaes"),
                vpclmulqdq: std::is_x86_feature_detected!("vpclmulqdq"),
                sha: std::is_x86_feature_detected!("sha"),
                bmi2: std::is_x86_feature_detected!("bmi2"),
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self {
                arch: std::env::consts::ARCH.to_string(),
                aes: false,
                pclmulqdq: false,
                avx2: false,
                avx512f: false,
                avx512bw: false,
                avx512vl: false,
                vaes: false,
                vpclmulqdq: false,
                sha: false,
                bmi2: false,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRunResult {
    pub allocator: String,
    pub build_profile: String,
    pub chunk_size_mib: usize,
    pub chunk_size_bytes: usize,
    pub threads: usize,
    pub max_in_flight_chunks: usize,
    pub total_stream_bytes: u64,
    pub num_chunks: usize,
    pub metadata_allocs_per_chunk: usize,
    pub total_metadata_allocs: u64,
    pub theoretical_in_flight_mib: f64,

    pub elapsed_ms: f64,
    pub throughput_gib_s: f64,
    pub wall_cycles_per_byte: f64,
    pub agg_thread_cycles_per_byte: f64,
    pub page_fault_delta: u64,
    pub verification_digest: u64,

    pub mem_process_start: MemorySnapshot,
    pub mem_baseline_idle: MemorySnapshot,
    pub mem_immediate_post_drop: MemorySnapshot,
    pub mem_post_burst_idle_200ms: MemorySnapshot,
    pub mem_after_main_collect: Option<MemorySnapshot>,
    pub mem_after_worker_collect: Option<MemorySnapshot>,
    pub mem_after_thread_exit: MemorySnapshot,

    pub retained_rss_delta_200ms_mib: f64,
    pub retained_private_delta_200ms_mib: f64,
    pub retained_rss_after_worker_collect_mib: Option<f64>,
    pub retained_private_after_worker_collect_mib: Option<f64>,
    pub cpu_features: CpuFeatures,
}

/// Counting semaphore bounding concurrent in-flight chunks to `2 * threads`.
struct Semaphore {
    state: Mutex<usize>,
    cvar: Condvar,
    max_permits: usize,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        Self {
            state: Mutex::new(permits),
            cvar: Condvar::new(),
            max_permits: permits,
        }
    }

    fn acquire(&self) {
        let mut count = self.state.lock().unwrap();
        while *count == 0 {
            count = self.cvar.wait(count).unwrap();
        }
        *count -= 1;
    }

    fn release(&self) {
        let mut count = self.state.lock().unwrap();
        *count += 1;
        debug_assert!(*count <= self.max_permits);
        self.cvar.notify_one();
    }

    fn available(&self) -> usize {
        *self.state.lock().unwrap()
    }
}

struct InFlightChunk {
    payload: BytesMut,
    key_ctx: Zeroizing<Vec<u8>>,
    meta_frames: Vec<Vec<u8>>,
}

impl InFlightChunk {
    /// Zeroizes sensitive payload buffer before dropping all heap allocations.
    #[inline(never)]
    fn consume_and_zeroize(mut self, sem: &Semaphore) -> u64 {
        let len = self.payload.len();
        let tag_sample = u64::from_le_bytes(
            self.payload[len - 8..len]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        let meta_sample = (self.meta_frames[0][0] as u64)
            ^ ((self.meta_frames[127][64] as u64) << 8)
            ^ ((self.meta_frames[255][self.meta_frames[255].len() - 1] as u64) << 16)
            ^ ((self.key_ctx[0] as u64) << 24);

        // Zeroize chunk buffer before returning pages to global allocator
        (&mut self.payload[..]).zeroize();
        black_box(&self.payload);
        black_box(&self.meta_frames);

        // Explicit drop order: payload + 256 metadata Vec<u8> + Zeroizing<Vec<u8>>
        drop(self.payload);
        drop(self.meta_frames);
        drop(self.key_ctx);

        sem.release();
        tag_sample ^ meta_sample
    }
}

#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Fills `chunk_size` bytes inside `BytesMut`'s spare capacity in a single pass with
/// deterministic high-entropy 64-bit stream words so every 4 KiB physical page is dirtied.
#[inline(never)]
fn fill_bytes_mut_deterministic(buf: &mut BytesMut, chunk_size: usize, chunk_idx: u64) {
    let spare = &mut buf.spare_capacity_mut()[..chunk_size];
    let seed = chunk_idx
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);

    // SAFETY: MaybeUninit<u8> and MaybeUninit<u64> have well-defined layout via align_to_mut.
    let (prefix, words, suffix) = unsafe { spare.align_to_mut::<MaybeUninit<u64>>() };
    for (i, b) in prefix.iter_mut().enumerate() {
        b.write((seed as u8).wrapping_add(i as u8) | 1);
    }

    let step0 = 0x9E37_79B9_7F4A_7C15u64;
    let step1 = 0xBF58_476D_1CE4_E5B9u64;
    let step2 = 0x94D0_49BB_1331_11EBu64;
    let step3 = 0x2545_F491_4F6C_DD1Du64;

    let mut s0 = seed ^ 0xA5A5_5A5A_F0F0_0F0F;
    let mut s1 = seed.rotate_left(17) ^ step1;
    let mut s2 = seed.rotate_left(33) ^ step2;
    let mut s3 = seed.rotate_left(49) ^ step3;

    let mut quads = words.chunks_exact_mut(4);
    for q in &mut quads {
        s0 = s0.wrapping_add(step0);
        s1 = s1.wrapping_add(step1);
        s2 = s2.wrapping_add(step2);
        s3 = s3.wrapping_add(step3);
        q[0].write(s0);
        q[1].write(s1);
        q[2].write(s2);
        q[3].write(s3);
    }
    for (i, w) in quads.into_remainder().iter_mut().enumerate() {
        w.write(s0.wrapping_add((i as u64).wrapping_mul(step0)));
    }
    for (i, b) in suffix.iter_mut().enumerate() {
        b.write((s1 as u8).wrapping_add(i as u8) | 1);
    }

    // SAFETY: Every single byte in 0..chunk_size was unconditionally initialized above.
    unsafe {
        buf.set_len(chunk_size);
    }
}

#[inline(never)]
fn process_single_chunk(chunk_size: usize, chunk_idx: u64) -> InFlightChunk {
    // 1. Allocate BytesMut::with_capacity(chunk_size + 64)
    let mut payload = BytesMut::with_capacity(chunk_size + 64);

    // 2. Allocate Zeroizing<Vec<u8>> 64-byte key/header context
    let mut key_ctx: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    key_ctx.resize(64, 0u8);
    for (i, b) in key_ctx.iter_mut().enumerate() {
        *b = ((chunk_idx as u8).wrapping_mul(37))
            .wrapping_add((i as u8).wrapping_mul(13))
            ^ 0xC3;
    }
    key_ctx[32..40].copy_from_slice(&chunk_idx.to_le_bytes());

    // 3. Allocate 256 small metadata Vec<u8> frames (128 B .. 4 KiB)
    let mut meta_frames = Vec::with_capacity(METADATA_FRAMES_PER_CHUNK);
    let mut meta_acc = 0u8;
    for m_idx in 0..METADATA_FRAMES_PER_CHUNK {
        let frame_len = 128 + (((m_idx * 163) + ((chunk_idx as usize) * 29)) % (4096 - 128 + 1));
        let fill_byte = 0x5Au8 ^ (m_idx as u8) ^ (chunk_idx as u8);
        let mut frame = vec![fill_byte; frame_len];
        frame[0] = (chunk_idx as u8).wrapping_add(m_idx as u8);
        frame[frame_len / 2] = ((chunk_idx >> 8) as u8) ^ (m_idx as u8);
        frame[frame_len - 1] = 0xA5u8.wrapping_sub(m_idx as u8);
        meta_acc ^= frame[0] ^ frame[frame_len - 1];
        meta_frames.push(black_box(frame));
    }
    key_ctx[63] ^= meta_acc;

    // 4. Touch every page of payload (deterministic stream) + aws-lc-rs AES-256-GCM seal
    fill_bytes_mut_deterministic(&mut payload, chunk_size, chunk_idx);

    let unbound = UnboundKey::new(&AES_256_GCM, &key_ctx[0..32]).expect("AES-256-GCM key");
    let aead_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&key_ctx[32..44]).expect("GCM nonce");
    let aad = Aad::from(&key_ctx[44..64]);

    let tag = aead_key
        .seal_in_place_separate_tag(nonce, aad, &mut payload[..chunk_size])
        .expect("AES-256-GCM seal_in_place");
    payload.extend_from_slice(tag.as_ref());

    InFlightChunk {
        payload,
        key_ctx,
        meta_frames,
    }
}

pub struct AllocatorCollectHooks {
    pub main_collect: Option<fn()>,
    pub worker_collect: Option<fn()>,
}

pub fn run_cli_benchmark(allocator_name: &str, hooks: AllocatorCollectHooks) {
    let args: Vec<String> = std::env::args().collect();
    let mut chunk_mib: usize = 4;
    let mut threads: usize = 4;
    let mut json_only = false;
    let mut build_profile = std::env::var("BENCH_BUILD_PROFILE").unwrap_or_else(|_| "release-x86-64".to_string());

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--chunk-mib" => {
                i += 1;
                chunk_mib = args[i].parse().expect("valid --chunk-mib");
            }
            "--threads" => {
                i += 1;
                threads = args[i].parse().expect("valid --threads");
            }
            "--profile-tag" => {
                i += 1;
                build_profile = args[i].clone();
            }
            "--json" => {
                json_only = true;
            }
            "--smoke" => {
                println!("smoke_ok allocator={allocator_name}");
                return;
            }
            other => {
                panic!("Unknown CLI flag: {other}");
            }
        }
        i += 1;
    }

    let res = execute_daemon_torture(allocator_name, &build_profile, chunk_mib, threads, hooks);
    if json_only {
        println!("{}", serde_json::to_string(&res).expect("serialize JSON"));
    } else {
        println!("{}", serde_json::to_string_pretty(&res).expect("serialize pretty JSON"));
    }
}

pub fn execute_daemon_torture(
    allocator_name: &str,
    build_profile: &str,
    chunk_size_mib: usize,
    threads: usize,
    hooks: AllocatorCollectHooks,
) -> BenchRunResult {
    assert!(
        chunk_size_mib == 1 || chunk_size_mib == 4 || chunk_size_mib == 16,
        "chunk_size_mib must be 1, 4, or 16"
    );
    assert!(threads >= 1, "threads must be >= 1");

    let mem_process_start = MemorySnapshot::capture();
    let cpu_features = CpuFeatures::detect();

    // One-time tiny stack-only crypto init so AWS-LC CPUID dispatch initializes before baseline
    {
        let raw_key = [0x11u8; 32];
        let raw_nonce = [0x22u8; 12];
        let mut block = [0x33u8; 16];
        let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &raw_key).unwrap());
        let _tag = k
            .seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(&raw_nonce).unwrap(),
                Aad::empty(),
                &mut block,
            )
            .unwrap();
    }

    let chunk_size_bytes = chunk_size_mib * 1024 * 1024;
    assert_eq!(TOTAL_STREAM_BYTES % chunk_size_bytes, 0);
    let num_chunks = TOTAL_STREAM_BYTES / chunk_size_bytes;
    let max_in_flight_chunks = 2 * threads;

    // Approximate theoretical live bytes per in-flight slot:
    // (chunk_size + 64) + 64 + 256 * avg(128..=4096 = 2112) + Vec<Vec<u8>>(256 * 24)
    let avg_meta_bytes_per_chunk = METADATA_FRAMES_PER_CHUNK * ((128 + 4096) / 2)
        + METADATA_FRAMES_PER_CHUNK * std::mem::size_of::<Vec<u8>>();
    let per_slot_bytes = (chunk_size_bytes + 64) + 64 + avg_meta_bytes_per_chunk;
    let theoretical_in_flight_mib =
        (max_in_flight_chunks as f64 * per_slot_bytes as f64) / (1024.0 * 1024.0);

    let sem = Arc::new(Semaphore::new(max_in_flight_chunks));
    let in_flight_queue: Arc<Mutex<VecDeque<InFlightChunk>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(max_in_flight_chunks + 2)));
    let next_chunk = Arc::new(AtomicUsize::new(0));
    let digest_acc = Arc::new(AtomicU64::new(0));
    let agg_thread_cycles = Arc::new(AtomicU64::new(0));

    // Synchronization barriers to keep persistent daemon worker threads alive & parked!
    let barrier_ready = Arc::new(Barrier::new(threads + 1));
    let barrier_start = Arc::new(Barrier::new(threads + 1));
    let barrier_tail_drain = Arc::new(Barrier::new(threads));
    let barrier_burst_done = Arc::new(Barrier::new(threads + 1));
    let barrier_collect_start = Arc::new(Barrier::new(threads + 1));
    let barrier_collect_done = Arc::new(Barrier::new(threads + 1));
    let barrier_exit = Arc::new(Barrier::new(threads + 1));

    let worker_collect_fn = hooks.worker_collect;

    let mut handles = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let sem = Arc::clone(&sem);
        let q = Arc::clone(&in_flight_queue);
        let next_chunk = Arc::clone(&next_chunk);
        let digest_acc = Arc::clone(&digest_acc);
        let agg_thread_cycles = Arc::clone(&agg_thread_cycles);

        let b_ready = Arc::clone(&barrier_ready);
        let b_start = Arc::clone(&barrier_start);
        let b_tail = Arc::clone(&barrier_tail_drain);
        let b_burst_done = Arc::clone(&barrier_burst_done);
        let b_collect_start = Arc::clone(&barrier_collect_start);
        let b_collect_done = Arc::clone(&barrier_collect_done);
        let b_exit = Arc::clone(&barrier_exit);

        let handle = thread::Builder::new()
            .name(format!("zv-worker-{worker_id}"))
            .spawn(move || {
                b_ready.wait();
                b_start.wait();

                let t_tsc_start = read_tsc();
                let mut local_digest = 0u64;

                loop {
                    let idx = next_chunk.fetch_add(1, Ordering::Relaxed);
                    if idx >= num_chunks {
                        break;
                    }

                    // Acquire permit from bounded `2 * threads` in-flight semaphore
                    sem.acquire();

                    let built = process_single_chunk(chunk_size_bytes, idx as u64);

                    // Push into bounded in-flight window (`threads` queued + `threads` active = `2 * threads` live).
                    // Pop oldest completed chunk outside lock so cross-thread zeroize + free happens concurrently!
                    let completed_opt = {
                        let mut guard = q.lock().unwrap();
                        guard.push_back(built);
                        if guard.len() > threads {
                            guard.pop_front()
                        } else {
                            None
                        }
                    };

                    if let Some(done_chunk) = completed_opt {
                        local_digest ^= done_chunk.consume_and_zeroize(&sem);
                    }
                }

                // Drain remaining `<= threads` in-flight chunks in parallel on the worker threads
                // so 100% of allocations and deallocations occur inside the daemon worker pool.
                b_tail.wait();
                loop {
                    let tail_opt = {
                        let mut guard = q.lock().unwrap();
                        guard.pop_front()
                    };
                    match tail_opt {
                        Some(done_chunk) => {
                            local_digest ^= done_chunk.consume_and_zeroize(&sem);
                        }
                        None => break,
                    }
                }

                let t_tsc_end = read_tsc();
                agg_thread_cycles.fetch_add(t_tsc_end.wrapping_sub(t_tsc_start), Ordering::Relaxed);
                digest_acc.fetch_xor(local_digest, Ordering::Relaxed);

                // Park worker thread (simulating persistent daemon pool idle state!)
                b_burst_done.wait();

                // Wait until +200ms unassisted measurement (+ optional main-thread collect) completes
                b_collect_start.wait();
                if let Some(w_collect) = worker_collect_fn {
                    w_collect();
                }
                b_collect_done.wait();

                // Wait until post-collect measurement completes before exiting thread
                b_exit.wait();
            })
            .expect("spawn worker thread");
        handles.push(handle);
    }

    // Wait for all persistent worker threads to spawn & initialize
    barrier_ready.wait();
    thread::sleep(Duration::from_millis(20));
    let mem_baseline_idle = MemorySnapshot::capture();

    // Start timed 2 GiB streaming torture burst
    let wall_start = Instant::now();
    let wall_tsc_start = read_tsc();
    barrier_start.wait();

    // Wait for all workers to finish producing, sealing, zeroizing, and dropping all chunks
    barrier_burst_done.wait();

    let wall_tsc_end = read_tsc();
    let elapsed = wall_start.elapsed();

    assert_eq!(
        sem.available(),
        max_in_flight_chunks,
        "All semaphore permits must be returned after burst drain"
    );

    // Snapshot #1 after burst: Immediate (+0ms)
    let mem_immediate_post_drop = MemorySnapshot::capture();

    // Snapshot #2 after burst: +200ms natural unassisted daemon idle (workers still alive & parked!)
    thread::sleep(Duration::from_millis(200));
    let mem_post_burst_idle_200ms = MemorySnapshot::capture();

    // Optional explicit collect test #1: Main-thread-only collect (e.g. housekeeping timer task)
    let mem_after_main_collect = if let Some(m_collect) = hooks.main_collect {
        m_collect();
        thread::sleep(Duration::from_millis(100));
        Some(MemorySnapshot::capture())
    } else {
        None
    };

    // Optional explicit collect test #2: Worker-thread collect across all live pool threads + main thread
    barrier_collect_start.wait();
    barrier_collect_done.wait();
    let mem_after_worker_collect = if hooks.worker_collect.is_some() || hooks.main_collect.is_some()
    {
        if let Some(m_collect) = hooks.main_collect {
            m_collect();
        }
        thread::sleep(Duration::from_millis(100));
        Some(MemorySnapshot::capture())
    } else {
        None
    };

    // Release workers to exit and join all threads
    barrier_exit.wait();
    for h in handles {
        h.join().expect("join worker thread");
    }
    thread::sleep(Duration::from_millis(50));
    let mem_after_thread_exit = MemorySnapshot::capture();

    let elapsed_secs = elapsed.as_secs_f64();
    let elapsed_ms = elapsed_secs * 1000.0;
    let total_gib = (TOTAL_STREAM_BYTES as f64) / (1024.0 * 1024.0 * 1024.0);
    let throughput_gib_s = total_gib / elapsed_secs;

    let wall_cycles = wall_tsc_end.wrapping_sub(wall_tsc_start);
    let wall_cycles_per_byte = (wall_cycles as f64) / (TOTAL_STREAM_BYTES as f64);
    let agg_cycles = agg_thread_cycles.load(Ordering::Relaxed);
    let agg_thread_cycles_per_byte = (agg_cycles as f64) / (TOTAL_STREAM_BYTES as f64);

    let page_fault_delta = (mem_immediate_post_drop.page_fault_count as u64)
        .saturating_sub(mem_baseline_idle.page_fault_count as u64);

    let retained_rss_delta_200ms_mib =
        mem_post_burst_idle_200ms.working_set_mib - mem_baseline_idle.working_set_mib;
    let retained_private_delta_200ms_mib =
        mem_post_burst_idle_200ms.private_usage_mib - mem_baseline_idle.private_usage_mib;

    let retained_rss_after_worker_collect_mib = mem_after_worker_collect
        .map(|m| m.working_set_mib - mem_baseline_idle.working_set_mib);
    let retained_private_after_worker_collect_mib = mem_after_worker_collect
        .map(|m| m.private_usage_mib - mem_baseline_idle.private_usage_mib);

    BenchRunResult {
        allocator: allocator_name.to_string(),
        build_profile: build_profile.to_string(),
        chunk_size_mib,
        chunk_size_bytes,
        threads,
        max_in_flight_chunks,
        total_stream_bytes: TOTAL_STREAM_BYTES as u64,
        num_chunks,
        metadata_allocs_per_chunk: METADATA_FRAMES_PER_CHUNK,
        total_metadata_allocs: (num_chunks * METADATA_FRAMES_PER_CHUNK) as u64,
        theoretical_in_flight_mib,

        elapsed_ms,
        throughput_gib_s,
        wall_cycles_per_byte,
        agg_thread_cycles_per_byte,
        page_fault_delta,
        verification_digest: digest_acc.load(Ordering::Relaxed),

        mem_process_start,
        mem_baseline_idle,
        mem_immediate_post_drop,
        mem_post_burst_idle_200ms,
        mem_after_main_collect,
        mem_after_worker_collect,
        mem_after_thread_exit,

        retained_rss_delta_200ms_mib,
        retained_private_delta_200ms_mib,
        retained_rss_after_worker_collect_mib,
        retained_private_after_worker_collect_mib,
        cpu_features,
    }
}
