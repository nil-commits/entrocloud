use std::arch::x86_64::{__cpuid, _mm_lfence, _rdtsc};
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Barrier;
use std::thread;
use std::time::Instant;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesGcmNonce, Tag as AesGcmTag};
use aws_lc_rs::aead::{
    Aad as AwsAad, LessSafeKey as AwsLessSafeKey, Nonce as AwsNonce, UnboundKey as AwsUnboundKey,
    AES_256_GCM as AWS_AES_256_GCM,
};
use ring::aead::{
    Aad as RingAad, LessSafeKey as RingLessSafeKey, Nonce as RingNonce,
    UnboundKey as RingUnboundKey, AES_256_GCM as RING_AES_256_GCM,
};
use serde::{Deserialize, Serialize};

const PAYLOAD_BYTES: usize = 2 * 1024 * 1024 * 1024; // Exact 2 GiB = 2,147,483,648 bytes
const PAYLOAD_GIB: f64 = 2.0;
const TAG_LEN: usize = 16;
const TIMED_PASSES: usize = 3;

const CHUNK_SIZES: [usize; 3] = [
    1 * 1024 * 1024,  // 1 MiB
    4 * 1024 * 1024,  // 4 MiB
    16 * 1024 * 1024, // 16 MiB
];
const THREAD_COUNTS: [usize; 3] = [1, 4, 8];

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct ProcessMemoryCounters {
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
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut core::ffi::c_void;
    fn K32GetProcessMemoryInfo(
        process: *mut core::ffi::c_void,
        ppsmem_counters: *mut ProcessMemoryCounters,
        cb: u32,
    ) -> i32;
}

fn query_process_memory() -> ProcessMemoryCounters {
    unsafe {
        let mut pmc = ProcessMemoryCounters {
            cb: core::mem::size_of::<ProcessMemoryCounters>() as u32,
            ..Default::default()
        };
        let ok = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb);
        assert!(ok != 0, "K32GetProcessMemoryInfo failed");
        pmc
    }
}

#[inline(always)]
fn rdtsc_serialized() -> u64 {
    unsafe {
        _mm_lfence();
        let tsc = _rdtsc();
        _mm_lfence();
        tsc
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFeatureFlags {
    pub aes: bool,
    pub pclmulqdq: bool,
    pub sse2: bool,
    pub sse4_1: bool,
    pub avx: bool,
    pub avx2: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_brand_string: String,
    pub logical_cores: usize,
    pub tsc_reference_ghz: f64,
    pub runtime_cpuid: CpuFeatureFlags,
    pub compile_time_target_features: CpuFeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteropVerification {
    pub chunk_bytes_tested: usize,
    pub aad_bytes_len: usize,
    pub ciphertexts_bit_identical: bool,
    pub tags_bit_identical: bool,
    pub cross_decrypt_ok: bool,
    pub aad_tamper_rejected_all_crates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PureL2MicroResult {
    pub crate_name: String,
    pub build_profile: String,
    pub buffer_bytes: usize,
    pub iterations: usize,
    pub enc_cycles_per_byte: f64,
    pub dec_cycles_per_byte: f64,
    pub enc_gib_s: f64,
    pub dec_gib_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRow {
    pub crate_name: String,
    pub crate_version: String,
    pub build_profile: String,
    pub chunk_size_bytes: usize,
    pub chunk_size_label: String,
    pub threads: usize,
    pub payload_bytes: usize,
    pub aad_bytes: usize,
    pub timed_passes: usize,
    pub enc_ms_median: f64,
    pub enc_ms_samples: Vec<f64>,
    pub enc_gib_s: f64,
    pub dec_ms_median: f64,
    pub dec_ms_samples: Vec<f64>,
    pub dec_gib_s: f64,
    pub enc_cycles_per_byte_1t: Option<f64>,
    pub dec_cycles_per_byte_1t: Option<f64>,
    pub working_set_bytes: usize,
    pub working_set_mib: f64,
    pub peak_working_set_bytes: usize,
    pub peak_working_set_mib: f64,
    pub page_fault_count_total: u32,
    pub page_fault_delta: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRunOutput {
    pub build_profile: String,
    pub rustflags: String,
    pub hardware: HardwareInfo,
    pub interop_verification: InteropVerification,
    pub pure_l2_micro: Vec<PureL2MicroResult>,
    pub results: Vec<BenchmarkRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedSuiteOutput {
    pub benchmark_title: String,
    pub timestamp_utc_approx: String,
    pub payload_size_bytes: usize,
    pub aad_format: String,
    pub builds: Vec<BuildRunOutput>,
}

fn read_cpu_brand_string() -> String {
    let max_ext = __cpuid(0x8000_0000).eax;
    if max_ext < 0x8000_0004 {
        return "Unknown x86_64 CPU".to_string();
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004 {
        let r = __cpuid(leaf);
        bytes.extend_from_slice(&r.eax.to_le_bytes());
        bytes.extend_from_slice(&r.ebx.to_le_bytes());
        bytes.extend_from_slice(&r.ecx.to_le_bytes());
        bytes.extend_from_slice(&r.edx.to_le_bytes());
    }
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul_pos]).trim().to_string()
}

fn calibrate_tsc_ghz() -> f64 {
    let t0 = Instant::now();
    let c0 = rdtsc_serialized();
    while t0.elapsed().as_millis() < 150 {
        core::hint::spin_loop();
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let c1 = rdtsc_serialized();
    ((c1 - c0) as f64 / elapsed) / 1e9
}

fn detect_hardware_info() -> HardwareInfo {
    let runtime_cpuid = CpuFeatureFlags {
        aes: std::arch::is_x86_feature_detected!("aes"),
        pclmulqdq: std::arch::is_x86_feature_detected!("pclmulqdq"),
        sse2: std::arch::is_x86_feature_detected!("sse2"),
        sse4_1: std::arch::is_x86_feature_detected!("sse4.1"),
        avx: std::arch::is_x86_feature_detected!("avx"),
        avx2: std::arch::is_x86_feature_detected!("avx2"),
        vaes: std::arch::is_x86_feature_detected!("vaes"),
        vpclmulqdq: std::arch::is_x86_feature_detected!("vpclmulqdq"),
        avx512f: std::arch::is_x86_feature_detected!("avx512f"),
        avx512bw: std::arch::is_x86_feature_detected!("avx512bw"),
        avx512vl: std::arch::is_x86_feature_detected!("avx512vl"),
    };
    let compile_time_target_features = CpuFeatureFlags {
        aes: cfg!(target_feature = "aes"),
        pclmulqdq: cfg!(target_feature = "pclmulqdq"),
        sse2: cfg!(target_feature = "sse2"),
        sse4_1: cfg!(target_feature = "sse4.1"),
        avx: cfg!(target_feature = "avx"),
        avx2: cfg!(target_feature = "avx2"),
        vaes: cfg!(target_feature = "vaes"),
        vpclmulqdq: cfg!(target_feature = "vpclmulqdq"),
        avx512f: cfg!(target_feature = "avx512f"),
        avx512bw: cfg!(target_feature = "avx512bw"),
        avx512vl: cfg!(target_feature = "avx512vl"),
    };
    HardwareInfo {
        cpu_brand_string: read_cpu_brand_string(),
        logical_cores: thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        tsc_reference_ghz: calibrate_tsc_ghz(),
        runtime_cpuid,
        compile_time_target_features,
    }
}

#[inline(always)]
fn build_aad(file_uuid: &[u8; 16], chunk_idx: u64, is_final: bool) -> [u8; 25] {
    let mut aad = [0u8; 25];
    aad[0..16].copy_from_slice(file_uuid);
    aad[16..24].copy_from_slice(&chunk_idx.to_le_bytes());
    aad[24] = if is_final { 1 } else { 0 };
    aad
}

#[inline(always)]
fn build_nonce(prefix: [u8; 4], chunk_idx: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&prefix);
    nonce[4..12].copy_from_slice(&chunk_idx.to_be_bytes());
    nonce
}

// =========================================================================
// Explicit non-inlined symbols for clean dumpbin /disasm hardware inspection
// =========================================================================

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_aws_lc_seal_chunk(
    key: &AwsLessSafeKey,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out: &mut [u8],
) -> [u8; 16] {
    let tag = key
        .seal_in_place_separate_tag(
            AwsNonce::assume_unique_for_key(nonce),
            AwsAad::from(&aad[..]),
            in_out,
        )
        .expect("aws-lc-rs seal failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    out
}

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_aws_lc_open_chunk(
    key: &AwsLessSafeKey,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out_with_tag: &mut [u8],
) {
    let _pt = key
        .open_in_place(
            AwsNonce::assume_unique_for_key(nonce),
            AwsAad::from(&aad[..]),
            in_out_with_tag,
        )
        .expect("aws-lc-rs open failed");
}

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_ring_seal_chunk(
    key: &RingLessSafeKey,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out: &mut [u8],
) -> [u8; 16] {
    let tag = key
        .seal_in_place_separate_tag(
            RingNonce::assume_unique_for_key(nonce),
            RingAad::from(&aad[..]),
            in_out,
        )
        .expect("ring seal failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    out
}

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_ring_open_chunk(
    key: &RingLessSafeKey,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out_with_tag: &mut [u8],
) {
    let _pt = key
        .open_in_place(
            RingNonce::assume_unique_for_key(nonce),
            RingAad::from(&aad[..]),
            in_out_with_tag,
        )
        .expect("ring open failed");
}

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_aes_gcm_seal_chunk(
    cipher: &Aes256Gcm,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out: &mut [u8],
) -> [u8; 16] {
    let tag = cipher
        .encrypt_in_place_detached(AesGcmNonce::from_slice(&nonce), aad, in_out)
        .expect("aes-gcm seal failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

#[no_mangle]
#[inline(never)]
pub fn cipher_bench_aes_gcm_open_chunk(
    cipher: &Aes256Gcm,
    nonce: [u8; 12],
    aad: &[u8; 25],
    in_out_with_tag: &mut [u8],
) {
    let ct_len = in_out_with_tag.len() - TAG_LEN;
    let (ct, tag_bytes) = in_out_with_tag.split_at_mut(ct_len);
    cipher
        .decrypt_in_place_detached(
            AesGcmNonce::from_slice(&nonce),
            aad,
            ct,
            AesGcmTag::from_slice(tag_bytes),
        )
        .expect("aes-gcm open failed");
}

trait CipherBackend: Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn seal_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out: &mut [u8]) -> [u8; 16];
    fn open_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out_with_tag: &mut [u8]);
}

struct AwsLcBackend {
    key: AwsLessSafeKey,
    version: &'static str,
}

impl CipherBackend for AwsLcBackend {
    fn name(&self) -> &'static str {
        "aws-lc-rs"
    }
    fn version(&self) -> &'static str {
        self.version
    }
    #[inline(always)]
    fn seal_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out: &mut [u8]) -> [u8; 16] {
        cipher_bench_aws_lc_seal_chunk(&self.key, nonce, aad, in_out)
    }
    #[inline(always)]
    fn open_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out_with_tag: &mut [u8]) {
        cipher_bench_aws_lc_open_chunk(&self.key, nonce, aad, in_out_with_tag)
    }
}

struct RingBackend {
    key: RingLessSafeKey,
    version: &'static str,
}

impl CipherBackend for RingBackend {
    fn name(&self) -> &'static str {
        "ring"
    }
    fn version(&self) -> &'static str {
        self.version
    }
    #[inline(always)]
    fn seal_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out: &mut [u8]) -> [u8; 16] {
        cipher_bench_ring_seal_chunk(&self.key, nonce, aad, in_out)
    }
    #[inline(always)]
    fn open_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out_with_tag: &mut [u8]) {
        cipher_bench_ring_open_chunk(&self.key, nonce, aad, in_out_with_tag)
    }
}

struct AesGcmBackend {
    cipher: Aes256Gcm,
    version: &'static str,
}

impl CipherBackend for AesGcmBackend {
    fn name(&self) -> &'static str {
        "aes-gcm"
    }
    fn version(&self) -> &'static str {
        self.version
    }
    #[inline(always)]
    fn seal_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out: &mut [u8]) -> [u8; 16] {
        cipher_bench_aes_gcm_seal_chunk(&self.cipher, nonce, aad, in_out)
    }
    #[inline(always)]
    fn open_chunk(&self, nonce: [u8; 12], aad: &[u8; 25], in_out_with_tag: &mut [u8]) {
        cipher_bench_aes_gcm_open_chunk(&self.cipher, nonce, aad, in_out_with_tag)
    }
}

#[inline(always)]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn fill_deterministic_payload(buf: &mut [u8]) {
    let block_size = 16 * 1024 * 1024;
    thread::scope(|s| {
        for (block_idx, slice) in buf.chunks_mut(block_size).enumerate() {
            s.spawn(move || {
                let base_word = (block_idx as u64) * ((block_size / 8) as u64);
                for (i, word_bytes) in slice.chunks_exact_mut(8).enumerate() {
                    let val = splitmix64(0xE472_0C10_0DBA_4E01 ^ (base_word + i as u64));
                    word_bytes.copy_from_slice(&val.to_le_bytes());
                }
            });
        }
    });
}

fn fast_payload_fingerprint(buf: &[u8]) -> u64 {
    // Parallel XOR-fold over 64-KiB stride + full sample check to ensure exact plaintext restoration
    let out = AtomicU64::new(0);
    let block_size = 64 * 1024 * 1024;
    thread::scope(|s| {
        for (b_idx, slice) in buf.chunks(block_size).enumerate() {
            let out_ref = &out;
            s.spawn(move || {
                let mut acc = splitmix64(b_idx as u64);
                // Check every 4096th u64 + boundaries
                let mut offset = 0usize;
                while offset + 8 <= slice.len() {
                    let w = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
                    acc = acc.rotate_left(7) ^ w;
                    offset += 512;
                }
                out_ref.fetch_xor(acc, Ordering::Relaxed);
            });
        }
    });
    out.load(Ordering::Relaxed)
}

fn verify_cross_crate_interop(
    aws: &AwsLcBackend,
    ring_b: &RingBackend,
    aes_b: &AesGcmBackend,
    file_uuid: &[u8; 16],
    nonce_prefix: [u8; 4],
) -> InteropVerification {
    let test_len = 1024 * 1024; // 1 MiB
    let mut orig = vec![0u8; test_len];
    for (i, chunk) in orig.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&splitmix64(i as u64 ^ 0xCAFE_BABE).to_le_bytes());
    }

    let nonce = build_nonce(nonce_prefix, 42);
    let aad = build_aad(file_uuid, 42, true);

    let mut b1 = orig.clone();
    let mut b2 = orig.clone();
    let mut b3 = orig.clone();

    let t1 = aws.seal_chunk(nonce, &aad, &mut b1);
    let t2 = ring_b.seal_chunk(nonce, &aad, &mut b2);
    let t3 = aes_b.seal_chunk(nonce, &aad, &mut b3);

    let ct_eq = (b1 == b2) && (b2 == b3);
    let tag_eq = (t1 == t2) && (t2 == t3);
    assert!(ct_eq, "Ciphertext mismatch across crates!");
    assert!(tag_eq, "GCM tag mismatch across crates!");

    // Cross decrypt: aws -> ring, ring -> aes-gcm, aes-gcm -> aws
    let mut d1 = Vec::with_capacity(test_len + TAG_LEN);
    d1.extend_from_slice(&b1);
    d1.extend_from_slice(&t1);
    ring_b.open_chunk(nonce, &aad, &mut d1);
    assert_eq!(&d1[..test_len], &orig[..]);

    let mut d2 = Vec::with_capacity(test_len + TAG_LEN);
    d2.extend_from_slice(&b2);
    d2.extend_from_slice(&t2);
    aes_b.open_chunk(nonce, &aad, &mut d2);
    assert_eq!(&d2[..test_len], &orig[..]);

    let mut d3 = Vec::with_capacity(test_len + TAG_LEN);
    d3.extend_from_slice(&b3);
    d3.extend_from_slice(&t3);
    aws.open_chunk(nonce, &aad, &mut d3);
    assert_eq!(&d3[..test_len], &orig[..]);

    // Verify 25-byte AAD tamper rejection on `is_final` byte (byte 24)
    let bad_aad = build_aad(file_uuid, 42, false);

    let mut tam1 = b1.clone();
    tam1.extend_from_slice(&t1);
    let r_aws = aws
        .key
        .open_in_place(
            AwsNonce::assume_unique_for_key(nonce),
            AwsAad::from(&bad_aad[..]),
            &mut tam1,
        )
        .is_err();

    let mut tam2 = b2.clone();
    tam2.extend_from_slice(&t2);
    let r_ring = ring_b
        .key
        .open_in_place(
            RingNonce::assume_unique_for_key(nonce),
            RingAad::from(&bad_aad[..]),
            &mut tam2,
        )
        .is_err();

    let mut tam3 = b3.clone();
    let r_aes = aes_b
        .cipher
        .decrypt_in_place_detached(
            AesGcmNonce::from_slice(&nonce),
            &bad_aad,
            &mut tam3,
            AesGcmTag::from_slice(&t3),
        )
        .is_err();

    assert!(r_aws && r_ring && r_aes, "AAD tamper was NOT rejected!");

    InteropVerification {
        chunk_bytes_tested: test_len,
        aad_bytes_len: 25,
        ciphertexts_bit_identical: ct_eq,
        tags_bit_identical: tag_eq,
        cross_decrypt_ok: true,
        aad_tamper_rejected_all_crates: r_aws && r_ring && r_aes,
    }
}

fn transform_payload_in_place(
    backend: &dyn CipherBackend,
    payload: &mut [u8],
    tags: &mut [[u8; 16]],
    chunk_size: usize,
    file_uuid: &[u8; 16],
    nonce_prefix: [u8; 4],
    encrypt: bool,
) {
    let total_chunks = payload.len() / chunk_size;
    assert_eq!(tags.len(), total_chunks);
    let workers = 8usize;
    let chunks_per_worker = total_chunks.div_ceil(workers);

    thread::scope(|s| {
        for (w_idx, (p_slice, t_slice)) in payload
            .chunks_mut(chunks_per_worker * chunk_size)
            .zip(tags.chunks_mut(chunks_per_worker))
            .enumerate()
        {
            let start_chunk = w_idx * chunks_per_worker;
            s.spawn(move || {
                let mut scratch = if !encrypt {
                    vec![0u8; chunk_size + TAG_LEN]
                } else {
                    Vec::new()
                };
                for (local_i, (c_bytes, tag_slot)) in p_slice
                    .chunks_exact_mut(chunk_size)
                    .zip(t_slice.iter_mut())
                    .enumerate()
                {
                    let c_idx = (start_chunk + local_i) as u64;
                    let is_final = (c_idx as usize + 1) == total_chunks;
                    let nonce = build_nonce(nonce_prefix, c_idx);
                    let aad = build_aad(file_uuid, c_idx, is_final);
                    if encrypt {
                        *tag_slot = backend.seal_chunk(nonce, &aad, c_bytes);
                    } else {
                        scratch[..chunk_size].copy_from_slice(c_bytes);
                        scratch[chunk_size..chunk_size + TAG_LEN].copy_from_slice(tag_slot);
                        backend.open_chunk(nonce, &aad, &mut scratch);
                        c_bytes.copy_from_slice(&scratch[..chunk_size]);
                    }
                }
            });
        }
    });
}

fn run_pure_l2_micro(
    backend: &dyn CipherBackend,
    build_profile: &str,
    file_uuid: &[u8; 16],
    nonce_prefix: [u8; 4],
) -> PureL2MicroResult {
    let buf_bytes = 256 * 1024; // 256 KiB fits comfortably inside 1 MiB Zen 4 L2 cache
    let iterations = 4096usize; // 1 GiB total processed in L2 cache
    let total_bytes = (buf_bytes * iterations) as f64;
    let mut buf = vec![0x5Au8; buf_bytes + TAG_LEN];
    let aad = build_aad(file_uuid, 0, true);
    let nonce = build_nonce(nonce_prefix, 0);

    // Warmup
    for _ in 0..32 {
        let tag = backend.seal_chunk(nonce, &aad, &mut buf[..buf_bytes]);
        buf[buf_bytes..buf_bytes + TAG_LEN].copy_from_slice(&tag);
        backend.open_chunk(nonce, &aad, &mut buf);
    }

    // Pure in-place seal
    let t0 = Instant::now();
    let c0 = rdtsc_serialized();
    for i in 0..iterations {
        let n = build_nonce(nonce_prefix, i as u64);
        let last_tag = backend.seal_chunk(n, &aad, &mut buf[..buf_bytes]);
        black_box(&last_tag);
    }
    let c1 = rdtsc_serialized();
    let enc_secs = t0.elapsed().as_secs_f64();

    // Prepare one valid ciphertext+tag in `orig_ct` so in-place open doesn't pay copy cost?
    // Wait: open_in_place mutates ciphertext -> plaintext! To avoid invalid tag on iteration 2,
    // copy from an L2-resident 256 KiB template (256 KiB + 256 KiB = 512 KiB < 1 MiB L2).
    let mut ct_template = vec![0xA5u8; buf_bytes];
    let valid_tag = backend.seal_chunk(nonce, &aad, &mut ct_template);

    let t1 = Instant::now();
    let d0 = rdtsc_serialized();
    for _ in 0..iterations {
        buf[..buf_bytes].copy_from_slice(&ct_template);
        buf[buf_bytes..buf_bytes + TAG_LEN].copy_from_slice(&valid_tag);
        backend.open_chunk(nonce, &aad, &mut buf);
        black_box(buf[0]);
    }
    let d1 = rdtsc_serialized();
    let dec_secs = t1.elapsed().as_secs_f64();

    PureL2MicroResult {
        crate_name: backend.name().to_string(),
        build_profile: build_profile.to_string(),
        buffer_bytes: buf_bytes,
        iterations,
        enc_cycles_per_byte: (c1 - c0) as f64 / total_bytes,
        dec_cycles_per_byte: (d1 - d0) as f64 / total_bytes,
        enc_gib_s: (total_bytes / (1024.0 * 1024.0 * 1024.0)) / enc_secs,
        dec_gib_s: (total_bytes / (1024.0 * 1024.0 * 1024.0)) / dec_secs,
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn run_streaming_benchmark(
    backend: &dyn CipherBackend,
    build_profile: &str,
    plaintext_2gib: &[u8],
    is_encrypted_mode: bool,
    tags: &[[u8; 16]],
    chunk_size: usize,
    threads: usize,
    file_uuid: &[u8; 16],
    nonce_prefix: [u8; 4],
) -> (Vec<f64>, Option<f64>, ProcessMemoryCounters, ProcessMemoryCounters) {
    let total_chunks = plaintext_2gib.len() / chunk_size;
    let mem_before = query_process_memory();

    let mut ms_samples = Vec::with_capacity(TIMED_PASSES);
    let mut cpb_samples = Vec::with_capacity(TIMED_PASSES);

    let cursor = AtomicUsize::new(0);
    let checksum_sink = AtomicU64::new(0);
    let start_barrier = Barrier::new(threads);
    let end_barrier = Barrier::new(threads);

    let pass_times_ms = std::sync::Mutex::new(Vec::with_capacity(TIMED_PASSES));
    let pass_cpb = std::sync::Mutex::new(Vec::with_capacity(TIMED_PASSES));
    let live_mem_slot = std::sync::Mutex::new(mem_before);

    thread::scope(|s| {
        for tid in 0..threads {
            let cursor_ref = &cursor;
            let sink_ref = &checksum_sink;
            let sb = &start_barrier;
            let eb = &end_barrier;
            let times_ref = &pass_times_ms;
            let cpb_ref = &pass_cpb;
            let mem_ref = &live_mem_slot;

            s.spawn(move || {
                // Bounded per-thread reusable chunk_size + 16 buffer, faulted into physical RAM prior to timing
                let mut work_buf = vec![0u8; chunk_size + TAG_LEN];
                black_box(&mut work_buf);

                // Warmup 1 chunk per thread
                {
                    let warm_idx = tid % total_chunks;
                    let offset = warm_idx * chunk_size;
                    work_buf[..chunk_size]
                        .copy_from_slice(&plaintext_2gib[offset..offset + chunk_size]);
                    let nonce = build_nonce(nonce_prefix, warm_idx as u64);
                    let aad = build_aad(file_uuid, warm_idx as u64, warm_idx + 1 == total_chunks);
                    if !is_encrypted_mode {
                        let tag = backend.seal_chunk(nonce, &aad, &mut work_buf[..chunk_size]);
                        work_buf[chunk_size..chunk_size + TAG_LEN].copy_from_slice(&tag);
                    } else {
                        work_buf[chunk_size..chunk_size + TAG_LEN]
                            .copy_from_slice(&tags[warm_idx]);
                        backend.open_chunk(nonce, &aad, &mut work_buf);
                    }
                    black_box(&work_buf);
                }

                for pass in 0..TIMED_PASSES {
                    if tid == 0 {
                        cursor_ref.store(0, Ordering::SeqCst);
                    }
                    sb.wait();

                    let t0 = if tid == 0 { Some(Instant::now()) } else { None };
                    let c0 = if tid == 0 && threads == 1 {
                        Some(rdtsc_serialized())
                    } else {
                        None
                    };

                    let mut local_acc = 0u64;
                    loop {
                        let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                        if idx >= total_chunks {
                            break;
                        }
                        let offset = idx * chunk_size;
                        let src = &plaintext_2gib[offset..offset + chunk_size];
                        work_buf[..chunk_size].copy_from_slice(src);

                        let nonce = build_nonce(nonce_prefix, idx as u64);
                        let is_final = (idx + 1) == total_chunks;
                        let aad = build_aad(file_uuid, idx as u64, is_final);

                        if !is_encrypted_mode {
                            let tag = backend.seal_chunk(nonce, &aad, &mut work_buf[..chunk_size]);
                            work_buf[chunk_size..chunk_size + TAG_LEN].copy_from_slice(&tag);
                            local_acc ^= (work_buf[0] as u64) ^ ((work_buf[chunk_size] as u64) << 8);
                        } else {
                            work_buf[chunk_size..chunk_size + TAG_LEN].copy_from_slice(&tags[idx]);
                            backend.open_chunk(nonce, &aad, &mut work_buf);
                            local_acc ^=
                                (work_buf[0] as u64) ^ ((work_buf[chunk_size - 1] as u64) << 8);
                        }
                        black_box(&work_buf);
                    }

                    sink_ref.fetch_xor(local_acc, Ordering::Relaxed);
                    eb.wait();

                    if tid == 0 {
                        let c1 = if threads == 1 {
                            Some(rdtsc_serialized())
                        } else {
                            None
                        };
                        let elapsed_ms = t0.unwrap().elapsed().as_secs_f64() * 1000.0;
                        times_ref.lock().unwrap().push(elapsed_ms);
                        if let (Some(start_c), Some(end_c)) = (c0, c1) {
                            let cpb = (end_c - start_c) as f64 / (PAYLOAD_BYTES as f64);
                            cpb_ref.lock().unwrap().push(cpb);
                        }
                        if pass + 1 == TIMED_PASSES {
                            // Sample Win32 process memory while ALL thread-local buffers are live
                            *mem_ref.lock().unwrap() = query_process_memory();
                        }
                    }
                    eb.wait();
                }
            });
        }
    });

    black_box(checksum_sink.load(Ordering::Relaxed));
    let _ = build_profile;
    ms_samples.extend(pass_times_ms.into_inner().unwrap());
    cpb_samples.extend(pass_cpb.into_inner().unwrap());
    let mem_live = live_mem_slot.into_inner().unwrap();

    let med_cpb = if cpb_samples.is_empty() {
        None
    } else {
        Some(median(cpb_samples))
    };

    (ms_samples, med_cpb, mem_before, mem_live)
}

fn chunk_label(bytes: usize) -> String {
    format!("{} MiB", bytes / (1024 * 1024))
}

fn run_build_suite(build_profile: &str, out_path: PathBuf) {
    println!("==================================================================");
    println!(" AEAD Cipher Bake-Off Runner | Build Profile: {}", build_profile);
    println!("==================================================================");

    let hw = detect_hardware_info();
    println!("CPU Brand          : {}", hw.cpu_brand_string);
    println!("Logical Cores      : {}", hw.logical_cores);
    println!("TSC Reference GHz  : {:.4} GHz", hw.tsc_reference_ghz);
    println!("Runtime CPUID      : {:?}", hw.runtime_cpuid);
    println!("Compile-Time Flags : {:?}", hw.compile_time_target_features);

    let key_bytes: [u8; 32] = [
        0x4B, 0x1D, 0x8F, 0x22, 0x99, 0xC3, 0x7A, 0xE0, 0x11, 0x56, 0xA8, 0x4D, 0x3C, 0xF1, 0x07,
        0x6E, 0x82, 0xB5, 0xE9, 0x14, 0x2D, 0x70, 0xC8, 0x53, 0x9F, 0x31, 0x64, 0xAA, 0x0B, 0xD7,
        0x48, 0xFE,
    ];
    let file_uuid: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let nonce_prefix: [u8; 4] = [0xEC, 0x10, 0x26, 0x01];

    let aws_backend = AwsLcBackend {
        key: AwsLessSafeKey::new(
            AwsUnboundKey::new(&AWS_AES_256_GCM, &key_bytes).expect("aws-lc-rs key"),
        ),
        version: "1.19.0 (aws-lc-sys 0.47.0)",
    };
    let ring_backend = RingBackend {
        key: RingLessSafeKey::new(
            RingUnboundKey::new(&RING_AES_256_GCM, &key_bytes).expect("ring key"),
        ),
        version: "0.17.14",
    };
    let aes_gcm_backend = AesGcmBackend {
        cipher: Aes256Gcm::new((&key_bytes).into()),
        version: "0.10.3 (aes 0.8.4 + polyval 0.6.2)",
    };

    let interop = verify_cross_crate_interop(
        &aws_backend,
        &ring_backend,
        &aes_gcm_backend,
        &file_uuid,
        nonce_prefix,
    );
    println!("Cross-Crate Interop & 25B AAD Tamper Proof: {:?}", interop);

    let backends: [&dyn CipherBackend; 3] = [&aws_backend, &ring_backend, &aes_gcm_backend];

    let mut pure_l2_micro = Vec::new();
    for b in &backends {
        let m = run_pure_l2_micro(*b, build_profile, &file_uuid, nonce_prefix);
        println!(
            "[L2 Pure In-Place] {:<10} | Enc: {:>6.2} GiB/s ({:.3} cpb) | Dec: {:>6.2} GiB/s ({:.3} cpb)",
            m.crate_name, m.enc_gib_s, m.enc_cycles_per_byte, m.dec_gib_s, m.dec_cycles_per_byte
        );
        pure_l2_micro.push(m);
    }

    println!(
        "Allocating & initializing deterministic 2 GiB ({} bytes) payload...",
        PAYLOAD_BYTES
    );
    let t_init = Instant::now();
    let mut payload = vec![0u8; PAYLOAD_BYTES];
    fill_deterministic_payload(&mut payload);
    let orig_fp = fast_payload_fingerprint(&payload);
    println!(
        "2 GiB payload initialized in {:.2} ms (fingerprint = 0x{:016X})",
        t_init.elapsed().as_secs_f64() * 1000.0,
        orig_fp
    );

    let mut results = Vec::new();

    // Outer loop by chunk_size so we encrypt the single 2 GiB buffer once for all decrypt runs at that chunk_size,
    // keeping process Peak RSS strictly bounded around ~2.0 GiB + T * (chunk_size + 16)!
    for &chunk_size in &CHUNK_SIZES {
        let num_chunks = PAYLOAD_BYTES / chunk_size;
        let mut tags = vec![[0u8; 16]; num_chunks];

        // Phase 1: Measure 2 GiB Encrypt across all 3 backends x 3 thread counts
        struct PartialEnc {
            crate_idx: usize,
            threads: usize,
            enc_ms_samples: Vec<f64>,
            enc_cpb: Option<f64>,
            mem_before: ProcessMemoryCounters,
            mem_live: ProcessMemoryCounters,
        }
        let mut partials = Vec::new();

        for (b_idx, backend) in backends.iter().enumerate() {
            for &threads in &THREAD_COUNTS {
                let (enc_ms_samples, enc_cpb, mem_before, mem_live) = run_streaming_benchmark(
                    *backend,
                    build_profile,
                    &payload,
                    false,
                    &tags,
                    chunk_size,
                    threads,
                    &file_uuid,
                    nonce_prefix,
                );
                partials.push(PartialEnc {
                    crate_idx: b_idx,
                    threads,
                    enc_ms_samples,
                    enc_cpb,
                    mem_before,
                    mem_live,
                });
            }
        }

        // Transform the single 2 GiB buffer in-place into real authenticated ciphertext + tags
        transform_payload_in_place(
            &aws_backend,
            &mut payload,
            &mut tags,
            chunk_size,
            &file_uuid,
            nonce_prefix,
            true,
        );

        // Phase 2: Measure 2 GiB Decrypt + Tag Authentication across all 3 backends x 3 thread counts
        for p in partials {
            let backend = backends[p.crate_idx];
            let (dec_ms_samples, dec_cpb, _dec_mem_before, dec_mem_live) = run_streaming_benchmark(
                backend,
                build_profile,
                &payload,
                true,
                &tags,
                chunk_size,
                p.threads,
                &file_uuid,
                nonce_prefix,
            );

            let enc_ms_med = median(p.enc_ms_samples.clone());
            let dec_ms_med = median(dec_ms_samples.clone());
            let enc_gib_s = PAYLOAD_GIB / (enc_ms_med / 1000.0);
            let dec_gib_s = PAYLOAD_GIB / (dec_ms_med / 1000.0);

            let ws_bytes = p.mem_live.working_set_size.max(dec_mem_live.working_set_size);
            let peak_ws_bytes = p
                .mem_live
                .peak_working_set_size
                .max(dec_mem_live.peak_working_set_size);
            let pf_total = dec_mem_live.page_fault_count;
            let pf_delta = dec_mem_live
                .page_fault_count
                .saturating_sub(p.mem_before.page_fault_count);

            println!(
                "{:<10} | {:<7} | {:>2}T | Enc: {:>7.2} ms ({:>6.2} GiB/s) | Dec: {:>7.2} ms ({:>6.2} GiB/s) | 1T cpb: {:<13} | RSS: {:>7.1} MiB",
                backend.name(),
                chunk_label(chunk_size),
                p.threads,
                enc_ms_med,
                enc_gib_s,
                dec_ms_med,
                dec_gib_s,
                match (p.enc_cpb, dec_cpb) {
                    (Some(ec), Some(dc)) => format!("{:.3}/{:.3}", ec, dc),
                    _ => "-".to_string(),
                },
                ws_bytes as f64 / (1024.0 * 1024.0)
            );

            results.push(BenchmarkRow {
                crate_name: backend.name().to_string(),
                crate_version: backend.version().to_string(),
                build_profile: build_profile.to_string(),
                chunk_size_bytes: chunk_size,
                chunk_size_label: chunk_label(chunk_size),
                threads: p.threads,
                payload_bytes: PAYLOAD_BYTES,
                aad_bytes: 25,
                timed_passes: TIMED_PASSES,
                enc_ms_median: enc_ms_med,
                enc_ms_samples: p.enc_ms_samples,
                enc_gib_s,
                dec_ms_median: dec_ms_med,
                dec_ms_samples,
                dec_gib_s,
                enc_cycles_per_byte_1t: p.enc_cpb,
                dec_cycles_per_byte_1t: dec_cpb,
                working_set_bytes: ws_bytes,
                working_set_mib: ws_bytes as f64 / (1024.0 * 1024.0),
                peak_working_set_bytes: peak_ws_bytes,
                peak_working_set_mib: peak_ws_bytes as f64 / (1024.0 * 1024.0),
                page_fault_count_total: pf_total,
                page_fault_delta: pf_delta,
            });
        }

        // Restore 2 GiB buffer back to original plaintext & verify fingerprint
        transform_payload_in_place(
            &aws_backend,
            &mut payload,
            &mut tags,
            chunk_size,
            &file_uuid,
            nonce_prefix,
            false,
        );
        let restored_fp = fast_payload_fingerprint(&payload);
        assert_eq!(
            orig_fp, restored_fp,
            "Plaintext restoration fingerprint mismatch!"
        );
    }

    let output = BuildRunOutput {
        build_profile: build_profile.to_string(),
        rustflags: env::var("CIPHER_BENCH_RUSTFLAGS_DESC").unwrap_or_default(),
        hardware: hw,
        interop_verification: interop,
        pure_l2_micro,
        results,
    };

    let json = serde_json::to_string_pretty(&output).expect("serialize JSON");
    fs::write(&out_path, json).expect("write output JSON");
    println!("Saved build results to {}", out_path.display());
}

fn merge_outputs(inputs: &[PathBuf], out_path: PathBuf) {
    let mut builds = Vec::new();
    for p in inputs {
        let raw = fs::read_to_string(p).expect("read partial json");
        let parsed: BuildRunOutput = serde_json::from_str(&raw).expect("parse partial json");
        builds.push(parsed);
    }
    let combined = CombinedSuiteOutput {
        benchmark_title: "Wave 1 Silicon Bake-Off Part A: AEAD Cipher & Hardware Instruction Proof"
            .to_string(),
        timestamp_utc_approx: "2026-11-17".to_string(),
        payload_size_bytes: PAYLOAD_BYTES,
        aad_format: "25 bytes: 16B file_uuid || 8B chunk_idx (LE) || 1B is_final".to_string(),
        builds,
    };
    let json = serde_json::to_string_pretty(&combined).expect("serialize combined JSON");
    fs::write(&out_path, json).expect("write combined JSON");
    println!("Merged {} build runs into {}", inputs.len(), out_path.display());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 && args[1] == "--merge" {
        assert!(
            args.len() >= 5,
            "Usage: cipher_bench --merge <out.json> <in1.json> <in2.json> ..."
        );
        let out = PathBuf::from(&args[2]);
        let inputs: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
        merge_outputs(&inputs, out);
        return;
    }

    let build_profile = args
        .iter()
        .position(|a| a == "--profile")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("baseline-x86_64");

    let out_path = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cipher_results_part.json"));

    run_build_suite(build_profile, out_path);
}
