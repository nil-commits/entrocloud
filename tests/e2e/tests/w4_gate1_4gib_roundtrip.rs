//! Wave 4 Gate 1 Adversarial Torture Test:
//! Bit-Exact 4 GiB Multi-Cloud Roundtrip, O(1) Arbitrary Video-Scrub Hydration,
//! Mirrored RAID-1 Tamper Failover, and Continuous Win32 Bounded-RSS Proof.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail, ensure};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use entrocloud_core::{
    SqliteMetadataStore, SyncEngine, SyncEngineConfig, reclaim_process_memory,
};
use entrocloud_crypto::RingHybridCryptoEngine;
use entrocloud_storage::{CloudBackend, QuotaSelectionStrategy, StorageRouter};
use entrocloud_types::{
    BackendConfig, BackendKind, CreateEntrySpec, CryptoEngine, HydrationState, KdfParams,
    MetadataStore, PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RedactedSecret, RoutingPolicy,
    StorageRouterTrait, VfsBackend, VirtualDrive, ZeroVaultError, validate_remote_object_key,
};
use entrocloud_vfs::MockDrive;

const FILE_SIZE_4GIB: u64 = 4 * 1024 * 1024 * 1024; // 4,294,967,296 bytes
const TOTAL_CHUNKS_4GIB: u64 = FILE_SIZE_4GIB / (PLAINTEXT_CHUNK_SIZE as u64); // 1,024 chunks
const SAMPLE_INTERVAL_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
const BACKEND_A_QUOTA_BYTES: u64 = 2_684_354_560; // 2.5 GiB (2,560 MiB) -> forces spillover!
const BACKEND_B_QUOTA_BYTES: u64 = 4_294_967_296; // 4.0 GiB (4,096 MiB)
const BACKEND_RESERVE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB headroom floor
const VIRTUAL_VIDEO_PATH: &str = "/torture_4gib_8k_raw.mkv";

const STREAM_KEY_4GIB: [u8; 32] = *b"ZV-W4-GATE1-4GIB-ADVERSARIAL-KEY";
const STREAM_KEY_MIRROR: [u8; 32] = *b"ZV-W4-GATE1-RAID1-MIRROR-TESTKEY";

#[derive(Debug, Clone, Copy, Default)]
struct ProcessMemSample {
    working_set_bytes: u64,
    peak_working_set_bytes: u64,
    private_usage_bytes: u64,
}

impl ProcessMemSample {
    fn capture() -> Self {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::ProcessStatus::{
                K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
            };
            use windows_sys::Win32::System::Threading::GetCurrentProcess;

            // SAFETY: `PROCESS_MEMORY_COUNTERS_EX` is plain-old-data initialized to zero with `cb`
            // set to its exact byte size; `GetCurrentProcess()` returns a pseudo-handle valid for
            // the lifetime of the process.
            unsafe {
                let mut pmc: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
                pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
                let ok = K32GetProcessMemoryInfo(
                    GetCurrentProcess(),
                    (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>(),
                    pmc.cb,
                );
                assert!(ok != 0, "K32GetProcessMemoryInfo failed");
                Self {
                    working_set_bytes: pmc.WorkingSetSize as u64,
                    peak_working_set_bytes: pmc.PeakWorkingSetSize as u64,
                    private_usage_bytes: pmc.PrivateUsage as u64,
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
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
            Self {
                working_set_bytes: rss_bytes,
                peak_working_set_bytes: peak_rss_bytes,
                private_usage_bytes: vmsize_bytes,
            }
        }
    }

    fn rss_mib(self) -> f64 {
        (self.working_set_bytes as f64) / (1024.0 * 1024.0)
    }

    fn peak_rss_mib(self) -> f64 {
        (self.peak_working_set_bytes as f64) / (1024.0 * 1024.0)
    }

    fn private_mib(self) -> f64 {
        (self.private_usage_bytes as f64) / (1024.0 * 1024.0)
    }
}

#[derive(Debug, Clone)]
struct TimelineRow {
    phase: String,
    stream_mib: u64,
    sample: ProcessMemSample,
}

/// Fills `out` in O(1) time with deterministic cryptographic-grade high-entropy bytes
/// at arbitrary byte `offset` in the virtual stream using keyed `BLAKE3` XOF counter mode.
fn fill_ground_truth(key: &[u8; 32], domain: &[u8], offset: u64, out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain);
    let mut xof = hasher.finalize_xof();
    xof.set_position(offset);
    xof.fill(out);
}

fn shannon_entropy_bits_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    encode_hex(&digest)
}

fn collect_files_recursive(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn count_zv_chunk_blobs_and_verify_zero_knowledge(cloud_root: &Path) -> anyhow::Result<(usize, u64)> {
    let files = collect_files_recursive(cloud_root)?;
    let mut zv_blob_count = 0usize;
    let mut zv_blob_bytes = 0u64;

    for full_path in files {
        let rel = full_path
            .strip_prefix(cloud_root)
            .with_context(|| format!("strip_prefix failed on {}", full_path.display()))?;
        let rel_key = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");

        // Adversarial check: zero plaintext filenames or unvalidated object keys on remote storage!
        ensure!(
            !rel_key.to_ascii_lowercase().contains("torture")
                && !rel_key.to_ascii_lowercase().contains(".mkv"),
            "PLAINTEXT LEAK DETECTED on cloud backend: {rel_key}"
        );
        validate_remote_object_key(&rel_key)
            .with_context(|| format!("remote object key violated zero-knowledge grammar: {rel_key}"))?;

        if full_path.extension() == Some(OsStr::new("zv")) && rel_key.starts_with("blobs/") {
            zv_blob_count += 1;
            zv_blob_bytes += std::fs::metadata(&full_path)?.len();
        }
    }

    Ok((zv_blob_count, zv_blob_bytes))
}

fn make_local_fs_backend_config(
    id: &str,
    root_dir: &Path,
    quota_limit_bytes: Option<u64>,
    min_free_reserve_bytes: u64,
) -> anyhow::Result<BackendConfig> {
    std::fs::create_dir_all(root_dir)?;
    Ok(BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: root_dir.to_string_lossy().into_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes,
        min_free_reserve_bytes,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4_gate1_bit_exact_4gib_multicloud_roundtrip_and_bounded_rss() -> anyhow::Result<()> {
    let suite_start = Instant::now();
    let mut timeline: Vec<TimelineRow> = Vec::with_capacity(96);

    let baseline_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "00_process_start_baseline".to_owned(),
        stream_mib: 0,
        sample: baseline_mem,
    });

    println!("================================================================================");
    println!("WAVE 4 GATE 1 ADVERSARIAL TORTURE TEST: 4 GiB MULTI-CLOUD ROUNDTRIP & BOUNDED RSS");
    println!("================================================================================");
    println!(
        "[MEM] Baseline Process Start : RSS={:.2} MiB | PeakRSS={:.2} MiB | Private={:.2} MiB",
        baseline_mem.rss_mib(),
        baseline_mem.peak_rss_mib(),
        baseline_mem.private_mib()
    );

    let workspace_tmp = TempDir::new().context("failed creating TempDir for 4 GiB torture test")?;
    let cloud_a_dir = workspace_tmp.path().join("cloud_pool_a");
    let cloud_b_dir = workspace_tmp.path().join("cloud_pool_b");
    let db_path = workspace_tmp.path().join("state").join("metadata.db");
    let staging_dir = workspace_tmp.path().join("state").join("staging");
    let mount_dir = workspace_tmp.path().join("mnt_vault");

    // -------------------------------------------------------------------------
    // STEP 1: Real Production Crates Init (RingHybridCryptoEngine, SqliteMetadataStore,
    //         StorageRouter QuotaPooled across 2 LocalFs backends, SyncEngine, MockDrive)
    // -------------------------------------------------------------------------
    let crypto_concrete = Arc::new(
        RingHybridCryptoEngine::new().context("RingHybridCryptoEngine::new failed")?,
    );
    let hw_caps = crypto_concrete
        .verify_hardware_acceleration()
        .context("hardware crypto acceleration check failed")?;
    ensure!(
        hw_caps.mandatory_satisfied && hw_caps.aes_hw && hw_caps.pclmul_hw,
        "mandatory hardware AES+PCLMUL acceleration not satisfied: {hw_caps:?}"
    );
    println!(
        "[HW ] Crypto Engine          : backend={} | arch={} | aes_hw={} | pclmul_hw={} | vaes_hw={} | avx2_hw={}",
        hw_caps.backend_name,
        hw_caps.arch,
        hw_caps.aes_hw,
        hw_caps.pclmul_hw,
        hw_caps.vaes_hw,
        hw_caps.avx2_hw
    );

    let passphrase = RedactedSecret::new("W4-Gate1-Adversarial-Passphrase-2026!#99");
    let vault_header = crypto_concrete
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await
        .context("init_vault failed")?;
    reclaim_process_memory().await;

    let post_kdf_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "01_post_argon2id_init".to_owned(),
        stream_mib: 0,
        sample: post_kdf_mem,
    });
    println!(
        "[MEM] Post-Argon2id (64 MiB) : RSS={:.2} MiB | PeakRSS={:.2} MiB | Private={:.2} MiB",
        post_kdf_mem.rss_mib(),
        post_kdf_mem.peak_rss_mib(),
        post_kdf_mem.private_mib()
    );

    let crypto: Arc<dyn CryptoEngine> = crypto_concrete;
    let sqlite_store = Arc::new(
        SqliteMetadataStore::open(&db_path, Arc::clone(&crypto))
            .context("SqliteMetadataStore::open failed")?,
    );
    ensure!(
        sqlite_store.journal_mode()?.eq_ignore_ascii_case("wal"),
        "SQLite journal_mode must be WAL"
    );
    ensure!(
        sqlite_store.secure_delete_mode()? == 1,
        "SQLite secure_delete must be enabled (1)"
    );
    let meta: Arc<dyn MetadataStore> = sqlite_store.clone();

    let backend_a_cfg = make_local_fs_backend_config(
        "cloud-pool-a",
        &cloud_a_dir,
        Some(BACKEND_A_QUOTA_BYTES),
        BACKEND_RESERVE_BYTES,
    )?;
    let backend_b_cfg = make_local_fs_backend_config(
        "cloud-pool-b",
        &cloud_b_dir,
        Some(BACKEND_B_QUOTA_BYTES),
        BACKEND_RESERVE_BYTES,
    )?;
    let backend_a = Arc::new(CloudBackend::from_config(&backend_a_cfg)?);
    let backend_b = Arc::new(CloudBackend::from_config(&backend_b_cfg)?);

    let router = Arc::new(
        StorageRouter::from_shared(
            [Arc::clone(&backend_a), Arc::clone(&backend_b)],
            RoutingPolicy::QuotaPooled {
                pool_backends: vec!["cloud-pool-a".to_owned(), "cloud-pool-b".to_owned()],
            },
        )?
        .with_quota_strategy(QuotaSelectionStrategy::OrderedSpillover),
    );
    let storage: Arc<dyn StorageRouterTrait> = router.clone();

    let engine_cfg = SyncEngineConfig {
        staging_dir: staging_dir.clone(),
        device_id: "w4-judge-node-01".to_owned(),
        ..SyncEngineConfig::default()
    };
    println!(
        "[CFG] SyncEngine             : max_ram_cache_bytes={} MiB | max_concurrent_transfers={}",
        engine_cfg.max_ram_cache_bytes / (1024 * 1024),
        engine_cfg.max_concurrent_transfers
    );

    let engine = Arc::new(SyncEngine::new(
        engine_cfg,
        Arc::clone(&meta),
        Arc::clone(&crypto),
        Arc::clone(&storage),
    )?);
    engine
        .publish_vault_header(&vault_header)
        .await
        .context("publish_vault_header failed")?;

    let vfs_backend: Arc<dyn VfsBackend> = engine.clone();
    let drive = MockDrive::new(Arc::clone(&vfs_backend));
    drive.mount(mount_dir.clone()).await?;
    ensure!(drive.is_mounted(), "MockDrive failed to mount");

    let pre_upload_baseline = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "02_engine_mounted_idle".to_owned(),
        stream_mib: 0,
        sample: pre_upload_baseline,
    });
    println!(
        "[MEM] Engine Mounted Idle    : RSS={:.2} MiB | PeakRSS={:.2} MiB | Private={:.2} MiB",
        pre_upload_baseline.rss_mib(),
        pre_upload_baseline.peak_rss_mib(),
        pre_upload_baseline.private_mib()
    );

    // -------------------------------------------------------------------------
    // STEP 2: Stream 4 GiB (1,024 x 4 MiB) High-Entropy Data Into VFS + Multi-Cloud Flush
    // -------------------------------------------------------------------------
    let created = drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "torture_4gib_8k_raw.mkv".to_owned(),
            mode: 0o644,
        })
        .await
        .context("create_entry failed")?;
    let file_inode = created.inode;

    let mut expected_full_hasher = Sha256::new();
    let mut stream_chunk_buf = vec![0u8; PLAINTEXT_CHUNK_SIZE];
    let mut chunk0_entropy = 0.0f64;

    let upload_total_start = Instant::now();
    let vfs_stage_start = Instant::now();

    for chunk_idx in 0..TOTAL_CHUNKS_4GIB {
        let offset = chunk_idx * (PLAINTEXT_CHUNK_SIZE as u64);
        fill_ground_truth(
            &STREAM_KEY_4GIB,
            b"W4-GATE1-4GIB-PAYLOAD-V1",
            offset,
            &mut stream_chunk_buf,
        );
        if chunk_idx == 0 {
            chunk0_entropy = shannon_entropy_bits_per_byte(&stream_chunk_buf);
        }
        expected_full_hasher.update(&stream_chunk_buf);

        let written = drive
            .backend()
            .write_range(file_inode, offset, &stream_chunk_buf)
            .await
            .with_context(|| format!("write_range failed at chunk {chunk_idx} (offset {offset})"))?;
        ensure!(
            written == PLAINTEXT_CHUNK_SIZE,
            "short write at chunk {chunk_idx}: {written}"
        );

        let completed_bytes = offset + (PLAINTEXT_CHUNK_SIZE as u64);
        if completed_bytes.is_multiple_of(SAMPLE_INTERVAL_BYTES) {
            let sample = ProcessMemSample::capture();
            timeline.push(TimelineRow {
                phase: "03_vfs_write_stage".to_owned(),
                stream_mib: completed_bytes / (1024 * 1024),
                sample,
            });
        }
    }
    // Drop the 4 MiB generator buffer before flush so even that 4 MiB isn't held unnecessarily.
    drop(stream_chunk_buf);

    let vfs_stage_secs = vfs_stage_start.elapsed().as_secs_f64();
    let vfs_stage_mib_s = 4096.0 / vfs_stage_secs;
    let expected_full_sha256 = encode_hex(&expected_full_hasher.finalize());

    let staged_parts_before_flush = engine
        .cache()
        .list_dirty_chunk_indices(file_inode)
        .await?
        .len();
    let pre_flush_mem = ProcessMemSample::capture();
    ensure!(
        staged_parts_before_flush == TOTAL_CHUNKS_4GIB as usize,
        "expected 1024 dirty .zvpart files staged before flush, found {staged_parts_before_flush}"
    );
    ensure!(
        chunk0_entropy > 7.99,
        "expected cryptographic high-entropy stream (>7.99 bits/byte), got {chunk0_entropy:.6}"
    );
    println!(
        "[INGEST] 4,096 MiB Staged    : {:.3} s ({:.2} MiB/s) | entropy={:.6} bits/B | .zvpart={} | RSS={:.2} MiB",
        vfs_stage_secs,
        vfs_stage_mib_s,
        chunk0_entropy,
        staged_parts_before_flush,
        pre_flush_mem.rss_mib()
    );
    println!("[HASH] Expected 4 GiB SHA-256: {expected_full_sha256}");

    // Spawn a high-frequency (25ms) Win32 RSS watchdog thread during concurrent multi-cloud `flush`
    // so zero transient memory spikes can hide between async calls.
    let flush_done = Arc::new(AtomicBool::new(false));
    let flush_max_rss_bytes = Arc::new(AtomicU64::new(0));
    let flush_max_private_bytes = Arc::new(AtomicU64::new(0));
    let flush_samples_count = Arc::new(AtomicU64::new(0));
    let monitor_done = Arc::clone(&flush_done);
    let monitor_max_rss = Arc::clone(&flush_max_rss_bytes);
    let monitor_max_priv = Arc::clone(&flush_max_private_bytes);
    let monitor_count = Arc::clone(&flush_samples_count);

    let flush_monitor = std::thread::spawn(move || {
        let mut local_timeline = Vec::new();
        let mut tick = 0u64;
        while !monitor_done.load(Ordering::Acquire) {
            let s = ProcessMemSample::capture();
            monitor_max_rss.fetch_max(s.working_set_bytes, Ordering::Relaxed);
            monitor_max_priv.fetch_max(s.private_usage_bytes, Ordering::Relaxed);
            monitor_count.fetch_add(1, Ordering::Relaxed);
            if tick.is_multiple_of(20) {
                // Record a timeline row every ~500ms during flush
                local_timeline.push(s);
            }
            tick += 1;
            std::thread::sleep(Duration::from_millis(25));
        }
        local_timeline
    });

    let flush_start = Instant::now();
    drive
        .backend()
        .flush(file_inode)
        .await
        .context("4 GiB multi-cloud flush failed")?;
    let flush_secs = flush_start.elapsed().as_secs_f64();
    let upload_total_secs = upload_total_start.elapsed().as_secs_f64();

    flush_done.store(true, Ordering::Release);
    let flush_periodic_samples = flush_monitor
        .join()
        .map_err(|_| anyhow!("flush RSS monitor thread panicked"))?;

    for (idx, s) in flush_periodic_samples.into_iter().enumerate() {
        timeline.push(TimelineRow {
            phase: format!("04_multicloud_flush_500ms_{idx:02}"),
            stream_mib: 4096,
            sample: s,
        });
    }

    let post_flush_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "05_post_multicloud_flush".to_owned(),
        stream_mib: 4096,
        sample: post_flush_mem,
    });

    let flush_mib_s = 4096.0 / flush_secs;
    let combined_upload_mib_s = 4096.0 / upload_total_secs;
    let flush_watchdog_max_rss_mib =
        (flush_max_rss_bytes.load(Ordering::Relaxed) as f64) / (1024.0 * 1024.0);
    let flush_watchdog_max_priv_mib =
        (flush_max_private_bytes.load(Ordering::Relaxed) as f64) / (1024.0 * 1024.0);

    println!(
        "[FLUSH] 4,096 MiB Cloud Sync : {:.3} s ({:.2} MiB/s) | Combined Ingest+Flush: {:.3} s ({:.2} MiB/s)",
        flush_secs, flush_mib_s, upload_total_secs, combined_upload_mib_s
    );
    println!(
        "[MEM] Flush 25ms Watchdog    : samples={} | MaxRSS={:.2} MiB | MaxPrivate={:.2} MiB | PostFlushRSS={:.2} MiB",
        flush_samples_count.load(Ordering::Relaxed),
        flush_watchdog_max_rss_mib,
        flush_watchdog_max_priv_mib,
        post_flush_mem.rss_mib()
    );

    // Verify QuotaPooled spillover across Backend A (2.5 GiB cap) and Backend B (4.0 GiB cap)
    let (blobs_on_a, bytes_on_a) = count_zv_chunk_blobs_and_verify_zero_knowledge(&cloud_a_dir)?;
    let (blobs_on_b, bytes_on_b) = count_zv_chunk_blobs_and_verify_zero_knowledge(&cloud_b_dir)?;
    let total_remote_blobs = blobs_on_a + blobs_on_b;
    let quota_a = backend_a.quota();
    let quota_b = backend_b.quota();
    let pooled_quota = router.pooled_quota().await?;

    println!(
        "[CLOUD] Backend A (2.5 GiB)  : blobs={} | blob_bytes={} ({:.2} MiB) | tracked_used={} ({:.2} MiB)",
        blobs_on_a,
        bytes_on_a,
        (bytes_on_a as f64) / (1024.0 * 1024.0),
        quota_a.used_bytes,
        (quota_a.used_bytes as f64) / (1024.0 * 1024.0)
    );
    println!(
        "[CLOUD] Backend B (4.0 GiB)  : blobs={} | blob_bytes={} ({:.2} MiB) | tracked_used={} ({:.2} MiB)",
        blobs_on_b,
        bytes_on_b,
        (bytes_on_b as f64) / (1024.0 * 1024.0),
        quota_b.used_bytes,
        (quota_b.used_bytes as f64) / (1024.0 * 1024.0)
    );
    println!(
        "[CLOUD] Total Pooled Blobs   : {} / {} | Pooled Used={:.2} MiB / {:.2} MiB",
        total_remote_blobs,
        TOTAL_CHUNKS_4GIB,
        (pooled_quota.used_bytes as f64) / (1024.0 * 1024.0),
        (pooled_quota.total_bytes as f64) / (1024.0 * 1024.0)
    );

    ensure!(
        total_remote_blobs == TOTAL_CHUNKS_4GIB as usize,
        "expected exactly 1,024 remote .zv blobs across pooled backends, got {total_remote_blobs}"
    );
    ensure!(
        (600..=640).contains(&blobs_on_a) && blobs_on_b >= 384,
        "QuotaPooled spillover invariant failed: blobs_on_a={blobs_on_a}, blobs_on_b={blobs_on_b}"
    );
    ensure!(
        quota_a.used_bytes <= BACKEND_A_QUOTA_BYTES,
        "Backend A exceeded configured 2.5 GiB quota limit: {} > {}",
        quota_a.used_bytes,
        BACKEND_A_QUOTA_BYTES
    );

    // -------------------------------------------------------------------------
    // STEP 3: Purge Local Cache Completely (Dehydrate + Lock & Purge + Unlock + Reclaim)
    // -------------------------------------------------------------------------
    drive
        .dehydrate_path(VIRTUAL_VIDEO_PATH)
        .await
        .context("dehydrate_path failed")?;
    let state_after_dehydrate = drive.backend().get_xattr_state(file_inode).await?;
    ensure!(
        state_after_dehydrate == HydrationState::OnlineOnly,
        "expected OnlineOnly after dehydrate, got {state_after_dehydrate:?}"
    );

    let chunk_rows_after_dehydrate = meta.list_chunks(file_inode).await?;
    ensure!(
        chunk_rows_after_dehydrate.len() == TOTAL_CHUNKS_4GIB as usize,
        "expected 1024 chunk metadata descriptors, got {}",
        chunk_rows_after_dehydrate.len()
    );
    ensure!(
        chunk_rows_after_dehydrate.iter().all(|c| !c.locally_hydrated),
        "expected 0 locally_hydrated chunks in SQLite after dehydrate"
    );

    engine
        .lock_and_purge_cache()
        .await
        .context("lock_and_purge_cache failed")?;

    // Adversarial check: reading while locked MUST fail closed with VaultLocked!
    let locked_read = drive.backend().read_range(file_inode, 0, 4096).await;
    ensure!(
        matches!(locked_read, Err(ZeroVaultError::VaultLocked)),
        "expected VaultLocked error on read_range while locked, got {locked_read:?}"
    );

    let staging_files_after_purge = collect_files_recursive(&staging_dir)?.len();
    ensure!(
        staging_files_after_purge == 0,
        "expected 0 files in staging_dir after lock_and_purge_cache, found {staging_files_after_purge}"
    );
    ensure!(
        engine.cache().ram_entry_count() == 0 && engine.cache().used_ram_bytes() == 0,
        "expected 0 bytes in ChunkCache RAM after lock_and_purge_cache"
    );
    ensure!(
        engine.pool().pooled_buffers() == 0 && engine.pool().in_use_slots() == 0,
        "expected 0 pooled buffers after lock_and_purge_cache"
    );

    let purged_locked_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "06_purged_and_locked".to_owned(),
        stream_mib: 0,
        sample: purged_locked_mem,
    });
    println!(
        "[PURGE] Cache Purged & Locked: RAM_LRU=0 B | StagingFiles=0 | SQLiteHydrated=0/1024 | RSS={:.2} MiB",
        purged_locked_mem.rss_mib()
    );

    // Re-unlock vault for cold hydration tests
    crypto
        .unlock_with_passphrase(&vault_header, &passphrase)
        .await
        .context("unlock_with_passphrase failed")?;
    reclaim_process_memory().await;

    let unlocked_cold_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "07_reunlocked_cold_cache".to_owned(),
        stream_mib: 0,
        sample: unlocked_cold_mem,
    });
    ensure!(
        engine.cache().ram_entry_count() == 0 && engine.cache().used_ram_bytes() == 0,
        "expected cold RAM cache immediately after unlock"
    );

    // -------------------------------------------------------------------------
    // STEP 4: Arbitrary 4 MiB Byte-Range Hydration (Video Scrub Simulation)
    // -------------------------------------------------------------------------
    let stats_before_scrub = drive.stats().await?;
    ensure!(
        stats_before_scrub.chunks_hydrated == 0,
        "expected 0 chunks_hydrated before cold scrub, got {}",
        stats_before_scrub.chunks_hydrated
    );

    // Includes all 5 mandated ranges from the prompt PLUS an exact cross-cloud spillover straddle!
    let spillover_boundary_offset =
        ((blobs_on_a as u64) - 1) * (PLAINTEXT_CHUNK_SIZE as u64) + 2 * 1024 * 1024;
    let scrub_specs: Vec<(&str, u64, usize)> = vec![
        ("scrub_0_head_aligned_cloudA", 0, PLAINTEXT_CHUNK_SIZE),
        (
            "scrub_1_1gib_unaligned_cloudA",
            1_073_741_824 + 123_456,
            PLAINTEXT_CHUNK_SIZE,
        ),
        (
            "scrub_2_cross_backend_spillover_straddle_A_to_B",
            spillover_boundary_offset,
            PLAINTEXT_CHUNK_SIZE,
        ),
        (
            "scrub_3_2_5gib_unaligned_cloudB",
            2_684_354_560 + 4_000_000,
            PLAINTEXT_CHUNK_SIZE,
        ),
        (
            "scrub_4_3_5gib_unaligned_cloudB",
            3_758_096_384 + 777,
            PLAINTEXT_CHUNK_SIZE,
        ),
        (
            "scrub_5_4gib_tail_final_chunk_cloudB",
            4_290_772_992,
            PLAINTEXT_CHUNK_SIZE,
        ),
    ];

    let mut expected_scrub_buf = vec![0u8; PLAINTEXT_CHUNK_SIZE];
    let scrub_phase_start = Instant::now();

    for (label, offset, len) in &scrub_specs {
        let prev_hydrated = drive.stats().await?.chunks_hydrated;
        let t0 = Instant::now();
        let actual_bytes = drive
            .backend()
            .read_range(file_inode, *offset, *len)
            .await
            .with_context(|| format!("scrub read_range failed for {label} at offset={offset}"))?;
        let scrub_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let now_hydrated = drive.stats().await?.chunks_hydrated;
        let delta_chunks = now_hydrated - prev_hydrated;

        ensure!(
            actual_bytes.len() == *len,
            "scrub {label} returned {} bytes, expected {len}",
            actual_bytes.len()
        );

        fill_ground_truth(
            &STREAM_KEY_4GIB,
            b"W4-GATE1-4GIB-PAYLOAD-V1",
            *offset,
            &mut expected_scrub_buf[..*len],
        );
        let expected_hex = sha256_hex(&expected_scrub_buf[..*len]);
        let actual_hex = sha256_hex(&actual_bytes);
        ensure!(
            actual_hex == expected_hex,
            "SHA-256 mismatch on video scrub {label} (offset={offset}): actual={actual_hex} != expected={expected_hex}"
        );
        ensure!(
            (1..=2).contains(&delta_chunks),
            "O(1) scrub hydration violated for {label}: hydrated {delta_chunks} chunks for 4 MiB read"
        );

        let start_chunk = offset / (PLAINTEXT_CHUNK_SIZE as u64);
        let end_chunk = (offset + (*len as u64) - 1) / (PLAINTEXT_CHUNK_SIZE as u64);
        println!(
            "[SCRUB] {:<47} | off={:>13} | chunks={:>4}..={:<4} | +{} chunks | {:>6.2} ms | SHA256={} (MATCH)",
            label,
            offset,
            start_chunk,
            end_chunk,
            delta_chunks,
            scrub_ms,
            &actual_hex[..16]
        );
    }
    drop(expected_scrub_buf);

    let scrub_phase_ms = scrub_phase_start.elapsed().as_secs_f64() * 1000.0;
    let stats_after_scrub = drive.stats().await?;
    let post_scrub_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "08_post_6x_video_scrub".to_owned(),
        stream_mib: 24,
        sample: post_scrub_mem,
    });
    println!(
        "[SCRUB] Summary              : 6 arbitrary 4 MiB ranges verified in {:.2} ms | chunks_hydrated={} / 1024 (O(1) PROVEN) | RSS={:.2} MiB",
        scrub_phase_ms,
        stats_after_scrub.chunks_hydrated,
        post_scrub_mem.rss_mib()
    );
    ensure!(
        stats_after_scrub.chunks_hydrated == 10,
        "expected exactly 10 hydrated chunks across 2 aligned + 4 cross-chunk 4 MiB scrubs, got {}",
        stats_after_scrub.chunks_hydrated
    );

    // Re-dehydrate & clear RAM LRU before full 4 GiB sequential download so all 1,024 chunks
    // are fetched & AEAD-verified cold from multi-cloud backends (zero warm-cache shortcuts!).
    drive.dehydrate_path(VIRTUAL_VIDEO_PATH).await?;
    engine.cache().clear_ram();
    engine.pool().clear_idle_buffers();
    reclaim_process_memory().await;
    ensure!(
        engine.cache().ram_entry_count() == 0,
        "expected 0 cached chunks before full 4 GiB cold sequential hydration"
    );

    // -------------------------------------------------------------------------
    // STEP 5: Full 4 GiB Sequential Hydration SHA-256 Verification & Continuous RSS Proof
    // -------------------------------------------------------------------------
    let hydrated_before_seq = drive.stats().await?.chunks_hydrated;
    let mut actual_full_hasher = Sha256::new();
    let mut total_seq_read_bytes = 0u64;
    let download_start = Instant::now();

    for chunk_idx in 0..TOTAL_CHUNKS_4GIB {
        let offset = chunk_idx * (PLAINTEXT_CHUNK_SIZE as u64);
        let chunk_bytes = drive
            .backend()
            .read_range(file_inode, offset, PLAINTEXT_CHUNK_SIZE)
            .await
            .with_context(|| format!("sequential read_range failed at chunk {chunk_idx}"))?;
        ensure!(
            chunk_bytes.len() == PLAINTEXT_CHUNK_SIZE,
            "unexpected chunk length {} at chunk {chunk_idx}",
            chunk_bytes.len()
        );
        actual_full_hasher.update(&chunk_bytes);
        total_seq_read_bytes += chunk_bytes.len() as u64;
        drop(chunk_bytes);

        if total_seq_read_bytes.is_multiple_of(SAMPLE_INTERVAL_BYTES) {
            let sample = ProcessMemSample::capture();
            timeline.push(TimelineRow {
                phase: "09_seq_4gib_download".to_owned(),
                stream_mib: total_seq_read_bytes / (1024 * 1024),
                sample,
            });
        }
    }

    let download_secs = download_start.elapsed().as_secs_f64();
    let download_mib_s = 4096.0 / download_secs;
    let actual_full_sha256 = encode_hex(&actual_full_hasher.finalize());
    let hydrated_after_seq = drive.stats().await?.chunks_hydrated;
    let seq_hydrated_delta = hydrated_after_seq - hydrated_before_seq;

    println!("[HASH] Actual   4 GiB SHA-256: {actual_full_sha256}");
    println!(
        "[READ] 4,096 MiB Hydrated    : {:.3} s ({:.2} MiB/s) | cold_chunks_hydrated={} / 1024",
        download_secs, download_mib_s, seq_hydrated_delta
    );

    ensure!(
        total_seq_read_bytes == FILE_SIZE_4GIB,
        "sequential read byte count mismatch: {total_seq_read_bytes} != {FILE_SIZE_4GIB}"
    );
    ensure!(
        actual_full_sha256 == expected_full_sha256,
        "4 GiB FULL SHA-256 MISMATCH: actual={actual_full_sha256} != expected={expected_full_sha256}"
    );
    ensure!(
        seq_hydrated_delta == TOTAL_CHUNKS_4GIB,
        "expected all 1,024 chunks to be cold-hydrated during full read, got {seq_hydrated_delta}"
    );

    // Reclaim idle memory after 4 GiB download and sample steady-state RSS
    drive.dehydrate_path(VIRTUAL_VIDEO_PATH).await?;
    engine.cache().clear_ram();
    engine.pool().clear_idle_buffers();
    reclaim_process_memory().await;

    let post_reclaim_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "10_post_4gib_reclaim_idle".to_owned(),
        stream_mib: 4096,
        sample: post_reclaim_mem,
    });
    println!(
        "[MEM] Post-Reclaim Idle      : RSS={:.2} MiB | PeakRSS={:.2} MiB | Private={:.2} MiB",
        post_reclaim_mem.rss_mib(),
        post_reclaim_mem.peak_rss_mib(),
        post_reclaim_mem.private_mib()
    );

    drive.unmount().await?;

    // -------------------------------------------------------------------------
    // STEP 6: Mirrored (RAID-1) Multi-Cloud Verification + Adversarial Bit-Rot Failover
    // -------------------------------------------------------------------------
    let mirror_start = Instant::now();
    let mirror_1_dir = workspace_tmp.path().join("mirror_cloud_1");
    let mirror_2_dir = workspace_tmp.path().join("mirror_cloud_2");
    let mirror_db_path = workspace_tmp.path().join("mirror_state").join("metadata.db");
    let mirror_staging_dir = workspace_tmp.path().join("mirror_state").join("staging");

    let mirror_1 = Arc::new(CloudBackend::from_config(&make_local_fs_backend_config(
        "mirror-cloud-1",
        &mirror_1_dir,
        None,
        0,
    )?)?);
    let mirror_2 = Arc::new(CloudBackend::from_config(&make_local_fs_backend_config(
        "mirror-cloud-2",
        &mirror_2_dir,
        None,
        0,
    )?)?);
    let mirror_router = Arc::new(StorageRouter::from_shared(
        [Arc::clone(&mirror_1), Arc::clone(&mirror_2)],
        RoutingPolicy::Mirrored {
            backends: vec!["mirror-cloud-1".to_owned(), "mirror-cloud-2".to_owned()],
            min_ack: 2,
        },
    )?);
    let mirror_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&mirror_db_path, Arc::clone(&crypto))?);
    let mirror_engine = Arc::new(SyncEngine::new(
        SyncEngineConfig {
            staging_dir: mirror_staging_dir,
            device_id: "w4-judge-mirror-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&mirror_meta),
        Arc::clone(&crypto),
        mirror_router.clone(),
    )?);
    mirror_engine.publish_vault_header(&vault_header).await?;

    let mirror_vfs: Arc<dyn VfsBackend> = mirror_engine.clone();
    let mirror_drive = MockDrive::new(Arc::clone(&mirror_vfs));
    mirror_drive
        .mount(workspace_tmp.path().join("mnt_mirror"))
        .await?;

    let mirror_chunks_count = 16u64; // 64 MiB multi-chunk RAID-1 stream
    let mirror_file_size = mirror_chunks_count * (PLAINTEXT_CHUNK_SIZE as u64);
    let mirror_entry = mirror_drive
        .backend()
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "raid1_verified_stream.bin".to_owned(),
            mode: 0o644,
        })
        .await?;

    let mut mirror_expected_hasher = Sha256::new();
    let mut mirror_buf = vec![0u8; PLAINTEXT_CHUNK_SIZE];
    for idx in 0..mirror_chunks_count {
        let off = idx * (PLAINTEXT_CHUNK_SIZE as u64);
        fill_ground_truth(
            &STREAM_KEY_MIRROR,
            b"W4-GATE1-MIRROR-64MIB",
            off,
            &mut mirror_buf,
        );
        mirror_expected_hasher.update(&mirror_buf);
        mirror_drive
            .backend()
            .write_range(mirror_entry.inode, off, &mirror_buf)
            .await?;
    }
    drop(mirror_buf);
    mirror_drive.backend().flush(mirror_entry.inode).await?;
    ensure!(
        mirror_drive.backend().getattr(mirror_entry.inode).await?.size == mirror_file_size,
        "Mirrored file size mismatch"
    );
    let mirror_expected_sha256 = encode_hex(&mirror_expected_hasher.finalize());

    let (m1_blobs, _) = count_zv_chunk_blobs_and_verify_zero_knowledge(&mirror_1_dir)?;
    let (m2_blobs, _) = count_zv_chunk_blobs_and_verify_zero_knowledge(&mirror_2_dir)?;
    ensure!(
        m1_blobs == 16 && m2_blobs == 16,
        "Mirrored min_ack=2 failed to replicate all 16 chunks to both backends: m1={m1_blobs}, m2={m2_blobs}"
    );

    // Adversarial Bit-Flip Attack on Primary Mirror (`mirror-cloud-1`) for chunk 0 and chunk 9!
    let mirror_descs = mirror_meta.list_chunks(mirror_entry.inode).await?;
    for target_idx in [0usize, 9usize] {
        let blob_key = entrocloud_types::BlobObjectKey::from_uuid(mirror_descs[target_idx].blob_id);
        let corrupt_path = mirror_1_dir.join(blob_key.as_str());
        let mut raw_wire = std::fs::read(&corrupt_path)?;
        let mid = raw_wire.len() / 2;
        raw_wire[mid] ^= 0x80; // Flip 1 bit in AES-256-GCM ciphertext!
        std::fs::write(&corrupt_path, &raw_wire)?;
    }

    // Purge local cache completely and hydrate all 64 MiB: MUST failover to `mirror-cloud-2` seamlessly!
    mirror_drive
        .dehydrate_path("/raid1_verified_stream.bin")
        .await?;
    mirror_engine.cache().clear_ram();

    let mut mirror_actual_hasher = Sha256::new();
    for idx in 0..mirror_chunks_count {
        let off = idx * (PLAINTEXT_CHUNK_SIZE as u64);
        let data = mirror_drive
            .backend()
            .read_range(mirror_entry.inode, off, PLAINTEXT_CHUNK_SIZE)
            .await
            .with_context(|| format!("Mirrored failover read failed at chunk {idx}"))?;
        mirror_actual_hasher.update(&data);
    }
    let mirror_actual_sha256 = encode_hex(&mirror_actual_hasher.finalize());
    ensure!(
        mirror_actual_sha256 == mirror_expected_sha256,
        "Mirrored failover SHA-256 mismatch: {mirror_actual_sha256} != {mirror_expected_sha256}"
    );

    // Now corrupt chunk 0 on `mirror-cloud-2` as well -> ALL replicas tampered -> MUST fail closed!
    let chunk0_key = entrocloud_types::BlobObjectKey::from_uuid(mirror_descs[0].blob_id);
    let m2_chunk0_path = mirror_2_dir.join(chunk0_key.as_str());
    let mut m2_wire = std::fs::read(&m2_chunk0_path)?;
    let mid = m2_wire.len() / 2;
    m2_wire[mid] ^= 0x01;
    std::fs::write(&m2_chunk0_path, &m2_wire)?;

    mirror_drive
        .dehydrate_path("/raid1_verified_stream.bin")
        .await?;
    mirror_engine.cache().clear_ram();

    let dual_corrupt_res = mirror_drive
        .backend()
        .read_range(mirror_entry.inode, 0, 4096)
        .await;
    ensure!(
        matches!(dual_corrupt_res, Err(ZeroVaultError::CryptoTamperDetected(_))),
        "expected CryptoTamperDetected when all mirror replicas are corrupted, got {dual_corrupt_res:?}"
    );
    mirror_drive.unmount().await?;
    mirror_engine.lock_and_purge_cache().await?;

    let mirror_secs = mirror_start.elapsed().as_secs_f64();
    println!(
        "[MIRROR] RAID-1 64 MiB Check : {:.3} s | m1_blobs=16, m2_blobs=16 | 1-Replica Bit-Flip Failover SHA256={} (MATCH) | Dual-Replica Tamper -> CryptoTamperDetected (FAIL-CLOSED)",
        mirror_secs,
        &mirror_actual_sha256[..16]
    );

    // Final cleanup & RSS summary table
    engine.lock_and_purge_cache().await?;
    let final_mem = ProcessMemSample::capture();
    timeline.push(TimelineRow {
        phase: "11_final_locked_reclaimed".to_owned(),
        stream_mib: 0,
        sample: final_mem,
    });

    println!("\n--------------------------------------------------------------------------------");
    println!(
        "{:<34} | {:>10} | {:>10} | {:>11} | {:>11}",
        "PHASE", "STREAM MiB", "RSS (MiB)", "PEAK (MiB)", "PRIV (MiB)"
    );
    println!("--------------------------------------------------------------------------------");
    let mut max_sampled_rss_mib = 0.0f64;
    let mut max_kernel_peak_rss_mib = 0.0f64;
    for row in &timeline {
        let rss = row.sample.rss_mib();
        let peak = row.sample.peak_rss_mib();
        let priv_m = row.sample.private_mib();
        if rss > max_sampled_rss_mib {
            max_sampled_rss_mib = rss;
        }
        if peak > max_kernel_peak_rss_mib {
            max_kernel_peak_rss_mib = peak;
        }
        println!(
            "{:<34} | {:>10} | {:>10.2} | {:>11.2} | {:>11.2}",
            row.phase, row.stream_mib, rss, peak, priv_m
        );
    }
    if flush_watchdog_max_rss_mib > max_sampled_rss_mib {
        max_sampled_rss_mib = flush_watchdog_max_rss_mib;
    }
    println!("--------------------------------------------------------------------------------");

    let max_rss_delta_over_baseline = max_sampled_rss_mib - baseline_mem.rss_mib();
    let max_rss_delta_over_mounted = max_sampled_rss_mib - pre_upload_baseline.rss_mib();
    let suite_secs = suite_start.elapsed().as_secs_f64();

    println!(
        "[SUMMARY] Total Suite Wall-Clock : {:.3} s",
        suite_secs
    );
    println!(
        "[SUMMARY] 4 GiB SHA-256 Digest   : {} (BIT-EXACT MATCH)",
        actual_full_sha256
    );
    println!(
        "[SUMMARY] Max Sampled RSS        : {:.2} MiB (Delta vs Start: {:+.2} MiB | Delta vs Mounted: {:+.2} MiB)",
        max_sampled_rss_mib, max_rss_delta_over_baseline, max_rss_delta_over_mounted
    );
    println!(
        "[SUMMARY] Win32 Kernel PeakRSS   : {:.2} MiB (Across entire 4,096 MiB Upload + 4,096 MiB Download + 64 MiB Argon2id)",
        max_kernel_peak_rss_mib
    );

    // Strict Gate 1 RSS Ceiling Enforcement:
    // Both sampled RSS delta and total RSS must stay strictly bounded (`<= 128 MiB` delta, `<< 256 MiB` kernel peak).
    if max_rss_delta_over_baseline > 128.0 {
        bail!(
            "GATE 1 VETO: Max sampled RSS delta ({max_rss_delta_over_baseline:.2} MiB) exceeded 128.0 MiB ceiling!"
        );
    }
    if max_kernel_peak_rss_mib > 256.0 {
        bail!(
            "GATE 1 VETO: Win32 Kernel PeakWorkingSetSize ({max_kernel_peak_rss_mib:.2} MiB) exceeded 256.0 MiB ceiling!"
        );
    }

    Ok(())
}
