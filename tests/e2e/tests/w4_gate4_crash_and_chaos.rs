//! Wave 4 Gate 4 Adversarial Chaos & Kill-Recovery Torture Suite:
//! - Part A: Real OS `TerminateProcess` (`SIGKILL` equivalent) mid-upload against `entrocloudd.exe`
//!   over an owner-only Windows Named Pipe (`\\.\pipe\entrocloudd-w4-kill-<uuid>`), post-crash
//!   forensic plaintext/manifest inspection before restart, SQLite WAL recovery (`PRAGMA integrity_check`),
//!   baseline SHA-256 verification, re-import/sync revision advancement, and clean `Shutdown`.
//! - Part B: `30%` (`3000 bps`) packet-failure network chaos recovery across a 3-cloud
//!   `StorageRouter` wrapped in `ChaosStorageRouter` (`put_blob`, `get_blob`, `put_manifest_cas`),
//!   streaming `24 MiB` (`6 × 4 MiB` chunks), retry-loop convergence, full local cache purge
//!   (`dehydrate` + `lock_and_purge_cache` + re-unlock), cold readback under active `30%` chaos,
//!   100% bit-exact SHA-256 verification, `0` corrupted manifests, and `0` orphaned plaintext files.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;
use entrocloud_core::{
    SqliteMetadataStore, SyncEngine, SyncEngineConfig, compute_manifest_id,
};
use entrocloud_crypto::AwsLcCryptoEngine;
use entrocloud_daemon::{IpcClient, IpcEndpoint};
use entrocloud_storage::{
    ChaosStorageRouter, CloudBackend, StorageRouter, retry_transient,
};
use entrocloud_types::{
    AddRemoteParams, BackendConfig, BackendKind, CreateEntrySpec, CryptoEngine, DaemonRequest,
    DaemonResponse, HydrationState, KdfParams, MANIFEST_HEAD_OBJECT_KEY, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, RedactedSecret, RoutingPolicy, StorageRouterTrait, VaultHeader, VfsBackend,
};

const KILL_CANARY_ASCII: &[u8] = b"PLAINTEXT_KILL_CANARY_884422";
const KILL_FILENAME_CANARY_ASCII: &[u8] = b"kill_target_secret_9911";
const CHAOS_CANARY_ASCII: &[u8] = b"PLAINTEXT_CHAOS_CANARY_773311";
const CHAOS_FILENAME_CANARY_ASCII: &[u8] = b"chaos_24mib_payload";

/// RAII guard ensuring a spawned `entrocloudd` child process is never leaked on early error return.
struct DaemonChildGuard {
    child: Option<Child>,
}

impl DaemonChildGuard {
    const fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    fn kill_and_wait(&mut self) -> Result<std::process::ExitStatus> {
        let Some(mut child) = self.child.take() else {
            bail!("daemon child process already consumed");
        };
        child
            .kill()
            .context("failed invoking TerminateProcess / SIGKILL on entrocloudd")?;
        let status = child
            .wait()
            .context("failed awaiting killed entrocloudd process exit")?;
        Ok(status)
    }

    fn wait_with_timeout(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        let Some(mut child) = self.child.take() else {
            bail!("daemon child process already consumed");
        };
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child
                .try_wait()
                .context("failed polling entrocloudd exit status")?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "timed out after {:?} waiting for entrocloudd graceful exit",
                    timeout
                );
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    }
}

impl Drop for DaemonChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessRssSample {
    working_set_bytes: u64,
    peak_working_set_bytes: u64,
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn sample_pid_rss(pid: u32) -> Option<ProcessRssSample> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` opens a read-only query
    // handle to our child process, `pmc` is zero-initialized with accurate `cb`, and `CloseHandle`
    // releases the kernel handle unconditionally before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = K32GetProcessMemoryInfo(handle, &mut pmc, pmc.cb);
        let _ = CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(ProcessRssSample {
            working_set_bytes: pmc.WorkingSetSize as u64,
            peak_working_set_bytes: pmc.PeakWorkingSetSize as u64,
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn sample_pid_rss(_pid: u32) -> Option<ProcessRssSample> {
    None
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn sample_current_process_rss() -> Option<ProcessRssSample> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid for the lifetime of the process
    // that does not require `CloseHandle`, and `pmc` is properly sized and zero-initialized.
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb);
        if ok == 0 {
            return None;
        }
        Some(ProcessRssSample {
            working_set_bytes: pmc.WorkingSetSize as u64,
            peak_working_set_bytes: pmc.PeakWorkingSetSize as u64,
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn sample_current_process_rss() -> Option<ProcessRssSample> {
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0F) as usize] as char);
    }
    out
}

fn sha256_bytes(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_encode(&digest)
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)
        .with_context(|| format!("failed opening file for SHA-256: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("failed reading file for SHA-256: {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((total, hex_encode(&hasher.finalize())))
}

fn utf16le_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0u8);
    }
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[derive(Debug, Default)]
struct ForensicScanReport {
    files_scanned: usize,
    bytes_scanned: u64,
    canary_hits: Vec<String>,
}

/// Recursively scans every file under `root` in bounded 1 MiB windows (with overlap) for any
/// UTF-8 or UTF-16LE occurrence of the provided plaintext canary byte sequences.
fn scan_tree_for_plaintext_canaries(
    root: &Path,
    ascii_canaries: &[&[u8]],
) -> Result<ForensicScanReport> {
    let mut report = ForensicScanReport::default();
    if !root.exists() {
        return Ok(report);
    }

    let mut needles: Vec<(String, Vec<u8>)> = Vec::with_capacity(ascii_canaries.len() * 2);
    let mut max_needle_len = 1usize;
    for &raw in ascii_canaries {
        let label = String::from_utf8_lossy(raw).into_owned();
        max_needle_len = max_needle_len.max(raw.len());
        needles.push((format!("{label} [utf8]"), raw.to_vec()));
        let u16_bytes = utf16le_bytes(raw);
        max_needle_len = max_needle_len.max(u16_bytes.len());
        needles.push((format!("{label} [utf16le]"), u16_bytes));
    }

    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed reading directory {}", dir.display()));
            }
        };
        for entry_res in rd {
            let entry = entry_res?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();

    let mut chunk_buf = vec![0u8; 1024 * 1024];
    let overlap_keep = max_needle_len.saturating_sub(1);

    for file_path in files {
        let mut file = match File::open(&file_path) {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed opening {} for scan", file_path.display()));
            }
        };
        report.files_scanned += 1;
        let mut window = Vec::with_capacity(chunk_buf.len() + overlap_keep);

        loop {
            let n = file
                .read(&mut chunk_buf)
                .with_context(|| format!("failed reading {} during scan", file_path.display()))?;
            if n == 0 {
                break;
            }
            report.bytes_scanned = report.bytes_scanned.saturating_add(n as u64);
            window.extend_from_slice(&chunk_buf[..n]);

            for (label, needle) in &needles {
                if contains_subslice(&window, needle) {
                    report
                        .canary_hits
                        .push(format!("{} matched {}", file_path.display(), label));
                }
            }

            if window.len() > overlap_keep {
                let drain_count = window.len() - overlap_keep;
                window.drain(..drain_count);
            }
        }
    }

    Ok(report)
}

fn count_files_with_extension(root: &Path, ext: &str) -> usize {
    if !root.exists() {
        return 0;
    }
    let mut count = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case(ext))
            {
                count += 1;
            }
        }
    }
    count
}

fn collect_files_with_extension(root: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry_res in std::fs::read_dir(&dir)? {
            let entry = entry_res?;
            let ft = entry.file_type()?;
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case(ext))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn resolve_entrocloudd_binary() -> Result<PathBuf> {
    let exe_name = if cfg!(target_os = "windows") {
        "entrocloudd.exe"
    } else {
        "entrocloudd"
    };

    if let Ok(explicit) = std::env::var("CARGO_BIN_EXE_entrocloudd") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Ok(p);
        }
    }

    let current_test_exe = std::env::current_exe().context("failed resolving current_exe()")?;
    let profile_dir_opt = current_test_exe.parent().and_then(Path::parent);
    let is_release_profile = !cfg!(debug_assertions)
        || profile_dir_opt
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("release"));
    let profile_subdir = if is_release_profile {
        "release"
    } else {
        "debug"
    };

    if let Some(profile_dir) = profile_dir_opt
        && profile_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(profile_subdir))
    {
        let sibling = profile_dir.join(exe_name);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(&target_dir)
            .join(profile_subdir)
            .join(exe_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let default_target_candidate = ws_root.join("target").join(profile_subdir).join(exe_name);
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && default_target_candidate.is_file() {
        return Ok(default_target_candidate);
    }

    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut build_cmd = Command::new(cargo_bin);
    build_cmd
        .current_dir(&ws_root)
        .arg("build")
        .arg("--locked")
        .arg("-p")
        .arg("entrocloud-daemon")
        .arg("--bin")
        .arg("entrocloudd");
    if is_release_profile {
        build_cmd.arg("--release");
    }
    let status = build_cmd
        .status()
        .context("failed invoking cargo build -p entrocloud-daemon --bin entrocloudd")?;
    ensure!(
        status.success(),
        "cargo build -p entrocloud-daemon --bin entrocloudd exited with {status:?}"
    );

    if let Some(profile_dir) = profile_dir_opt
        && profile_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(profile_subdir))
    {
        let sibling = profile_dir.join(exe_name);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(&target_dir)
            .join(profile_subdir)
            .join(exe_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    if default_target_candidate.is_file() {
        return Ok(default_target_candidate);
    }

    bail!(
        "unable to locate compiled `{exe_name}` under `{profile_subdir}`; build `-p entrocloud-daemon --bin entrocloudd --locked` first"
    )
}

fn spawn_entrocloudd_process(
    daemon_bin: &Path,
    state_dir: &Path,
    endpoint_str: &str,
) -> Result<DaemonChildGuard> {
    let child = Command::new(daemon_bin)
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--ipc")
        .arg(endpoint_str)
        .arg("--mock-vfs")
        .arg("--sync-interval-secs")
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed spawning {}", daemon_bin.display()))?;
    Ok(DaemonChildGuard::new(child))
}

async fn wait_for_daemon_ready(client: &IpcClient, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_err = String::from("not yet probed");
    while Instant::now() < deadline {
        match client.ping().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err.to_string();
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
    bail!(
        "entrocloudd did not become ready on {} within {:?}: last_err={last_err}",
        client.endpoint(),
        timeout
    )
}

fn build_canary_payload(total_bytes: usize, canary: &[u8], extra_marker: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; total_bytes];
    let page_size = 4096usize;
    let num_pages = total_bytes.div_ceil(page_size);

    for page_idx in 0..num_pages {
        let start = page_idx * page_size;
        let end = (start + page_size).min(total_bytes);
        let page = &mut buf[start..end];

        // Fill deterministic high-entropy-like stream first so chunks are distinct.
        let mut s = (page_idx as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0xD1B5_4A32_D192_ED03);
        for byte in page.iter_mut() {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let val = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
            *byte = (val >> 56) as u8;
        }

        // Stamp plaintext canary and filename canary into every 4 KiB page.
        if page.len() >= canary.len() {
            page[..canary.len()].copy_from_slice(canary);
        }
        let second_offset = canary.len() + 16;
        if page.len() >= second_offset + extra_marker.len() {
            page[second_offset..second_offset + extra_marker.len()].copy_from_slice(extra_marker);
        }
    }

    buf
}

#[derive(Debug)]
struct SqliteIntegritySnapshot {
    journal_mode: String,
    integrity_check: String,
    quick_check: String,
    foreign_key_violations: usize,
    inode_rows: i64,
    chunk_rows: i64,
    dirty_op_rows: i64,
    manifest_revision: i64,
}

fn inspect_sqlite_wal_integrity(db_path: &Path) -> Result<SqliteIntegritySnapshot> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("failed opening SQLite DB {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;

    let journal_mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0))?;
    let integrity_check: String = conn.query_row("PRAGMA integrity_check;", [], |r| r.get(0))?;
    let quick_check: String = conn.query_row("PRAGMA quick_check;", [], |r| r.get(0))?;

    let mut fk_stmt = conn.prepare("PRAGMA foreign_key_check;")?;
    let fk_rows = fk_stmt.query_map([], |_row| Ok(()))?;
    let mut foreign_key_violations = 0usize;
    for r in fk_rows {
        r?;
        foreign_key_violations += 1;
    }

    let inode_rows: i64 = conn.query_row("SELECT COUNT(*) FROM inodes;", [], |r| r.get(0))?;
    let chunk_rows: i64 = conn.query_row("SELECT COUNT(*) FROM chunks;", [], |r| r.get(0))?;
    let dirty_op_rows: i64 =
        conn.query_row("SELECT COUNT(*) FROM dirty_ops;", [], |r| r.get(0))?;
    let manifest_revision: i64 = conn
        .query_row(
            "SELECT COALESCE((SELECT revision FROM manifest_cursor WHERE id = 1), 0);",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    Ok(SqliteIntegritySnapshot {
        journal_mode,
        integrity_check,
        quick_check,
        foreign_key_violations,
        inode_rows,
        chunk_rows,
        dirty_op_rows,
        manifest_revision,
    })
}

fn local_fs_backend_config(id: &str, dir: &Path, quota_limit_bytes: u64) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: dir.to_string_lossy().into_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes: Some(quota_limit_bytes),
        min_free_reserve_bytes: 0,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn part_a_real_terminate_process_mid_upload_and_sqlite_wal_recovery() -> Result<()> {
    let suite_start = Instant::now();
    let daemon_bin = resolve_entrocloudd_binary()?;
    let (daemon_bin_bytes, daemon_bin_sha256) = sha256_file(&daemon_bin)?;

    println!("=== [PART A] REAL TerminateProcess MID-UPLOAD TORTURE TEST ===");
    println!(
        "[PART A] entrocloudd binary: {} ({} bytes, sha256={})",
        daemon_bin.display(),
        daemon_bin_bytes,
        daemon_bin_sha256
    );

    let tmp = TempDir::new().context("failed creating Part A TempDir")?;
    let state_dir = tmp.path().join("state");
    let staging_dir = state_dir.join("staging");
    let remote_dir = tmp.path().join("remote_cloud");
    let inputs_dir = tmp.path().join("local_inputs");
    let exports_dir = tmp.path().join("local_exports");
    std::fs::create_dir_all(&inputs_dir)?;
    std::fs::create_dir_all(&exports_dir)?;

    let pipe_uuid = Uuid::new_v4().as_simple().to_string();
    #[cfg(target_os = "windows")]
    let endpoint_str = format!(r"\\.\pipe\entrocloudd-w4-kill-{pipe_uuid}");
    #[cfg(not(target_os = "windows"))]
    let endpoint_str = tmp
        .path()
        .join(format!("entrocloudd-w4-kill-{pipe_uuid}.sock"))
        .to_string_lossy()
        .into_owned();

    let endpoint = IpcEndpoint::parse(&endpoint_str)?;
    let client = IpcClient::new(endpoint);
    let passphrase = "w4-gate4-kill-recovery-zero-knowledge-passphrase";

    // 1. Generate deterministic baseline file (`5 MiB + 13,337 B` = 2 chunks) and `128 MiB` (32 chunks) kill target.
    let baseline_len = PLAINTEXT_CHUNK_SIZE + 1_048_576 + 13_337; // 5,256,217 bytes
    let baseline_bytes: Vec<u8> = (0..baseline_len)
        .map(|i| ((i.wrapping_mul(131)) ^ (i >> 11) ^ 0x5A) as u8)
        .collect();
    let baseline_sha256 = sha256_bytes(&baseline_bytes);
    let baseline_src_path = inputs_dir.join("baseline.bin");
    std::fs::write(&baseline_src_path, &baseline_bytes)?;

    let kill_target_len = 32 * PLAINTEXT_CHUNK_SIZE; // 128 MiB = 134,217,728 bytes (32 × 4 MiB chunks)
    let kill_target_bytes = build_canary_payload(
        kill_target_len,
        KILL_CANARY_ASCII,
        KILL_FILENAME_CANARY_ASCII,
    );
    let kill_target_sha256 = sha256_bytes(&kill_target_bytes);
    let kill_target_src_path = inputs_dir.join("kill_target_secret_9911.bin");
    std::fs::write(&kill_target_src_path, &kill_target_bytes)?;
    // Drop raw 128 MiB vector in test harness to keep test process memory lean.
    drop(kill_target_bytes);

    println!(
        "[PART A] Pipe endpoint={} | baseline={} B (sha256={}) | kill_target={} B / 128.00 MiB (sha256={})",
        endpoint_str, baseline_len, baseline_sha256, kill_target_len, kill_target_sha256
    );

    // 2. Spawn `entrocloudd.exe` Instance #1 and commit `/baseline.bin` at `rev 1`.
    let spawn1_start = Instant::now();
    let mut daemon1 = spawn_entrocloudd_process(&daemon_bin, &state_dir, &endpoint_str)?;
    let pid1 = daemon1.pid().unwrap_or(0);
    wait_for_daemon_ready(&client, Duration::from_secs(10)).await?;
    let spawn1_ready_ms = spawn1_start.elapsed().as_secs_f64() * 1000.0;
    let rss_pid1_idle = sample_pid_rss(pid1).unwrap_or_default();
    println!(
        "[PART A] Daemon #1 (PID={}) ready in {:.2} ms | Idle WorkingSet64={:.3} MiB (Peak={:.3} MiB)",
        pid1,
        spawn1_ready_ms,
        rss_pid1_idle.working_set_bytes as f64 / (1024.0 * 1024.0),
        rss_pid1_idle.peak_working_set_bytes as f64 / (1024.0 * 1024.0),
    );

    let init_resp = client
        .request(&DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await?;
    ensure!(
        matches!(init_resp, DaemonResponse::Ok { .. }),
        "expected InitVault Ok, got {init_resp:?}"
    );

    let add_remote_resp = client
        .request(&DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "local-fs-primary".to_owned(),
            kind: "fs".to_owned(),
            root: remote_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(2 * 1024 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await?;
    ensure!(
        matches!(add_remote_resp, DaemonResponse::Ok { .. }),
        "expected AddRemote Ok, got {add_remote_resp:?}"
    );

    let import_base_resp = client
        .request(&DaemonRequest::ImportLocalFile {
            local_path: baseline_src_path.to_string_lossy().into_owned(),
            virtual_dest_path: "/baseline.bin".to_owned(),
        })
        .await?;
    ensure!(
        matches!(import_base_resp, DaemonResponse::Ok { .. }),
        "expected baseline ImportLocalFile Ok, got {import_base_resp:?}"
    );

    let sync_base_resp = client.request(&DaemonRequest::SyncNow).await?;
    ensure!(
        matches!(sync_base_resp, DaemonResponse::Ok { .. }),
        "expected baseline SyncNow Ok, got {sync_base_resp:?}"
    );

    let status_rev1 = match client.request(&DaemonRequest::Status).await? {
        DaemonResponse::Status(report) => report,
        other => bail!("expected Status report after baseline commit, got {other:?}"),
    };
    ensure!(
        status_rev1.unlocked && status_rev1.manifest_revision == 1,
        "expected unlocked vault at manifest_revision == 1, got rev={}",
        status_rev1.manifest_revision
    );
    ensure!(
        status_rev1.throughput.pending_dirty_ops == 0,
        "expected 0 pending_dirty_ops after rev 1 commit, got {}",
        status_rev1.throughput.pending_dirty_ops
    );

    let baseline_remote_blobs = count_files_with_extension(&remote_dir.join("blobs"), "zv");
    ensure!(
        baseline_remote_blobs == 2,
        "expected 2 remote .zv blobs for 5 MiB baseline file, found {baseline_remote_blobs}"
    );
    println!(
        "[PART A] Committed `/baseline.bin` at manifest rev={} | remote_blobs={}",
        status_rev1.manifest_revision, baseline_remote_blobs
    );

    // 3. Kick off 128 MiB multi-chunk `ImportLocalFile` over IPC and forcefully kill `entrocloudd.exe`
    //    via `child.kill()` (`Win32 TerminateProcess`) while staging/upload is actively in flight!
    let client_for_kill_import = client.clone();
    let kill_src_str = kill_target_src_path.to_string_lossy().into_owned();
    let import_inflight_started = Arc::new(AtomicBool::new(false));
    let inflight_flag_clone = Arc::clone(&import_inflight_started);

    let inflight_import_task = tokio::spawn(async move {
        inflight_flag_clone.store(true, Ordering::Release);
        client_for_kill_import
            .request(&DaemonRequest::ImportLocalFile {
                local_path: kill_src_str,
                virtual_dest_path: "/kill_target_secret_9911.bin".to_owned(),
            })
            .await
    });

    // Dedicated OS watcher thread polling at 200 µs resolution so Tokio task scheduling cannot
    // delay catching the 128 MiB upload mid-flight.
    let watch_staging = staging_dir.join("dirty");
    let watch_remote_blobs = remote_dir.join("blobs");
    let kill_watch_start = Instant::now();
    let kill_deadline = kill_watch_start + Duration::from_secs(20);
    let mut observed_staged_at_kill = 0usize;
    let mut observed_remote_blobs_at_kill = baseline_remote_blobs;

    while Instant::now() < kill_deadline {
        if import_inflight_started.load(Ordering::Acquire) {
            let cur_staged = count_files_with_extension(&watch_staging, "zvpart");
            let cur_remote = count_files_with_extension(&watch_remote_blobs, "zv");
            // Strike right as remote cloud upload is actively mid-flight (`>= baseline + 4` out of `+32` blobs)!
            if cur_remote >= baseline_remote_blobs + 4
                || (cur_staged >= 24 && kill_watch_start.elapsed() > Duration::from_secs(5))
            {
                observed_staged_at_kill = cur_staged;
                observed_remote_blobs_at_kill = cur_remote;
                break;
            }
        }
        std::thread::sleep(Duration::from_micros(200));
    }

    ensure!(
        observed_staged_at_kill > 0 || observed_remote_blobs_at_kill > baseline_remote_blobs,
        "watcher did not observe active staging/upload before kill deadline"
    );

    let rss_pid1_pre_kill = sample_pid_rss(pid1).unwrap_or_default();
    let kill_trigger_elapsed_ms = kill_watch_start.elapsed().as_secs_f64() * 1000.0;
    let kill_call_start = Instant::now();
    let killed_status = daemon1.kill_and_wait()?;
    let kill_wait_ms = kill_call_start.elapsed().as_secs_f64() * 1000.0;

    ensure!(
        !killed_status.success(),
        "killed entrocloudd process must exit non-zero, got {killed_status:?}"
    );
    #[cfg(target_os = "windows")]
    ensure!(
        killed_status.code() == Some(1),
        "Win32 TerminateProcess via Child::kill() must report exit code 1, got {:?}",
        killed_status.code()
    );

    let interrupted_ipc_res = inflight_import_task
        .await
        .context("in-flight ImportLocalFile join panicked")?;
    ensure!(
        interrupted_ipc_res.is_err(),
        "in-flight ImportLocalFile MUST fail with broken-pipe/IPC error on mid-upload kill, but returned: {interrupted_ipc_res:?}"
    );

    println!(
        "[PART A] TerminateProcess struck at {:.2} ms (reap={:.2} ms) | exit_status={:?} (code={:?}) | Peak WorkingSet64={:.3} MiB | staged_at_kill={} | remote_blobs_at_kill={} | interrupted_ipc_err={}",
        kill_trigger_elapsed_ms,
        kill_wait_ms,
        killed_status,
        killed_status.code(),
        rss_pid1_pre_kill.peak_working_set_bytes as f64 / (1024.0 * 1024.0),
        observed_staged_at_kill,
        observed_remote_blobs_at_kill,
        interrupted_ipc_res.as_ref().err().map_or_else(String::new, ToString::to_string),
    );

    // 4. Forensic Post-Crash Inspection (BEFORE restarting `entrocloudd.exe`)!
    let post_crash_wal_path = state_dir.join("metadata.db-wal");
    let post_crash_db_bytes = std::fs::metadata(state_dir.join("metadata.db"))
        .map(|m| m.len())
        .unwrap_or(0);
    let post_crash_wal_bytes = std::fs::metadata(&post_crash_wal_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let post_crash_zvpart_count = count_files_with_extension(&staging_dir, "zvpart");
    let post_crash_remote_blobs = count_files_with_extension(&remote_dir.join("blobs"), "zv");

    let scan_canaries: [&[u8]; 2] = [KILL_CANARY_ASCII, KILL_FILENAME_CANARY_ASCII];
    let state_scan = scan_tree_for_plaintext_canaries(&state_dir, &scan_canaries)?;
    let staging_scan = scan_tree_for_plaintext_canaries(&staging_dir, &scan_canaries)?;
    let remote_scan = scan_tree_for_plaintext_canaries(&remote_dir, &scan_canaries)?;

    println!(
        "[PART A][FORENSIC PRE-RESTART] metadata.db={} B | metadata.db-wal={} B | staged_.zvpart={} | remote_.zv={}",
        post_crash_db_bytes, post_crash_wal_bytes, post_crash_zvpart_count, post_crash_remote_blobs
    );
    println!(
        "[PART A][FORENSIC PRE-RESTART] Plaintext Canary Scan -> state_dir: {} files ({} B, {} hits) | staging_dir: {} files ({} B, {} hits) | remote_dir: {} files ({} B, {} hits)",
        state_scan.files_scanned,
        state_scan.bytes_scanned,
        state_scan.canary_hits.len(),
        staging_scan.files_scanned,
        staging_scan.bytes_scanned,
        staging_scan.canary_hits.len(),
        remote_scan.files_scanned,
        remote_scan.bytes_scanned,
        remote_scan.canary_hits.len(),
    );

    ensure!(
        state_scan.canary_hits.is_empty(),
        "CRITICAL ZERO-KNOWLEDGE VIOLATION in state_dir post-crash: {:?}",
        state_scan.canary_hits
    );
    ensure!(
        staging_scan.canary_hits.is_empty(),
        "CRITICAL ZERO-KNOWLEDGE VIOLATION in staging_dir post-crash: {:?}",
        staging_scan.canary_hits
    );
    ensure!(
        remote_scan.canary_hits.is_empty(),
        "CRITICAL ZERO-KNOWLEDGE VIOLATION in remote_dir post-crash: {:?}",
        remote_scan.canary_hits
    );

    // Verify remote `manifests/head.zvm` (and all snapshot `.zvm` files) are NOT half-written/corrupted!
    let header_raw = std::fs::read(state_dir.join("vault.zvh"))
        .context("failed reading local vault.zvh for post-crash manifest audit")?;
    let decoded_header = VaultHeader::decode(&header_raw)?;
    let verifier_crypto = AwsLcCryptoEngine::new()?;
    verifier_crypto
        .unlock_with_passphrase(&decoded_header, &RedactedSecret::new(passphrase))
        .await?;

    let head_zvm_path = remote_dir.join(MANIFEST_HEAD_OBJECT_KEY);
    ensure!(
        head_zvm_path.is_file(),
        "remote manifests/head.zvm missing after mid-upload kill"
    );
    let head_zvm_bytes = std::fs::read(&head_zvm_path)?;
    let opened_head = verifier_crypto
        .open_manifest(&head_zvm_bytes)
        .context("remote manifests/head.zvm was corrupted by mid-upload TerminateProcess")?;
    let opened_head_id = compute_manifest_id(&opened_head)?;
    ensure!(
        opened_head.revision == 1 || opened_head.revision == 2,
        "unexpected post-crash head.zvm revision {}",
        opened_head.revision
    );

    let all_zvm_files = collect_files_with_extension(&remote_dir.join("manifests"), "zvm")?;
    ensure!(
        !all_zvm_files.is_empty(),
        "expected at least head.zvm + rev 1 snapshot in remote manifests/"
    );
    for zvm_file in &all_zvm_files {
        let raw = std::fs::read(zvm_file)?;
        let m = verifier_crypto
            .open_manifest(&raw)
            .with_context(|| format!("corrupted manifest file {}", zvm_file.display()))?;
        let _ = compute_manifest_id(&m)?;
    }
    verifier_crypto.lock_vault().await?;

    println!(
        "[PART A][FORENSIC PRE-RESTART] Verified {} remote .zvm manifest files (0 corrupted) | head.zvm rev={} id={} ({} B)",
        all_zvm_files.len(),
        opened_head.revision,
        opened_head_id,
        head_zvm_bytes.len()
    );

    // 5. Daemon Restart & SQLite WAL Recovery on the EXACT SAME `state_dir` and Named Pipe!
    let spawn2_start = Instant::now();
    let mut daemon2 = spawn_entrocloudd_process(&daemon_bin, &state_dir, &endpoint_str)?;
    let pid2 = daemon2.pid().unwrap_or(0);
    wait_for_daemon_ready(&client, Duration::from_secs(10)).await?;
    let spawn2_ready_ms = spawn2_start.elapsed().as_secs_f64() * 1000.0;

    let unlock_start = Instant::now();
    let unlock_resp = client
        .request(&DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await?;
    let unlock_ms = unlock_start.elapsed().as_secs_f64() * 1000.0;
    ensure!(
        matches!(unlock_resp, DaemonResponse::Ok { .. }),
        "expected UnlockVault Ok after crash recovery, got {unlock_resp:?}"
    );

    // Inspect SQLite WAL directly after unlock recovery!
    let wal_after_unlock = inspect_sqlite_wal_integrity(&state_dir.join("metadata.db"))?;
    println!(
        "[PART A][WAL RECOVERY] Daemon #2 (PID={}) ready in {:.2} ms, unlocked in {:.2} ms | journal_mode={} | integrity_check={} | quick_check={} | fk_violations={} | inodes={} chunks={} dirty_ops={} cursor_rev={}",
        pid2,
        spawn2_ready_ms,
        unlock_ms,
        wal_after_unlock.journal_mode,
        wal_after_unlock.integrity_check,
        wal_after_unlock.quick_check,
        wal_after_unlock.foreign_key_violations,
        wal_after_unlock.inode_rows,
        wal_after_unlock.chunk_rows,
        wal_after_unlock.dirty_op_rows,
        wal_after_unlock.manifest_revision,
    );

    ensure!(
        wal_after_unlock.journal_mode.eq_ignore_ascii_case("wal"),
        "expected WAL journal_mode, got {}",
        wal_after_unlock.journal_mode
    );
    ensure!(
        wal_after_unlock.integrity_check == "ok" && wal_after_unlock.quick_check == "ok",
        "SQLite WAL integrity check failed after TerminateProcess: integrity={}, quick={}",
        wal_after_unlock.integrity_check,
        wal_after_unlock.quick_check
    );
    ensure!(
        wal_after_unlock.foreign_key_violations == 0,
        "SQLite foreign_key_check found {} violations",
        wal_after_unlock.foreign_key_violations
    );

    // Dehydrate `/baseline.bin` and export from remote cloud storage -> prove 100% SHA-256 intact!
    let dehydrate_base = client
        .request(&DaemonRequest::Dehydrate {
            virtual_path: "/baseline.bin".to_owned(),
        })
        .await?;
    ensure!(
        matches!(dehydrate_base, DaemonResponse::Ok { .. }),
        "expected baseline Dehydrate Ok, got {dehydrate_base:?}"
    );

    let exported_baseline_path = exports_dir.join("baseline_recovered.bin");
    let export_base_resp = client
        .request(&DaemonRequest::ExportVaultFile {
            virtual_path: "/baseline.bin".to_owned(),
            local_dest_path: exported_baseline_path.to_string_lossy().into_owned(),
        })
        .await?;
    ensure!(
        matches!(export_base_resp, DaemonResponse::Ok { .. }),
        "expected baseline ExportVaultFile Ok, got {export_base_resp:?}"
    );
    let (exported_base_len, exported_base_sha256) = sha256_file(&exported_baseline_path)?;
    ensure!(
        exported_base_len == baseline_len as u64 && exported_base_sha256 == baseline_sha256,
        "baseline SHA-256 mismatch after crash recovery: expected {baseline_sha256}, got {exported_base_sha256}"
    );
    println!(
        "[PART A][RECOVERY] `/baseline.bin` verified 100% bit-exact ({} B, sha256={})",
        exported_base_len, exported_base_sha256
    );

    // Re-import & sync the interrupted 128 MiB file and verify clean `rev` advancement!
    let reimport_start = Instant::now();
    let reimport_resp = client
        .request(&DaemonRequest::ImportLocalFile {
            local_path: kill_target_src_path.to_string_lossy().into_owned(),
            virtual_dest_path: "/kill_target_secret_9911.bin".to_owned(),
        })
        .await?;
    ensure!(
        matches!(reimport_resp, DaemonResponse::Ok { .. }),
        "expected re-import ImportLocalFile Ok, got {reimport_resp:?}"
    );

    let resync_resp = client.request(&DaemonRequest::SyncNow).await?;
    ensure!(
        matches!(resync_resp, DaemonResponse::Ok { .. }),
        "expected post-reimport SyncNow Ok, got {resync_resp:?}"
    );
    let reimport_secs = reimport_start.elapsed().as_secs_f64();
    let reimport_mib_s = (kill_target_len as f64 / (1024.0 * 1024.0)) / reimport_secs.max(1e-6);

    let status_recovered = match client.request(&DaemonRequest::Status).await? {
        DaemonResponse::Status(report) => report,
        other => bail!("expected Status report after recovery sync, got {other:?}"),
    };
    ensure!(
        status_recovered.manifest_revision >= 2,
        "expected manifest_revision >= 2 after re-importing interrupted file, got {}",
        status_recovered.manifest_revision
    );
    ensure!(
        status_recovered.throughput.pending_dirty_ops == 0,
        "expected 0 pending_dirty_ops after recovery sync, got {}",
        status_recovered.throughput.pending_dirty_ops
    );
    ensure!(
        status_recovered.conflict_count == 0,
        "expected 0 conflicts after recovery sync, got {}",
        status_recovered.conflict_count
    );

    // Dehydrate `/kill_target_secret_9911.bin` and export all 128 MiB back to verify SHA-256!
    let dehydrate_kill_resp = client
        .request(&DaemonRequest::Dehydrate {
            virtual_path: "/kill_target_secret_9911.bin".to_owned(),
        })
        .await?;
    ensure!(
        matches!(dehydrate_kill_resp, DaemonResponse::Ok { .. }),
        "expected Dehydrate on recovered 128 MiB file Ok, got {dehydrate_kill_resp:?}"
    );

    let exported_kill_path = exports_dir.join("kill_target_recovered.bin");
    let export_start = Instant::now();
    let export_kill_resp = client
        .request(&DaemonRequest::ExportVaultFile {
            virtual_path: "/kill_target_secret_9911.bin".to_owned(),
            local_dest_path: exported_kill_path.to_string_lossy().into_owned(),
        })
        .await?;
    let export_secs = export_start.elapsed().as_secs_f64();
    let export_mib_s = (kill_target_len as f64 / (1024.0 * 1024.0)) / export_secs.max(1e-6);
    ensure!(
        matches!(export_kill_resp, DaemonResponse::Ok { .. }),
        "expected ExportVaultFile on recovered 128 MiB file Ok, got {export_kill_resp:?}"
    );

    let (exported_kill_len, exported_kill_sha256) = sha256_file(&exported_kill_path)?;
    ensure!(
        exported_kill_len == kill_target_len as u64 && exported_kill_sha256 == kill_target_sha256,
        "recovered 128 MiB SHA-256 mismatch: expected {kill_target_sha256}, got {exported_kill_sha256}"
    );

    let rss_pid2_post_sync = sample_pid_rss(pid2).unwrap_or_default();
    println!(
        "[PART A][RECOVERY] 128 MiB re-import+sync={:.2} ms ({:.2} MiB/s) | cold dehydrate+export={:.2} ms ({:.2} MiB/s) | rev={} | sha256={} (MATCH) | PID #2 WorkingSet64={:.3} MiB (Peak={:.3} MiB)",
        reimport_secs * 1000.0,
        reimport_mib_s,
        export_secs * 1000.0,
        export_mib_s,
        status_recovered.manifest_revision,
        exported_kill_sha256,
        rss_pid2_post_sync.working_set_bytes as f64 / (1024.0 * 1024.0),
        rss_pid2_post_sync.peak_working_set_bytes as f64 / (1024.0 * 1024.0),
    );

    // Clean `Shutdown` and final post-shutdown WAL + zero-plaintext verification.
    let shutdown_resp = client.request(&DaemonRequest::Shutdown).await?;
    ensure!(
        matches!(shutdown_resp, DaemonResponse::Ok { .. }),
        "expected Shutdown Ok, got {shutdown_resp:?}"
    );
    let daemon2_exit = daemon2.wait_with_timeout(Duration::from_secs(10))?;
    ensure!(
        daemon2_exit.success(),
        "restarted entrocloudd must exit cleanly with code 0 on Shutdown, got {daemon2_exit:?}"
    );

    let wal_after_shutdown = inspect_sqlite_wal_integrity(&state_dir.join("metadata.db"))?;
    ensure!(
        wal_after_shutdown.integrity_check == "ok" && wal_after_shutdown.dirty_op_rows == 0,
        "post-shutdown SQLite state invalid: {wal_after_shutdown:?}"
    );
    let leftover_zvpart = count_files_with_extension(&staging_dir, "zvpart");
    ensure!(
        leftover_zvpart == 0,
        "expected 0 leftover .zvpart files after clean sync + shutdown, found {leftover_zvpart}"
    );

    let final_state_scan = scan_tree_for_plaintext_canaries(&state_dir, &scan_canaries)?;
    let final_remote_scan = scan_tree_for_plaintext_canaries(&remote_dir, &scan_canaries)?;
    ensure!(
        final_state_scan.canary_hits.is_empty() && final_remote_scan.canary_hits.is_empty(),
        "post-shutdown plaintext canary leak detected"
    );

    println!(
        "[PART A] PASS in {:.2} ms | Daemon #2 exit={:?} | final SQLite integrity_check={} | leftover_.zvpart=0 | plaintext_canary_hits=0",
        suite_start.elapsed().as_secs_f64() * 1000.0,
        daemon2_exit.code(),
        wal_after_shutdown.integrity_check
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn part_b_thirty_percent_packet_failure_network_chaos_recovery() -> Result<()> {
    let suite_start = Instant::now();
    println!("=== [PART B] 30% (3000 bps) PACKET FAILURE NETWORK CHAOS TORTURE TEST ===");

    let tmp = TempDir::new().context("failed creating Part B TempDir")?;
    let state_dir = tmp.path().join("chaos_state");
    let staging_dir = state_dir.join("staging");
    let db_path = state_dir.join("metadata.db");
    let cloud_alpha_dir = tmp.path().join("cloud_alpha");
    let cloud_beta_dir = tmp.path().join("cloud_beta");
    let cloud_gamma_dir = tmp.path().join("cloud_gamma");
    std::fs::create_dir_all(&staging_dir)?;

    // 1. Build 3-cloud `StorageRouter` (Mirrored RAID-1 across 3 LocalFs clouds, `min_ack = 2`)
    //    wrapped inside `ChaosStorageRouter` at `failure_rate_bps = 3000` (`30.0%` packet drops
    //    across `put_blob`, `get_blob`, `get_blob_from_backend`, and `put_manifest_cas`).
    let quota_cap = 512 * 1024 * 1024u64;
    let backends = vec![
        CloudBackend::from_config(&local_fs_backend_config(
            "cloud-alpha",
            &cloud_alpha_dir,
            quota_cap,
        ))?,
        CloudBackend::from_config(&local_fs_backend_config(
            "cloud-beta",
            &cloud_beta_dir,
            quota_cap,
        ))?,
        CloudBackend::from_config(&local_fs_backend_config(
            "cloud-gamma",
            &cloud_gamma_dir,
            quota_cap,
        ))?,
    ];
    let policy = RoutingPolicy::Mirrored {
        backends: vec![
            "cloud-alpha".to_owned(),
            "cloud-beta".to_owned(),
            "cloud-gamma".to_owned(),
        ],
        min_ack: 2,
    };
    let inner_router = Arc::new(StorageRouter::new(backends, policy)?);
    let chaos_seed: u64 = 0x5A56_4348_414F_5334;
    let chaos_router = Arc::new(ChaosStorageRouter::from_storage_router(
        Arc::clone(&inner_router),
        chaos_seed,
        3_000,
    ));
    ensure!(
        chaos_router.failure_rate_bps() == 3_000,
        "expected failure_rate_bps == 3000"
    );

    // 2. Initialize real hardware-accelerated `AwsLcCryptoEngine`, WAL `SqliteMetadataStore`, and `SyncEngine`.
    let crypto = Arc::new(AwsLcCryptoEngine::new()?);
    let passphrase = RedactedSecret::new("w4-gate4-chaos-30pct-vault-passphrase");
    let vault_header = crypto
        .init_vault(&passphrase, KdfParams::interactive_production())
        .await?;

    let meta = Arc::new(SqliteMetadataStore::open(
        &db_path,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
    )?);
    let engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: staging_dir.clone(),
            device_id: "chaos-node-1".to_owned(),
            ..SyncEngineConfig::default()
        },
        meta,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
        Arc::clone(&chaos_router) as Arc<dyn StorageRouterTrait>,
    )?;

    // Publish `vault/header.zvh` under active 30% chaos via transient retry.
    retry_transient(32, Duration::from_millis(2), || {
        engine.publish_vault_header(&vault_header)
    })
    .await
    .context("failed publishing vault header under 30% packet chaos")?;

    // 3. Stream `24 MiB` (`6 × 4 MiB` chunks) payload with known `SHA-256` into `SyncEngine`.
    let payload_len = 6 * PLAINTEXT_CHUNK_SIZE; // 24 MiB = 25,165,824 bytes
    let payload = build_canary_payload(
        payload_len,
        CHAOS_CANARY_ASCII,
        CHAOS_FILENAME_CANARY_ASCII,
    );
    let expected_sha256 = sha256_bytes(&payload);

    let stage_start = Instant::now();
    let created = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "chaos_24mib_payload.bin".to_owned(),
            mode: 0o644,
        })
        .await?;

    for chunk_idx in 0..6usize {
        let start = chunk_idx * PLAINTEXT_CHUNK_SIZE;
        let end = start + PLAINTEXT_CHUNK_SIZE;
        let written = engine
            .write_range(created.inode, start as u64, &payload[start..end])
            .await?;
        ensure!(
            written == PLAINTEXT_CHUNK_SIZE,
            "short write_range on chunk {chunk_idx}"
        );
    }
    drop(payload);
    let stage_ms = stage_start.elapsed().as_secs_f64() * 1000.0;

    let initial_dirty = engine.metadata().list_dirty_ops().await?;
    ensure!(
        initial_dirty.len() == 1,
        "expected 1 queued UpsertFile dirty_op before sync, got {}",
        initial_dirty.len()
    );
    let staged_parts_before_sync = count_files_with_extension(&staging_dir, "zvpart");
    ensure!(
        staged_parts_before_sync == 6,
        "expected 6 encrypted .zvpart staging files for 24 MiB file, got {staged_parts_before_sync}"
    );

    // 4. Run `sync_once()` retry loop under active 30% packet-failure chaos until `dirty_ops` drains!
    let stats_before_upload = chaos_router.stats();
    let upload_sync_start = Instant::now();
    let mut sync_attempts = 0usize;
    let mut transient_sync_errors = 0usize;
    let mut sample_transient_error = String::new();
    let mut final_published_rev: Option<u64> = None;

    for attempt in 1..=128usize {
        sync_attempts = attempt;
        match engine.sync_once().await {
            Ok(report) => {
                if let Some(rev) = report.published_revision {
                    final_published_rev = Some(rev);
                }
                if engine.metadata().list_dirty_ops().await?.is_empty() {
                    break;
                }
            }
            Err(err) => {
                transient_sync_errors += 1;
                if sample_transient_error.is_empty() {
                    sample_transient_error = err.to_string();
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    let upload_sync_secs = upload_sync_start.elapsed().as_secs_f64();
    let upload_eff_mib_s = (payload_len as f64 / (1024.0 * 1024.0)) / upload_sync_secs.max(1e-6);

    let remaining_dirty = engine.metadata().list_dirty_ops().await?;
    ensure!(
        remaining_dirty.is_empty(),
        "dirty_ops failed to drain after {sync_attempts} sync_once() attempts: {remaining_dirty:?}"
    );
    ensure!(
        final_published_rev == Some(1),
        "expected published_revision == Some(1), got {final_published_rev:?}"
    );

    let stats_after_upload = chaos_router.stats();
    let upload_ops = stats_after_upload
        .total_ops
        .saturating_sub(stats_before_upload.total_ops);
    let upload_injected_failures = stats_after_upload
        .injected_transient_failures
        .saturating_sub(stats_before_upload.injected_transient_failures);

    ensure!(
        upload_injected_failures > 0,
        "ChaosStorageRouter MUST inject > 0 transient failures during 24 MiB upload/CAS sync, got 0"
    );

    println!(
        "[PART B][UPLOAD CONVERGENCE] Staged 24 MiB in {:.2} ms | Converged in {} sync_once() attempts ({} transient errors) over {:.2} ms ({:.2} MiB/s) | upload_chaos_ops={} injected_failures={} ({:.1}%) | sample_fault=\"{}\"",
        stage_ms,
        sync_attempts,
        transient_sync_errors,
        upload_sync_secs * 1000.0,
        upload_eff_mib_s,
        upload_ops,
        upload_injected_failures,
        (upload_injected_failures as f64 / upload_ops.max(1) as f64) * 100.0,
        sample_transient_error,
    );

    // 5. Purge local cache & read back all `24 MiB` under active `30%` (`3000 bps`) packet-failure chaos!
    //    Pass 1 verifies cold hydration after `dehydrate()`, and Pass 2 verifies cold hydration after
    //    `dehydrate()` + `lock_and_purge_cache()` + `unlock_with_passphrase()`.
    let stats_before_read = chaos_router.stats();
    let read_start = Instant::now();

    for pass in 1..=2usize {
        engine.dehydrate(created.inode).await?;
        let dehydrated_rec = engine.getattr(created.inode).await?;
        ensure!(
            dehydrated_rec.hydration == HydrationState::OnlineOnly,
            "expected HydrationState::OnlineOnly after dehydrate (pass {pass}), got {:?}",
            dehydrated_rec.hydration
        );
        let chunk_descs = engine.metadata().list_chunks(created.inode).await?;
        ensure!(
            chunk_descs.len() == 6 && chunk_descs.iter().all(|c| !c.locally_hydrated),
            "expected all 6 chunk descriptors marked locally_hydrated == false (pass {pass})"
        );

        if pass == 2 {
            engine.lock_and_purge_cache().await?;
            ensure!(
                !crypto.is_unlocked(),
                "crypto engine must be locked after lock_and_purge_cache()"
            );
            ensure!(
                engine.cache().used_ram_bytes() == 0 && engine.cache().ram_entry_count() == 0,
                "RAM chunk cache must be 0 bytes after lock_and_purge_cache()"
            );
            ensure!(
                count_files_with_extension(&staging_dir, "zvpart") == 0,
                "staging_dir must contain 0 .zvpart files after lock_and_purge_cache()"
            );
            crypto
                .unlock_with_passphrase(&vault_header, &passphrase)
                .await?;
        }

        let mut rehydrated = Zeroizing::new(Vec::with_capacity(payload_len));
        let read_slice_len = 2 * 1024 * 1024usize;
        let mut offset = 0u64;

        while (offset as usize) < payload_len {
            let step = (payload_len - offset as usize).min(read_slice_len);
            let inode = created.inode;
            let cur_off = offset;
            let bytes = retry_transient(64, Duration::from_millis(2), || {
                engine.read_range(inode, cur_off, step)
            })
            .await
            .with_context(|| {
                format!(
                    "failed reading range offset={cur_off} len={step} under 30% chaos (pass {pass})"
                )
            })?;
            ensure!(
                bytes.len() == step,
                "expected {step} bytes from read_range (pass {pass}), got {}",
                bytes.len()
            );
            rehydrated.extend_from_slice(&bytes);
            offset += step as u64;
        }

        let actual_sha256 = sha256_bytes(&rehydrated);
        drop(rehydrated);
        ensure!(
            actual_sha256 == expected_sha256,
            "24 MiB readback SHA-256 mismatch under 30% chaos (pass {pass}): expected {expected_sha256}, got {actual_sha256}"
        );
    }

    let read_secs = read_start.elapsed().as_secs_f64();
    let read_eff_mib_s =
        ((payload_len * 2) as f64 / (1024.0 * 1024.0)) / read_secs.max(1e-6);

    let stats_after_read = chaos_router.stats();
    let read_ops = stats_after_read
        .total_ops
        .saturating_sub(stats_before_read.total_ops);
    let read_injected_failures = stats_after_read
        .injected_transient_failures
        .saturating_sub(stats_before_read.injected_transient_failures);

    ensure!(
        read_injected_failures > 0,
        "ChaosStorageRouter MUST inject > 0 transient get_blob failures during cold readback, got 0"
    );

    println!(
        "[PART B][COLD READBACK] Hydrated & verified 2 × 24 MiB (48 MiB cold) in {:.2} ms ({:.2} MiB/s) | read_chaos_ops={} injected_failures={} ({:.1}%) | total_chaos_stats={:?} | sha256={} (100% MATCH)",
        read_secs * 1000.0,
        read_eff_mib_s,
        read_ops,
        read_injected_failures,
        (read_injected_failures as f64 / read_ops.max(1) as f64) * 100.0,
        stats_after_read,
        expected_sha256,
    );

    // 7. Verify `0` corrupted manifests across ALL 3 cloud backends (`cloud-alpha`, `cloud-beta`, `cloud-gamma`)!
    let mut total_verified_manifests = 0usize;
    for (cloud_label, cloud_root) in [
        ("cloud-alpha", &cloud_alpha_dir),
        ("cloud-beta", &cloud_beta_dir),
        ("cloud-gamma", &cloud_gamma_dir),
    ] {
        let zvm_files = collect_files_with_extension(&cloud_root.join("manifests"), "zvm")?;
        for zvm_path in &zvm_files {
            let raw = std::fs::read(zvm_path)?;
            let manifest = crypto.open_manifest(&raw).with_context(|| {
                format!(
                    "corrupted manifest detected on {cloud_label} at {}",
                    zvm_path.display()
                )
            })?;
            let _ = compute_manifest_id(&manifest)?;
            ensure!(
                manifest.revision == 1 && manifest.nodes.len() == 1,
                "unexpected manifest contents on {cloud_label}: rev={}, nodes={}",
                manifest.revision,
                manifest.nodes.len()
            );
            total_verified_manifests += 1;
        }
    }
    ensure!(
        total_verified_manifests >= 4,
        "expected >= 4 replicated .zvm manifest objects across 3 clouds (min_ack=2), found {total_verified_manifests}"
    );

    // 8. Lock & purge cache, verify SQLite WAL integrity, and scan all local & cloud directories
    //    for `0` orphaned partial/plaintext files!
    engine.lock_and_purge_cache().await?;
    let sqlite_snap = inspect_sqlite_wal_integrity(&db_path)?;
    ensure!(
        sqlite_snap.integrity_check == "ok"
            && sqlite_snap.quick_check == "ok"
            && sqlite_snap.foreign_key_violations == 0
            && sqlite_snap.dirty_op_rows == 0,
        "post-chaos SQLite WAL integrity check failed: {sqlite_snap:?}"
    );

    let chaos_canaries: [&[u8]; 2] = [CHAOS_CANARY_ASCII, CHAOS_FILENAME_CANARY_ASCII];
    let mut total_scanned_files = 0usize;
    let mut total_scanned_bytes = 0u64;
    for dir in [
        &state_dir,
        &staging_dir,
        &cloud_alpha_dir,
        &cloud_beta_dir,
        &cloud_gamma_dir,
    ] {
        let scan = scan_tree_for_plaintext_canaries(dir, &chaos_canaries)?;
        ensure!(
            scan.canary_hits.is_empty(),
            "CRITICAL ZERO-KNOWLEDGE VIOLATION in {}: {:?}",
            dir.display(),
            scan.canary_hits
        );
        total_scanned_files += scan.files_scanned;
        total_scanned_bytes += scan.bytes_scanned;
    }

    let proc_rss = sample_current_process_rss().unwrap_or_default();
    println!(
        "[PART B] PASS in {:.2} ms | verified_manifests={} (corrupted=0) | SQLite integrity_check={} | scanned {} files ({} B) -> 0 orphaned plaintext bytes | Harness WorkingSet64={:.3} MiB (Peak={:.3} MiB)",
        suite_start.elapsed().as_secs_f64() * 1000.0,
        total_verified_manifests,
        sqlite_snap.integrity_check,
        total_scanned_files,
        total_scanned_bytes,
        proc_rss.working_set_bytes as f64 / (1024.0 * 1024.0),
        proc_rss.peak_working_set_bytes as f64 / (1024.0 * 1024.0),
    );

    Ok(())
}
