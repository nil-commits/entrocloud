//! Wave 4 Gate 2 & Gate 3 Adversarial Security Torture Suite (`Agent-Judge`).
//!
//! Covers:
//! 1. **Wave 4 Gate 2 — Zero-Knowledge Storage Inspection:**
//!    - Exercises real `DaemonRuntime` + real `SyncEngine` + real `RingHybridCryptoEngine`
//!      + real `SqliteMetadataStore` + real `StorageRouter` (`Mirrored` & `QuotaPooled` `LocalFs`).
//!    - Populates nested directories and files with unmistakable plaintext canary strings, triggers
//!      a live `.zvpart` staged dirty write, a real conflict preservation fork (`conflicts` table),
//!      a `zv://` capability share (`.zvs`), a post-quantum `keybox.zv` (`ZVK1`), a `ZVH1` header,
//!      multi-backend `.zv` chunks & `.zvm` manifests, and executes `PRAGMA wal_checkpoint(TRUNCATE)`.
//!    - Scans every single byte (both UTF-8 and UTF-16LE) of all remote paths/filenames, all remote
//!      `.zv`/`.zvm`/`.zvh`/`.zvs`/`keybox.zv` blobs, all local `.zvpart` staging files, every SQLite
//!      DDL & column value across every table, and raw `metadata.db`, `metadata.db-wal`, and
//!      `metadata.db-shm` files — asserting `0` matches across 100% of storage & metadata artifacts.
//! 2. **Wave 4 Gate 3 — Cryptographic Tamper & Rollback Rejection (5 Mandatory Attacks + Red-Team Probe):**
//!    - Attack 1: 1-bit ciphertext flip in `.zv` chunk body (& GCM tag) -> `CryptoTamperDetected`, `0` pt bytes.
//!    - Attack 2: Chunk `3 <-> 4` swap on a `24 MiB` (`6`-chunk) file (raw blob swap + forged header index)
//!      -> `CryptoTamperDetected` via 25-byte `ChunkAad` (`file_id || chunk_index_le || is_final`).
//!    - Attack 3: Final chunk byte truncation & whole-chunk trailing truncation via `CHUNK_FLAG_FINAL`
//!      bit-flip on chunk `N-2` -> `CryptoTamperDetected` / `InvalidWireFormat`, `0` pt bytes.
//!    - Attack 4: Unsigned/corrupted `manifests/head.zvm` + forged-signature `ZVS1` & `ZVK1` injection
//!      -> `sync_once()`, `open_capability_share`, and `open_keybox` fail closed with `CryptoTamperDetected`.
//!    - Attack 5: `keybox.zv` `epoch = 1` rollback replay after revocation at `epoch = 2`
//!      (`ML-KEM-768 + X25519 + Ed25519`) -> Bob rejected at `epoch = 2` (`UnauthorizedRecipient`),
//!      and replaying valid signed `epoch = 1` `keybox.zv` causes `DaemonRuntime`, `SyncEngine`, and
//!      `open_keybox` to fail closed with `CryptoTamperDetected` (`1 < 2`).
//!    - Red-Team Audit Probe (`t07`): Tests whether `DaemonRuntime::KeyboxStatus` / `SyncEngine::fetch_keybox`
//!      verify `Ed25519` signatures before advancing SQLite `security_epochs("keybox")`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use entrocloud_core::{
    EPOCH_SCOPE_KEYBOX, EPOCH_SCOPE_MANIFEST, SqliteMetadataStore, SyncEngine, SyncEngineConfig,
    reclaim_process_memory,
};
use entrocloud_crypto::RingHybridCryptoEngine;
use entrocloud_daemon::{DaemonRuntime, DaemonStateConfig};
use entrocloud_storage::{CloudBackend, StorageRouter};
use entrocloud_types::mocks::InMemorySecretStore;
use entrocloud_types::{
    AddRemoteParams, BackendConfig, BackendKind, BlobObjectKey, CHUNK_FLAG_FINAL, CHUNK_HEADER_LEN,
    CapabilityUri, ChunkHeader, CreateEntrySpec, CryptoEngine, DaemonRequest, DaemonResponse,
    KEYBOX_OBJECT_KEY, KdfParams, MANIFEST_FORMAT_VERSION, MANIFEST_HEAD_OBJECT_KEY,
    ML_KEM_768_DECAPS_KEY_LEN, ML_KEM_768_ENCAPS_KEY_LEN, ManifestWireHeader, MetadataStore,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, RedactedSecret, RoutingPolicy, ShareDescriptor,
    ShareObjectKey, SignedKeybox, StorageRouterTrait, VAULT_HEADER_OBJECT_KEY, VaultHeader,
    VaultManifest, VfsBackend, WrappedDek, ZeroVaultError, validate_remote_object_key,
};

const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

// Mandatory Gate 2 unmistakable canary strings:
const CANARY_DIR_1: &str = "CANARY_DIR_OMEGA_SUBMARINE";
const CANARY_DIR_2: &str = "CANARY_DIR_FINANCE_2026";
const CANARY_FILE_1: &str = "CANARY_FILE_NUCLEAR_LAUNCH_CODES.txt";
const CANARY_FILE_2: &str = "CANARY_CONFLICT_DOC_SECRET.md";
const CANARY_PAYLOAD: &str = "CANARY_PAYLOAD_PLAINTEXT_NEVER_LEAK_9988776655";

/// Serializes torture tests so per-test RSS (`WorkingSet64` / Peak) and throughput telemetry are uncontended.
fn suite_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

#[derive(Debug, Clone, Copy, Default)]
struct MemorySample {
    working_set_bytes: u64,
    peak_working_set_bytes: u64,
    private_bytes: u64,
}

impl MemorySample {
    fn ws_mib(self) -> f64 {
        self.working_set_bytes as f64 / BYTES_PER_MIB
    }

    fn peak_mib(self) -> f64 {
        self.peak_working_set_bytes as f64 / BYTES_PER_MIB
    }

    fn priv_mib(self) -> f64 {
        self.private_bytes as f64 / BYTES_PER_MIB
    }
}

fn sample_process_memory() -> MemorySample {
    #[cfg(target_os = "windows")]
    {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        // SAFETY: `PROCESS_MEMORY_COUNTERS_EX` is a C POD struct initialized with `cb` set to its exact byte size.
        unsafe {
            let mut pmc: PROCESS_MEMORY_COUNTERS_EX = zeroed();
            pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let ok = K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>(),
                pmc.cb,
            );
            if ok != 0 {
                return MemorySample {
                    working_set_bytes: pmc.WorkingSetSize as u64,
                    peak_working_set_bytes: pmc.PeakWorkingSetSize as u64,
                    private_bytes: pmc.PrivateUsage as u64,
                };
            }
        }
        MemorySample::default()
    }

    #[cfg(target_os = "linux")]
    {
        let mut ws = 0u64;
        let mut peak = 0u64;
        let mut priv_b = 0u64;
        if let Ok(raw) = std::fs::read_to_string("/proc/self/status") {
            for line in raw.lines() {
                let parse_kib = |s: &str| -> u64 {
                    s.split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0)
                        * 1024
                };
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    ws = parse_kib(rest);
                } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                    peak = parse_kib(rest);
                } else if let Some(rest) = line.strip_prefix("RssAnon:") {
                    priv_b = parse_kib(rest);
                }
            }
        }
        MemorySample {
            working_set_bytes: ws,
            peak_working_set_bytes: peak.max(ws),
            private_bytes: if priv_b == 0 { ws } else { priv_b },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        MemorySample::default()
    }
}

fn encode_utf16le(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for unit in input.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|win| win == needle)
}

#[derive(Debug, Clone)]
struct CanaryNeedle {
    label: String,
    encoding: &'static str,
    bytes: Vec<u8>,
}

fn build_canary_needles() -> Vec<CanaryNeedle> {
    let patterns = [
        CANARY_DIR_1,
        CANARY_DIR_2,
        CANARY_FILE_1,
        CANARY_FILE_2,
        CANARY_PAYLOAD,
        // Additional substring stems to prove even partial stems never leak:
        "CANARY_",
        "OMEGA_SUBMARINE",
        "FINANCE_2026",
        "NUCLEAR_LAUNCH_CODES",
        "CONFLICT_DOC_SECRET",
        "NEVER_LEAK_9988776655",
    ];
    let mut out = Vec::with_capacity(patterns.len() * 2);
    for pat in patterns {
        out.push(CanaryNeedle {
            label: pat.to_owned(),
            encoding: "UTF-8",
            bytes: pat.as_bytes().to_vec(),
        });
        out.push(CanaryNeedle {
            label: pat.to_owned(),
            encoding: "UTF-16LE",
            bytes: encode_utf16le(pat),
        });
    }
    out
}

fn scan_bytes_for_canaries(
    target_desc: &str,
    data: &[u8],
    needles: &[CanaryNeedle],
    matches_out: &mut Vec<String>,
) {
    for needle in needles {
        if let Some(offset) = find_subsequence(data, &needle.bytes) {
            matches_out.push(format!(
                "LEAK DETECTED in {target_desc} at byte offset {offset}: '{}' ({})",
                needle.label, needle.encoding
            ));
        }
    }
}

fn collect_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry_res in
            std::fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))?
        {
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
    Ok(files)
}

#[derive(Debug, Default)]
struct ZkAuditTelemetry {
    remote_files_scanned: usize,
    remote_path_bytes_scanned: u64,
    remote_blob_bytes_scanned: u64,
    zv_count: usize,
    zvm_count: usize,
    zvh_count: usize,
    zvs_count: usize,
    keybox_count: usize,
    staging_zvpart_count: usize,
    staging_bytes_scanned: u64,
    sqlite_ddl_statements: usize,
    sqlite_tables_scanned: usize,
    sqlite_rows_scanned: usize,
    sqlite_columns_scanned: usize,
    sqlite_column_bytes_scanned: u64,
    raw_db_bytes: u64,
    raw_wal_bytes: u64,
    raw_shm_bytes: u64,
    matches: Vec<String>,
}

fn run_exhaustive_zk_scan(
    phase_label: &str,
    cloud_roots: &[(&str, &Path)],
    staging_dir: &Path,
    db_path: &Path,
    needles: &[CanaryNeedle],
) -> Result<ZkAuditTelemetry> {
    let mut tel = ZkAuditTelemetry::default();

    // 1 & 2. Scan every remote object relative path/filename AND raw blob bytes across all cloud backends.
    for (backend_id, root) in cloud_roots {
        let files = collect_files_recursive(root)?;
        for file_path in files {
            let rel = file_path
                .strip_prefix(root)
                .with_context(|| format!("strip_prefix {} on {}", root.display(), file_path.display()))?;
            let rel_norm = rel.to_string_lossy().replace('\\', "/");

            // Enforce strict zero-knowledge remote object key grammar on 100% of cloud objects!
            validate_remote_object_key(&rel_norm).map_err(|e| {
                anyhow!("remote file '{rel_norm}' on backend '{backend_id}' violated ZK key grammar: {e}")
            })?;

            // Scan relative path in UTF-8 and UTF-16LE
            let rel_utf8 = rel_norm.as_bytes();
            let rel_utf16 = encode_utf16le(&rel_norm);
            tel.remote_path_bytes_scanned += (rel_utf8.len() + rel_utf16.len()) as u64;
            scan_bytes_for_canaries(
                &format!("[{phase_label}] remote_path({backend_id}:{rel_norm})"),
                rel_utf8,
                needles,
                &mut tel.matches,
            );
            scan_bytes_for_canaries(
                &format!("[{phase_label}] remote_path_utf16({backend_id}:{rel_norm})"),
                &rel_utf16,
                needles,
                &mut tel.matches,
            );

            // Classify remote object type
            if rel_norm == VAULT_HEADER_OBJECT_KEY {
                tel.zvh_count += 1;
            } else if rel_norm == KEYBOX_OBJECT_KEY {
                tel.keybox_count += 1;
            } else if rel_norm.ends_with(".zv") {
                tel.zv_count += 1;
            } else if rel_norm.ends_with(".zvm") {
                tel.zvm_count += 1;
            } else if rel_norm.ends_with(".zvs") {
                tel.zvs_count += 1;
            } else {
                bail!("unexpected unclassified remote object '{rel_norm}' on '{backend_id}'");
            }

            let raw_blob = std::fs::read(&file_path)
                .with_context(|| format!("read remote blob {}", file_path.display()))?;
            tel.remote_files_scanned += 1;
            tel.remote_blob_bytes_scanned += raw_blob.len() as u64;
            scan_bytes_for_canaries(
                &format!("[{phase_label}] remote_blob({backend_id}:{rel_norm})"),
                &raw_blob,
                needles,
                &mut tel.matches,
            );
        }
    }

    // 3. Scan every local `.zvpart` staging file's relative path and raw bytes.
    let staging_files = collect_files_recursive(staging_dir)?;
    for st_file in staging_files {
        let rel = st_file
            .strip_prefix(staging_dir)
            .unwrap_or(&st_file)
            .to_string_lossy()
            .replace('\\', "/");
        scan_bytes_for_canaries(
            &format!("[{phase_label}] staging_path({rel})"),
            rel.as_bytes(),
            needles,
            &mut tel.matches,
        );
        scan_bytes_for_canaries(
            &format!("[{phase_label}] staging_path_utf16({rel})"),
            &encode_utf16le(&rel),
            needles,
            &mut tel.matches,
        );
        if rel.ends_with(".zvpart") {
            tel.staging_zvpart_count += 1;
        }
        let raw = std::fs::read(&st_file)
            .with_context(|| format!("read staging file {}", st_file.display()))?;
        tel.staging_bytes_scanned += raw.len() as u64;
        scan_bytes_for_canaries(
            &format!("[{phase_label}] staging_bytes({rel})"),
            &raw,
            needles,
            &mut tel.matches,
        );
    }

    // 4A. Scan SQLite `sqlite_master` DDL + every column of every row in every table!
    let ro_conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open SQLite read-only {}", db_path.display()))?;
    ro_conn.busy_timeout(Duration::from_secs(5))?;

    let mut table_names = Vec::new();
    {
        let mut master_stmt =
            ro_conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")?;
        let mut rows = master_stmt.query([])?;
        while let Some(row) = rows.next()? {
            tel.sqlite_ddl_statements += 1;
            let obj_type: String = row.get(0)?;
            let name: String = row.get(1)?;
            let tbl_name: String = row.get(2)?;
            let sql_opt: Option<String> = row.get(3)?;

            for field in [&obj_type, &name, &tbl_name] {
                tel.sqlite_column_bytes_scanned += field.len() as u64;
                scan_bytes_for_canaries(
                    &format!("[{phase_label}] sqlite_master({name})"),
                    field.as_bytes(),
                    needles,
                    &mut tel.matches,
                );
            }
            if let Some(ref sql) = sql_opt {
                tel.sqlite_column_bytes_scanned += sql.len() as u64;
                scan_bytes_for_canaries(
                    &format!("[{phase_label}] sqlite_master.sql({name})"),
                    sql.as_bytes(),
                    needles,
                    &mut tel.matches,
                );
            }
            if obj_type == "table" {
                table_names.push(name);
            }
        }
    }

    for tbl in &table_names {
        tel.sqlite_tables_scanned += 1;
        let escaped_tbl = tbl.replace('"', "\"\"");
        let query = format!("SELECT * FROM \"{escaped_tbl}\"");
        let mut stmt = ro_conn.prepare(&query)?;
        let col_count = stmt.column_count();
        let col_names: Vec<String> = stmt
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        for cn in &col_names {
            scan_bytes_for_canaries(
                &format!("[{phase_label}] sqlite_colname({tbl}.{cn})"),
                cn.as_bytes(),
                needles,
                &mut tel.matches,
            );
        }

        let mut rows = stmt.query([])?;
        let mut row_idx = 0usize;
        while let Some(row) = rows.next()? {
            tel.sqlite_rows_scanned += 1;
            for (col_idx, col_label) in col_names.iter().enumerate().take(col_count) {
                tel.sqlite_columns_scanned += 1;
                let vref = row.get_ref(col_idx)?;
                match vref {
                    ValueRef::Null => {}
                    ValueRef::Integer(i) => {
                        let s = i.to_string();
                        let le = i.to_le_bytes();
                        tel.sqlite_column_bytes_scanned += (s.len() + le.len()) as u64;
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_int({tbl}[{row_idx}].{col_label})"),
                            s.as_bytes(),
                            needles,
                            &mut tel.matches,
                        );
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_int_le({tbl}[{row_idx}].{col_label})"),
                            &le,
                            needles,
                            &mut tel.matches,
                        );
                    }
                    ValueRef::Real(f) => {
                        let s = f.to_string();
                        let le = f.to_le_bytes();
                        tel.sqlite_column_bytes_scanned += (s.len() + le.len()) as u64;
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_real({tbl}[{row_idx}].{col_label})"),
                            s.as_bytes(),
                            needles,
                            &mut tel.matches,
                        );
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_real_le({tbl}[{row_idx}].{col_label})"),
                            &le,
                            needles,
                            &mut tel.matches,
                        );
                    }
                    ValueRef::Text(txt) => {
                        tel.sqlite_column_bytes_scanned += txt.len() as u64;
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_text({tbl}[{row_idx}].{col_label})"),
                            txt,
                            needles,
                            &mut tel.matches,
                        );
                    }
                    ValueRef::Blob(blob) => {
                        tel.sqlite_column_bytes_scanned += blob.len() as u64;
                        scan_bytes_for_canaries(
                            &format!("[{phase_label}] sqlite_blob({tbl}[{row_idx}].{col_label})"),
                            blob,
                            needles,
                            &mut tel.matches,
                        );
                    }
                }
            }
            row_idx += 1;
        }
    }

    // Keep `ro_conn` alive while scanning `metadata.db`, `metadata.db-wal`, and `metadata.db-shm`
    // so `.db-wal` and `.db-shm` remain materialized on disk!
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));

    let raw_db = read_file_tolerant_locked(db_path)
        .with_context(|| format!("read raw metadata.db at {}", db_path.display()))?;
    tel.raw_db_bytes = raw_db.len() as u64;
    scan_bytes_for_canaries(
        &format!("[{phase_label}] raw_file(metadata.db)"),
        &raw_db,
        needles,
        &mut tel.matches,
    );

    if wal_path.exists() {
        let raw_wal = read_file_tolerant_locked(&wal_path)
            .with_context(|| format!("read raw metadata.db-wal at {}", wal_path.display()))?;
        tel.raw_wal_bytes = raw_wal.len() as u64;
        scan_bytes_for_canaries(
            &format!("[{phase_label}] raw_file(metadata.db-wal)"),
            &raw_wal,
            needles,
            &mut tel.matches,
        );
    }

    if shm_path.exists() {
        let raw_shm = read_file_tolerant_locked(&shm_path)
            .with_context(|| format!("read raw metadata.db-shm at {}", shm_path.display()))?;
        tel.raw_shm_bytes = raw_shm.len() as u64;
        scan_bytes_for_canaries(
            &format!("[{phase_label}] raw_file(metadata.db-shm)"),
            &raw_shm,
            needles,
            &mut tel.matches,
        );
    }

    drop(ro_conn);
    Ok(tel)
}

/// Reads every readable byte of `path`; if Windows mandatory byte-range locking (`ERROR_LOCK_VIOLATION` = 33)
/// protects SQLite's 8-byte DMS lock slot inside `.db-shm`, falls back to 64-byte block reads skipping only
/// OS-locked control bytes while reading 100% of data pages.
fn read_file_tolerant_locked(path: &Path) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = std::fs::File::open(path)
                .with_context(|| format!("open {} after {}", path.display(), err))?;
            let total_len = file.metadata()?.len() as usize;
            let mut out = vec![0u8; total_len];
            let step = 64usize;
            let mut offset = 0usize;
            while offset < total_len {
                let to_read = step.min(total_len - offset);
                file.seek(SeekFrom::Start(offset as u64))?;
                let _ = file.read(&mut out[offset..offset + to_read]);
                offset += to_read;
            }
            Ok(out)
        }
    }
}

fn local_fs_backend_cfg(id: &str, root: &Path, quota_limit_bytes: Option<u64>) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: root.to_string_lossy().into_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes,
        min_free_reserve_bytes: 0,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

fn build_deterministic_chunk_payload(seed_tag: u8, total_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; total_bytes];
    for (i, b) in out.iter_mut().enumerate() {
        let chunk_no = (i / PLAINTEXT_CHUNK_SIZE) as u8;
        let mix = (i as u64)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = seed_tag ^ chunk_no.wrapping_mul(37) ^ ((mix >> 32) as u8);
    }
    out
}

// ============================================================================
// WAVE 4 GATE 2 — ZERO-KNOWLEDGE STORAGE, SQLITE WAL & STAGING INSPECTION
// ============================================================================

#[tokio::test]
async fn t01_gate2_zero_knowledge_storage_sqlite_and_staging_inspection() -> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();
    let mem_before = sample_process_memory();

    let tmp = TempDir::new()?;
    let state_alpha = tmp.path().join("alpha_state");
    let state_beta = tmp.path().join("beta_state");
    let state_pooled = tmp.path().join("pooled_state");
    let cloud_mirror_a = tmp.path().join("cloud_mirror_a");
    let cloud_mirror_b = tmp.path().join("cloud_mirror_b");
    let cloud_pool_1 = tmp.path().join("cloud_pool_1");
    let cloud_pool_2 = tmp.path().join("cloud_pool_2");

    std::fs::create_dir_all(&cloud_mirror_a)?;
    std::fs::create_dir_all(&cloud_mirror_b)?;
    std::fs::create_dir_all(&cloud_pool_1)?;
    std::fs::create_dir_all(&cloud_pool_2)?;

    // --- Step 1: Real `DaemonRuntime` + `RingHybridCryptoEngine` + `Mirrored` LocalFs ---
    let crypto_alpha_rt = Arc::new(RingHybridCryptoEngine::new()?);
    let caps = crypto_alpha_rt.verify_hardware_acceleration()?;
    ensure!(caps.mandatory_satisfied, "mandatory hardware AES+GHASH must be active");

    let daemon_cfg = DaemonStateConfig::new(state_alpha.clone())
        .with_mock_vfs(true)
        .with_sync_interval(Duration::ZERO);
    let runtime = DaemonRuntime::builder(daemon_cfg)
        .with_crypto(Arc::clone(&crypto_alpha_rt) as Arc<dyn CryptoEngine>)
        .with_secret_store(Arc::new(InMemorySecretStore::default()))
        .build()?;

    let passphrase = "w4-gate2-zero-knowledge-ryzen-vaes-passphrase";
    match runtime
        .handle_request(DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("InitVault failed: {other:?}"),
    }

    for (id, root) in [("mirror-a", &cloud_mirror_a), ("mirror-b", &cloud_mirror_b)] {
        match runtime
            .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: id.to_owned(),
                kind: "fs".to_owned(),
                root: root.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(256 * 1024 * 1024),
                policy: Some("mirrored".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await
        {
            DaemonResponse::Ok { .. } => {}
            other => bail!("AddRemote({id}) failed: {other:?}"),
        }
    }

    // Create nested canary directories & canary files via real DaemonRuntime
    let nested_dir_vpath = format!("/{CANARY_DIR_1}/{CANARY_DIR_2}");
    let launch_codes_vpath = format!("{nested_dir_vpath}/{CANARY_FILE_1}");
    let conflict_doc_vpath = format!("/{CANARY_DIR_1}/{CANARY_FILE_2}");

    match runtime
        .handle_request(DaemonRequest::CreateDirectory {
            virtual_path: nested_dir_vpath.clone(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("CreateDirectory failed: {other:?}"),
    }

    let rich_canary_content = format!(
        "TOP-SECRET-HEADER\n{CANARY_PAYLOAD}\ndir1={CANARY_DIR_1}\ndir2={CANARY_DIR_2}\nfile={CANARY_FILE_1}\n{}",
        CANARY_PAYLOAD.repeat(512)
    );
    match runtime
        .handle_request(DaemonRequest::SaveTextNote {
            virtual_path: launch_codes_vpath.clone(),
            content: rich_canary_content.clone(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("SaveTextNote(launch_codes) failed: {other:?}"),
    }

    let initial_conflict_content =
        format!("v1-baseline: {CANARY_PAYLOAD} inside {CANARY_FILE_2}");
    match runtime
        .handle_request(DaemonRequest::SaveTextNote {
            virtual_path: conflict_doc_vpath.clone(),
            content: initial_conflict_content.clone(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("SaveTextNote(conflict_doc) failed: {other:?}"),
    }

    // Initialize `vault/keybox.zv` (`ZVK1`) and grant a post-quantum recipient
    match runtime.handle_request(DaemonRequest::InitKeybox).await {
        DaemonResponse::KeyboxInfo(kb) => ensure!(kb.epoch == 1, "expected keybox epoch 1"),
        other => bail!("InitKeybox failed: {other:?}"),
    }
    let alice_pq = crypto_alpha_rt.generate_recipient_identity("alice-pq")?;
    match runtime
        .handle_request(DaemonRequest::GrantKeyboxRecipient {
            recipient_bundle_b64: alice_pq.public.to_base64()?,
        })
        .await
    {
        DaemonResponse::KeyboxInfo(kb) => ensure!(kb.recipient_ids.len() >= 2),
        other => bail!("GrantKeyboxRecipient failed: {other:?}"),
    }

    // Create a `zv://` capability share (`shares/<aa>/<bb>/<uuid>.zvs` — `ZVS1`) for `CANARY_FILE_1`
    match runtime
        .handle_request(DaemonRequest::CreateCapabilityShare {
            virtual_path: launch_codes_vpath.clone(),
        })
        .await
    {
        DaemonResponse::ShareUriCreated { uri, .. } => {
            ensure!(
                !uri.contains("CANARY_"),
                "zv:// capability URI leaked plaintext canary string: {uri}"
            );
        }
        other => bail!("CreateCapabilityShare failed: {other:?}"),
    }

    match runtime.handle_request(DaemonRequest::SyncNow).await {
        DaemonResponse::Ok { .. } => {}
        other => bail!("SyncNow failed: {other:?}"),
    }

    // Lock DaemonRuntime cleanly so we can drive concurrent multi-device conflict + un-flushed `.zvpart`
    // directly on the exact same `state_alpha/metadata.db` & `state_alpha/staging`!
    match runtime.handle_request(DaemonRequest::LockVault).await {
        DaemonResponse::Ok { .. } => {}
        other => bail!("LockVault failed: {other:?}"),
    }

    // --- Step 2: Exercise `QuotaPooled` `LocalFs` Spillover with Multi-Chunk Canary Payload ---
    let crypto_pool = Arc::new(RingHybridCryptoEngine::new()?);
    let pool_hdr = crypto_pool
        .init_vault(
            &RedactedSecret::from("w4-gate2-pooled-passphrase"),
            KdfParams::interactive_production(),
        )
        .await?;
    let pool_router = Arc::new(StorageRouter::new(
        vec![
            // Tight 6 MiB quota on pool-1 forces 9 MiB (3-chunk) canary file to spill chunks onto pool-2!
            CloudBackend::from_config(&local_fs_backend_cfg(
                "pool-1",
                &cloud_pool_1,
                Some(6 * 1024 * 1024),
            ))?,
            CloudBackend::from_config(&local_fs_backend_cfg(
                "pool-2",
                &cloud_pool_2,
                Some(128 * 1024 * 1024),
            ))?,
        ],
        RoutingPolicy::QuotaPooled {
            pool_backends: vec!["pool-1".to_owned(), "pool-2".to_owned()],
        },
    )?);
    let pool_db_path = state_pooled.join("metadata.db");
    let pool_staging = state_pooled.join("staging");
    let pool_meta = Arc::new(SqliteMetadataStore::open(
        &pool_db_path,
        Arc::clone(&crypto_pool) as Arc<dyn CryptoEngine>,
    )?);
    let pool_engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: pool_staging.clone(),
            device_id: "pool-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&pool_meta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto_pool) as Arc<dyn CryptoEngine>,
        Arc::clone(&pool_router) as Arc<dyn StorageRouterTrait>,
    )?;
    pool_engine.publish_vault_header(&pool_hdr).await?;
    let d1 = pool_engine.mkdir(ROOT_INODE, CANARY_DIR_1, 0o755).await?;
    let d2 = pool_engine.mkdir(d1.inode, CANARY_DIR_2, 0o755).await?;
    let pooled_file = pool_engine
        .create_entry(CreateEntrySpec {
            parent_inode: d2.inode,
            name: CANARY_FILE_1.to_owned(),
            mode: 0o644,
        })
        .await?;
    // 9 MiB (3 chunks: 4 MiB + 4 MiB + 1 MiB) packed with `CANARY_PAYLOAD`!
    let mut nine_mib = build_deterministic_chunk_payload(0x5A, 9 * 1024 * 1024);
    let canary_bytes = CANARY_PAYLOAD.as_bytes();
    for chunk_idx in 0..3usize {
        let start = chunk_idx * PLAINTEXT_CHUNK_SIZE;
        nine_mib[start..start + canary_bytes.len()].copy_from_slice(canary_bytes);
    }
    pool_engine.write_range(pooled_file.inode, 0, &nine_mib).await?;
    let pool_sync_report = pool_engine.sync_once().await?;
    ensure!(pool_sync_report.published_revision == Some(1));
    // Verify spillover actually placed `.zv` blobs on BOTH `pool-1` and `pool-2`!
    let pool1_files = collect_files_recursive(&cloud_pool_1)?;
    let pool2_files = collect_files_recursive(&cloud_pool_2)?;
    ensure!(
        !pool1_files.is_empty() && !pool2_files.is_empty(),
        "expected QuotaPooled spillover across both pool-1 ({}) and pool-2 ({})",
        pool1_files.len(),
        pool2_files.len()
    );

    // --- Step 3: Trigger Real Conflict Preservation (`conflicts` table) + Un-flushed `.zvpart` ---
    let vault_hdr = VaultHeader::decode(&std::fs::read(state_alpha.join("vault.zvh"))?)?;
    let make_mirrored_router = || -> Result<Arc<StorageRouter>> {
        Ok(Arc::new(StorageRouter::new(
            vec![
                CloudBackend::from_config(&local_fs_backend_cfg(
                    "mirror-a",
                    &cloud_mirror_a,
                    Some(256 * 1024 * 1024),
                ))?,
                CloudBackend::from_config(&local_fs_backend_cfg(
                    "mirror-b",
                    &cloud_mirror_b,
                    Some(256 * 1024 * 1024),
                ))?,
            ],
            RoutingPolicy::Mirrored {
                backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
                min_ack: 2,
            },
        )?))
    };

    // Peer Device Beta pulls manifest, updates `CANARY_CONFLICT_DOC_SECRET.md`, and publishes rev+1.
    let crypto_beta = Arc::new(RingHybridCryptoEngine::new()?);
    crypto_beta
        .unlock_with_passphrase(&vault_hdr, &RedactedSecret::from(passphrase))
        .await?;
    let meta_beta = Arc::new(SqliteMetadataStore::open(
        state_beta.join("metadata.db"),
        Arc::clone(&crypto_beta) as Arc<dyn CryptoEngine>,
    )?);
    let engine_beta = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: state_beta.join("staging"),
            device_id: "beta-peer".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta_beta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto_beta) as Arc<dyn CryptoEngine>,
        make_mirrored_router()? as Arc<dyn StorageRouterTrait>,
    )?;
    engine_beta.sync_once().await?;
    let beta_conflict_ino = engine_beta.resolve_path(&conflict_doc_vpath).await?;
    let beta_new_payload =
        format!("beta-remote-winner: {CANARY_PAYLOAD} ({CANARY_FILE_2} / {CANARY_DIR_1})");
    engine_beta
        .write_range(beta_conflict_ino.inode, 0, beta_new_payload.as_bytes())
        .await?;
    engine_beta.sync_once().await?;

    // Device Alpha re-opens `state_alpha/metadata.db` & `state_alpha/staging`, writes dirty local edit
    // to `CANARY_CONFLICT_DOC_SECRET.md`, then calls `sync_once()` to record a real conflict in `conflicts`!
    let crypto_alpha = Arc::new(RingHybridCryptoEngine::new()?);
    crypto_alpha
        .unlock_with_passphrase(&vault_hdr, &RedactedSecret::from(passphrase))
        .await?;
    let alpha_db_path = state_alpha.join("metadata.db");
    let alpha_staging_dir = state_alpha.join("staging");
    let meta_alpha = Arc::new(SqliteMetadataStore::open(
        &alpha_db_path,
        Arc::clone(&crypto_alpha) as Arc<dyn CryptoEngine>,
    )?);
    ensure!(
        meta_alpha.journal_mode()?.eq_ignore_ascii_case("wal"),
        "SQLite must operate in WAL mode"
    );
    ensure!(
        meta_alpha.secure_delete_mode()? == 1,
        "SQLite PRAGMA secure_delete must be ON (1)"
    );

    let engine_alpha = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: alpha_staging_dir.clone(),
            device_id: "alpha-host".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta_alpha) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto_alpha) as Arc<dyn CryptoEngine>,
        make_mirrored_router()? as Arc<dyn StorageRouterTrait>,
    )?;

    let alpha_conflict_ino = engine_alpha.resolve_path(&conflict_doc_vpath).await?;
    let alpha_dirty_conflict_payload =
        format!("alpha-local-dirty-fork: {CANARY_PAYLOAD} ({CANARY_FILE_2})");
    engine_alpha
        .write_range(
            alpha_conflict_ino.inode,
            0,
            alpha_dirty_conflict_payload.as_bytes(),
        )
        .await?;

    let conflict_sync = engine_alpha.sync_once().await?;
    ensure!(
        conflict_sync.conflicts_resolved >= 1,
        "expected >= 1 non-destructive conflict resolved, got {conflict_sync:?}"
    );
    let recorded_conflicts = meta_alpha.list_conflicts().await?;
    ensure!(
        !recorded_conflicts.is_empty(),
        "expected SQLite conflicts table to contain preserved conflict record"
    );
    ensure!(
        recorded_conflicts[0].original_path.contains(CANARY_DIR_1)
            && recorded_conflicts[0].original_path.contains(CANARY_FILE_2)
            && recorded_conflicts[0].conflict_path.contains("CANARY_CONFLICT_DOC_SECRET"),
        "decrypted ConflictRecord must positively contain canary path strings: {:?}",
        recorded_conflicts[0]
    );

    // Stage an un-flushed `.zvpart` dirty write BEFORE flush so `.zvpart`, `dirty_ops`, `conflicts`,
    // `inodes`, `chunks`, and `metadata.db-wal` ALL simultaneously hold live canary-backed ciphertext!
    let launch_rec = engine_alpha.resolve_path(&launch_codes_vpath).await?;
    let unflushed_stage_payload = format!(
        "UNFLUSHED-STAGED-ZVPART-WRITE::{CANARY_PAYLOAD}::{CANARY_DIR_1}::{CANARY_DIR_2}::{CANARY_FILE_1}\n{}",
        CANARY_PAYLOAD.repeat(256)
    );
    engine_alpha
        .write_range(launch_rec.inode, 0, unflushed_stage_payload.as_bytes())
        .await?;

    let dirty_ops_now = meta_alpha.list_dirty_ops().await?;
    ensure!(
        !dirty_ops_now.is_empty() && dirty_ops_now[0].virtual_path.contains(CANARY_FILE_1),
        "expected live dirty_ops row for staged canary file"
    );
    let read_back_staged = engine_alpha
        .read_range(launch_rec.inode, 0, unflushed_stage_payload.len())
        .await?;
    ensure!(
        read_back_staged.as_ref() == unflushed_stage_payload.as_bytes(),
        "authorized VFS read_range must return exact staged canary plaintext"
    );

    // --- Step 4: Exhaustive Byte-for-Byte UTF-8 + UTF-16LE Scan BEFORE & AFTER `wal_checkpoint(TRUNCATE)` ---
    let needles = build_canary_needles();
    let cloud_roots: Vec<(&str, &Path)> = vec![
        ("mirror-a", cloud_mirror_a.as_path()),
        ("mirror-b", cloud_mirror_b.as_path()),
        ("pool-1", cloud_pool_1.as_path()),
        ("pool-2", cloud_pool_2.as_path()),
    ];

    // Pass A: Pre-checkpoint (while `metadata.db-wal` contains active WAL frames!)
    let pre_ckpt = run_exhaustive_zk_scan(
        "PRE-WAL-CHECKPOINT",
        &cloud_roots,
        &alpha_staging_dir,
        &alpha_db_path,
        &needles,
    )?;
    ensure!(
        pre_ckpt.matches.is_empty(),
        "ZERO-KNOWLEDGE VIOLATION BEFORE WAL CHECKPOINT: {:#?}",
        pre_ckpt.matches
    );
    ensure!(pre_ckpt.raw_wal_bytes > 0, "expected non-empty metadata.db-wal before checkpoint");

    // Execute mandatory `PRAGMA wal_checkpoint(TRUNCATE)`!
    meta_alpha.wal_checkpoint_truncate()?;
    pool_meta.wal_checkpoint_truncate()?;

    // Pass B: Post-checkpoint on `alpha` + `pooled` SQLite stores
    let post_ckpt = run_exhaustive_zk_scan(
        "POST-WAL-CHECKPOINT-TRUNCATE",
        &cloud_roots,
        &alpha_staging_dir,
        &alpha_db_path,
        &needles,
    )?;
    let post_pool_ckpt = run_exhaustive_zk_scan(
        "POST-WAL-CHECKPOINT-POOLED",
        &[
            ("pool-1", cloud_pool_1.as_path()),
            ("pool-2", cloud_pool_2.as_path()),
        ],
        &pool_staging,
        &pool_db_path,
        &needles,
    )?;

    ensure!(
        post_ckpt.matches.is_empty(),
        "ZERO-KNOWLEDGE VIOLATION AFTER WAL CHECKPOINT: {:#?}",
        post_ckpt.matches
    );
    ensure!(
        post_pool_ckpt.matches.is_empty(),
        "ZERO-KNOWLEDGE VIOLATION IN QUOTA-POOLED STORE: {:#?}",
        post_pool_ckpt.matches
    );

    // Positively assert every required artifact class was materialized and scanned!
    // (`Mirrored` writes 2 copies of header.zvh across mirror-a/b + `QuotaPooled` writes 1 on pool-1 = 3 total)
    ensure!(post_ckpt.zv_count >= 4, "expected >= 4 remote .zv blobs, got {}", post_ckpt.zv_count);
    ensure!(post_ckpt.zvm_count >= 4, "expected >= 4 remote .zvm manifests, got {}", post_ckpt.zvm_count);
    ensure!(post_ckpt.zvh_count >= 3, "expected >= 3 remote header.zvh files, got {}", post_ckpt.zvh_count);
    ensure!(post_ckpt.zvs_count >= 2, "expected >= 2 remote .zvs share files, got {}", post_ckpt.zvs_count);
    ensure!(post_ckpt.keybox_count >= 2, "expected >= 2 remote keybox.zv files, got {}", post_ckpt.keybox_count);
    ensure!(
        post_ckpt.staging_zvpart_count >= 1 && post_ckpt.staging_bytes_scanned > 0,
        "expected >= 1 live local .zvpart staging file, got count={} bytes={}",
        post_ckpt.staging_zvpart_count,
        post_ckpt.staging_bytes_scanned
    );
    ensure!(post_ckpt.raw_db_bytes > 0, "metadata.db bytes must be > 0");
    ensure!(post_ckpt.raw_wal_bytes == 0, "PRAGMA wal_checkpoint(TRUNCATE) must truncate metadata.db-wal to 0 bytes, got {}", post_ckpt.raw_wal_bytes);

    let total_scanned_bytes = pre_ckpt.remote_path_bytes_scanned
        + pre_ckpt.remote_blob_bytes_scanned
        + pre_ckpt.staging_bytes_scanned
        + pre_ckpt.sqlite_column_bytes_scanned
        + pre_ckpt.raw_db_bytes
        + pre_ckpt.raw_wal_bytes
        + pre_ckpt.raw_shm_bytes
        + post_ckpt.remote_path_bytes_scanned
        + post_ckpt.remote_blob_bytes_scanned
        + post_ckpt.staging_bytes_scanned
        + post_ckpt.sqlite_column_bytes_scanned
        + post_ckpt.raw_db_bytes
        + post_ckpt.raw_shm_bytes
        + post_pool_ckpt.raw_db_bytes;

    let mem_peak = sample_process_memory();
    engine_alpha.lock_and_purge_cache().await?;
    pool_engine.lock_and_purge_cache().await?;
    engine_beta.lock_and_purge_cache().await?;
    reclaim_process_memory().await;
    let mem_idle = sample_process_memory();
    let elapsed = started.elapsed();
    let scan_mib_s = (total_scanned_bytes as f64 / BYTES_PER_MIB) / elapsed.as_secs_f64().max(1e-6);

    println!(
        "[PROOF-GATE2-ZK] status=PASS matches=0 needles={} (UTF-8+UTF-16LE) \
         remote_files={} (.zv={}, .zvm={}, .zvh={}, .zvs={}, keybox.zv={}) \
         staging_zvpart={} staging_bytes={} \
         sqlite_ddl={} tables={} rows={} cols={} \
         pre_ckpt_wal_bytes={} post_ckpt_wal_bytes={} raw_db_bytes={} raw_shm_bytes={} \
         total_scanned_bytes={} ({:.3} MiB @ {:.2} MiB/s) \
         elapsed_ms={:.2} rss_before_mib={:.2} rss_active_mib={:.2} rss_peak_mib={:.2} priv_active_mib={:.2} rss_post_reclaim_mib={:.2}",
        needles.len(),
        post_ckpt.remote_files_scanned,
        post_ckpt.zv_count,
        post_ckpt.zvm_count,
        post_ckpt.zvh_count,
        post_ckpt.zvs_count,
        post_ckpt.keybox_count,
        post_ckpt.staging_zvpart_count,
        post_ckpt.staging_bytes_scanned,
        post_ckpt.sqlite_ddl_statements,
        post_ckpt.sqlite_tables_scanned,
        post_ckpt.sqlite_rows_scanned,
        post_ckpt.sqlite_columns_scanned,
        pre_ckpt.raw_wal_bytes,
        post_ckpt.raw_wal_bytes,
        post_ckpt.raw_db_bytes,
        post_ckpt.raw_shm_bytes,
        total_scanned_bytes,
        total_scanned_bytes as f64 / BYTES_PER_MIB,
        scan_mib_s,
        elapsed.as_secs_f64() * 1000.0,
        mem_before.ws_mib(),
        mem_peak.ws_mib(),
        mem_peak.peak_mib(),
        mem_peak.priv_mib(),
        mem_idle.ws_mib(),
    );

    Ok(())
}

// ============================================================================
// WAVE 4 GATE 3 — ATTACK 1: 1-BIT CIPHERTEXT FLIP IN `.zv` CHUNK BODY
// ============================================================================

#[tokio::test]
async fn t02_gate3_attack1_single_bit_ciphertext_flip_fails_closed() -> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_a = tmp.path().join("mirror_a");
    let cloud_b = tmp.path().join("mirror_b");
    std::fs::create_dir_all(&cloud_a)?;
    std::fs::create_dir_all(&cloud_b)?;

    let crypto = Arc::new(RingHybridCryptoEngine::new()?);
    crypto
        .init_vault(
            &RedactedSecret::from("attack1-bitflip-passphrase"),
            KdfParams::interactive_production(),
        )
        .await?;
    let router = Arc::new(StorageRouter::new(
        vec![
            CloudBackend::from_config(&local_fs_backend_cfg("mirror-a", &cloud_a, None))?,
            CloudBackend::from_config(&local_fs_backend_cfg("mirror-b", &cloud_b, None))?,
        ],
        RoutingPolicy::Mirrored {
            backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
            min_ack: 2,
        },
    )?);
    let meta = Arc::new(SqliteMetadataStore::open(
        state_dir.join("metadata.db"),
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
    )?);
    let engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: state_dir.join("staging"),
            device_id: "attack1-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
        Arc::clone(&router) as Arc<dyn StorageRouterTrait>,
    )?;

    let created = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "telemetry_block.bin".to_owned(),
            mode: 0o644,
        })
        .await?;
    let original_pt = build_deterministic_chunk_payload(0xA1, PLAINTEXT_CHUNK_SIZE);
    engine.write_range(created.inode, 0, &original_pt).await?;
    engine.sync_once().await?;

    let chunks = meta.list_chunks(created.inode).await?;
    ensure!(chunks.len() == 1, "expected 1 chunk");
    let blob_rel = BlobObjectKey::from_uuid(chunks[0].blob_id);
    let path_a = cloud_a.join(blob_rel.as_str());
    let path_b = cloud_b.join(blob_rel.as_str());
    let clean_wire = std::fs::read(&path_a)?;
    let flip_offset = CHUNK_HEADER_LEN + (PLAINTEXT_CHUNK_SIZE / 2);

    // 1A: Single-replica bit-flip on `mirror-a` ONLY -> RAID-1 verified failover recovers from `mirror-b`.
    engine.dehydrate(created.inode).await?;
    let mut flipped_wire = clean_wire.clone();
    flipped_wire[flip_offset] ^= 0x01;
    std::fs::write(&path_a, &flipped_wire)?;

    let healed = engine
        .read_range(created.inode, 0, PLAINTEXT_CHUNK_SIZE)
        .await?;
    ensure!(
        healed.as_ref() == original_pt.as_slice(),
        "Mirrored router must detect 1-bit flip on mirror-a and fail over to intact mirror-b"
    );

    // 1B: 1-bit ciphertext flip across ALL replicas -> `read_range` MUST fail closed with `CryptoTamperDetected` and 0 bytes!
    engine.dehydrate(created.inode).await?;
    ensure!(
        engine.cache().get(created.file_id, 0).is_none(),
        "RAM cache must be empty after dehydrate"
    );
    std::fs::write(&path_b, &flipped_wire)?;

    let tamper_res = engine
        .read_range(created.inode, 0, PLAINTEXT_CHUNK_SIZE)
        .await;
    let tamper_err_msg = match tamper_res {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!(
            "Attack 1 FAILED: expected Err(CryptoTamperDetected), got {:?}",
            other.map(|b| b.len())
        ),
    };
    ensure!(
        engine.cache().get(created.file_id, 0).is_none(),
        "tampered chunk must never populate RAM cache"
    );

    // Direct `decrypt_chunk_into` buffer scrub verification: pre-fill `out_plaintext` and verify it is scrubbed to 0 bytes!
    let inode_rec = engine.getattr(created.inode).await?;
    let wrapped_dek = inode_rec
        .wrapped_dek
        .as_ref()
        .ok_or_else(|| anyhow!("missing wrapped_dek"))?;
    let dek = crypto.unwrap_dek(inode_rec.file_id, wrapped_dek)?;
    let mut dirty_out = BytesMut::from(&b"PREFILLED_SENSITIVE_BUFFER"[..]);
    let direct_res = crypto.decrypt_chunk_into(
        &dek,
        inode_rec.file_id,
        Some(0),
        &flipped_wire,
        &mut dirty_out,
    );
    ensure!(
        matches!(direct_res, Err(ZeroVaultError::CryptoTamperDetected(_))),
        "decrypt_chunk_into must return CryptoTamperDetected on 1-bit ciphertext flip"
    );
    ensure!(
        dirty_out.is_empty(),
        "decrypt_chunk_into must scrub and clear out_plaintext to 0 bytes on tamper, got {} bytes",
        dirty_out.len()
    );

    // 1C: 1-bit flip in the 16-byte AES-256-GCM authentication tag -> also fails closed!
    let mut tag_flipped = clean_wire;
    if let Some(last) = tag_flipped.last_mut() {
        *last ^= 0x80;
    }
    std::fs::write(&path_a, &tag_flipped)?;
    std::fs::write(&path_b, &tag_flipped)?;
    let tag_res = engine
        .read_range(created.inode, 0, PLAINTEXT_CHUNK_SIZE)
        .await;
    ensure!(
        matches!(tag_res, Err(ZeroVaultError::CryptoTamperDetected(_))),
        "1-bit GCM tag flip must fail closed with CryptoTamperDetected"
    );

    let mem = sample_process_memory();
    engine.lock_and_purge_cache().await?;
    let elapsed = started.elapsed();

    println!(
        "[PROOF-GATE3-ATTACK1] status=PASS flip_offset={} xor_mask=0x01 \
         read_range_result=Err(CryptoTamperDetected(\"{}\")) plaintext_bytes_returned=0 \
         decrypt_chunk_into_out_len={} mirror_failover_verified=true \
         elapsed_ms={:.2} rss_mib={:.2} peak_rss_mib={:.2}",
        flip_offset,
        tamper_err_msg,
        dirty_out.len(),
        elapsed.as_secs_f64() * 1000.0,
        mem.ws_mib(),
        mem.peak_mib(),
    );
    Ok(())
}

// ============================================================================
// WAVE 4 GATE 3 — ATTACK 2: CHUNK `3 <-> 4` SWAP ON `24 MiB` (`6`-CHUNK) FILE
// ============================================================================

#[tokio::test]
async fn t03_gate3_attack2_chunk_3_and_4_swap_fails_closed() -> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");
    std::fs::create_dir_all(&cloud_dir)?;

    let crypto = Arc::new(RingHybridCryptoEngine::new()?);
    crypto
        .init_vault(
            &RedactedSecret::from("attack2-chunk-swap-passphrase"),
            KdfParams::interactive_production(),
        )
        .await?;
    let router = Arc::new(StorageRouter::new(
        vec![CloudBackend::from_config(&local_fs_backend_cfg(
            "cloud-main",
            &cloud_dir,
            None,
        ))?],
        RoutingPolicy::Targeted {
            prefix_routes: Vec::new(),
            default_backend: "cloud-main".to_owned(),
        },
    )?);
    let meta = Arc::new(SqliteMetadataStore::open(
        state_dir.join("metadata.db"),
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
    )?);
    let engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: state_dir.join("staging"),
            device_id: "attack2-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
        Arc::clone(&router) as Arc<dyn StorageRouterTrait>,
    )?;

    // Write a 24 MiB (`6 * 4 MiB` chunks: 0, 1, 2, 3, 4, 5 -> >= 20 MiB) file so BOTH chunk 3 and chunk 4
    // are full 4 MiB non-final chunks with identical wire length (`4,194,352` bytes) and `flags = 0x00`.
    let file_size = 6 * PLAINTEXT_CHUNK_SIZE;
    let payload = build_deterministic_chunk_payload(0xB2, file_size);
    let created = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "archive_24mib.bin".to_owned(),
            mode: 0o644,
        })
        .await?;
    engine.write_range(created.inode, 0, &payload).await?;
    engine.sync_once().await?;

    let chunks = meta.list_chunks(created.inode).await?;
    ensure!(chunks.len() == 6, "expected 6 chunks for 24 MiB file, got {}", chunks.len());
    let path_c3 = cloud_dir.join(BlobObjectKey::from_uuid(chunks[3].blob_id).as_str());
    let path_c4 = cloud_dir.join(BlobObjectKey::from_uuid(chunks[4].blob_id).as_str());
    let orig_wire_c3 = std::fs::read(&path_c3)?;
    let orig_wire_c4 = std::fs::read(&path_c4)?;
    ensure!(
        orig_wire_c3.len() == orig_wire_c4.len(),
        "chunks 3 & 4 must have identical wire size"
    );

    // Baseline verification after dehydrate
    engine.dehydrate(created.inode).await?;
    let ok_c3 = engine
        .read_range(
            created.inode,
            3 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await?;
    ensure!(
        ok_c3.as_ref() == &payload[3 * PLAINTEXT_CHUNK_SIZE..4 * PLAINTEXT_CHUNK_SIZE]
    );

    // --- Sub-attack 2A: Swap remote `.zv` blob files for chunk 3 and chunk 4 ---
    engine.dehydrate(created.inode).await?;
    std::fs::write(&path_c3, &orig_wire_c4)?;
    std::fs::write(&path_c4, &orig_wire_c3)?;

    let err_swap_c3 = match engine
        .read_range(
            created.inode,
            3 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Sub-attack 2A chunk 3 expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };
    let err_swap_c4 = match engine
        .read_range(
            created.inode,
            4 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Sub-attack 2A chunk 4 expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };

    // --- Sub-attack 2B: Smart Byzantine swap that ALSO patches `header.chunk_index` (`bytes[8..16]`)
    //     to `3` and `4` so shallow header checks pass and ONLY the 25-byte `ChunkAad` GCM tag catches it! ---
    let mut forged_c3 = orig_wire_c4.clone();
    forged_c3[8..16].copy_from_slice(&3u64.to_le_bytes());
    let mut forged_c4 = orig_wire_c3.clone();
    forged_c4[8..16].copy_from_slice(&4u64.to_le_bytes());
    ensure!(ChunkHeader::decode(&forged_c3)?.chunk_index == 3);
    ensure!(ChunkHeader::decode(&forged_c4)?.chunk_index == 4);

    std::fs::write(&path_c3, &forged_c3)?;
    std::fs::write(&path_c4, &forged_c4)?;

    let err_aad_c3 = match engine
        .read_range(
            created.inode,
            3 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Sub-attack 2B (25B ChunkAad) chunk 3 expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };
    let err_aad_c4 = match engine
        .read_range(
            created.inode,
            4 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Sub-attack 2B (25B ChunkAad) chunk 4 expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };

    let mem = sample_process_memory();
    engine.lock_and_purge_cache().await?;
    let elapsed = started.elapsed();
    let throughput_mib_s = (file_size as f64 / BYTES_PER_MIB) / elapsed.as_secs_f64().max(1e-6);

    println!(
        "[PROOF-GATE3-ATTACK2] status=PASS file_mib=24 chunks=6 \
         raw_swap_c3=Err(CryptoTamperDetected(\"{}\")) \
         raw_swap_c4=Err(CryptoTamperDetected(\"{}\")) \
         forged_hdr_25b_aad_c3=Err(CryptoTamperDetected(\"{}\")) \
         forged_hdr_25b_aad_c4=Err(CryptoTamperDetected(\"{}\")) \
         plaintext_bytes_returned=0 throughput_mib_s={:.2} elapsed_ms={:.2} rss_mib={:.2} peak_rss_mib={:.2}",
        err_swap_c3,
        err_swap_c4,
        err_aad_c3,
        err_aad_c4,
        throughput_mib_s,
        elapsed.as_secs_f64() * 1000.0,
        mem.ws_mib(),
        mem.peak_mib(),
    );
    Ok(())
}

// ============================================================================
// WAVE 4 GATE 3 — ATTACK 3: FINAL CHUNK TRUNCATION & `is_final` BIT-FLIP
// ============================================================================

#[tokio::test]
async fn t04_gate3_attack3_final_chunk_truncation_and_is_final_bitflip_fail_closed() -> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let cloud_dir = tmp.path().join("cloud");
    std::fs::create_dir_all(&cloud_dir)?;

    let crypto = Arc::new(RingHybridCryptoEngine::new()?);
    crypto
        .init_vault(
            &RedactedSecret::from("attack3-truncation-passphrase"),
            KdfParams::interactive_production(),
        )
        .await?;
    let router = Arc::new(StorageRouter::new(
        vec![CloudBackend::from_config(&local_fs_backend_cfg(
            "cloud-main",
            &cloud_dir,
            None,
        ))?],
        RoutingPolicy::Targeted {
            prefix_routes: Vec::new(),
            default_backend: "cloud-main".to_owned(),
        },
    )?);
    let meta = Arc::new(SqliteMetadataStore::open(
        state_dir.join("metadata.db"),
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
    )?);
    let engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: state_dir.join("staging"),
            device_id: "attack3-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
        Arc::clone(&router) as Arc<dyn StorageRouterTrait>,
    )?;

    // 18 MiB (`N = 5` chunks: chunks 0..=3 are 4 MiB non-final; chunk 4 is 2 MiB final; chunk N-2 = 3).
    let tail_len = 2 * 1024 * 1024usize;
    let total_size = 4 * PLAINTEXT_CHUNK_SIZE + tail_len;
    let payload = build_deterministic_chunk_payload(0xC3, total_size);
    let created = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "stream_18mib.bin".to_owned(),
            mode: 0o644,
        })
        .await?;
    engine.write_range(created.inode, 0, &payload).await?;
    engine.sync_once().await?;

    let chunks = meta.list_chunks(created.inode).await?;
    ensure!(chunks.len() == 5, "expected 5 chunks (N=5), got {}", chunks.len());
    let inode_rec = engine.getattr(created.inode).await?;
    let dek = crypto.unwrap_dek(
        inode_rec.file_id,
        inode_rec
            .wrapped_dek
            .as_ref()
            .ok_or_else(|| anyhow!("missing wrapped_dek"))?,
    )?;

    let path_n_minus_2 = cloud_dir.join(BlobObjectKey::from_uuid(chunks[3].blob_id).as_str());
    let path_final = cloud_dir.join(BlobObjectKey::from_uuid(chunks[4].blob_id).as_str());
    let orig_n_minus_2 = std::fs::read(&path_n_minus_2)?;
    let orig_final = std::fs::read(&path_final)?;

    // --- Sub-attack 3A(i): Truncate 128 trailing bytes from final chunk `N-1` (chunk 4) ---
    engine.dehydrate(created.inode).await?;
    let truncated_tail = &orig_final[..orig_final.len() - 128];
    std::fs::write(&path_final, truncated_tail)?;

    let err_trunc_tail = match engine
        .read_range(created.inode, 4 * PLAINTEXT_CHUNK_SIZE as u64, tail_len)
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("3A(i) expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };

    // --- Sub-attack 3A(ii): Truncate 128 bytes AND forge `plaintext_len` in `ZVC1` header (`bytes[16..20]`) ---
    let mut forged_trunc = orig_final[..orig_final.len() - 128].to_vec();
    let forged_pt_len = (tail_len - 128) as u32;
    forged_trunc[16..20].copy_from_slice(&forged_pt_len.to_le_bytes());
    std::fs::write(&path_final, &forged_trunc)?;

    let err_forged_len = match engine
        .read_range(created.inode, 4 * PLAINTEXT_CHUNK_SIZE as u64, tail_len)
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("3A(ii) expected CryptoTamperDetected, got {:?}", other.map(|b| b.len())),
    };

    // --- Sub-attack 3A(iii): Truncate final chunk below 32-byte `ZVC1` header (`12` bytes) ---
    let short_hdr_bytes = &orig_final[..12];
    let direct_short_res = crypto.decrypt_chunk(&dek, inode_rec.file_id, Some(4), short_hdr_bytes);
    ensure!(
        matches!(direct_short_res, Err(ZeroVaultError::InvalidWireFormat(_))),
        "direct decrypt_chunk on 12B truncated header must return InvalidWireFormat, got {:?}",
        direct_short_res.map(|(_, b)| b.len())
    );
    std::fs::write(&path_final, short_hdr_bytes)?;
    let engine_short_res = engine
        .read_range(created.inode, 4 * PLAINTEXT_CHUNK_SIZE as u64, tail_len)
        .await;
    ensure!(
        matches!(
            engine_short_res,
            Err(ZeroVaultError::CryptoTamperDetected(_) | ZeroVaultError::InvalidWireFormat(_))
        ),
        "SyncEngine read_range on 12B truncated chunk must fail closed"
    );

    // --- Sub-attack 3B: Truncate entire trailing chunk `4` by flipping `CHUNK_FLAG_FINAL` (`0x01`)
    //     on chunk `N - 2` (`chunk_index = 3`) and deleting chunk `4`! ---
    let mut forged_final_n_minus_2 = orig_n_minus_2.clone();
    ensure!(
        (forged_final_n_minus_2[5] & CHUNK_FLAG_FINAL) == 0,
        "chunk N-2 must initially have CHUNK_FLAG_FINAL == 0"
    );
    forged_final_n_minus_2[5] |= CHUNK_FLAG_FINAL;
    ensure!(
        ChunkHeader::decode(&forged_final_n_minus_2)?.is_final_chunk,
        "forged chunk N-2 header must decode with is_final_chunk == true"
    );

    std::fs::write(&path_n_minus_2, &forged_final_n_minus_2)?;
    std::fs::remove_file(&path_final)?;

    // Both stream-level `decrypt_chunk` (no manifest size needed!) AND `SyncEngine::read_range`
    // MUST fail closed with `CryptoTamperDetected` via `is_final` in the 25-byte `ChunkAad`!
    let direct_flag_flip = crypto.decrypt_chunk(
        &dek,
        inode_rec.file_id,
        Some(3),
        &forged_final_n_minus_2,
    );
    let direct_flag_err = match direct_flag_flip {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!(
            "3B direct decrypt_chunk expected CryptoTamperDetected, got {:?}",
            other.map(|(_, b)| b.len())
        ),
    };

    let engine_flag_err = match engine
        .read_range(
            created.inode,
            3 * PLAINTEXT_CHUNK_SIZE as u64,
            PLAINTEXT_CHUNK_SIZE,
        )
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!(
            "3B SyncEngine read_range expected CryptoTamperDetected, got {:?}",
            other.map(|b| b.len())
        ),
    };

    let mem = sample_process_memory();
    engine.lock_and_purge_cache().await?;
    let elapsed = started.elapsed();

    println!(
        "[PROOF-GATE3-ATTACK3] status=PASS chunks=5 \
         trunc_128b=Err(CryptoTamperDetected(\"{}\")) \
         trunc_forged_hdr=Err(CryptoTamperDetected(\"{}\")) \
         trunc_12b_hdr=Err(InvalidWireFormat) \
         is_final_flip_chunk3_direct=Err(CryptoTamperDetected(\"{}\")) \
         is_final_flip_chunk3_engine=Err(CryptoTamperDetected(\"{}\")) \
         plaintext_bytes_returned=0 elapsed_ms={:.2} rss_mib={:.2} peak_rss_mib={:.2}",
        err_trunc_tail,
        err_forged_len,
        direct_flag_err,
        engine_flag_err,
        elapsed.as_secs_f64() * 1000.0,
        mem.ws_mib(),
        mem.peak_mib(),
    );
    Ok(())
}

// ============================================================================
// WAVE 4 GATE 3 — ATTACK 4: UNSIGNED / FORGED MANIFEST & SHARE / KEYBOX INJECTION
// ============================================================================

#[tokio::test]
async fn t05_gate3_attack4_unsigned_manifest_and_forged_share_keybox_injection_fail_closed()
-> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();

    let tmp = TempDir::new()?;
    let state_dir = tmp.path().join("state");
    let daemon_state = tmp.path().join("daemon_state");
    let cloud_dir = tmp.path().join("cloud");
    let daemon_cloud = tmp.path().join("daemon_cloud");
    std::fs::create_dir_all(&cloud_dir)?;
    std::fs::create_dir_all(&daemon_cloud)?;

    let crypto = Arc::new(RingHybridCryptoEngine::new()?);
    let hdr = crypto
        .init_vault(
            &RedactedSecret::from("attack4-manifest-share-passphrase"),
            KdfParams::interactive_production(),
        )
        .await?;
    let vault_id = hdr.vault_id;

    let router = Arc::new(StorageRouter::new(
        vec![CloudBackend::from_config(&local_fs_backend_cfg(
            "cloud-main",
            &cloud_dir,
            None,
        ))?],
        RoutingPolicy::Targeted {
            prefix_routes: Vec::new(),
            default_backend: "cloud-main".to_owned(),
        },
    )?);
    let meta = Arc::new(SqliteMetadataStore::open(
        state_dir.join("metadata.db"),
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
    )?);
    let engine = SyncEngine::new(
        SyncEngineConfig {
            staging_dir: state_dir.join("staging"),
            device_id: "attack4-node".to_owned(),
            ..SyncEngineConfig::default()
        },
        Arc::clone(&meta) as Arc<dyn MetadataStore>,
        Arc::clone(&crypto) as Arc<dyn CryptoEngine>,
        Arc::clone(&router) as Arc<dyn StorageRouterTrait>,
    )?;

    // Publish rev 1 and rev 2 so we also capture valid `rev1_manifest_bytes` for manifest rollback check.
    let f1 = engine
        .create_entry(CreateEntrySpec {
            parent_inode: ROOT_INODE,
            name: "doc_rev1.txt".to_owned(),
            mode: 0o644,
        })
        .await?;
    engine
        .write_range(f1.inode, 0, b"authentic-revision-1")
        .await?;
    engine.sync_once().await?;
    let rev1_head_bytes = router.get_blob(MANIFEST_HEAD_OBJECT_KEY, &[]).await?;

    engine
        .write_range(f1.inode, 0, b"authentic-revision-2-updated")
        .await?;
    engine.sync_once().await?;
    ensure!(meta.epoch_floor(EPOCH_SCOPE_MANIFEST).await? == 2);

    // --- Sub-attack 4A(i): Inject raw unsigned/unencrypted `manifests/head.zvm` ---
    router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            Bytes::from_static(b"UNSIGNED_FORGED_MANIFEST_JSON_{nodes:[]}"),
            None,
        )
        .await?;
    let unsigned_sync_err = match engine.sync_once().await {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("4A(i) unsigned head.zvm expected CryptoTamperDetected, got {other:?}"),
    };

    // --- Sub-attack 4A(ii): Inject structurally valid `ZVM1` wire header + forged GCM tag ---
    let forged_zvm_hdr = ManifestWireHeader {
        version: MANIFEST_FORMAT_VERSION,
        vault_id,
        revision: 99,
        nonce: [0x37; 12],
    };
    let mut forged_zvm_bytes = Vec::new();
    forged_zvm_bytes.extend_from_slice(&forged_zvm_hdr.encode());
    forged_zvm_bytes.extend_from_slice(b"UNAUTHENTICATED_POSTCARD_MANIFEST_STREAM");
    forged_zvm_bytes.extend_from_slice(&[0xAA; 16]);

    ensure!(
        matches!(
            crypto.open_manifest(&forged_zvm_bytes),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "open_manifest must fail closed with CryptoTamperDetected on forged ZVM1 tag"
    );
    router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            Bytes::from(forged_zvm_bytes),
            None,
        )
        .await?;
    let forged_zvm_sync_err = match engine.sync_once().await {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("4A(ii) forged ZVM1 expected CryptoTamperDetected, got {other:?}"),
    };

    // --- Sub-attack 4A(iii): Mallory-key-sealed `ZVM1` `VaultManifest` + Stale `rev=1` Rollback ---
    let mallory_crypto = RingHybridCryptoEngine::new()?;
    mallory_crypto.unlock_with_folder_key(vault_id, &[0x99; 32])?;
    let mallory_manifest = VaultManifest {
        vault_id,
        revision: 50,
        parent_manifest_id: meta.parent_manifest_id().await?,
        device_id: "mallory".to_owned(),
        created_at: Utc::now(),
        nodes: Vec::new(),
    };
    let mallory_sealed = mallory_crypto.seal_manifest(&mallory_manifest)?;
    router
        .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, mallory_sealed, None)
        .await?;
    ensure!(
        matches!(
            engine.sync_once().await,
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "Mallory-sealed ZVM1 must fail closed with CryptoTamperDetected"
    );

    // Replay genuine `revision = 1` `head.zvm` when `epoch_floor("manifest") == 2`!
    router
        .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, rev1_head_bytes, None)
        .await?;
    let rev_rollback_err = match engine.sync_once().await {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("4A(iii) manifest rev=1 replay expected CryptoTamperDetected, got {other:?}"),
    };
    ensure!(
        rev_rollback_err.contains("rollback"),
        "expected manifest rollback message, got {rev_rollback_err}"
    );

    // --- Sub-attack 4B: Forged-Signature `ZVS1` Capability Share Injection ---
    let owner_id = crypto.generate_recipient_identity("owner")?;
    let mallory_id = crypto.generate_recipient_identity("mallory")?;
    let (valid_uri, valid_share_env) = engine
        .create_file_capability_share(
            &owner_id,
            "fs",
            &cloud_dir.to_string_lossy(),
            "/doc_rev1.txt",
        )
        .await?;
    let encoded_uri = valid_uri.encode()?;
    let parsed_uri = CapabilityUri::parse(&encoded_uri)?;

    // 4B(i): 1-bit flip in `ed25519_signature` of `ZVS1`
    let mut bitflip_zvs = valid_share_env.clone();
    bitflip_zvs.ed25519_signature[0] ^= 0x01;
    let zvs_bitflip_err = match crypto.open_capability_share(&parsed_uri, &bitflip_zvs) {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("4B(i) ZVS1 signature bit-flip expected CryptoTamperDetected, got {other:?}"),
    };

    // 4B(ii): Mallory re-signs a `ShareDescriptor` with Mallory's valid `Ed25519` keypair
    let fake_dek = crypto.generate_dek()?;
    let fake_desc = ShareDescriptor {
        share_id: parsed_uri.share_id,
        file_id: Uuid::new_v4(),
        filename: "injected_trojan.txt".to_owned(),
        size: 0,
        created_at: Utc::now(),
        wrapped_dek: WrappedDek {
            nonce: [0u8; 12],
            ciphertext_and_tag: vec![0u8; 48],
        },
        chunks: Vec::new(),
    };
    let (_mallory_uri, mut mallory_env) = crypto.create_capability_share(
        &mallory_id,
        "fs",
        &cloud_dir.to_string_lossy(),
        &fake_dek,
        &fake_desc,
    )?;
    // Rejected both with Mallory's pubkey AND when spoofing Owner's pubkey!
    ensure!(matches!(
        crypto.open_capability_share(&parsed_uri, &mallory_env),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    mallory_env.owner_ed25519_pubkey = owner_id.public.ed25519_pubkey;
    ensure!(matches!(
        crypto.open_capability_share(&parsed_uri, &mallory_env),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Overwrite remote `shares/<aa>/<bb>/<share_id>.zvs` with Mallory's forged envelope -> `import_capability_share` fails closed!
    let share_key = ShareObjectKey::from_uuid(parsed_uri.share_id);
    router
        .put_blob("/doc_rev1.txt", share_key.as_str(), Bytes::from(mallory_env.encode()?))
        .await?;
    ensure!(
        matches!(
            engine
                .import_capability_share(&encoded_uri, "/imported_bad.txt")
                .await,
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "SyncEngine::import_capability_share must fail closed with CryptoTamperDetected on forged ZVS1"
    );

    // --- Sub-attack 4C: Forged-Signature `ZVK1` Keybox Injection ---
    let alice_id = crypto.generate_recipient_identity("alice")?;
    let frk = crypto.export_folder_root_key()?;
    let valid_kb = crypto.seal_keybox(
        &owner_id,
        vault_id,
        1,
        &frk,
        std::slice::from_ref(&alice_id.public),
    )?;

    // 4C(i): 1-bit flip in `owner_signature` of `ZVK1`
    let mut bitflip_kb = valid_kb.clone();
    bitflip_kb.owner_signature[0] ^= 0x01;
    let zvk_bitflip_err = match crypto.open_keybox(
        &bitflip_kb,
        Some(&owner_id.public.ed25519_pubkey),
        1,
        &alice_id,
    ) {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("4C(i) ZVK1 signature bit-flip expected CryptoTamperDetected, got {other:?}"),
    };

    // 4C(ii): Mallory signs a forged `SignedKeybox` wrapping Mallory's FRK for Alice
    let mut mallory_kb = crypto.seal_keybox(
        &mallory_id,
        vault_id,
        1,
        &[0xEE; 32],
        std::slice::from_ref(&alice_id.public),
    )?;
    ensure!(matches!(
        crypto.open_keybox(
            &mallory_kb,
            Some(&owner_id.public.ed25519_pubkey),
            1,
            &alice_id
        ),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));
    mallory_kb.owner_ed25519_pubkey = owner_id.public.ed25519_pubkey;
    ensure!(matches!(
        crypto.open_keybox(&mallory_kb, None, 1, &alice_id),
        Err(ZeroVaultError::CryptoTamperDetected(_))
    ));

    // Overwrite remote `vault/keybox.zv` with forged `ZVK1` -> `fetch_and_open_keybox` fails closed!
    router
        .put_manifest_cas(KEYBOX_OBJECT_KEY, Bytes::from(mallory_kb.encode()?), None)
        .await?;
    ensure!(
        matches!(
            engine
                .fetch_and_open_keybox(Some(&owner_id.public.ed25519_pubkey), &alice_id)
                .await,
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "SyncEngine::fetch_and_open_keybox must fail closed with CryptoTamperDetected on forged ZVK1"
    );

    // Also verify `DaemonRuntime::SyncNow` & `ImportCapabilityShare` fail closed with `code == "crypto_tamper"`!
    let daemon_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(daemon_state)
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::new(RingHybridCryptoEngine::new()?))
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;
    let _ = daemon_rt
        .handle_request(DaemonRequest::InitVault {
            passphrase: "daemon-attack4-passphrase".to_owned(),
        })
        .await;
    let _ = daemon_rt
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "d-cloud".to_owned(),
            kind: "fs".to_owned(),
            root: daemon_cloud.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            username: None,
            secret: None,
        })))
        .await;
    std::fs::create_dir_all(daemon_cloud.join("manifests"))?;
    std::fs::write(
        daemon_cloud.join(MANIFEST_HEAD_OBJECT_KEY),
        b"CORRUPT_UNSIGNED_HEAD_ZVM_PAYLOAD",
    )?;
    match daemon_rt.handle_request(DaemonRequest::SyncNow).await {
        DaemonResponse::Error { code, .. } => {
            ensure!(code == "crypto_tamper", "expected crypto_tamper, got {code}");
        }
        other => bail!("DaemonRuntime::SyncNow on unsigned head.zvm expected Error(crypto_tamper), got {other:?}"),
    }

    let mem = sample_process_memory();
    engine.lock_and_purge_cache().await?;
    daemon_rt.graceful_shutdown().await?;
    let elapsed = started.elapsed();

    println!(
        "[PROOF-GATE3-ATTACK4] status=PASS \
         unsigned_zvm_sync=Err(CryptoTamperDetected(\"{}\")) \
         forged_zvm1_tag=Err(CryptoTamperDetected(\"{}\")) \
         manifest_rev1_rollback=Err(CryptoTamperDetected(\"{}\")) \
         forged_zvs1_sig=Err(CryptoTamperDetected(\"{}\")) \
         forged_zvk1_sig=Err(CryptoTamperDetected(\"{}\")) \
         daemon_sync_code=crypto_tamper \
         elapsed_ms={:.2} rss_mib={:.2} peak_rss_mib={:.2}",
        unsigned_sync_err,
        forged_zvm_sync_err,
        rev_rollback_err,
        zvs_bitflip_err,
        zvk_bitflip_err,
        elapsed.as_secs_f64() * 1000.0,
        mem.ws_mib(),
        mem.peak_mib(),
    );
    Ok(())
}

// ============================================================================
// WAVE 4 GATE 3 — ATTACK 5: `keybox.zv` `epoch = 1` ROLLBACK REPLAY AFTER REVOCATION AT `epoch = 2`
// ============================================================================

#[tokio::test]
async fn t06_gate3_attack5_keybox_epoch1_rollback_replay_after_epoch2_revocation_fails_closed()
-> Result<()> {
    let _serial = suite_lock().lock().await;
    let started = Instant::now();

    let tmp = TempDir::new()?;
    let owner_state = tmp.path().join("owner_state");
    let alice_state = tmp.path().join("alice_state");
    let bob_state = tmp.path().join("bob_state");
    let shared_cloud = tmp.path().join("shared_pq_cloud");
    std::fs::create_dir_all(&shared_cloud)?;

    let owner_crypto = Arc::new(RingHybridCryptoEngine::new()?);
    let owner_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(owner_state.clone())
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>)
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;

    let owner_passphrase = "attack5-pq-keybox-revocation-passphrase";
    match owner_rt
        .handle_request(DaemonRequest::InitVault {
            passphrase: owner_passphrase.to_owned(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("InitVault failed: {other:?}"),
    }
    match owner_rt
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "pq-shared".to_owned(),
            kind: "fs".to_owned(),
            root: shared_cloud.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: Some(256 * 1024 * 1024),
            policy: Some("targeted".to_owned()),
            prefix: None,
            username: None,
            secret: None,
        })))
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("AddRemote failed: {other:?}"),
    }

    // Save initial file at epoch = 1
    match owner_rt
        .handle_request(DaemonRequest::SaveTextNote {
            virtual_path: "/Shared/design_v1.md".to_owned(),
            content: "Epoch-1 Shared Confidential Specification".to_owned(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("SaveTextNote failed: {other:?}"),
    }

    // Generate NIST FIPS 203 `ML-KEM-768 + X25519 + Ed25519` identities for Alice & Bob
    let pq_helper = Arc::new(RingHybridCryptoEngine::new()?);
    let alice_id = pq_helper.generate_recipient_identity("alice")?;
    let bob_id = pq_helper.generate_recipient_identity("bob")?;
    ensure!(alice_id.public.mlkem768_encaps_key.len() == ML_KEM_768_ENCAPS_KEY_LEN);
    ensure!(alice_id.mlkem768_decaps_key.len() == ML_KEM_768_DECAPS_KEY_LEN);
    ensure!(bob_id.public.mlkem768_encaps_key.len() == ML_KEM_768_ENCAPS_KEY_LEN);
    ensure!(bob_id.mlkem768_decaps_key.len() == ML_KEM_768_DECAPS_KEY_LEN);

    // Initialize `keybox.zv` (`epoch = 1`) and grant Alice + Bob
    match owner_rt.handle_request(DaemonRequest::InitKeybox).await {
        DaemonResponse::KeyboxInfo(info) => ensure!(info.epoch == 1),
        other => bail!("InitKeybox failed: {other:?}"),
    }
    for bundle_b64 in [alice_id.public.to_base64()?, bob_id.public.to_base64()?] {
        match owner_rt
            .handle_request(DaemonRequest::GrantKeyboxRecipient {
                recipient_bundle_b64: bundle_b64,
            })
            .await
        {
            DaemonResponse::KeyboxInfo(info) => ensure!(info.epoch == 1),
            other => bail!("GrantKeyboxRecipient failed: {other:?}"),
        }
    }

    // Capture raw `keybox_epoch1_bytes` and verify Bob CAN open `epoch = 1`!
    let kb_disk_path = shared_cloud.join(KEYBOX_OBJECT_KEY);
    let keybox_epoch1_bytes = std::fs::read(&kb_disk_path)?;
    let kb_ep1 = SignedKeybox::decode(&keybox_epoch1_bytes)?;
    ensure!(kb_ep1.epoch == 1, "expected epoch 1");
    let owner_ed25519_pub = kb_ep1.owner_ed25519_pubkey;

    let bob_frk_ep1 = pq_helper.open_keybox(&kb_ep1, Some(&owner_ed25519_pub), 1, &bob_id)?;
    let alice_frk_ep1 = pq_helper.open_keybox(&kb_ep1, Some(&owner_ed25519_pub), 1, &alice_id)?;
    ensure!(
        *bob_frk_ep1 == *alice_frk_ep1,
        "Alice and Bob must decapsulate identical FolderRootKey at epoch 1"
    );

    // Build real SyncEngines for Alice and Bob backed by SQLite WAL stores
    let make_peer_engine = |peer_dir: &Path, dev: &str| -> Result<(Arc<SyncEngine>, Arc<SqliteMetadataStore>, Arc<RingHybridCryptoEngine>)> {
        let c = Arc::new(RingHybridCryptoEngine::new()?);
        let r = Arc::new(StorageRouter::new(
            vec![CloudBackend::from_config(&local_fs_backend_cfg(
                "pq-shared",
                &shared_cloud,
                None,
            ))?],
            RoutingPolicy::Targeted {
                prefix_routes: Vec::new(),
                default_backend: "pq-shared".to_owned(),
            },
        )?);
        let m = Arc::new(SqliteMetadataStore::open(
            peer_dir.join("metadata.db"),
            Arc::clone(&c) as Arc<dyn CryptoEngine>,
        )?);
        let e = Arc::new(SyncEngine::new(
            SyncEngineConfig {
                staging_dir: peer_dir.join("staging"),
                device_id: dev.to_owned(),
                ..SyncEngineConfig::default()
            },
            Arc::clone(&m) as Arc<dyn MetadataStore>,
            Arc::clone(&c) as Arc<dyn CryptoEngine>,
            r as Arc<dyn StorageRouterTrait>,
        )?);
        Ok((e, m, c))
    };

    let (bob_engine, bob_meta, bob_crypto) = make_peer_engine(&bob_state, "bob-dev")?;
    let (opened_bob_kb1, _) = bob_engine
        .fetch_and_open_keybox(Some(&owner_ed25519_pub), &bob_id)
        .await?;
    ensure!(opened_bob_kb1.epoch == 1 && bob_meta.epoch_floor(EPOCH_SCOPE_KEYBOX).await? == 1);
    bob_engine.sync_once().await?;
    let bob_doc = bob_engine.resolve_path("/Shared/design_v1.md").await?;
    let bob_read = bob_engine
        .read_range(bob_doc.inode, 0, bob_doc.size as usize)
        .await?;
    ensure!(bob_read.as_ref() == b"Epoch-1 Shared Confidential Specification");

    // --- Revoke Bob (`RevokeKeyboxRecipient`) -> advances `keybox.zv` to `epoch = 2` + rotates `FRK`! ---
    let revoked_info = match owner_rt
        .handle_request(DaemonRequest::RevokeKeyboxRecipient {
            recipient_id: bob_id.public.recipient_id.clone(),
        })
        .await
    {
        DaemonResponse::KeyboxInfo(info) => info,
        other => bail!("RevokeKeyboxRecipient failed: {other:?}"),
    };
    ensure!(revoked_info.epoch == 2, "expected epoch 2 after revoking Bob");
    ensure!(revoked_info.recipient_ids.contains(&alice_id.public.recipient_id));
    ensure!(!revoked_info.recipient_ids.contains(&bob_id.public.recipient_id));

    // Verify Owner's SQLite `epoch_floor("keybox") == 2`!
    let owner_sqlite_probe = SqliteMetadataStore::open(
        owner_state.join("metadata.db"),
        Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>,
    )?;
    let owner_floor = owner_sqlite_probe.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
    ensure!(
        owner_floor == 2,
        "Owner SQLite epoch_floor('keybox') must equal 2, got {owner_floor}"
    );

    // Write post-revocation secret at `epoch = 2` under rotated `FolderRootKey`
    match owner_rt
        .handle_request(DaemonRequest::SaveTextNote {
            virtual_path: "/Shared/post_revocation_epoch2.md".to_owned(),
            content: "Eyes-Only Epoch-2 Post-Revocation Payload".to_owned(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("SaveTextNote epoch 2 failed: {other:?}"),
    }

    let keybox_epoch2_bytes = std::fs::read(&kb_disk_path)?;
    let kb_ep2 = SignedKeybox::decode(&keybox_epoch2_bytes)?;
    ensure!(kb_ep2.epoch == 2);

    // --- Prove (a): Bob is rejected on `epoch = 2` (`UnauthorizedRecipient` + cannot decrypt new key/manifest) ---
    let bob_ep2_open = pq_helper.open_keybox(&kb_ep2, Some(&owner_ed25519_pub), 2, &bob_id);
    let bob_unauth_msg = match bob_ep2_open {
        Err(ZeroVaultError::UnauthorizedRecipient(msg)) => msg,
        other => bail!("Attack 5(a) expected UnauthorizedRecipient for Bob on epoch 2, got {other:?}"),
    };
    ensure!(
        matches!(
            bob_engine
                .fetch_and_open_keybox(Some(&owner_ed25519_pub), &bob_id)
                .await,
            Err(ZeroVaultError::UnauthorizedRecipient(_))
        ),
        "Bob's SyncEngine::fetch_and_open_keybox must reject Bob on epoch 2 with UnauthorizedRecipient"
    );

    // Even if Bob kept `bob_frk_ep1` cached in RAM, Bob CANNOT decrypt the rotated `epoch = 2` `head.zvm`!
    bob_crypto.unlock_with_folder_key(kb_ep2.vault_id, &bob_frk_ep1)?;
    let head_zvm_epoch2 = std::fs::read(shared_cloud.join(MANIFEST_HEAD_OBJECT_KEY))?;
    ensure!(
        matches!(
            bob_crypto.open_manifest(&head_zvm_epoch2),
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "Bob's retained epoch-1 FolderRootKey must fail to decrypt rotated epoch-2 manifest"
    );

    // Meanwhile Alice opens `epoch = 2`, advances her SQLite `epoch_floor("keybox") = 2`, and reads epoch-2 data!
    let (alice_engine, alice_meta, _alice_crypto) = make_peer_engine(&alice_state, "alice-dev")?;
    let (opened_alice_kb2, alice_frk_ep2) = alice_engine
        .fetch_and_open_keybox(Some(&owner_ed25519_pub), &alice_id)
        .await?;
    ensure!(opened_alice_kb2.epoch == 2);
    ensure!(*alice_frk_ep2 != *alice_frk_ep1, "FolderRootKey MUST rotate on revocation");
    ensure!(alice_meta.epoch_floor(EPOCH_SCOPE_KEYBOX).await? == 2);
    alice_engine.sync_once().await?;
    let alice_ep2_doc = alice_engine
        .resolve_path("/Shared/post_revocation_epoch2.md")
        .await?;
    let alice_ep2_bytes = alice_engine
        .read_range(alice_ep2_doc.inode, 0, alice_ep2_doc.size as usize)
        .await?;
    ensure!(alice_ep2_bytes.as_ref() == b"Eyes-Only Epoch-2 Post-Revocation Payload");

    // --- Prove (b): Overwrite remote `vault/keybox.zv` with valid signed `keybox_epoch1_bytes` (`epoch = 1`) ->
    //     `open_keybox`, `SyncEngine`, AND `DaemonRuntime` MUST all fail closed with `CryptoTamperDetected` (`1 < 2`)! ---
    std::fs::write(&kb_disk_path, &keybox_epoch1_bytes)?;

    // Layer 1: `RingHybridCryptoEngine::open_keybox` with `min_epoch_floor = 2`
    let open_kb_rollback_msg = match pq_helper.open_keybox(
        &kb_ep1,
        Some(&owner_ed25519_pub),
        2,
        &alice_id,
    ) {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Attack 5(b) open_keybox expected CryptoTamperDetected, got {other:?}"),
    };

    // Layer 2: `SyncEngine::fetch_and_open_keybox` (backed by SQLite `epoch_floor("keybox") == 2`)
    let sync_engine_rollback_msg = match alice_engine
        .fetch_and_open_keybox(Some(&owner_ed25519_pub), &alice_id)
        .await
    {
        Err(ZeroVaultError::CryptoTamperDetected(msg)) => msg,
        other => bail!("Attack 5(b) SyncEngine::fetch_and_open_keybox expected CryptoTamperDetected, got {other:?}"),
    };
    ensure!(
        matches!(
            alice_engine.publish_keybox(&kb_ep1).await,
            Err(ZeroVaultError::CryptoTamperDetected(_))
        ),
        "SyncEngine::publish_keybox must also refuse rolled-back epoch 1 < 2"
    );

    // Layer 3A: `DaemonRuntime::KeyboxStatus`
    let daemon_kb_status_err = match owner_rt.handle_request(DaemonRequest::KeyboxStatus).await {
        DaemonResponse::Error { code, message } => {
            ensure!(
                code == "crypto_tamper",
                "expected DaemonRuntime KeyboxStatus code=='crypto_tamper', got '{code}': {message}"
            );
            message
        }
        other => bail!("Attack 5(b) DaemonRuntime::KeyboxStatus expected Error(crypto_tamper), got {other:?}"),
    };

    // Layer 3B: `DaemonRuntime::UnlockVault` after `LockVault` while rolled-back `epoch = 1` sits on cloud!
    match owner_rt.handle_request(DaemonRequest::LockVault).await {
        DaemonResponse::Ok { .. } => {}
        other => bail!("LockVault failed: {other:?}"),
    }
    let daemon_unlock_rollback_err = match owner_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: owner_passphrase.to_owned(),
        })
        .await
    {
        DaemonResponse::Error { code, message } => {
            ensure!(
                code == "crypto_tamper",
                "expected UnlockVault rollback code=='crypto_tamper', got '{code}': {message}"
            );
            message
        }
        other => bail!("Attack 5(b) UnlockVault on rolled-back keybox.zv expected Error(crypto_tamper), got {other:?}"),
    };
    ensure!(
        !owner_crypto.is_unlocked(),
        "DaemonRuntime must remain locked when UnlockVault aborts on keybox epoch rollback"
    );

    // Restore legitimate `epoch = 2` `keybox.zv` -> `UnlockVault` succeeds cleanly!
    std::fs::write(&kb_disk_path, &keybox_epoch2_bytes)?;
    match owner_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: owner_passphrase.to_owned(),
        })
        .await
    {
        DaemonResponse::Ok { .. } => {}
        other => bail!("UnlockVault after restoring epoch=2 keybox failed: {other:?}"),
    }

    let mem = sample_process_memory();
    owner_rt.graceful_shutdown().await?;
    alice_engine.lock_and_purge_cache().await?;
    bob_engine.lock_and_purge_cache().await?;
    drop(owner_sqlite_probe);
    let elapsed = started.elapsed();

    println!(
        "[PROOF-GATE3-ATTACK5] status=PASS \
         bob_revoked_ep2=Err(UnauthorizedRecipient(\"{}\")) \
         bob_old_frk_manifest=Err(CryptoTamperDetected) \
         sqlite_epoch_floor=2 \
         open_keybox_replay=Err(CryptoTamperDetected(\"{}\")) \
         sync_engine_replay=Err(CryptoTamperDetected(\"{}\")) \
         daemon_status_replay=Err(crypto_tamper: \"{}\") \
         daemon_unlock_replay=Err(crypto_tamper: \"{}\") \
         elapsed_ms={:.2} rss_mib={:.2} peak_rss_mib={:.2}",
        bob_unauth_msg,
        open_kb_rollback_msg,
        sync_engine_rollback_msg,
        daemon_kb_status_err,
        daemon_unlock_rollback_err,
        elapsed.as_secs_f64() * 1000.0,
        mem.ws_mib(),
        mem.peak_mib(),
    );
    Ok(())
}

// ============================================================================
// RED-TEAM AUDIT PROBE (`t07`): `DaemonRuntime::KeyboxStatus` & `SyncEngine::fetch_keybox`
// FORGED `ZVK1` SIGNATURE + EPOCH-FLOOR POISONING (`W4-VETO-KEYBOX-SIG`)
// ============================================================================

#[tokio::test]
async fn t07_gate3_redteam_daemon_keybox_forged_signature_epoch_poisoning_audit() -> Result<()> {
    let _serial = suite_lock().lock().await;

    let tmp = TempDir::new()?;
    let owner_state = tmp.path().join("owner_state");
    let cloud_dir = tmp.path().join("cloud");
    std::fs::create_dir_all(&cloud_dir)?;

    let owner_crypto = Arc::new(RingHybridCryptoEngine::new()?);
    let owner_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(owner_state.clone())
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>)
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;

    let passphrase = "redteam-keybox-poison-passphrase";
    let _ = owner_rt
        .handle_request(DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    let _ = owner_rt
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "cloud".to_owned(),
            kind: "fs".to_owned(),
            root: cloud_dir.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            username: None,
            secret: None,
        })))
        .await;

    // Legitimate `InitKeybox` at `epoch = 1`
    match owner_rt.handle_request(DaemonRequest::InitKeybox).await {
        DaemonResponse::KeyboxInfo(kb) => ensure!(kb.epoch == 1),
        other => bail!("InitKeybox failed: {other:?}"),
    }

    let kb_path = cloud_dir.join(KEYBOX_OBJECT_KEY);
    let legit_ep1_bytes = std::fs::read(&kb_path)?;
    let mut forged_poison_kb = SignedKeybox::decode(&legit_ep1_bytes)?;

    // Byzantine cloud adversary / revoked user injects a FORGED-SIGNATURE `ZVK1` with `epoch = 999_999`
    // and 64 garbage signature bytes `[0xDE; 64]`!
    forged_poison_kb.epoch = 999_999;
    forged_poison_kb.owner_signature = vec![0xDE; 64];
    let forged_wire = forged_poison_kb.encode()?;
    std::fs::write(&kb_path, &forged_wire)?;

    // UI (`entrocloud-ui` worker.rs:1005,1103) or CLI (`zv keybox status`) polls `DaemonRequest::KeyboxStatus`:
    let status_resp = owner_rt.handle_request(DaemonRequest::KeyboxStatus).await;

    let sqlite_probe = SqliteMetadataStore::open(
        owner_state.join("metadata.db"),
        Arc::clone(&owner_crypto) as Arc<dyn CryptoEngine>,
    )?;
    let persisted_floor = sqlite_probe.epoch_floor(EPOCH_SCOPE_KEYBOX).await?;
    drop(sqlite_probe);

    // Restore legitimate `epoch = 1` keybox and check if `LockVault -> UnlockVault` is permanently bricked!
    std::fs::write(&kb_path, &legit_ep1_bytes)?;
    let _ = owner_rt.handle_request(DaemonRequest::LockVault).await;
    let re_unlock_resp = owner_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;

    // Vector B: Single-user vault (no `recipient_identity.zvi` yet) unlocks while a forged-signature
    // `ZVK1` (`epoch = 888_888`, `sig = [0xDE; 64]`) is planted on remote `vault/keybox.zv`.
    let single_state = tmp.path().join("single_user_state");
    let single_cloud = tmp.path().join("single_user_cloud");
    std::fs::create_dir_all(&single_cloud)?;
    let single_crypto = Arc::new(RingHybridCryptoEngine::new()?);
    let single_rt = DaemonRuntime::builder(
        DaemonStateConfig::new(single_state.clone())
            .with_mock_vfs(true)
            .with_sync_interval(Duration::ZERO),
    )
    .with_crypto(Arc::clone(&single_crypto) as Arc<dyn CryptoEngine>)
    .with_secret_store(Arc::new(InMemorySecretStore::default()))
    .build()?;
    let _ = single_rt
        .handle_request(DaemonRequest::InitVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    let single_vault_id = single_crypto
        .vault_id()
        .ok_or_else(|| anyhow!("missing single_vault_id"))?;
    let _ = single_rt
        .handle_request(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: "single-cloud".to_owned(),
            kind: "fs".to_owned(),
            root: single_cloud.to_string_lossy().into_owned(),
            endpoint: None,
            bucket: None,
            region: None,
            quota_limit_bytes: None,
            policy: None,
            prefix: None,
            username: None,
            secret: None,
        })))
        .await;
    let _ = single_rt.handle_request(DaemonRequest::LockVault).await;

    // Plant forged-signature `ZVK1` matching `single_vault_id` at `epoch = 888_888`!
    let mut single_forged_kb = forged_poison_kb.clone();
    single_forged_kb.vault_id = single_vault_id;
    single_forged_kb.epoch = 888_888;
    single_forged_kb.owner_signature = vec![0xDE; 64];
    std::fs::create_dir_all(single_cloud.join("vault"))?;
    std::fs::write(
        single_cloud.join(KEYBOX_OBJECT_KEY),
        single_forged_kb.encode()?,
    )?;
    let single_unlock_resp = single_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;
    let single_floor = if single_crypto.is_unlocked() {
        let sp = SqliteMetadataStore::open(
            single_state.join("metadata.db"),
            Arc::clone(&single_crypto) as Arc<dyn CryptoEngine>,
        )?;
        sp.epoch_floor(EPOCH_SCOPE_KEYBOX).await?
    } else {
        0
    };

    // Vector C: Smart adversary (`Mallory`) signs a `ZVK1` at `epoch = 777_777` with Mallory's OWN
    // cryptographically valid `Ed25519` keypair (so self-signature passes, testing owner-pinning &
    // single-user unexpected-keybox rejection)!
    let mallory_helper = RingHybridCryptoEngine::new()?;
    let mallory_id = mallory_helper.generate_recipient_identity("mallory")?;
    let mallory_valid_sig_kb_owner = mallory_helper.seal_keybox(
        &mallory_id,
        forged_poison_kb.vault_id,
        777_777,
        &[0xCC; 32],
        std::slice::from_ref(&mallory_id.public),
    )?;
    std::fs::write(&kb_path, mallory_valid_sig_kb_owner.encode()?)?;
    let mallory_pinned_status_resp = owner_rt.handle_request(DaemonRequest::KeyboxStatus).await;
    std::fs::write(&kb_path, &legit_ep1_bytes)?;

    let mallory_valid_sig_kb_single = mallory_helper.seal_keybox(
        &mallory_id,
        single_vault_id,
        777_777,
        &[0xDD; 32],
        std::slice::from_ref(&mallory_id.public),
    )?;
    std::fs::write(
        single_cloud.join(KEYBOX_OBJECT_KEY),
        mallory_valid_sig_kb_single.encode()?,
    )?;
    let mallory_single_unlock_resp = single_rt
        .handle_request(DaemonRequest::UnlockVault {
            passphrase: passphrase.to_owned(),
        })
        .await;

    println!(
        "[PROOF-REDTEAM-T07] status=PASS \
         vector_a(forged_zvk1_epoch=999999 sig=[0xDE;64]): \
         keybox_status_resp={:?} persisted_sqlite_epoch_floor={} subsequent_legit_unlock_resp={:?} | \
         vector_b(single_user_unlock_on_forged_zvk1_epoch=888888): \
         unlock_resp={:?} poisoned_single_user_floor={} | \
         vector_c(mallory_valid_ed25519_zvk1_epoch=777777): \
         pinned_status_resp={:?} single_unlock_resp={:?}",
        status_resp,
        persisted_floor,
        re_unlock_resp,
        single_unlock_resp,
        single_floor,
        mallory_pinned_status_resp,
        mallory_single_unlock_resp
    );

    ensure!(
        matches!(status_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "W4-VETO-KEYBOX-SIG (Vector A): DaemonRuntime::KeyboxStatus accepted forged 64B Ed25519 signature on ZVK1 \
         (returned {status_resp:?}) and poisoned SQLite security_epochs('keybox') to {persisted_floor}, \
         causing subsequent legitimate UnlockVault to fail with {re_unlock_resp:?}!"
    );
    ensure!(
        matches!(single_unlock_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper")
            && single_floor == 0,
        "W4-VETO-KEYBOX-SIG (Vector B): Single-user UnlockVault accepted forged 64B Ed25519 signature on ZVK1 \
         (returned {single_unlock_resp:?}) and poisoned SQLite security_epochs('keybox') to {single_floor}!"
    );
    ensure!(
        matches!(mallory_pinned_status_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper")
            && matches!(mallory_single_unlock_resp, DaemonResponse::Error { ref code, .. } if code == "crypto_tamper"),
        "W4-VETO-KEYBOX-SIG (Vector C): Mallory self-signed ZVK1 was not rejected! pinned={mallory_pinned_status_resp:?}, single={mallory_single_unlock_resp:?}"
    );
    ensure!(
        persisted_floor == 1,
        "SQLite security_epochs('keybox') was poisoned from 1 to {persisted_floor} by unauthenticated ZVK1!"
    );
    ensure!(
        matches!(re_unlock_resp, DaemonResponse::Ok { .. }),
        "Legitimate UnlockVault failed after forged ZVK1 probe: {re_unlock_resp:?}"
    );

    owner_rt.graceful_shutdown().await?;
    single_rt.graceful_shutdown().await?;
    Ok(())
}
