//! CloudBridge-inspired automatic PC folder backup, incremental dry-run preview,
//! non-destructive 1-click restore, path-overlap guards, and schedule policy engine.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use parking_lot::RwLock as SyncRwLock;
use serde::{Deserialize, Serialize};
use tokio::fs::OpenOptions;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use zeroize::Zeroizing;
use entrocloud_types::{
    BackupJobSpec, BackupJobSummary, BackupRunReport, CreateEntrySpec, EntryKind, InodeId,
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, SetAttrSpec, VfsBackend, ZeroVaultError, ZeroVaultResult,
    validate_portable_entry_name,
};

use crate::dacl::{ensure_owner_only_dir, ensure_owner_only_file, is_symlink_or_reparse};
use crate::service::{SyncBackendBundle, normalize_vault_virtual_path};

/// Default exclusion patterns matching common OS temporary, cache, and build directories.
pub const DEFAULT_BACKUP_EXCLUDES: &[&str] = &[
    "desktop.ini",
    "Thumbs.db",
    "~$*",
    "*.tmp",
    ".DS_Store",
    "node_modules",
    ".git",
    "target",
    ".venv",
    "__pycache__",
    ".next",
    ".cache",
];

/// Maximum supported automatic backup cadence in minutes (7 days = `10,080` minutes).
pub const MAX_BACKUP_INTERVAL_MINUTES: u32 = 10_080;

/// Non-secret persisted configuration and execution telemetry for a PC folder backup job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBackupJob {
    /// Stable backup job identifier.
    pub id: String,
    /// Friendly display name.
    pub name: String,
    /// Canonical or normalized local PC source directory path.
    pub source_path: String,
    /// Normalized destination directory path inside the encrypted vault (e.g., `"/Backups/Documents"`).
    pub vault_folder: String,
    /// Automatic run interval in minutes (`0` for manual-only).
    pub interval_minutes: u32,
    /// Whether automatic background backup is enabled while unlocked.
    pub enabled: bool,
    /// Filename / glob patterns excluded from backup.
    pub excludes: Vec<String>,
    /// Timestamp of most recent non-preview backup attempt.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Timestamp of most recent successful non-preview backup.
    pub last_success_at: Option<DateTime<Utc>>,
    /// Most recent error message, if any.
    pub last_error: Option<String>,
    /// Files uploaded during the most recent successful run.
    #[serde(default)]
    pub last_files_synced: u64,
    /// Plaintext bytes uploaded during the most recent successful run.
    #[serde(default)]
    pub last_bytes_synced: u64,
}

impl StoredBackupJob {
    /// Projects this persisted job into an IPC [`BackupJobSummary`] with live computed `status`.
    #[must_use]
    pub fn to_summary(
        &self,
        unlocked: bool,
        backups_paused: bool,
        active_job_id: Option<&str>,
    ) -> BackupJobSummary {
        BackupJobSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            source_path: self.source_path.clone(),
            vault_folder: self.vault_folder.clone(),
            interval_minutes: self.interval_minutes,
            enabled: self.enabled,
            excludes: self.excludes.clone(),
            status: compute_job_status(self, unlocked, backups_paused, active_job_id),
            last_attempt_at: self.last_attempt_at,
            last_success_at: self.last_success_at,
            last_error: self.last_error.clone(),
            last_files_synced: self.last_files_synced,
            last_bytes_synced: self.last_bytes_synced,
        }
    }
}

/// Persisted `backup_jobs.json` state stored atomically inside `state_dir`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBackupState {
    /// Whether automatic background PC folder backups are paused.
    #[serde(default)]
    pub backups_paused: bool,
    /// Configured PC folder backup jobs.
    #[serde(default)]
    pub jobs: Vec<StoredBackupJob>,
}

/// Computes the human-readable job `status` string per specification:
/// `"Locked"` when `!unlocked`, `"Backing up…"` when active, `"Paused"` when `backups_paused`,
/// `"Needs attention"` when `last_error.is_some()`, `"Manual"` when `!enabled || interval_minutes == 0`,
/// else `"Backed up"` if `last_success_at.is_some()` or `"Ready"`.
#[must_use]
pub fn compute_job_status(
    job: &StoredBackupJob,
    unlocked: bool,
    backups_paused: bool,
    active_job_id: Option<&str>,
) -> String {
    if !unlocked {
        "Locked".to_owned()
    } else if active_job_id == Some(job.id.as_str()) {
        "Backing up\u{2026}".to_owned()
    } else if backups_paused {
        "Paused".to_owned()
    } else if job.last_error.as_deref().is_some_and(|e| !e.is_empty()) {
        "Needs attention".to_owned()
    } else if !job.enabled || job.interval_minutes == 0 {
        "Manual".to_owned()
    } else if job.last_success_at.is_some() {
        "Backed up".to_owned()
    } else {
        "Ready".to_owned()
    }
}

/// Background backup cadence and retry backoff policy ported from `CloudBridge` `SchedulePolicy.IsDue`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedulePolicy;

impl SchedulePolicy {
    /// Returns `true` when `job` is eligible to run on a background scheduler tick at `now`.
    ///
    /// Enforces:
    /// - `enabled && !backups_paused && unlocked && interval_minutes > 0`
    /// - `>= 60s` minimum debounce between attempts
    /// - `min(interval_minutes, 5)` minutes error retry backoff when `last_error` is present
    /// - `interval_minutes` normal cadence otherwise
    #[must_use]
    pub fn is_due(
        job: &StoredBackupJob,
        backups_paused: bool,
        unlocked: bool,
        now: DateTime<Utc>,
    ) -> bool {
        if !unlocked || backups_paused || !job.enabled || job.interval_minutes == 0 {
            return false;
        }
        let Some(attempt) = job.last_attempt_at else {
            return true;
        };
        let elapsed_secs = (now - attempt).num_seconds();
        if elapsed_secs < 60 {
            return false;
        }
        if job.last_error.as_deref().is_some_and(|e| !e.is_empty()) {
            let backoff_mins = i64::from(job.interval_minutes.min(5));
            return elapsed_secs >= backoff_mins.saturating_mul(60);
        }
        let cadence_secs = i64::from(job.interval_minutes).saturating_mul(60);
        elapsed_secs >= cadence_secs
    }
}

/// Loads `backup_jobs.json` from `path`, returning default empty state when the file does not exist.
pub fn load_backup_state(path: &Path) -> ZeroVaultResult<PersistedBackupState> {
    if !path.exists() {
        return Ok(PersistedBackupState::default());
    }
    let raw = std::fs::read(path)?;
    serde_json::from_slice(&raw).map_err(|e| {
        ZeroVaultError::ConfigError(format!(
            "failed parsing backup_jobs.json at {}: {e}",
            path.display()
        ))
    })
}

/// Atomically persists `backup_jobs.json` via a private owner-only temporary file + rename.
pub fn persist_backup_state(path: &Path, state: &PersistedBackupState) -> ZeroVaultResult<()> {
    let json = serde_json::to_vec_pretty(state).map_err(|e| {
        ZeroVaultError::ConfigError(format!("failed serializing backup_jobs.json: {e}"))
    })?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_owner_only_dir(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("backup_jobs.json");
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4().as_simple()));
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        if let Err(err) = file.write_all(&json).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, &json)?;
    }
    if let Err(err) = ensure_owner_only_file(&tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }
    Ok(())
}

/// Strips Windows extended-length path prefixes (`\\?\UNC\` / `\\?\`) for clean display and comparison.
#[must_use]
pub fn clean_local_path_display(path: &Path) -> String {
    let raw = path.display().to_string();
    #[cfg(target_os = "windows")]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            if let Some(unc_tail) = stripped.strip_prefix(r"UNC\") {
                return format!(r"\\{unc_tail}");
            }
            return stripped.to_owned();
        }
    }
    raw
}

fn resolve_canonical_with_nonexistent_tail(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    // Normalize lexical `.` and `..` before finding the deepest existing ancestor.
    let mut normalized = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    let mut cur = normalized.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canon) = std::fs::canonicalize(cur) {
            let mut rebuilt = canon;
            for part in tail.into_iter().rev() {
                rebuilt.push(part);
            }
            return rebuilt;
        }
        let Some(name) = cur.file_name() else {
            return normalized;
        };
        tail.push(name.to_os_string());
        let Some(parent) = cur.parent() else {
            return normalized;
        };
        cur = parent;
    }
}

fn normalized_overlap_key(path: &Path) -> String {
    let resolved = resolve_canonical_with_nonexistent_tail(path);
    let cleaned = clean_local_path_display(&resolved);
    #[cfg(target_os = "windows")]
    {
        let mut s = cleaned.replace('/', r"\");
        while s.len() > 3 && s.ends_with('\\') {
            s.pop();
        }
        if !s.ends_with('\\') {
            s.push('\\');
        }
        s.to_ascii_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut s = cleaned;
        while s.len() > 1 && s.ends_with('/') {
            s.pop();
        }
        if !s.ends_with('/') {
            s.push('/');
        }
        s
    }
}

/// Returns `true` if `a` and `b` are equal, `a` is an ancestor of `b`, or `b` is an ancestor of `a`
/// (ported from `CloudBridge` `JobValidation.Overlaps`).
#[must_use]
pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    let key_a = normalized_overlap_key(a);
    let key_b = normalized_overlap_key(b);
    key_a.starts_with(&key_b) || key_b.starts_with(&key_a)
}

/// Validates a backup job's `source_path` (must exist, be a real directory without symlinks/junctions,
/// and must NOT overlap `state_dir`, `staging_dir`, or active `mount_point`).
pub fn validate_backup_source_dir(
    raw_source_path: &str,
    state_dir: &Path,
    staging_dir: &Path,
    mount_point: Option<&Path>,
) -> ZeroVaultResult<PathBuf> {
    let trimmed = raw_source_path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(ZeroVaultError::InvalidPath(
            "backup source folder path must not be empty or contain NUL".into(),
        ));
    }
    let src_path = Path::new(trimmed);
    let meta = std::fs::symlink_metadata(src_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ZeroVaultError::InvalidPath(format!(
                "backup source folder does not exist: {}",
                src_path.display()
            ))
        } else {
            ZeroVaultError::Io(e)
        }
    })?;

    if is_symlink_or_reparse(&meta) {
        return Err(ZeroVaultError::InvalidPath(
            "backup source folder must be a real directory, not a symlink or junction".into(),
        ));
    }
    if !meta.is_dir() {
        return Err(ZeroVaultError::InvalidPath(format!(
            "backup source path is not a directory: {}",
            src_path.display()
        )));
    }

    let canon = std::fs::canonicalize(src_path)?;
    if paths_overlap(&canon, state_dir) {
        return Err(ZeroVaultError::InvalidPath(
            "backup source folder cannot overlap EntroCloud's private state directory".into(),
        ));
    }
    if paths_overlap(&canon, staging_dir) {
        return Err(ZeroVaultError::InvalidPath(
            "backup source folder cannot overlap EntroCloud's staging directory".into(),
        ));
    }
    if let Some(mp) = mount_point
        && paths_overlap(&canon, mp)
    {
        return Err(ZeroVaultError::InvalidPath(
            "backup source folder cannot overlap the active EntroCloud virtual drive mount point"
                .into(),
        ));
    }

    Ok(canon)
}

/// Validates a restore `destination_parent` directory (rejects symlinks/junctions and any overlap
/// with `state_dir`, `staging_dir`, `mount_point`, or ANY configured backup job's `source_path`).
pub fn validate_restore_destination_parent(
    raw_dest_parent: &str,
    state_dir: &Path,
    staging_dir: &Path,
    mount_point: Option<&Path>,
    jobs: &[StoredBackupJob],
) -> ZeroVaultResult<PathBuf> {
    let trimmed = raw_dest_parent.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(ZeroVaultError::InvalidPath(
            "restore destination folder must not be empty or contain NUL".into(),
        ));
    }

    let dest_parent = PathBuf::from(trimmed);
    // Verify deepest existing ancestor is a real directory and not a symlink/junction.
    let mut probe = Some(dest_parent.as_path());
    while let Some(cur) = probe {
        if cur.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(cur) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err(ZeroVaultError::InvalidPath(
                        "restore destination cannot traverse a symlink or NTFS junction".into(),
                    ));
                }
                if !meta.is_dir() {
                    return Err(ZeroVaultError::InvalidPath(format!(
                        "restore destination path component is not a directory: {}",
                        cur.display()
                    )));
                }
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                probe = cur.parent();
            }
            Err(err) => return Err(err.into()),
        }
    }

    if paths_overlap(&dest_parent, state_dir) {
        return Err(ZeroVaultError::InvalidPath(
            "restore destination cannot overlap EntroCloud's private state directory".into(),
        ));
    }
    if paths_overlap(&dest_parent, staging_dir) {
        return Err(ZeroVaultError::InvalidPath(
            "restore destination cannot overlap EntroCloud's staging directory".into(),
        ));
    }
    if let Some(mp) = mount_point
        && paths_overlap(&dest_parent, mp)
    {
        return Err(ZeroVaultError::InvalidPath(
            "restore destination cannot overlap the active EntroCloud virtual drive mount point"
                .into(),
        ));
    }
    for job in jobs {
        if paths_overlap(&dest_parent, Path::new(&job.source_path)) {
            return Err(ZeroVaultError::InvalidPath(format!(
                "restore destination cannot overlap backed-up folder '{}'",
                job.name
            )));
        }
    }

    Ok(dest_parent)
}

/// Validates and normalizes a [`BackupJobSpec`] into an updated or newly created [`StoredBackupJob`].
pub fn build_stored_backup_job(
    spec: BackupJobSpec,
    existing: Option<&StoredBackupJob>,
    state_dir: &Path,
    staging_dir: &Path,
    mount_point: Option<&Path>,
) -> ZeroVaultResult<StoredBackupJob> {
    let name = spec.name.trim().to_owned();
    if name.is_empty() {
        return Err(ZeroVaultError::ConfigError(
            "backup job name must not be empty".into(),
        ));
    }
    if spec.interval_minutes > MAX_BACKUP_INTERVAL_MINUTES {
        return Err(ZeroVaultError::ConfigError(format!(
            "backup interval_minutes ({}) exceeds maximum ({MAX_BACKUP_INTERVAL_MINUTES})",
            spec.interval_minutes
        )));
    }
    for pat in &spec.excludes {
        if pat.contains('\n') || pat.contains('\r') || pat.contains('\0') {
            return Err(ZeroVaultError::ConfigError(
                "backup exclusion pattern must not contain newline or NUL characters".into(),
            ));
        }
    }

    let canon_src = validate_backup_source_dir(&spec.source_path, state_dir, staging_dir, mount_point)?;
    let clean_src = clean_local_path_display(&canon_src);

    let raw_vf = if spec.vault_folder.trim().is_empty() {
        let safe_leaf: String = name
            .chars()
            .map(|c| {
                if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0')
                    || c.is_control()
                {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        format!("/Backups/{}", safe_leaf.trim_matches(['.', ' ']))
    } else {
        spec.vault_folder.clone()
    };
    let vault_folder = normalize_vault_virtual_path(&raw_vf)?;
    if vault_folder == "/" {
        return Err(ZeroVaultError::InvalidPath(
            "backup vault_folder must be a subdirectory inside the vault (e.g., '/Backups/Documents'), not '/'".into(),
        ));
    }
    for seg in vault_folder.trim_start_matches('/').split('/') {
        validate_portable_entry_name(seg, false)?;
    }

    let id = match spec.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw_id) => {
            if raw_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
                return Err(ZeroVaultError::ConfigError(format!(
                    "backup job id '{raw_id}' contains invalid characters"
                )));
            }
            raw_id.to_owned()
        }
        None => Uuid::new_v4().simple().to_string(),
    };

    let excludes: Vec<String> = spec
        .excludes
        .into_iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(StoredBackupJob {
        id,
        name,
        source_path: clean_src,
        vault_folder,
        interval_minutes: spec.interval_minutes,
        enabled: spec.enabled,
        excludes,
        last_attempt_at: existing.and_then(|e| e.last_attempt_at),
        last_success_at: existing.and_then(|e| e.last_success_at),
        last_error: None,
        last_files_synced: existing.map_or(0, |e| e.last_files_synced),
        last_bytes_synced: existing.map_or(0, |e| e.last_bytes_synced),
    })
}

/// Zero-backtracking iterative glob matcher supporting `*` and `?` (ASCII case-insensitive).
#[must_use]
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();

    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Returns `true` if an entry with relative forward-slash path `rel_path` and basename `entry_name`
/// matches any exclusion rule in `excludes`.
#[must_use]
pub fn should_exclude(rel_path: &str, entry_name: &str, excludes: &[String]) -> bool {
    for raw in excludes {
        let mut pat = raw.trim().replace('\\', "/");
        if let Some(stripped) = pat.strip_prefix("./") {
            pat = stripped.to_owned();
        }
        let clean = pat.trim_matches('/');
        if clean.is_empty() {
            continue;
        }
        if clean.contains('/') {
            if wildcard_match(clean, rel_path) {
                return true;
            }
        } else if wildcard_match(clean, entry_name) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone)]
struct ExistingVaultFile {
    inode: InodeId,
    size: u64,
    modified_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct PendingLocalFile {
    local_path: PathBuf,
    rel_path: String,
    file_name: String,
    parent_vpath: String,
    size: u64,
    modified_at: DateTime<Utc>,
    existing_inode: Option<InodeId>,
}

struct JobScanResult {
    files_scanned: u64,
    files_unchanged: u64,
    pending_uploads: Vec<PendingLocalFile>,
    dir_cache: HashMap<String, InodeId>,
}

async fn preload_existing_vault_tree(
    vfs: &dyn VfsBackend,
    vault_folder: &str,
) -> ZeroVaultResult<(HashMap<String, ExistingVaultFile>, HashMap<String, InodeId>)> {
    let mut files = HashMap::new();
    let mut dirs = HashMap::new();
    dirs.insert("/".to_owned(), ROOT_INODE);

    let root_rec = match vfs.resolve_path(vault_folder).await {
        Ok(rec) => rec,
        Err(ZeroVaultError::InodeNotFound(_) | ZeroVaultError::InvalidPath(_)) => {
            return Ok((files, dirs));
        }
        Err(err) => return Err(err),
    };

    if root_rec.kind != EntryKind::Directory {
        return Err(ZeroVaultError::NotADirectory(root_rec.inode));
    }

    dirs.insert(vault_folder.to_owned(), root_rec.inode);
    let mut stack: Vec<(InodeId, String, String)> =
        vec![(root_rec.inode, String::new(), vault_folder.to_owned())];

    while let Some((dir_inode, rel_prefix, cur_vpath)) = stack.pop() {
        let children = vfs.readdir(dir_inode).await?;
        for child in children {
            let child_rel = if rel_prefix.is_empty() {
                child.name.clone()
            } else {
                format!("{rel_prefix}/{}", child.name)
            };
            let child_vpath = if cur_vpath == "/" {
                format!("/{}", child.name)
            } else {
                format!("{cur_vpath}/{}", child.name)
            };
            match child.kind {
                EntryKind::Directory => {
                    dirs.insert(child_vpath.clone(), child.inode);
                    stack.push((child.inode, child_rel, child_vpath));
                }
                EntryKind::File => {
                    files.insert(
                        child_rel,
                        ExistingVaultFile {
                            inode: child.inode,
                            size: child.size,
                            modified_at: child.modified_at,
                        },
                    );
                }
            }
        }
    }

    Ok((files, dirs))
}

async fn scan_backup_job(
    vfs: &dyn VfsBackend,
    job: &StoredBackupJob,
    state_dir: &Path,
    staging_dir: &Path,
    mount_point: Option<&Path>,
    cancel_flag: &AtomicBool,
) -> ZeroVaultResult<JobScanResult> {
    let canon_src = validate_backup_source_dir(&job.source_path, state_dir, staging_dir, mount_point)?;
    let (existing_files, dir_cache) = preload_existing_vault_tree(vfs, &job.vault_folder).await?;

    let mut files_scanned = 0u64;
    let mut files_unchanged = 0u64;
    let mut pending_uploads = Vec::new();

    let mut stack: Vec<(PathBuf, String)> = vec![(canon_src, String::new())];
    while let Some((cur_dir, rel_dir)) = stack.pop() {
        if cancel_flag.load(Ordering::Acquire) {
            return Err(backup_cancelled_error());
        }

        let mut rd = tokio::fs::read_dir(&cur_dir).await?;
        let mut dir_entries = Vec::new();
        while let Some(entry) = rd.next_entry().await? {
            dir_entries.push(entry);
        }
        dir_entries.sort_by_key(|e| e.file_name());

        let mut subdirs_to_push = Vec::new();
        for entry in dir_entries {
            if cancel_flag.load(Ordering::Acquire) {
                return Err(backup_cancelled_error());
            }

            let entry_path = entry.path();
            let sym_meta = tokio::fs::symlink_metadata(&entry_path).await?;
            // Strictly skip symlinks, NTFS junctions, and reparse points.
            if sym_meta.file_type().is_symlink() || is_symlink_or_reparse(&sym_meta) {
                continue;
            }

            let os_name = entry.file_name();
            let Some(entry_name) = os_name.to_str() else {
                return Err(ZeroVaultError::InvalidPath(format!(
                    "non-UTF-8 filename in backup source: {}",
                    entry_path.display()
                )));
            };
            if entry_name.is_empty() || entry_name == "." || entry_name == ".." {
                continue;
            }

            let rel_path = if rel_dir.is_empty() {
                entry_name.to_owned()
            } else {
                format!("{rel_dir}/{entry_name}")
            };

            if should_exclude(&rel_path, entry_name, &job.excludes) {
                continue;
            }

            validate_portable_entry_name(entry_name, false)?;

            if sym_meta.is_dir() {
                subdirs_to_push.push((entry_path, rel_path));
            } else if sym_meta.is_file() {
                files_scanned = files_scanned.saturating_add(1);
                let local_size = sym_meta.len();
                let local_mtime: DateTime<Utc> = sym_meta
                    .modified()
                    .map(DateTime::<Utc>::from)
                    .unwrap_or_else(|_| Utc::now());

                if let Some(existing) = existing_files.get(&rel_path)
                    && existing.size == local_size
                    && existing.modified_at == local_mtime
                {
                    files_unchanged = files_unchanged.saturating_add(1);
                    continue;
                }

                let parent_vpath = if rel_dir.is_empty() {
                    job.vault_folder.clone()
                } else {
                    format!("{}/{rel_dir}", job.vault_folder)
                };

                pending_uploads.push(PendingLocalFile {
                    local_path: entry_path,
                    rel_path: rel_path.clone(),
                    file_name: entry_name.to_owned(),
                    parent_vpath,
                    size: local_size,
                    modified_at: local_mtime,
                    existing_inode: existing_files.get(&rel_path).map(|e| e.inode),
                });
            }
        }

        // Push in reverse order so lexicographically earlier directories pop first.
        for sub in subdirs_to_push.into_iter().rev() {
            stack.push(sub);
        }
    }

    Ok(JobScanResult {
        files_scanned,
        files_unchanged,
        pending_uploads,
        dir_cache,
    })
}

async fn ensure_cached_virtual_dir(
    vfs: &dyn VfsBackend,
    dir_vpath: &str,
    cache: &mut HashMap<String, InodeId>,
) -> ZeroVaultResult<InodeId> {
    if let Some(&inode) = cache.get(dir_vpath) {
        return Ok(inode);
    }
    let norm = normalize_vault_virtual_path(dir_vpath)?;
    if norm == "/" {
        return Ok(ROOT_INODE);
    }

    let mut cur_inode = ROOT_INODE;
    let mut cur_path = String::new();
    for seg in norm.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        cur_path.push('/');
        cur_path.push_str(seg);
        if let Some(&cached) = cache.get(&cur_path) {
            cur_inode = cached;
            continue;
        }
        let next_inode = match vfs.lookup(cur_inode, seg).await {
            Ok(child) => {
                if child.kind != EntryKind::Directory {
                    return Err(ZeroVaultError::NotADirectory(child.inode));
                }
                child.inode
            }
            Err(ZeroVaultError::InodeNotFound(_)) => vfs.mkdir(cur_inode, seg, 0o755).await?.inode,
            Err(err) => return Err(err),
        };
        cache.insert(cur_path.clone(), next_inode);
        cur_inode = next_inode;
    }

    Ok(cur_inode)
}

/// Formats the canonical dry-run preview completion message.
#[must_use]
pub fn format_preview_message(
    files_uploaded: u64,
    bytes_uploaded: u64,
    files_unchanged: u64,
) -> String {
    format!(
        "Preview complete: {files_uploaded} new/changed file(s) ({bytes_uploaded} B) to upload, {files_unchanged} unchanged skipped. No cloud files modified."
    )
}

/// Formats the canonical live backup completion message.
#[must_use]
pub fn format_backup_message(
    files_uploaded: u64,
    bytes_uploaded: u64,
    files_unchanged: u64,
) -> String {
    format!(
        "Backup complete: {files_uploaded} file(s) ({bytes_uploaded} B) encrypted & synced, {files_unchanged} unchanged skipped."
    )
}

/// Returns `true` when `err` represents an intentional user backup cancellation.
#[must_use]
pub fn is_backup_cancelled_error(err: &ZeroVaultError) -> bool {
    matches!(err, ZeroVaultError::Io(io_err) if io_err.kind() == std::io::ErrorKind::Interrupted)
}

fn backup_cancelled_error() -> ZeroVaultError {
    ZeroVaultError::Io(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "backup cancelled by user",
    ))
}

/// Executes a single backup job (either in zero-write `preview` mode or live bounded-4-MiB upload mode).
#[allow(clippy::too_many_arguments)]
pub async fn execute_single_backup_job(
    bundle: &SyncBackendBundle,
    job: &StoredBackupJob,
    preview: bool,
    has_remotes: bool,
    state_dir: &Path,
    staging_dir: &Path,
    mount_point: Option<&Path>,
    cancel_flag: &AtomicBool,
    active_activity: &SyncRwLock<Option<String>>,
) -> ZeroVaultResult<BackupRunReport> {
    let started = Instant::now();
    if !preview {
        *active_activity.write() = Some(format!("Scanning {}\u{2026}", job.name));
    }

    let mut scan = scan_backup_job(
        bundle.vfs.as_ref(),
        job,
        state_dir,
        staging_dir,
        mount_point,
        cancel_flag,
    )
    .await?;

    if preview {
        let files_uploaded = scan.pending_uploads.len() as u64;
        let bytes_uploaded: u64 = scan.pending_uploads.iter().map(|f| f.size).sum();
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        return Ok(BackupRunReport {
            job_id: job.id.clone(),
            preview: true,
            files_scanned: scan.files_scanned,
            files_uploaded,
            files_unchanged: scan.files_unchanged,
            bytes_uploaded,
            elapsed_ms,
            message: format_preview_message(files_uploaded, bytes_uploaded, scan.files_unchanged),
        });
    }

    let total_to_upload = scan.pending_uploads.len();
    *active_activity.write() = Some(format!(
        "Backing up {} (0/{total_to_upload} files)\u{2026}",
        job.name
    ));

    // Ensure root backup destination folder exists inside the vault even if 0 files changed.
    let _ = ensure_cached_virtual_dir(bundle.vfs.as_ref(), &job.vault_folder, &mut scan.dir_cache)
        .await?;

    let mut files_uploaded = 0u64;
    let mut bytes_uploaded = 0u64;

    if total_to_upload > 0 {
        let mut chunk_buf = Zeroizing::new(vec![0u8; PLAINTEXT_CHUNK_SIZE]);

        for (idx, pending) in scan.pending_uploads.iter().enumerate() {
            if cancel_flag.load(Ordering::Acquire) {
                return Err(backup_cancelled_error());
            }

            *active_activity.write() = Some(format!(
                "Backing up {} ({idx}/{total_to_upload} files)\u{2026}",
                job.name
            ));

            // Re-verify regular file & symlink absence immediately before and after open (TOCTOU safe).
            let pre_meta = tokio::fs::symlink_metadata(&pending.local_path).await?;
            if pre_meta.file_type().is_symlink() || is_symlink_or_reparse(&pre_meta) || !pre_meta.is_file() {
                continue;
            }

            let mut open_opts = OpenOptions::new();
            open_opts.read(true);
            #[cfg(unix)]
            {
                open_opts.custom_flags(libc::O_NOFOLLOW);
            }
            let mut src = open_opts.open(&pending.local_path).await?;
            let handle_meta = src.metadata().await?;
            if handle_meta.file_type().is_symlink()
                || is_symlink_or_reparse(&handle_meta)
                || !handle_meta.is_file()
            {
                return Err(ZeroVaultError::InvalidPath(
                    "backup source file failed TOCTOU regular-file verification".into(),
                ));
            }
            let live_mtime: DateTime<Utc> = handle_meta
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or(pending.modified_at);

            let parent_inode = ensure_cached_virtual_dir(
                bundle.vfs.as_ref(),
                &pending.parent_vpath,
                &mut scan.dir_cache,
            )
            .await?;

            let inode = if let Some(existing_id) = pending.existing_inode {
                bundle
                    .vfs
                    .setattr(
                        existing_id,
                        SetAttrSpec {
                            size: Some(0),
                            mode: None,
                            modified_at: Some(live_mtime),
                        },
                    )
                    .await?
                    .inode
            } else {
                match bundle.vfs.lookup(parent_inode, &pending.file_name).await {
                    Ok(existing) => {
                        if existing.kind == EntryKind::Directory {
                            return Err(ZeroVaultError::IsADirectory(existing.inode));
                        }
                        bundle
                            .vfs
                            .setattr(
                                existing.inode,
                                SetAttrSpec {
                                    size: Some(0),
                                    mode: None,
                                    modified_at: Some(live_mtime),
                                },
                            )
                            .await?
                            .inode
                    }
                    Err(ZeroVaultError::InodeNotFound(_)) => {
                        bundle
                            .vfs
                            .create_entry(CreateEntrySpec {
                                parent_inode,
                                name: pending.file_name.clone(),
                                mode: 0o644,
                            })
                            .await?
                            .inode
                    }
                    Err(err) => return Err(err),
                }
            };

            let mut offset = 0u64;
            loop {
                if cancel_flag.load(Ordering::Acquire) {
                    return Err(backup_cancelled_error());
                }
                let mut filled = 0usize;
                while filled < chunk_buf.len() {
                    let n = src.read(&mut chunk_buf[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                if cancel_flag.load(Ordering::Acquire) {
                    return Err(backup_cancelled_error());
                }
                bundle
                    .vfs
                    .write_range(inode, offset, &chunk_buf[..filled])
                    .await?;
                offset = offset.saturating_add(filled as u64);
                if filled < chunk_buf.len() {
                    break;
                }
            }

            // Stamp the exact local file modification timestamp on the vault inode for O(1) incremental skip!
            let _ = bundle
                .vfs
                .setattr(
                    inode,
                    SetAttrSpec {
                        size: None,
                        mode: None,
                        modified_at: Some(live_mtime),
                    },
                )
                .await?;

            files_uploaded = files_uploaded.saturating_add(1);
            bytes_uploaded = bytes_uploaded.saturating_add(offset);

            let done = idx + 1;
            *active_activity.write() = Some(format!(
                "Backing up {} ({done}/{total_to_upload} files)\u{2026}",
                job.name
            ));
            let _ = &pending.rel_path;
        }
    }

    if cancel_flag.load(Ordering::Acquire) {
        return Err(backup_cancelled_error());
    }

    if has_remotes {
        let job_name = job.name.clone();
        *active_activity.write() = Some(format!("Syncing {job_name} to cloud\u{2026}"));
        if let Some(ref engine) = bundle.sync_engine {
            let progress_cb = |done: usize, total: usize| {
                *active_activity.write() = Some(format!(
                    "Uploading {job_name} to cloud ({done}/{total} files)\u{2026}"
                ));
            };
            let _ = engine
                .sync_once_with_options(Some(cancel_flag), Some(&progress_cb))
                .await?;
        } else if let Some(ref runner) = bundle.sync_runner {
            runner.sync_now().await?;
        }
    }

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(BackupRunReport {
        job_id: job.id.clone(),
        preview: false,
        files_scanned: scan.files_scanned,
        files_uploaded,
        files_unchanged: scan.files_unchanged,
        bytes_uploaded,
        elapsed_ms,
        message: format_backup_message(files_uploaded, bytes_uploaded, scan.files_unchanged),
    })
}

/// Formats a fresh timestamped restore directory name: `"EntroCloud Restore YYYY-MM-DD HHmmss-<short4>"`.
#[must_use]
pub fn make_restore_folder_name(now: DateTime<Utc>) -> String {
    let ts = now.format("%Y-%m-%d %H%M%S");
    let short4 = &Uuid::new_v4().simple().to_string()[..4];
    format!("EntroCloud Restore {ts}-{short4}")
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use tempfile::TempDir;

    use super::*;

    fn sample_job() -> StoredBackupJob {
        StoredBackupJob {
            id: "job1".to_owned(),
            name: "Documents".to_owned(),
            source_path: "/tmp/docs".to_owned(),
            vault_folder: "/Backups/Documents".to_owned(),
            interval_minutes: 15,
            enabled: true,
            excludes: DEFAULT_BACKUP_EXCLUDES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            last_attempt_at: None,
            last_success_at: None,
            last_error: None,
            last_files_synced: 0,
            last_bytes_synced: 0,
        }
    }

    #[test]
    fn job_status_priority_matches_contract() {
        let mut job = sample_job();
        assert_eq!(compute_job_status(&job, false, false, None), "Locked");
        assert_eq!(compute_job_status(&job, true, false, Some("job1")), "Backing up\u{2026}");
        assert_eq!(compute_job_status(&job, true, true, None), "Paused");

        job.last_error = Some("network timeout".to_owned());
        assert_eq!(compute_job_status(&job, true, false, None), "Needs attention");
        job.last_error = None;

        job.enabled = false;
        assert_eq!(compute_job_status(&job, true, false, None), "Manual");
        job.enabled = true;
        job.interval_minutes = 0;
        assert_eq!(compute_job_status(&job, true, false, None), "Manual");
        job.interval_minutes = 15;

        assert_eq!(compute_job_status(&job, true, false, None), "Ready");
        job.last_success_at = Some(Utc::now());
        assert_eq!(compute_job_status(&job, true, false, None), "Backed up");
    }

    #[test]
    fn schedule_policy_enforces_debounce_cadence_and_error_backoff() {
        let now = Utc::now();
        let mut job = sample_job();

        // Never attempted -> due immediately when unlocked & unpaused.
        assert!(SchedulePolicy::is_due(&job, false, true, now));
        assert!(!SchedulePolicy::is_due(&job, true, true, now));
        assert!(!SchedulePolicy::is_due(&job, false, false, now));

        // 30s ago -> blocked by 60s min debounce even with interval=1 min.
        job.interval_minutes = 1;
        job.last_attempt_at = Some(now - ChronoDuration::seconds(30));
        assert!(!SchedulePolicy::is_due(&job, false, true, now));

        // 61s ago with interval=15 min -> not yet due on normal cadence.
        job.interval_minutes = 15;
        job.last_attempt_at = Some(now - ChronoDuration::seconds(61));
        assert!(!SchedulePolicy::is_due(&job, false, true, now));

        // Error retry backoff: min(15, 5) = 5 minutes.
        job.last_error = Some("transient cloud failure".to_owned());
        job.last_attempt_at = Some(now - ChronoDuration::minutes(4));
        assert!(!SchedulePolicy::is_due(&job, false, true, now));
        job.last_attempt_at = Some(now - ChronoDuration::minutes(5));
        assert!(SchedulePolicy::is_due(&job, false, true, now));

        // Normal 15-min cadence.
        job.last_error = None;
        job.last_attempt_at = Some(now - ChronoDuration::minutes(15));
        assert!(SchedulePolicy::is_due(&job, false, true, now));
    }

    #[test]
    fn wildcard_excludes_match_cloudbridge_defaults() {
        let excludes: Vec<String> = DEFAULT_BACKUP_EXCLUDES
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert!(should_exclude("desktop.ini", "desktop.ini", &excludes));
        assert!(should_exclude("Sub/DESKTOP.INI", "DESKTOP.INI", &excludes));
        assert!(should_exclude("Photos/Thumbs.db", "Thumbs.db", &excludes));
        assert!(should_exclude("Finance/~$Budget2026.xlsx", "~$Budget2026.xlsx", &excludes));
        assert!(should_exclude("Work/draft.TMP", "draft.TMP", &excludes));
        assert!(should_exclude(".DS_Store", ".DS_Store", &excludes));
        assert!(!should_exclude("Finance/Budget2026.xlsx", "Budget2026.xlsx", &excludes));
    }

    #[test]
    fn path_overlap_detects_ancestors_and_ignores_sibling_prefixes() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let docs = tmp.path().join("Docs");
        let docs_sub = docs.join("2026");
        let docs_archive = tmp.path().join("DocsArchive");
        std::fs::create_dir_all(&docs_sub)?;
        std::fs::create_dir_all(&docs_archive)?;

        assert!(paths_overlap(&docs, &docs));
        assert!(paths_overlap(&docs, &docs_sub));
        assert!(paths_overlap(&docs_sub, &docs));
        assert!(paths_overlap(&docs, &docs.join("nonexistent_future_restore")));
        assert!(!paths_overlap(&docs, &docs_archive));
        Ok(())
    }
}
