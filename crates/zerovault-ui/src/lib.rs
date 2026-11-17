//! Zerovault Tauri v2 desktop UI view-models, embedded/IPC daemon bridge, and Tauri commands.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock as SyncRwLock;
use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager, State, WindowEvent,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tokio::sync::Mutex as AsyncMutex;
use zerovault_crypto::AwsLcCryptoEngine;
use zerovault_daemon::{DaemonRuntime, DaemonStateConfig, IpcClient, IpcEndpoint, IpcServer};
use zerovault_types::{
    AddRemoteParams, BackendQuota, CryptoBenchmarkReport, CryptoEngine, DaemonRequest,
    DaemonResponse, EntryKind, HardwareCryptoCaps, HydrationState, OAuthLoginParams, RoutingPolicy,
    VaultEntrySummary, VaultStatusReport,
};

/// Shared Tauri application state bridging either an external `zerovaultd` IPC endpoint
/// or an auto-started embedded [`DaemonRuntime`] so the GUI works standalone with zero CLI setup.
#[derive(Clone)]
pub struct UiAppState {
    ipc_client: IpcClient,
    embedded_runtime: Arc<AsyncMutex<Option<Arc<DaemonRuntime>>>>,
    daemon_mode: Arc<SyncRwLock<String>>,
    allow_embedded_fallback: bool,
    embedded_state_dir: Option<PathBuf>,
}

impl fmt::Debug for UiAppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.daemon_mode.read().clone();
        f.debug_struct("UiAppState")
            .field("ipc_endpoint", &self.ipc_client.endpoint().to_string())
            .field("daemon_mode", &mode)
            .field("allow_embedded_fallback", &self.allow_embedded_fallback)
            .finish_non_exhaustive()
    }
}

impl Default for UiAppState {
    fn default() -> Self {
        Self {
            ipc_client: IpcClient::default(),
            embedded_runtime: Arc::new(AsyncMutex::new(None)),
            daemon_mode: Arc::new(SyncRwLock::new("Connecting...".to_owned())),
            allow_embedded_fallback: true,
            embedded_state_dir: None,
        }
    }
}

impl UiAppState {
    /// Creates UI state targeting a specific external IPC endpoint without embedded fallback.
    #[must_use]
    pub fn with_ipc_only(ipc_client: IpcClient) -> Self {
        Self {
            ipc_client,
            embedded_runtime: Arc::new(AsyncMutex::new(None)),
            daemon_mode: Arc::new(SyncRwLock::new("External Daemon (IPC)".to_owned())),
            allow_embedded_fallback: false,
            embedded_state_dir: None,
        }
    }

    /// Creates UI state backed directly by an isolated in-process embedded engine inside `state_dir`.
    #[must_use]
    pub fn with_embedded_state_dir(state_dir: PathBuf) -> Self {
        Self {
            ipc_client: IpcClient::default(),
            embedded_runtime: Arc::new(AsyncMutex::new(None)),
            daemon_mode: Arc::new(SyncRwLock::new("Embedded Engine".to_owned())),
            allow_embedded_fallback: true,
            embedded_state_dir: Some(state_dir),
        }
    }

    /// Returns the active daemon execution mode label (`"External Daemon (IPC)"` or `"Embedded Engine"`).
    #[must_use]
    pub fn daemon_mode_label(&self) -> String {
        self.daemon_mode.read().clone()
    }

    /// Dispatches a [`DaemonRequest`] to the active external daemon or auto-started embedded engine.
    pub async fn dispatch(&self, req: DaemonRequest) -> Result<DaemonResponse, String> {
        let existing = {
            let guard = self.embedded_runtime.lock().await;
            guard.clone()
        };
        if let Some(rt) = existing {
            return Ok(rt.handle_request(req).await);
        }

        if self.embedded_state_dir.is_none() {
            match self.ipc_client.request(&req).await {
                Ok(resp) => {
                    {
                        *self.daemon_mode.write() = "External Daemon (IPC)".to_owned();
                    }
                    return Ok(resp);
                }
                Err(ipc_err) => {
                    if !self.allow_embedded_fallback {
                        return Err(ipc_err.to_string());
                    }
                }
            }
        }

        let rt = self.ensure_embedded_runtime().await?;
        Ok(rt.handle_request(req).await)
    }

    async fn ensure_embedded_runtime(&self) -> Result<Arc<DaemonRuntime>, String> {
        let mut guard = self.embedded_runtime.lock().await;
        if let Some(rt) = guard.as_ref() {
            return Ok(Arc::clone(rt));
        }

        let state_dir = self
            .embedded_state_dir
            .clone()
            .unwrap_or_else(DaemonStateConfig::default_state_dir);
        let cfg = DaemonStateConfig::new(state_dir);
        let runtime = Arc::new(
            DaemonRuntime::new_default(cfg)
                .map_err(|err| format!("failed starting embedded Zerovault engine: {err}"))?,
        );

        // Expose local IPC listener when running in desktop mode so `zv` CLI can also attach.
        if self.embedded_state_dir.is_none()
            && let Ok(endpoint) = IpcEndpoint::from_env_or_default()
        {
            match IpcServer::bind(endpoint).await {
                Ok(server) => {
                    let rt_dispatch = Arc::clone(&runtime);
                    let notify = runtime.shutdown_notify();
                    tracing::info!(
                        endpoint = %server.endpoint(),
                        "zerovault-ui started embedded engine with local IPC listener"
                    );
                    tokio::spawn(async move {
                        let shutdown_fut = async move {
                            notify.notified().await;
                        };
                        if let Err(err) = server
                            .serve_with_shutdown(
                                move |req| {
                                    let rt = Arc::clone(&rt_dispatch);
                                    async move { rt.handle_request(req).await }
                                },
                                shutdown_fut,
                            )
                            .await
                        {
                            tracing::warn!(error = %err, "embedded IPC listener exited");
                        }
                    });
                }
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        "running embedded engine in-process without local IPC listener"
                    );
                }
            }
        }

        *guard = Some(Arc::clone(&runtime));
        drop(guard);
        {
            *self.daemon_mode.write() = "Embedded Engine".to_owned();
        }
        Ok(runtime)
    }

    /// Gracefully unmounts any mounted drive and zeroizes keys if running an embedded engine.
    pub async fn graceful_stop(&self) {
        let rt = {
            let guard = self.embedded_runtime.lock().await;
            guard.clone()
        };
        if let Some(runtime) = rt
            && let Err(err) = runtime.graceful_shutdown().await
        {
            tracing::warn!(error = %err, "error shutting down embedded Zerovault engine");
        }
    }

    /// Sends a request expecting [`DaemonResponse::Ok`].
    pub async fn send_ok(&self, req: DaemonRequest) -> Result<String, String> {
        match self.dispatch(req).await? {
            DaemonResponse::Ok { message } => Ok(message),
            DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
            other => Err(format!("unexpected daemon response: {other:?}")),
        }
    }

    /// Fetches full daemon/vault status mapped into [`TrayStatusViewModel`].
    pub async fn fetch_status_vm(&self) -> TrayStatusViewModel {
        match self.dispatch(DaemonRequest::Status).await {
            Ok(DaemonResponse::Status(report)) => {
                build_status_view_model_with_context(&report, &self.daemon_mode_label())
            }
            Ok(DaemonResponse::Error { code, message }) => {
                offline_status_view_model(&format!("[{code}] {message}"))
            }
            Ok(other) => offline_status_view_model(&format!("unexpected status response: {other:?}")),
            Err(err) => offline_status_view_model(&err),
        }
    }

    /// Lists entries inside a vault virtual directory.
    pub async fn list_vault_dir(&self, virtual_path: String) -> Result<DirectoryListingViewModel, String> {
        match self
            .dispatch(DaemonRequest::ListDirectory { virtual_path })
            .await?
        {
            DaemonResponse::DirectoryEntries {
                virtual_path,
                entries,
            } => Ok(DirectoryListingViewModel {
                virtual_path,
                entries: entries.iter().map(build_entry_view_model).collect(),
            }),
            DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
            other => Err(format!("unexpected directory response: {other:?}")),
        }
    }

    /// Lists non-destructive conflict records sorted newest-first.
    pub async fn list_conflicts_vm(&self) -> Result<Vec<ConflictViewModel>, String> {
        match self.dispatch(DaemonRequest::ListConflicts).await? {
            DaemonResponse::Conflicts(items) => Ok(items
                .into_iter()
                .map(|c| ConflictViewModel {
                    original_path: c.original_path,
                    conflict_path: c.conflict_path,
                    remote_revision: c.remote_revision,
                    detected_at: c.detected_at.to_rfc3339(),
                })
                .collect()),
            DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
            other => Err(format!("unexpected conflicts response: {other:?}")),
        }
    }

    /// Encrypts and imports dropped/selected local files and directories (skipping symlinks)
    /// into `virtual_dir` using bounded 4 MiB chunk streaming.
    pub async fn import_paths_into_vault(
        &self,
        local_paths: Vec<String>,
        virtual_dir: String,
    ) -> Result<String, String> {
        if local_paths.is_empty() {
            return Err("No local files selected to import".to_owned());
        }
        let target_dir = normalize_ui_vpath(&virtual_dir);
        let mut imported_files = 0usize;
        let mut created_dirs = 0usize;
        let mut last_msg = String::new();

        for raw_path in local_paths {
            let trimmed = raw_path.trim();
            if trimmed.is_empty() {
                continue;
            }
            let src_path = PathBuf::from(trimmed);
            let meta = std::fs::symlink_metadata(&src_path)
                .map_err(|err| format!("Failed inspecting local path: {err}"))?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_file() {
                last_msg = self
                    .send_ok(DaemonRequest::ImportLocalFile {
                        local_path: trimmed.to_owned(),
                        virtual_dest_path: target_dir.clone(),
                    })
                    .await?;
                imported_files += 1;
                continue;
            }
            if meta.is_dir() {
                let Some(dir_name) = src_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty() && *s != "." && *s != "..")
                else {
                    return Err("Dropped directory has an invalid or non-UTF-8 name".to_owned());
                };
                let root_vpath = join_ui_vpath(&target_dir, dir_name);
                if self.create_dir_idempotent(&root_vpath).await? {
                    created_dirs += 1;
                }

                let mut stack: Vec<(PathBuf, String)> = vec![(src_path, root_vpath)];
                while let Some((cur_dir, cur_vpath)) = stack.pop() {
                    let read_dir = std::fs::read_dir(&cur_dir)
                        .map_err(|err| format!("Failed reading dropped directory: {err}"))?;
                    let mut children = Vec::new();
                    for item in read_dir {
                        let Ok(entry) = item else {
                            continue;
                        };
                        children.push(entry.path());
                    }
                    children.sort();

                    for child_path in children {
                        let Ok(cmeta) = std::fs::symlink_metadata(&child_path) else {
                            continue;
                        };
                        if cmeta.file_type().is_symlink() {
                            continue;
                        }
                        let Some(name_str) = child_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
                        else {
                            continue;
                        };
                        if cmeta.is_dir() {
                            let sub_vpath = join_ui_vpath(&cur_vpath, name_str);
                            if self.create_dir_idempotent(&sub_vpath).await? {
                                created_dirs += 1;
                            }
                            stack.push((child_path, sub_vpath));
                        } else if cmeta.is_file() {
                            last_msg = self
                                .send_ok(DaemonRequest::ImportLocalFile {
                                    local_path: child_path.to_string_lossy().into_owned(),
                                    virtual_dest_path: cur_vpath.clone(),
                                })
                                .await?;
                            imported_files += 1;
                        }
                    }
                }
            }
        }

        if imported_files == 1 && created_dirs == 0 {
            Ok(last_msg)
        } else if imported_files == 0 && created_dirs == 0 {
            Err("No regular files or directories imported (symlinks skipped)".to_owned())
        } else {
            Ok(format!(
                "Encrypted & imported {imported_files} file(s) across {created_dirs} folder(s)"
            ))
        }
    }

    async fn create_dir_idempotent(&self, virtual_path: &str) -> Result<bool, String> {
        match self
            .dispatch(DaemonRequest::CreateDirectory {
                virtual_path: virtual_path.to_owned(),
            })
            .await?
        {
            DaemonResponse::Ok { .. } => Ok(true),
            DaemonResponse::Error { code, .. } if code == "already_exists" => Ok(false),
            DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
            other => Err(format!("unexpected create directory response: {other:?}")),
        }
    }
}

fn normalize_ui_vpath(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_owned()
    } else {
        let parts: Vec<&str> = trimmed
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        if parts.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", parts.join("/"))
        }
    }
}

fn join_ui_vpath(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Returns a concise label describing the host OS virtual filesystem driver.
#[must_use]
pub fn platform_vfs_label() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Windows Cloud Files API (CfApi)"
    }
    #[cfg(target_os = "linux")]
    {
        "Linux FUSE3 (User-Space)"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        "Portable Virtual Drive"
    }
}

/// Returns the default OS sync root / mount directory path (`~/Zerovault`).
#[must_use]
pub fn default_mount_point() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Zerovault")
        .display()
        .to_string()
}

/// Formatted remote account badge data rendered in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteBadgeViewModel {
    /// Backend identifier.
    pub id: String,
    /// Provider kind (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`).
    pub kind: String,
    /// Configured root folder/prefix.
    pub root: String,
    /// Whether recent requests succeeded.
    pub healthy: bool,
    /// Formatted latency indicator (e.g. `"12 ms"` or `"--"`).
    pub latency_label: String,
    /// Formatted per-remote quota summary.
    pub quota_label: String,
    /// Raw used bytes on this remote.
    pub used_bytes: u64,
    /// Raw total quota bytes on this remote.
    pub total_bytes: u64,
    /// Non-sensitive error message, if unhealthy.
    pub last_error: Option<String>,
}

/// Complete desktop & tray dashboard view-model derived from [`VaultStatusReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrayStatusViewModel {
    /// Whether `zerovaultd` or the embedded engine answered the status request.
    pub daemon_reachable: bool,
    /// Active engine connection mode (`"Embedded Engine"` or `"External Daemon (IPC)"`).
    pub daemon_mode: String,
    /// Whether a vault header (`vault.zvh`) exists on disk.
    pub vault_initialized: bool,
    /// Active vault UUID string, if initialized.
    pub vault_id: Option<String>,
    /// Whether master keys are currently unlocked in daemon memory.
    pub unlocked: bool,
    /// Whether the virtual drive is mounted.
    pub mounted: bool,
    /// Active mount point path string, if mounted.
    pub mount_point: Option<String>,
    /// Native OS VFS driver label for display.
    pub platform_vfs_label: String,
    /// Default suggested OS mount directory path.
    pub default_mount_point: String,
    /// Human-readable sync state (`"Idle"`, `"Syncing (3 pending)"`, `"Locked"`, `"Daemon Offline"`).
    pub sync_state: String,
    /// Formatted upload throughput (e.g. `"12.50 MiB/s"`).
    pub upload_rate: String,
    /// Formatted download throughput (e.g. `"48.00 MiB/s"`).
    pub download_rate: String,
    /// Raw upload throughput in bytes/sec.
    pub upload_bytes_per_sec: u64,
    /// Raw download throughput in bytes/sec.
    pub download_bytes_per_sec: u64,
    /// Number of queued dirty sync operations.
    pub pending_dirty_ops: usize,
    /// Number of non-destructive conflicts recorded.
    pub conflict_count: usize,
    /// Current encrypted manifest revision.
    pub manifest_revision: u64,
    /// Formatted pooled cloud storage quota summary.
    pub quota_summary: String,
    /// Pooled quota fill percentage (`0.0..=100.0`).
    pub quota_used_percent: f64,
    /// Raw pooled used bytes.
    pub quota_used_bytes: u64,
    /// Raw pooled total bytes.
    pub quota_total_bytes: u64,
    /// Formatted decrypted chunk RAM cache occupancy.
    pub cache_ram_label: String,
    /// Formatted cumulative virtual bytes hydrated/read.
    pub bytes_read_label: String,
    /// Formatted cumulative virtual bytes written.
    pub bytes_written_label: String,
    /// Total 4 MiB chunks hydrated on demand.
    pub chunks_hydrated: u64,
    /// Total local cache hits.
    pub cache_hits: u64,
    /// Active routing policy summary label.
    pub routing_policy: String,
    /// Raw structured routing policy for the interactive routing editor.
    pub routing_policy_raw: Option<RoutingPolicy>,
    /// Per-remote health & quota badges.
    pub remotes: Vec<RemoteBadgeViewModel>,
    /// Optional non-sensitive status/connectivity error banner.
    pub error_message: Option<String>,
}

/// UI-friendly representation of one encrypted file or directory inside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntryViewModel {
    /// Virtual inode ID.
    pub inode: u64,
    /// Basename.
    pub name: String,
    /// Full normalized virtual path.
    pub virtual_path: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// `"dir"` or `"file"`.
    pub kind: String,
    /// Plaintext byte size (`0` for directories).
    pub size: u64,
    /// Human-readable byte size (`"--"` for directories).
    pub size_label: String,
    /// Canonical hydration slug (`"online-only"`, `"partially-hydrated"`, `"cached"`, `"pinned"`, `"dirty"`).
    pub hydration: String,
    /// Human-readable hydration badge text.
    pub hydration_label: String,
    /// Whether entry is explicitly pinned offline.
    pub pinned: bool,
    /// Monotonic node version.
    pub version: u64,
    /// ISO-8601 modification timestamp.
    pub modified_at: String,
}

/// Directory listing view-model returned by `list_vault_dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryListingViewModel {
    /// Normalized virtual directory path.
    pub virtual_path: String,
    /// Sorted entries inside the directory.
    pub entries: Vec<VaultEntryViewModel>,
}

/// UI conflict preservation row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictViewModel {
    /// Original conflicted virtual path.
    pub original_path: String,
    /// Preserved conflict copy path.
    pub conflict_path: String,
    /// Remote manifest revision where conflict occurred.
    pub remote_revision: u64,
    /// ISO-8601 timestamp recorded.
    pub detected_at: String,
}

/// Form payload for adding a remote storage backend from the GUI.
#[derive(Clone, Deserialize)]
pub struct AddRemoteUiInput {
    pub id: String,
    pub kind: String,
    pub root: String,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub quota_mib: Option<u64>,
    pub policy: Option<String>,
    pub prefix: Option<String>,
    pub username: Option<String>,
    pub secret: Option<String>,
}

impl fmt::Debug for AddRemoteUiInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddRemoteUiInput")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("root", &self.root)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Form payload for browser OAuth2 + PKCE remote onboarding from the GUI.
#[derive(Clone, Deserialize)]
pub struct OAuthLoginUiInput {
    pub id: String,
    pub kind: String,
    pub root: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub quota_mib: Option<u64>,
    pub policy: Option<String>,
    pub prefix: Option<String>,
}

impl fmt::Debug for OAuthLoginUiInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthLoginUiInput")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Form payload for switching multi-cloud routing policies live in the GUI.
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingPolicyUiInput {
    pub mode: String,
    pub backends: Vec<String>,
    pub min_ack: Option<usize>,
    pub default_backend: Option<String>,
    pub prefix_routes: Vec<(String, String)>,
}

/// Quick navigation bookmark for the built-in local filesystem picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalQuickRoot {
    /// Display label (`"Home"`, `"Desktop"`, `"C:\\"`, etc.).
    pub label: String,
    /// Absolute directory path.
    pub path: String,
}

/// Local filesystem entry returned to the file/folder picker modal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFsEntry {
    /// File or directory name.
    pub name: String,
    /// Full local path.
    pub path: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Byte size (`0` for directories).
    pub size: u64,
    /// Human-readable size label.
    pub size_label: String,
}

/// Local directory snapshot for the built-in desktop file/folder picker modal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFsListing {
    /// Normalized current directory path.
    pub current_path: String,
    /// Parent directory path if not at filesystem root.
    pub parent_path: Option<String>,
    /// Quick root bookmarks.
    pub quick_roots: Vec<LocalQuickRoot>,
    /// Directory and (optionally) file entries sorted folders-first.
    pub entries: Vec<LocalFsEntry>,
}

/// Formats an arbitrary byte count using binary IEC units (`B`, `KiB`, `MiB`, `GiB`, `TiB`).
#[must_use]
pub fn format_bytes_human(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.2} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.2} MiB", b / MIB)
    } else if b < TIB {
        format!("{:.2} GiB", b / GIB)
    } else {
        format!("{:.2} TiB", b / TIB)
    }
}

/// Formats a byte-per-second throughput rate for UI display (e.g. `"24.50 MiB/s"`).
#[must_use]
pub fn format_bytes_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes_human(bytes_per_sec))
}

/// Formats a [`BackendQuota`] into a concise pooled storage meter summary string.
#[must_use]
pub fn format_quota_summary(quota: Option<&BackendQuota>) -> String {
    let Some(q) = quota else {
        return "No cloud quota configured".to_owned();
    };

    if q.total_bytes == 0 {
        return format!(
            "{} / 0 B (0.0% used, 0 B free)",
            format_bytes_human(q.used_bytes)
        );
    }

    let pct = ((q.used_bytes as f64) / (q.total_bytes as f64) * 100.0).clamp(0.0, 100.0);
    format!(
        "{} / {} ({pct:.1}% used, {} free)",
        format_bytes_human(q.used_bytes),
        format_bytes_human(q.total_bytes),
        format_bytes_human(q.available_bytes),
    )
}

/// Formats a [`VaultEntrySummary`] into a [`VaultEntryViewModel`].
#[must_use]
pub fn build_entry_view_model(entry: &VaultEntrySummary) -> VaultEntryViewModel {
    let is_dir = entry.kind == EntryKind::Directory;
    let hydration_label = if is_dir {
        "Folder".to_owned()
    } else {
        match entry.hydration {
            HydrationState::OnlineOnly => "Online-Only".to_owned(),
            HydrationState::PartiallyHydrated => "Partial Cache".to_owned(),
            HydrationState::LocallyCached => "Locally Cached".to_owned(),
            HydrationState::Pinned => "Pinned Offline".to_owned(),
            HydrationState::DirtyLocal => "Pending Sync".to_owned(),
        }
    };

    VaultEntryViewModel {
        inode: entry.inode,
        name: entry.name.clone(),
        virtual_path: entry.virtual_path.clone(),
        is_dir,
        kind: if is_dir {
            "dir".to_owned()
        } else {
            "file".to_owned()
        },
        size: entry.size,
        size_label: if is_dir {
            "--".to_owned()
        } else {
            format_bytes_human(entry.size)
        },
        hydration: entry.hydration.as_xattr_str().to_owned(),
        hydration_label,
        pinned: entry.pinned,
        version: entry.version,
        modified_at: entry.modified_at.to_rfc3339(),
    }
}

/// Converts a [`VaultStatusReport`] returned by `zerovaultd` into a [`TrayStatusViewModel`].
#[must_use]
pub fn build_status_view_model(report: &VaultStatusReport) -> TrayStatusViewModel {
    build_status_view_model_with_context(report, "External Daemon (IPC)")
}

/// Converts a [`VaultStatusReport`] with explicit daemon connection mode metadata.
#[must_use]
pub fn build_status_view_model_with_context(
    report: &VaultStatusReport,
    daemon_mode: &str,
) -> TrayStatusViewModel {
    let sync_state = if report.vault_id.is_none() {
        "Needs Setup".to_owned()
    } else if !report.unlocked {
        "Locked".to_owned()
    } else if report.throughput.pending_dirty_ops > 0 {
        format!("Syncing ({} pending)", report.throughput.pending_dirty_ops)
    } else if report.mounted {
        "Idle (Mounted)".to_owned()
    } else {
        "Unlocked".to_owned()
    };

    let (quota_used_bytes, quota_total_bytes, quota_used_percent) = match report.pooled_quota.as_ref()
    {
        Some(q) if q.total_bytes > 0 => {
            let pct = ((q.used_bytes as f64) / (q.total_bytes as f64) * 100.0).clamp(0.0, 100.0);
            (q.used_bytes, q.total_bytes, pct)
        }
        Some(q) => (q.used_bytes, 0, 0.0),
        None => (0, 0, 0.0),
    };

    let routing_policy = match report.routing_policy.as_ref() {
        None => "Unconfigured".to_owned(),
        Some(RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        }) => format!("Targeted ({default_backend}, {} rules)", prefix_routes.len()),
        Some(RoutingPolicy::Mirrored { backends, min_ack }) => {
            format!("Mirrored RAID-1 ({}x, ack>={min_ack})", backends.len())
        }
        Some(RoutingPolicy::QuotaPooled { pool_backends }) => {
            format!("Quota-Pooled ({} accounts)", pool_backends.len())
        }
    };

    let remotes = report
        .remotes
        .iter()
        .map(|r| RemoteBadgeViewModel {
            id: r.id.clone(),
            kind: r.kind.clone(),
            root: r.root.clone(),
            healthy: r.health.healthy,
            latency_label: r
                .health
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "--".to_owned()),
            quota_label: format!(
                "{} / {}",
                format_bytes_human(r.health.quota.used_bytes),
                format_bytes_human(r.health.quota.total_bytes)
            ),
            used_bytes: r.health.quota.used_bytes,
            total_bytes: r.health.quota.total_bytes,
            last_error: r.health.last_error.clone(),
        })
        .collect();

    TrayStatusViewModel {
        daemon_reachable: true,
        daemon_mode: daemon_mode.to_owned(),
        vault_initialized: report.vault_id.is_some(),
        vault_id: report.vault_id.map(|id| id.to_string()),
        unlocked: report.unlocked,
        mounted: report.mounted,
        mount_point: report.mount_point.clone(),
        platform_vfs_label: platform_vfs_label().to_owned(),
        default_mount_point: default_mount_point(),
        sync_state,
        upload_rate: format_bytes_rate(report.throughput.upload_bytes_per_sec),
        download_rate: format_bytes_rate(report.throughput.download_bytes_per_sec),
        upload_bytes_per_sec: report.throughput.upload_bytes_per_sec,
        download_bytes_per_sec: report.throughput.download_bytes_per_sec,
        pending_dirty_ops: report.throughput.pending_dirty_ops,
        conflict_count: report.conflict_count,
        manifest_revision: report.manifest_revision,
        quota_summary: format_quota_summary(report.pooled_quota.as_ref()),
        quota_used_percent,
        quota_used_bytes,
        quota_total_bytes,
        cache_ram_label: format_bytes_human(report.throughput.cache_bytes_used),
        bytes_read_label: format_bytes_human(report.drive_stats.bytes_read),
        bytes_written_label: format_bytes_human(report.drive_stats.bytes_written),
        chunks_hydrated: report.drive_stats.chunks_hydrated,
        cache_hits: report.drive_stats.cache_hits,
        routing_policy,
        routing_policy_raw: report.routing_policy.clone(),
        remotes,
        error_message: None,
    }
}

/// Builds a graceful offline view-model when `zerovaultd` is unreachable or returns an error.
#[must_use]
pub fn offline_status_view_model(error: &str) -> TrayStatusViewModel {
    TrayStatusViewModel {
        daemon_reachable: false,
        daemon_mode: "Offline".to_owned(),
        vault_initialized: false,
        vault_id: None,
        unlocked: false,
        mounted: false,
        mount_point: None,
        platform_vfs_label: platform_vfs_label().to_owned(),
        default_mount_point: default_mount_point(),
        sync_state: "Engine Offline".to_owned(),
        upload_rate: format_bytes_rate(0),
        download_rate: format_bytes_rate(0),
        upload_bytes_per_sec: 0,
        download_bytes_per_sec: 0,
        pending_dirty_ops: 0,
        conflict_count: 0,
        manifest_revision: 0,
        quota_summary: format_quota_summary(None),
        quota_used_percent: 0.0,
        quota_used_bytes: 0,
        quota_total_bytes: 0,
        cache_ram_label: format_bytes_human(0),
        bytes_read_label: format_bytes_human(0),
        bytes_written_label: format_bytes_human(0),
        chunks_hydrated: 0,
        cache_hits: 0,
        routing_policy: "Unconfigured".to_owned(),
        routing_policy_raw: None,
        remotes: Vec::new(),
        error_message: Some(error.to_owned()),
    }
}

/// Validates and maps a [`RoutingPolicyUiInput`] into a [`RoutingPolicy`].
pub fn build_routing_policy(input: RoutingPolicyUiInput) -> Result<RoutingPolicy, String> {
    let mode = input.mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "pooled" | "quota-pooled" | "quota_pooled" => {
            if input.backends.is_empty() {
                return Err("Select at least one cloud backend for Quota-Pooled mode".to_owned());
            }
            Ok(RoutingPolicy::QuotaPooled {
                pool_backends: input.backends,
            })
        }
        "mirrored" | "raid1" | "raid-1" => {
            if input.backends.is_empty() {
                return Err("Select at least one cloud backend for Mirrored RAID-1".to_owned());
            }
            let min_ack = input.min_ack.unwrap_or(1).clamp(1, input.backends.len());
            Ok(RoutingPolicy::Mirrored {
                backends: input.backends,
                min_ack,
            })
        }
        "targeted" => {
            let default_backend = input
                .default_backend
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .or_else(|| input.backends.first().cloned())
                .ok_or_else(|| {
                    "Select a default cloud backend for Targeted routing".to_owned()
                })?;
            let mut prefix_routes = Vec::with_capacity(input.prefix_routes.len());
            for (raw_prefix, raw_backend) in input.prefix_routes {
                let pfx = raw_prefix.trim();
                let bk = raw_backend.trim();
                if pfx.is_empty() || bk.is_empty() {
                    continue;
                }
                prefix_routes.push((pfx.to_owned(), bk.to_owned()));
            }
            Ok(RoutingPolicy::Targeted {
                prefix_routes,
                default_backend,
            })
        }
        other => Err(format!("Unsupported routing mode '{other}'")),
    }
}

/// Detects local hardware AES-256-GCM acceleration capabilities (`AES-NI` / `VAES` / `PCLMULQDQ`).
pub fn detect_hardware_caps_sync() -> Result<HardwareCryptoCaps, String> {
    let engine = AwsLcCryptoEngine::new()
        .map_err(|err| format!("hardware AES-256-GCM initialization failed: {err}"))?;
    engine
        .verify_hardware_acceleration()
        .map_err(|err| format!("CPUID verification failed: {err}"))
}

/// Runs a 4 MiB chunk AES-256-GCM hardware benchmark (`mib` clamped to `4..=512`).
pub fn run_crypto_benchmark_sync(mib: usize) -> Result<CryptoBenchmarkReport, String> {
    let clamped = mib.clamp(4, 512);
    let engine = AwsLcCryptoEngine::new()
        .map_err(|err| format!("hardware AES-256-GCM initialization failed: {err}"))?;
    engine
        .benchmark_aes256_gcm(clamped)
        .map_err(|err| format!("crypto benchmark failed: {err}"))
}

/// Opens a local mounted or staging directory in the OS file manager (`explorer.exe` / `xdg-open`).
pub fn open_directory_in_file_manager(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Directory path must not be empty".to_owned());
    }
    let dir = Path::new(trimmed);
    if !dir.exists() || !dir.is_dir() {
        return Err(format!("Directory does not exist: {trimmed}"));
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer.exe")
            .arg(dir)
            .spawn()
            .map_err(|err| format!("failed opening Explorer: {err}"))?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(dir)
            .spawn()
            .map_err(|err| format!("failed opening Finder: {err}"))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .map_err(|err| format!("failed opening file manager: {err}"))?;
    }

    Ok(format!("Opened {trimmed}"))
}

/// Enumerates local filesystem quick roots and sorted folder/file entries for the GUI picker.
pub fn browse_local_fs_sync(
    path: Option<&str>,
    include_files: bool,
) -> Result<LocalFsListing, String> {
    let quick_roots = collect_quick_roots();
    let target_dir = match path.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => PathBuf::from(raw),
        None => dirs::home_dir()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from(".")),
    };

    if !target_dir.exists() || !target_dir.is_dir() {
        return Err(format!(
            "Directory does not exist: {}",
            target_dir.display()
        ));
    }

    let canonical = target_dir.canonicalize().unwrap_or(target_dir);
    let current_path = clean_display_path(&canonical);
    let parent_path = canonical.parent().map(clean_display_path);

    let read_dir = std::fs::read_dir(&canonical)
        .map_err(|err| format!("Failed reading {}: {err}", current_path))?;

    let mut entries = Vec::new();
    for item in read_dir {
        let Ok(dir_entry) = item else {
            continue;
        };
        let Ok(meta) = dir_entry.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        if !is_dir && !include_files {
            continue;
        }
        let name = dir_entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() {
            continue;
        }
        let full_path = clean_display_path(&dir_entry.path());
        let size = if is_dir { 0 } else { meta.len() };
        entries.push(LocalFsEntry {
            name,
            path: full_path,
            is_dir,
            size,
            size_label: if is_dir {
                "Folder".to_owned()
            } else {
                format_bytes_human(size)
            },
        });
    }

    entries.sort_by(|a, b| {
        (!a.is_dir, a.name.to_ascii_lowercase(), &a.name).cmp(&(
            !b.is_dir,
            b.name.to_ascii_lowercase(),
            &b.name,
        ))
    });

    Ok(LocalFsListing {
        current_path,
        parent_path,
        quick_roots,
        entries,
    })
}

/// Creates a new local directory inside `parent_path` from the local folder picker modal.
pub fn create_local_dir_sync(parent_path: &str, name: &str) -> Result<String, String> {
    let parent_trimmed = parent_path.trim();
    let name_trimmed = name.trim();
    if parent_trimmed.is_empty() {
        return Err("Parent directory path must not be empty".to_owned());
    }
    if name_trimmed.is_empty()
        || name_trimmed == "."
        || name_trimmed == ".."
        || name_trimmed.contains('/')
        || name_trimmed.contains('\\')
        || name_trimmed.contains('\0')
    {
        return Err("Invalid folder name".to_owned());
    }
    let target = Path::new(parent_trimmed).join(name_trimmed);
    if target.exists() {
        return Err(format!("Folder already exists: {}", target.display()));
    }
    std::fs::create_dir_all(&target)
        .map_err(|err| format!("Failed creating directory: {err}"))?;
    Ok(clean_display_path(&target))
}

fn clean_display_path(path: &Path) -> String {
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

fn collect_quick_roots() -> Vec<LocalQuickRoot> {
    let mut roots = Vec::new();
    let candidates = [
        ("Home", dirs::home_dir()),
        ("Desktop", dirs::desktop_dir()),
        ("Documents", dirs::document_dir()),
        ("Downloads", dirs::download_dir()),
    ];
    for (label, maybe_path) in candidates {
        if let Some(p) = maybe_path
            && p.exists()
        {
            roots.push(LocalQuickRoot {
                label: label.to_owned(),
                path: clean_display_path(&p),
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", char::from(letter));
            if Path::new(&drive).exists() {
                roots.push(LocalQuickRoot {
                    label: format!("Drive {}:", char::from(letter)),
                    path: drive,
                });
            }
        }
    }

    #[cfg(unix)]
    {
        roots.push(LocalQuickRoot {
            label: "Root /".to_owned(),
            path: "/".to_owned(),
        });
    }

    roots
}

fn non_empty_opt(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Tauri IPC command handlers wired into [`tauri::generate_handler!`].
pub mod commands {
    use super::*;

    /// Tauri IPC command fetching current daemon/vault status for the desktop UI.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn fetch_status(state: State<'_, UiAppState>) -> Result<TrayStatusViewModel, String> {
        Ok(state.fetch_status_vm().await)
    }

    /// Tauri IPC command initializing a brand-new encrypted vault (`DaemonRequest::InitVault`).
    #[tauri::command(rename_all = "snake_case")]
    pub async fn init_vault(
        state: State<'_, UiAppState>,
        passphrase: String,
    ) -> Result<String, String> {
        state.send_ok(DaemonRequest::InitVault { passphrase }).await
    }

    /// Tauri IPC command unlocking an existing vault (`DaemonRequest::UnlockVault`).
    #[tauri::command(rename_all = "snake_case")]
    pub async fn unlock_vault(
        state: State<'_, UiAppState>,
        passphrase: String,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::UnlockVault { passphrase })
            .await
    }

    /// Tauri IPC command immediately locking the vault and zeroizing RAM keys (`DaemonRequest::LockVault`).
    #[tauri::command(rename_all = "snake_case")]
    pub async fn lock_vault(state: State<'_, UiAppState>) -> Result<String, String> {
        state.send_ok(DaemonRequest::LockVault).await
    }

    /// Tauri IPC command triggering an immediate daemon sync (`DaemonRequest::SyncNow`).
    #[tauri::command(rename_all = "snake_case")]
    pub async fn sync_now(state: State<'_, UiAppState>) -> Result<String, String> {
        state.send_ok(DaemonRequest::SyncNow).await
    }

    /// Tauri IPC command listing entries inside a virtual vault directory.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn list_vault_dir(
        state: State<'_, UiAppState>,
        virtual_path: String,
    ) -> Result<DirectoryListingViewModel, String> {
        state.list_vault_dir(virtual_path).await
    }

    /// Tauri IPC command creating a new virtual directory inside the vault.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn create_vault_dir(
        state: State<'_, UiAppState>,
        virtual_path: String,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::CreateDirectory { virtual_path })
            .await
    }

    /// Tauri IPC command encrypting and importing local files or folders into `virtual_dir`.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn import_local_files(
        state: State<'_, UiAppState>,
        local_paths: Vec<String>,
        virtual_dir: String,
    ) -> Result<String, String> {
        state
            .import_paths_into_vault(local_paths, virtual_dir)
            .await
    }

    /// Tauri IPC command decrypting and exporting a vault file to `local_dest_path`.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn export_vault_file(
        state: State<'_, UiAppState>,
        virtual_path: String,
        local_dest_path: String,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::ExportVaultFile {
                virtual_path,
                local_dest_path,
            })
            .await
    }

    /// Tauri IPC command deleting a virtual file or directory.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn delete_vault_entry(
        state: State<'_, UiAppState>,
        virtual_path: String,
        recursive: bool,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::DeleteEntry {
                virtual_path,
                recursive,
            })
            .await
    }

    /// Tauri IPC command renaming or moving a virtual file or directory.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn rename_vault_entry(
        state: State<'_, UiAppState>,
        virtual_path: String,
        new_name_or_path: String,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::RenameEntry {
                virtual_path,
                new_virtual_path: new_name_or_path,
            })
            .await
    }

    /// Tauri IPC command pinning a virtual entry offline and hydrating all chunks.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn pin_vault_entry(
        state: State<'_, UiAppState>,
        virtual_path: String,
    ) -> Result<String, String> {
        state.send_ok(DaemonRequest::Pin { virtual_path }).await
    }

    /// Tauri IPC command clearing an offline pin flag.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn unpin_vault_entry(
        state: State<'_, UiAppState>,
        virtual_path: String,
    ) -> Result<String, String> {
        state.send_ok(DaemonRequest::Unpin { virtual_path }).await
    }

    /// Tauri IPC command dehydrating a virtual entry back to online-only state.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn dehydrate_vault_entry(
        state: State<'_, UiAppState>,
        virtual_path: String,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::Dehydrate { virtual_path })
            .await
    }

    /// Tauri IPC command registering a non-OAuth or pre-tokenized cloud remote.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn add_remote(
        state: State<'_, UiAppState>,
        params: AddRemoteUiInput,
    ) -> Result<String, String> {
        let req = DaemonRequest::AddRemote(Box::new(AddRemoteParams {
            id: params.id,
            kind: params.kind,
            root: params.root,
            endpoint: non_empty_opt(params.endpoint),
            bucket: non_empty_opt(params.bucket),
            region: non_empty_opt(params.region),
            quota_limit_bytes: params.quota_mib.map(|m| m.saturating_mul(1024 * 1024)),
            policy: non_empty_opt(params.policy),
            prefix: non_empty_opt(params.prefix),
            username: non_empty_opt(params.username),
            secret: params.secret.filter(|s| !s.is_empty()),
        }));
        state.send_ok(req).await
    }

    /// Tauri IPC command starting interactive browser OAuth2 + PKCE remote sign-in.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn oauth_login_remote(
        state: State<'_, UiAppState>,
        params: OAuthLoginUiInput,
    ) -> Result<String, String> {
        let req = DaemonRequest::OAuthLogin(Box::new(OAuthLoginParams {
            id: params.id,
            kind: params.kind,
            root: params.root,
            client_id: params.client_id,
            client_secret: non_empty_opt(params.client_secret),
            auth_url: non_empty_opt(params.auth_url),
            token_url: non_empty_opt(params.token_url),
            quota_limit_bytes: params.quota_mib.map(|m| m.saturating_mul(1024 * 1024)),
            policy: non_empty_opt(params.policy),
            prefix: non_empty_opt(params.prefix),
            timeout_secs: Some(180),
            open_browser: true,
        }));
        state.send_ok(req).await
    }

    /// Tauri IPC command removing a configured remote cloud backend.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn remove_remote(
        state: State<'_, UiAppState>,
        id: String,
    ) -> Result<String, String> {
        state.send_ok(DaemonRequest::RemoveRemote { id }).await
    }

    /// Tauri IPC command switching multi-cloud routing policy live.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn set_routing_policy(
        state: State<'_, UiAppState>,
        input: RoutingPolicyUiInput,
    ) -> Result<String, String> {
        let policy = build_routing_policy(input)?;
        state
            .send_ok(DaemonRequest::SetRoutingPolicy { policy })
            .await
    }

    /// Tauri IPC command mounting the virtual drive (`CfApi`/`FUSE3` or `MockDrive`).
    #[tauri::command(rename_all = "snake_case")]
    pub async fn mount_drive(
        state: State<'_, UiAppState>,
        mount_point: String,
        use_mock_vfs: bool,
    ) -> Result<String, String> {
        state
            .send_ok(DaemonRequest::MountWithOptions {
                mount_point,
                use_mock_vfs,
            })
            .await
    }

    /// Tauri IPC command unmounting the active virtual drive.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn unmount_drive(state: State<'_, UiAppState>) -> Result<String, String> {
        state.send_ok(DaemonRequest::Unmount).await
    }

    /// Tauri IPC command opening a local directory in Windows Explorer / Linux file manager.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn open_in_file_manager(path: String) -> Result<String, String> {
        open_directory_in_file_manager(&path)
    }

    /// Tauri IPC command listing non-destructive conflict preservation records.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn list_conflicts(
        state: State<'_, UiAppState>,
    ) -> Result<Vec<ConflictViewModel>, String> {
        state.list_conflicts_vm().await
    }

    /// Tauri IPC command verifying runtime CPUID hardware AES/GHASH capabilities.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn get_hardware_caps() -> Result<HardwareCryptoCaps, String> {
        detect_hardware_caps_sync()
    }

    /// Tauri IPC command running an on-demand 4 MiB AES-256-GCM throughput benchmark.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn run_crypto_benchmark(mib: usize) -> Result<CryptoBenchmarkReport, String> {
        tokio::task::spawn_blocking(move || run_crypto_benchmark_sync(mib))
            .await
            .map_err(|err| format!("benchmark worker failed: {err}"))?
    }

    /// Tauri IPC command browsing local folders/files for the built-in desktop picker modal.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn browse_local_fs(
        path: Option<String>,
        include_files: bool,
    ) -> Result<LocalFsListing, String> {
        tokio::task::spawn_blocking(move || browse_local_fs_sync(path.as_deref(), include_files))
            .await
            .map_err(|err| format!("local filesystem browser failed: {err}"))?
    }

    /// Tauri IPC command creating a local directory inside the folder picker modal.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn create_local_dir(parent_path: String, name: String) -> Result<String, String> {
        create_local_dir_sync(&parent_path, &name)
    }

    /// Tauri IPC command gracefully unmounting, zeroizing keys, and exiting the desktop app.
    #[tauri::command(rename_all = "snake_case")]
    pub async fn quit_app(app: AppHandle, state: State<'_, UiAppState>) -> Result<(), String> {
        state.graceful_stop().await;
        app.exit(0);
        Ok(())
    }
}

pub use commands::{
    add_remote, browse_local_fs, create_local_dir, create_vault_dir, dehydrate_vault_entry,
    delete_vault_entry, export_vault_file, fetch_status, get_hardware_caps, import_local_files,
    init_vault, list_conflicts, list_vault_dir, lock_vault, mount_drive, oauth_login_remote,
    open_in_file_manager, pin_vault_entry, quit_app, remove_remote, rename_vault_entry,
    run_crypto_benchmark, set_routing_policy, sync_now, unlock_vault, unmount_drive,
    unpin_vault_entry,
};

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let visible = window.is_visible().unwrap_or(false);
        let minimized = window.is_minimized().unwrap_or(false);
        let focused = window.is_focused().unwrap_or(false);
        if visible && !minimized && focused {
            let _ = window.hide();
        } else {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Configures the Tauri v2 system tray icon, menu actions, and minimize-to-tray lifecycle.
pub fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open_item = MenuItem::with_id(app, "open_dashboard", "Open Zerovault", true, None::<&str>)?;
    let sync_item = MenuItem::with_id(app, "sync_now", "Sync Now", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock_vault", "Lock Vault", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Zerovault", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open_item, &sync_item, &lock_item, &quit_item])?;

    let mut tray_builder = TrayIconBuilder::with_id("zerovault-tray")
        .menu(&menu)
        .tooltip("Zerovault — Zero-Knowledge Multi-Cloud Drive")
        .show_menu_on_left_click(false);

    if let Some(icon) = app.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    }

    let tray_result = tray_builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open_dashboard" => show_main_window(app),
            "sync_now" => {
                let ui_state = app.state::<UiAppState>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = ui_state.send_ok(DaemonRequest::SyncNow).await {
                        tracing::warn!(error = %err, "tray menu sync_now failed");
                    }
                });
            }
            "lock_vault" => {
                let ui_state = app.state::<UiAppState>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = ui_state.send_ok(DaemonRequest::LockVault).await {
                        tracing::warn!(error = %err, "tray menu lock_vault failed");
                    }
                });
            }
            "quit" => {
                let ui_state = app.state::<UiAppState>().inner().clone();
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    ui_state.graceful_stop().await;
                    handle.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_main_window(tray.app_handle());
            }
        })
        .build(app);

    match tray_result {
        Ok(_) => {
            if let Some(main_win) = app.get_webview_window("main") {
                let main_clone = main_win.clone();
                main_win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = main_clone.hide();
                    }
                });
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "system tray unavailable on this desktop environment; closing the main window will exit"
            );
            if let Some(main_win) = app.get_webview_window("main") {
                let ui_state = app.state::<UiAppState>().inner().clone();
                let handle = app.handle().clone();
                let closing = Arc::new(AtomicBool::new(false));
                main_win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event
                        && !closing.swap(true, Ordering::AcqRel)
                    {
                        api.prevent_close();
                        let state_clone = ui_state.clone();
                        let app_handle = handle.clone();
                        tauri::async_runtime::spawn(async move {
                            state_clone.graceful_stop().await;
                            app_handle.exit(0);
                        });
                    }
                });
            }
        }
    }

    Ok(())
}

/// Runs the Zerovault Tauri v2 desktop application and tray integration.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .manage(UiAppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::fetch_status,
            commands::init_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::sync_now,
            commands::list_vault_dir,
            commands::create_vault_dir,
            commands::import_local_files,
            commands::export_vault_file,
            commands::delete_vault_entry,
            commands::rename_vault_entry,
            commands::pin_vault_entry,
            commands::unpin_vault_entry,
            commands::dehydrate_vault_entry,
            commands::add_remote,
            commands::oauth_login_remote,
            commands::remove_remote,
            commands::set_routing_policy,
            commands::mount_drive,
            commands::unmount_drive,
            commands::open_in_file_manager,
            commands::list_conflicts,
            commands::get_hardware_caps,
            commands::run_crypto_benchmark,
            commands::browse_local_fs,
            commands::create_local_dir,
            commands::quit_app,
        ])
        .setup(|app| setup_tray(app))
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::TempDir;
    use zerovault_types::{
        BackendHealth, BackendKind, BackendQuota, DriveStats, RemoteAccountSummary, RoutingPolicy,
        ThroughputSnapshot, VaultStatusReport,
    };

    use super::*;

    #[test]
    fn formats_bytes_rates_and_quota_summaries() {
        assert_eq!(format_bytes_rate(0), "0 B/s");
        assert_eq!(format_bytes_rate(512), "512 B/s");
        assert_eq!(format_bytes_rate(1536), "1.50 KiB/s");
        assert_eq!(format_bytes_rate(10 * 1024 * 1024), "10.00 MiB/s");
        assert_eq!(format_bytes_rate(2 * 1024 * 1024 * 1024), "2.00 GiB/s");

        assert_eq!(format_quota_summary(None), "No cloud quota configured");

        let zero_quota = BackendQuota {
            backend_id: "pool".to_owned(),
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
        };
        assert_eq!(
            format_quota_summary(Some(&zero_quota)),
            "0 B / 0 B (0.0% used, 0 B free)"
        );

        let quota = BackendQuota {
            backend_id: "pool-total".to_owned(),
            total_bytes: 15 * 1024 * 1024 * 1024,
            used_bytes: 3 * 1024 * 1024 * 1024,
            available_bytes: 12 * 1024 * 1024 * 1024,
        };
        assert_eq!(
            format_quota_summary(Some(&quota)),
            "3.00 GiB / 15.00 GiB (20.0% used, 12.00 GiB free)"
        );
    }

    #[test]
    fn builds_tray_status_view_model_from_report() {
        let report = VaultStatusReport {
            vault_id: Some(uuid::Uuid::new_v4()),
            unlocked: true,
            mounted: true,
            mount_point: Some("/mnt/zerovault".to_owned()),
            manifest_revision: 42,
            routing_policy: Some(RoutingPolicy::QuotaPooled {
                pool_backends: vec!["gdrive-1".to_owned(), "s3-2".to_owned()],
            }),
            remotes: vec![RemoteAccountSummary {
                id: "gdrive-1".to_owned(),
                kind: "gdrive".to_owned(),
                root: "/zerovault".to_owned(),
                health: BackendHealth {
                    backend_id: "gdrive-1".to_owned(),
                    kind: BackendKind::GoogleDrive,
                    healthy: true,
                    latency_ms: Some(18),
                    last_error: None,
                    quota: BackendQuota {
                        backend_id: "gdrive-1".to_owned(),
                        total_bytes: 15 * 1024 * 1024 * 1024,
                        used_bytes: 5 * 1024 * 1024 * 1024,
                        available_bytes: 10 * 1024 * 1024 * 1024,
                    },
                },
            }],
            pooled_quota: Some(BackendQuota {
                backend_id: "pool-total".to_owned(),
                total_bytes: 20 * 1024 * 1024 * 1024,
                used_bytes: 5 * 1024 * 1024 * 1024,
                available_bytes: 15 * 1024 * 1024 * 1024,
            }),
            throughput: ThroughputSnapshot {
                upload_bytes_per_sec: 16 * 1024 * 1024,
                download_bytes_per_sec: 64 * 1024 * 1024,
                pending_dirty_ops: 2,
                cache_bytes_used: 8 * 1024 * 1024,
                sampled_at: None,
            },
            drive_stats: DriveStats::default(),
            conflict_count: 1,
        };

        let vm = build_status_view_model(&report);
        assert!(vm.daemon_reachable);
        assert!(vm.vault_initialized);
        assert!(vm.unlocked);
        assert!(vm.mounted);
        assert_eq!(vm.sync_state, "Syncing (2 pending)");
        assert_eq!(vm.upload_rate, "16.00 MiB/s");
        assert_eq!(vm.download_rate, "64.00 MiB/s");
        assert!((vm.quota_used_percent - 25.0).abs() < 0.01);
        assert_eq!(vm.routing_policy, "Quota-Pooled (2 accounts)");
        assert_eq!(vm.cache_ram_label, "8.00 MiB");
        assert_eq!(vm.remotes.len(), 1);
        assert_eq!(vm.remotes[0].latency_label, "18 ms");
        assert_eq!(vm.conflict_count, 1);

        let offline = offline_status_view_model("pipe not found");
        assert!(!offline.daemon_reachable);
        assert!(!offline.vault_initialized);
        assert_eq!(offline.sync_state, "Engine Offline");
        assert_eq!(offline.error_message.as_deref(), Some("pipe not found"));
    }

    #[test]
    fn routing_policy_builder_and_local_fs_browser_work() {
        let pooled = build_routing_policy(RoutingPolicyUiInput {
            mode: "pooled".to_owned(),
            backends: vec!["a".to_owned(), "b".to_owned()],
            min_ack: None,
            default_backend: None,
            prefix_routes: Vec::new(),
        })
        .expect("pooled");
        assert_eq!(
            pooled,
            RoutingPolicy::QuotaPooled {
                pool_backends: vec!["a".to_owned(), "b".to_owned()]
            }
        );

        let mirrored = build_routing_policy(RoutingPolicyUiInput {
            mode: "mirrored".to_owned(),
            backends: vec!["a".to_owned(), "b".to_owned()],
            min_ack: Some(2),
            default_backend: None,
            prefix_routes: Vec::new(),
        })
        .expect("mirrored");
        assert_eq!(
            mirrored,
            RoutingPolicy::Mirrored {
                backends: vec!["a".to_owned(), "b".to_owned()],
                min_ack: 2
            }
        );

        let targeted = build_routing_policy(RoutingPolicyUiInput {
            mode: "targeted".to_owned(),
            backends: vec!["a".to_owned(), "b".to_owned()],
            min_ack: None,
            default_backend: Some("a".to_owned()),
            prefix_routes: vec![("/Docs".to_owned(), "b".to_owned())],
        })
        .expect("targeted");
        assert_eq!(
            targeted,
            RoutingPolicy::Targeted {
                prefix_routes: vec![("/Docs".to_owned(), "b".to_owned())],
                default_backend: "a".to_owned()
            }
        );

        let tmp = TempDir::new().expect("tempdir");
        let sub = create_local_dir_sync(tmp.path().to_str().expect("utf8"), "NewFolder")
            .expect("create local dir");
        std::fs::write(tmp.path().join("notes.txt"), b"hello").expect("write file");

        let dirs_only = browse_local_fs_sync(tmp.path().to_str(), false).expect("browse dirs");
        assert_eq!(dirs_only.entries.len(), 1);
        assert!(dirs_only.entries[0].is_dir);
        assert_eq!(dirs_only.entries[0].name, "NewFolder");

        let with_files = browse_local_fs_sync(tmp.path().to_str(), true).expect("browse all");
        assert_eq!(with_files.entries.len(), 2);
        assert!(Path::new(&sub).is_dir());
        assert!(create_local_dir_sync(tmp.path().to_str().expect("utf8"), "../bad").is_err());

        let caps = detect_hardware_caps_sync().expect("hw caps");
        assert!(caps.mandatory_satisfied);

        let entry_vm = build_entry_view_model(&VaultEntrySummary {
            inode: 2,
            name: "doc.pdf".to_owned(),
            virtual_path: "/doc.pdf".to_owned(),
            kind: EntryKind::File,
            size: 2048,
            hydration: HydrationState::Pinned,
            pinned: true,
            version: 1,
            modified_at: Utc::now(),
        });
        assert_eq!(entry_vm.hydration_label, "Pinned Offline");
        assert_eq!(entry_vm.size_label, "2.00 KiB");
    }

    #[tokio::test]
    async fn embedded_ui_state_auto_starts_and_manages_vault_without_cli() {
        let tmp = TempDir::new().expect("tempdir");
        let state_dir = tmp.path().join("ui_state");
        let remote_dir = tmp.path().join("remote_cloud");
        let mount_dir = tmp.path().join("mount_root");
        let sample_src = tmp.path().join("hello.txt");
        let sample_dst = tmp.path().join("hello_out.txt");
        std::fs::write(&sample_src, b"zero-knowledge standalone desktop ui test")
            .expect("write fixture");

        let ui_state = UiAppState::with_embedded_state_dir(state_dir.clone());

        let initial_vm = ui_state.fetch_status_vm().await;
        assert!(initial_vm.daemon_reachable);
        assert_eq!(initial_vm.daemon_mode, "Embedded Engine");
        assert!(!initial_vm.vault_initialized);
        assert!(!initial_vm.unlocked);

        ui_state
            .send_ok(DaemonRequest::InitVault {
                passphrase: "standalone-gui-passphrase".to_owned(),
            })
            .await
            .expect("init vault");

        let after_init = ui_state.fetch_status_vm().await;
        assert!(after_init.vault_initialized);
        assert!(after_init.unlocked);

        ui_state
            .send_ok(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                id: "local-1".to_owned(),
                kind: "fs".to_owned(),
                root: remote_dir.to_string_lossy().into_owned(),
                endpoint: None,
                bucket: None,
                region: None,
                quota_limit_bytes: Some(32 * 1024 * 1024),
                policy: Some("pooled".to_owned()),
                prefix: None,
                username: None,
                secret: None,
            })))
            .await
            .expect("add remote");

        ui_state
            .send_ok(DaemonRequest::CreateDirectory {
                virtual_path: "/Notes".to_owned(),
            })
            .await
            .expect("mkdir");
        ui_state
            .send_ok(DaemonRequest::ImportLocalFile {
                local_path: sample_src.to_string_lossy().into_owned(),
                virtual_dest_path: "/Notes".to_owned(),
            })
            .await
            .expect("import");

        let listing = ui_state
            .list_vault_dir("/Notes".to_owned())
            .await
            .expect("list /Notes");
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "hello.txt");

        ui_state
            .send_ok(DaemonRequest::ExportVaultFile {
                virtual_path: "/Notes/hello.txt".to_owned(),
                local_dest_path: sample_dst.to_string_lossy().into_owned(),
            })
            .await
            .expect("export");
        assert_eq!(
            std::fs::read(&sample_dst).expect("read exported"),
            b"zero-knowledge standalone desktop ui test"
        );

        ui_state
            .send_ok(DaemonRequest::MountWithOptions {
                mount_point: mount_dir.to_string_lossy().into_owned(),
                use_mock_vfs: true,
            })
            .await
            .expect("mount");
        assert!(ui_state.fetch_status_vm().await.mounted);

        // Verify dropped folder + nested subfolder import
        let drop_root = tmp.path().join("DroppedFolder");
        let drop_sub = drop_root.join("Nested");
        std::fs::create_dir_all(&drop_sub).expect("mkdir dropped");
        std::fs::write(drop_root.join("top.txt"), b"top-contents").expect("write top");
        std::fs::write(drop_sub.join("inner.txt"), b"inner-contents").expect("write inner");

        let import_folder_msg = ui_state
            .import_paths_into_vault(
                vec![drop_root.to_string_lossy().into_owned()],
                "/".to_owned(),
            )
            .await
            .expect("import dropped folder");
        assert!(import_folder_msg.contains("2 file(s)"));
        let nested_listing = ui_state
            .list_vault_dir("/DroppedFolder/Nested".to_owned())
            .await
            .expect("list nested");
        assert_eq!(nested_listing.entries.len(), 1);
        assert_eq!(nested_listing.entries[0].name, "inner.txt");

        ui_state.graceful_stop().await;
        let locked_vm = ui_state.fetch_status_vm().await;
        assert!(!locked_vm.unlocked);
        assert!(!locked_vm.mounted);
    }
}
