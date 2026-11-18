//! Non-blocking background IPC worker thread for `entrocloud`.
//!
//! Keeps the `eframe`/`glow` GPU render thread 100% responsive during vault key derivation,
//! file imports/exports, backup runs, hardware speed tests, and interactive browser OAuth2 sign-in
//! (which runs on a dedicated short-lived thread so status polling and `CancelOAuth` never block).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use eframe::egui;
use entrocloud_types::{
    AddRemoteParams, BackupJobSpec, BackupRunReport, ConflictRecord, CryptoBenchmarkReport,
    DaemonRequest, DaemonResponse, DetectedCloudFolder, KeyboxSummary, OAuthLoginParams,
    RemoteTestReport, RoutingPolicy, VaultEntrySummary, VaultStatusReport,
};
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::ipc_client::IpcClient;
use crate::session::{
    count_session_preview_files, export_for_secure_preview, import_local_paths_recursive,
    normalize_ui_vpath, open_in_os_default_app, scrub_session_dir,
};
use crate::tray_common::format_bytes_human;

const SPARKLINE_HISTORY_LEN: usize = 72;
const MAX_NOTE_BYTES: usize = 2 * 1024 * 1024;

/// Commands sent from the `egui` UI thread to the background IPC worker thread.
pub enum UiCommand {
    /// Poll `Status` (and `ListDirectory` for `current_dir` when unlocked).
    RefreshAll {
        current_dir: String,
    },
    /// Attempt to auto-start sibling `entrocloudd` and refresh status.
    ReconnectOrAutostart {
        current_dir: String,
    },
    /// Initialize a brand-new encrypted vault with `passphrase` (zeroized on drop).
    InitVault {
        passphrase: Zeroizing<String>,
    },
    /// Unlock an existing vault with `passphrase` (zeroized on drop).
    UnlockVault {
        passphrase: Zeroizing<String>,
        current_dir: String,
    },
    /// Immediately lock the vault in `entrocloudd` AND zero-wipe all preview temp files.
    LockVault,
    /// Mount the virtual drive at `mount_point`.
    MountDrive {
        mount_point: String,
        use_mock_vfs: bool,
    },
    /// Unmount the active virtual drive.
    UnmountDrive,
    /// Trigger an immediate sync pass (`DaemonRequest::SyncNow`).
    SyncNow,
    /// List a virtual directory inside the vault.
    ListDirectory {
        virtual_path: String,
    },
    /// Create a new virtual folder inside `parent_dir`.
    CreateDirectory {
        virtual_path: String,
        refresh_dir: String,
    },
    /// Encrypt & import local files/folders recursively (skipping symlinks) into `target_dir`.
    ImportLocalPaths {
        local_paths: Vec<PathBuf>,
        target_dir: String,
    },
    /// Decrypt & export a vault file to `local_dest_path`.
    ExportVaultFile {
        virtual_path: String,
        local_dest_path: String,
    },
    /// Export a vault file into private `session_dir` and open in OS default app.
    PreviewVaultFile {
        virtual_path: String,
    },
    /// Manually zero-overwrite and delete all temporary preview files in `session_dir`.
    ScrubPreviewsNow,
    /// Toggle offline pin (`Pin` / `Unpin`) on `virtual_path`.
    SetPinned {
        virtual_path: String,
        pinned: bool,
        refresh_dir: String,
    },
    /// Free up local disk space (`Unpin` + `Dehydrate`).
    FreeUpSpace {
        virtual_path: String,
        refresh_dir: String,
    },
    /// Rename or move an entry inside the vault.
    RenameEntry {
        virtual_path: String,
        new_virtual_path: String,
        refresh_dir: String,
    },
    /// Delete a file or folder inside the vault.
    DeleteEntry {
        virtual_path: String,
        recursive: bool,
        refresh_dir: String,
    },
    /// Read an encrypted UTF-8 text note (`<= 2 MiB`) directly into memory (zero temp files).
    ReadTextNote {
        virtual_path: String,
    },
    /// Save an in-memory UTF-8 text note (`<= 2 MiB`) directly into encrypted chunks (zero temp files).
    SaveTextNote {
        virtual_path: String,
        content: Zeroizing<String>,
        refresh_dir: String,
    },
    /// Scan installed local cloud sync directories (`DetectLocalClouds`).
    DetectLocalClouds,
    /// Add a storage backend (`AddRemote`).
    AddRemote {
        params: Box<AddRemoteParams>,
    },
    /// Remove a storage backend (`RemoveRemote`).
    RemoveRemote {
        id: String,
    },
    /// Probe connectivity, latency, and quota for a configured cloud (`TestRemote`).
    TestRemote {
        id: String,
    },
    /// Run interactive browser OAuth2 + PKCE login (`OAuthLogin`) on a dedicated short-lived thread.
    OAuthLogin {
        params: Box<OAuthLoginParams>,
    },
    /// Cancel an in-progress interactive browser OAuth2 login (`CancelOAuth`).
    CancelOAuth,
    /// Apply a live multi-cloud routing policy (`SetRoutingPolicy`).
    SetRoutingPolicy {
        policy: RoutingPolicy,
    },
    /// Create or update an automatic PC folder backup job (`UpsertBackupJob`).
    UpsertBackupJob {
        spec: Box<BackupJobSpec>,
    },
    /// Remove an automatic PC folder backup job (`RemoveBackupJob`).
    RemoveBackupJob {
        id: String,
    },
    /// Run or dry-run preview a specific PC folder backup job (`RunBackupJob`).
    RunBackupJob {
        id: String,
        preview: bool,
    },
    /// Run or dry-run preview all enabled PC folder backup jobs (`RunAllBackups`).
    RunAllBackups {
        preview: bool,
    },
    /// Restore a backed-up folder into a clean subfolder inside `destination_parent` (`RestoreBackupJob`).
    RestoreBackupJob {
        id: String,
        destination_parent: String,
    },
    /// Pause or resume automatic background PC folder backups (`SetBackupsPaused`).
    SetBackupsPaused {
        paused: bool,
    },
    /// Stop any active backup transfer and pause scheduling (`CancelActiveBackup`).
    CancelActiveBackup,
    /// Generate/export local invite code (`ExportRecipientBundle`).
    ExportRecipientBundle {
        label: String,
    },
    /// Create a 1-click read-only `ec://` private share link for `virtual_path`.
    CreateCapabilityShare {
        virtual_path: String,
    },
    /// Import an `ec://` or legacy `zv://` private share link into `dest_virtual_path`.
    ImportCapabilityShare {
        uri: Zeroizing<String>,
        dest_virtual_path: String,
        refresh_dir: String,
    },
    /// Initialize shared team vault access (`InitKeybox`).
    InitKeybox,
    /// Query shared team vault status (`KeyboxStatus`).
    RefreshKeybox,
    /// Grant shared folder access to an invite code (`GrantKeyboxRecipient`).
    GrantKeyboxRecipient {
        recipient_bundle_b64: String,
    },
    /// Revoke shared folder access (`RevokeKeyboxRecipient`).
    RevokeKeyboxRecipient {
        recipient_id: String,
    },
    /// Refresh conflict preservation history (`ListConflicts`).
    RefreshConflicts,
    /// Run live encryption speed test (`BenchCrypto`).
    RunCryptoBench {
        total_mib: usize,
    },
    /// Cleanly stop the UI worker thread (leaving `entrocloudd` running).
    ShutdownWorker,
}

/// Shared state snapshot read briefly by `EntroCloudApp::update()` on each GPU frame.
pub struct SharedWorkerState {
    pub ipc_endpoint: String,
    pub daemon_connected: bool,
    pub busy_task: Option<String>,
    pub active_tasks: usize,
    pub oauth_in_progress: Option<String>,
    pub oauth_cancelled: Arc<AtomicBool>,
    pub oauth_gen: u64,
    pub toast_info: Option<String>,
    pub toast_info_set_at: Option<Instant>,
    pub toast_error: Option<String>,
    pub status: Option<VaultStatusReport>,
    pub current_dir: String,
    pub entries: Vec<VaultEntrySummary>,
    pub detected_clouds: Vec<DetectedCloudFolder>,
    pub remote_tests: HashMap<String, RemoteTestReport>,
    pub testing_remotes: HashSet<String>,
    pub backup_request_inflight: bool,
    pub sync_inflight: bool,
    pub unlock_inflight: bool,
    pub last_backup_report: Option<BackupRunReport>,
    pub last_restored_folder: Option<(String, u64, u64)>,
    pub last_connected_remote: Option<String>,
    pub loaded_note: Option<(String, Zeroizing<String>)>,
    pub recipient_bundle: Option<(String, String)>,
    pub latest_share_uri: Option<(String, Zeroizing<String>)>,
    pub keybox_info: Option<KeyboxSummary>,
    pub conflicts: Vec<ConflictRecord>,
    pub crypto_bench: Option<CryptoBenchmarkReport>,
    pub active_preview_files: usize,
    pub up_mib_history: VecDeque<f32>,
    pub down_mib_history: VecDeque<f32>,
    pub peak_up_mib_s: f64,
    pub peak_down_mib_s: f64,
    pub egui_ctx: Option<egui::Context>,
}

impl SharedWorkerState {
    pub(crate) fn new(
        endpoint_str: String,
        initial_status: Option<VaultStatusReport>,
        daemon_connected: bool,
        session_dir: &std::path::Path,
    ) -> Self {
        let mut s = Self {
            ipc_endpoint: endpoint_str,
            daemon_connected,
            busy_task: None,
            active_tasks: 0,
            oauth_in_progress: None,
            oauth_cancelled: Arc::new(AtomicBool::new(false)),
            oauth_gen: 0,
            toast_info: None,
            toast_info_set_at: None,
            toast_error: None,
            status: None,
            current_dir: "/".to_owned(),
            entries: Vec::new(),
            detected_clouds: Vec::new(),
            remote_tests: HashMap::new(),
            testing_remotes: HashSet::new(),
            backup_request_inflight: false,
            sync_inflight: false,
            unlock_inflight: false,
            last_backup_report: None,
            last_restored_folder: None,
            last_connected_remote: None,
            loaded_note: None,
            recipient_bundle: None,
            latest_share_uri: None,
            keybox_info: None,
            conflicts: Vec::new(),
            crypto_bench: None,
            active_preview_files: count_session_preview_files(session_dir),
            up_mib_history: VecDeque::with_capacity(SPARKLINE_HISTORY_LEN),
            down_mib_history: VecDeque::with_capacity(SPARKLINE_HISTORY_LEN),
            peak_up_mib_s: 0.0,
            peak_down_mib_s: 0.0,
            egui_ctx: None,
        };
        if let Some(st) = initial_status {
            s.apply_status(st);
        }
        s
    }

    pub fn apply_status(&mut self, report: VaultStatusReport) {
        let up_mib = report.throughput.upload_bytes_per_sec as f64 / (1024.0 * 1024.0);
        let down_mib = report.throughput.download_bytes_per_sec as f64 / (1024.0 * 1024.0);
        if up_mib > self.peak_up_mib_s {
            self.peak_up_mib_s = up_mib;
        }
        if down_mib > self.peak_down_mib_s {
            self.peak_down_mib_s = down_mib;
        }
        if self.up_mib_history.len() >= SPARKLINE_HISTORY_LEN {
            self.up_mib_history.pop_front();
        }
        if self.down_mib_history.len() >= SPARKLINE_HISTORY_LEN {
            self.down_mib_history.pop_front();
        }
        self.up_mib_history.push_back(up_mib as f32);
        self.down_mib_history.push_back(down_mib as f32);
        if !report.unlocked {
            self.entries.clear();
            self.loaded_note = None;
            self.latest_share_uri = None;
        }
        self.daemon_connected = true;
        self.status = Some(report);
    }

    pub fn notify_repaint(&self) {
        if let Some(ref ctx) = self.egui_ctx {
            ctx.request_repaint();
        }
    }
}

/// Handle owned by `EntroCloudApp` to submit non-blocking IPC commands and cleanly stop on window exit.
pub struct UiWorkerHandle {
    pub state: Arc<Mutex<SharedWorkerState>>,
    tx: Sender<UiCommand>,
    stop_flag: Arc<AtomicBool>,
    worker_done: Arc<AtomicBool>,
    session_dir: PathBuf,
    join_handle: Option<JoinHandle<()>>,
}

impl UiWorkerHandle {
    /// Spawns the background IPC worker thread (or inert state in `--bench-cold` / `--screenshot-tour` mode).
    #[must_use]
    pub fn spawn(
        client: IpcClient,
        session_dir: PathBuf,
        initial_status: Option<VaultStatusReport>,
        daemon_connected: bool,
        allow_autostart: bool,
        enable_background_polling: bool,
    ) -> Self {
        let shared = Arc::new(Mutex::new(SharedWorkerState::new(
            client.endpoint().to_string(),
            initial_status,
            daemon_connected,
            &session_dir,
        )));
        let (tx, rx) = mpsc::channel::<UiCommand>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_done = Arc::new(AtomicBool::new(!enable_background_polling));

        if !enable_background_polling {
            return Self {
                state: shared,
                tx,
                stop_flag,
                worker_done,
                session_dir,
                join_handle: None,
            };
        }

        let worker_state = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop_flag);
        let worker_done_bg = Arc::clone(&worker_done);
        let worker_session = session_dir.clone();

        let join_handle = thread::spawn(move || {
            struct DoneGuard(Arc<AtomicBool>);
            impl Drop for DoneGuard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _done = DoneGuard(worker_done_bg);
            worker_loop(
                client,
                rx,
                worker_state,
                worker_stop,
                worker_session,
                allow_autostart,
            );
        });

        Self {
            state: shared,
            tx,
            stop_flag,
            worker_done,
            session_dir,
            join_handle: Some(join_handle),
        }
    }

    /// Sends a command to the background worker thread without blocking the GPU render loop.
    pub fn send(&self, cmd: UiCommand) {
        let _ = self.tx.send(cmd);
    }

    /// Returns the active session preview directory path.
    #[must_use]
    pub fn session_dir(&self) -> &std::path::Path {
        &self.session_dir
    }

    /// Stops the background worker thread (with a bounded wait so exit never hangs) and
    /// zero-wipes all previewed temporary session files.
    pub fn shutdown_and_scrub(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.tx.send(UiCommand::ShutdownWorker);
        if let Some(handle) = self.join_handle.take() {
            let deadline = Instant::now() + Duration::from_millis(500);
            while !self.worker_done.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if self.worker_done.load(Ordering::Acquire) {
                let _ = handle.join();
            }
        }
        let _ = scrub_session_dir(&self.session_dir);
        let remaining = count_session_preview_files(&self.session_dir);
        let mut guard = self.state.lock();
        guard.loaded_note = None;
        guard.latest_share_uri = None;
        guard.active_preview_files = remaining;
    }
}

impl Drop for UiWorkerHandle {
    fn drop(&mut self) {
        self.shutdown_and_scrub();
    }
}

fn worker_loop(
    client: IpcClient,
    rx: mpsc::Receiver<UiCommand>,
    state: Arc<Mutex<SharedWorkerState>>,
    stop_flag: Arc<AtomicBool>,
    session_dir: PathBuf,
    allow_autostart: bool,
) {
    refresh_status_and_dir(&client, &state, "/", false);
    // Proactively detect local cloud sync folders on first launch so 1-click setup is instant.
    if let Ok(DaemonResponse::DetectedClouds(clouds)) =
        client.request(&DaemonRequest::DetectLocalClouds)
    {
        let mut guard = state.lock();
        guard.detected_clouds = clouds;
        guard.notify_repaint();
    }

    let mut last_poll = Instant::now();
    while !stop_flag.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(UiCommand::ShutdownWorker) => break,
            Ok(cmd) => {
                handle_command(&client, &state, &session_dir, allow_autostart, cmd);
                last_poll = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let fast_poll = {
                    let guard = state.lock();
                    guard.backup_request_inflight
                        || guard.unlock_inflight
                        || !guard.testing_remotes.is_empty()
                        || guard.busy_task.is_some()
                        || guard
                            .status
                            .as_ref()
                            .is_some_and(|s| s.active_activity.is_some() || s.throughput.pending_dirty_ops > 0)
                };
                let poll_interval = if fast_poll {
                    Duration::from_millis(450)
                } else {
                    Duration::from_millis(1000)
                };
                if last_poll.elapsed() >= poll_interval {
                    poll_status_quietly(&client, &state, &session_dir);
                    last_poll = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn friendly_ipc_error(err: &impl std::fmt::Display) -> String {
    let raw = err.to_string();
    let lower = raw.to_ascii_lowercase();
    if lower.contains("os error 2)")
        || lower.contains("os error 2:")
        || lower.contains("cannot find the file")
        || lower.contains("no such file or directory")
        || lower.contains("connection refused")
        || lower.contains("os error 10061")
    {
        return "Could not reach the EntroCloud background service. Click Reconnect to start it."
            .to_owned();
    }
    if lower.contains("os error 231") || lower.contains("pipe instances are busy") {
        return "The EntroCloud background service is busy. Please try again in a moment."
            .to_owned();
    }
    if lower.contains("os error 109")
        || lower.contains("os error 232")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
        || lower.contains("connection reset")
    {
        return "Connection to the EntroCloud background service was interrupted. Please try again."
            .to_owned();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "The background service took too long to respond. Please try again.".to_owned();
    }
    if lower.contains("access is denied")
        || lower.contains("os error 5)")
        || lower.contains("os error 5:")
        || lower.contains("permission denied")
    {
        return "Access denied while communicating with the background service.".to_owned();
    }
    raw.strip_prefix("IPC error: ")
        .or_else(|| raw.strip_prefix("I/O error: "))
        .unwrap_or(&raw)
        .trim()
        .to_owned()
}

fn friendly_error_text(code: &str, message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if code == "invalid_passphrase" || lower.contains("invalid vault passphrase") {
        return "Incorrect Master Password. Please check Caps Lock and try again.".to_owned();
    }
    let trimmed = message.trim();
    if trimmed.is_empty() {
        format!("Action could not be completed ({code})")
    } else {
        trimmed.to_owned()
    }
}

fn provider_friendly_name(kind: &str) -> &'static str {
    match kind {
        "gdrive" => "Google Drive",
        "onedrive" => "Microsoft OneDrive",
        "dropbox" => "Dropbox",
        "s3" => "S3 / Cloud Object Storage",
        "webdav" => "WebDAV / Nextcloud",
        "fs" => "Local / Synced Folder",
        _ => "Cloud Storage",
    }
}

fn set_busy(state: &Arc<Mutex<SharedWorkerState>>, label: Option<&str>) {
    let mut guard = state.lock();
    if let Some(lbl) = label {
        guard.active_tasks = guard.active_tasks.saturating_add(1);
        guard.busy_task = Some(lbl.to_owned());
        guard.toast_error = None;
    } else {
        end_task_locked(&mut guard);
    }
    guard.notify_repaint();
}

fn end_task_locked(guard: &mut SharedWorkerState) {
    guard.active_tasks = guard.active_tasks.saturating_sub(1);
    if guard.active_tasks == 0 {
        if guard.backup_request_inflight {
            guard.busy_task = Some("Backup in progress…".to_owned());
        } else {
            guard.busy_task = None;
        }
    } else if guard.backup_request_inflight && guard.busy_task.is_none() {
        guard.busy_task = Some("Backup in progress…".to_owned());
    }
}

fn finish_ok(state: &Arc<Mutex<SharedWorkerState>>, info: impl Into<String>) {
    let mut guard = state.lock();
    end_task_locked(&mut guard);
    guard.toast_info = Some(info.into());
    guard.toast_info_set_at = Some(Instant::now());
    guard.toast_error = None;
    guard.notify_repaint();
}

fn finish_err(state: &Arc<Mutex<SharedWorkerState>>, err: impl Into<String>) {
    let mut guard = state.lock();
    end_task_locked(&mut guard);
    guard.toast_error = Some(err.into());
    guard.notify_repaint();
}

fn set_toast_ok(state: &Arc<Mutex<SharedWorkerState>>, info: impl Into<String>) {
    let mut guard = state.lock();
    guard.toast_info = Some(info.into());
    guard.toast_info_set_at = Some(Instant::now());
    guard.toast_error = None;
    guard.notify_repaint();
}

fn set_toast_err(state: &Arc<Mutex<SharedWorkerState>>, err: impl Into<String>) {
    let mut guard = state.lock();
    guard.toast_error = Some(err.into());
    guard.notify_repaint();
}

fn poll_status_quietly(
    client: &IpcClient,
    state: &Arc<Mutex<SharedWorkerState>>,
    session_dir: &std::path::Path,
) {
    match client.request(&DaemonRequest::Status) {
        Ok(DaemonResponse::Status(report)) => {
            let previews = count_session_preview_files(session_dir);
            let mut guard = state.lock();
            guard.active_preview_files = previews;
            guard.apply_status(*report);
            guard.notify_repaint();
        }
        Ok(_) => {}
        Err(_) => {
            let mut guard = state.lock();
            guard.daemon_connected = false;
            guard.notify_repaint();
        }
    }
}

fn refresh_status_and_dir(
    client: &IpcClient,
    state: &Arc<Mutex<SharedWorkerState>>,
    dir: &str,
    surface_errors: bool,
) {
    let norm_dir = normalize_ui_vpath(dir);
    match client.request(&DaemonRequest::Status) {
        Ok(DaemonResponse::Status(report)) => {
            let unlocked = report.unlocked;
            {
                let mut guard = state.lock();
                guard.apply_status(*report);
            }
            if unlocked {
                match client.request(&DaemonRequest::ListDirectory {
                    virtual_path: norm_dir,
                }) {
                    Ok(DaemonResponse::DirectoryEntries {
                        virtual_path,
                        entries,
                    }) => {
                        let mut guard = state.lock();
                        guard.current_dir = virtual_path;
                        guard.entries = entries;
                    }
                    Ok(DaemonResponse::Error { code, message }) if surface_errors => {
                        let mut guard = state.lock();
                        guard.toast_error = Some(friendly_error_text(&code, &message));
                    }
                    _ => {}
                }
            }
            state.lock().notify_repaint();
        }
        Ok(DaemonResponse::Error { code, message }) => {
            if surface_errors {
                set_toast_err(state, friendly_error_text(&code, &message));
            }
        }
        Ok(_) => {}
        Err(err) => {
            let mut guard = state.lock();
            guard.daemon_connected = false;
            if surface_errors {
                guard.toast_error = Some(friendly_ipc_error(&err));
            }
            guard.notify_repaint();
        }
    }
}

fn expect_ok_response(client: &IpcClient, req: &DaemonRequest) -> Result<String, String> {
    match client.request(req).map_err(|e| friendly_ipc_error(&e))? {
        DaemonResponse::Ok { message } => Ok(message),
        DaemonResponse::Error { code, message } => Err(friendly_error_text(&code, &message)),
        other => Err(format!("Unexpected background service response: {other:?}")),
    }
}

fn handle_command(
    client: &IpcClient,
    state: &Arc<Mutex<SharedWorkerState>>,
    session_dir: &std::path::Path,
    allow_autostart: bool,
    cmd: UiCommand,
) {
    match cmd {
        UiCommand::ShutdownWorker => {}
        UiCommand::RefreshAll { current_dir } => {
            set_busy(state, Some("Refreshing status..."));
            refresh_status_and_dir(client, state, &current_dir, true);
            let mut guard = state.lock();
            end_task_locked(&mut guard);
            guard.notify_repaint();
        }
        UiCommand::ReconnectOrAutostart { current_dir } => {
            set_busy(state, Some("Starting EntroCloud background service..."));
            match client.ensure_daemon_running(allow_autostart, Duration::from_millis(2500)) {
                Ok(spawned) => {
                    refresh_status_and_dir(client, state, &current_dir, true);
                    let msg = if spawned {
                        "EntroCloud background service started and connected"
                    } else {
                        "Connected to EntroCloud background service"
                    };
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::InitVault { passphrase } => {
            {
                let mut g = state.lock();
                if g.unlock_inflight {
                    return;
                }
                g.unlock_inflight = true;
            }
            set_busy(state, Some("Creating your encrypted vault..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-init-vault".to_owned())
                .spawn(move || {
                    let req = DaemonRequest::InitVault {
                        passphrase: (*passphrase).clone(),
                    };
                    drop(passphrase);
                    let res = expect_ok_response(&bg_client, &req);
                    drop(req);
                    match res {
                        Ok(_) => {
                            refresh_status_and_dir(&bg_client, &bg_state, "/", false);
                            bg_state.lock().unlock_inflight = false;
                            finish_ok(&bg_state, "Your encrypted vault is ready and unlocked.");
                        }
                        Err(err) => {
                            bg_state.lock().unlock_inflight = false;
                            finish_err(&bg_state, err);
                        }
                    }
                });
            if let Err(err) = spawn_res {
                state.lock().unlock_inflight = false;
                finish_err(state, format!("Failed starting vault creation worker: {err}"));
            }
        }
        UiCommand::UnlockVault {
            passphrase,
            current_dir,
        } => {
            {
                let mut g = state.lock();
                if g.unlock_inflight {
                    return;
                }
                g.unlock_inflight = true;
            }
            set_busy(state, Some("Unlocking your vault..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-unlock-vault".to_owned())
                .spawn(move || {
                    let req = DaemonRequest::UnlockVault {
                        passphrase: (*passphrase).clone(),
                    };
                    drop(passphrase);
                    let res = expect_ok_response(&bg_client, &req);
                    drop(req);
                    match res {
                        Ok(_) => {
                            refresh_status_and_dir(&bg_client, &bg_state, &current_dir, false);
                            bg_state.lock().unlock_inflight = false;
                            finish_ok(&bg_state, "Vault unlocked.");
                        }
                        Err(err) => {
                            bg_state.lock().unlock_inflight = false;
                            finish_err(&bg_state, err);
                        }
                    }
                });
            if let Err(err) = spawn_res {
                state.lock().unlock_inflight = false;
                finish_err(state, format!("Failed starting vault unlock worker: {err}"));
            }
        }
        UiCommand::LockVault => {
            set_busy(state, Some("Locking vault and clearing temporary files..."));
            let scrubbed = scrub_session_dir(session_dir);
            let remaining = count_session_preview_files(session_dir);
            let res = expect_ok_response(client, &DaemonRequest::LockVault);
            refresh_status_and_dir(client, state, "/", false);
            {
                let mut guard = state.lock();
                guard.active_preview_files = remaining;
                guard.loaded_note = None;
                guard.latest_share_uri = None;
            }
            match res {
                Ok(_) => {
                    if remaining > 0 {
                        let noun = if remaining == 1 { "file" } else { "files" };
                        finish_err(
                            state,
                            format!(
                                "Vault locked, but {remaining} temporary preview {noun} remained locked by an external viewer. Close the viewer and scrub previews again."
                            ),
                        );
                    } else {
                        let msg = if scrubbed > 0 {
                            let noun = if scrubbed == 1 { "file" } else { "files" };
                            format!("Vault locked and {scrubbed} temporary preview {noun} wiped.")
                        } else {
                            "Vault locked.".to_owned()
                        };
                        finish_ok(state, msg);
                    }
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::MountDrive {
            mount_point,
            use_mock_vfs,
        } => {
            let mount_msg = if cfg!(target_os = "windows") {
                "Turning on EntroCloud Drive in File Explorer..."
            } else {
                "Turning on EntroCloud Drive..."
            };
            set_busy(state, Some(mount_msg));
            let req = if use_mock_vfs {
                DaemonRequest::MountWithOptions {
                    mount_point,
                    use_mock_vfs: true,
                }
            } else {
                DaemonRequest::Mount { mount_point }
            };
            match expect_ok_response(client, &req) {
                Ok(msg) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::UnmountDrive => {
            set_busy(state, Some("Turning off EntroCloud Drive..."));
            match expect_ok_response(client, &DaemonRequest::Unmount) {
                Ok(msg) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::SyncNow => {
            {
                let mut guard = state.lock();
                if guard.sync_inflight {
                    guard.toast_info = Some("Sync is already in progress.".to_owned());
                    guard.toast_info_set_at = Some(Instant::now());
                    guard.notify_repaint();
                    return;
                }
                guard.sync_inflight = true;
            }
            set_busy(state, Some("Syncing changes across your clouds..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-sync-now".to_owned())
                .spawn(move || {
                    let res = expect_ok_response(&bg_client, &DaemonRequest::SyncNow);
                    bg_state.lock().sync_inflight = false;
                    match res {
                        Ok(msg) => {
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            finish_ok(&bg_state, msg);
                        }
                        Err(err) => finish_err(&bg_state, err),
                    }
                });
            if let Err(err) = spawn_res {
                state.lock().sync_inflight = false;
                finish_err(state, format!("Failed starting sync worker: {err}"));
            }
        }
        UiCommand::ListDirectory { virtual_path } => {
            let norm = normalize_ui_vpath(&virtual_path);
            set_busy(state, Some("Opening folder..."));
            match client.request(&DaemonRequest::ListDirectory { virtual_path: norm }) {
                Ok(DaemonResponse::DirectoryEntries {
                    virtual_path,
                    entries,
                }) => {
                    let mut guard = state.lock();
                    end_task_locked(&mut guard);
                    guard.current_dir = virtual_path;
                    guard.entries = entries;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::CreateDirectory {
            virtual_path,
            refresh_dir,
        } => {
            set_busy(state, Some("Creating folder..."));
            let norm = normalize_ui_vpath(&virtual_path);
            match expect_ok_response(client, &DaemonRequest::CreateDirectory { virtual_path: norm })
            {
                Ok(msg) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::ImportLocalPaths {
            local_paths,
            target_dir,
        } => {
            set_busy(state, Some("Encrypting and adding files to your vault..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-import-files".to_owned())
                .spawn(move || {
                    match import_local_paths_recursive(&bg_client, &local_paths, &target_dir) {
                        Ok(summary) => {
                            refresh_status_and_dir(&bg_client, &bg_state, &target_dir, false);
                            finish_ok(&bg_state, summary.message);
                        }
                        Err(err) => finish_err(&bg_state, err),
                    }
                });
            if let Err(err) = spawn_res {
                finish_err(state, format!("Failed starting file import worker: {err}"));
            }
        }
        UiCommand::ExportVaultFile {
            virtual_path,
            local_dest_path,
        } => {
            set_busy(state, Some("Decrypting and saving copy to this PC..."));
            let norm = normalize_ui_vpath(&virtual_path);
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-export-file".to_owned())
                .spawn(move || {
                    match expect_ok_response(
                        &bg_client,
                        &DaemonRequest::ExportVaultFile {
                            virtual_path: norm,
                            local_dest_path,
                        },
                    ) {
                        Ok(msg) => finish_ok(&bg_state, msg),
                        Err(err) => finish_err(&bg_state, err),
                    }
                });
            if let Err(err) = spawn_res {
                finish_err(state, format!("Failed starting file export worker: {err}"));
            }
        }
        UiCommand::PreviewVaultFile { virtual_path } => {
            set_busy(state, Some("Opening file in default application..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let bg_session_dir = session_dir.to_path_buf();
            let spawn_res = thread::Builder::new()
                .name("ec-preview-file".to_owned())
                .spawn(move || {
                    match export_for_secure_preview(&bg_client, &bg_session_dir, &virtual_path) {
                        Ok(preview_path) => {
                            let count = count_session_preview_files(&bg_session_dir);
                            bg_state.lock().active_preview_files = count;
                            match open_in_os_default_app(&preview_path) {
                                Ok(()) => finish_ok(
                                    &bg_state,
                                    "Opened file (temporary copy will be wiped automatically when you lock or exit).",
                                ),
                                Err(err) => finish_err(&bg_state, err),
                            }
                        }
                        Err(err) => finish_err(&bg_state, err),
                    }
                });
            if let Err(err) = spawn_res {
                finish_err(state, format!("Failed starting file preview worker: {err}"));
            }
        }
        UiCommand::ScrubPreviewsNow => {
            let wiped = scrub_session_dir(session_dir);
            let remaining = count_session_preview_files(session_dir);
            state.lock().active_preview_files = remaining;
            if remaining > 0 {
                let wiped_noun = if wiped == 1 { "file" } else { "files" };
                let rem_noun = if remaining == 1 { "file" } else { "files" };
                set_toast_err(
                    state,
                    format!(
                        "Wiped {wiped} temporary preview {wiped_noun}, but {remaining} {rem_noun} still locked by an external viewer. Close the viewer and try again."
                    ),
                );
            } else {
                let noun = if wiped == 1 { "file" } else { "files" };
                set_toast_ok(
                    state,
                    format!("Securely wiped {wiped} temporary preview {noun}."),
                );
            }
        }
        UiCommand::SetPinned {
            virtual_path,
            pinned,
            refresh_dir,
        } => {
            let norm = normalize_ui_vpath(&virtual_path);
            let req = if pinned {
                DaemonRequest::Pin { virtual_path: norm }
            } else {
                DaemonRequest::Unpin { virtual_path: norm }
            };
            set_busy(
                state,
                Some(if pinned {
                    "Downloading encrypted copy for offline access..."
                } else {
                    "Updating offline setting..."
                }),
            );
            match expect_ok_response(client, &req) {
                Ok(msg) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::FreeUpSpace {
            virtual_path,
            refresh_dir,
        } => {
            let norm = normalize_ui_vpath(&virtual_path);
            set_busy(state, Some("Freeing local disk space..."));
            if let Err(err) = expect_ok_response(
                client,
                &DaemonRequest::Unpin {
                    virtual_path: norm.clone(),
                },
            ) {
                finish_err(state, err);
                return;
            }
            match expect_ok_response(client, &DaemonRequest::Dehydrate { virtual_path: norm }) {
                Ok(_) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, "Freed local disk space on this PC (file stays safely in your cloud).");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::RenameEntry {
            virtual_path,
            new_virtual_path,
            refresh_dir,
        } => {
            set_busy(state, Some("Renaming item..."));
            match expect_ok_response(
                client,
                &DaemonRequest::RenameEntry {
                    virtual_path: normalize_ui_vpath(&virtual_path),
                    new_virtual_path: normalize_ui_vpath(&new_virtual_path),
                },
            ) {
                Ok(msg) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::DeleteEntry {
            virtual_path,
            recursive,
            refresh_dir,
        } => {
            set_busy(state, Some("Removing item from vault..."));
            match expect_ok_response(
                client,
                &DaemonRequest::DeleteEntry {
                    virtual_path: normalize_ui_vpath(&virtual_path),
                    recursive,
                },
            ) {
                Ok(msg) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::ReadTextNote { virtual_path } => {
            let norm = normalize_ui_vpath(&virtual_path);
            set_busy(state, Some("Opening private note..."));
            match client.request(&DaemonRequest::ReadTextNote { virtual_path: norm }) {
                Ok(DaemonResponse::TextNote {
                    virtual_path,
                    content,
                }) => {
                    let guarded = Zeroizing::new(content);
                    let mut guard = state.lock();
                    end_task_locked(&mut guard);
                    guard.loaded_note = Some((virtual_path, guarded));
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected note response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::SaveTextNote {
            virtual_path,
            content,
            refresh_dir,
        } => {
            if content.len() > MAX_NOTE_BYTES {
                set_toast_err(
                    state,
                    format!(
                        "Note is larger than the 2 MB built-in editor limit ({} bytes).",
                        content.len()
                    ),
                );
                return;
            }
            let norm = normalize_ui_vpath(&virtual_path);
            set_busy(state, Some("Encrypting and saving private note..."));
            let req = DaemonRequest::SaveTextNote {
                virtual_path: norm.clone(),
                content: (*content).clone(),
            };
            drop(content);
            let res = expect_ok_response(client, &req);
            drop(req);
            match res {
                Ok(_) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, format!("Saved encrypted note {norm}."));
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::DetectLocalClouds => {
            set_busy(state, Some("Checking for cloud folders on this PC..."));
            match client.request(&DaemonRequest::DetectLocalClouds) {
                Ok(DaemonResponse::DetectedClouds(clouds)) => {
                    let mut guard = state.lock();
                    guard.detected_clouds = clouds;
                    end_task_locked(&mut guard);
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::AddRemote { params } => {
            let remote_id = params.id.clone();
            set_busy(state, Some("Connecting storage location..."));
            let req = DaemonRequest::AddRemote(params);
            let res = expect_ok_response(client, &req);
            drop(req);
            match res {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    state.lock().last_connected_remote = Some(remote_id.clone());
                    finish_ok(state, format!("Connected storage '{remote_id}'."));
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::RemoveRemote { id } => {
            set_busy(state, Some("Removing cloud connection..."));
            match expect_ok_response(client, &DaemonRequest::RemoveRemote { id: id.clone() }) {
                Ok(_) => {
                    state.lock().remote_tests.remove(&id);
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, format!("Removed connection '{id}'."));
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::TestRemote { id } => {
            {
                let mut guard = state.lock();
                if !guard.testing_remotes.insert(id.clone()) {
                    return;
                }
                guard.active_tasks = guard.active_tasks.saturating_add(1);
                guard.busy_task = Some(format!("Testing connection to '{id}'..."));
                guard.toast_error = None;
                guard.notify_repaint();
            }
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let id_for_thread = id.clone();
            let spawn_res = thread::Builder::new()
                .name("ec-test-remote".to_owned())
                .spawn(move || {
                    let res =
                        bg_client.request(&DaemonRequest::TestRemote { id: id_for_thread.clone() });
                    {
                        let mut guard = bg_state.lock();
                        guard.testing_remotes.remove(&id_for_thread);
                    }
                    match res {
                        Ok(DaemonResponse::RemoteTest(report)) => {
                            let msg = if report.healthy {
                                format!(
                                    "{} is healthy ({} ms response).",
                                    report.id, report.latency_ms
                                )
                            } else {
                                format!("{} needs attention: {}", report.id, report.message)
                            };
                            let healthy = report.healthy;
                            {
                                let mut guard = bg_state.lock();
                                guard.remote_tests.insert(id_for_thread, report);
                            }
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            if healthy {
                                finish_ok(&bg_state, msg);
                            } else {
                                finish_err(&bg_state, msg);
                            }
                        }
                        Ok(DaemonResponse::Error { code, message }) => {
                            finish_err(&bg_state, friendly_error_text(&code, &message));
                        }
                        Ok(other) => {
                            finish_err(&bg_state, format!("Unexpected response: {other:?}"))
                        }
                        Err(err) => finish_err(&bg_state, friendly_ipc_error(&err)),
                    }
                });
            if let Err(err) = spawn_res {
                state.lock().testing_remotes.remove(&id);
                finish_err(state, format!("Failed starting connection test worker: {err}"));
            }
        }
        UiCommand::OAuthLogin { params } => {
            // Dedicated short-lived thread so `worker_loop` keeps polling status and can send `CancelOAuth`!
            let provider_label = provider_friendly_name(&params.kind);
            let remote_id = params.id.clone();
            let (cancel_flag, my_gen) = {
                let mut guard = state.lock();
                guard.oauth_cancelled.store(true, Ordering::SeqCst);
                guard.oauth_gen = guard.oauth_gen.wrapping_add(1);
                let my_gen = guard.oauth_gen;
                let fresh_cancel = Arc::new(AtomicBool::new(false));
                guard.oauth_cancelled = Arc::clone(&fresh_cancel);
                guard.oauth_in_progress = Some(format!(
                    "Waiting for {provider_label} sign-in in your browser..."
                ));
                guard.toast_error = None;
                guard.notify_repaint();
                (fresh_cancel, my_gen)
            };

            let oauth_client = client.clone();
            let oauth_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-oauth".to_owned())
                .spawn(move || {
                    let req = DaemonRequest::OAuthLogin(params);
                    let res = expect_ok_response(&oauth_client, &req);
                    drop(req);

                    let was_cancelled = cancel_flag.load(Ordering::SeqCst);
                    {
                        let mut guard = oauth_state.lock();
                        if guard.oauth_gen != my_gen {
                            return;
                        }
                        guard.oauth_in_progress = None;
                    }

                    match res {
                        Ok(_) => {
                            let cur = oauth_state.lock().current_dir.clone();
                            refresh_status_and_dir(&oauth_client, &oauth_state, &cur, false);
                            let mut guard = oauth_state.lock();
                            if guard.oauth_gen != my_gen {
                                return;
                            }
                            guard.last_connected_remote = Some(remote_id.clone());
                            guard.toast_info = Some(format!(
                                "Connected {provider_label} ('{remote_id}')."
                            ));
                            guard.toast_info_set_at = Some(Instant::now());
                            guard.toast_error = None;
                            guard.notify_repaint();
                        }
                        Err(err) => {
                            let mut guard = oauth_state.lock();
                            if guard.oauth_gen != my_gen {
                                return;
                            }
                            if was_cancelled || err.to_ascii_lowercase().contains("cancel") {
                                guard.toast_info = Some("Browser sign-in was cancelled.".to_owned());
                                guard.toast_info_set_at = Some(Instant::now());
                                guard.toast_error = None;
                            } else {
                                guard.toast_error = Some(err);
                            }
                            guard.notify_repaint();
                        }
                    }
                });
            if let Err(err) = spawn_res {
                let mut guard = state.lock();
                if guard.oauth_gen == my_gen {
                    guard.oauth_in_progress = None;
                }
                guard.toast_error = Some(format!("Failed starting browser sign-in worker: {err}"));
                guard.notify_repaint();
            }
        }
        UiCommand::CancelOAuth => {
            {
                let mut guard = state.lock();
                guard.oauth_cancelled.store(true, Ordering::SeqCst);
                guard.oauth_gen = guard.oauth_gen.wrapping_add(1);
                guard.oauth_in_progress = None;
                guard.notify_repaint();
            }
            let _ = client.request(&DaemonRequest::CancelOAuth);
            set_toast_ok(state, "Cancelled browser sign-in.");
        }
        UiCommand::SetRoutingPolicy { policy } => {
            set_busy(state, Some("Saving multi-cloud storage preferences..."));
            match expect_ok_response(client, &DaemonRequest::SetRoutingPolicy { policy }) {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, "Saved multi-cloud storage preferences.");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::UpsertBackupJob { spec } => {
            let job_name = spec.name.clone();
            set_busy(state, Some("Saving folder backup schedule..."));
            match expect_ok_response(client, &DaemonRequest::UpsertBackupJob(spec)) {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, format!("Saved backup folder '{job_name}'."));
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::RemoveBackupJob { id } => {
            set_busy(state, Some("Removing backup schedule..."));
            match expect_ok_response(client, &DaemonRequest::RemoveBackupJob { id }) {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(
                        state,
                        "Removed folder schedule (your local files and cloud backups remain intact).",
                    );
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::RunBackupJob { id, preview } => {
            {
                let mut guard = state.lock();
                if !preview && guard.backup_request_inflight {
                    guard.toast_info = Some(
                        "Backup is already running — watch live progress on the Backups page."
                            .to_owned(),
                    );
                    guard.toast_info_set_at = Some(Instant::now());
                    guard.notify_repaint();
                    return;
                }
                if !preview {
                    guard.backup_request_inflight = true;
                }
                guard.active_tasks = guard.active_tasks.saturating_add(1);
                guard.busy_task = Some(
                    if preview {
                        "Previewing changes for backup folder..."
                    } else {
                        "Starting folder backup..."
                    }
                    .to_owned(),
                );
                guard.toast_error = None;
                guard.notify_repaint();
            }

            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-backup-job".to_owned())
                .spawn(move || {
                    let res = bg_client.request(&DaemonRequest::RunBackupJob { id, preview });
                    if !preview {
                        bg_state.lock().backup_request_inflight = false;
                    }
                    match res {
                        Ok(DaemonResponse::BackupReport(report)) => {
                            let summary_msg = if report.preview {
                                format!(
                                    "Preview complete: {} new/changed {} ({}) to upload, {} unchanged.",
                                    report.files_uploaded,
                                    if report.files_uploaded == 1 { "file" } else { "files" },
                                    format_bytes_human(report.bytes_uploaded),
                                    report.files_unchanged
                                )
                            } else {
                                format!(
                                    "Backup complete: {} {} ({}) encrypted & synced, {} unchanged.",
                                    report.files_uploaded,
                                    if report.files_uploaded == 1 { "file" } else { "files" },
                                    format_bytes_human(report.bytes_uploaded),
                                    report.files_unchanged
                                )
                            };
                            bg_state.lock().last_backup_report = Some(report);
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            finish_ok(&bg_state, summary_msg);
                        }
                        Ok(DaemonResponse::Ok { message }) => {
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            finish_ok(&bg_state, message);
                        }
                        Ok(DaemonResponse::Error { code, message }) => {
                            finish_err(&bg_state, friendly_error_text(&code, &message));
                        }
                        Ok(other) => {
                            finish_err(&bg_state, format!("Unexpected backup response: {other:?}"))
                        }
                        Err(err) => finish_err(&bg_state, friendly_ipc_error(&err)),
                    }
                });
            if let Err(err) = spawn_res {
                if !preview {
                    state.lock().backup_request_inflight = false;
                }
                finish_err(state, format!("Failed starting backup worker: {err}"));
            }
        }
        UiCommand::RunAllBackups { preview } => {
            {
                let mut guard = state.lock();
                if !preview && guard.backup_request_inflight {
                    guard.toast_info = Some(
                        "Backup is already running — watch live progress on the Backups page."
                            .to_owned(),
                    );
                    guard.toast_info_set_at = Some(Instant::now());
                    guard.notify_repaint();
                    return;
                }
                if !preview {
                    guard.backup_request_inflight = true;
                }
                guard.active_tasks = guard.active_tasks.saturating_add(1);
                guard.busy_task = Some(
                    if preview {
                        "Previewing all protected folders..."
                    } else {
                        "Starting backup of all protected folders..."
                    }
                    .to_owned(),
                );
                guard.toast_error = None;
                guard.notify_repaint();
            }

            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-backup-all".to_owned())
                .spawn(move || {
                    let res = bg_client.request(&DaemonRequest::RunAllBackups { preview });
                    if !preview {
                        bg_state.lock().backup_request_inflight = false;
                    }
                    match res {
                        Ok(DaemonResponse::BackupReport(report)) => {
                            let summary_msg = if report.preview {
                                format!(
                                    "Preview complete: {} new/changed {} ({}) to upload, {} unchanged.",
                                    report.files_uploaded,
                                    if report.files_uploaded == 1 { "file" } else { "files" },
                                    format_bytes_human(report.bytes_uploaded),
                                    report.files_unchanged
                                )
                            } else {
                                format!(
                                    "Backup complete: {} {} ({}) encrypted & synced, {} unchanged.",
                                    report.files_uploaded,
                                    if report.files_uploaded == 1 { "file" } else { "files" },
                                    format_bytes_human(report.bytes_uploaded),
                                    report.files_unchanged
                                )
                            };
                            bg_state.lock().last_backup_report = Some(report);
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            finish_ok(&bg_state, summary_msg);
                        }
                        Ok(DaemonResponse::Ok { message }) => {
                            let cur = bg_state.lock().current_dir.clone();
                            refresh_status_and_dir(&bg_client, &bg_state, &cur, false);
                            finish_ok(&bg_state, message);
                        }
                        Ok(DaemonResponse::Error { code, message }) => {
                            finish_err(&bg_state, friendly_error_text(&code, &message));
                        }
                        Ok(other) => {
                            finish_err(&bg_state, format!("Unexpected backup response: {other:?}"))
                        }
                        Err(err) => finish_err(&bg_state, friendly_ipc_error(&err)),
                    }
                });
            if let Err(err) = spawn_res {
                if !preview {
                    state.lock().backup_request_inflight = false;
                }
                finish_err(state, format!("Failed starting backup worker: {err}"));
            }
        }
        UiCommand::RestoreBackupJob {
            id,
            destination_parent,
        } => {
            set_busy(state, Some("Decrypting and restoring backup snapshot..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-restore-job".to_owned())
                .spawn(move || {
                    match bg_client.request(&DaemonRequest::RestoreBackupJob {
                        id,
                        destination_parent,
                    }) {
                        Ok(DaemonResponse::RestoreCompleted {
                            restored_folder,
                            files_restored,
                            bytes_restored,
                        }) => {
                            let noun = if files_restored == 1 { "file" } else { "files" };
                            let msg = format!(
                                "Restored {files_restored} {noun} ({}) into {restored_folder}",
                                format_bytes_human(bytes_restored)
                            );
                            {
                                let mut guard = bg_state.lock();
                                guard.last_restored_folder =
                                    Some((restored_folder, files_restored, bytes_restored));
                            }
                            finish_ok(&bg_state, msg);
                        }
                        Ok(DaemonResponse::Ok { message }) => finish_ok(&bg_state, message),
                        Ok(DaemonResponse::Error { code, message }) => {
                            finish_err(&bg_state, friendly_error_text(&code, &message));
                        }
                        Ok(other) => finish_err(
                            &bg_state,
                            format!("Unexpected restore response: {other:?}"),
                        ),
                        Err(err) => finish_err(&bg_state, friendly_ipc_error(&err)),
                    }
                });
            if let Err(err) = spawn_res {
                finish_err(state, format!("Failed starting restore worker: {err}"));
            }
        }
        UiCommand::SetBackupsPaused { paused } => {
            set_busy(
                state,
                Some(if paused {
                    "Pausing scheduled backups..."
                } else {
                    "Resuming scheduled backups..."
                }),
            );
            match expect_ok_response(client, &DaemonRequest::SetBackupsPaused { paused }) {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(
                        state,
                        if paused {
                            "Automatic backups paused."
                        } else {
                            "Automatic backups resumed."
                        },
                    );
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::CancelActiveBackup => {
            set_busy(state, Some("Stopping active backup..."));
            match expect_ok_response(client, &DaemonRequest::CancelActiveBackup) {
                Ok(_) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, "Stopped active backup and paused schedule.");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::ExportRecipientBundle { label } => {
            set_busy(state, Some("Generating your personal invite code..."));
            match client.request(&DaemonRequest::ExportRecipientBundle { label }) {
                Ok(DaemonResponse::RecipientBundle {
                    recipient_id,
                    bundle_b64,
                }) => {
                    let mut guard = state.lock();
                    end_task_locked(&mut guard);
                    guard.recipient_bundle = Some((recipient_id, bundle_b64));
                    guard.toast_info = Some("Generated your invite code.".to_owned());
                    guard.toast_info_set_at = Some(Instant::now());
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::CreateCapabilityShare { virtual_path } => {
            let norm = normalize_ui_vpath(&virtual_path);
            set_busy(state, Some("Creating private share link..."));
            match client.request(&DaemonRequest::CreateCapabilityShare {
                virtual_path: norm.clone(),
            }) {
                Ok(DaemonResponse::ShareUriCreated { uri, share_id }) => {
                    let mut guard = state.lock();
                    end_task_locked(&mut guard);
                    guard.latest_share_uri = Some((share_id.to_string(), Zeroizing::new(uri)));
                    guard.toast_info = Some(format!("Created private share link for {norm}."));
                    guard.toast_info_set_at = Some(Instant::now());
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::ImportCapabilityShare {
            uri,
            dest_virtual_path,
            refresh_dir,
        } => {
            set_busy(state, Some("Verifying and saving shared file..."));
            let req = DaemonRequest::ImportCapabilityShare {
                uri: (*uri).clone(),
                dest_virtual_path: normalize_ui_vpath(&dest_virtual_path),
            };
            drop(uri);
            let res = expect_ok_response(client, &req);
            drop(req);
            match res {
                Ok(_) => {
                    refresh_status_and_dir(client, state, &refresh_dir, false);
                    finish_ok(state, "Saved shared file into your vault.");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::InitKeybox => {
            set_busy(state, Some("Enabling shared team vault access..."));
            apply_keybox_request(client, state, &DaemonRequest::InitKeybox);
        }
        UiCommand::RefreshKeybox => {
            set_busy(state, Some("Refreshing shared team access..."));
            apply_keybox_request(client, state, &DaemonRequest::KeyboxStatus);
        }
        UiCommand::GrantKeyboxRecipient {
            recipient_bundle_b64,
        } => {
            set_busy(state, Some("Granting member access..."));
            apply_keybox_request(
                client,
                state,
                &DaemonRequest::GrantKeyboxRecipient {
                    recipient_bundle_b64,
                },
            );
        }
        UiCommand::RevokeKeyboxRecipient { recipient_id } => {
            set_busy(state, Some("Removing member access and rotating vault keys..."));
            apply_keybox_request(
                client,
                state,
                &DaemonRequest::RevokeKeyboxRecipient { recipient_id },
            );
        }
        UiCommand::RefreshConflicts => {
            set_busy(state, Some("Checking conflicted file copies..."));
            match client.request(&DaemonRequest::ListConflicts) {
                Ok(DaemonResponse::Conflicts(items)) => {
                    let mut guard = state.lock();
                    end_task_locked(&mut guard);
                    guard.conflicts = items;
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, friendly_ipc_error(&err)),
            }
        }
        UiCommand::RunCryptoBench { total_mib } => {
            let clamped = total_mib.clamp(4, 512);
            set_busy(state, Some("Testing encryption speed on this computer..."));
            let bg_client = client.clone();
            let bg_state = Arc::clone(state);
            let spawn_res = thread::Builder::new()
                .name("ec-crypto-bench".to_owned())
                .spawn(move || {
                    match bg_client.request(&DaemonRequest::BenchCrypto { total_mib: clamped }) {
                        Ok(DaemonResponse::CryptoBench(report)) => {
                            let enc_gb = report.encrypt_mib_per_sec / 1024.0;
                            let dec_gb = report.decrypt_mib_per_sec / 1024.0;
                            let mut guard = bg_state.lock();
                            end_task_locked(&mut guard);
                            guard.crypto_bench = Some(report);
                            guard.toast_info = Some(format!(
                                "Speed test complete: {enc_gb:.2} GB/s encrypting, {dec_gb:.2} GB/s reading"
                            ));
                            guard.toast_info_set_at = Some(Instant::now());
                            guard.toast_error = None;
                            guard.notify_repaint();
                        }
                        Ok(DaemonResponse::Error { code, message }) => {
                            finish_err(&bg_state, friendly_error_text(&code, &message));
                        }
                        Ok(other) => {
                            finish_err(&bg_state, format!("Unexpected response: {other:?}"))
                        }
                        Err(err) => finish_err(&bg_state, friendly_ipc_error(&err)),
                    }
                });
            if let Err(err) = spawn_res {
                finish_err(state, format!("Failed starting speed test worker: {err}"));
            }
        }
    }
}

fn apply_keybox_request(
    client: &IpcClient,
    state: &Arc<Mutex<SharedWorkerState>>,
    req: &DaemonRequest,
) {
    match client.request(req) {
        Ok(DaemonResponse::KeyboxInfo(summary)) => {
            let count = summary.recipient_ids.len();
            let cur = state.lock().current_dir.clone();
            {
                let mut guard = state.lock();
                guard.keybox_info = Some(summary);
            }
            refresh_status_and_dir(client, state, &cur, false);
            let noun = if count == 1 { "member" } else { "members" };
            finish_ok(
                state,
                format!("Shared access updated ({count} authorized {noun})."),
            );
        }
        Ok(DaemonResponse::Ok { message }) => {
            if let Ok(DaemonResponse::KeyboxInfo(summary)) =
                client.request(&DaemonRequest::KeyboxStatus)
            {
                state.lock().keybox_info = Some(summary);
            }
            let cur = state.lock().current_dir.clone();
            refresh_status_and_dir(client, state, &cur, false);
            finish_ok(state, message);
        }
        Ok(DaemonResponse::Error { code, message }) => {
            finish_err(state, friendly_error_text(&code, &message));
        }
        Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
        Err(err) => finish_err(state, friendly_ipc_error(&err)),
    }
}
