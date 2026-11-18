//! Non-blocking background IPC worker thread for `entrocloud`.
//!
//! Keeps the `eframe`/`glow` GPU render thread 100% responsive during vault key derivation,
//! file imports/exports, backup runs, hardware speed tests, and interactive browser OAuth2 sign-in
//! (which runs on a dedicated short-lived thread so status polling and `CancelOAuth` never block).

use std::collections::{HashMap, VecDeque};
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
    pub oauth_in_progress: Option<String>,
    pub oauth_cancelled: Arc<AtomicBool>,
    pub toast_info: Option<String>,
    pub toast_error: Option<String>,
    pub status: Option<VaultStatusReport>,
    pub current_dir: String,
    pub entries: Vec<VaultEntrySummary>,
    pub detected_clouds: Vec<DetectedCloudFolder>,
    pub remote_tests: HashMap<String, RemoteTestReport>,
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
            oauth_in_progress: None,
            oauth_cancelled: Arc::new(AtomicBool::new(false)),
            toast_info: None,
            toast_error: None,
            status: None,
            current_dir: "/".to_owned(),
            entries: Vec::new(),
            detected_clouds: Vec::new(),
            remote_tests: HashMap::new(),
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

        if !enable_background_polling {
            return Self {
                state: shared,
                tx,
                stop_flag,
                session_dir,
                join_handle: None,
            };
        }

        let worker_state = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop_flag);
        let worker_session = session_dir.clone();

        let join_handle = thread::spawn(move || {
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

    /// Stops the background worker thread and zero-wipes all previewed temporary session files.
    pub fn shutdown_and_scrub(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.tx.send(UiCommand::ShutdownWorker);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
        let _ = scrub_session_dir(&self.session_dir);
        let mut guard = self.state.lock();
        guard.loaded_note = None;
        guard.latest_share_uri = None;
        guard.active_preview_files = 0;
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
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(UiCommand::ShutdownWorker) => break,
            Ok(cmd) => {
                handle_command(&client, &state, &session_dir, allow_autostart, cmd);
                last_poll = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if last_poll.elapsed() >= Duration::from_millis(1000) {
                    poll_status_quietly(&client, &state, &session_dir);
                    last_poll = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn friendly_error_text(code: &str, message: &str) -> String {
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
    guard.busy_task = label.map(str::to_owned);
    if label.is_some() {
        guard.toast_error = None;
    }
    guard.notify_repaint();
}

fn finish_ok(state: &Arc<Mutex<SharedWorkerState>>, info: impl Into<String>) {
    let mut guard = state.lock();
    guard.busy_task = None;
    guard.toast_info = Some(info.into());
    guard.toast_error = None;
    guard.notify_repaint();
}

fn finish_err(state: &Arc<Mutex<SharedWorkerState>>, err: impl Into<String>) {
    let mut guard = state.lock();
    guard.busy_task = None;
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
                finish_err(state, friendly_error_text(&code, &message));
            }
        }
        Ok(_) => {}
        Err(err) => {
            let mut guard = state.lock();
            guard.daemon_connected = false;
            if surface_errors {
                guard.toast_error = Some(err.to_string());
            }
            guard.notify_repaint();
        }
    }
}

fn expect_ok_response(client: &IpcClient, req: &DaemonRequest) -> Result<String, String> {
    match client.request(req).map_err(|e| e.to_string())? {
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
            state.lock().busy_task = None;
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
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::InitVault { passphrase } => {
            set_busy(state, Some("Creating your encrypted vault..."));
            let req = DaemonRequest::InitVault {
                passphrase: (*passphrase).clone(),
            };
            drop(passphrase);
            let res = expect_ok_response(client, &req);
            drop(req);
            match res {
                Ok(_) => {
                    refresh_status_and_dir(client, state, "/", false);
                    finish_ok(state, "Your encrypted vault is ready and unlocked.");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::UnlockVault {
            passphrase,
            current_dir,
        } => {
            set_busy(state, Some("Unlocking your vault..."));
            let req = DaemonRequest::UnlockVault {
                passphrase: (*passphrase).clone(),
            };
            drop(passphrase);
            let res = expect_ok_response(client, &req);
            drop(req);
            match res {
                Ok(_) => {
                    refresh_status_and_dir(client, state, &current_dir, false);
                    finish_ok(state, "Vault unlocked.");
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::LockVault => {
            set_busy(state, Some("Locking vault and clearing temporary files..."));
            let scrubbed = scrub_session_dir(session_dir);
            let res = expect_ok_response(client, &DaemonRequest::LockVault);
            refresh_status_and_dir(client, state, "/", false);
            {
                let mut guard = state.lock();
                guard.active_preview_files = 0;
                guard.loaded_note = None;
                guard.latest_share_uri = None;
            }
            match res {
                Ok(_) => {
                    let msg = if scrubbed > 0 {
                        format!("Vault locked and {scrubbed} temporary preview file(s) wiped.")
                    } else {
                        "Vault locked.".to_owned()
                    };
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::MountDrive {
            mount_point,
            use_mock_vfs,
        } => {
            set_busy(state, Some("Turning on EntroCloud Drive in File Explorer..."));
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
                    refresh_status_and_dir(client, state, "/", false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::UnmountDrive => {
            set_busy(state, Some("Turning off EntroCloud Drive..."));
            match expect_ok_response(client, &DaemonRequest::Unmount) {
                Ok(msg) => {
                    refresh_status_and_dir(client, state, "/", false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::SyncNow => {
            set_busy(state, Some("Syncing changes across your clouds..."));
            match expect_ok_response(client, &DaemonRequest::SyncNow) {
                Ok(msg) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, msg);
                }
                Err(err) => finish_err(state, err),
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
                    guard.busy_task = None;
                    guard.current_dir = virtual_path;
                    guard.entries = entries;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
            match import_local_paths_recursive(client, &local_paths, &target_dir) {
                Ok(summary) => {
                    refresh_status_and_dir(client, state, &target_dir, false);
                    finish_ok(state, summary.message);
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::ExportVaultFile {
            virtual_path,
            local_dest_path,
        } => {
            set_busy(state, Some("Decrypting and saving copy to this PC..."));
            let norm = normalize_ui_vpath(&virtual_path);
            match expect_ok_response(
                client,
                &DaemonRequest::ExportVaultFile {
                    virtual_path: norm,
                    local_dest_path,
                },
            ) {
                Ok(msg) => finish_ok(state, msg),
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::PreviewVaultFile { virtual_path } => {
            set_busy(state, Some("Opening file in default application..."));
            match export_for_secure_preview(client, session_dir, &virtual_path) {
                Ok(preview_path) => {
                    let count = count_session_preview_files(session_dir);
                    state.lock().active_preview_files = count;
                    match open_in_os_default_app(&preview_path) {
                        Ok(()) => finish_ok(
                            state,
                            "Opened file (temporary copy will be wiped automatically when you lock or exit).",
                        ),
                        Err(err) => finish_err(state, err),
                    }
                }
                Err(err) => finish_err(state, err),
            }
        }
        UiCommand::ScrubPreviewsNow => {
            let wiped = scrub_session_dir(session_dir);
            state.lock().active_preview_files = 0;
            finish_ok(
                state,
                format!("Securely wiped {wiped} temporary preview file(s)."),
            );
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
            let _ = client.request(&DaemonRequest::Unpin {
                virtual_path: norm.clone(),
            });
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
                    guard.busy_task = None;
                    guard.loaded_note = Some((virtual_path, guarded));
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected note response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::SaveTextNote {
            virtual_path,
            content,
            refresh_dir,
        } => {
            if content.len() > MAX_NOTE_BYTES {
                finish_err(
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
                    guard.busy_task = None;
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
            set_busy(state, Some("Testing cloud connection..."));
            match client.request(&DaemonRequest::TestRemote { id: id.clone() }) {
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
                        let mut guard = state.lock();
                        guard.remote_tests.insert(id, report);
                    }
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    if healthy {
                        finish_ok(state, msg);
                    } else {
                        finish_err(state, msg);
                    }
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::OAuthLogin { params } => {
            // Dedicated short-lived thread so `worker_loop` keeps polling status and can send `CancelOAuth`!
            let provider_label = provider_friendly_name(&params.kind);
            let remote_id = params.id.clone();
            let cancel_flag = {
                let mut guard = state.lock();
                guard.oauth_cancelled.store(false, Ordering::SeqCst);
                guard.oauth_in_progress = Some(format!(
                    "Waiting for {provider_label} sign-in in your browser..."
                ));
                guard.toast_error = None;
                guard.notify_repaint();
                Arc::clone(&guard.oauth_cancelled)
            };

            let oauth_client = client.clone();
            let oauth_state = Arc::clone(state);
            let _ = thread::Builder::new()
                .name("ec-oauth".to_owned())
                .spawn(move || {
                    let req = DaemonRequest::OAuthLogin(params);
                    let res = expect_ok_response(&oauth_client, &req);
                    drop(req);

                    let was_cancelled = cancel_flag.load(Ordering::SeqCst);
                    {
                        let mut guard = oauth_state.lock();
                        guard.oauth_in_progress = None;
                    }

                    match res {
                        Ok(_) => {
                            let cur = oauth_state.lock().current_dir.clone();
                            refresh_status_and_dir(&oauth_client, &oauth_state, &cur, false);
                            let mut guard = oauth_state.lock();
                            guard.last_connected_remote = Some(remote_id.clone());
                            guard.toast_info = Some(format!(
                                "Connected {provider_label} ('{remote_id}')."
                            ));
                            guard.toast_error = None;
                            guard.notify_repaint();
                        }
                        Err(err) => {
                            let mut guard = oauth_state.lock();
                            if was_cancelled || err.to_ascii_lowercase().contains("cancel") {
                                guard.toast_info = Some("Browser sign-in was cancelled.".to_owned());
                                guard.toast_error = None;
                            } else {
                                guard.toast_error = Some(err);
                            }
                            guard.notify_repaint();
                        }
                    }
                });
        }
        UiCommand::CancelOAuth => {
            {
                let mut guard = state.lock();
                guard.oauth_cancelled.store(true, Ordering::SeqCst);
                guard.oauth_in_progress = None;
                guard.notify_repaint();
            }
            let _ = client.request(&DaemonRequest::CancelOAuth);
            finish_ok(state, "Cancelled browser sign-in.");
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
            set_busy(
                state,
                Some(if preview {
                    "Previewing changes for backup folder..."
                } else {
                    "Backing up folder..."
                }),
            );
            match client.request(&DaemonRequest::RunBackupJob { id, preview }) {
                Ok(DaemonResponse::BackupReport(report)) => {
                    let summary_msg = report.message.clone();
                    state.lock().last_backup_report = Some(report);
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, summary_msg);
                }
                Ok(DaemonResponse::Ok { message }) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, message);
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected backup response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::RunAllBackups { preview } => {
            set_busy(
                state,
                Some(if preview {
                    "Previewing all protected folders..."
                } else {
                    "Backing up all protected folders..."
                }),
            );
            match client.request(&DaemonRequest::RunAllBackups { preview }) {
                Ok(DaemonResponse::BackupReport(report)) => {
                    let summary_msg = report.message.clone();
                    state.lock().last_backup_report = Some(report);
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, summary_msg);
                }
                Ok(DaemonResponse::Ok { message }) => {
                    let cur = state.lock().current_dir.clone();
                    refresh_status_and_dir(client, state, &cur, false);
                    finish_ok(state, message);
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected backup response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::RestoreBackupJob {
            id,
            destination_parent,
        } => {
            set_busy(state, Some("Decrypting and restoring backup snapshot..."));
            match client.request(&DaemonRequest::RestoreBackupJob {
                id,
                destination_parent,
            }) {
                Ok(DaemonResponse::RestoreCompleted {
                    restored_folder,
                    files_restored,
                    bytes_restored,
                }) => {
                    let msg = format!(
                        "Restored {files_restored} file(s) ({}) into {restored_folder}",
                        format_bytes_human(bytes_restored)
                    );
                    {
                        let mut guard = state.lock();
                        guard.last_restored_folder =
                            Some((restored_folder, files_restored, bytes_restored));
                    }
                    finish_ok(state, msg);
                }
                Ok(DaemonResponse::Ok { message }) => finish_ok(state, message),
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected restore response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
                    guard.busy_task = None;
                    guard.recipient_bundle = Some((recipient_id, bundle_b64));
                    guard.toast_info = Some("Generated your invite code.".to_owned());
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
                    guard.busy_task = None;
                    guard.latest_share_uri = Some((share_id.to_string(), Zeroizing::new(uri)));
                    guard.toast_info = Some(format!("Created private share link for {norm}."));
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
                    guard.busy_task = None;
                    guard.conflicts = items;
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
            }
        }
        UiCommand::RunCryptoBench { total_mib } => {
            let clamped = total_mib.clamp(4, 512);
            set_busy(state, Some("Testing encryption speed on this computer..."));
            match client.request(&DaemonRequest::BenchCrypto { total_mib: clamped }) {
                Ok(DaemonResponse::CryptoBench(report)) => {
                    let enc_gb = report.encrypt_mib_per_sec / 1024.0;
                    let dec_gb = report.decrypt_mib_per_sec / 1024.0;
                    let mut guard = state.lock();
                    guard.busy_task = None;
                    guard.crypto_bench = Some(report);
                    guard.toast_info = Some(format!(
                        "Speed test complete: {enc_gb:.2} GB/s encrypting, {dec_gb:.2} GB/s reading"
                    ));
                    guard.toast_error = None;
                    guard.notify_repaint();
                }
                Ok(DaemonResponse::Error { code, message }) => {
                    finish_err(state, friendly_error_text(&code, &message));
                }
                Ok(other) => finish_err(state, format!("Unexpected response: {other:?}")),
                Err(err) => finish_err(state, err.to_string()),
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
            finish_ok(
                state,
                format!("Shared access updated ({count} authorized member(s))."),
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
        Err(err) => finish_err(state, err.to_string()),
    }
}
