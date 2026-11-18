//! Clean consumer views for EntroCloud (`Backups`, `My Files`, `Cloud Connections`,
//! `Computer Drive`, `Sharing`, `Settings`, and the locked-vault `Unlock` screen).

pub mod backups;
pub mod clouds;
pub mod drive;
pub mod files;
pub mod settings;
pub mod sharing;
pub mod unlock;

use std::collections::HashMap;

use entrocloud_types::{
    BackupRunReport, ConflictRecord, CryptoBenchmarkReport, DetectedCloudFolder, KeyboxSummary,
    RemoteTestReport, VaultEntrySummary, VaultStatusReport,
};
use zeroize::Zeroizing;

/// Primary left-sidebar navigation pages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NavPage {
    /// Protected PC folder backup schedules & status (`CloudBridge` home).
    #[default]
    Backups,
    /// Encrypted Vault File Browser (Grid & List views + Private Notes).
    MyFiles,
    /// Connected cloud accounts, latency/quota health, and multi-cloud storage rules.
    CloudConnections,
    /// Virtual Explorer / FUSE computer drive mount & throughput stats.
    ComputerDrive,
    /// Private `ec://` share links & shared team vault access.
    Sharing,
    /// Appearance (`Light`/`Dark`/`System`), OS startup, session lock, conflicts, & speed test.
    Settings,
}

#[allow(non_upper_case_globals)]
impl NavPage {
    // Backward-compatible aliases so existing test callers referencing `StudioTab::*` keep compiling cleanly!
    pub const VaultExplorer: Self = Self::MyFiles;
    pub const NoteEditor: Self = Self::MyFiles;
    pub const MultiCloudRouting: Self = Self::CloudConnections;
    pub const ServerlessSharing: Self = Self::Sharing;
    pub const DiagnosticsBench: Self = Self::Settings;

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Backups => "Backups",
            Self::MyFiles => "My Files",
            Self::CloudConnections => "Cloud Connections",
            Self::ComputerDrive => "Computer Drive",
            Self::Sharing => "Sharing",
            Self::Settings => "Settings",
        }
    }
}

/// Sort column for the `My Files` list table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExplorerSortColumn {
    #[default]
    Name,
    Size,
    Hydration,
}

/// Immutable per-frame snapshot copied briefly from `SharedWorkerState` before layout.
pub struct FrameSnapshot {
    pub ipc_endpoint: String,
    pub daemon_connected: bool,
    pub busy_task: Option<String>,
    pub oauth_in_progress: Option<String>,
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
    pub recipient_bundle: Option<(String, String)>,
    pub latest_share_uri: Option<(String, Zeroizing<String>)>,
    pub keybox_info: Option<KeyboxSummary>,
    pub conflicts: Vec<ConflictRecord>,
    pub crypto_bench: Option<CryptoBenchmarkReport>,
    pub active_preview_files: usize,
    pub up_history: Vec<f32>,
    pub down_history: Vec<f32>,
    pub peak_up_mib_s: f64,
    pub peak_down_mib_s: f64,
}
