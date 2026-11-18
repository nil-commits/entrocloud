use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::traits::{
    BackendHealth, BackendQuota, ConflictRecord, CryptoBenchmarkReport, DriveStats, EntryKind,
    HydrationState, InodeId, RoutingPolicy,
};

/// Maximum IPC frame payload permitted on the local daemon socket/named pipe (`4 MiB` pre-alloc DoS bound).
pub const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Remote backend configuration summary returned over IPC (secrets excluded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAccountSummary {
    /// Stable backend identifier.
    pub id: String,
    /// Provider kind string (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`).
    pub kind: String,
    /// Remote root prefix.
    pub root: String,
    /// Health and quota details.
    pub health: BackendHealth,
}

/// Auto-detected local cloud sync directory for 1-click onboarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedCloudFolder {
    /// Display provider name (`OneDrive`, `Google Drive`, `Dropbox`, `iCloud Drive`, `Local Backup`).
    pub provider: String,
    /// Suggested remote ID.
    pub suggested_id: String,
    /// Local sync folder path.
    pub path: String,
}

/// Summary of an active post-quantum `keybox.zv` shared folder configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboxSummary {
    /// Vault UUID.
    pub vault_id: Uuid,
    /// Current monotonic epoch (`>= 1`).
    pub epoch: u64,
    /// Hex-encoded owner `Ed25519` public key.
    pub owner_pubkey_hex: String,
    /// Authorized recipient 32-hex fingerprints.
    pub recipient_ids: Vec<String>,
}

/// Instantaneous throughput and sync queue telemetry for native UI, tray, and CLI status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ThroughputSnapshot {
    /// Current upload throughput in bytes per second.
    pub upload_bytes_per_sec: u64,
    /// Current download/hydration throughput in bytes per second.
    pub download_bytes_per_sec: u64,
    /// Active dirty operations waiting to sync.
    pub pending_dirty_ops: usize,
    /// Active encrypted/decrypted cache memory in bytes.
    pub cache_bytes_used: u64,
    /// Timestamp of snapshot.
    pub sampled_at: Option<DateTime<Utc>>,
}

/// Automatic PC folder backup job specification (inspired by CloudBridge folder jobs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupJobSpec {
    /// Existing job identifier when editing, or `None` when creating a new backup job.
    pub id: Option<String>,
    /// Friendly display name (e.g., `"Documents"` or `"Tax 2026"`).
    pub name: String,
    /// Local PC source directory path to back up.
    pub source_path: String,
    /// Destination directory path inside the encrypted vault (e.g., `"/Backups/Documents"`).
    pub vault_folder: String,
    /// Automatic run interval in minutes (`0` for manual-only).
    pub interval_minutes: u32,
    /// Whether automatic background backup is enabled while the vault is unlocked.
    pub enabled: bool,
    /// Filename / glob patterns excluded from backup (e.g., `["desktop.ini", "Thumbs.db", "~$*"]`).
    pub excludes: Vec<String>,
}

/// Summary and live status of a configured PC folder backup job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupJobSummary {
    /// Stable backup job identifier.
    pub id: String,
    /// Friendly display name.
    pub name: String,
    /// Local PC source directory path.
    pub source_path: String,
    /// Destination directory path inside the encrypted vault.
    pub vault_folder: String,
    /// Automatic run interval in minutes (`0` for manual-only).
    pub interval_minutes: u32,
    /// Whether automatic background backup is enabled while unlocked.
    pub enabled: bool,
    /// Excluded filename / glob patterns.
    pub excludes: Vec<String>,
    /// Human-readable status (`"Ready"`, `"Backing up…"`, `"Backed up"`, `"Paused"`, `"Locked"`, `"Needs attention"`).
    pub status: String,
    /// Timestamp of most recent backup attempt.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Timestamp of most recent successful backup.
    pub last_success_at: Option<DateTime<Utc>>,
    /// Most recent error message, if any.
    pub last_error: Option<String>,
    /// Files uploaded during the most recent run.
    pub last_files_synced: u64,
    /// Plaintext bytes uploaded during the most recent run.
    pub last_bytes_synced: u64,
}

/// Execution report returned after running or previewing a folder backup job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRunReport {
    /// Backup job identifier (`"*"` when running all jobs).
    pub job_id: String,
    /// `true` when executed in dry-run preview mode (`0` vault/cloud writes).
    pub preview: bool,
    /// Total local files scanned.
    pub files_scanned: u64,
    /// New or modified files encrypted & uploaded (or queued in preview).
    pub files_uploaded: u64,
    /// Unchanged files skipped without re-uploading.
    pub files_unchanged: u64,
    /// Total bytes encrypted & uploaded (or queued in preview).
    pub bytes_uploaded: u64,
    /// Wall-clock duration in milliseconds.
    pub elapsed_ms: u64,
    /// Human-readable summary message.
    pub message: String,
}

/// Connectivity and quota probe report returned by [`DaemonRequest::TestRemote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTestReport {
    /// Tested remote identifier.
    pub id: String,
    /// Provider kind (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`).
    pub kind: String,
    /// Whether connectivity and authentication succeeded.
    pub healthy: bool,
    /// Measured round-trip probe latency in milliseconds.
    pub latency_ms: u64,
    /// Reported storage quota.
    pub quota: BackendQuota,
    /// Human-readable status or diagnostic message.
    pub message: String,
}

/// Comprehensive daemon status report returned by [`DaemonResponse::Status`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultStatusReport {
    /// Active vault UUID, if initialized.
    pub vault_id: Option<Uuid>,
    /// Whether master keys are currently unlocked.
    pub unlocked: bool,
    /// Whether the virtual drive is currently mounted/connected.
    pub mounted: bool,
    /// Active mount point path string, if mounted.
    pub mount_point: Option<String>,
    /// Current manifest revision.
    pub manifest_revision: u64,
    /// Current `keybox.zv` epoch (`0` if single-user vault).
    pub keybox_epoch: u64,
    /// Active routing policy, if configured.
    pub routing_policy: Option<RoutingPolicy>,
    /// Per-remote health & quota summaries.
    pub remotes: Vec<RemoteAccountSummary>,
    /// Aggregated pooled quota across all configured clouds.
    pub pooled_quota: Option<BackendQuota>,
    /// Live throughput & dirty queue stats.
    pub throughput: ThroughputSnapshot,
    /// Virtual filesystem counters.
    pub drive_stats: DriveStats,
    /// Number of recorded non-destructive conflicts.
    pub conflict_count: usize,
    /// Whether automatic background PC folder backups are currently paused.
    #[serde(default)]
    pub backups_paused: bool,
    /// Configured PC folder backup jobs.
    #[serde(default)]
    pub backup_jobs: Vec<BackupJobSummary>,
    /// Human-readable active transfer / backup progress banner, if running.
    #[serde(default)]
    pub active_activity: Option<String>,
}

/// Parameters for registering a remote cloud backend over local IPC.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRemoteParams {
    /// Backend identifier.
    pub id: String,
    /// Provider kind (`gdrive`, `onedrive`, `dropbox`, `s3`, `webdav`, `fs`).
    pub kind: String,
    /// Remote prefix / local directory path / bucket.
    pub root: String,
    /// Optional S3/WebDAV endpoint URL.
    pub endpoint: Option<String>,
    /// Optional bucket name.
    pub bucket: Option<String>,
    /// Optional region.
    pub region: Option<String>,
    /// Optional quota cap in bytes.
    pub quota_limit_bytes: Option<u64>,
    /// Routing policy name (`targeted`, `mirrored`, `pooled`).
    pub policy: Option<String>,
    /// Optional prefix rule for targeted routing.
    pub prefix: Option<String>,
    /// Optional non-OAuth access key / username.
    pub username: Option<String>,
    /// Optional non-OAuth secret (stored in OS keyring, never logged).
    pub secret: Option<String>,
}

impl std::fmt::Debug for AddRemoteParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddRemoteParams")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("root", &self.root)
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("quota_limit_bytes", &self.quota_limit_bytes)
            .field("policy", &self.policy)
            .field("prefix", &"[REDACTED]")
            .field("username", &self.username)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Parameters for starting an interactive browser OAuth2 + S256 PKCE remote login over IPC.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthLoginParams {
    /// Stable backend identifier to register (e.g. `"gdrive-personal"`).
    pub id: String,
    /// OAuth2 provider kind (`"gdrive"`, `"onedrive"`, `"dropbox"`).
    pub kind: String,
    /// Remote root prefix inside the cloud drive.
    pub root: String,
    /// OAuth2 application client ID.
    pub client_id: String,
    /// Optional OAuth2 client secret (never logged; wrapped and stored in OS keyring).
    pub client_secret: Option<String>,
    /// Optional authorization endpoint URL override.
    pub auth_url: Option<String>,
    /// Optional token endpoint URL override.
    pub token_url: Option<String>,
    /// Optional quota cap in bytes for Quota Pooling.
    pub quota_limit_bytes: Option<u64>,
    /// Optional routing policy name (`"targeted"`, `"mirrored"`, `"pooled"`).
    pub policy: Option<String>,
    /// Optional virtual path prefix rule when `policy` is `"targeted"`.
    pub prefix: Option<String>,
    /// Callback timeout in seconds (defaults to 180s if omitted).
    pub timeout_secs: Option<u64>,
    /// Whether the daemon should automatically launch the system browser to the auth URL.
    pub open_browser: bool,
}

impl std::fmt::Debug for OAuthLoginParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthLoginParams")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("root", &self.root)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("quota_limit_bytes", &self.quota_limit_bytes)
            .field("policy", &self.policy)
            .field("prefix", &"[REDACTED]")
            .field("timeout_secs", &self.timeout_secs)
            .field("open_browser", &self.open_browser)
            .finish()
    }
}

/// Virtual file or directory metadata summary returned for GUI/CLI vault browsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntrySummary {
    /// Virtual inode number.
    pub inode: InodeId,
    /// Entry basename.
    pub name: String,
    /// Full normalized virtual path inside the vault.
    pub virtual_path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Plaintext byte size (`0` for directories).
    pub size: u64,
    /// Current on-demand hydration state.
    pub hydration: HydrationState,
    /// Explicit offline pin flag.
    pub pinned: bool,
    /// Monotonic node version.
    pub version: u64,
    /// Last modification timestamp.
    pub modified_at: DateTime<Utc>,
}

/// IPC request frame sent by `zv` CLI, `zerovault-tray`, and native `entrocloud-ui` to `zerovaultd`.
///
/// Framed on wire with a **4-byte big-endian `u32` length prefix** (`<= MAX_IPC_FRAME_BYTES`)
/// followed by UTF-8 `serde_json` bytes over owner-ACL Named Pipes (`\\.\pipe\zerovaultd`)
/// or `0600` Unix Domain Sockets (`$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock`).
#[derive(Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Ping daemon liveness.
    Ping,
    /// Initialize a brand-new encrypted vault at the local state path (and publish `header.zvh` to remotes).
    InitVault {
        /// Passphrase string (never logged).
        passphrase: String,
    },
    /// Unlock an existing vault using its passphrase (fetching `header.zvh` from remotes if absent locally).
    UnlockVault {
        /// Passphrase string (never logged).
        passphrase: String,
    },
    /// Immediately lock the vault, purge staging/LRU caches, zeroize keys, and reclaim `mimalloc` pages.
    LockVault,
    /// Register a remote cloud backend.
    AddRemote(Box<AddRemoteParams>),
    /// Unregister and remove a configured remote cloud backend.
    RemoveRemote {
        /// Backend identifier to remove.
        id: String,
    },
    /// Replace the multi-cloud routing policy live.
    SetRoutingPolicy {
        /// New multi-cloud routing policy.
        policy: RoutingPolicy,
    },
    /// Execute interactive browser OAuth2 + PKCE loopback login and register the remote.
    OAuthLogin(Box<OAuthLoginParams>),
    /// Cancel an in-progress interactive browser OAuth2 login flow, if active.
    CancelOAuth,
    /// Probe connectivity, latency, and quota for a configured remote backend.
    TestRemote {
        /// Backend identifier to test.
        id: String,
    },
    /// List configured remote backends and quotas.
    ListRemotes,
    /// Auto-detect locally installed cloud sync folders (OneDrive, GDrive, Dropbox, iCloud).
    DetectLocalClouds,
    /// List configured automatic PC folder backup jobs.
    ListBackupJobs,
    /// Create or update an automatic PC folder backup job.
    UpsertBackupJob(Box<BackupJobSpec>),
    /// Remove a configured PC folder backup job (local and cloud files remain intact).
    RemoveBackupJob {
        /// Backup job identifier to remove.
        id: String,
    },
    /// Run or dry-run preview a specific PC folder backup job immediately.
    RunBackupJob {
        /// Backup job identifier.
        id: String,
        /// When `true`, scans and reports pending uploads without modifying the vault or cloud.
        preview: bool,
    },
    /// Run or dry-run preview all enabled PC folder backup jobs.
    RunAllBackups {
        /// When `true`, scans without uploading.
        preview: bool,
    },
    /// Decrypt and restore a backed-up folder into a fresh subfolder inside `destination_parent`.
    RestoreBackupJob {
        /// Backup job identifier (or virtual `/Backups/<Name>` path).
        id: String,
        /// Local parent directory where a fresh restore folder will be created.
        destination_parent: String,
    },
    /// Pause or resume automatic background PC folder backup scheduling.
    SetBackupsPaused {
        /// `true` to pause automatic runs; `false` to resume.
        paused: bool,
    },
    /// Cancel any currently running folder backup job and pause scheduling.
    CancelActiveBackup,
    /// Mount the virtual drive at `mount_point`.
    Mount {
        /// Local filesystem path for mount / Windows CfApi sync root.
        mount_point: String,
    },
    /// Mount the virtual drive with explicit native vs mock VFS selection.
    MountWithOptions {
        /// Local filesystem path for mount / Windows CfApi sync root.
        mount_point: String,
        /// When `true`, mount with in-memory `MockDrive`; when `false`, use native OS VFS (`CfApi`/`FUSE3`).
        use_mock_vfs: bool,
    },
    /// Unmount the active virtual drive.
    Unmount,
    /// Pin a virtual path offline and hydrate all chunks.
    Pin {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// Clear the offline pin flag for a virtual path so it becomes eligible for dehydration.
    Unpin {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// Dehydrate a virtual path back to online-only state.
    Dehydrate {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// List direct entries inside a virtual directory inside the vault.
    ListDirectory {
        /// Normalized virtual directory path.
        virtual_path: String,
    },
    /// Create a new virtual directory inside the vault.
    CreateDirectory {
        /// Normalized virtual directory path to create.
        virtual_path: String,
    },
    /// Encrypt and import a local disk file into the vault in bounded 4 MiB chunks.
    ImportLocalFile {
        /// Local disk source file path.
        local_path: String,
        /// Target virtual file or directory path inside the vault.
        virtual_dest_path: String,
    },
    /// Decrypt and export a vault file to a local disk path atomically via `.partial` promotion.
    ExportVaultFile {
        /// Virtual file path inside the vault.
        virtual_path: String,
        /// Local destination file or directory path.
        local_dest_path: String,
    },
    /// Read a small (`<= 2 MiB`) encrypted UTF-8 note directly into memory.
    ReadTextNote {
        /// Virtual file path inside the vault.
        virtual_path: String,
    },
    /// Save an in-memory (`<= 2 MiB`) UTF-8 note directly into encrypted chunks.
    SaveTextNote {
        /// Virtual file path inside the vault.
        virtual_path: String,
        /// UTF-8 note content.
        content: String,
    },
    /// Delete a virtual file or directory (`recursive` deletes directory contents).
    DeleteEntry {
        /// Virtual path inside the vault.
        virtual_path: String,
        /// When `true`, recursively removes non-empty directories.
        recursive: bool,
    },
    /// Rename or move a virtual file or directory inside the vault.
    RenameEntry {
        /// Current virtual path inside the vault.
        virtual_path: String,
        /// Target virtual path or new entry name.
        new_virtual_path: String,
    },
    /// Generate or export the local user's post-quantum `RecipientPublicBundle` (`Ed25519+X25519+ML-KEM-768`).
    ExportRecipientBundle {
        /// Human-readable label if generating for the first time.
        label: String,
    },
    /// Create a 1-click read-only `zv://` capability URI for `virtual_path`.
    CreateCapabilityShare {
        /// Virtual file path to share.
        virtual_path: String,
    },
    /// Open and import a `zv://` capability share URI into `dest_virtual_path`.
    ImportCapabilityShare {
        /// Full `zv://...#<SRK+PubKey>` capability URI.
        uri: String,
        /// Destination virtual path inside the local vault (or local export path).
        dest_virtual_path: String,
    },
    /// Initialize or inspect the vault's `keybox.zv` (`ZVK1`) multi-recipient shared folder keybox.
    InitKeybox,
    /// Grant folder access to a recipient by adding their Base64 `RecipientPublicBundle` to `keybox.zv`.
    GrantKeyboxRecipient {
        /// Base64url-encoded `RecipientPublicBundle`.
        recipient_bundle_b64: String,
    },
    /// Revoke a recipient from `keybox.zv`, rotating `FolderRootKey` and advancing `epoch -> epoch + 1`.
    RevokeKeyboxRecipient {
        /// 32-hex `recipient_id` to revoke.
        recipient_id: String,
    },
    /// Query current `keybox.zv` epoch and authorized recipient list.
    KeyboxStatus,
    /// Run a live hardware AES-256-GCM benchmark (`total_mib` MiB).
    BenchCrypto {
        /// Payload size in MiB (`4..=512`).
        total_mib: usize,
    },
    /// List recorded non-destructive conflict preservation records.
    ListConflicts,
    /// Trigger an immediate manifest & dirty-queue sync cycle.
    SyncNow,
    /// Query full vault, quota, and throughput status.
    Status,
    /// Gracefully shut down the daemon.
    Shutdown,
}

impl std::fmt::Debug for DaemonRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ping => f.write_str("DaemonRequest::Ping"),
            Self::InitVault { .. } => f.write_str("DaemonRequest::InitVault([REDACTED])"),
            Self::UnlockVault { .. } => f.write_str("DaemonRequest::UnlockVault([REDACTED])"),
            Self::LockVault => f.write_str("DaemonRequest::LockVault"),
            Self::AddRemote(params) => f
                .debug_struct("DaemonRequest::AddRemote")
                .field("id", &params.id)
                .field("kind", &params.kind)
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::RemoveRemote { id } => f
                .debug_struct("DaemonRequest::RemoveRemote")
                .field("id", id)
                .finish(),
            Self::SetRoutingPolicy { policy } => f
                .debug_struct("DaemonRequest::SetRoutingPolicy")
                .field("policy", policy)
                .finish(),
            Self::OAuthLogin(params) => f
                .debug_struct("DaemonRequest::OAuthLogin")
                .field("id", &params.id)
                .field("kind", &params.kind)
                .field("client_secret", &"[REDACTED]")
                .finish(),
            Self::CancelOAuth => f.write_str("DaemonRequest::CancelOAuth"),
            Self::TestRemote { id } => f
                .debug_struct("DaemonRequest::TestRemote")
                .field("id", id)
                .finish(),
            Self::ListRemotes => f.write_str("DaemonRequest::ListRemotes"),
            Self::DetectLocalClouds => f.write_str("DaemonRequest::DetectLocalClouds"),
            Self::ListBackupJobs => f.write_str("DaemonRequest::ListBackupJobs"),
            Self::UpsertBackupJob(spec) => f
                .debug_struct("DaemonRequest::UpsertBackupJob")
                .field("id", &spec.id)
                .field("name", &spec.name)
                .field("source_path", &"[REDACTED_PATH]")
                .finish(),
            Self::RemoveBackupJob { id } => f
                .debug_struct("DaemonRequest::RemoveBackupJob")
                .field("id", id)
                .finish(),
            Self::RunBackupJob { id, preview } => f
                .debug_struct("DaemonRequest::RunBackupJob")
                .field("id", id)
                .field("preview", preview)
                .finish(),
            Self::RunAllBackups { preview } => f
                .debug_struct("DaemonRequest::RunAllBackups")
                .field("preview", preview)
                .finish(),
            Self::RestoreBackupJob { id, .. } => f
                .debug_struct("DaemonRequest::RestoreBackupJob")
                .field("id", id)
                .field("destination_parent", &"[REDACTED_PATH]")
                .finish(),
            Self::SetBackupsPaused { paused } => f
                .debug_struct("DaemonRequest::SetBackupsPaused")
                .field("paused", paused)
                .finish(),
            Self::CancelActiveBackup => f.write_str("DaemonRequest::CancelActiveBackup"),
            Self::Mount { mount_point } => f
                .debug_struct("DaemonRequest::Mount")
                .field("mount_point", mount_point)
                .finish(),
            Self::MountWithOptions {
                mount_point,
                use_mock_vfs,
            } => f
                .debug_struct("DaemonRequest::MountWithOptions")
                .field("mount_point", mount_point)
                .field("use_mock_vfs", use_mock_vfs)
                .finish(),
            Self::Unmount => f.write_str("DaemonRequest::Unmount"),
            Self::Pin { .. } => f.write_str("DaemonRequest::Pin([REDACTED_PATH])"),
            Self::Unpin { .. } => f.write_str("DaemonRequest::Unpin([REDACTED_PATH])"),
            Self::Dehydrate { .. } => f.write_str("DaemonRequest::Dehydrate([REDACTED_PATH])"),
            Self::ListDirectory { .. } => {
                f.write_str("DaemonRequest::ListDirectory([REDACTED_PATH])")
            }
            Self::CreateDirectory { .. } => {
                f.write_str("DaemonRequest::CreateDirectory([REDACTED_PATH])")
            }
            Self::ImportLocalFile { .. } => {
                f.write_str("DaemonRequest::ImportLocalFile([REDACTED_PATH])")
            }
            Self::ExportVaultFile { .. } => {
                f.write_str("DaemonRequest::ExportVaultFile([REDACTED_PATH])")
            }
            Self::ReadTextNote { .. } => {
                f.write_str("DaemonRequest::ReadTextNote([REDACTED_PATH])")
            }
            Self::SaveTextNote { .. } => f.write_str("DaemonRequest::SaveTextNote([REDACTED])"),
            Self::DeleteEntry { recursive, .. } => f
                .debug_struct("DaemonRequest::DeleteEntry")
                .field("virtual_path", &"[REDACTED_PATH]")
                .field("recursive", recursive)
                .finish(),
            Self::RenameEntry { .. } => f.write_str("DaemonRequest::RenameEntry([REDACTED_PATH])"),
            Self::ExportRecipientBundle { label } => f
                .debug_struct("DaemonRequest::ExportRecipientBundle")
                .field("label", label)
                .finish(),
            Self::CreateCapabilityShare { .. } => {
                f.write_str("DaemonRequest::CreateCapabilityShare([REDACTED_PATH])")
            }
            Self::ImportCapabilityShare { .. } => {
                f.write_str("DaemonRequest::ImportCapabilityShare([REDACTED_URI])")
            }
            Self::InitKeybox => f.write_str("DaemonRequest::InitKeybox"),
            Self::GrantKeyboxRecipient { .. } => {
                f.write_str("DaemonRequest::GrantKeyboxRecipient([BUNDLE])")
            }
            Self::RevokeKeyboxRecipient { recipient_id } => f
                .debug_struct("DaemonRequest::RevokeKeyboxRecipient")
                .field("recipient_id", recipient_id)
                .finish(),
            Self::KeyboxStatus => f.write_str("DaemonRequest::KeyboxStatus"),
            Self::BenchCrypto { total_mib } => f
                .debug_struct("DaemonRequest::BenchCrypto")
                .field("total_mib", total_mib)
                .finish(),
            Self::ListConflicts => f.write_str("DaemonRequest::ListConflicts"),
            Self::SyncNow => f.write_str("DaemonRequest::SyncNow"),
            Self::Status => f.write_str("DaemonRequest::Status"),
            Self::Shutdown => f.write_str("DaemonRequest::Shutdown"),
        }
    }
}

/// IPC response frame returned by `zerovaultd`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Generic success acknowledgment with status message.
    Ok {
        /// Non-sensitive operational summary.
        message: String,
    },
    /// Vault status payload.
    Status(Box<VaultStatusReport>),
    /// Configured remotes payload.
    Remotes(Vec<RemoteAccountSummary>),
    /// Remote connectivity and quota test report.
    RemoteTest(RemoteTestReport),
    /// Auto-detected local cloud sync folders.
    DetectedClouds(Vec<DetectedCloudFolder>),
    /// Configured PC folder backup jobs.
    BackupJobs(Vec<BackupJobSummary>),
    /// Completed backup or preview run report.
    BackupReport(BackupRunReport),
    /// Completed encrypted backup restore report.
    RestoreCompleted {
        /// Newly created local folder containing the restored files.
        restored_folder: String,
        /// Total files restored and verified.
        files_restored: u64,
        /// Total bytes restored and verified.
        bytes_restored: u64,
    },
    /// Directory listing payload for a virtual path inside the vault.
    DirectoryEntries {
        /// Normalized directory path that was listed.
        virtual_path: String,
        /// Sorted child entries inside the directory.
        entries: Vec<VaultEntrySummary>,
    },
    /// Decrypted UTF-8 text note payload.
    TextNote {
        /// Virtual path of the note.
        virtual_path: String,
        /// UTF-8 content.
        content: String,
    },
    /// Exported post-quantum recipient public bundle.
    RecipientBundle {
        /// 32-hex recipient fingerprint.
        recipient_id: String,
        /// Base64url-encoded `RecipientPublicBundle`.
        bundle_b64: String,
    },
    /// Newly created `zv://` capability share URI.
    ShareUriCreated {
        /// Full `zv://...#<SRK+PubKey>` URI.
        uri: String,
        /// Share object UUID.
        share_id: Uuid,
    },
    /// Active `keybox.zv` summary.
    KeyboxInfo(KeyboxSummary),
    /// Hardware AES-256-GCM benchmark report.
    CryptoBench(CryptoBenchmarkReport),
    /// Recorded conflict preservation events.
    Conflicts(Vec<ConflictRecord>),
    /// Error payload.
    Error {
        /// Error classification code.
        code: String,
        /// Non-sensitive error description.
        message: String,
    },
}
