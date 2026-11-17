use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::traits::{
    BackendHealth, BackendQuota, ConflictRecord, DriveStats, EntryKind, HydrationState, InodeId,
    RoutingPolicy,
};

/// Maximum IPC frame payload permitted on the local daemon socket/named pipe (16 MiB).
pub const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;

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

/// Instantaneous throughput and sync queue telemetry for tray UI and CLI status.
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
            .field("prefix", &self.prefix)
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

/// IPC request frame sent by `zv` CLI and `zerovault-ui` Tauri app to `zerovaultd`.
///
/// Passphrases, secret fields, and plaintext virtual paths are transmitted ONLY over
/// OS-authenticated local IPC (Windows Named Pipes / `0600` Unix Domain Sockets) and must NEVER be logged.
#[derive(Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Ping daemon liveness.
    Ping,
    /// Initialize a brand-new encrypted vault at the local state path.
    InitVault {
        /// Passphrase string (never logged).
        passphrase: String,
    },
    /// Unlock an existing vault using its passphrase.
    UnlockVault {
        /// Passphrase string (never logged).
        passphrase: String,
    },
    /// Immediately lock the vault and zeroize all keys in RAM.
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
    /// List configured remote backends and quotas.
    ListRemotes,
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
        /// Virtual path inside the vault (e.g. `"/Docs/manual.pdf"`).
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
        /// Normalized virtual directory path (e.g. `"/"` or `"/Docs"`).
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
    /// Decrypt and export a vault file to a local disk path in bounded 4 MiB chunks.
    ExportVaultFile {
        /// Virtual file path inside the vault.
        virtual_path: String,
        /// Local destination file or directory path.
        local_dest_path: String,
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
            Self::ListRemotes => f.write_str("DaemonRequest::ListRemotes"),
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
            Self::DeleteEntry { recursive, .. } => f
                .debug_struct("DaemonRequest::DeleteEntry")
                .field("virtual_path", &"[REDACTED_PATH]")
                .field("recursive", recursive)
                .finish(),
            Self::RenameEntry { .. } => f.write_str("DaemonRequest::RenameEntry([REDACTED_PATH])"),
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
    /// Directory listing payload for a virtual path inside the vault.
    DirectoryEntries {
        /// Normalized directory path that was listed.
        virtual_path: String,
        /// Sorted child entries inside the directory.
        entries: Vec<VaultEntrySummary>,
    },
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
