use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::traits::{BackendHealth, BackendQuota, DriveStats, RoutingPolicy};

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

/// IPC request frame sent by `zv` CLI and `zerovault-ui` Tauri tray app to `zerovaultd`.
///
/// Passphrases and secret fields are transmitted ONLY over OS-authenticated local IPC
/// (Windows Named Pipes / `0600` Unix Domain Sockets) and must NEVER be logged.
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
    /// List configured remote backends and quotas.
    ListRemotes,
    /// Mount the virtual drive at `mount_point`.
    Mount {
        /// Local filesystem path for mount / Windows CfApi sync root.
        mount_point: String,
    },
    /// Unmount the active virtual drive.
    Unmount,
    /// Pin a virtual path offline and hydrate all chunks.
    Pin {
        /// Virtual path inside the vault (e.g. `"/Docs/manual.pdf"`).
        virtual_path: String,
    },
    /// Dehydrate a virtual path back to online-only state.
    Dehydrate {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
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
            Self::ListRemotes => f.write_str("DaemonRequest::ListRemotes"),
            Self::Mount { mount_point } => f
                .debug_struct("DaemonRequest::Mount")
                .field("mount_point", mount_point)
                .finish(),
            Self::Unmount => f.write_str("DaemonRequest::Unmount"),
            Self::Pin { virtual_path } => f
                .debug_struct("DaemonRequest::Pin")
                .field("virtual_path", virtual_path)
                .finish(),
            Self::Dehydrate { virtual_path } => f
                .debug_struct("DaemonRequest::Dehydrate")
                .field("virtual_path", virtual_path)
                .finish(),
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
    /// Error payload.
    Error {
        /// Error classification code.
        code: String,
        /// Non-sensitive error description.
        message: String,
    },
}
