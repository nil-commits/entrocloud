//! CLI parser, `Zeroizing` secret handling (`NEW-M04`), sibling `entrocloudd` auto-spawner,
//! IPC request builder, and output renderer for `ec`.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::{Zeroize, Zeroizing};
use entrocloud_crypto::AwsLcCryptoEngine;
use entrocloud_daemon::{
    DEFAULT_BACKUP_EXCLUDES, DaemonStateConfig, IpcClient, IpcEndpoint, MAX_TEXT_NOTE_BYTES,
};
use entrocloud_types::{
    AddRemoteParams, BackupJobSpec, BackupJobSummary, BackupRunReport, CryptoBenchmarkReport,
    CryptoEngine, DaemonRequest, DaemonResponse, DetectedCloudFolder, KeyboxSummary,
    OAuthLoginParams, RemoteAccountSummary, RemoteTestReport, RoutingPolicy, VaultEntrySummary,
    VaultStatusReport,
};

/// Primary environment variable consulted for non-interactive vault passphrases when `--passphrase-stdin` is false.
pub const ENV_EC_PASSPHRASE: &str = "EC_PASSPHRASE";

/// Legacy backward-compatible environment variable consulted when `EC_PASSPHRASE` is unset.
pub const ENV_ZV_PASSPHRASE: &str = "ZV_PASSPHRASE";

/// Win32 `CREATE_NO_WINDOW` process creation flag (`0x08000000`).
#[cfg(target_os = "windows")]
const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn default_mount_point_string() -> String {
    DaemonStateConfig::default_mount_point()
        .display()
        .to_string()
}

/// Top-level `ec` CLI options and subcommands.
#[derive(Debug, Parser)]
#[command(
    name = "ec",
    version,
    about = "EntroCloud v1.0 zero-knowledge multi-cloud backup, sync, and virtual drive CLI"
)]
pub struct Cli {
    /// Override daemon IPC endpoint (Windows Named Pipe, Unix socket, or tcp://127.0.0.1:PORT)
    #[arg(long = "ipc", global = true, env = "ENTROCLOUD_ENDPOINT")]
    pub ipc: Option<String>,

    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Primary `ec` subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Commands {
    /// Initialize a brand-new zero-knowledge encrypted vault (and publish `header.zvh` to remotes).
    Init {
        /// Read vault passphrase non-interactively from stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Unlock an existing vault using its passphrase (bootstrapping `header.zvh` from remotes if needed).
    Unlock {
        /// Read vault passphrase non-interactively from stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Immediately lock the vault, purge staging/LRU caches, zeroize keys, and reclaim heap pages.
    Lock,
    /// Query vault lock, mount, backup schedule, keybox epoch, quota, and throughput status.
    Status,
    /// Trigger an immediate manifest & dirty-queue synchronization cycle.
    Sync,
    /// Manage remote cloud storage accounts, connectivity tests, and multi-cloud routing policies.
    Remote {
        /// Remote subcommand.
        #[command(subcommand)]
        action: RemoteCommands,
    },
    /// Manage automatic PC folder backup schedules, previews, and 1-click restores.
    Backup {
        /// Backup subcommand.
        #[command(subcommand)]
        action: BackupCommands,
    },
    /// Mount the virtual drive at `<path>` (defaults to `~/EntroCloud`).
    Mount {
        /// Target mount point directory / Windows sync root folder.
        #[arg(default_value_t = default_mount_point_string())]
        path: String,
        /// Mount using in-memory `MockDrive` instead of OS native `CfApi` / `FUSE3`.
        #[arg(long)]
        mock_vfs: bool,
    },
    /// Unmount the active virtual drive.
    Unmount,
    /// Pin a virtual path offline and hydrate all 4 MiB chunks.
    Pin {
        /// Virtual path inside the vault (e.g. `/Docs/manual.pdf`).
        virtual_path: String,
    },
    /// Clear the offline pin flag on a virtual path so it can be dehydrated.
    Unpin {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// Dehydrate a virtual path back to an online-only placeholder.
    Dehydrate {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// List entries inside a virtual vault directory.
    Ls {
        /// Virtual directory path inside the vault (defaults to `/`).
        #[arg(default_value = "/")]
        virtual_path: String,
    },
    /// Create a new virtual directory inside the vault.
    Mkdir {
        /// Virtual directory path inside the vault.
        virtual_path: String,
    },
    /// Encrypt and import a local disk file into the vault in bounded 4 MiB chunks.
    Import {
        /// Local disk source file path.
        local_path: String,
        /// Destination virtual directory or file path inside the vault.
        #[arg(default_value = "/")]
        virtual_dest_path: String,
    },
    /// Decrypt, verify, and atomically export a vault file to a local disk path.
    Export {
        /// Virtual file path inside the vault.
        virtual_path: String,
        /// Local destination file or directory path.
        local_dest_path: String,
    },
    /// Delete a virtual file or directory inside the vault.
    Rm {
        /// Virtual path inside the vault.
        virtual_path: String,
        /// Recursively delete non-empty directories.
        #[arg(short, long)]
        recursive: bool,
    },
    /// Rename or move a virtual file or directory inside the vault.
    Mv {
        /// Existing virtual path inside the vault.
        virtual_path: String,
        /// New basename or target virtual path.
        new_virtual_path: String,
    },
    /// Read or save encrypted UTF-8 text notes (`<= 2 MiB`).
    Note {
        /// Note subcommand.
        #[command(subcommand)]
        action: NoteCommands,
    },
    /// Serverless zero-knowledge E2E sharing (`ec://` & legacy `zv://` capability URIs + post-quantum `keybox.zv`).
    Share {
        /// Sharing subcommand.
        #[command(subcommand)]
        action: ShareCommands,
    },
    /// List recorded non-destructive conflict preservation events.
    Conflicts,
    /// Run a hardware-accelerated AES-256-GCM 4 MiB chunk throughput benchmark.
    BenchCrypto {
        /// Total MiB to encrypt and decrypt (`4..=512`).
        #[arg(long, default_value_t = 64)]
        mib: usize,
        /// Run benchmark inside `entrocloudd` over IPC instead of locally in `ec`.
        #[arg(long)]
        daemon: bool,
    },
    /// Gracefully lock, unmount, and shut down `entrocloudd`.
    Shutdown,
}

/// Remote management subcommands (`ec remote ...`).
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum RemoteCommands {
    /// Register a remote cloud storage backend.
    Add(RemoteAddArgs),
    /// Unregister and remove a configured remote backend.
    Remove {
        /// Backend identifier to remove.
        id: String,
    },
    /// Probe connectivity, round-trip latency, and quota for a configured remote backend.
    Test {
        /// Backend identifier to test.
        id: String,
    },
    /// List configured remote backends and quota telemetry.
    List,
    /// Replace the active multi-cloud routing policy live.
    SetPolicy(SetPolicyArgs),
    /// Auto-detect locally installed cloud sync directories (OneDrive, Google Drive, Dropbox, iCloud).
    DetectClouds,
    /// Authenticate a cloud remote via interactive OAuth2 + S256 PKCE loopback sign-in.
    #[command(name = "oauth")]
    OAuth(RemoteOAuthArgs),
    /// Cancel an in-progress interactive browser OAuth2 sign-in flow.
    #[command(name = "cancel-oauth")]
    CancelOAuth,
}

/// Automatic PC folder backup & restore subcommands (`ec backup ...`).
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum BackupCommands {
    /// List configured PC folder backup jobs and their live status.
    List,
    /// Create or update an automatic PC folder backup job.
    Add(BackupAddArgs),
    /// Remove a configured PC folder backup job (local and cloud files remain intact).
    Remove {
        /// Backup job identifier to remove.
        id: String,
    },
    /// Run a specific backup job immediately (or all enabled jobs when `--all` or no ID is given).
    Run {
        /// Specific backup job ID to run (omit or pass `--all` to run all enabled jobs).
        id: Option<String>,
        /// Run all enabled PC folder backup jobs.
        #[arg(long)]
        all: bool,
    },
    /// Dry-run preview pending uploads for a backup job (or all enabled jobs) with zero writes.
    Preview {
        /// Specific backup job ID to preview (omit or pass `--all` to preview all enabled jobs).
        id: Option<String>,
        /// Preview all enabled PC folder backup jobs.
        #[arg(long)]
        all: bool,
    },
    /// Decrypt and restore a backed-up folder into a fresh timestamped directory inside `destination_parent`.
    Restore {
        /// Backup job ID (or virtual `/Backups/<Name>` path).
        id: String,
        /// Local parent directory where a clean `EntroCloud Restore ...` folder will be created.
        destination_parent: String,
    },
    /// Pause automatic background PC folder backups.
    Pause,
    /// Resume automatic background PC folder backups.
    Resume,
    /// Cancel any active backup transfer immediately and pause automatic scheduling.
    Stop,
}

/// Arguments for `ec backup add`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct BackupAddArgs {
    /// Friendly display name (e.g. `Documents`, `Photos`).
    pub name: String,
    /// Local PC source directory path to back up.
    pub source_path: String,
    /// Existing backup job ID when updating an existing schedule.
    #[arg(long)]
    pub id: Option<String>,
    /// Target directory inside the encrypted vault (defaults to `/Backups/<name>`).
    #[arg(long)]
    pub vault_folder: Option<String>,
    /// Automatic backup cadence in minutes (`0` for manual-only).
    #[arg(long, alias = "interval", default_value_t = 15)]
    pub interval_minutes: u32,
    /// Configure as manual-only (`enabled = false`, `interval_minutes = 0`).
    #[arg(long)]
    pub manual: bool,
    /// Excluded filename / glob patterns (comma-separated or repeatable; defaults to standard OS temp patterns).
    #[arg(long = "exclude", value_delimiter = ',')]
    pub excludes: Vec<String>,
    /// Do not populate default OS exclusion patterns (`desktop.ini`, `Thumbs.db`, `~$*`, `*.tmp`, `.DS_Store`).
    #[arg(long)]
    pub no_default_excludes: bool,
}

/// UTF-8 encrypted note subcommands (`ec note ...`).
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum NoteCommands {
    /// Read and print a UTF-8 note from the vault.
    Read {
        /// Virtual file path inside the vault.
        virtual_path: String,
    },
    /// Save UTF-8 note text (`--content` or stdin) into the vault.
    Save {
        /// Virtual file path inside the vault.
        virtual_path: String,
        /// Inline UTF-8 note text (if omitted, reads from stdin up to 2 MiB).
        #[arg(long)]
        content: Option<String>,
        /// Explicitly read note content from stdin.
        #[arg(long)]
        stdin: bool,
    },
}

/// Serverless zero-knowledge sharing subcommands (`ec share ...`).
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ShareCommands {
    /// Generate or export the local post-quantum `RecipientPublicBundle` (`Ed25519+X25519+ML-KEM-768`).
    Id {
        /// Human-readable label when generating identity for the first time.
        #[arg(long, default_value = "default")]
        label: String,
    },
    /// Create a signed read-only `ec://` capability share URI for a vault file.
    CreateUri {
        /// Virtual file path inside the vault.
        virtual_path: String,
    },
    /// Verify and import an `ec://` (or legacy `zv://`) capability share URI into the vault.
    ImportUri {
        /// Full `ec://share/v1/...#<SRK+PubKey>` (or `zv://...`) capability URI.
        uri: String,
        /// Destination virtual directory or file path inside the vault.
        #[arg(default_value = "/")]
        dest_virtual_path: String,
    },
    /// Initialize or inspect the vault's `keybox.zv` (`ZVK1`) multi-recipient shared folder keybox.
    KeyboxInit,
    /// Grant folder access to a recipient by adding their Base64url `RecipientPublicBundle` to `keybox.zv`.
    KeyboxGrant {
        /// Base64url-encoded `RecipientPublicBundle`.
        recipient_bundle_b64: String,
    },
    /// Revoke a recipient from `keybox.zv`, rotating `FolderRootKey` and advancing `epoch -> epoch + 1`.
    KeyboxRevoke {
        /// 32-hex `recipient_id` fingerprint to revoke.
        recipient_id: String,
    },
    /// Query current `keybox.zv` monotonic epoch and authorized recipient list.
    KeyboxStatus,
}

/// Arguments for `ec remote add`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct RemoteAddArgs {
    /// Stable remote backend identifier (e.g. `gdrive-main`, `s3-archive`).
    pub id: String,
    /// Cloud provider kind.
    #[arg(long, value_enum)]
    pub kind: RemoteKindArg,
    /// Remote root folder/prefix or local directory path.
    #[arg(long)]
    pub root: String,
    /// Optional S3 or WebDAV endpoint URL.
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Optional bucket name (S3).
    #[arg(long)]
    pub bucket: Option<String>,
    /// Optional cloud region (S3).
    #[arg(long)]
    pub region: Option<String>,
    /// Optional quota cap in MiB for Quota Pooling.
    #[arg(long = "quota-mib")]
    pub quota_mib: Option<u64>,
    /// Multi-cloud placement policy (`targeted`, `mirrored`, `pooled`).
    #[arg(long, value_enum)]
    pub policy: Option<RoutingPolicyArg>,
    /// Optional virtual path prefix rule for `targeted` routing.
    #[arg(long)]
    pub prefix: Option<String>,
    /// Optional username / WebDAV user / S3 access key ID.
    #[arg(long)]
    pub username: Option<String>,
    /// Read secret access key / password / OAuth token JSON from stdin.
    #[arg(long)]
    pub secret_stdin: bool,
}

/// Arguments for `ec remote set-policy`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct SetPolicyArgs {
    /// Routing policy mode (`targeted`, `mirrored`, `pooled`).
    #[arg(long, value_enum)]
    pub mode: RoutingPolicyArg,
    /// Backend IDs participating in `pooled` or `mirrored` routing (comma-separated or repeated).
    #[arg(long = "backends", value_delimiter = ',')]
    pub backends: Vec<String>,
    /// Default fallback backend ID for `targeted` routing.
    #[arg(long)]
    pub default_backend: Option<String>,
    /// Minimum replica acknowledgments required for `mirrored` writes.
    #[arg(long)]
    pub min_ack: Option<usize>,
    /// Prefix route rule `<VIRTUAL_PREFIX>=<BACKEND_ID>` for `targeted` routing (repeatable).
    #[arg(long = "route")]
    pub routes: Vec<String>,
}

/// Arguments for `ec remote oauth`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct RemoteOAuthArgs {
    /// Stable backend identifier to register (e.g. `gdrive-personal`).
    pub id: String,
    /// OAuth2 cloud provider (`gdrive`, `onedrive`, `dropbox`).
    #[arg(long, value_enum)]
    pub kind: OAuthKindArg,
    /// Remote root prefix inside the cloud drive.
    #[arg(long, default_value = "/EntroCloud")]
    pub root: String,
    /// OAuth2 application client ID.
    #[arg(long)]
    pub client_id: String,
    /// Read optional OAuth2 client secret from stdin.
    #[arg(long)]
    pub client_secret_stdin: bool,
    /// Optional authorization endpoint URL override.
    #[arg(long)]
    pub auth_url: Option<String>,
    /// Optional token endpoint URL override.
    #[arg(long)]
    pub token_url: Option<String>,
    /// Optional quota cap in MiB for Quota Pooling.
    #[arg(long = "quota-mib")]
    pub quota_mib: Option<u64>,
    /// Multi-cloud placement policy (`targeted`, `mirrored`, `pooled`).
    #[arg(long, value_enum)]
    pub policy: Option<RoutingPolicyArg>,
    /// Optional virtual path prefix rule for `targeted` routing.
    #[arg(long)]
    pub prefix: Option<String>,
    /// Callback timeout in seconds.
    #[arg(long, default_value_t = 180)]
    pub timeout_secs: u64,
    /// Do not automatically launch the system browser.
    #[arg(long)]
    pub no_browser: bool,
}

/// Supported CLI `--kind` values for `ec remote add`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RemoteKindArg {
    /// Google Drive.
    Gdrive,
    /// Microsoft OneDrive.
    Onedrive,
    /// Dropbox.
    Dropbox,
    /// S3-compatible object storage.
    S3,
    /// WebDAV server.
    Webdav,
    /// Local filesystem directory (`opendal::services::Fs`).
    Fs,
}

impl RemoteKindArg {
    /// Canonical string sent over daemon IPC.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gdrive => "gdrive",
            Self::Onedrive => "onedrive",
            Self::Dropbox => "dropbox",
            Self::S3 => "s3",
            Self::Webdav => "webdav",
            Self::Fs => "fs",
        }
    }
}

/// Supported CLI `--kind` values for `ec remote oauth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OAuthKindArg {
    /// Google Drive OAuth2 + PKCE.
    Gdrive,
    /// Microsoft OneDrive OAuth2 + PKCE.
    Onedrive,
    /// Dropbox OAuth2 + PKCE.
    Dropbox,
}

impl OAuthKindArg {
    /// Canonical string sent over daemon IPC.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gdrive => "gdrive",
            Self::Onedrive => "onedrive",
            Self::Dropbox => "dropbox",
        }
    }
}

/// Supported CLI `--policy` / `--mode` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoutingPolicyArg {
    /// Prefix-targeted routing.
    Targeted,
    /// RAID-1 multi-cloud mirroring.
    Mirrored,
    /// Quota-pooled automatic spillover.
    Pooled,
}

impl RoutingPolicyArg {
    /// Canonical string sent over daemon IPC.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Targeted => "targeted",
            Self::Mirrored => "mirrored",
            Self::Pooled => "pooled",
        }
    }
}

/// Parses CLI arguments from an iterator (helpful for unit tests).
pub fn parse_cli_from<I, T>(iter: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(iter)
}

/// Reads a single non-empty secret line into a [`Zeroizing<String>`] (`NEW-M04`).
pub fn read_secret_line(
    stdin: &mut dyn BufRead,
    prompt: Option<&str>,
    stderr: &mut dyn Write,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(label) = prompt {
        write!(stderr, "{label}").context("failed writing prompt")?;
        stderr.flush().context("failed flushing prompt")?;
    }
    let mut line = Zeroizing::new(String::new());
    let n = stdin
        .read_line(&mut line)
        .context("failed reading secret from input")?;
    if n == 0 {
        bail!("unexpected EOF while reading secret input");
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        bail!("secret input must not be empty");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Resolves a vault passphrase wrapped strictly in [`Zeroizing<String>`] (`NEW-M04`):
/// 1. When `passphrase_stdin` is `true`, reads from `stdin`.
/// 2. Else if `EC_PASSPHRASE` (or fallback `ZV_PASSPHRASE`) is set and non-empty, wraps its value in [`Zeroizing`].
/// 3. Else prompts on `stderr` and reads from `stdin`.
pub fn resolve_passphrase(
    passphrase_stdin: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> anyhow::Result<Zeroizing<String>> {
    if passphrase_stdin {
        return read_secret_line(stdin, None, stderr);
    }
    for env_key in [ENV_EC_PASSPHRASE, ENV_ZV_PASSPHRASE] {
        if let Ok(raw_env) = std::env::var(env_key) {
            let wrapped = Zeroizing::new(raw_env);
            let trimmed = wrapped.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                return Ok(Zeroizing::new(trimmed.to_owned()));
            }
        }
    }
    read_secret_line(stdin, Some("Vault passphrase: "), stderr)
}

fn read_bounded_utf8_note(stdin: &mut dyn BufRead) -> anyhow::Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(Vec::new());
    let limit = (MAX_TEXT_NOTE_BYTES as u64).saturating_add(1);
    stdin
        .take(limit)
        .read_to_end(&mut buf)
        .context("failed reading note content from stdin")?;
    if buf.len() > MAX_TEXT_NOTE_BYTES {
        bail!("note content exceeds maximum 2 MiB UTF-8 size");
    }
    let text = std::str::from_utf8(buf.as_slice()).context("note input is not valid UTF-8")?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn build_routing_policy_from_args(args: &SetPolicyArgs) -> anyhow::Result<RoutingPolicy> {
    let cleaned_backends: Vec<String> = args
        .backends
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    match args.mode {
        RoutingPolicyArg::Pooled => {
            if cleaned_backends.is_empty() {
                bail!("--backends must list at least one backend ID for pooled policy");
            }
            Ok(RoutingPolicy::QuotaPooled {
                pool_backends: cleaned_backends,
            })
        }
        RoutingPolicyArg::Mirrored => {
            if cleaned_backends.is_empty() {
                bail!("--backends must list at least one backend ID for mirrored policy");
            }
            let min_ack = args
                .min_ack
                .unwrap_or_else(|| (cleaned_backends.len() / 2) + 1)
                .clamp(1, cleaned_backends.len());
            Ok(RoutingPolicy::Mirrored {
                backends: cleaned_backends,
                min_ack,
            })
        }
        RoutingPolicyArg::Targeted => {
            let default_backend = args
                .default_backend
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| cleaned_backends.first().cloned())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "specify --default-backend <ID> (or --backends <ID>) for targeted policy"
                    )
                })?;

            let mut prefix_routes = Vec::with_capacity(args.routes.len());
            for rule in &args.routes {
                let Some((pfx, bk)) = rule.split_once('=') else {
                    bail!(
                        "invalid --route '{rule}'; expected <VIRTUAL_PREFIX>=<BACKEND_ID> (e.g. /Docs=gdrive-1)"
                    );
                };
                let pfx_trim = pfx.trim();
                let bk_trim = bk.trim();
                if pfx_trim.is_empty() || bk_trim.is_empty() {
                    bail!("invalid --route '{rule}'; prefix and backend ID must be non-empty");
                }
                prefix_routes.push((pfx_trim.to_owned(), bk_trim.to_owned()));
            }

            Ok(RoutingPolicy::Targeted {
                prefix_routes,
                default_backend,
            })
        }
    }
}

/// Converts a parsed CLI [`Commands`] variant into a [`DaemonRequest`].
pub fn build_daemon_request(
    cmd: &mut Commands,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> anyhow::Result<DaemonRequest> {
    match cmd {
        Commands::Init { passphrase_stdin } => {
            let pass = resolve_passphrase(*passphrase_stdin, stdin, stderr)?;
            Ok(DaemonRequest::InitVault {
                passphrase: pass.as_str().to_owned(),
            })
        }
        Commands::Unlock { passphrase_stdin } => {
            let pass = resolve_passphrase(*passphrase_stdin, stdin, stderr)?;
            Ok(DaemonRequest::UnlockVault {
                passphrase: pass.as_str().to_owned(),
            })
        }
        Commands::Lock => Ok(DaemonRequest::LockVault),
        Commands::Status => Ok(DaemonRequest::Status),
        Commands::Sync => Ok(DaemonRequest::SyncNow),
        Commands::Remote { action } => match action {
            RemoteCommands::Add(args) => {
                let secret = if args.secret_stdin {
                    let s = read_secret_line(stdin, None, stderr)?;
                    Some(s.as_str().to_owned())
                } else {
                    None
                };
                let quota_limit_bytes = args
                    .quota_mib
                    .map(|mib| mib.saturating_mul(1024 * 1024));
                Ok(DaemonRequest::AddRemote(Box::new(AddRemoteParams {
                    id: args.id.clone(),
                    kind: args.kind.as_str().to_owned(),
                    root: args.root.clone(),
                    endpoint: args.endpoint.clone(),
                    bucket: args.bucket.clone(),
                    region: args.region.clone(),
                    quota_limit_bytes,
                    policy: args.policy.map(|p| p.as_str().to_owned()),
                    prefix: args.prefix.clone(),
                    username: args.username.clone(),
                    secret,
                })))
            }
            RemoteCommands::Remove { id } => Ok(DaemonRequest::RemoveRemote { id: id.clone() }),
            RemoteCommands::Test { id } => Ok(DaemonRequest::TestRemote { id: id.clone() }),
            RemoteCommands::List => Ok(DaemonRequest::ListRemotes),
            RemoteCommands::SetPolicy(args) => {
                let policy = build_routing_policy_from_args(args)?;
                Ok(DaemonRequest::SetRoutingPolicy { policy })
            }
            RemoteCommands::DetectClouds => Ok(DaemonRequest::DetectLocalClouds),
            RemoteCommands::OAuth(args) => {
                let client_secret = if args.client_secret_stdin {
                    let s = read_secret_line(stdin, None, stderr)?;
                    Some(s.as_str().to_owned())
                } else {
                    None
                };
                let quota_limit_bytes = args
                    .quota_mib
                    .map(|mib| mib.saturating_mul(1024 * 1024));
                Ok(DaemonRequest::OAuthLogin(Box::new(OAuthLoginParams {
                    id: args.id.clone(),
                    kind: args.kind.as_str().to_owned(),
                    root: args.root.clone(),
                    client_id: args.client_id.clone(),
                    client_secret,
                    auth_url: args.auth_url.clone(),
                    token_url: args.token_url.clone(),
                    quota_limit_bytes,
                    policy: args.policy.map(|p| p.as_str().to_owned()),
                    prefix: args.prefix.clone(),
                    timeout_secs: Some(args.timeout_secs),
                    open_browser: !args.no_browser,
                })))
            }
            RemoteCommands::CancelOAuth => Ok(DaemonRequest::CancelOAuth),
        },
        Commands::Backup { action } => match action {
            BackupCommands::List => Ok(DaemonRequest::ListBackupJobs),
            BackupCommands::Add(args) => {
                let (enabled, interval_minutes) = if args.manual || args.interval_minutes == 0 {
                    (false, 0)
                } else {
                    (true, args.interval_minutes)
                };
                let excludes = if !args.excludes.is_empty() {
                    args.excludes.clone()
                } else if args.no_default_excludes {
                    Vec::new()
                } else {
                    DEFAULT_BACKUP_EXCLUDES
                        .iter()
                        .map(|s| (*s).to_owned())
                        .collect()
                };
                let vault_folder = args
                    .vault_folder
                    .clone()
                    .unwrap_or_else(|| format!("/Backups/{}", args.name.trim()));
                Ok(DaemonRequest::UpsertBackupJob(Box::new(BackupJobSpec {
                    id: args.id.clone(),
                    name: args.name.clone(),
                    source_path: args.source_path.clone(),
                    vault_folder,
                    interval_minutes,
                    enabled,
                    excludes,
                })))
            }
            BackupCommands::Remove { id } => Ok(DaemonRequest::RemoveBackupJob { id: id.clone() }),
            BackupCommands::Run { id, all } => {
                if *all || id.is_none() {
                    Ok(DaemonRequest::RunAllBackups { preview: false })
                } else if let Some(job_id) = id {
                    Ok(DaemonRequest::RunBackupJob {
                        id: job_id.clone(),
                        preview: false,
                    })
                } else {
                    Ok(DaemonRequest::RunAllBackups { preview: false })
                }
            }
            BackupCommands::Preview { id, all } => {
                if *all || id.is_none() {
                    Ok(DaemonRequest::RunAllBackups { preview: true })
                } else if let Some(job_id) = id {
                    Ok(DaemonRequest::RunBackupJob {
                        id: job_id.clone(),
                        preview: true,
                    })
                } else {
                    Ok(DaemonRequest::RunAllBackups { preview: true })
                }
            }
            BackupCommands::Restore {
                id,
                destination_parent,
            } => Ok(DaemonRequest::RestoreBackupJob {
                id: id.clone(),
                destination_parent: destination_parent.clone(),
            }),
            BackupCommands::Pause => Ok(DaemonRequest::SetBackupsPaused { paused: true }),
            BackupCommands::Resume => Ok(DaemonRequest::SetBackupsPaused { paused: false }),
            BackupCommands::Stop => Ok(DaemonRequest::CancelActiveBackup),
        },
        Commands::Mount { path, mock_vfs } => {
            if *mock_vfs {
                Ok(DaemonRequest::MountWithOptions {
                    mount_point: path.clone(),
                    use_mock_vfs: true,
                })
            } else {
                Ok(DaemonRequest::Mount {
                    mount_point: path.clone(),
                })
            }
        }
        Commands::Unmount => Ok(DaemonRequest::Unmount),
        Commands::Pin { virtual_path } => Ok(DaemonRequest::Pin {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Unpin { virtual_path } => Ok(DaemonRequest::Unpin {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Dehydrate { virtual_path } => Ok(DaemonRequest::Dehydrate {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Ls { virtual_path } => Ok(DaemonRequest::ListDirectory {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Mkdir { virtual_path } => Ok(DaemonRequest::CreateDirectory {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Import {
            local_path,
            virtual_dest_path,
        } => Ok(DaemonRequest::ImportLocalFile {
            local_path: local_path.clone(),
            virtual_dest_path: virtual_dest_path.clone(),
        }),
        Commands::Export {
            virtual_path,
            local_dest_path,
        } => Ok(DaemonRequest::ExportVaultFile {
            virtual_path: virtual_path.clone(),
            local_dest_path: local_dest_path.clone(),
        }),
        Commands::Rm {
            virtual_path,
            recursive,
        } => Ok(DaemonRequest::DeleteEntry {
            virtual_path: virtual_path.clone(),
            recursive: *recursive,
        }),
        Commands::Mv {
            virtual_path,
            new_virtual_path,
        } => Ok(DaemonRequest::RenameEntry {
            virtual_path: virtual_path.clone(),
            new_virtual_path: new_virtual_path.clone(),
        }),
        Commands::Note { action } => match action {
            NoteCommands::Read { virtual_path } => Ok(DaemonRequest::ReadTextNote {
                virtual_path: virtual_path.clone(),
            }),
            NoteCommands::Save {
                virtual_path,
                content,
                stdin: force_stdin,
            } => {
                let text: Zeroizing<String> = if !*force_stdin
                    && let Some(mut inline) = content.take()
                {
                    let z = Zeroizing::new(std::mem::take(&mut inline));
                    inline.zeroize();
                    if z.len() > MAX_TEXT_NOTE_BYTES {
                        bail!("note content exceeds maximum 2 MiB UTF-8 size");
                    }
                    z
                } else {
                    read_bounded_utf8_note(stdin)?
                };
                Ok(DaemonRequest::SaveTextNote {
                    virtual_path: virtual_path.clone(),
                    content: text.as_str().to_owned(),
                })
            }
        },
        Commands::Share { action } => match action {
            ShareCommands::Id { label } => Ok(DaemonRequest::ExportRecipientBundle {
                label: label.clone(),
            }),
            ShareCommands::CreateUri { virtual_path } => Ok(DaemonRequest::CreateCapabilityShare {
                virtual_path: virtual_path.clone(),
            }),
            ShareCommands::ImportUri {
                uri,
                dest_virtual_path,
            } => {
                let mut taken_uri = std::mem::take(uri);
                let z_uri = Zeroizing::new(taken_uri.clone());
                taken_uri.zeroize();
                Ok(DaemonRequest::ImportCapabilityShare {
                    uri: z_uri.as_str().to_owned(),
                    dest_virtual_path: dest_virtual_path.clone(),
                })
            }
            ShareCommands::KeyboxInit => Ok(DaemonRequest::InitKeybox),
            ShareCommands::KeyboxGrant {
                recipient_bundle_b64,
            } => Ok(DaemonRequest::GrantKeyboxRecipient {
                recipient_bundle_b64: recipient_bundle_b64.clone(),
            }),
            ShareCommands::KeyboxRevoke { recipient_id } => {
                Ok(DaemonRequest::RevokeKeyboxRecipient {
                    recipient_id: recipient_id.clone(),
                })
            }
            ShareCommands::KeyboxStatus => Ok(DaemonRequest::KeyboxStatus),
        },
        Commands::Conflicts => Ok(DaemonRequest::ListConflicts),
        Commands::BenchCrypto { mib, .. } => Ok(DaemonRequest::BenchCrypto { total_mib: *mib }),
        Commands::Shutdown => Ok(DaemonRequest::Shutdown),
    }
}

fn scrub_daemon_request(req: &mut DaemonRequest) {
    match req {
        DaemonRequest::InitVault { passphrase } | DaemonRequest::UnlockVault { passphrase } => {
            passphrase.zeroize();
        }
        DaemonRequest::AddRemote(params) => {
            if let Some(ref mut s) = params.secret {
                s.zeroize();
            }
        }
        DaemonRequest::OAuthLogin(params) => {
            if let Some(ref mut s) = params.client_secret {
                s.zeroize();
            }
        }
        DaemonRequest::SaveTextNote { content, .. } => {
            content.zeroize();
        }
        DaemonRequest::ImportCapabilityShare { uri, .. } => {
            uri.zeroize();
        }
        _ => {}
    }
}

/// Locates the sibling `entrocloudd` executable next to `std::env::current_exe()`.
#[must_use]
pub fn locate_sibling_daemon_exe() -> Option<PathBuf> {
    let cur = std::env::current_exe().ok()?;
    let dir = cur.parent()?;
    let bin_name = if cfg!(target_os = "windows") {
        "entrocloudd.exe"
    } else {
        "entrocloudd"
    };
    let candidate = dir.join(bin_name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn spawn_detached_entrocloudd(exe_path: &Path) -> anyhow::Result<()> {
    let mut cmd = ProcessCommand::new(exe_path);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    }
    let _child = cmd
        .spawn()
        .with_context(|| format!("failed spawning background daemon {}", exe_path.display()))?;
    Ok(())
}

async fn ensure_daemon_autostart_if_default(
    client: &IpcClient,
    allow_autostart: bool,
) -> anyhow::Result<()> {
    if !allow_autostart {
        return Ok(());
    }
    if client.ping().await.is_ok() {
        return Ok(());
    }
    let Some(daemon_exe) = locate_sibling_daemon_exe() else {
        return Ok(());
    };
    spawn_detached_entrocloudd(&daemon_exe)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if client.ping().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    Ok(())
}

/// Runs `AwsLcCryptoEngine::benchmark_aes256_gcm(mib)` locally and returns the report.
pub fn run_local_crypto_benchmark(mib: usize) -> anyhow::Result<CryptoBenchmarkReport> {
    let clamped = mib.clamp(4, 512);
    let engine = AwsLcCryptoEngine::new()
        .context("failed initializing hardware-accelerated AES-256-GCM engine")?;
    engine
        .benchmark_aes256_gcm(clamped)
        .context("AES-256-GCM benchmark failed")
}

/// Executes a parsed [`Cli`] command using injectable stdio streams for clean unit testing.
pub async fn run_cli_with_io(
    cli: Cli,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<()> {
    Box::pin(run_cli_with_io_inner(cli, stdin, stderr, stdout)).await
}

async fn run_cli_with_io_inner(
    mut cli: Cli,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
    stdout: &mut dyn Write,
) -> anyhow::Result<()> {
    if let Commands::BenchCrypto { mib, daemon: false } = cli.command
        && cli.ipc.is_none()
    {
        let report = run_local_crypto_benchmark(mib)?;
        if cli.json {
            write_json_pretty(stdout, &report)?;
        } else {
            write_benchmark_report(stdout, &report)?;
        }
        return Ok(());
    }

    let explicit_ipc = cli.ipc.is_some();
    let endpoint = match cli.ipc.as_deref() {
        Some(raw) => IpcEndpoint::parse(raw).context("invalid --ipc / --endpoint value")?,
        None => IpcEndpoint::from_env_or_default().context("failed resolving IPC endpoint")?,
    };
    let is_default_ep = !explicit_ipc && endpoint == IpcEndpoint::default();
    let allow_autostart = is_default_ep && !matches!(cli.command, Commands::Shutdown);
    let client = IpcClient::new(endpoint);

    let mut request = build_daemon_request(&mut cli.command, stdin, stderr)?;
    let _ = ensure_daemon_autostart_if_default(&client, allow_autostart).await;
    let response_res = client.request(&request).await;
    scrub_daemon_request(&mut request);

    let response = match response_res {
        Ok(resp) => resp,
        Err(err) => {
            return Err(err).context("failed communicating with entrocloudd");
        }
    };

    render_daemon_response(response, cli.json, stdout)
}

fn write_json_pretty<T: serde::Serialize>(stdout: &mut dyn Write, value: &T) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *stdout, value).context("failed serializing JSON output")?;
    writeln!(stdout).context("failed writing trailing newline")?;
    Ok(())
}

fn render_daemon_response(
    response: DaemonResponse,
    json_output: bool,
    stdout: &mut dyn Write,
) -> anyhow::Result<()> {
    if let DaemonResponse::Error { code, message } = response {
        bail!("[{code}] {message}");
    }

    if json_output {
        return match response {
            DaemonResponse::Status(report) => write_json_pretty(stdout, &report),
            DaemonResponse::Remotes(remotes) => write_json_pretty(stdout, &remotes),
            DaemonResponse::RemoteTest(report) => write_json_pretty(stdout, &report),
            DaemonResponse::DetectedClouds(clouds) => write_json_pretty(stdout, &clouds),
            DaemonResponse::BackupJobs(jobs) => write_json_pretty(stdout, &jobs),
            DaemonResponse::BackupReport(report) => write_json_pretty(stdout, &report),
            DaemonResponse::CryptoBench(report) => write_json_pretty(stdout, &report),
            DaemonResponse::KeyboxInfo(info) => write_json_pretty(stdout, &info),
            DaemonResponse::Conflicts(conflicts) => write_json_pretty(stdout, &conflicts),
            other => write_json_pretty(stdout, &other),
        };
    }

    match response {
        DaemonResponse::Ok { message } => {
            writeln!(stdout, "{message}").context("failed writing output")?;
            Ok(())
        }
        DaemonResponse::Status(report) => write_status_report(stdout, &report),
        DaemonResponse::Remotes(remotes) => write_remotes_table(stdout, &remotes),
        DaemonResponse::RemoteTest(report) => write_remote_test_report(stdout, &report),
        DaemonResponse::DetectedClouds(clouds) => write_detected_clouds(stdout, &clouds),
        DaemonResponse::BackupJobs(jobs) => write_backup_jobs_table(stdout, &jobs),
        DaemonResponse::BackupReport(report) => write_backup_run_report(stdout, &report),
        DaemonResponse::RestoreCompleted {
            restored_folder,
            files_restored,
            bytes_restored,
        } => {
            writeln!(
                stdout,
                "Restore complete: {files_restored} file(s) ({bytes_restored} B) restored to {restored_folder}"
            )?;
            Ok(())
        }
        DaemonResponse::DirectoryEntries {
            virtual_path,
            entries,
        } => write_directory_entries(stdout, &virtual_path, &entries),
        DaemonResponse::TextNote { content, .. } => {
            write!(stdout, "{content}").context("failed writing note content")?;
            if !content.ends_with('\n') {
                writeln!(stdout).context("failed writing trailing newline")?;
            }
            Ok(())
        }
        DaemonResponse::RecipientBundle {
            recipient_id,
            bundle_b64,
        } => {
            writeln!(stdout, "Recipient ID: {recipient_id}")?;
            writeln!(stdout, "Bundle:       {bundle_b64}")?;
            Ok(())
        }
        DaemonResponse::ShareUriCreated { uri, share_id } => {
            writeln!(stdout, "Share ID: {share_id}")?;
            writeln!(stdout, "URI:      {uri}")?;
            Ok(())
        }
        DaemonResponse::KeyboxInfo(summary) => write_keybox_summary(stdout, &summary),
        DaemonResponse::CryptoBench(report) => write_benchmark_report(stdout, &report),
        DaemonResponse::Conflicts(conflicts) => {
            writeln!(stdout, "Conflicts ({}):", conflicts.len())?;
            for c in conflicts {
                writeln!(
                    stdout,
                    "  {} -> {} (rev {})",
                    c.original_path, c.conflict_path, c.remote_revision
                )?;
            }
            Ok(())
        }
        DaemonResponse::Error { code, message } => bail!("[{code}] {message}"),
    }
}

fn write_remote_test_report(
    stdout: &mut dyn Write,
    report: &RemoteTestReport,
) -> anyhow::Result<()> {
    let state = if report.healthy { "healthy" } else { "unhealthy" };
    writeln!(stdout, "Remote Test:  {} [{}] ({state})", report.id, report.kind)?;
    writeln!(stdout, "  Latency:    {} ms", report.latency_ms)?;
    writeln!(
        stdout,
        "  Quota:      used={}B / total={}B (avail={}B)",
        report.quota.used_bytes, report.quota.total_bytes, report.quota.available_bytes
    )?;
    writeln!(stdout, "  Message:    {}", report.message)?;
    Ok(())
}

fn write_backup_jobs_table(
    stdout: &mut dyn Write,
    jobs: &[BackupJobSummary],
) -> anyhow::Result<()> {
    if jobs.is_empty() {
        writeln!(stdout, "No automatic PC folder backup jobs configured.")?;
        return Ok(());
    }
    writeln!(stdout, "Backup Jobs ({}):", jobs.len())?;
    for job in jobs {
        let cadence = if !job.enabled || job.interval_minutes == 0 {
            "manual".to_owned()
        } else {
            format!("every {}m", job.interval_minutes)
        };
        writeln!(
            stdout,
            "  - {} [id={}] status=\"{}\" ({}) {} -> {}",
            job.name, job.id, job.status, cadence, job.source_path, job.vault_folder
        )?;
    }
    Ok(())
}

fn write_backup_run_report(
    stdout: &mut dyn Write,
    report: &BackupRunReport,
) -> anyhow::Result<()> {
    writeln!(stdout, "{}", report.message)?;
    writeln!(
        stdout,
        "  Job: {} | Scanned: {} | Uploaded: {} ({} B) | Unchanged: {} | Elapsed: {} ms",
        report.job_id,
        report.files_scanned,
        report.files_uploaded,
        report.bytes_uploaded,
        report.files_unchanged,
        report.elapsed_ms
    )?;
    Ok(())
}

fn write_detected_clouds(
    stdout: &mut dyn Write,
    clouds: &[DetectedCloudFolder],
) -> anyhow::Result<()> {
    writeln!(stdout, "Detected Cloud Folders ({}):", clouds.len())?;
    for c in clouds {
        writeln!(
            stdout,
            "  - {} [id={}] path={}",
            c.provider, c.suggested_id, c.path
        )?;
    }
    Ok(())
}

fn write_directory_entries(
    stdout: &mut dyn Write,
    virtual_path: &str,
    entries: &[VaultEntrySummary],
) -> anyhow::Result<()> {
    writeln!(stdout, "Directory {virtual_path} ({} entries):", entries.len())?;
    for entry in entries {
        writeln!(
            stdout,
            "  {:?} {} ({} B, state={}, pinned={})",
            entry.kind,
            entry.name,
            entry.size,
            entry.hydration.as_xattr_str(),
            entry.pinned
        )?;
    }
    Ok(())
}

fn write_keybox_summary(stdout: &mut dyn Write, summary: &KeyboxSummary) -> anyhow::Result<()> {
    writeln!(stdout, "Keybox Vault ID: {}", summary.vault_id)?;
    writeln!(stdout, "Keybox Epoch:    {}", summary.epoch)?;
    writeln!(stdout, "Owner PubKey:    {}", summary.owner_pubkey_hex)?;
    writeln!(
        stdout,
        "Recipients ({}):  {}",
        summary.recipient_ids.len(),
        summary.recipient_ids.join(", ")
    )?;
    Ok(())
}

fn write_benchmark_report(
    stdout: &mut dyn Write,
    report: &CryptoBenchmarkReport,
) -> anyhow::Result<()> {
    writeln!(stdout, "EntroCloud Hardware Crypto Benchmark")?;
    writeln!(stdout, "  Arch:           {}", report.caps.arch)?;
    writeln!(stdout, "  Backend:        {}", report.caps.backend_name)?;
    writeln!(stdout, "  AES HW:         {}", report.caps.aes_hw)?;
    writeln!(stdout, "  PCLMUL/PMULL:   {}", report.caps.pclmul_hw)?;
    writeln!(stdout, "  VAES:           {}", report.caps.vaes_hw)?;
    writeln!(stdout, "  AVX2:           {}", report.caps.avx2_hw)?;
    writeln!(
        stdout,
        "  Mandatory HW:   {}",
        report.caps.mandatory_satisfied
    )?;
    writeln!(stdout, "  Payload:        {} MiB (4 MiB chunks)", report.total_mib)?;
    writeln!(
        stdout,
        "  Encrypt:        {:.2} MiB/s ({} ms)",
        report.encrypt_mib_per_sec, report.encrypt_elapsed_ms
    )?;
    writeln!(
        stdout,
        "  Decrypt+Verify: {:.2} MiB/s ({} ms)",
        report.decrypt_mib_per_sec, report.decrypt_elapsed_ms
    )?;
    Ok(())
}

fn write_remotes_table(
    stdout: &mut dyn Write,
    remotes: &[RemoteAccountSummary],
) -> anyhow::Result<()> {
    if remotes.is_empty() {
        writeln!(stdout, "No remote backends configured.")?;
        return Ok(());
    }

    writeln!(stdout, "Configured Remotes ({}):", remotes.len())?;
    for remote in remotes {
        let status = if remote.health.healthy {
            "healthy"
        } else {
            "offline/unhealthy"
        };
        let latency = remote
            .health
            .latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".to_owned());
        writeln!(
            stdout,
            "  - {} [{}] root={} status={} latency={} used={}B total={}B",
            remote.id,
            remote.kind,
            remote.root,
            status,
            latency,
            remote.health.quota.used_bytes,
            remote.health.quota.total_bytes
        )?;
    }
    Ok(())
}

fn write_status_report(stdout: &mut dyn Write, report: &VaultStatusReport) -> anyhow::Result<()> {
    writeln!(
        stdout,
        "Vault ID:     {}",
        report
            .vault_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "<uninitialized>".to_owned())
    )?;
    writeln!(stdout, "Unlocked:     {}", report.unlocked)?;
    writeln!(
        stdout,
        "Mounted:      {}{}",
        report.mounted,
        report
            .mount_point
            .as_deref()
            .map(|p| format!(" ({p})"))
            .unwrap_or_default()
    )?;
    writeln!(stdout, "Manifest:     rev {}", report.manifest_revision)?;
    writeln!(stdout, "Keybox Epoch: {}", report.keybox_epoch)?;
    writeln!(
        stdout,
        "Policy:       {}",
        format_routing_policy(report.routing_policy.as_ref())
    )?;
    writeln!(
        stdout,
        "Throughput:   up={} B/s down={} B/s dirty_ops={} cache={} B",
        report.throughput.upload_bytes_per_sec,
        report.throughput.download_bytes_per_sec,
        report.throughput.pending_dirty_ops,
        report.throughput.cache_bytes_used
    )?;
    if let Some(ref quota) = report.pooled_quota {
        writeln!(
            stdout,
            "Pool Quota:   used={}B / total={}B (avail={}B)",
            quota.used_bytes, quota.total_bytes, quota.available_bytes
        )?;
    }
    writeln!(stdout, "Conflicts:    {}", report.conflict_count)?;
    writeln!(
        stdout,
        "Backups:      {} ({} job(s))",
        if report.backups_paused {
            "paused"
        } else {
            "active"
        },
        report.backup_jobs.len()
    )?;
    if let Some(ref act) = report.active_activity {
        writeln!(stdout, "Activity:     {act}")?;
    }
    write_remotes_table(stdout, &report.remotes)?;
    if !report.backup_jobs.is_empty() {
        write_backup_jobs_table(stdout, &report.backup_jobs)?;
    }
    Ok(())
}

fn format_routing_policy(policy: Option<&RoutingPolicy>) -> String {
    match policy {
        None => "none".to_owned(),
        Some(RoutingPolicy::Targeted {
            prefix_routes,
            default_backend,
        }) => format!(
            "targeted (default={default_backend}, rules={})",
            prefix_routes.len()
        ),
        Some(RoutingPolicy::Mirrored { backends, min_ack }) => {
            format!("mirrored (backends={}, min_ack={min_ack})", backends.len())
        }
        Some(RoutingPolicy::QuotaPooled { pool_backends }) => {
            format!("pooled (backends={})", pool_backends.len())
        }
    }
}
