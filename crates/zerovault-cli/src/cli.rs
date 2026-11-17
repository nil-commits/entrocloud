//! CLI parser, request builder, and testable command runner for `zv`.

use std::io::{BufRead, Write};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;
use zerovault_crypto::AwsLcCryptoEngine;
use zerovault_daemon::{IpcClient, IpcEndpoint};
use zerovault_types::{
    AddRemoteParams, CryptoBenchmarkReport, CryptoEngine, DaemonRequest, DaemonResponse,
    RemoteAccountSummary, RoutingPolicy, VaultStatusReport,
};

/// Top-level `zv` CLI options and subcommands.
#[derive(Debug, Parser)]
#[command(
    name = "zv",
    version,
    about = "Zerovault zero-knowledge multi-cloud virtual drive CLI"
)]
pub struct Cli {
    /// Override daemon IPC endpoint (Windows pipe, Unix socket, or tcp://127.0.0.1:PORT)
    #[arg(long, global = true, env = "ZEROVAULT_ENDPOINT")]
    pub endpoint: Option<String>,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Primary `zv` subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Commands {
    /// Initialize a brand-new zero-knowledge encrypted vault.
    Init {
        /// Read vault passphrase non-interactively from stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Unlock an existing vault using its passphrase.
    Unlock {
        /// Read vault passphrase non-interactively from stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Immediately lock the vault and zeroize all keys in RAM.
    Lock,
    /// Manage remote cloud storage accounts.
    Remote {
        /// Remote subcommand.
        #[command(subcommand)]
        action: RemoteCommands,
    },
    /// Mount the virtual drive at `<path>`.
    Mount {
        /// Target mount point directory / Windows sync root folder.
        path: String,
    },
    /// Unmount the active virtual drive.
    Unmount,
    /// Pin a virtual path offline and hydrate all 4 MiB chunks.
    Pin {
        /// Virtual path inside the vault (e.g. `/Docs/manual.pdf`).
        virtual_path: String,
    },
    /// Dehydrate a virtual path back to an online-only placeholder.
    Dehydrate {
        /// Virtual path inside the vault.
        virtual_path: String,
    },
    /// Trigger an immediate manifest & dirty-queue synchronization cycle.
    Sync,
    /// Query vault lock, mount, quota, and throughput status.
    Status {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Run a local hardware-accelerated AES-256-GCM 4 MiB chunk benchmark.
    BenchCrypto {
        /// Total MiB to encrypt and decrypt (rounded up to 4 MiB chunk multiples).
        #[arg(long, default_value_t = 64)]
        mib: usize,
    },
}

/// Remote management subcommands (`zv remote ...`).
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum RemoteCommands {
    /// Register a remote cloud storage backend.
    Add(RemoteAddArgs),
    /// List configured remote backends and quota telemetry.
    List,
}

/// Arguments for `zv remote add`.
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

/// Supported CLI `--kind` values for `zv remote add`.
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

/// Supported CLI `--policy` values for `zv remote add`.
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

/// Reads a single non-empty secret line into a [`Zeroizing<String>`].
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

/// Converts a parsed CLI [`Commands`] variant (other than `BenchCrypto`) into a [`DaemonRequest`].
pub fn build_daemon_request(
    cmd: &Commands,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> anyhow::Result<DaemonRequest> {
    match cmd {
        Commands::Init { passphrase_stdin } => {
            let prompt = if *passphrase_stdin {
                None
            } else {
                Some("Vault passphrase: ")
            };
            let pass = read_secret_line(stdin, prompt, stderr)?;
            Ok(DaemonRequest::InitVault {
                passphrase: pass.to_string(),
            })
        }
        Commands::Unlock { passphrase_stdin } => {
            let prompt = if *passphrase_stdin {
                None
            } else {
                Some("Vault passphrase: ")
            };
            let pass = read_secret_line(stdin, prompt, stderr)?;
            Ok(DaemonRequest::UnlockVault {
                passphrase: pass.to_string(),
            })
        }
        Commands::Lock => Ok(DaemonRequest::LockVault),
        Commands::Remote { action } => match action {
            RemoteCommands::Add(args) => {
                let secret = if args.secret_stdin {
                    Some(read_secret_line(stdin, None, stderr)?.to_string())
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
            RemoteCommands::List => Ok(DaemonRequest::ListRemotes),
        },
        Commands::Mount { path } => Ok(DaemonRequest::Mount {
            mount_point: path.clone(),
        }),
        Commands::Unmount => Ok(DaemonRequest::Unmount),
        Commands::Pin { virtual_path } => Ok(DaemonRequest::Pin {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Dehydrate { virtual_path } => Ok(DaemonRequest::Dehydrate {
            virtual_path: virtual_path.clone(),
        }),
        Commands::Sync => Ok(DaemonRequest::SyncNow),
        Commands::Status { .. } => Ok(DaemonRequest::Status),
        Commands::BenchCrypto { .. } => {
            bail!("bench-crypto runs locally and does not build a daemon IPC request")
        }
    }
}

/// Runs `AwsLcCryptoEngine::benchmark_aes256_gcm(mib)` locally and returns the report.
pub fn run_local_crypto_benchmark(mib: usize) -> anyhow::Result<CryptoBenchmarkReport> {
    let engine = AwsLcCryptoEngine::new()
        .context("failed initializing hardware-accelerated AES-256-GCM engine")?;
    engine
        .benchmark_aes256_gcm(mib)
        .context("AES-256-GCM benchmark failed")
}

/// Executes a parsed [`Cli`] command using injectable stdio streams for clean unit testing.
pub async fn run_cli_with_io(
    cli: Cli,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<()> {
    if let Commands::BenchCrypto { mib } = cli.command {
        let report = run_local_crypto_benchmark(mib)?;
        write_benchmark_report(stdout, &report)?;
        return Ok(());
    }

    let endpoint = match cli.endpoint.as_deref() {
        Some(raw) => IpcEndpoint::parse(raw).context("invalid --endpoint value")?,
        None => IpcEndpoint::from_env_or_default().context("failed resolving IPC endpoint")?,
    };
    let client = IpcClient::new(endpoint);

    let json_status = matches!(cli.command, Commands::Status { json: true });
    let request = build_daemon_request(&cli.command, stdin, stderr)?;
    let response = client
        .request(&request)
        .await
        .context("failed communicating with zerovaultd")?;

    render_daemon_response(response, json_status, stdout)
}

fn render_daemon_response(
    response: DaemonResponse,
    json_status: bool,
    stdout: &mut dyn Write,
) -> anyhow::Result<()> {
    match response {
        DaemonResponse::Ok { message } => {
            writeln!(stdout, "{message}").context("failed writing output")?;
            Ok(())
        }
        DaemonResponse::Remotes(remotes) => write_remotes_table(stdout, &remotes),
        DaemonResponse::Status(report) => {
            if json_status {
                serde_json::to_writer_pretty(&mut *stdout, &report)
                    .context("failed serializing JSON status")?;
                writeln!(stdout).context("failed writing newline")?;
                Ok(())
            } else {
                write_status_report(stdout, &report)
            }
        }
        DaemonResponse::Error { code, message } => {
            bail!("[{code}] {message}");
        }
    }
}

fn write_benchmark_report(
    stdout: &mut dyn Write,
    report: &CryptoBenchmarkReport,
) -> anyhow::Result<()> {
    writeln!(stdout, "Zerovault Hardware Crypto Benchmark")?;
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
        "Vault ID:   {}",
        report
            .vault_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "<uninitialized>".to_owned())
    )?;
    writeln!(stdout, "Unlocked:   {}", report.unlocked)?;
    writeln!(
        stdout,
        "Mounted:    {}{}",
        report.mounted,
        report
            .mount_point
            .as_deref()
            .map(|p| format!(" ({p})"))
            .unwrap_or_default()
    )?;
    writeln!(stdout, "Manifest:   rev {}", report.manifest_revision)?;
    writeln!(
        stdout,
        "Policy:     {}",
        format_routing_policy(report.routing_policy.as_ref())
    )?;
    writeln!(
        stdout,
        "Throughput: up={} B/s down={} B/s dirty_ops={}",
        report.throughput.upload_bytes_per_sec,
        report.throughput.download_bytes_per_sec,
        report.throughput.pending_dirty_ops
    )?;
    if let Some(ref quota) = report.pooled_quota {
        writeln!(
            stdout,
            "Pool Quota: used={}B / total={}B (avail={}B)",
            quota.used_bytes, quota.total_bytes, quota.available_bytes
        )?;
    }
    writeln!(stdout, "Conflicts:  {}", report.conflict_count)?;
    write_remotes_table(stdout, &report.remotes)
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tempfile::TempDir;
    use zerovault_daemon::{DaemonRuntime, DaemonStateConfig, IpcEndpoint, IpcServer};
    use zerovault_types::mocks::{InMemorySecretStore, MockCryptoEngine};

    use super::*;

    #[test]
    fn parses_all_cli_subcommands() {
        let init = parse_cli_from(["zv", "init", "--passphrase-stdin"]).expect("init");
        assert_eq!(
            init.command,
            Commands::Init {
                passphrase_stdin: true
            }
        );

        let unlock = parse_cli_from(["zv", "unlock", "--passphrase-stdin"]).expect("unlock");
        assert_eq!(
            unlock.command,
            Commands::Unlock {
                passphrase_stdin: true
            }
        );

        let lock = parse_cli_from(["zv", "lock"]).expect("lock");
        assert_eq!(lock.command, Commands::Lock);

        let remote_add = parse_cli_from([
            "zv",
            "remote",
            "add",
            "s3-main",
            "--kind",
            "s3",
            "--root",
            "vault",
            "--endpoint",
            "http://127.0.0.1:9000",
            "--bucket",
            "my-bkt",
            "--region",
            "us-east-1",
            "--quota-mib",
            "1024",
            "--policy",
            "pooled",
            "--prefix",
            "/Docs",
            "--username",
            "AKIA",
            "--secret-stdin",
        ])
        .expect("remote add");
        match remote_add.command {
            Commands::Remote {
                action: RemoteCommands::Add(args),
            } => {
                assert_eq!(args.id, "s3-main");
                assert_eq!(args.kind, RemoteKindArg::S3);
                assert_eq!(args.quota_mib, Some(1024));
                assert_eq!(args.policy, Some(RoutingPolicyArg::Pooled));
                assert!(args.secret_stdin);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let remote_list = parse_cli_from(["zv", "remote", "list"]).expect("remote list");
        assert_eq!(
            remote_list.command,
            Commands::Remote {
                action: RemoteCommands::List
            }
        );

        let mount = parse_cli_from(["zv", "mount", "/mnt/zv"]).expect("mount");
        assert_eq!(
            mount.command,
            Commands::Mount {
                path: "/mnt/zv".to_owned()
            }
        );

        let unmount = parse_cli_from(["zv", "unmount"]).expect("unmount");
        assert_eq!(unmount.command, Commands::Unmount);

        let pin = parse_cli_from(["zv", "pin", "/Docs/tax.pdf"]).expect("pin");
        assert_eq!(
            pin.command,
            Commands::Pin {
                virtual_path: "/Docs/tax.pdf".to_owned()
            }
        );

        let dehydrate = parse_cli_from(["zv", "dehydrate", "/Docs/tax.pdf"]).expect("dehydrate");
        assert_eq!(
            dehydrate.command,
            Commands::Dehydrate {
                virtual_path: "/Docs/tax.pdf".to_owned()
            }
        );

        let sync = parse_cli_from(["zv", "sync"]).expect("sync");
        assert_eq!(sync.command, Commands::Sync);

        let status = parse_cli_from(["zv", "status", "--json"]).expect("status");
        assert_eq!(status.command, Commands::Status { json: true });

        let bench = parse_cli_from(["zv", "bench-crypto", "--mib", "8"]).expect("bench");
        assert_eq!(bench.command, Commands::BenchCrypto { mib: 8 });
    }

    #[tokio::test]
    async fn executes_live_bench_crypto_8mib() {
        let cli = parse_cli_from(["zv", "bench-crypto", "--mib", "8"]).expect("parse");
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_cli_with_io(cli, &mut stdin, &mut stdout, &mut stderr)
            .await
            .expect("bench-crypto execution");

        let out_str = String::from_utf8(stdout).expect("utf8");
        assert!(out_str.contains("Zerovault Hardware Crypto Benchmark"));
        assert!(out_str.contains("AES HW:"));
        assert!(out_str.contains("MiB/s"));
        assert!(out_str.contains("8 MiB"));
    }

    #[tokio::test]
    async fn cli_drives_daemon_over_tcp_loopback() {
        let tmp = TempDir::new().expect("tempdir");
        let remote_root = tmp.path().join("remote");
        let mount_dir = tmp.path().join("mount");
        std::fs::create_dir_all(&mount_dir).expect("mkdir");

        let runtime = Arc::new(
            DaemonRuntime::builder(
                DaemonStateConfig::new(tmp.path().join("state")).with_mock_vfs(true),
            )
            .with_crypto(Arc::new(MockCryptoEngine::default()))
            .with_secret_store(Arc::new(InMemorySecretStore::default()))
            .build()
            .expect("runtime"),
        );

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server = IpcServer::bind(IpcEndpoint::TcpLoopback(addr))
            .await
            .expect("bind");
        let ep_str = server.endpoint().to_string();

        let rt_dispatch = Arc::clone(&runtime);
        let server_task = tokio::spawn(async move {
            server
                .serve_with_shutdown(
                    move |req| {
                        let rt = Arc::clone(&rt_dispatch);
                        async move { rt.handle_request(req).await }
                    },
                    std::future::pending::<()>(),
                )
                .await
                .expect("serve");
        });

        let mut stderr = Vec::new();

        // zv init --passphrase-stdin
        let mut out = Vec::new();
        let mut stdin = Cursor::new(b"cli-passphrase\n".to_vec());
        let cli = parse_cli_from(["zv", "--endpoint", &ep_str, "init", "--passphrase-stdin"])
            .expect("parse");
        run_cli_with_io(cli, &mut stdin, &mut out, &mut stderr)
            .await
            .expect("init");

        // zv remote add
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let cli = parse_cli_from([
            "zv",
            "--endpoint",
            &ep_str,
            "remote",
            "add",
            "local-fs",
            "--kind",
            "fs",
            "--root",
            remote_root.to_str().expect("utf8"),
            "--quota-mib",
            "256",
            "--policy",
            "pooled",
        ])
        .expect("parse");
        run_cli_with_io(cli, &mut stdin, &mut out, &mut stderr)
            .await
            .expect("remote add");

        // zv status --json
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let cli =
            parse_cli_from(["zv", "--endpoint", &ep_str, "status", "--json"]).expect("parse");
        run_cli_with_io(cli, &mut stdin, &mut out, &mut stderr)
            .await
            .expect("status");
        let status: VaultStatusReport = serde_json::from_slice(&out).expect("status json");
        assert!(status.unlocked);
        assert_eq!(status.remotes.len(), 1);
        assert_eq!(status.remotes[0].id, "local-fs");

        // zv lock
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let cli = parse_cli_from(["zv", "--endpoint", &ep_str, "lock"]).expect("parse");
        run_cli_with_io(cli, &mut stdin, &mut out, &mut stderr)
            .await
            .expect("lock");

        // Cleanup daemon via Shutdown
        let client = IpcClient::new(IpcEndpoint::parse(&ep_str).expect("ep"));
        let _ = client.request(&DaemonRequest::Shutdown).await;
        server_task.await.expect("join");
    }
}
