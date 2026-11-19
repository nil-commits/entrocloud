//! `entrocloudd` background zero-knowledge synchronization, automatic backup, and virtual filesystem daemon binary.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "entrocloudd",
    version,
    about = "EntroCloud v1.0 zero-knowledge multi-cloud backup, sync, and virtual drive daemon"
)]
struct DaemonArgs {
    /// Local daemon state directory containing vault header, SQLite WAL, and backup schedule
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Override local IPC endpoint (Windows Named Pipe, Unix Domain Socket, or tcp://127.0.0.1:PORT)
    #[arg(long = "ipc", alias = "endpoint", env = "ENTROCLOUD_ENDPOINT")]
    ipc: Option<String>,

    /// Use in-memory MockDrive instead of native Windows CfApi / Linux FUSE3 virtual drive
    #[arg(long)]
    mock_vfs: bool,

    /// Periodic background sync and backup scheduler interval in seconds (`0` disables background loop)
    #[arg(long, default_value_t = 30)]
    sync_interval_secs: u64,
}

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let args = DaemonArgs::parse();
    entrocloud_daemon::run_daemon_blocking(
        args.state_dir,
        args.ipc,
        args.mock_vfs,
        args.sync_interval_secs,
    )
}

#[cfg(test)]
mod bin_tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn daemon_cli_args_validate_and_parse_sync_interval() -> anyhow::Result<()> {
        DaemonArgs::command().debug_assert();
        let parsed = DaemonArgs::try_parse_from([
            "entrocloudd",
            "--ipc",
            "tcp://127.0.0.1:0",
            "--sync-interval-secs",
            "15",
            "--mock-vfs",
        ])?;
        if parsed.sync_interval_secs != 15 || !parsed.mock_vfs {
            anyhow::bail!("unexpected parsed DaemonArgs");
        }
        Ok(())
    }
}
