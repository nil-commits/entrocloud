//! `zv` command-line client for Zerovault.

use std::io;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use zerovault_cli::{Cli, run_cli_with_io};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();

    let mut stdin_lock = stdin.lock();
    let mut stdout_lock = stdout.lock();
    let mut stderr_lock = stderr.lock();

    run_cli_with_io(cli, &mut stdin_lock, &mut stdout_lock, &mut stderr_lock).await
}
