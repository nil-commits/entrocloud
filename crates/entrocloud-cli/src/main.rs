//! `ec` command-line client for EntroCloud v1.0.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use entrocloud_cli::{Cli, run_cli_with_io};

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

#[cfg(test)]
mod bin_tests {
    use clap::CommandFactory;
    use entrocloud_cli::Cli;

    #[test]
    fn ec_binary_clap_schema_is_valid() {
        let cmd = Cli::command();
        assert_eq!(cmd.get_name(), "ec");
        cmd.debug_assert();
    }
}
