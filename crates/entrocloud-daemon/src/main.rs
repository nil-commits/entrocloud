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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use entrocloud_core::reclaim_process_memory;
use entrocloud_daemon::{DaemonRuntime, DaemonStateConfig, IpcEndpoint, IpcServer};

/// Dedicated 8 MiB thread stack size for host and Tokio worker threads (prevents 1 MiB PE stack overflow in `dev` builds).
const DAEMON_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

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

    let join_handle = std::thread::Builder::new()
        .name("entrocloudd-main".to_owned())
        .stack_size(DAEMON_THREAD_STACK_BYTES)
        .spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .thread_name("entrocloudd-worker")
                .thread_stack_size(DAEMON_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .context("failed building Tokio multi-thread runtime")?;
            rt.block_on(Box::pin(async_main(args)))
        })
        .context("failed spawning 8 MiB entrocloudd-main thread")?;

    match join_handle.join() {
        Ok(res) => res,
        Err(_) => Err(anyhow!("entrocloudd-main thread panicked unexpectedly")),
    }
}

async fn async_main(args: DaemonArgs) -> anyhow::Result<()> {
    let sync_interval = Duration::from_secs(args.sync_interval_secs);
    let config = match args.state_dir {
        Some(state_dir) => DaemonStateConfig::new(state_dir),
        None => DaemonStateConfig::default(),
    }
    .with_mock_vfs(args.mock_vfs)
    .with_sync_interval(sync_interval);

    let endpoint = match args.ipc {
        Some(raw) => IpcEndpoint::parse(&raw).context("invalid --ipc / --endpoint value")?,
        None => IpcEndpoint::from_env_or_default().context("failed resolving IPC endpoint")?,
    };

    let runtime = Arc::new(
        DaemonRuntime::new_default(config).context("failed initializing EntroCloud daemon runtime")?,
    );
    let server = IpcServer::bind(endpoint)
        .await
        .context("failed binding EntroCloud IPC server")?;

    let bg_sync = runtime.spawn_background_sync(sync_interval);
    reclaim_process_memory().await;

    tracing::info!(
        endpoint = %server.endpoint(),
        mock_vfs = args.mock_vfs,
        sync_interval_secs = args.sync_interval_secs,
        "entrocloudd listening"
    );

    let shutdown_runtime = Arc::clone(&runtime);
    let ctrl_c_shutdown = Box::pin(async move {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "failed awaiting ctrl-c signal");
            return;
        }
        tracing::info!("received Ctrl-C, locking vault and unmounting virtual drive");
        if let Err(err) = shutdown_runtime.graceful_shutdown().await {
            tracing::warn!(error = %err, "error during Ctrl-C graceful shutdown");
        }
    });

    let dispatch_runtime = Arc::clone(&runtime);
    let serve_res = server
        .serve_with_shutdown(
            move |req| {
                let rt = Arc::clone(&dispatch_runtime);
                Box::pin(async move { rt.handle_request(req).await })
            },
            ctrl_c_shutdown,
        )
        .await;

    if let Some(bg) = bg_sync {
        bg.stop().await;
    }
    let _ = runtime.graceful_shutdown().await;

    serve_res.context("IPC server exited with error")?;
    tracing::info!("entrocloudd exited cleanly");
    Ok(())
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
