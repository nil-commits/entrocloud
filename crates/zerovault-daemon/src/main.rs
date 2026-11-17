//! `zerovaultd` background synchronization and virtual filesystem daemon binary.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use zerovault_daemon::{
    DaemonRuntime, DaemonStateConfig, IpcEndpoint, IpcServer,
};

#[derive(Debug, Parser)]
#[command(
    name = "zerovaultd",
    version,
    about = "Zerovault background zero-knowledge sync and virtual drive daemon"
)]
struct DaemonArgs {
    /// Local daemon state directory containing vault header and non-secret remote metadata
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Override local IPC endpoint (Windows Named Pipe, Unix Domain Socket, or tcp://127.0.0.1:PORT)
    #[arg(long, env = "ZEROVAULT_ENDPOINT")]
    endpoint: Option<String>,

    /// Use in-memory MockDrive instead of native Windows CfApi / Linux FUSE3 virtual drive
    #[arg(long)]
    mock_vfs: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let args = DaemonArgs::parse();
    let state_dir = args
        .state_dir
        .unwrap_or_else(DaemonStateConfig::default_state_dir);
    let config = DaemonStateConfig::new(state_dir).with_mock_vfs(args.mock_vfs);

    let endpoint = match args.endpoint {
        Some(raw) => IpcEndpoint::parse(&raw).context("invalid --endpoint value")?,
        None => IpcEndpoint::default(),
    };

    let runtime = Arc::new(
        DaemonRuntime::new_default(config).context("failed initializing Zerovault daemon runtime")?,
    );
    let server = IpcServer::bind(endpoint)
        .await
        .context("failed binding Zerovault IPC server")?;

    tracing::info!(
        endpoint = %server.endpoint(),
        mock_vfs = args.mock_vfs,
        "zerovaultd listening"
    );

    let shutdown_runtime = Arc::clone(&runtime);
    let ctrl_c_shutdown = async move {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "failed awaiting ctrl-c signal");
            return;
        }
        tracing::info!("received Ctrl-C, locking vault and unmounting virtual drive");
        if let Err(err) = shutdown_runtime.graceful_shutdown().await {
            tracing::warn!(error = %err, "error during Ctrl-C graceful shutdown");
        }
    };

    let dispatch_runtime = Arc::clone(&runtime);
    server
        .serve_with_shutdown(
            move |req| {
                let rt = Arc::clone(&dispatch_runtime);
                async move { rt.handle_request(req).await }
            },
            ctrl_c_shutdown,
        )
        .await
        .context("IPC server exited with error")?;

    tracing::info!("zerovaultd exited cleanly");
    Ok(())
}
