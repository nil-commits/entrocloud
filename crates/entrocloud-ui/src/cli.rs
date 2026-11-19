//! Deterministic CLI flag parsing for `entrocloud`.

use std::path::PathBuf;

use clap::Parser;
use entrocloud_types::{CapabilityUri, ZeroVaultError, ZeroVaultResult};

/// Command-line flags for the native `eframe`/`glow` EntroCloud desktop application (`entrocloud`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Parser)]
#[command(
    name = "entrocloud",
    version,
    about = "EntroCloud — Private Multi-Cloud Backup & Encrypted Drive"
)]
pub struct UiCliArgs {
    /// Custom Named Pipe (`\\.\pipe\...`), Unix Domain Socket, or loopback TCP (`tcp://127.0.0.1:PORT`) IPC endpoint.
    #[arg(long = "ipc")]
    pub ipc: Option<String>,

    /// Pre-populate and immediately open the private share import dialog for an `ec://` or `zv://` link.
    #[arg(long = "open-uri")]
    pub open_uri: Option<String>,

    /// Cold-start benchmark mode: opens real `eframe` `glow` window, renders Frame #1 + swap,
    /// samples `WorkingSet64` + verifies `0` browser runtime modules, prints JSON to stdout, and exits `0`.
    #[arg(long = "bench-cold")]
    pub bench_cold: bool,

    /// Optional parent QPC tick timestamp passed by external benchmark harnesses for spawn-to-Frame-#1 latency.
    #[arg(long = "spawn-qpc")]
    pub spawn_qpc: Option<i64>,

    /// Disable automatic background spawning of sibling `entrocloudd` when the default IPC endpoint is offline.
    #[arg(long = "no-autostart")]
    pub no_autostart: bool,

    /// Launch a 1280x820 automated visual tour with realistic demo state, capture all 8 Light & Dark
    /// PNG screenshots into `<OUTPUT_DIR>`, and exit `0`.
    #[arg(long = "screenshot-tour", value_name = "OUTPUT_DIR")]
    pub screenshot_tour: Option<PathBuf>,

    /// Capture GPU-rendered modal verification screenshots (`Add Backup Folder` Light & Dark,
    /// `Private Encrypted Note`, and `Restore Backup`) into `<OUTPUT_DIR>` and exit `0`.
    #[arg(long = "screenshot-modals", value_name = "OUTPUT_DIR")]
    pub screenshot_modals: Option<PathBuf>,

    /// Internal single-executable background daemon mode (spawned automatically by `EntroCloud.exe`
    /// when no separate sibling `entrocloudd` binary is present).
    #[arg(long = "daemon", hide = true)]
    pub daemon: bool,

    /// Optional positional `ec://...` or `zv://...` URI passed directly by OS protocol handlers.
    #[arg(value_name = "URI")]
    pub positional_uri: Option<String>,
}

impl UiCliArgs {
    /// Parses CLI arguments from an arbitrary iterator of strings.
    pub fn parse_from_iter<I, T>(iter: I) -> ZeroVaultResult<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(iter).map_err(|err| ZeroVaultError::ConfigError(err.to_string()))
    }

    /// Resolves the active `ec://` or `zv://` URI from `--open-uri` or positional protocol argument, if any,
    /// trimming surrounding quotes added by Windows shell handlers.
    #[must_use]
    pub fn resolved_open_uri(&self) -> Option<String> {
        let candidate = self
            .open_uri
            .as_deref()
            .or(self.positional_uri.as_deref())?;
        let cleaned = candidate.trim().trim_matches('"').trim();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.to_owned())
        }
    }

    /// Validates `--open-uri` (`ec://` or legacy `zv://`) if present, returning a suggested destination
    /// virtual path inside `/Shared/`.
    pub fn validate_open_uri(&self) -> ZeroVaultResult<Option<(String, String)>> {
        let Some(raw_uri) = self.resolved_open_uri() else {
            return Ok(None);
        };
        let parsed = CapabilityUri::parse(&raw_uri)?;
        let short_id = parsed.share_id.simple().to_string();
        let prefix = short_id.get(..8).unwrap_or("file");
        let suggested_dest = format!("/Shared/share_{prefix}");
        Ok(Some((raw_uri, suggested_dest)))
    }
}
