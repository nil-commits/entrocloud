//! Owner-only local IPC framing and transport for `entrocloudd`, `ec`, and `entrocloud-ui`.
//!
//! Enforces:
//! - 4-byte big-endian `u32` length prefix (`1..=MAX_IPC_FRAME_BYTES = 1 MiB` pre-allocation check)
//!   with UTF-8 `serde_json` payloads wrapped in [`Zeroizing`].
//! - [`MAX_CONCURRENT_IPC_CONNECTIONS`] (`64`) semaphore backpressure.
//! - [`IPC_FRAME_IO_TIMEOUT`] (`30s`) frame read/write deadlines.
//! - Windows Named Pipe (`\\.\pipe\entrocloudd`) `PROTECTED_DACL` SDDL `D:P(A;;GA;;;SY)(A;;GA;;;OW)`
//!   with `first_pipe_instance(true)` and `reject_remote_clients(true)`.
//! - Safe Unix Domain Socket bind (`NEW-L02` remediation): `0700` parent directory created *before*
//!   `bind`, `symlink_metadata()?.file_type().is_socket()` check, `500ms` `Ping` liveness probe,
//!   and `0600` socket permissions.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use zeroize::Zeroizing;
use entrocloud_types::{
    DaemonRequest, DaemonResponse, MAX_IPC_FRAME_BYTES, ZeroVaultError, ZeroVaultResult,
};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer};

#[cfg(target_os = "windows")]
use crate::dacl::win_acl::create_owner_only_named_pipe;

/// Default Windows Named Pipe path for `entrocloudd`.
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\entrocloudd";

/// Maximum concurrent client connections served simultaneously by [`IpcServer`].
pub const MAX_CONCURRENT_IPC_CONNECTIONS: usize = 64;

/// Per-frame read/write I/O timeout enforced by [`IpcServer`] and [`IpcClient`].
pub const IPC_FRAME_IO_TIMEOUT: Duration = Duration::from_secs(30);

const FRAME_HEADER_LEN: usize = 4;
const IPC_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const UNIX_STALE_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Local IPC endpoint address for `zerovaultd` clients and server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Windows Named Pipe (`\\.\pipe\<name>`).
    #[cfg(target_os = "windows")]
    NamedPipe(String),
    /// Unix Domain Socket path (`0700` parent directory, `0600` socket file).
    #[cfg(unix)]
    UnixSocket(PathBuf),
    /// Loopback TCP address (`127.0.0.1` / `::1`) used for cross-platform tests.
    TcpLoopback(SocketAddr),
}

impl Default for IpcEndpoint {
    fn default() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::NamedPipe(DEFAULT_WINDOWS_PIPE_NAME.to_owned())
        }
        #[cfg(unix)]
        {
            Self::UnixSocket(default_unix_socket_path())
        }
        #[cfg(not(any(target_os = "windows", unix)))]
        {
            Self::TcpLoopback(SocketAddr::from(([127, 0, 0, 1], 49152)))
        }
    }
}

impl fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "windows")]
            Self::NamedPipe(name) => f.write_str(name),
            #[cfg(unix)]
            Self::UnixSocket(path) => write!(f, "{}", path.display()),
            Self::TcpLoopback(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

impl FromStr for IpcEndpoint {
    type Err = ZeroVaultError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl IpcEndpoint {
    /// Parses a CLI/config IPC endpoint string into a validated [`IpcEndpoint`].
    ///
    /// Rejects non-loopback TCP addresses and malformed pipe/socket paths.
    pub fn parse(raw: &str) -> ZeroVaultResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "IPC endpoint string must not be empty".into(),
            ));
        }

        if let Some(addr_str) = trimmed.strip_prefix("tcp://") {
            let addr: SocketAddr = addr_str.parse().map_err(|e| {
                ZeroVaultError::ConfigError(format!("invalid TCP IPC endpoint '{trimmed}': {e}"))
            })?;
            return Self::validated_tcp(addr);
        }

        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            return Self::validated_tcp(addr);
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(pipe_tail) = trimmed.strip_prefix("pipe://") {
                let clean = pipe_tail.trim_start_matches('/');
                if clean.is_empty() {
                    return Err(ZeroVaultError::ConfigError(
                        "named pipe endpoint must specify a pipe name".into(),
                    ));
                }
                let full = if clean.starts_with(r"\\.\pipe\") {
                    clean.to_owned()
                } else {
                    format!(r"\\.\pipe\{clean}")
                };
                return Ok(Self::NamedPipe(full));
            }
            if trimmed.starts_with(r"\\.\pipe\") && trimmed.len() > r"\\.\pipe\".len() {
                return Ok(Self::NamedPipe(trimmed.to_owned()));
            }
        }

        #[cfg(unix)]
        {
            if let Some(sock_path) = trimmed.strip_prefix("unix://") {
                if sock_path.trim().is_empty() {
                    return Err(ZeroVaultError::ConfigError(
                        "unix IPC endpoint must specify a socket path".into(),
                    ));
                }
                return Ok(Self::UnixSocket(PathBuf::from(sock_path)));
            }
            if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
                return Ok(Self::UnixSocket(PathBuf::from(trimmed)));
            }
        }

        Err(ZeroVaultError::ConfigError(format!(
            "unsupported IPC endpoint '{trimmed}'"
        )))
    }

    fn validated_tcp(addr: SocketAddr) -> ZeroVaultResult<Self> {
        if !is_loopback_ip(addr.ip()) {
            return Err(ZeroVaultError::ConfigError(format!(
                "TCP IPC endpoint must bind/connect strictly to loopback, got {}",
                addr.ip()
            )));
        }
        Ok(Self::TcpLoopback(addr))
    }

    /// Resolves the IPC endpoint from `ENTROCLOUD_IPC` / `ENTROCLOUD_ENDPOINT`
    /// (or legacy `ZEROVAULT_IPC` / `ZEROVAULT_ENDPOINT`) if present, otherwise default.
    pub fn from_env_or_default() -> ZeroVaultResult<Self> {
        for key in [
            "ENTROCLOUD_IPC",
            "ENTROCLOUD_ENDPOINT",
            "ZEROVAULT_IPC",
            "ZEROVAULT_ENDPOINT",
        ] {
            if let Ok(val) = std::env::var(key) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return Self::parse(trimmed);
                }
            }
        }
        Ok(Self::default())
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Resolves the canonical Unix Domain Socket path for `entrocloudd`:
/// `$XDG_RUNTIME_DIR/entrocloud/entrocloudd.sock`, falling back to
/// `/run/user/<uid>/entrocloud/entrocloudd.sock`.
#[must_use]
pub fn default_unix_socket_path_for_uid(xdg_runtime_dir: Option<&Path>, uid: u32) -> PathBuf {
    if let Some(runtime_dir) = xdg_runtime_dir
        && !runtime_dir.as_os_str().is_empty()
    {
        return runtime_dir.join("entrocloud").join("entrocloudd.sock");
    }
    PathBuf::from(format!("/run/user/{uid}"))
        .join("entrocloud")
        .join("entrocloudd.sock")
}

#[cfg(unix)]
fn current_uid_raw() -> u32 {
    #[cfg(target_os = "linux")]
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        use std::os::unix::fs::MetadataExt;
        return meta.uid();
    }
    if let Some(home) = dirs::home_dir()
        && let Ok(meta) = std::fs::metadata(home)
    {
        use std::os::unix::fs::MetadataExt;
        return meta.uid();
    }
    std::env::var("UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

#[cfg(unix)]
fn default_unix_socket_path() -> PathBuf {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    default_unix_socket_path_for_uid(xdg.as_deref(), current_uid_raw())
}

/// Validates that an IPC frame length lies within `1..=MAX_IPC_FRAME_BYTES`.
pub fn validate_frame_len(len: usize) -> ZeroVaultResult<()> {
    if len == 0 {
        return Err(ZeroVaultError::IpcError(
            "IPC frame length must be non-zero".into(),
        ));
    }
    if len > MAX_IPC_FRAME_BYTES {
        return Err(ZeroVaultError::IpcError(format!(
            "IPC frame length {len} exceeds MAX_IPC_FRAME_BYTES ({MAX_IPC_FRAME_BYTES})"
        )));
    }
    Ok(())
}

/// Reads a single length-prefixed (`u32 BE`) frame from `reader`, failing closed before
/// allocation if the declared length is `0` or exceeds [`MAX_IPC_FRAME_BYTES`].
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> ZeroVaultResult<Vec<u8>> {
    let mut len_buf = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        ZeroVaultError::IpcError(format!("failed reading IPC frame length header: {e}"))
    })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    validate_frame_len(len)?;

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| ZeroVaultError::IpcError(format!("failed reading IPC frame payload: {e}")))?;
    Ok(payload)
}

async fn read_frame_or_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> ZeroVaultResult<Option<Zeroizing<Vec<u8>>>> {
    let mut len_buf = [0u8; FRAME_HEADER_LEN];
    let first = reader.read(&mut len_buf[..1]).await.map_err(|e| {
        ZeroVaultError::IpcError(format!("failed reading IPC frame header byte: {e}"))
    })?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut len_buf[1..]).await.map_err(|e| {
        ZeroVaultError::IpcError(format!("truncated IPC frame length header: {e}"))
    })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    validate_frame_len(len)?;

    let mut payload = Zeroizing::new(vec![0u8; len]);
    reader
        .read_exact(payload.as_mut_slice())
        .await
        .map_err(|e| ZeroVaultError::IpcError(format!("failed reading IPC frame payload: {e}")))?;
    Ok(Some(payload))
}

/// Writes a single length-prefixed (`u32 BE`) frame to `writer`, validating bounds up front.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> ZeroVaultResult<()> {
    validate_frame_len(payload.len())?;
    let len_u32 = u32::try_from(payload.len())
        .map_err(|_| ZeroVaultError::IpcError("IPC frame length exceeds u32::MAX".into()))?;
    writer
        .write_all(&len_u32.to_be_bytes())
        .await
        .map_err(|e| ZeroVaultError::IpcError(format!("failed writing IPC frame header: {e}")))?;
    writer
        .write_all(payload)
        .await
        .map_err(|e| ZeroVaultError::IpcError(format!("failed writing IPC frame payload: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| ZeroVaultError::IpcError(format!("failed flushing IPC frame: {e}")))?;
    Ok(())
}

/// Serializes `value` as JSON and writes it as a length-prefixed IPC frame.
pub async fn write_json_frame<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
) -> ZeroVaultResult<()> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|e| ZeroVaultError::IpcError(format!("failed to serialize IPC frame: {e}")))?,
    );
    write_frame(writer, encoded.as_slice()).await
}

/// Reads a length-prefixed JSON IPC frame and deserializes it into `T`.
pub async fn read_json_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> ZeroVaultResult<T> {
    let raw = Zeroizing::new(read_frame(reader).await?);
    serde_json::from_slice(raw.as_slice())
        .map_err(|e| ZeroVaultError::IpcError(format!("failed to decode IPC JSON frame: {e}")))
}

#[cfg(unix)]
fn ensure_unix_socket_parent_dir(path: &Path) -> ZeroVaultResult<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    let is_system_tmp =
        parent == Path::new("/") || parent == Path::new("/tmp") || parent == Path::new("/var/tmp");
    if is_system_tmp {
        return Ok(());
    }

    match std::fs::symlink_metadata(parent) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(ZeroVaultError::IpcError(format!(
                    "IPC socket directory {} must be a real directory, not a symlink",
                    parent.display()
                )));
            }
            let expected_uid = current_uid_raw();
            if meta.uid() != expected_uid {
                return Err(ZeroVaultError::IpcError(format!(
                    "IPC socket directory {} owned by uid {}, expected {expected_uid}",
                    parent.display(),
                    meta.uid()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent)?;
        }
        Err(err) => return Err(err.into()),
    }

    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
async fn probe_unix_socket_live(path: &Path) -> bool {
    let probe = async {
        let mut stream = UnixStream::connect(path).await.ok()?;
        write_json_frame(&mut stream, &DaemonRequest::Ping)
            .await
            .ok()?;
        let resp = read_json_frame::<_, DaemonResponse>(&mut stream)
            .await
            .ok()?;
        Some(matches!(
            resp,
            DaemonResponse::Ok { .. } | DaemonResponse::Error { .. }
        ))
    };

    matches!(
        tokio::time::timeout(UNIX_STALE_PROBE_TIMEOUT, probe).await,
        Ok(Some(true))
    )
}

#[cfg(unix)]
async fn prepare_unix_socket_bind(path: &Path) -> ZeroVaultResult<()> {
    use std::os::unix::fs::FileTypeExt;

    // Step 1 (`NEW-L02`): Create / harden parent directory `0o700` *before* `bind`.
    ensure_unix_socket_parent_dir(path)?;

    // Step 2 (`NEW-L02`): If path exists, verify `is_socket()` and run 500ms `Ping` check.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(ZeroVaultError::IpcError(format!(
                    "refusing to overwrite existing non-socket path {}",
                    path.display()
                )));
            }
            if probe_unix_socket_live(path).await {
                return Err(ZeroVaultError::IpcError(format!(
                    "live entrocloudd already listening on IPC socket {}",
                    path.display()
                )));
            }
            std::fs::remove_file(path)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    Ok(())
}

#[cfg(unix)]
fn set_unix_socket_permissions(path: &Path) -> ZeroVaultResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

enum BoundListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        path: PathBuf,
    },
    #[cfg(target_os = "windows")]
    NamedPipe {
        pipe_name: String,
        current: Option<NamedPipeServer>,
    },
}

/// Multi-transport local IPC server for `zerovaultd`.
pub struct IpcServer {
    endpoint: IpcEndpoint,
    listener: BoundListener,
    conn_semaphore: Arc<Semaphore>,
}

impl fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcServer")
            .field("endpoint", &self.endpoint)
            .field(
                "available_connection_slots",
                &self.conn_semaphore.available_permits(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        if let BoundListener::Unix { path, .. } = &self.listener {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl IpcServer {
    /// Binds an IPC server on `endpoint`, enforcing loopback-only TCP, safe `0700`/`0600` Unix
    /// socket bind (`NEW-L02`), or `D:P(A;;GA;;;SY)(A;;GA;;;OW)` `PROTECTED_DACL` Windows Named Pipes.
    pub async fn bind(endpoint: IpcEndpoint) -> ZeroVaultResult<Self> {
        let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CONNECTIONS));

        match endpoint {
            IpcEndpoint::TcpLoopback(addr) => {
                if !is_loopback_ip(addr.ip()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "refusing to bind TCP IPC server on non-loopback IP {}",
                        addr.ip()
                    )));
                }
                let listener = TcpListener::bind(addr).await.map_err(|e| {
                    ZeroVaultError::IpcError(format!("failed to bind TCP IPC on {addr}: {e}"))
                })?;
                let local_addr = listener.local_addr().map_err(|e| {
                    ZeroVaultError::IpcError(format!("failed to read local TCP addr: {e}"))
                })?;
                Ok(Self {
                    endpoint: IpcEndpoint::TcpLoopback(local_addr),
                    listener: BoundListener::Tcp(listener),
                    conn_semaphore,
                })
            }
            #[cfg(unix)]
            IpcEndpoint::UnixSocket(path) => {
                prepare_unix_socket_bind(&path).await?;
                let listener = UnixListener::bind(&path).map_err(|e| {
                    ZeroVaultError::IpcError(format!(
                        "failed to bind Unix IPC socket {}: {e}",
                        path.display()
                    ))
                })?;
                set_unix_socket_permissions(&path)?;
                Ok(Self {
                    endpoint: IpcEndpoint::UnixSocket(path.clone()),
                    listener: BoundListener::Unix { listener, path },
                    conn_semaphore,
                })
            }
            #[cfg(target_os = "windows")]
            IpcEndpoint::NamedPipe(pipe_name) => {
                if !pipe_name.starts_with(r"\\.\pipe\") || pipe_name.len() <= r"\\.\pipe\".len() {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "invalid Windows named pipe path '{pipe_name}'"
                    )));
                }
                let first = create_owner_only_named_pipe(&pipe_name, true)?;
                Ok(Self {
                    endpoint: IpcEndpoint::NamedPipe(pipe_name.clone()),
                    listener: BoundListener::NamedPipe {
                        pipe_name,
                        current: Some(first),
                    },
                    conn_semaphore,
                })
            }
        }
    }

    /// Returns the actual bound endpoint (e.g., resolved ephemeral port for `127.0.0.1:0`).
    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Serves incoming IPC connections (bounded to [`MAX_CONCURRENT_IPC_CONNECTIONS`] = 64)
    /// until `external_shutdown` resolves OR a client sends [`DaemonRequest::Shutdown`].
    pub async fn serve_with_shutdown<F, Fut, S>(
        mut self,
        handler: F,
        external_shutdown: S,
    ) -> ZeroVaultResult<()>
    where
        F: Fn(DaemonRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = DaemonResponse> + Send,
        S: Future<Output = ()> + Send,
    {
        let handler = Arc::new(handler);
        let (internal_tx, mut internal_rx) = watch::channel(false);
        let mut tasks = JoinSet::new();
        tokio::pin!(external_shutdown);

        loop {
            while let Some(res) = tasks.try_join_next() {
                if let Err(err) = res {
                    tracing::warn!(error = %err, "IPC connection task failed");
                }
            }

            if *internal_rx.borrow() {
                break;
            }

            // Acquire one of the 64 connection permits before accepting the next stream.
            let permit = tokio::select! {
                _ = &mut external_shutdown => {
                    break;
                }
                _ = internal_rx.changed() => {
                    if *internal_rx.borrow() {
                        break;
                    }
                    continue;
                }
                acquired = Arc::clone(&self.conn_semaphore).acquire_owned() => {
                    match acquired {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                }
            };

            match &mut self.listener {
                BoundListener::Tcp(listener) => {
                    tokio::select! {
                        _ = &mut external_shutdown => {
                            drop(permit);
                            break;
                        }
                        _ = internal_rx.changed() => {
                            drop(permit);
                            if *internal_rx.borrow() {
                                break;
                            }
                        }
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((stream, _peer)) => {
                                    let h = Arc::clone(&handler);
                                    let tx = internal_tx.clone();
                                    tasks.spawn(async move {
                                        handle_stream(stream, h, tx, permit).await;
                                    });
                                }
                                Err(err) => {
                                    drop(permit);
                                    tracing::warn!(error = %err, "TCP IPC accept error");
                                }
                            }
                        }
                    }
                }
                #[cfg(unix)]
                BoundListener::Unix { listener, .. } => {
                    tokio::select! {
                        _ = &mut external_shutdown => {
                            drop(permit);
                            break;
                        }
                        _ = internal_rx.changed() => {
                            drop(permit);
                            if *internal_rx.borrow() {
                                break;
                            }
                        }
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((stream, _addr)) => {
                                    let h = Arc::clone(&handler);
                                    let tx = internal_tx.clone();
                                    tasks.spawn(async move {
                                        handle_stream(stream, h, tx, permit).await;
                                    });
                                }
                                Err(err) => {
                                    drop(permit);
                                    tracing::warn!(error = %err, "Unix IPC accept error");
                                }
                            }
                        }
                    }
                }
                #[cfg(target_os = "windows")]
                BoundListener::NamedPipe { pipe_name, current } => {
                    let Some(server) = current.take() else {
                        drop(permit);
                        return Err(ZeroVaultError::IpcError(
                            "Windows named pipe server state missing".into(),
                        ));
                    };
                    tokio::select! {
                        _ = &mut external_shutdown => {
                            drop(permit);
                            drop(server);
                            break;
                        }
                        _ = internal_rx.changed() => {
                            drop(permit);
                            drop(server);
                            if *internal_rx.borrow() {
                                break;
                            }
                        }
                        res = server.connect() => {
                            match res {
                                Ok(()) => {
                                    match create_owner_only_named_pipe(pipe_name.as_str(), false) {
                                        Ok(next) => {
                                            *current = Some(next);
                                        }
                                        Err(err) => {
                                            tracing::error!(error = %err, "failed creating next owner-only named pipe instance");
                                            let h = Arc::clone(&handler);
                                            let tx = internal_tx.clone();
                                            tasks.spawn(async move {
                                                handle_stream(server, h, tx, permit).await;
                                            });
                                            break;
                                        }
                                    }
                                    let h = Arc::clone(&handler);
                                    let tx = internal_tx.clone();
                                    tasks.spawn(async move {
                                        handle_stream(server, h, tx, permit).await;
                                    });
                                }
                                Err(err) => {
                                    drop(permit);
                                    tracing::warn!(error = %err, "Windows named pipe connect error");
                                    *current = Some(create_owner_only_named_pipe(pipe_name.as_str(), false)?);
                                }
                            }
                        }
                    }
                }
            }
        }

        let _ = tokio::time::timeout(IPC_DRAIN_TIMEOUT, async {
            while let Some(res) = tasks.join_next().await {
                if let Err(err) = res {
                    tracing::warn!(error = %err, "IPC connection task failed during drain");
                }
            }
        })
        .await;

        Ok(())
    }
}

async fn handle_stream<S, F, Fut>(
    mut stream: S,
    handler: Arc<F>,
    shutdown_tx: watch::Sender<bool>,
    _permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(DaemonRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = DaemonResponse> + Send,
{
    loop {
        let raw = match tokio::time::timeout(IPC_FRAME_IO_TIMEOUT, read_frame_or_eof(&mut stream))
            .await
        {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "rejected invalid IPC frame");
                break;
            }
            Err(_) => {
                tracing::debug!("closing idle or stalled IPC stream after 30s frame I/O timeout");
                break;
            }
        };

        let request: DaemonRequest = match serde_json::from_slice(raw.as_slice()) {
            Ok(req) => req,
            Err(err) => {
                let err_resp = DaemonResponse::Error {
                    code: "invalid_request".to_owned(),
                    message: format!("malformed IPC request JSON: {err}"),
                };
                let _ =
                    tokio::time::timeout(IPC_FRAME_IO_TIMEOUT, write_json_frame(&mut stream, &err_resp))
                        .await;
                break;
            }
        };
        drop(raw);

        let is_shutdown = matches!(request, DaemonRequest::Shutdown);
        let response = handler(request).await;

        match tokio::time::timeout(
            IPC_FRAME_IO_TIMEOUT,
            write_json_frame(&mut stream, &response),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "failed writing IPC response frame");
                break;
            }
            Err(_) => {
                tracing::warn!("timed out writing IPC response frame after 30s");
                break;
            }
        }

        if is_shutdown {
            let _ = shutdown_tx.send(true);
            break;
        }
    }
}

/// Local IPC client used by `zv` CLI, `zerovault-tray`, and `entrocloud-ui`.
#[derive(Debug, Clone)]
pub struct IpcClient {
    endpoint: IpcEndpoint,
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new(IpcEndpoint::from_env_or_default().unwrap_or_default())
    }
}

impl IpcClient {
    /// Creates a new [`IpcClient`] targeting `endpoint`.
    #[must_use]
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self { endpoint }
    }

    /// Returns the configured target [`IpcEndpoint`].
    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Sends one [`DaemonRequest`] over local IPC and awaits the [`DaemonResponse`].
    pub async fn request(&self, req: &DaemonRequest) -> ZeroVaultResult<DaemonResponse> {
        let payload = Zeroizing::new(serde_json::to_vec(req).map_err(|e| {
            ZeroVaultError::IpcError(format!("failed serializing DaemonRequest: {e}"))
        })?);
        validate_frame_len(payload.len())?;

        let read_timeout = response_wait_timeout(req);

        match &self.endpoint {
            IpcEndpoint::TcpLoopback(addr) => {
                if !is_loopback_ip(addr.ip()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "refusing TCP IPC connection to non-loopback address {}",
                        addr.ip()
                    )));
                }
                let mut stream = tokio::time::timeout(IPC_FRAME_IO_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .map_err(|_| {
                        ZeroVaultError::IpcError(format!(
                            "timed out connecting to TCP IPC {addr}"
                        ))
                    })?
                    .map_err(|e| {
                        ZeroVaultError::IpcError(format!(
                            "failed connecting to TCP IPC {addr}: {e}"
                        ))
                    })?;
                exchange_frames(&mut stream, payload.as_slice(), read_timeout).await
            }
            #[cfg(unix)]
            IpcEndpoint::UnixSocket(path) => {
                let mut stream =
                    tokio::time::timeout(IPC_FRAME_IO_TIMEOUT, UnixStream::connect(path))
                        .await
                        .map_err(|_| {
                            ZeroVaultError::IpcError(format!(
                                "timed out connecting to Unix IPC {}",
                                path.display()
                            ))
                        })?
                        .map_err(|e| {
                            ZeroVaultError::IpcError(format!(
                                "failed connecting to Unix IPC {}: {e}",
                                path.display()
                            ))
                        })?;
                exchange_frames(&mut stream, payload.as_slice(), read_timeout).await
            }
            #[cfg(target_os = "windows")]
            IpcEndpoint::NamedPipe(pipe_name) => {
                let mut stream = connect_named_pipe_with_retry(pipe_name).await?;
                exchange_frames(&mut stream, payload.as_slice(), read_timeout).await
            }
        }
    }

    /// Convenience liveness check sending [`DaemonRequest::Ping`].
    pub async fn ping(&self) -> ZeroVaultResult<()> {
        match self.request(&DaemonRequest::Ping).await? {
            DaemonResponse::Ok { .. } => Ok(()),
            DaemonResponse::Error { code, message } => {
                Err(ZeroVaultError::IpcError(format!("[{code}] {message}")))
            }
            other => Err(ZeroVaultError::IpcError(format!(
                "unexpected Ping response: {other:?}"
            ))),
        }
    }
}

fn response_wait_timeout(req: &DaemonRequest) -> Duration {
    match req {
        DaemonRequest::OAuthLogin(params) => {
            let secs = params.timeout_secs.unwrap_or(180).clamp(5, 600);
            Duration::from_secs(secs.saturating_add(30))
        }
        DaemonRequest::ImportLocalFile { .. }
        | DaemonRequest::ExportVaultFile { .. }
        | DaemonRequest::ImportCapabilityShare { .. }
        | DaemonRequest::RunBackupJob { .. }
        | DaemonRequest::RunAllBackups { .. }
        | DaemonRequest::RestoreBackupJob { .. }
        | DaemonRequest::TestRemote { .. }
        | DaemonRequest::SyncNow
        | DaemonRequest::Pin { .. } => Duration::from_secs(300),
        _ => IPC_FRAME_IO_TIMEOUT,
    }
}

async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    read_timeout: Duration,
) -> ZeroVaultResult<DaemonResponse> {
    tokio::time::timeout(IPC_FRAME_IO_TIMEOUT, write_frame(stream, payload))
        .await
        .map_err(|_| ZeroVaultError::IpcError("IPC request frame write timed out (30s)".into()))??;

    tokio::time::timeout(read_timeout, read_json_frame::<_, DaemonResponse>(stream))
        .await
        .map_err(|_| {
            ZeroVaultError::IpcError(format!(
                "IPC response frame read timed out ({}s)",
                read_timeout.as_secs()
            ))
        })?
}

#[cfg(target_os = "windows")]
async fn connect_named_pipe_with_retry(
    pipe_name: &str,
) -> ZeroVaultResult<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: usize = 100;

    for attempt in 0..MAX_ATTEMPTS {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt + 1 < MAX_ATTEMPTS =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => {
                return Err(ZeroVaultError::IpcError(format!(
                    "failed connecting to Windows named pipe '{pipe_name}': {err}"
                )));
            }
        }
    }

    Err(ZeroVaultError::IpcError(format!(
        "Windows named pipe '{pipe_name}' remained busy after {MAX_ATTEMPTS} retries"
    )))
}
