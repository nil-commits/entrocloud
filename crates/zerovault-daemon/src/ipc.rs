//! Local IPC framing and transport for `zerovaultd`, `zv`, and `zerovault-ui`.
//!
//! Supports Windows Named Pipes (`\\.\pipe\zerovaultd`), Unix Domain Sockets (`0700` directory,
//! `0600` socket), and loopback TCP (`127.0.0.1` / `::1`) for cross-platform automated tests.
//! Every message uses a `u32` big-endian length-prefixed JSON frame capped at
//! [`MAX_IPC_FRAME_BYTES`] (16 MiB).

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;
use zerovault_types::{
    DaemonRequest, DaemonResponse, MAX_IPC_FRAME_BYTES, ZeroVaultError, ZeroVaultResult,
};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

/// Default Windows Named Pipe path for `zerovaultd`.
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\zerovaultd";

const FRAME_HEADER_LEN: usize = 4;
const IPC_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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

    /// Resolves the IPC endpoint from `ZEROVAULT_ENDPOINT` env var if present, otherwise default.
    pub fn from_env_or_default() -> ZeroVaultResult<Self> {
        match std::env::var("ZEROVAULT_ENDPOINT") {
            Ok(val) if !val.trim().is_empty() => Self::parse(&val),
            _ => Ok(Self::default()),
        }
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
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
fn current_uid_string() -> String {
    current_uid_raw().to_string()
}

#[cfg(unix)]
fn default_unix_socket_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR")
        && !runtime_dir.is_empty()
    {
        return PathBuf::from(runtime_dir)
            .join("zerovault")
            .join("zerovaultd.sock");
    }
    PathBuf::from(format!("/tmp/zerovault-{}", current_uid_string())).join("zerovaultd.sock")
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
fn prepare_unix_socket_dir_and_path(path: &Path) -> ZeroVaultResult<()> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let is_system_tmp =
            parent == Path::new("/") || parent == Path::new("/tmp") || parent == Path::new("/var/tmp");
        if !is_system_tmp {
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
        }
    }

    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_socket() || meta.file_type().is_file() {
                std::fs::remove_file(path)?;
            } else {
                return Err(ZeroVaultError::IpcError(format!(
                    "IPC socket path {} exists and is not a socket",
                    path.display()
                )));
            }
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
}

impl fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcServer")
            .field("endpoint", &self.endpoint)
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
    /// Binds an IPC server on `endpoint`, enforcing loopback-only TCP, `0700`/`0600` Unix socket
    /// permissions, or `reject_remote_clients(true)` on Windows Named Pipes.
    pub async fn bind(endpoint: IpcEndpoint) -> ZeroVaultResult<Self> {
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
                })
            }
            #[cfg(unix)]
            IpcEndpoint::UnixSocket(path) => {
                if path.exists() && UnixStream::connect(&path).await.is_ok() {
                    return Err(ZeroVaultError::IpcError(format!(
                        "IPC socket {} is already actively served",
                        path.display()
                    )));
                }
                prepare_unix_socket_dir_and_path(&path)?;
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
                })
            }
            #[cfg(target_os = "windows")]
            IpcEndpoint::NamedPipe(pipe_name) => {
                if !pipe_name.starts_with(r"\\.\pipe\") {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "invalid Windows named pipe path '{pipe_name}'"
                    )));
                }
                let first = ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(&pipe_name)
                    .map_err(|e| {
                        ZeroVaultError::IpcError(format!(
                            "failed to create Windows named pipe '{pipe_name}': {e}"
                        ))
                    })?;
                Ok(Self {
                    endpoint: IpcEndpoint::NamedPipe(pipe_name.clone()),
                    listener: BoundListener::NamedPipe {
                        pipe_name,
                        current: Some(first),
                    },
                })
            }
        }
    }

    /// Returns the actual bound endpoint (e.g., resolved ephemeral port for `127.0.0.1:0`).
    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Serves incoming IPC connections until `external_shutdown` resolves OR a client sends
    /// [`DaemonRequest::Shutdown`].
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
                    tracing::warn!(error = %err, "IPC connection task panicked");
                }
            }

            if *internal_rx.borrow() {
                break;
            }

            match &mut self.listener {
                BoundListener::Tcp(listener) => {
                    tokio::select! {
                        _ = &mut external_shutdown => {
                            break;
                        }
                        _ = internal_rx.changed() => {
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
                                        handle_stream(stream, h, tx).await;
                                    });
                                }
                                Err(err) => {
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
                            break;
                        }
                        _ = internal_rx.changed() => {
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
                                        handle_stream(stream, h, tx).await;
                                    });
                                }
                                Err(err) => {
                                    tracing::warn!(error = %err, "Unix IPC accept error");
                                }
                            }
                        }
                    }
                }
                #[cfg(target_os = "windows")]
                BoundListener::NamedPipe { pipe_name, current } => {
                    let Some(server) = current.take() else {
                        return Err(ZeroVaultError::IpcError(
                            "Windows named pipe server state missing".into(),
                        ));
                    };
                    tokio::select! {
                        _ = &mut external_shutdown => {
                            drop(server);
                            break;
                        }
                        _ = internal_rx.changed() => {
                            drop(server);
                            if *internal_rx.borrow() {
                                break;
                            }
                        }
                        res = server.connect() => {
                            match res {
                                Ok(()) => {
                                    match ServerOptions::new()
                                        .first_pipe_instance(false)
                                        .reject_remote_clients(true)
                                        .create(pipe_name.as_str())
                                    {
                                        Ok(next) => {
                                            *current = Some(next);
                                        }
                                        Err(err) => {
                                            tracing::error!(error = %err, "failed creating next named pipe instance");
                                            let h = Arc::clone(&handler);
                                            let tx = internal_tx.clone();
                                            tasks.spawn(async move {
                                                handle_stream(server, h, tx).await;
                                            });
                                            break;
                                        }
                                    }
                                    let h = Arc::clone(&handler);
                                    let tx = internal_tx.clone();
                                    tasks.spawn(async move {
                                        handle_stream(server, h, tx).await;
                                    });
                                }
                                Err(err) => {
                                    tracing::warn!(error = %err, "Windows named pipe connect error");
                                    *current = Some(ServerOptions::new()
                                        .first_pipe_instance(false)
                                        .reject_remote_clients(true)
                                        .create(pipe_name.as_str())
                                        .map_err(|e| ZeroVaultError::IpcError(format!("named pipe recreate failed: {e}")))?);
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
) where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(DaemonRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = DaemonResponse> + Send,
{
    loop {
        let raw = match read_frame_or_eof(&mut stream).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(error = %err, "rejected invalid IPC frame");
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
                if let Err(write_err) = write_json_frame(&mut stream, &err_resp).await {
                    tracing::warn!(error = %write_err, "failed sending IPC error frame");
                }
                break;
            }
        };
        drop(raw);

        let is_shutdown = matches!(request, DaemonRequest::Shutdown);
        let response = handler(request).await;

        if let Err(err) = write_json_frame(&mut stream, &response).await {
            tracing::warn!(error = %err, "failed writing IPC response frame");
            break;
        }

        if is_shutdown {
            let _ = shutdown_tx.send(true);
            break;
        }
    }
}

/// Local IPC client used by `zv` CLI and `zerovault-ui`.
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

        match &self.endpoint {
            IpcEndpoint::TcpLoopback(addr) => {
                if !is_loopback_ip(addr.ip()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "refusing TCP IPC connection to non-loopback address {}",
                        addr.ip()
                    )));
                }
                let mut stream = TcpStream::connect(addr).await.map_err(|e| {
                    ZeroVaultError::IpcError(format!("failed connecting to TCP IPC {addr}: {e}"))
                })?;
                exchange_frames(&mut stream, payload.as_slice()).await
            }
            #[cfg(unix)]
            IpcEndpoint::UnixSocket(path) => {
                let mut stream = UnixStream::connect(path).await.map_err(|e| {
                    ZeroVaultError::IpcError(format!(
                        "failed connecting to Unix IPC {}: {e}",
                        path.display()
                    ))
                })?;
                exchange_frames(&mut stream, payload.as_slice()).await
            }
            #[cfg(target_os = "windows")]
            IpcEndpoint::NamedPipe(pipe_name) => {
                let mut stream = connect_named_pipe_with_retry(pipe_name).await?;
                exchange_frames(&mut stream, payload.as_slice()).await
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

async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> ZeroVaultResult<DaemonResponse> {
    write_frame(stream, payload).await?;
    read_json_frame::<_, DaemonResponse>(stream).await
}

#[cfg(target_os = "windows")]
async fn connect_named_pipe_with_retry(
    pipe_name: &str,
) -> ZeroVaultResult<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: usize = 50;

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
        "timed out waiting for busy Windows named pipe '{pipe_name}'"
    )))
}
