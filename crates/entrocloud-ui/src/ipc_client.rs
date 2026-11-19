//! Decoupled cross-platform IPC client (`u32 BE` length prefix + `serde_json`) and
//! sibling `entrocloudd` background auto-spawner.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use entrocloud_types::{
    DaemonRequest, DaemonResponse, MAX_IPC_FRAME_BYTES, ZeroVaultError, ZeroVaultResult,
};
use zeroize::Zeroizing;

/// Default Windows Named Pipe path for `entrocloudd`.
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\entrocloudd";

/// Win32 `CREATE_NO_WINDOW` process creation flag (`0x08000000`).
pub const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

const FRAME_HEADER_LEN: usize = 4;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_READ_WRITE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Validated local IPC endpoint targeting `entrocloudd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Windows Named Pipe (`\\.\pipe\<name>`).
    #[cfg(target_os = "windows")]
    NamedPipe(String),
    /// Unix Domain Socket (`$XDG_RUNTIME_DIR/entrocloud/entrocloudd.sock` or `/tmp/entrocloud-<uid>/entrocloudd.sock`).
    #[cfg(unix)]
    UnixSocket(PathBuf),
    /// Loopback TCP socket (`127.0.0.1:<port>` or `[::1]:<port>`), strictly restricted to loopback IPs.
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
            Self::NamedPipe(pipe) => f.write_str(pipe),
            #[cfg(unix)]
            Self::UnixSocket(path) => write!(f, "{}", path.display()),
            Self::TcpLoopback(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

impl FromStr for IpcEndpoint {
    type Err = ZeroVaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl IpcEndpoint {
    /// Parses and validates an IPC endpoint string (`\\.\pipe\...`, `pipe://...`, `unix://...`, `/path.sock`, or `tcp://127.0.0.1:PORT`).
    pub fn parse(raw: &str) -> ZeroVaultResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ZeroVaultError::ConfigError(
                "IPC endpoint string must not be empty".into(),
            ));
        }

        if let Some(addr_str) = trimmed.strip_prefix("tcp://") {
            let addr: SocketAddr = addr_str.parse().map_err(|err| {
                ZeroVaultError::ConfigError(format!("invalid TCP IPC endpoint '{trimmed}': {err}"))
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
                let clean = sock_path.trim();
                if clean.is_empty() {
                    return Err(ZeroVaultError::ConfigError(
                        "unix socket endpoint must specify a socket path".into(),
                    ));
                }
                return Ok(Self::UnixSocket(PathBuf::from(clean)));
            }
            if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
                return Ok(Self::UnixSocket(PathBuf::from(trimmed)));
            }
        }

        Err(ZeroVaultError::ConfigError(format!(
            "unsupported IPC endpoint '{trimmed}'"
        )))
    }

    /// Resolves an endpoint from an explicit CLI override, `ENTROCLOUD_IPC` / `ENTROCLOUD_ENDPOINT`
    /// (or legacy `ZEROVAULT_IPC` / `ZEROVAULT_ENDPOINT`) env vars, or the platform default
    /// (`\\.\pipe\entrocloudd` on Windows, `$XDG_RUNTIME_DIR/entrocloud/entrocloudd.sock` on Unix).
    pub fn resolve(cli_override: Option<&str>) -> ZeroVaultResult<(Self, bool)> {
        if let Some(explicit) = cli_override.map(str::trim).filter(|s| !s.is_empty()) {
            let ep = Self::parse(explicit)?;
            let is_default = ep == Self::default();
            return Ok((ep, is_default));
        }
        for env_key in [
            "ENTROCLOUD_IPC",
            "ENTROCLOUD_ENDPOINT",
            "ZEROVAULT_IPC",
            "ZEROVAULT_ENDPOINT",
        ] {
            if let Ok(val) = std::env::var(env_key) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    let ep = Self::parse(trimmed)?;
                    let is_default = ep == Self::default();
                    return Ok((ep, is_default));
                }
            }
        }
        Ok((Self::default(), true))
    }

    fn validated_tcp(addr: SocketAddr) -> ZeroVaultResult<Self> {
        if !is_loopback_ip(addr.ip()) {
            return Err(ZeroVaultError::ConfigError(format!(
                "TCP IPC endpoint must use a loopback IP (127.0.0.1 / ::1), got {}",
                addr.ip()
            )));
        }
        Ok(Self::TcpLoopback(addr))
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Resolves the Unix Domain Socket path:
/// `$XDG_RUNTIME_DIR/entrocloud/entrocloudd.sock`, falling back to `/tmp/entrocloud-<uid>/entrocloudd.sock`.
#[must_use]
pub fn unix_socket_path_from_env(xdg_runtime_dir: Option<&Path>, uid: u32) -> PathBuf {
    if let Some(dir) = xdg_runtime_dir
        && !dir.as_os_str().is_empty()
    {
        return dir.join("entrocloud").join("entrocloudd.sock");
    }
    PathBuf::from(format!("/tmp/entrocloud-{uid}")).join("entrocloudd.sock")
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
    unix_socket_path_from_env(xdg.as_deref(), current_uid_raw())
}

/// Validates that an IPC frame byte length lies strictly within `1..=MAX_IPC_FRAME_BYTES`.
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

/// Writes a single `u32` big-endian length-prefixed frame to `writer`.
pub fn write_raw_frame<W: Write>(writer: &mut W, payload: &[u8]) -> ZeroVaultResult<()> {
    validate_frame_len(payload.len())?;
    let len_u32 = u32::try_from(payload.len())
        .map_err(|_| ZeroVaultError::IpcError("IPC payload exceeds u32::MAX".into()))?;
    writer
        .write_all(&len_u32.to_be_bytes())
        .map_err(|err| ZeroVaultError::IpcError(format!("failed writing IPC length header: {err}")))?;
    writer
        .write_all(payload)
        .map_err(|err| ZeroVaultError::IpcError(format!("failed writing IPC payload: {err}")))?;
    writer
        .flush()
        .map_err(|err| ZeroVaultError::IpcError(format!("failed flushing IPC stream: {err}")))?;
    Ok(())
}

/// Reads a single `u32` big-endian length-prefixed frame into a `Zeroizing<Vec<u8>>`,
/// rejecting oversized frames (`> MAX_IPC_FRAME_BYTES`) BEFORE allocating memory.
pub fn read_raw_frame<R: Read>(reader: &mut R) -> ZeroVaultResult<Zeroizing<Vec<u8>>> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut hdr)
        .map_err(|err| ZeroVaultError::IpcError(format!("failed reading IPC length header: {err}")))?;
    let len = u32::from_be_bytes(hdr) as usize;
    validate_frame_len(len)?;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader
        .read_exact(buf.as_mut_slice())
        .map_err(|err| ZeroVaultError::IpcError(format!("failed reading IPC payload: {err}")))?;
    Ok(buf)
}

/// Serializes `value` as UTF-8 JSON inside a `Zeroizing` buffer and sends it with a `u32 BE` header.
pub fn write_json_frame<W: Write, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
) -> ZeroVaultResult<()> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|err| ZeroVaultError::IpcError(format!("failed encoding IPC JSON: {err}")))?,
    );
    write_raw_frame(writer, encoded.as_slice())
}

/// Reads a `u32 BE` length-prefixed UTF-8 JSON frame and deserializes it into `T`, zeroizing raw bytes on drop.
pub fn read_json_frame<R: Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> ZeroVaultResult<T> {
    let raw = read_raw_frame(reader)?;
    serde_json::from_slice(raw.as_slice())
        .map_err(|err| ZeroVaultError::IpcError(format!("failed decoding IPC JSON: {err}")))
}

/// Decoupled synchronous IPC client for `entrocloud` and `entrocloud-tray`.
#[derive(Debug, Clone)]
pub struct IpcClient {
    endpoint: IpcEndpoint,
    pipe_wait_ms: u32,
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new(IpcEndpoint::default())
    }
}

impl IpcClient {
    /// Creates an [`IpcClient`] bound to `endpoint`.
    #[must_use]
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self {
            endpoint,
            pipe_wait_ms: 800,
        }
    }

    /// Creates a fast-probing [`IpcClient`] with a short busy-wait budget (used for `--bench-cold`).
    #[must_use]
    pub fn with_pipe_wait_ms(mut self, wait_ms: u32) -> Self {
        self.pipe_wait_ms = wait_ms;
        self
    }

    /// Returns the target [`IpcEndpoint`].
    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Sends one [`DaemonRequest`] frame and awaits the corresponding [`DaemonResponse`] frame.
    pub fn request(&self, req: &DaemonRequest) -> ZeroVaultResult<DaemonResponse> {
        let payload = Zeroizing::new(serde_json::to_vec(req).map_err(|err| {
            ZeroVaultError::IpcError(format!("failed serializing DaemonRequest: {err}"))
        })?);
        validate_frame_len(payload.len())?;

        match &self.endpoint {
            IpcEndpoint::TcpLoopback(addr) => {
                if !is_loopback_ip(addr.ip()) {
                    return Err(ZeroVaultError::ConfigError(format!(
                        "refusing non-loopback TCP IPC target {}",
                        addr.ip()
                    )));
                }
                let mut stream =
                    TcpStream::connect_timeout(addr, TCP_CONNECT_TIMEOUT).map_err(|err| {
                        ZeroVaultError::IpcError(format!(
                            "failed connecting to TCP IPC {addr}: {err}"
                        ))
                    })?;
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(IO_READ_WRITE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_READ_WRITE_TIMEOUT));
                exchange_stream(&mut stream, payload.as_slice())
            }
            #[cfg(unix)]
            IpcEndpoint::UnixSocket(path) => {
                use std::os::unix::net::UnixStream;
                let mut stream = UnixStream::connect(path).map_err(|err| {
                    ZeroVaultError::IpcError(format!(
                        "failed connecting to Unix socket {}: {err}",
                        path.display()
                    ))
                })?;
                let _ = stream.set_read_timeout(Some(IO_READ_WRITE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_READ_WRITE_TIMEOUT));
                exchange_stream(&mut stream, payload.as_slice())
            }
            #[cfg(target_os = "windows")]
            IpcEndpoint::NamedPipe(pipe_name) => {
                let mut pipe_file = open_windows_named_pipe(pipe_name, self.pipe_wait_ms)?;
                exchange_stream(&mut pipe_file, payload.as_slice())
            }
        }
    }

    /// Sends [`DaemonRequest::Ping`] and verifies [`DaemonResponse::Ok`].
    pub fn ping(&self) -> ZeroVaultResult<()> {
        match self.request(&DaemonRequest::Ping)? {
            DaemonResponse::Ok { .. } => Ok(()),
            DaemonResponse::Error { code, message } => {
                Err(ZeroVaultError::IpcError(format!("[{code}] {message}")))
            }
            other => Err(ZeroVaultError::IpcError(format!(
                "unexpected Ping response: {other:?}"
            ))),
        }
    }

    /// Ensures `entrocloudd` is reachable on `self.endpoint()`.
    ///
    /// If the initial `Ping` fails AND `allow_autostart` is `true`, locates the sibling
    /// `entrocloudd` executable next to `std::env::current_exe()`, spawns it detached in the
    /// background (`CREATE_NO_WINDOW` `0x08000000` on Windows), and retries `Ping` up to `timeout`.
    pub fn ensure_daemon_running(
        &self,
        allow_autostart: bool,
        timeout: Duration,
    ) -> ZeroVaultResult<bool> {
        if self.ping().is_ok() {
            return Ok(false);
        }
        if !allow_autostart {
            return Err(ZeroVaultError::IpcError(format!(
                "EntroCloud background service is not reachable at {}",
                self.endpoint
            )));
        }

        let sibling_daemon = locate_sibling_executable("entrocloudd")
            .or_else(|| locate_sibling_executable("EntroCloudd"))
            .or_else(|| locate_sibling_executable("zerovaultd"));

        let launched_path = if let Some(daemon_exe) = sibling_daemon {
            spawn_detached_daemon(&daemon_exe, &self.endpoint)?;
            daemon_exe
        } else {
            let self_exe = std::env::current_exe().map_err(|err| {
                ZeroVaultError::IpcError(format!(
                    "EntroCloud background service is offline and current executable path could not be resolved: {err}"
                ))
            })?;
            spawn_detached_embedded_daemon(&self_exe, &self.endpoint)?;
            self_exe
        };

        let deadline = Instant::now() + timeout;
        let mut last_err = String::from("background service starting");
        while Instant::now() < deadline {
            match self.ping() {
                Ok(()) => return Ok(true),
                Err(err) => {
                    last_err = err.to_string();
                    thread::sleep(Duration::from_millis(35));
                }
            }
        }

        Err(ZeroVaultError::IpcError(format!(
            "started {} but connection timed out: {last_err}",
            launched_path.display()
        )))
    }
}

fn exchange_stream<S: Read + Write>(
    stream: &mut S,
    request_bytes: &[u8],
) -> ZeroVaultResult<DaemonResponse> {
    write_raw_frame(stream, request_bytes)?;
    read_json_frame::<_, DaemonResponse>(stream)
}

/// Resolves a sibling binary (`entrocloudd` or `entrocloud`) located in the same directory as `current_exe()`.
#[must_use]
pub fn locate_sibling_executable(stem: &str) -> Option<PathBuf> {
    let cur = std::env::current_exe().ok()?;
    let dir = cur.parent()?;
    locate_executable_in_dir(dir, stem)
}

/// Resolves an executable named `stem` (`<stem>.exe` on Windows, `<stem>` on Unix) inside `dir`.
#[must_use]
pub fn locate_executable_in_dir(dir: &Path, stem: &str) -> Option<PathBuf> {
    let file_name = if cfg!(target_os = "windows") {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    };
    let candidate = dir.join(file_name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Spawns a sibling EntroCloud helper process detached in the background without opening a console window.
pub fn spawn_detached_process(
    exe_path: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> ZeroVaultResult<()> {
    let mut cmd = Command::new(exe_path);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for &(k, v) in envs {
        cmd.env(k, v);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Isolate the detached daemon/UI in its own process group so parent terminal signals
        // (`SIGINT` / `SIGHUP`) do not terminate the background process.
        cmd.process_group(0);
    }

    let _child = cmd.spawn().map_err(|err| {
        ZeroVaultError::IpcError(format!(
            "failed spawning background process {}: {err}",
            exe_path.display()
        ))
    })?;
    Ok(())
}

fn spawn_detached_daemon(daemon_exe: &Path, endpoint: &IpcEndpoint) -> ZeroVaultResult<()> {
    let ep_str = endpoint.to_string();
    spawn_detached_process(
        daemon_exe,
        &["--ipc", ep_str.as_str()],
        &[
            ("ENTROCLOUD_IPC", ep_str.as_str()),
            ("ENTROCLOUD_ENDPOINT", ep_str.as_str()),
            ("ZEROVAULT_IPC", ep_str.as_str()),
            ("ZEROVAULT_ENDPOINT", ep_str.as_str()),
        ],
    )
}

fn spawn_detached_embedded_daemon(ui_exe: &Path, endpoint: &IpcEndpoint) -> ZeroVaultResult<()> {
    let ep_str = endpoint.to_string();
    spawn_detached_process(
        ui_exe,
        &["--daemon", "--ipc", ep_str.as_str()],
        &[
            ("ENTROCLOUD_IPC", ep_str.as_str()),
            ("ENTROCLOUD_ENDPOINT", ep_str.as_str()),
            ("ZEROVAULT_IPC", ep_str.as_str()),
            ("ZEROVAULT_ENDPOINT", ep_str.as_str()),
        ],
    )
}

#[cfg(target_os = "windows")]
fn open_windows_named_pipe(pipe_name: &str, max_wait_ms: u32) -> ZeroVaultResult<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    if !pipe_name.starts_with(r"\\.\pipe\") || pipe_name.len() <= r"\\.\pipe\".len() {
        return Err(ZeroVaultError::ConfigError(format!(
            "invalid Windows Named Pipe path '{pipe_name}'"
        )));
    }

    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + Duration::from_millis(u64::from(max_wait_ms));

    loop {
        // SAFETY: `wide` is null-terminated UTF-16; `SECURITY_SQOS_PRESENT` (`SECURITY_ANONYMOUS == 0`)
        // prevents named-pipe client impersonation. Returned handle is owned exclusively by `File`.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            // SAFETY: `handle` was just validated as a live Win32 file/pipe handle.
            let file = unsafe { std::fs::File::from_raw_handle(handle) };
            return Ok(file);
        }

        // SAFETY: Reads thread-local Win32 error code immediately after `CreateFileW`.
        let err_code = unsafe { GetLastError() };
        if err_code == ERROR_PIPE_BUSY && Instant::now() < deadline {
            // SAFETY: `wide` is a valid null-terminated UTF-16 pipe name.
            unsafe {
                let _ = WaitNamedPipeW(wide.as_ptr(), 25);
            }
            continue;
        }

        return Err(ZeroVaultError::IpcError(format!(
            "failed connecting to Windows Named Pipe '{pipe_name}' (Win32 error {err_code})"
        )));
    }
}
