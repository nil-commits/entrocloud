//! Lightweight in-process mock IPC server speaking exact `zerovaultd` `u32 BE` + `serde_json`
//! wire frames over loopback TCP or Windows Named Pipes / Unix Domain Sockets for automated tests.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use entrocloud_types::{DaemonRequest, DaemonResponse, ZeroVaultError, ZeroVaultResult};

use crate::ipc_client::{IpcEndpoint, read_raw_frame, write_json_frame};

/// Multi-connection loopback TCP mock daemon server used in unit and integration tests.
pub struct MockDaemonServer {
    endpoint: IpcEndpoint,
    stop_flag: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl MockDaemonServer {
    /// Binds an ephemeral `127.0.0.1:0` loopback TCP listener and dispatches every incoming
    /// length-prefixed [`DaemonRequest`] through `handler`.
    pub fn spawn_tcp<F>(handler: F) -> ZeroVaultResult<Self>
    where
        F: Fn(DaemonRequest) -> DaemonResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| {
            ZeroVaultError::IpcError(format!("failed binding mock TCP listener: {err}"))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            ZeroVaultError::IpcError(format!("failed setting nonblocking listener: {err}"))
        })?;
        let local_addr = listener.local_addr().map_err(|err| {
            ZeroVaultError::IpcError(format!("failed reading mock TCP local_addr: {err}"))
        })?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);
        let shared_handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            let mut client_threads = Vec::new();
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let h = Arc::clone(&shared_handler);
                        let cstop = Arc::clone(&thread_stop);
                        client_threads.push(thread::spawn(move || {
                            serve_sync_stream(&mut stream, h.as_ref(), &cstop);
                        }));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for t in client_threads {
                let _ = t.join();
            }
        });

        Ok(Self {
            endpoint: IpcEndpoint::TcpLoopback(local_addr),
            stop_flag,
            accept_thread: Some(handle),
        })
    }

    /// Returns the bound [`IpcEndpoint`] for `IpcClient::new(...)` or `--ipc <endpoint>`.
    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Signals the mock server to stop accepting connections and joins the accept thread.
    pub fn shutdown(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MockDaemonServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve_sync_stream<S, F>(stream: &mut S, handler: &F, stop: &AtomicBool)
where
    S: Read + Write,
    F: Fn(DaemonRequest) -> DaemonResponse,
{
    while !stop.load(Ordering::Relaxed) {
        let raw = match read_raw_frame(stream) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let req: DaemonRequest = match serde_json::from_slice(raw.as_slice()) {
            Ok(r) => r,
            Err(err) => {
                let resp = DaemonResponse::Error {
                    code: "invalid_request".to_owned(),
                    message: format!("malformed JSON: {err}"),
                };
                let _ = write_json_frame(stream, &resp);
                break;
            }
        };
        drop(raw);
        let is_shutdown = matches!(req, DaemonRequest::Shutdown);
        let resp = handler(req);
        if write_json_frame(stream, &resp).is_err() {
            break;
        }
        if is_shutdown {
            stop.store(true, Ordering::Relaxed);
            break;
        }
    }
}
