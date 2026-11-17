//! Zerovault background daemon library & cross-platform local IPC transport.
//!
//! Exposes:
//! - [`ipc`]: length-prefixed JSON IPC over Windows Named Pipes, Unix Domain Sockets (`0700`/`0600`),
//!   and loopback TCP with strict [`zerovault_types::MAX_IPC_FRAME_BYTES`] (16 MiB) framing checks.
//! - [`service`]: [`DaemonRuntime`] orchestrating vault key lifecycle, multi-cloud storage routing,
//!   and injectable [`SyncEngineFactory`] / [`DriveFactory`] hooks.

pub mod ipc;
pub mod service;

#[cfg(test)]
mod tests;

pub use ipc::{
    DEFAULT_WINDOWS_PIPE_NAME, IpcClient, IpcEndpoint, IpcServer, read_frame, read_json_frame,
    validate_frame_len, write_frame, write_json_frame,
};
pub use service::{
    CoreSyncEngineFactory, DaemonRuntime, DaemonRuntimeBuilder, DaemonStateConfig,
    DefaultDriveFactory, DriveFactory, DynamicStorageRouter, MockSyncEngineFactory,
    SyncBackendBundle, SyncBackendProvider, SyncEngineFactory, SyncRunner, SyncTelemetryProvider,
    backend_kind_label, normalize_vault_virtual_path, parse_backend_kind,
};
pub use zerovault_types;
