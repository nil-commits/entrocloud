//! Pure-Rust Zero-WebView Native GPU Desktop Application (`eframe 0.29.1` / `egui` + `glow` + `AccessKit`)
//! and System Tray companion (`tray-icon 0.26.1`) for `EntroCloud v1.0`.
//!
//! Strictly decoupled from `entrocloudd` over local Named Pipe / Unix Domain Socket / loopback TCP
//! IPC (`u32 BE` length prefix + `serde_json`), with zero unwrap/expect calls, zero WebView2/browser
//! modules, async background OS file pickers, and anti-aliased vector iconography.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod app;
pub mod cli;
pub mod demo;
pub mod dialogs;
pub mod icons;
pub mod ipc_client;
pub mod metrics;
pub mod mock_ipc;
pub mod session;
pub mod theme;
pub mod tray_common;
pub mod views;
pub mod wizard;
pub mod worker;

pub use app::{ColdBenchConfig, EntroCloudApp, StudioTab, ZeroVaultApp};
pub use cli::UiCliArgs;
pub use demo::{
    MODAL_TOUR_STEPS, ScreenshotTourDriver, TOUR_STEPS, populate_demo_worker_state,
    write_color_image_png,
};
pub use dialogs::{AsyncDialogs, DialogOutcome, DialogPurpose};
pub use icons::{Icon, paint_brand_mark, paint_icon};
pub use ipc_client::{
    DEFAULT_WINDOWS_PIPE_NAME, IpcClient, IpcEndpoint, WINDOWS_CREATE_NO_WINDOW,
    locate_executable_in_dir, locate_sibling_executable, read_json_frame, read_raw_frame,
    spawn_detached_process, unix_socket_path_from_env, validate_frame_len, write_json_frame,
    write_raw_frame,
};
pub use metrics::{
    ColdBenchReport, ProcessMemorySnapshot, TrayBenchReport, detect_loaded_webview_modules,
    elapsed_ms, is_forbidden_browser_module_name, now_ticks, round3,
    sample_current_process_memory, ticks_per_sec,
};
pub use mock_ipc::MockDaemonServer;
pub use session::{
    ImportSummary, count_session_preview_files, create_unique_preview_subdir,
    default_session_preview_dir, ensure_private_dir, export_for_secure_preview,
    import_local_paths_recursive, join_ui_vpath, normalize_ui_vpath, open_https_url,
    open_in_os_default_app, scrub_session_dir, split_ui_parent_and_name,
    zero_wipe_and_remove_file,
};
pub use theme::{
    Palette, PillTone, SEMIBOLD_FAMILY_NAME, ThemePreference, UiPrefs, apply_palette,
    escape_desktop_exec_arg, install_os_fonts, set_os_autostart_enabled,
};
pub use tray_common::{
    format_bytes_human, format_bytes_iec, format_rate_iec, generate_entrocloud_rgba_icon,
    generate_vault_rgba_icon,
};
pub use views::sharing::ShareImportModalState;
pub use views::{ExplorerSortColumn, FrameSnapshot, NavPage};
pub use wizard::{OnboardingFlow, S3Preset, WizardOutcome, WizardProvider, WizardState, WizardStep};
pub use worker::{SharedWorkerState, UiCommand, UiWorkerHandle};
