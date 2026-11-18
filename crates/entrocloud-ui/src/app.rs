//! Native `eframe`/`egui` (`glow` + `AccessKit`) EntroCloud Desktop Application.
//!
//! Combines CloudBridge's calm `#132D37` sidebar, `#F4F7F8` canvas, `#FFFFFF` cards, and `#007D78`
//! teal actions with ZeroVault's friendly plain-English Cloud Backup, Computer Drive, Vault Files,
//! Private Sharing (`ec://`), and Settings views — with zero WebView2 or browser runtimes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{
    self, Align2, Color32, CursorIcon, FontId, Margin, Pos2, Rect, RichText, Rounding, Sense,
    Stroke, Vec2,
};
use entrocloud_types::CapabilityUri;
use parking_lot::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::demo::{
    MODAL_TOUR_STEPS, ScreenshotTourDriver, TOUR_STEPS, configure_tour_step_ui,
    populate_demo_worker_state, write_color_image_png,
};
use crate::dialogs::{AsyncDialogs, DialogOutcome, DialogPurpose};
use crate::icons::{Icon, paint_brand_mark, paint_icon};
use crate::metrics::{
    ColdBenchReport, detect_loaded_webview_modules, elapsed_ms, now_ticks, round3,
    sample_current_process_memory,
};
use crate::theme::{
    Palette, PillTone, ThemePreference, UiPrefs, apply_palette, form_label, icon_button,
    input_row_with_right_widget, install_os_fonts, modal_dialog, primary_button, secondary_button,
    semibold_font, sidebar_action_button, sidebar_nav_item, status_pill, text_input_single,
};
use crate::tray_common::format_bytes_human;
use crate::views::backups::{BackupJobModalState, RestoreModalState, render_backups_view};
use crate::views::clouds::{CloudsViewState, render_clouds_view};
use crate::views::drive::render_drive_view;
use crate::views::files::{FilesViewState, render_files_view};
use crate::views::settings::{render_settings_cards, render_settings_view};
use crate::views::sharing::{
    ShareImportModalState, SharingViewState, render_sharing_cards, render_sharing_view,
};
use crate::views::unlock::render_unlock_screen;
use crate::views::{FrameSnapshot, NavPage};
use crate::wizard::{OnboardingFlow, WizardOutcome, WizardProvider, WizardState, WizardStep};
use crate::worker::{UiCommand, UiWorkerHandle};

/// Backward-compatible type alias for existing integration tests.
pub type StudioTab = NavPage;
/// Backward-compatible type alias for existing integration tests.
pub type ZeroVaultApp = EntroCloudApp;

/// Cold-start benchmark timing context when `--bench-cold` is passed.
#[derive(Debug, Clone, Copy)]
pub struct ColdBenchConfig {
    pub main_entry_ticks: i64,
    pub ipc_probe_ms: f64,
    pub spawn_qpc: Option<i64>,
}

/// Main native GPU EntroCloud Desktop Application (`eframe::App`).
pub struct EntroCloudApp {
    worker: UiWorkerHandle,
    dialogs: AsyncDialogs,
    gpu_adapter: String,
    cold_bench: Option<ColdBenchConfig>,
    bench_output: Arc<Mutex<Option<ColdBenchReport>>>,
    tour_driver: Option<ScreenshotTourDriver>,
    tour_result: Option<Arc<Mutex<Result<usize, String>>>>,
    persist_prefs_to_disk: bool,
    total_gpu_frames: u32,
    frame1_update_cpu_ms: f64,
    exit_handled: bool,

    // Persistent preferences & active navigation
    prefs: UiPrefs,
    prefs_dirty: bool,
    active_page: NavPage,
    wizard: WizardState,
    auto_wizard_evaluated: bool,

    // Unlock / passphrase buffers (zeroized immediately on submit & exit)
    was_unlocked: bool,
    init_new_vault_mode: bool,
    passphrase_input: Zeroizing<String>,
    confirm_passphrase_input: Zeroizing<String>,
    show_unlock_pass: bool,
    unlock_error: Option<String>,
    unlock_autofocused: bool,

    // Per-view interactive state
    selected_backup_job_id: Option<String>,
    backup_job_modal: BackupJobModalState,
    restore_modal: RestoreModalState,
    remove_confirm_job: Option<(String, String)>,

    files_state: FilesViewState,
    clouds_state: CloudsViewState,
    sharing_state: SharingViewState,
    share_import_modal: ShareImportModalState,

    mount_point_input: String,
    last_daemon_mount_point: Option<String>,
    use_portable_sandbox: bool,
    bench_payload_mib: usize,
}

impl EntroCloudApp {
    /// Constructs a new [`EntroCloudApp`] bound to `worker`.
    #[must_use]
    pub fn new(
        cc: Option<&eframe::CreationContext<'_>>,
        worker: UiWorkerHandle,
        initial_open_uri: Option<(String, String)>,
        cold_bench: Option<ColdBenchConfig>,
        bench_output: Arc<Mutex<Option<ColdBenchReport>>>,
    ) -> Self {
        let is_test_or_bench = cc.is_none() || cold_bench.is_some();
        let prefs = if is_test_or_bench {
            UiPrefs {
                wizard_completed: true,
                ..UiPrefs::default()
            }
        } else {
            UiPrefs::load()
        };

        let gpu_adapter = if let Some(creation_ctx) = cc {
            install_os_fonts(&creation_ctx.egui_ctx);
            let pal = Palette::resolve(prefs.theme, &creation_ctx.egui_ctx);
            apply_palette(&creation_ctx.egui_ctx, &pal);
            worker.state.lock().egui_ctx = Some(creation_ctx.egui_ctx.clone());
            detect_glow_adapter_string(creation_ctx)
        } else {
            "Headless Test Context".to_owned()
        };

        let default_mount = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("EntroCloud")
            .display()
            .to_string();

        let mut share_import_modal = ShareImportModalState::default();
        let mut sharing_state = SharingViewState::default();
        let mut active_page = NavPage::Backups;

        if let Some((uri_str, suggested_dest)) = initial_open_uri {
            share_import_modal.open = true;
            share_import_modal.uri = Zeroizing::new(uri_str.clone());
            share_import_modal.dest_virtual_path = suggested_dest.clone();
            sharing_state.accept_uri = Zeroizing::new(uri_str);
            sharing_state.accept_dest_vpath = suggested_dest;
            active_page = NavPage::Sharing;
        }

        let initially_unlocked = worker
            .state
            .lock()
            .status
            .as_ref()
            .is_some_and(|s| s.unlocked);

        Self {
            worker,
            dialogs: AsyncDialogs::new(),
            gpu_adapter,
            cold_bench,
            bench_output,
            tour_driver: None,
            tour_result: None,
            persist_prefs_to_disk: !is_test_or_bench,
            total_gpu_frames: 0,
            frame1_update_cpu_ms: 0.0,
            exit_handled: false,
            prefs,
            prefs_dirty: false,
            active_page,
            wizard: WizardState::new(),
            auto_wizard_evaluated: false,
            was_unlocked: initially_unlocked,
            init_new_vault_mode: false,
            passphrase_input: Zeroizing::new(String::new()),
            confirm_passphrase_input: Zeroizing::new(String::new()),
            show_unlock_pass: false,
            unlock_error: None,
            unlock_autofocused: false,
            selected_backup_job_id: None,
            backup_job_modal: BackupJobModalState::new_blank(),
            restore_modal: RestoreModalState::default(),
            remove_confirm_job: None,
            files_state: FilesViewState::default(),
            clouds_state: CloudsViewState::default(),
            sharing_state,
            share_import_modal,
            mount_point_input: default_mount,
            last_daemon_mount_point: None,
            use_portable_sandbox: false,
            bench_payload_mib: 128,
        }
    }

    /// Configures the app for `--screenshot-tour <OUTPUT_DIR>` with populated demo state.
    #[must_use]
    pub fn with_screenshot_tour(
        mut self,
        output_dir: PathBuf,
        result_slot: Arc<Mutex<Result<usize, String>>>,
    ) -> Self {
        self.persist_prefs_to_disk = false;
        self.auto_wizard_evaluated = true;
        {
            let mut guard = self.worker.state.lock();
            configure_tour_step_ui(
                0,
                &mut guard,
                &mut self.prefs,
                &mut self.active_page,
                &mut self.wizard,
            );
        }
        self.tour_driver = Some(ScreenshotTourDriver::new(output_dir));
        self.tour_result = Some(result_slot);
        self
    }

    /// Configures the app for `--screenshot-modals <OUTPUT_DIR>` to capture GPU-rendered modal dialogs.
    #[must_use]
    pub fn with_modal_screenshot_tour(
        mut self,
        output_dir: PathBuf,
        result_slot: Arc<Mutex<Result<usize, String>>>,
    ) -> Self {
        self.persist_prefs_to_disk = false;
        self.auto_wizard_evaluated = true;
        self.apply_modal_tour_step(0);
        self.tour_driver = Some(ScreenshotTourDriver::new_modals(output_dir));
        self.tour_result = Some(result_slot);
        self
    }

    fn apply_modal_tour_step(&mut self, idx: usize) {
        let Some(&(_, _, theme)) = MODAL_TOUR_STEPS.get(idx) else {
            return;
        };
        self.prefs.theme = theme;
        self.prefs.wizard_completed = true;
        self.wizard.open = false;
        self.backup_job_modal.open = false;
        self.restore_modal.open = false;
        self.remove_confirm_job = None;
        self.files_state.note_modal.open = false;
        self.files_state.new_folder_open = false;
        self.files_state.rename_target = None;
        self.files_state.delete_target = None;
        self.share_import_modal.open = false;

        {
            let mut guard = self.worker.state.lock();
            populate_demo_worker_state(&mut guard);
        }

        match idx {
            0 | 1 => {
                self.active_page = NavPage::Backups;
                self.backup_job_modal.open_for_new();
                self.backup_job_modal
                    .set_picked_source_folder(std::path::Path::new(r"C:\Users\Alex\Documents"));
            }
            2 => {
                self.active_page = NavPage::MyFiles;
                self.open_note_modal(
                    "/Documents/Recovery Codes.md",
                    "# Vault Recovery Notes\n\n- Primary cloud: GoogleDrive (/EntroCloud)\n- Mirror backup: CloudflareR2\n- Emergency contact keybox epoch: 2\n",
                );
            }
            3 => {
                self.active_page = NavPage::Backups;
                self.open_restore_modal("job-docs", "Documents", r"C:\Users\Alex\Desktop");
            }
            _ => {}
        }
    }

    /// Returns a reference to the asynchronous OS dialog manager (used in non-blocking dialog unit tests).
    #[must_use]
    pub fn dialogs(&self) -> &AsyncDialogs {
        &self.dialogs
    }

    /// Returns a mutable reference to the Setup Wizard state (used in headless wizard unit tests).
    pub fn wizard_mut(&mut self) -> &mut WizardState {
        &mut self.wizard
    }

    /// Sets the active color theme preference (`Light`, `Dark`, `System`) for tests or UI actions.
    pub fn set_theme_preference(&mut self, pref: ThemePreference) {
        self.prefs.theme = pref;
    }

    /// Sets Grid (`true`) vs List (`false`) mode in `My Files`.
    pub fn set_file_view_grid(&mut self, grid: bool) {
        self.prefs.file_view_grid = grid;
    }

    /// Returns the currently selected local folder path in the Add/Edit Backup Folder modal.
    #[must_use]
    pub fn backup_modal_source_path(&self) -> &str {
        &self.backup_job_modal.source_path
    }

    /// Opens the Add Protected Backup Folder modal (for layout/geometry tests and tour inspection).
    pub fn open_backup_job_modal(&mut self) {
        self.backup_job_modal.open_for_new();
    }

    /// Opens the Restore Encrypted Backup modal (for layout/geometry tests).
    pub fn open_restore_modal(&mut self, job_id: &str, job_name: &str, dest_parent: &str) {
        self.restore_modal.open = true;
        self.restore_modal.job_id = job_id.to_owned();
        self.restore_modal.job_name = job_name.to_owned();
        self.restore_modal.destination_parent = dest_parent.to_owned();
        self.restore_modal.error = None;
    }

    /// Opens the Remove Backup Schedule confirmation modal (for layout/geometry tests).
    pub fn open_remove_job_modal(&mut self, job_id: &str, job_name: &str) {
        self.remove_confirm_job = Some((job_id.to_owned(), job_name.to_owned()));
    }

    /// Opens the Disconnect Cloud Account confirmation modal (for layout/geometry tests).
    pub fn open_disconnect_cloud_modal(&mut self, remote_id: &str) {
        self.clouds_state.remove_remote_confirm = Some(remote_id.to_owned());
    }

    /// Opens the Private Encrypted Note modal (for layout/geometry tests).
    pub fn open_note_modal(&mut self, vpath: &str, body: &str) {
        self.files_state.note_modal.open = true;
        self.files_state.note_modal.virtual_path = vpath.to_owned();
        *self.files_state.note_modal.content = body.to_owned();
        self.files_state.note_modal.dirty = false;
        self.files_state.note_modal.loading = false;
    }

    /// Opens the New Folder modal (for layout/geometry tests).
    pub fn open_new_folder_modal(&mut self, initial_name: &str) {
        self.files_state.new_folder_open = true;
        self.files_state.new_folder_name = initial_name.to_owned();
    }

    /// Opens the Rename Item modal (for layout/geometry tests).
    pub fn open_rename_modal(&mut self, orig_vpath: &str, suggested_name: &str) {
        self.files_state.rename_target = Some(orig_vpath.to_owned());
        self.files_state.rename_new_path = suggested_name.to_owned();
    }

    /// Opens the Delete from Vault modal (for layout/geometry tests).
    pub fn open_delete_modal(&mut self, target_vpath: &str, is_dir: bool) {
        self.files_state.delete_target = Some((target_vpath.to_owned(), is_dir));
        self.files_state.delete_recursive = is_dir;
    }

    /// Opens the Save Shared Encrypted File modal (for layout/geometry tests).
    pub fn open_share_import_modal(&mut self, uri: &str, dest_vpath: &str) {
        self.share_import_modal.open = true;
        self.share_import_modal.uri = Zeroizing::new(uri.to_owned());
        self.share_import_modal.dest_virtual_path = dest_vpath.to_owned();
    }

    /// Returns whether the `ImportCapabilityShare` modal is open and its pre-populated target path.
    #[must_use]
    pub fn share_import_modal_summary(&self) -> (bool, String, bool) {
        (
            self.share_import_modal.open,
            self.share_import_modal.dest_virtual_path.clone(),
            !self.share_import_modal.uri.is_empty(),
        )
    }

    /// Switches the active navigation page (used by headless UI layout tests).
    pub fn set_active_tab(&mut self, page: NavPage) {
        self.active_page = page;
    }

    /// Sets the UI passphrase input buffers (exposed for unit tests verifying immediate zeroization).
    pub fn set_passphrase_inputs_for_test(&mut self, pass: &str, confirm: &str, init_mode: bool) {
        self.init_new_vault_mode = init_mode;
        *self.passphrase_input = pass.to_owned();
        *self.confirm_passphrase_input = confirm.to_owned();
    }

    /// Returns `true` when both UI passphrase input buffers are completely empty/zeroized.
    #[must_use]
    pub fn are_passphrase_buffers_empty(&self) -> bool {
        self.passphrase_input.is_empty() && self.confirm_passphrase_input.is_empty()
    }

    /// Submits Unlock or InitVault and IMMEDIATELY zeroizes both UI passphrase buffers in RAM.
    pub fn submit_passphrase_action(&mut self, current_dir: &str) -> Result<(), String> {
        if self.passphrase_input.is_empty() {
            return Err("Enter your Master Password first.".to_owned());
        }
        if self.init_new_vault_mode && *self.passphrase_input != *self.confirm_passphrase_input {
            self.passphrase_input.zeroize();
            self.confirm_passphrase_input.zeroize();
            return Err("Master Password and confirmation do not match.".to_owned());
        }

        let secret = Zeroizing::new((*self.passphrase_input).clone());
        self.passphrase_input.zeroize();
        self.confirm_passphrase_input.zeroize();

        if self.init_new_vault_mode {
            self.worker.send(UiCommand::InitVault { passphrase: secret });
        } else {
            self.worker.send(UiCommand::UnlockVault {
                passphrase: secret,
                current_dir: current_dir.to_owned(),
            });
        }
        Ok(())
    }

    /// Executes one full `egui` layout pass without requiring an `eframe::Frame` handle.
    pub fn render_headless_frame(&mut self, ctx: &egui::Context) {
        let pal = Palette::resolve(self.prefs.theme, ctx);
        apply_palette(ctx, &pal);

        self.poll_async_dialogs();
        let snap = self.sync_frame_snapshot(ctx);
        self.evaluate_first_run_wizard(&snap);

        let vault_initialized = snap
            .status
            .as_ref()
            .is_some_and(|s| s.vault_id.is_some() || s.unlocked);
        let vault_unlocked = snap.status.as_ref().is_some_and(|s| s.unlocked);
        if self.was_unlocked && !vault_unlocked {
            self.files_state.zeroize_secrets();
            self.sharing_state.zeroize_secrets();
            self.backup_job_modal.open = false;
            self.restore_modal.open = false;
            self.remove_confirm_job = None;
            self.files_state.note_modal.open = false;
            self.files_state.note_modal.loading = false;
            self.files_state.new_folder_open = false;
            self.files_state.rename_target = None;
            self.files_state.delete_target = None;
            self.clouds_state.remove_remote_confirm = None;
            self.share_import_modal.uri.zeroize();
            self.share_import_modal.open = false;
            if self.wizard.open && self.wizard.standalone_add_cloud {
                self.wizard.zeroize_secrets();
                self.wizard.open = false;
                self.wizard.standalone_add_cloud = false;
            }
            self.unlock_error = None;
        }
        self.was_unlocked = vault_unlocked;

        let remotes = snap
            .status
            .as_ref()
            .map_or(&[][..], |s| s.remotes.as_slice());

        // Full-window Wizard mode when onboarding or adding a cloud
        if self.wizard.open {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(pal.canvas_bg)
                        .inner_margin(Margin::symmetric(34.0, 22.0)),
                )
                .show(ctx, |ui| {
                    let wiz_outcome = self.wizard.render(
                        ctx,
                        ui,
                        &pal,
                        &self.worker,
                        &self.dialogs,
                        vault_initialized,
                        vault_unlocked,
                        remotes,
                        &snap.detected_clouds,
                        snap.oauth_in_progress.as_deref(),
                        snap.last_connected_remote.as_deref(),
                    );
                    self.apply_wizard_outcome(wiz_outcome);
                });
            self.render_toast_strip(ctx, &pal, &snap);
            self.flush_prefs_if_dirty();
            return;
        }

        // Centered Unlock Card when vault exists & is currently locked
        if !vault_unlocked {
            // Never dump a brand-new user (`vault_id.is_none()`) onto Unlock!
            if snap.daemon_connected && !vault_initialized && self.cold_bench.is_none() {
                self.wizard.flow = OnboardingFlow::CreateNewVault;
                self.wizard.open_full(WizardStep::Welcome);
                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::none()
                            .fill(pal.canvas_bg)
                            .inner_margin(Margin::symmetric(34.0, 22.0)),
                    )
                    .show(ctx, |ui| {
                        let wiz_outcome = self.wizard.render(
                            ctx,
                            ui,
                            &pal,
                            &self.worker,
                            &self.dialogs,
                            false,
                            false,
                            remotes,
                            &snap.detected_clouds,
                            snap.oauth_in_progress.as_deref(),
                            snap.last_connected_remote.as_deref(),
                        );
                        self.apply_wizard_outcome(wiz_outcome);
                    });
                return;
            }

            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(pal.canvas_bg)
                        .inner_margin(Margin::symmetric(28.0, 22.0)),
                )
                .show(ctx, |ui| {
                    render_unlock_screen(
                        ctx,
                        ui,
                        &pal,
                        &snap,
                        &self.worker,
                        &mut self.wizard,
                        &mut self.passphrase_input,
                        &mut self.show_unlock_pass,
                        &mut self.unlock_error,
                        &mut self.unlock_autofocused,
                    );
                });
            self.flush_prefs_if_dirty();
            return;
        }

        // Reset auto-focus flag so locking the vault later focuses the Master Password input again
        self.unlock_autofocused = false;

        // Unlocked Main Workspace: Fixed 248px CloudBridge Left Sidebar + Top Header + Active View
        self.render_sidebar(ctx, &pal, &snap);
        self.render_top_header(ctx, &pal, &snap);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(pal.canvas_bg)
                    .inner_margin(Margin::symmetric(28.0, 20.0)),
            )
            .show(ctx, |ui| {
                let split_tour = self
                    .tour_driver
                    .as_ref()
                    .is_some_and(ScreenshotTourDriver::is_split_sharing_and_settings);

                if split_tour {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.columns(2, |cols| {
                                render_sharing_cards(
                                    ctx,
                                    &mut cols[0],
                                    &pal,
                                    &snap,
                                    &self.worker,
                                    &mut self.sharing_state,
                                );
                                render_settings_cards(
                                    ctx,
                                    &mut cols[1],
                                    &pal,
                                    &snap,
                                    &self.worker,
                                    &mut self.wizard,
                                    &mut self.prefs,
                                    &mut self.prefs_dirty,
                                    &mut self.bench_payload_mib,
                                    &self.gpu_adapter,
                                );
                            });
                        });
                } else {
                    match self.active_page {
                        NavPage::Backups => render_backups_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &self.dialogs,
                            &mut self.wizard,
                            &mut self.selected_backup_job_id,
                            &mut self.backup_job_modal,
                            &mut self.restore_modal,
                            &mut self.remove_confirm_job,
                        ),
                        NavPage::MyFiles => render_files_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &self.dialogs,
                            &mut self.wizard,
                            &mut self.files_state,
                            &mut self.prefs.file_view_grid,
                            &mut self.prefs_dirty,
                            &mut self.active_page,
                            &mut self.sharing_state.share_source_vpath,
                        ),
                        NavPage::CloudConnections => render_clouds_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &mut self.wizard,
                            &mut self.clouds_state,
                        ),
                        NavPage::ComputerDrive => render_drive_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &self.dialogs,
                            &mut self.mount_point_input,
                            &mut self.use_portable_sandbox,
                        ),
                        NavPage::Sharing => render_sharing_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &mut self.sharing_state,
                        ),
                        NavPage::Settings => render_settings_view(
                            ctx,
                            ui,
                            &pal,
                            &snap,
                            &self.worker,
                            &mut self.wizard,
                            &mut self.prefs,
                            &mut self.prefs_dirty,
                            &mut self.bench_payload_mib,
                            &self.gpu_adapter,
                        ),
                    }
                }
            });

        self.render_toast_strip(ctx, &pal, &snap);
        self.render_global_modals(ctx, &pal, &snap);
        self.flush_prefs_if_dirty();
    }

    fn evaluate_first_run_wizard(&mut self, snap: &FrameSnapshot) {
        if self.auto_wizard_evaluated || self.cold_bench.is_some() || self.tour_driver.is_some() {
            return;
        }
        let Some(ref st) = snap.status else {
            return;
        };
        self.auto_wizard_evaluated = true;

        if (!self.prefs.wizard_completed && (st.vault_id.is_none() || st.remotes.is_empty()))
            || (st.vault_id.is_none() && !st.unlocked)
        {
            self.wizard.open_full(WizardStep::Welcome);
        }
    }

    fn apply_wizard_outcome(&mut self, outcome: WizardOutcome) {
        match outcome {
            WizardOutcome::None => {}
            WizardOutcome::FinishToWorkspace => {
                self.prefs.wizard_completed = true;
                self.prefs_dirty = true;
            }
            WizardOutcome::FinishAndAddBackupFolder => {
                self.prefs.wizard_completed = true;
                self.prefs_dirty = true;
                self.active_page = NavPage::Backups;
                self.backup_job_modal.open_for_new();
            }
            WizardOutcome::FinishAndOpenComputerDrive => {
                self.prefs.wizard_completed = true;
                self.prefs_dirty = true;
                self.active_page = NavPage::ComputerDrive;
            }
        }
    }

    fn flush_prefs_if_dirty(&mut self) {
        if self.prefs_dirty {
            self.prefs_dirty = false;
            if self.persist_prefs_to_disk {
                let _ = self.prefs.save();
            }
        }
    }

    fn poll_async_dialogs(&mut self) {
        while let Some(outcome) = self.dialogs.try_recv() {
            match outcome {
                DialogOutcome::Cancelled => {}
                DialogOutcome::FilesPicked {
                    purpose: DialogPurpose::ImportFiles { target_vdir },
                    paths,
                } => {
                    self.worker.send(UiCommand::ImportLocalPaths {
                        local_paths: paths,
                        target_dir: target_vdir,
                    });
                }
                DialogOutcome::FolderPicked { purpose, path } => match purpose {
                    DialogPurpose::ImportFolder { target_vdir } => {
                        self.worker.send(UiCommand::ImportLocalPaths {
                            local_paths: vec![path],
                            target_dir: target_vdir,
                        });
                    }
                    DialogPurpose::WizardLocalCloudFolder => {
                        if self.wizard.conn_name.trim().is_empty()
                            && let Some(name) = path.file_name().and_then(|s| s.to_str())
                        {
                            self.wizard.conn_name = name.to_owned();
                        }
                        self.wizard.local_folder_path = path.display().to_string();
                    }
                    DialogPurpose::BackupJobSourceFolder => {
                        self.backup_job_modal.set_picked_source_folder(&path);
                    }
                    DialogPurpose::RestoreDestinationParent { job_id, .. } => {
                        if self.restore_modal.open && self.restore_modal.job_id == job_id {
                            self.restore_modal.destination_parent = path.display().to_string();
                        }
                    }
                    DialogPurpose::MountPointFolder => {
                        self.mount_point_input = path.display().to_string();
                    }
                    _ => {}
                },
                DialogOutcome::SaveFilePicked {
                    purpose: DialogPurpose::ExportFileSaveCopy { virtual_path, .. },
                    path,
                } => {
                    self.worker.send(UiCommand::ExportVaultFile {
                        virtual_path,
                        local_dest_path: path.display().to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    fn sync_frame_snapshot(&mut self, ctx: &egui::Context) -> FrameSnapshot {
        let mut guard = self.worker.state.lock();

        // Auto-dismiss transient info banners after 6 seconds so they never clutter the workspace
        if let Some(set_at) = guard.toast_info_set_at {
            if set_at.elapsed() >= Duration::from_secs(6) {
                guard.toast_info = None;
                guard.toast_info_set_at = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
        }

        // Consume one-shot loaded note event so reopening the same note always reloads cleanly
        if let Some((vpath, content)) = guard.loaded_note.take() {
            self.files_state.note_modal.open = true;
            self.files_state.note_modal.virtual_path = vpath;
            *self.files_state.note_modal.content = (*content).clone();
            self.files_state.note_modal.dirty = false;
            self.files_state.note_modal.loading = false;
        }

        // Consume one-shot connected remote event so reconnecting a same-named cloud always fires
        let last_connected_remote = guard.last_connected_remote.take();

        if let Some(ref st) = guard.status {
            self.clouds_state
                .sync_from_status(&st.remotes, st.routing_policy.as_ref());
            if let Some(ref mp) = st.mount_point
                && !mp.is_empty()
                && self.last_daemon_mount_point.as_deref() != Some(mp.as_str())
            {
                self.mount_point_input = mp.clone();
                self.last_daemon_mount_point = Some(mp.clone());
            }
        }

        FrameSnapshot {
            ipc_endpoint: guard.ipc_endpoint.clone(),
            daemon_connected: guard.daemon_connected,
            busy_task: guard.busy_task.clone(),
            oauth_in_progress: guard.oauth_in_progress.clone(),
            toast_info: guard.toast_info.clone(),
            toast_error: guard.toast_error.clone(),
            status: guard.status.clone(),
            current_dir: guard.current_dir.clone(),
            entries: guard.entries.clone(),
            detected_clouds: guard.detected_clouds.clone(),
            remote_tests: guard.remote_tests.clone(),
            testing_remotes: guard.testing_remotes.clone(),
            backup_request_inflight: guard.backup_request_inflight,
            unlock_inflight: guard.unlock_inflight,
            last_backup_report: guard.last_backup_report.clone(),
            last_restored_folder: guard.last_restored_folder.clone(),
            last_connected_remote,
            recipient_bundle: guard.recipient_bundle.clone(),
            latest_share_uri: guard.latest_share_uri.clone(),
            keybox_info: guard.keybox_info.clone(),
            conflicts: guard.conflicts.clone(),
            crypto_bench: guard.crypto_bench.clone(),
            active_preview_files: guard.active_preview_files,
            up_history: guard.up_mib_history.iter().copied().collect(),
            down_history: guard.down_mib_history.iter().copied().collect(),
            peak_up_mib_s: guard.peak_up_mib_s,
            peak_down_mib_s: guard.peak_down_mib_s,
        }
    }

    fn render_sidebar(&mut self, ctx: &egui::Context, pal: &Palette, snap: &FrameSnapshot) {
        let st = snap.status.as_ref();
        let jobs_badge = st
            .map(|s| s.backup_jobs.len())
            .filter(|&n| n > 0)
            .map(|n| n.to_string());
        let dirty_badge = st
            .map(|s| s.throughput.pending_dirty_ops)
            .filter(|&n| n > 0)
            .map(|n| n.to_string());
        let remotes_badge = st
            .map(|s| s.remotes.len())
            .filter(|&n| n > 0)
            .map(|n| n.to_string());
        let mount_badge = st
            .filter(|s| s.mounted)
            .map(|_| "On".to_owned());
        let conflict_badge = st
            .map(|s| s.conflict_count)
            .filter(|&n| n > 0)
            .map(|n| n.to_string());

        egui::SidePanel::left("ec_left_sidebar")
            .exact_width(248.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(pal.sidebar_bg)
                    .inner_margin(Margin::symmetric(20.0, 24.0)),
            )
            .show(ctx, |ui| {
                // Brand Mark + Wordmark
                ui.horizontal(|ui| {
                    let (mark_r, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                    paint_brand_mark(ui.painter(), mark_r);
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("EntroCloud")
                            .font(semibold_font(ctx, 21.5))
                            .color(pal.sidebar_text),
                    );
                });
                ui.add_space(4.0);
                ui.label(
                    RichText::new("YOUR FILES. YOUR CLOUD.")
                        .font(semibold_font(ctx, 10.0))
                        .color(pal.sidebar_muted),
                );
                ui.add_space(22.0);

                // 6 Navigation Items
                let nav_items = [
                    (NavPage::Backups, Icon::HomeBackups, "Backups", jobs_badge.as_deref()),
                    (NavPage::MyFiles, Icon::Folder, "My Files", dirty_badge.as_deref()),
                    (
                        NavPage::CloudConnections,
                        Icon::Cloud,
                        "Cloud Connections",
                        remotes_badge.as_deref(),
                    ),
                    (
                        NavPage::ComputerDrive,
                        Icon::HardDrive,
                        "Computer Drive",
                        mount_badge.as_deref(),
                    ),
                    (NavPage::Sharing, Icon::ShareLink, "Sharing", None),
                    (
                        NavPage::Settings,
                        Icon::Settings,
                        "Settings",
                        conflict_badge.as_deref(),
                    ),
                ];

                ui.spacing_mut().item_spacing.y = 4.0;
                for (page, icon, label, badge) in nav_items {
                    let is_active = self.active_page == page;
                    if sidebar_nav_item(ui, pal, icon, label, badge, is_active).clicked() {
                        self.active_page = page;
                        if page == NavPage::MyFiles {
                            self.worker.send(UiCommand::ListDirectory {
                                virtual_path: snap.current_dir.clone(),
                            });
                        } else if page == NavPage::Settings {
                            self.worker.send(UiCommand::RefreshConflicts);
                        }
                    }
                }

                // Bottom-anchored Storage Summary + Quick Connect + Theme Toggle
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.spacing_mut().item_spacing.y = 10.0;

                    ui.horizontal(|ui| {
                        let (dot_r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter()
                            .circle_filled(dot_r.center(), 3.0, pal.sidebar_accent);
                        ui.label(
                            RichText::new("Active in system tray")
                                .font(FontId::proportional(11.4))
                                .color(pal.sidebar_muted),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let theme_ic = if pal.is_dark { Icon::Sun } else { Icon::Moon };
                            let tip = if pal.is_dark {
                                "Switch to Light theme"
                            } else {
                                "Switch to Dark theme"
                            };
                            let (btn_r, resp) =
                                ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
                            let resp = resp.on_hover_text(tip);
                            if resp.hovered() {
                                ctx.set_cursor_icon(CursorIcon::PointingHand);
                            }
                            if ui.is_rect_visible(btn_r) {
                                ui.painter().rect_filled(
                                    btn_r,
                                    Rounding::same(6.0),
                                    if resp.hovered() {
                                        pal.sidebar_active_bg
                                    } else {
                                        Color32::TRANSPARENT
                                    },
                                );
                                paint_icon(
                                    ui.painter(),
                                    btn_r.shrink(5.5),
                                    theme_ic,
                                    pal.sidebar_muted,
                                );
                            }
                            if resp.clicked() {
                                self.prefs.theme = if pal.is_dark {
                                    ThemePreference::Light
                                } else {
                                    ThemePreference::Dark
                                };
                                self.prefs_dirty = true;
                            }
                        });
                    });

                    if sidebar_action_button(ui, pal, Icon::Plus, "Connect a cloud")
                        .clicked()
                    {
                        self.wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                    }

                    // Pooled Storage Mini-Card (exact 76px bottom-anchored card painted top-down)
                    let card_w = ui.available_width().max(160.0);
                    let (card_r, card_resp) =
                        ui.allocate_exact_size(Vec2::new(card_w, 76.0), Sense::click());
                    let card_resp =
                        card_resp.on_hover_text("View connected clouds and storage usage");
                    if card_resp.hovered() {
                        ctx.set_cursor_icon(CursorIcon::PointingHand);
                    }
                    if card_resp.clicked() {
                        self.active_page = NavPage::CloudConnections;
                    }
                    if ui.is_rect_visible(card_r) {
                        let bg = if card_resp.hovered() {
                            pal.sidebar_active_bg.gamma_multiply(1.18)
                        } else {
                            pal.sidebar_active_bg
                        };
                        let border_col = if card_resp.hovered() {
                            pal.sidebar_accent.gamma_multiply(0.65)
                        } else {
                            pal.sidebar_border
                        };
                        ui.painter()
                            .rect_filled(card_r, Rounding::same(10.0), bg);
                        ui.painter().rect_stroke(
                            card_r,
                            Rounding::same(10.0),
                            Stroke::new(1.0, border_col),
                        );

                        let pooled = st.and_then(|s| s.pooled_quota.as_ref());
                        let (pct, detail) = if let Some(q) = pooled
                            && q.total_bytes > 0
                        {
                            let f = (q.used_bytes as f32 / q.total_bytes as f32).clamp(0.0, 1.0);
                            (
                                f,
                                format!(
                                    "{} of {} used",
                                    format_bytes_human(q.used_bytes),
                                    format_bytes_human(q.total_bytes)
                                ),
                            )
                        } else {
                            (0.0, "No cloud connected yet".to_owned())
                        };

                        ui.painter().text(
                            Pos2::new(card_r.left() + 13.0, card_r.top() + 17.0),
                            Align2::LEFT_CENTER,
                            "Backup Storage",
                            semibold_font(ctx, 12.0),
                            pal.sidebar_text,
                        );
                        ui.painter().text(
                            Pos2::new(card_r.right() - 13.0, card_r.top() + 17.0),
                            Align2::RIGHT_CENTER,
                            format!("{:.0}%", pct * 100.0),
                            FontId::monospace(11.5),
                            pal.sidebar_accent,
                        );

                        let bar_r = Rect::from_min_max(
                            Pos2::new(card_r.left() + 13.0, card_r.top() + 34.0),
                            Pos2::new(card_r.right() - 13.0, card_r.top() + 39.5),
                        );
                        ui.painter().rect_filled(
                            bar_r,
                            Rounding::same(2.8),
                            Color32::from_rgba_unmultiplied(255, 255, 255, 34),
                        );
                        if pct > 0.005 {
                            let fw = (bar_r.width() * pct).max(5.5);
                            let fill_r = Rect::from_min_max(
                                bar_r.min,
                                Pos2::new(bar_r.left() + fw, bar_r.bottom()),
                            );
                            ui.painter()
                                .rect_filled(fill_r, Rounding::same(2.8), pal.sidebar_accent);
                        }

                        ui.painter().text(
                            Pos2::new(card_r.left() + 13.0, card_r.top() + 56.0),
                            Align2::LEFT_CENTER,
                            detail,
                            FontId::proportional(11.3),
                            pal.sidebar_muted,
                        );
                    }
                });
            });
    }

    fn render_top_header(&mut self, ctx: &egui::Context, pal: &Palette, snap: &FrameSnapshot) {
        let split_tour = self
            .tour_driver
            .as_ref()
            .is_some_and(ScreenshotTourDriver::is_split_sharing_and_settings);
        let page_title = if split_tour {
            "Sharing & Settings"
        } else {
            self.active_page.title()
        };

        let st = snap.status.as_ref();
        let (pill_label, pill_tone, pill_icon) = if !snap.daemon_connected {
            ("Service Offline", PillTone::Danger, Some(Icon::Alert))
        } else if st.is_some_and(|s| s.backups_paused) {
            ("Backups Paused", PillTone::Warn, Some(Icon::Pause))
        } else if st.is_some_and(|s| s.throughput.pending_dirty_ops > 0)
            || snap.busy_task.is_some()
        {
            ("Syncing Changes...", PillTone::Accent, Some(Icon::Refresh))
        } else if st.is_some_and(|s| s.remotes.is_empty()) {
            ("Local Vault Ready", PillTone::Neutral, Some(Icon::Check))
        } else {
            ("Protected & Up to Date", PillTone::Ok, Some(Icon::Check))
        };

        egui::TopBottomPanel::top("ec_top_header")
            .exact_height(60.0)
            .frame(
                egui::Frame::none()
                    .fill(pal.topbar_bg)
                    .inner_margin(Margin::symmetric(28.0, 12.0)),
            )
            .show(ctx, |ui| {
                let clip = ui.clip_rect();
                ui.painter().line_segment(
                    [
                        Pos2::new(clip.left(), clip.bottom() - 0.5),
                        Pos2::new(clip.right(), clip.bottom() - 0.5),
                    ],
                    Stroke::new(1.0, pal.card_border),
                );
                ui.horizontal_centered(|ui| {
                    ui.label(
                        RichText::new(page_title)
                            .font(semibold_font(ctx, 20.5))
                            .color(pal.ink),
                    );
                    ui.add_space(8.0);
                    status_pill(ui, pal, pill_icon, pill_label, pill_tone);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if secondary_button(ui, pal, Some(Icon::Lock), "Lock").clicked() {
                            self.worker.send(UiCommand::LockVault);
                        }
                        if secondary_button(ui, pal, Some(Icon::Refresh), "Sync Now").clicked() {
                            self.worker.send(UiCommand::SyncNow);
                        }
                    });
                });
            });
    }

    fn render_toast_strip(&mut self, ctx: &egui::Context, pal: &Palette, snap: &FrameSnapshot) {
        if snap.toast_error.is_none() && snap.busy_task.is_none() && snap.toast_info.is_none() {
            return;
        }
        let max_w = (ctx.screen_rect().width() - 48.0).clamp(280.0, 560.0);
        let shadow = egui::epaint::Shadow {
            offset: Vec2::new(0.0, 4.0),
            blur: 14.0,
            spread: 0.0,
            color: Color32::from_black_alpha(if pal.is_dark { 96 } else { 32 }),
        };

        egui::Area::new(egui::Id::new("ec_floating_toast"))
            .order(egui::Order::Foreground)
            .anchor(Align2::CENTER_BOTTOM, Vec2::new(0.0, -18.0))
            .interactable(true)
            .show(ctx, |ui| {
                ui.set_max_width(max_w);
                if let Some(ref err) = snap.toast_error {
                    let mut dismiss = false;
                    egui::Frame::none()
                        .fill(pal.danger_bg)
                        .stroke(Stroke::new(1.0, pal.danger_border))
                        .rounding(Rounding::same(10.0))
                        .shadow(shadow)
                        .inner_margin(Margin::symmetric(14.0, 9.0))
                        .show(ui, |ui| {
                            input_row_with_right_widget(
                                ui,
                                |ui| {
                                    if icon_button(ui, pal, Icon::Close, "Dismiss").clicked() {
                                        dismiss = true;
                                    }
                                },
                                |ui, rem_w| {
                                    ui.set_max_width(rem_w);
                                    let (ic_r, _) =
                                        ui.allocate_exact_size(Vec2::splat(17.0), Sense::hover());
                                    paint_icon(ui.painter(), ic_r, Icon::Alert, pal.danger_fg);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(err).color(pal.danger_fg).size(12.8),
                                        )
                                        .wrap(),
                                    )
                                    .on_hover_text(err);
                                },
                            );
                        });
                    if dismiss {
                        self.worker.state.lock().toast_error = None;
                    }
                } else if let Some(ref busy) = snap.busy_task {
                    egui::Frame::none()
                        .fill(pal.accent_soft_bg)
                        .stroke(Stroke::new(1.0, pal.primary_btn.gamma_multiply(0.35)))
                        .rounding(Rounding::same(10.0))
                        .shadow(shadow)
                        .inner_margin(Margin::symmetric(14.0, 9.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let (ic_r, _) =
                                    ui.allocate_exact_size(Vec2::splat(17.0), Sense::hover());
                                paint_icon(ui.painter(), ic_r, Icon::Refresh, pal.accent_soft_fg);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(busy).color(pal.ink).size(12.8),
                                    )
                                    .wrap(),
                                )
                                .on_hover_text(busy);
                            });
                        });
                } else if let Some(ref info) = snap.toast_info {
                    let mut ok_clicked = false;
                    egui::Frame::none()
                        .fill(pal.ok_bg)
                        .stroke(Stroke::new(1.0, pal.ok_fg.gamma_multiply(0.30)))
                        .rounding(Rounding::same(10.0))
                        .shadow(shadow)
                        .inner_margin(Margin::symmetric(14.0, 8.0))
                        .show(ui, |ui| {
                            input_row_with_right_widget(
                                ui,
                                |ui| {
                                    if icon_button(ui, pal, Icon::Close, "Dismiss").clicked() {
                                        ok_clicked = true;
                                    }
                                },
                                |ui, rem_w| {
                                    ui.set_max_width(rem_w);
                                    let (ic_r, _) =
                                        ui.allocate_exact_size(Vec2::splat(17.0), Sense::hover());
                                    paint_icon(ui.painter(), ic_r, Icon::Check, pal.ok_fg);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(info).color(pal.ink).size(12.6),
                                        )
                                        .wrap(),
                                    )
                                    .on_hover_text(info);
                                },
                            );
                        });
                    if ok_clicked {
                        let mut g = self.worker.state.lock();
                        g.toast_info = None;
                        g.toast_info_set_at = None;
                    }
                }
            });
    }

    fn render_global_modals(&mut self, ctx: &egui::Context, pal: &Palette, snap: &FrameSnapshot) {
        // `--open-uri` (`ec://` or `zv://`) Private Share Link Modal
        if self.share_import_modal.open {
            let mut close_req = false;
            modal_dialog(
                ctx,
                pal,
                "ec_share_import_modal",
                "Save Shared Encrypted File",
                520.0,
                &mut close_req,
                |ui| {
                    form_label(ui, pal, "Private Share Link (ec:// or zv://)");
                    ui.add(
                        egui::TextEdit::multiline(&mut *self.share_import_modal.uri)
                            .margin(Margin::symmetric(10.0, 8.0))
                            .desired_rows(3)
                            .desired_width(f32::INFINITY)
                            .font(FontId::monospace(11.5)),
                    );

                    let trimmed = self.share_import_modal.uri.trim();
                    let uri_valid = if !trimmed.is_empty() {
                        ui.add_space(4.0);
                        match CapabilityUri::parse(trimmed) {
                            Ok(parsed) => {
                                status_pill(
                                    ui,
                                    pal,
                                    Some(Icon::Check),
                                    &format!("Verified link format ({})", parsed.backend_hint),
                                    PillTone::Ok,
                                );
                                true
                            }
                            Err(err) => {
                                ui.label(
                                    RichText::new(format!("Invalid share link: {err}"))
                                        .color(pal.danger_fg)
                                        .size(12.0),
                                );
                                false
                            }
                        }
                    } else {
                        false
                    };

                    ui.add_space(8.0);
                    form_label(ui, pal, "Save into vault path");
                    ui.add(text_input_single(
                        &mut self.share_import_modal.dest_virtual_path,
                        "/Shared/received_file",
                    ));

                    let can_save =
                        uri_valid && !self.share_import_modal.dest_virtual_path.trim().is_empty();

                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if secondary_button(ui, pal, None, "Cancel").clicked() {
                            self.share_import_modal.uri.zeroize();
                            self.share_import_modal.open = false;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let clicked = ui
                                .add_enabled_ui(can_save, |ui| {
                                    primary_button(
                                        ui,
                                        pal,
                                        Some(Icon::Download),
                                        "Verify & Save to Vault",
                                    )
                                })
                                .inner
                                .clicked();
                            if can_save && clicked {
                                let uri_copy =
                                    Zeroizing::new(self.share_import_modal.uri.trim().to_owned());
                                let dest =
                                    self.share_import_modal.dest_virtual_path.trim().to_owned();
                                self.share_import_modal.uri.zeroize();
                                self.share_import_modal.open = false;
                                self.worker.send(UiCommand::ImportCapabilityShare {
                                    uri: uri_copy,
                                    dest_virtual_path: dest,
                                    refresh_dir: snap.current_dir.clone(),
                                });
                            }
                        });
                    });
                },
            );
            if close_req {
                self.share_import_modal.uri.zeroize();
                self.share_import_modal.open = false;
            }
        }
    }

    fn step_screenshot_tour(&mut self, ctx: &egui::Context) {
        if self.tour_driver.is_none() {
            return;
        }

        // 1. Check whether `eframe` delivered a captured `Event::Screenshot` at the start of this frame!
        let captured_img = ctx.input(|i| {
            i.events.iter().find_map(|ev| match ev {
                egui::Event::Screenshot { image, .. } => Some(Arc::clone(image)),
                _ => None,
            })
        });

        let mut advance_to: Option<(usize, bool)> = None;
        let mut close_now = false;

        if let Some(ref mut drv) = self.tour_driver
            && let Some(img) = captured_img
            && drv.screenshot_requested
        {
            let steps = if drv.modal_mode {
                &MODAL_TOUR_STEPS[..]
            } else {
                &TOUR_STEPS[..]
            };
            if let Some(&(_, filename, _)) = steps.get(drv.step_idx) {
                let out_path = drv.output_dir.join(filename);
                match write_color_image_png(&img, &out_path) {
                    Ok(()) => {
                        drv.written_files.push(out_path);
                        drv.step_idx += 1;
                        drv.settle_frames = 0;
                        drv.screenshot_requested = false;
                        drv.wait_frames = 0;
                        if drv.step_idx >= steps.len() {
                            if let Some(ref slot) = self.tour_result {
                                *slot.lock() = Ok(drv.written_files.len());
                            }
                            close_now = true;
                        } else {
                            advance_to = Some((drv.step_idx, drv.modal_mode));
                        }
                    }
                    Err(err) => {
                        drv.error = Some(err.clone());
                        if let Some(ref slot) = self.tour_result {
                            *slot.lock() = Err(err);
                        }
                        close_now = true;
                    }
                }
            }
        }

        if let Some((next_idx, is_modal)) = advance_to {
            if is_modal {
                self.apply_modal_tour_step(next_idx);
            } else {
                let mut guard = self.worker.state.lock();
                configure_tour_step_ui(
                    next_idx,
                    &mut guard,
                    &mut self.prefs,
                    &mut self.active_page,
                    &mut self.wizard,
                );
            }
        }

        if close_now {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Render the current step cleanly!
        self.render_headless_frame(ctx);

        if let Some(ref mut drv) = self.tour_driver {
            if !drv.screenshot_requested {
                drv.settle_frames = drv.settle_frames.saturating_add(1);
                // Allow 4 settle frames so modal sizing passes + column/scroll layouts stabilize cleanly.
                if drv.settle_frames >= 4 {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
                    drv.screenshot_requested = true;
                    drv.wait_frames = 0;
                }
            } else {
                drv.wait_frames = drv.wait_frames.saturating_add(1);
                if drv.wait_frames > 120 {
                    let msg = format!(
                        "Screenshot capture timed out at step {}",
                        drv.step_idx
                    );
                    if let Some(ref slot) = self.tour_result {
                        *slot.lock() = Err(msg);
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
            }
            ctx.request_repaint();
        }
    }

    fn finalize_on_window_exit(&mut self) {
        if self.exit_handled {
            return;
        }
        self.exit_handled = true;

        if let Some(cfg) = self.cold_bench {
            let exit_ticks = now_ticks();
            let mem = sample_current_process_memory();
            let webview_mods = detect_loaded_webview_modules();
            let webview_count = webview_mods.len();
            let (ep, connected) = {
                let g = self.worker.state.lock();
                (g.ipc_endpoint.clone(), g.daemon_connected)
            };
            let cold_ms = elapsed_ms(cfg.main_entry_ticks, exit_ticks);
            let report = ColdBenchReport {
                mode: "bench-cold".to_owned(),
                renderer: "glow".to_owned(),
                backend: "glow".to_owned(),
                gpu_adapter: self.gpu_adapter.clone(),
                ipc_endpoint: ep,
                ipc_connected: connected,
                ipc_roundtrip_ms: cfg.ipc_probe_ms,
                cold_open_latency_ms: cold_ms,
                internal_cold_start_ms: cold_ms,
                external_cold_start_ms: cfg.spawn_qpc.map(|sq| elapsed_ms(sq, exit_ticks)),
                frame1_update_cpu_ms: round3(self.frame1_update_cpu_ms),
                working_set_64: mem.working_set_bytes,
                working_set_bytes: mem.working_set_bytes,
                working_set_mib: mem.working_set_mib,
                peak_working_set_bytes: mem.peak_working_set_bytes,
                peak_working_set_mib: mem.peak_working_set_mib,
                private_usage_bytes: mem.private_usage_bytes,
                private_usage_mib: mem.private_usage_mib,
                webview2_modules: webview_count,
                webview2_detected: webview_count > 0,
                loaded_webview_modules: webview_mods,
                memory: mem,
            };
            *self.bench_output.lock() = Some(report);
        }

        // Zeroize all sensitive UI buffers and scrub temporary preview files on disk!
        self.passphrase_input.zeroize();
        self.confirm_passphrase_input.zeroize();
        self.wizard.zeroize_secrets();
        self.files_state.zeroize_secrets();
        self.sharing_state.zeroize_secrets();
        self.share_import_modal.uri.zeroize();
        self.worker.shutdown_and_scrub();
    }
}

impl eframe::App for EntroCloudApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let update_start = now_ticks();
        self.total_gpu_frames = self.total_gpu_frames.saturating_add(1);

        if self.tour_driver.is_some() {
            self.step_screenshot_tour(ctx);
        } else {
            self.render_headless_frame(ctx);
        }

        let update_end = now_ticks();
        if self.total_gpu_frames == 1 {
            self.frame1_update_cpu_ms = elapsed_ms(update_start, update_end);
        }

        if self.cold_bench.is_some() && self.total_gpu_frames >= 1 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.finalize_on_window_exit();
    }
}

fn detect_glow_adapter_string(cc: &eframe::CreationContext<'_>) -> String {
    if let Some(ref gl) = cc.gl {
        use eframe::glow::HasContext;
        // SAFETY: `cc.gl` is a current, initialized OpenGL context provided by `eframe`.
        let (renderer, version) = unsafe {
            (
                gl.get_parameter_string(eframe::glow::RENDERER),
                gl.get_parameter_string(eframe::glow::VERSION),
            )
        };
        return format!("{renderer} [{version}]");
    }
    "OpenGL (glow)".to_owned()
}
