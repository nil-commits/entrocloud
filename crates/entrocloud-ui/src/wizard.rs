//! 4-Step Guided First-Run Introduction & Interactive Cloud Provider API Setup Wizard.
//!
//! Combines CloudBridge's calm consumer copy and `GOOGLE-DRIVE-SETUP.md` walkthrough with
//! ZeroVault's 1-click detected cloud folders, Entra/Dropbox/S3/R2/B2/Nextcloud setup guides,
//! Master Password strength meter, and immediate secret zeroization.

use std::time::{Duration, Instant};

use eframe::egui::{
    self, Color32, FontId, Key, Margin, RichText, Rounding, Sense, Stroke, Vec2,
};
use entrocloud_types::{
    AddRemoteParams, DetectedCloudFolder, OAuthLoginParams, RemoteAccountSummary,
};
use zeroize::{Zeroize, Zeroizing};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_brand_mark, paint_icon};
use crate::session::open_https_url;
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, icon_button,
    input_row_with_right_widget, interactive_card, primary_button, progress_bar_clean,
    secondary_button, semibold_font, small_button, status_pill, step_indicator, sub_card_frame,
    text_input_single,
};
use crate::worker::{UiCommand, UiWorkerHandle};

/// Four-step onboarding wizard progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Welcome = 0,
    ConnectCloud = 1,
    MasterPassword = 2,
    Ready = 3,
}

impl WizardStep {
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Choice on Step 1 between creating a brand-new vault or recovering an existing cloud vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingFlow {
    CreateNewVault,
    RecoverExistingVault,
}

/// Supported cloud/storage providers in Step 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardProvider {
    SyncedFolder,
    GoogleDrive,
    OneDrive,
    Dropbox,
    S3,
    WebDav,
}

/// Quick presets for S3-compatible object storage providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Preset {
    CloudflareR2,
    BackblazeB2,
    AmazonS3,
    Wasabi,
    CustomMinio,
}

/// High-level navigation action requested by the wizard upon completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardOutcome {
    None,
    FinishToWorkspace,
    FinishAndAddBackupFolder,
    FinishAndOpenComputerDrive,
}

/// Mutable UI state for the 4-step Setup & Cloud Connection Wizard.
pub struct WizardState {
    pub open: bool,
    /// When `true`, opened from `+ Connect a cloud` (jumps straight to Step 2 with `Back to Workspace`).
    pub standalone_add_cloud: bool,
    pub step: WizardStep,
    pub flow: OnboardingFlow,
    pub provider: WizardProvider,
    pub s3_preset: S3Preset,

    // Common connection fields
    pub conn_name: String,
    pub cloud_folder: String,
    pub quota_gb_preset: Option<u64>,
    pub custom_quota_gb: String,

    // Synced / Local folder
    pub local_folder_path: String,

    // OAuth2 fields (Google Drive / OneDrive / Dropbox)
    pub oauth_client_id: String,
    pub oauth_client_secret: Zeroizing<String>,
    pub show_oauth_secret: bool,

    // S3 fields
    pub s3_endpoint: String,
    pub s3_region: String,
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: Zeroizing<String>,
    pub show_s3_secret: bool,

    // WebDAV fields
    pub webdav_endpoint: String,
    pub webdav_username: String,
    pub webdav_password: Zeroizing<String>,
    pub show_webdav_secret: bool,

    // Step 3 Master Password fields
    pub pass_input: Zeroizing<String>,
    pub pass_confirm: Zeroizing<String>,
    pub show_pass: bool,
    pub form_error: Option<String>,
    pub copied_hint: Option<String>,
    pub copied_hint_at: Option<Instant>,
}

impl Default for WizardState {
    fn default() -> Self {
        Self::new()
    }
}

impl WizardState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            open: false,
            standalone_add_cloud: false,
            step: WizardStep::Welcome,
            flow: OnboardingFlow::CreateNewVault,
            provider: WizardProvider::GoogleDrive,
            s3_preset: S3Preset::CloudflareR2,
            conn_name: "GoogleDrive".to_owned(),
            cloud_folder: "/EntroCloud".to_owned(),
            quota_gb_preset: None,
            custom_quota_gb: String::new(),
            local_folder_path: String::new(),
            oauth_client_id: String::new(),
            oauth_client_secret: Zeroizing::new(String::new()),
            show_oauth_secret: false,
            s3_endpoint: "https://<ACCOUNT_ID>.r2.cloudflarestorage.com".to_owned(),
            s3_region: "auto".to_owned(),
            s3_bucket: "entrocloud-backup".to_owned(),
            s3_access_key: String::new(),
            s3_secret_key: Zeroizing::new(String::new()),
            show_s3_secret: false,
            webdav_endpoint: "https://cloud.example.com/remote.php/dav/files/username/".to_owned(),
            webdav_username: String::new(),
            webdav_password: Zeroizing::new(String::new()),
            show_webdav_secret: false,
            pass_input: Zeroizing::new(String::new()),
            pass_confirm: Zeroizing::new(String::new()),
            show_pass: false,
            form_error: None,
            copied_hint: None,
            copied_hint_at: None,
        }
    }

    fn set_copied_hint(&mut self, msg: &str) {
        self.copied_hint = Some(msg.to_owned());
        self.copied_hint_at = Some(Instant::now());
    }

    /// Zeroizes all sensitive credential and passphrase fields in the wizard.
    pub fn zeroize_secrets(&mut self) {
        self.oauth_client_secret.zeroize();
        self.s3_secret_key.zeroize();
        self.webdav_password.zeroize();
        self.pass_input.zeroize();
        self.pass_confirm.zeroize();
    }

    /// Opens the full 4-step introduction & setup wizard at `step`.
    pub fn open_full(&mut self, step: WizardStep) {
        self.open = true;
        self.standalone_add_cloud = false;
        self.step = step;
        self.form_error = None;
        self.copied_hint = None;
        self.copied_hint_at = None;
    }

    /// Opens directly to Step 2 (`Connect a Cloud`) when adding another cloud from the workspace.
    pub fn open_connect_cloud(&mut self, provider: WizardProvider) {
        self.open = true;
        self.standalone_add_cloud = true;
        self.step = WizardStep::ConnectCloud;
        self.select_provider(provider);
        self.form_error = None;
        self.copied_hint = None;
        self.copied_hint_at = None;
    }

    /// Selects a cloud provider in Step 2 and populates sensible default connection names.
    pub fn select_provider(&mut self, provider: WizardProvider) {
        self.provider = provider;
        self.form_error = None;
        self.copied_hint = None;
        self.copied_hint_at = None;
        self.oauth_client_id.clear();
        self.oauth_client_secret.zeroize();
        self.quota_gb_preset = None;
        self.custom_quota_gb.clear();
        match provider {
            WizardProvider::SyncedFolder => {
                self.conn_name = "LocalBackup".to_owned();
            }
            WizardProvider::GoogleDrive => {
                self.conn_name = "GoogleDrive".to_owned();
                self.cloud_folder = "/EntroCloud".to_owned();
            }
            WizardProvider::OneDrive => {
                self.conn_name = "OneDrive".to_owned();
                self.cloud_folder = "/EntroCloud".to_owned();
            }
            WizardProvider::Dropbox => {
                self.conn_name = "Dropbox".to_owned();
                self.cloud_folder = "/EntroCloud".to_owned();
            }
            WizardProvider::S3 => {
                self.apply_s3_preset(self.s3_preset);
            }
            WizardProvider::WebDav => {
                self.conn_name = "Nextcloud".to_owned();
                self.cloud_folder = "/EntroCloud".to_owned();
            }
        }
    }

    /// Applies an S3 provider preset (`Cloudflare R2`, `Backblaze B2`, `Amazon S3`, `Wasabi`, `Custom / MinIO`).
    pub fn apply_s3_preset(&mut self, preset: S3Preset) {
        self.s3_preset = preset;
        match preset {
            S3Preset::CloudflareR2 => {
                self.conn_name = "CloudflareR2".to_owned();
                self.s3_endpoint = "https://<ACCOUNT_ID>.r2.cloudflarestorage.com".to_owned();
                self.s3_region = "auto".to_owned();
            }
            S3Preset::BackblazeB2 => {
                self.conn_name = "BackblazeB2".to_owned();
                self.s3_endpoint = "https://s3.us-west-004.backblazeb2.com".to_owned();
                self.s3_region = "us-west-004".to_owned();
            }
            S3Preset::AmazonS3 => {
                self.conn_name = "AmazonS3".to_owned();
                self.s3_endpoint = "https://s3.amazonaws.com".to_owned();
                self.s3_region = "us-east-1".to_owned();
            }
            S3Preset::Wasabi => {
                self.conn_name = "Wasabi".to_owned();
                self.s3_endpoint = "https://s3.wasabisys.com".to_owned();
                self.s3_region = "us-east-1".to_owned();
            }
            S3Preset::CustomMinio => {
                self.conn_name = "MinIO".to_owned();
                self.s3_endpoint = "http://127.0.0.1:9000".to_owned();
                self.s3_region = "us-east-1".to_owned();
            }
        }
    }

    fn resolved_quota_bytes(&self) -> Option<u64> {
        if let Ok(custom_gb) = self.custom_quota_gb.trim().parse::<u64>()
            && custom_gb > 0
        {
            return Some(custom_gb.saturating_mul(1024 * 1024 * 1024));
        }
        self.quota_gb_preset
            .map(|gb| gb.saturating_mul(1024 * 1024 * 1024))
    }

    /// Renders the active wizard view inside the main canvas.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        dialogs: &AsyncDialogs,
        vault_initialized: bool,
        vault_unlocked: bool,
        remotes: &[RemoteAccountSummary],
        detected_clouds: &[DetectedCloudFolder],
        oauth_in_progress: Option<&str>,
        last_connected_remote: Option<&str>,
    ) -> WizardOutcome {
        // Auto-clear transient "Copied ..." pill after 3 seconds
        if let Some(at) = self.copied_hint_at {
            if at.elapsed() >= Duration::from_secs(3) {
                self.copied_hint = None;
                self.copied_hint_at = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }

        // Allow Escape to close the standalone "Connect a Cloud" wizard cleanly
        if self.standalone_add_cloud && ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.zeroize_secrets();
            self.open = false;
            return WizardOutcome::FinishToWorkspace;
        }

        // Automatically react when a new remote finishes connecting (`connected_remote_event` is one-shot).
        if last_connected_remote.is_some() {
            self.oauth_client_secret.zeroize();
            self.s3_secret_key.zeroize();
            self.webdav_password.zeroize();
            if self.standalone_add_cloud {
                self.open = false;
                return WizardOutcome::FinishToWorkspace;
            }
        }

        // Auto-advance Step 3 -> Step 4 once vault becomes unlocked!
        if !self.standalone_add_cloud && self.step == WizardStep::MasterPassword && vault_unlocked
        {
            self.pass_input.zeroize();
            self.pass_confirm.zeroize();
            self.step = WizardStep::Ready;
        }

        let mut outcome = WizardOutcome::None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);
                // Top Wizard Header + Stepper
                ui.horizontal(|ui| {
                    let (mark_rect, _) =
                        ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                    paint_brand_mark(ui.painter(), mark_rect);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(
                            RichText::new(if self.standalone_add_cloud {
                                "Connect a Cloud Storage Account"
                            } else {
                                "EntroCloud Setup Guide"
                            })
                            .font(semibold_font(ctx, 19.0))
                            .color(pal.ink),
                        );
                        ui.label(
                            RichText::new("Your files stay encrypted on this PC before leaving it.")
                                .font(FontId::proportional(12.5))
                                .color(pal.muted),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.standalone_add_cloud {
                            if secondary_button(ui, pal, Some(Icon::ArrowLeft), "Back to Workspace")
                                .clicked()
                            {
                                self.zeroize_secrets();
                                self.open = false;
                                outcome = WizardOutcome::FinishToWorkspace;
                            }
                        } else if (vault_initialized || vault_unlocked)
                            && secondary_button(ui, pal, None, "Skip to Workspace").clicked()
                        {
                            self.zeroize_secrets();
                            self.open = false;
                            outcome = WizardOutcome::FinishToWorkspace;
                        }
                    });
                });

                ui.add_space(12.0);
                if !self.standalone_add_cloud {
                    card_frame(pal)
                        .inner_margin(egui::Margin::symmetric(20.0, 13.0))
                        .show(ui, |ui| {
                            step_indicator(
                                ui,
                                pal,
                                &[
                                    "Welcome",
                                    "Connect a Cloud",
                                    "Encryption Password",
                                    "Ready",
                                ],
                                self.step.index(),
                            );
                        });
                    ui.add_space(14.0);
                }

                match self.step {
                    WizardStep::Welcome => {
                        self.render_step_welcome(ctx, ui, pal, vault_initialized, &mut outcome);
                    }
                    WizardStep::ConnectCloud => {
                        self.render_step_connect_cloud(
                            ctx,
                            ui,
                            pal,
                            worker,
                            dialogs,
                            vault_unlocked,
                            remotes,
                            detected_clouds,
                            oauth_in_progress,
                        );
                    }
                    WizardStep::MasterPassword => {
                        self.render_step_password(ctx, ui, pal, worker, vault_initialized);
                    }
                    WizardStep::Ready => {
                        self.render_step_ready(ctx, ui, pal, remotes, &mut outcome);
                    }
                }
                ui.add_space(20.0);
            });

        outcome
    }

    fn render_step_welcome(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        vault_initialized: bool,
        outcome: &mut WizardOutcome,
    ) {
        card_frame(pal).show(ui, |ui| {
            ui.label(
                RichText::new("Welcome to EntroCloud")
                    .font(semibold_font(ctx, 26.0))
                    .color(pal.ink),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Keep the files and folders you care about encrypted across your clouds.",
                )
                .font(FontId::proportional(15.0))
                .color(pal.muted),
            );

            ui.add_space(18.0);
            ui.columns(3, |cols| {
                welcome_pillar_card(
                    &mut cols[0],
                    pal,
                    Icon::Cloud,
                    "1. Connect your clouds",
                    "Link Google Drive, Microsoft OneDrive, Dropbox, S3 / Cloudflare R2 / Backblaze B2, NAS, or a local drive.",
                );
                welcome_pillar_card(
                    &mut cols[1],
                    pal,
                    Icon::Lock,
                    "2. Lock on your PC first",
                    "File contents and filenames are encrypted on this computer with your Master Password before upload.",
                );
                let drive_desc = if cfg!(target_os = "windows") {
                    "Schedule automatic PC folder backups in the background or mount your vault inside File Explorer."
                } else {
                    "Schedule automatic folder backups in the background or mount your vault inside your File Manager."
                };
                welcome_pillar_card(
                    &mut cols[2],
                    pal,
                    Icon::HomeBackups,
                    "3. Automatic backup & drive",
                    drive_desc,
                );
            });

            ui.add_space(20.0);
            form_label(ui, pal, "How would you like to get started?");
            ui.add_space(6.0);

            ui.columns(2, |cols| {
                if onboarding_choice_card(
                    &mut cols[0],
                    pal,
                    Icon::Sparkles,
                    "Set Up New Cloud Vault",
                    "Create a fresh encrypted vault and choose where to store your backups.",
                    self.flow == OnboardingFlow::CreateNewVault,
                )
                .clicked()
                {
                    self.flow = OnboardingFlow::CreateNewVault;
                }
                if onboarding_choice_card(
                    &mut cols[1],
                    pal,
                    Icon::Refresh,
                    "Recover Existing Cloud Vault on This PC",
                    "Connect the cloud or folder holding your existing vault, then unlock it with your Master Password.",
                    self.flow == OnboardingFlow::RecoverExistingVault,
                )
                .clicked()
                {
                    self.flow = OnboardingFlow::RecoverExistingVault;
                }
            });

            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if primary_button(
                    ui,
                    pal,
                    Some(Icon::ChevronRight),
                    "Continue to Cloud Setup",
                )
                .clicked()
                {
                    self.step = WizardStep::ConnectCloud;
                }

                if vault_initialized
                    && secondary_button(ui, pal, Some(Icon::Unlock), "Unlock Existing Local Vault")
                        .clicked()
                {
                    self.zeroize_secrets();
                    self.open = false;
                    *outcome = WizardOutcome::FinishToWorkspace;
                }
            });
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn render_step_connect_cloud(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        dialogs: &AsyncDialogs,
        vault_unlocked: bool,
        remotes: &[RemoteAccountSummary],
        detected_clouds: &[DetectedCloudFolder],
        oauth_in_progress: Option<&str>,
    ) {
        // Active OAuth waiting banner with working Cancel Sign-In button!
        if let Some(wait_msg) = oauth_in_progress {
            egui::Frame::none()
                .fill(pal.accent_soft_bg)
                .stroke(Stroke::new(1.2, pal.primary_btn))
                .rounding(Rounding::same(11.0))
                .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                        paint_icon(ui.painter(), ic_r, Icon::Refresh, pal.accent_soft_fg);
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(wait_msg)
                                    .font(semibold_font(ctx, 14.5))
                                    .color(pal.ink),
                            );
                            ui.label(
                                RichText::new(
                                    "Complete sign-in in the browser window that opened. EntroCloud will finish connecting automatically.",
                                )
                                .font(FontId::proportional(12.5))
                                .color(pal.muted),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if danger_button(ui, pal, Some(Icon::Stop), "Cancel Sign-In").clicked()
                            {
                                worker.send(UiCommand::CancelOAuth);
                            }
                        });
                    });
                });
            ui.add_space(12.0);
        }

        // Connected cloud confirmation strip if at least 1 cloud is already connected
        if !remotes.is_empty() && !self.standalone_add_cloud {
            egui::Frame::none()
                .fill(pal.ok_bg)
                .stroke(Stroke::new(1.0, pal.ok_fg.gamma_multiply(0.35)))
                .rounding(Rounding::same(10.0))
                .inner_margin(egui::Margin::symmetric(16.0, 11.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let names: Vec<&str> = remotes.iter().map(|r| r.id.as_str()).collect();
                        let noun = if remotes.len() == 1 {
                            "cloud location"
                        } else {
                            "cloud locations"
                        };
                        status_pill(ui, pal, Some(Icon::Check), "Connected", PillTone::Ok);
                        ui.label(
                            RichText::new(format!(
                                "{} {noun} ready: {}",
                                remotes.len(),
                                names.join(", ")
                            ))
                            .font(semibold_font(ctx, 13.0))
                            .color(pal.ink),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let next_lbl = if vault_unlocked {
                                "Continue"
                            } else {
                                "Continue to Encryption Password"
                            };
                            if primary_button(ui, pal, Some(Icon::ChevronRight), next_lbl).clicked()
                            {
                                self.step = if vault_unlocked {
                                    WizardStep::Ready
                                } else {
                                    WizardStep::MasterPassword
                                };
                            }
                        });
                    });
                });
            ui.add_space(12.0);
        }

        // Provider Selector Grid (6 cards)
        card_frame(pal)
            .inner_margin(egui::Margin::symmetric(20.0, 16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Choose where to store your encrypted files")
                            .font(semibold_font(ctx, 17.5))
                            .color(pal.ink),
                    );
                    if let Some(ref copied) = self.copied_hint {
                        ui.add_space(8.0);
                        status_pill(ui, pal, Some(Icon::Check), copied, PillTone::Ok);
                    }
                });
                ui.add_space(8.0);

                let providers = [
                    (
                        WizardProvider::SyncedFolder,
                        Icon::FolderOpen,
                        "Synced PC / USB Folder",
                        "1-Click setup",
                    ),
                    (
                        WizardProvider::GoogleDrive,
                        Icon::Cloud,
                        "Google Drive",
                        "Desktop OAuth2",
                    ),
                    (
                        WizardProvider::OneDrive,
                        Icon::Cloud,
                        "Microsoft OneDrive",
                        "Entra PKCE",
                    ),
                    (
                        WizardProvider::Dropbox,
                        Icon::CloudPlus,
                        "Dropbox",
                        "Scoped App Folder",
                    ),
                    (
                        WizardProvider::S3,
                        Icon::HardDrive,
                        "S3 / Cloudflare R2 / B2",
                        "Object Storage",
                    ),
                    (
                        WizardProvider::WebDav,
                        Icon::Users,
                        "WebDAV / Nextcloud / NAS",
                        "App Password",
                    ),
                ];

                ui.columns(3, |cols| {
                    for (i, (p, icon, title, sub)) in providers.iter().enumerate() {
                        let col = &mut cols[i % 3];
                        if i >= 3 {
                            col.add_space(6.0);
                        }
                        if provider_tile(col, pal, *icon, title, sub, self.provider == *p).clicked()
                        {
                            self.select_provider(*p);
                            if *p == WizardProvider::SyncedFolder && detected_clouds.is_empty() {
                                worker.send(UiCommand::DetectLocalClouds);
                            }
                        }
                    }
                });
            });

        ui.add_space(12.0);

        if let Some(ref err) = self.form_error {
            egui::Frame::none()
                .fill(pal.danger_bg)
                .stroke(Stroke::new(1.0, pal.danger_border))
                .rounding(Rounding::same(9.0))
                .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                .show(ui, |ui| {
                    ui.label(RichText::new(err).color(pal.danger_fg));
                });
            ui.add_space(10.0);
        }

        // Provider-specific interactive guide + connection form
        ui.spacing_mut().item_spacing.x = 16.0;
        match self.provider {
            WizardProvider::SyncedFolder => {
                self.render_provider_synced_folder(ctx, ui, pal, worker, dialogs, detected_clouds);
            }
            WizardProvider::GoogleDrive => {
                self.render_provider_gdrive(ctx, ui, pal, worker, oauth_in_progress.is_some());
            }
            WizardProvider::OneDrive => {
                self.render_provider_onedrive(ctx, ui, pal, worker, oauth_in_progress.is_some());
            }
            WizardProvider::Dropbox => {
                self.render_provider_dropbox(ctx, ui, pal, worker, oauth_in_progress.is_some());
            }
            WizardProvider::S3 => {
                self.render_provider_s3(ctx, ui, pal, worker);
            }
            WizardProvider::WebDav => {
                self.render_provider_webdav(ctx, ui, pal, worker);
            }
        }

        // Bottom wizard navigation bar
        if !self.standalone_add_cloud {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if secondary_button(ui, pal, Some(Icon::ArrowLeft), "Back").clicked() {
                    self.step = WizardStep::Welcome;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let skip_label = if remotes.is_empty() {
                        "Set Up Cloud Later → Password"
                    } else if vault_unlocked {
                        "Continue"
                    } else {
                        "Continue to Encryption Password"
                    };
                    if secondary_button(ui, pal, Some(Icon::ChevronRight), skip_label).clicked() {
                        self.step = if vault_unlocked {
                            WizardStep::Ready
                        } else {
                            WizardStep::MasterPassword
                        };
                    }
                });
            });
        }
    }

    fn render_provider_synced_folder(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        dialogs: &AsyncDialogs,
        detected_clouds: &[DetectedCloudFolder],
    ) {
        ui.columns(2, |cols| {
            // Left: 1-Click Detected Cloud Sync Folders
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("1-Click Synced Folders on This PC")
                            .font(semibold_font(ctx, 16.0))
                            .color(pal.ink),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if small_button(ui, pal, Some(Icon::Refresh), "Scan", false).clicked() {
                            worker.send(UiCommand::DetectLocalClouds);
                        }
                    });
                });
                ui.label(
                    RichText::new(
                        "If OneDrive, Google Drive Desktop, Dropbox, or iCloud Drive is installed, click once to store encrypted vault files inside it.",
                    )
                    .font(FontId::proportional(12.5))
                    .color(pal.muted),
                );
                ui.add_space(10.0);

                if detected_clouds.is_empty() {
                    sub_card_frame(pal).show(ui, |ui| {
                        ui.label(
                            RichText::new(
                                "No desktop cloud sync folder was auto-detected yet. Choose any local folder, NAS share, or USB drive on the right.",
                            )
                            .color(pal.muted),
                        );
                    });
                } else {
                    for det in detected_clouds {
                        sub_card_frame(pal).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&det.provider)
                                            .font(semibold_font(ctx, 14.0))
                                            .color(pal.ink),
                                    );
                                    ui.label(
                                        RichText::new(&det.path)
                                            .font(FontId::proportional(11.8))
                                            .color(pal.muted),
                                    );
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if primary_button(ui, pal, Some(Icon::Plus), "Connect")
                                            .clicked()
                                        {
                                            let target_path = std::path::Path::new(&det.path)
                                                .join("EntroCloud")
                                                .display()
                                                .to_string();
                                            worker.send(UiCommand::AddRemote {
                                                params: Box::new(AddRemoteParams {
                                                    id: det.suggested_id.clone(),
                                                    kind: "fs".to_owned(),
                                                    root: target_path,
                                                    endpoint: None,
                                                    bucket: None,
                                                    region: None,
                                                    quota_limit_bytes: None,
                                                    policy: None,
                                                    prefix: None,
                                                    username: None,
                                                    secret: None,
                                                }),
                                            });
                                        }
                                    },
                                );
                            });
                        });
                        ui.add_space(6.0);
                    }
                }
            });

            // Right: Custom Local / External USB Drive Folder
            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Choose Any Folder or External Drive")
                        .font(semibold_font(ctx, 16.0))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new(
                        "Pick a folder on an external SSD, USB drive, network share, or this computer.",
                    )
                    .font(FontId::proportional(12.5))
                    .color(pal.muted),
                );
                ui.add_space(12.0);

                form_label(ui, pal, "Connection Name");
                ui.add(text_input_single(&mut self.conn_name, "e.g. ExternalDrive"));
                ui.add_space(8.0);

                form_label(ui, pal, "Selected Folder");
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        if secondary_button(
                            ui,
                            pal,
                            Some(Icon::FolderOpen),
                            "Browse Folders...",
                        )
                        .clicked()
                        {
                            dialogs.pick_folder(
                                ctx,
                                "Choose a folder or external drive for encrypted storage",
                                None,
                                DialogPurpose::WizardLocalCloudFolder,
                            );
                        }
                    },
                    |ui, _rem_w| {
                        ui.add(text_input_single(
                            &mut self.local_folder_path,
                            "Choose a folder...",
                        ));
                    },
                );

                ui.add_space(8.0);
                self.render_quota_presets(ui, pal, &[15, 100, 200, 2048]);

                ui.add_space(14.0);
                if primary_button(ui, pal, Some(Icon::Check), "Connect Folder").clicked() {
                    let id = self.conn_name.trim().to_owned();
                    let root = self.local_folder_path.trim().to_owned();
                    if id.is_empty() || root.is_empty() {
                        self.form_error =
                            Some("Enter a connection name and choose a folder first.".to_owned());
                    } else {
                        self.form_error = None;
                        worker.send(UiCommand::AddRemote {
                            params: Box::new(AddRemoteParams {
                                id,
                                kind: "fs".to_owned(),
                                root,
                                endpoint: None,
                                bucket: None,
                                region: None,
                                quota_limit_bytes: self.resolved_quota_bytes(),
                                policy: None,
                                prefix: None,
                                username: None,
                                secret: None,
                            }),
                        });
                    }
                }
            });
        });
    }

    fn render_provider_gdrive(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        oauth_busy: bool,
    ) {
        ui.columns(2, |cols| {
            // Left: Step-by-Step Google Drive OAuth Guide (ported from CloudBridge GOOGLE-DRIVE-SETUP.md)
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
                    paint_icon(ui.painter(), ic_r, Icon::BookOpen, pal.primary_btn);
                    ui.label(
                        RichText::new("Google Drive Step-by-Step Setup Guide")
                            .font(semibold_font(ctx, 16.0))
                            .color(pal.ink),
                    );
                });
                ui.label(
                    RichText::new(
                        "EntroCloud uses your own Google Desktop app OAuth client so your credentials belong solely to you.",
                    )
                    .font(FontId::proportional(12.3))
                    .color(pal.muted),
                );
                ui.add_space(8.0);

                guide_step_box(
                    ui,
                    pal,
                    "1",
                    "Open Google Cloud Console, create or select a project, and enable the Google Drive API.",
                );
                ui.horizontal_wrapped(|ui| {
                    if small_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Open Google Cloud Console",
                        false,
                    )
                    .clicked()
                        && let Err(err) = open_https_url("https://console.cloud.google.com/")
                    {
                        self.form_error = Some(err);
                    }
                    if small_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Open Drive API Library",
                        false,
                    )
                    .clicked()
                        && let Err(err) = open_https_url(
                            "https://console.cloud.google.com/apis/library/drive.googleapis.com",
                        )
                    {
                        self.form_error = Some(err);
                    }
                });

                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "2",
                    "Open Google Auth Platform / OAuth Consent Screen, set App Name (EntroCloud), support email, and Audience (External for personal Gmail). If in Testing mode, add your Gmail under Test Users.",
                );

                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "3",
                    "Under Data Access / Scopes, add https://www.googleapis.com/auth/drive.file so EntroCloud manages only its own encrypted backup files.",
                );
                ui.horizontal(|ui| {
                    if small_button(ui, pal, Some(Icon::Copy), "Copy Scope", false).clicked() {
                        ctx.copy_text("https://www.googleapis.com/auth/drive.file".to_owned());
                        self.set_copied_hint("Copied drive.file scope");
                    }
                    ui.monospace(
                        RichText::new("https://www.googleapis.com/auth/drive.file")
                            .size(11.2)
                            .color(pal.muted),
                    );
                });

                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "4",
                    "Open Clients / Credentials → Create Credentials → OAuth client ID → Desktop app, then copy your Client ID and Client Secret.",
                );

                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "5",
                    "Keep Cloud Folder as a dedicated new folder (/EntroCloud) — drive.file only accesses folders created by this OAuth client — then click Sign in with Google Browser.",
                );
            });

            // Right: Google Drive Connection Inputs
            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Connect Google Drive")
                        .font(semibold_font(ctx, 16.5))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new(
                        "Your Client Secret is wrapped and stored safely in your OS credential keyring.",
                    )
                    .font(FontId::proportional(12.3))
                    .color(pal.muted),
                );
                ui.add_space(12.0);

                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Connection Name");
                    fcols[0].add(text_input_single(&mut self.conn_name, "GoogleDrive"));
                    form_label(&mut fcols[1], pal, "Cloud Folder");
                    fcols[1].add(text_input_single(&mut self.cloud_folder, "/EntroCloud"));
                });

                ui.add_space(8.0);
                form_label(ui, pal, "Google Desktop App OAuth Client ID");
                ui.add(text_input_single(
                    &mut self.oauth_client_id,
                    "1234567890-abc...apps.googleusercontent.com",
                ));

                ui.add_space(8.0);
                form_label(ui, pal, "Google OAuth Client Secret");
                let show_sec = self.show_oauth_secret;
                let mut toggle_sec = false;
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        let eye = if show_sec { Icon::EyeOff } else { Icon::Eye };
                        if icon_button(ui, pal, eye, "Show or hide Client Secret").clicked() {
                            toggle_sec = true;
                        }
                    },
                    |ui, _rem_w| {
                        ui.add(
                            egui::TextEdit::singleline(&mut *self.oauth_client_secret)
                                .password(!show_sec)
                                .margin(Margin::symmetric(10.0, 7.5))
                                .desired_width(f32::INFINITY)
                                .hint_text("GOCSPX-..."),
                        );
                    },
                );
                if toggle_sec {
                    self.show_oauth_secret = !self.show_oauth_secret;
                }

                ui.add_space(8.0);
                self.render_quota_presets(ui, pal, &[15, 100, 200, 2048]);

                ui.add_space(14.0);
                ui.add_enabled_ui(!oauth_busy, |ui| {
                    if primary_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Sign in with Google Browser",
                    )
                    .clicked()
                    {
                        self.submit_oauth_provider(worker, "gdrive", true);
                    }
                });
            });
        });
    }

    fn render_provider_onedrive(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        oauth_busy: bool,
    ) {
        ui.columns(2, |cols| {
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
                    paint_icon(ui.painter(), ic_r, Icon::BookOpen, pal.primary_btn);
                    ui.label(
                        RichText::new("Microsoft OneDrive Setup Guide")
                            .font(semibold_font(ctx, 16.0))
                            .color(pal.ink),
                    );
                });
                ui.add_space(8.0);
                guide_step_box(
                    ui,
                    pal,
                    "1",
                    "Open Microsoft Entra App Registrations and click New registration.",
                );
                if small_button(
                    ui,
                    pal,
                    Some(Icon::ExternalLink),
                    "Open Entra App Registrations",
                    false,
                )
                .clicked()
                    && let Err(err) = open_https_url(
                        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
                    )
                {
                    self.form_error = Some(err);
                }
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "2",
                    "Set Name to EntroCloud and choose Accounts in any organizational directory and personal Microsoft accounts.",
                );
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "3",
                    "Under Redirect URI, select Mobile and desktop applications and enter http://127.0.0.1.",
                );
                if small_button(ui, pal, Some(Icon::Copy), "Copy Redirect URI", false).clicked() {
                    ctx.copy_text("http://127.0.0.1".to_owned());
                    self.set_copied_hint("Copied http://127.0.0.1");
                }
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "4",
                    "Under API permissions → Microsoft Graph → Delegated permissions, add Files.ReadWrite and offline_access, then copy the Application (client) ID.",
                );
                if small_button(ui, pal, Some(Icon::Copy), "Copy Permissions", false).clicked() {
                    ctx.copy_text("Files.ReadWrite offline_access".to_owned());
                    self.set_copied_hint("Copied Graph permissions");
                }
            });

            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Connect Microsoft OneDrive")
                        .font(semibold_font(ctx, 16.5))
                        .color(pal.ink),
                );
                ui.add_space(12.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Connection Name");
                    fcols[0].add(text_input_single(&mut self.conn_name, "OneDrive"));
                    form_label(&mut fcols[1], pal, "Cloud Folder");
                    fcols[1].add(text_input_single(&mut self.cloud_folder, "/EntroCloud"));
                });
                ui.add_space(8.0);
                form_label(ui, pal, "Application (Client) ID");
                ui.add(text_input_single(
                    &mut self.oauth_client_id,
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                ));
                ui.add_space(8.0);
                self.render_quota_presets(ui, pal, &[5, 100, 1024, 2048]);
                ui.add_space(14.0);
                ui.add_enabled_ui(!oauth_busy, |ui| {
                    if primary_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Sign in with Microsoft",
                    )
                    .clicked()
                    {
                        self.submit_oauth_provider(worker, "onedrive", false);
                    }
                });
            });
        });
    }

    fn render_provider_dropbox(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        oauth_busy: bool,
    ) {
        ui.columns(2, |cols| {
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
                    paint_icon(ui.painter(), ic_r, Icon::BookOpen, pal.primary_btn);
                    ui.label(
                        RichText::new("Dropbox App Console Setup Guide")
                            .font(semibold_font(ctx, 16.0))
                            .color(pal.ink),
                    );
                });
                ui.add_space(8.0);
                guide_step_box(
                    ui,
                    pal,
                    "1",
                    "Open Dropbox App Console and click Create app.",
                );
                if small_button(
                    ui,
                    pal,
                    Some(Icon::ExternalLink),
                    "Open Dropbox App Console",
                    false,
                )
                .clicked()
                    && let Err(err) = open_https_url("https://www.dropbox.com/developers/apps")
                {
                    self.form_error = Some(err);
                }
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "2",
                    "Choose Scoped access, then select App folder so EntroCloud only touches its own private folder.",
                );
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "3",
                    "Open the Permissions tab, enable files.metadata.read, files.content.write, and files.content.read, and click Submit.",
                );
                if small_button(ui, pal, Some(Icon::Copy), "Copy Scopes", false).clicked() {
                    ctx.copy_text(
                        "files.metadata.read files.content.write files.content.read".to_owned(),
                    );
                    self.set_copied_hint("Copied Dropbox scopes");
                }
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "4",
                    "Copy your App key from Settings and paste it on the right.",
                );
            });

            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Connect Dropbox")
                        .font(semibold_font(ctx, 16.5))
                        .color(pal.ink),
                );
                ui.add_space(12.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Connection Name");
                    fcols[0].add(text_input_single(&mut self.conn_name, "Dropbox"));
                    form_label(&mut fcols[1], pal, "Cloud Folder");
                    fcols[1].add(text_input_single(&mut self.cloud_folder, "/EntroCloud"));
                });
                ui.add_space(8.0);
                form_label(ui, pal, "Dropbox App Key");
                ui.add(text_input_single(&mut self.oauth_client_id, "App key"));
                ui.add_space(8.0);
                form_label(ui, pal, "Dropbox App Secret (optional with PKCE)");
                let show_sec = self.show_oauth_secret;
                let mut toggle_sec = false;
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        let eye = if show_sec { Icon::EyeOff } else { Icon::Eye };
                        if icon_button(ui, pal, eye, "Show or hide App Secret").clicked() {
                            toggle_sec = true;
                        }
                    },
                    |ui, _rem_w| {
                        ui.add(
                            egui::TextEdit::singleline(&mut *self.oauth_client_secret)
                                .password(!show_sec)
                                .margin(Margin::symmetric(10.0, 7.5))
                                .desired_width(f32::INFINITY)
                                .hint_text("Optional"),
                        );
                    },
                );
                if toggle_sec {
                    self.show_oauth_secret = !self.show_oauth_secret;
                }
                ui.add_space(8.0);
                self.render_quota_presets(ui, pal, &[2, 15, 2048]);
                ui.add_space(14.0);
                ui.add_enabled_ui(!oauth_busy, |ui| {
                    if primary_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Sign in with Dropbox",
                    )
                    .clicked()
                    {
                        self.submit_oauth_provider(worker, "dropbox", false);
                    }
                });
            });
        });
    }

    fn render_provider_s3(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
    ) {
        ui.columns(2, |cols| {
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new("S3 / R2 / Backblaze B2 Presets & Guide")
                        .font(semibold_font(ctx, 16.0))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new("Pick a provider preset to pre-fill the endpoint format:")
                        .font(FontId::proportional(12.5))
                        .color(pal.muted),
                );
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    for (preset, lbl) in [
                        (S3Preset::CloudflareR2, "Cloudflare R2"),
                        (S3Preset::BackblazeB2, "Backblaze B2"),
                        (S3Preset::AmazonS3, "Amazon S3"),
                        (S3Preset::Wasabi, "Wasabi"),
                        (S3Preset::CustomMinio, "Custom / MinIO"),
                    ] {
                        if small_button(ui, pal, None, lbl, self.s3_preset == preset).clicked() {
                            self.apply_s3_preset(preset);
                        }
                    }
                });
                ui.add_space(10.0);
                let hint_text = match self.s3_preset {
                    S3Preset::CloudflareR2 => {
                        "Cloudflare R2: Create a bucket in your Cloudflare dashboard, open Manage R2 API Tokens → Create API Token with Object Read & Write permissions, and replace <ACCOUNT_ID> in the endpoint URL."
                    }
                    S3Preset::BackblazeB2 => {
                        "Backblaze B2: Create a private bucket, copy its S3 Endpoint (e.g. https://s3.us-west-004.backblazeb2.com), and generate an Application Key restricted to that bucket."
                    }
                    S3Preset::AmazonS3 => {
                        "Amazon S3: Create a private S3 bucket, match the AWS region (e.g. us-east-1 or eu-central-1), and provide an IAM Access Key scoped to that bucket."
                    }
                    S3Preset::Wasabi => {
                        "Wasabi: Match your bucket's regional Wasabi endpoint (e.g. https://s3.eu-central-1.wasabisys.com) and provide a sub-user Access Key."
                    }
                    S3Preset::CustomMinio => {
                        "Custom / MinIO: Enter your self-hosted HTTPS/HTTP S3 gateway URL, bucket name, and access credentials."
                    }
                };
                sub_card_frame(pal).show(ui, |ui| {
                    ui.label(RichText::new(hint_text).color(pal.ink).size(12.6));
                });
            });

            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Connect Object Storage")
                        .font(semibold_font(ctx, 16.5))
                        .color(pal.ink),
                );
                ui.add_space(10.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Connection Name");
                    fcols[0].add(text_input_single(&mut self.conn_name, "CloudflareR2"));
                    form_label(&mut fcols[1], pal, "Bucket Name");
                    fcols[1].add(text_input_single(
                        &mut self.s3_bucket,
                        "my-encrypted-bucket",
                    ));
                });
                ui.add_space(6.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Endpoint URL");
                    fcols[0].add(text_input_single(&mut self.s3_endpoint, "https://..."));
                    form_label(&mut fcols[1], pal, "Region");
                    fcols[1].add(text_input_single(&mut self.s3_region, "auto or us-east-1"));
                });
                ui.add_space(6.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Access Key ID");
                    fcols[0].add(text_input_single(&mut self.s3_access_key, "Access key"));
                    form_label(&mut fcols[1], pal, "Folder Prefix");
                    fcols[1].add(text_input_single(&mut self.cloud_folder, "/EntroCloud"));
                });
                ui.add_space(6.0);
                form_label(ui, pal, "Secret Access Key");
                let show_s3 = self.show_s3_secret;
                let mut toggle_s3 = false;
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        let eye = if show_s3 { Icon::EyeOff } else { Icon::Eye };
                        if icon_button(ui, pal, eye, "Show or hide Secret Access Key").clicked() {
                            toggle_s3 = true;
                        }
                    },
                    |ui, _rem_w| {
                        ui.add(
                            egui::TextEdit::singleline(&mut *self.s3_secret_key)
                                .password(!show_s3)
                                .margin(Margin::symmetric(10.0, 7.5))
                                .desired_width(f32::INFINITY)
                                .hint_text("Stored safely in OS credential keyring"),
                        );
                    },
                );
                if toggle_s3 {
                    self.show_s3_secret = !self.show_s3_secret;
                }
                ui.add_space(12.0);
                if primary_button(ui, pal, Some(Icon::Check), "Connect Storage").clicked() {
                    let id = self.conn_name.trim().to_owned();
                    let bucket = self.s3_bucket.trim().to_owned();
                    let endpoint = self.s3_endpoint.trim().to_owned();
                    let ak = self.s3_access_key.trim().to_owned();
                    let sk = self.s3_secret_key.trim().to_owned();
                    if id.is_empty() || bucket.is_empty() || endpoint.is_empty() || ak.is_empty() || sk.is_empty() {
                        self.form_error = Some(
                            "Complete Connection Name, Bucket Name, Endpoint URL, Access Key ID, and Secret Access Key.".to_owned(),
                        );
                    } else {
                        self.form_error = None;
                        worker.send(UiCommand::AddRemote {
                            params: Box::new(AddRemoteParams {
                                id,
                                kind: "s3".to_owned(),
                                root: self.cloud_folder.trim().to_owned(),
                                endpoint: Some(endpoint),
                                bucket: Some(bucket),
                                region: Some(self.s3_region.trim().to_owned()),
                                quota_limit_bytes: self.resolved_quota_bytes(),
                                policy: None,
                                prefix: None,
                                username: Some(ak),
                                secret: Some(sk),
                            }),
                        });
                    }
                }
            });
        });
    }

    fn render_provider_webdav(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
    ) {
        ui.columns(2, |cols| {
            card_frame(pal).show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new("WebDAV / Nextcloud / Synology Guide")
                        .font(semibold_font(ctx, 16.0))
                        .color(pal.ink),
                );
                ui.add_space(8.0);
                guide_step_box(
                    ui,
                    pal,
                    "1",
                    "In Nextcloud, open Settings → Security → Devices & sessions, type EntroCloud, and click Create new app password.",
                );
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "2",
                    "Use your Nextcloud WebDAV files URL: https://cloud.example.com/remote.php/dav/files/username/",
                );
                if small_button(ui, pal, Some(Icon::Copy), "Copy URL Format", false).clicked() {
                    ctx.copy_text(
                        "https://cloud.example.com/remote.php/dav/files/username/".to_owned(),
                    );
                    self.set_copied_hint("Copied Nextcloud WebDAV example URL");
                }
                ui.add_space(6.0);
                guide_step_box(
                    ui,
                    pal,
                    "3",
                    "For Synology DSM or home NAS, enable WebDAV Server over HTTPS and enter your dedicated backup username and password.",
                );
            });

            card_frame(pal).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Connect WebDAV / Nextcloud")
                        .font(semibold_font(ctx, 16.5))
                        .color(pal.ink),
                );
                ui.add_space(10.0);
                ui.columns(2, |fcols| {
                    form_label(&mut fcols[0], pal, "Connection Name");
                    fcols[0].add(text_input_single(&mut self.conn_name, "Nextcloud"));
                    form_label(&mut fcols[1], pal, "Remote Folder");
                    fcols[1].add(text_input_single(&mut self.cloud_folder, "/EntroCloud"));
                });
                ui.add_space(6.0);
                form_label(ui, pal, "WebDAV Server Address");
                ui.add(text_input_single(
                    &mut self.webdav_endpoint,
                    "https://cloud.example.com/remote.php/dav/files/username/",
                ));
                ui.add_space(6.0);
                form_label(ui, pal, "Username");
                ui.add(text_input_single(&mut self.webdav_username, "Username"));
                ui.add_space(6.0);
                form_label(ui, pal, "App Password");
                let show_wd = self.show_webdav_secret;
                let mut toggle_wd = false;
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        let eye = if show_wd { Icon::EyeOff } else { Icon::Eye };
                        if icon_button(ui, pal, eye, "Show or hide App Password").clicked() {
                            toggle_wd = true;
                        }
                    },
                    |ui, _rem_w| {
                        ui.add(
                            egui::TextEdit::singleline(&mut *self.webdav_password)
                                .password(!show_wd)
                                .margin(Margin::symmetric(10.0, 7.5))
                                .desired_width(f32::INFINITY)
                                .hint_text("Stored safely in OS credential keyring"),
                        );
                    },
                );
                if toggle_wd {
                    self.show_webdav_secret = !self.show_webdav_secret;
                }
                ui.add_space(12.0);
                if primary_button(ui, pal, Some(Icon::Check), "Connect Storage").clicked() {
                    let id = self.conn_name.trim().to_owned();
                    let ep = self.webdav_endpoint.trim().to_owned();
                    let user = self.webdav_username.trim().to_owned();
                    let pw = self.webdav_password.trim().to_owned();
                    if id.is_empty() || ep.is_empty() || user.is_empty() || pw.is_empty() {
                        self.form_error = Some(
                            "Enter Connection Name, WebDAV Address, Username, and App Password."
                                .to_owned(),
                        );
                    } else {
                        self.form_error = None;
                        worker.send(UiCommand::AddRemote {
                            params: Box::new(AddRemoteParams {
                                id,
                                kind: "webdav".to_owned(),
                                root: self.cloud_folder.trim().to_owned(),
                                endpoint: Some(ep),
                                bucket: None,
                                region: None,
                                quota_limit_bytes: self.resolved_quota_bytes(),
                                policy: None,
                                prefix: None,
                                username: Some(user),
                                secret: Some(pw),
                            }),
                        });
                    }
                }
            });
        });
    }

    fn render_quota_presets(&mut self, ui: &mut egui::Ui, pal: &Palette, presets_gb: &[u64]) {
        form_label(ui, pal, "Optional Storage Limit");
        ui.horizontal_wrapped(|ui| {
            for &gb in presets_gb {
                let lbl = if gb >= 1024 && gb.is_multiple_of(1024) {
                    format!("{} TB", gb / 1024)
                } else {
                    format!("{gb} GB")
                };
                let sel = self.quota_gb_preset == Some(gb) && self.custom_quota_gb.trim().is_empty();
                if small_button(ui, pal, None, &lbl, sel).clicked() {
                    self.quota_gb_preset = Some(gb);
                    self.custom_quota_gb.clear();
                }
            }
            let unlim_sel = self.quota_gb_preset.is_none() && self.custom_quota_gb.trim().is_empty();
            if small_button(ui, pal, None, "Unlimited", unlim_sel).clicked() {
                self.quota_gb_preset = None;
                self.custom_quota_gb.clear();
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.custom_quota_gb)
                    .margin(Margin::symmetric(8.0, 5.5))
                    .desired_width(82.0)
                    .hint_text("Custom GB"),
            );
        });
    }

    fn submit_oauth_provider(
        &mut self,
        worker: &UiWorkerHandle,
        kind: &str,
        secret_required: bool,
    ) {
        let id = self.conn_name.trim().to_owned();
        let client_id = self.oauth_client_id.trim().to_owned();
        let secret_trimmed = self.oauth_client_secret.trim().to_owned();
        if id.is_empty() {
            self.form_error = Some("Enter a Connection Name first.".to_owned());
            return;
        }
        if client_id.is_empty() || (secret_required && secret_trimmed.is_empty()) {
            self.form_error = Some(if secret_required {
                "Create a Desktop app OAuth client using the setup guide on the left, then paste its Client ID and Client Secret.".to_owned()
            } else {
                "Paste your OAuth Application Client ID / App Key from the setup guide first.".to_owned()
            });
            return;
        }
        self.form_error = None;
        let secret_opt = if secret_trimmed.is_empty() {
            None
        } else {
            Some(secret_trimmed)
        };
        let folder = if self.cloud_folder.trim().is_empty() {
            "/EntroCloud".to_owned()
        } else {
            self.cloud_folder.trim().to_owned()
        };
        worker.send(UiCommand::OAuthLogin {
            params: Box::new(OAuthLoginParams {
                id,
                kind: kind.to_owned(),
                root: folder,
                client_id,
                client_secret: secret_opt,
                auth_url: None,
                token_url: None,
                quota_limit_bytes: self.resolved_quota_bytes(),
                policy: None,
                prefix: None,
                timeout_secs: Some(180),
                open_browser: true,
            }),
        });
    }

    fn render_step_password(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        worker: &UiWorkerHandle,
        vault_initialized: bool,
    ) {
        let is_recover_or_existing =
            self.flow == OnboardingFlow::RecoverExistingVault || vault_initialized;

        ui.vertical_centered(|ui| {
            ui.set_max_width(580.0);
            card_frame(pal).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                    paint_icon(ui.painter(), ic_r, Icon::Lock, pal.primary_btn);
                    ui.label(
                        RichText::new(if is_recover_or_existing {
                            "Unlock Your Cloud Vault"
                        } else {
                            "Create Your Master Password"
                        })
                        .font(semibold_font(ctx, 22.0))
                        .color(pal.ink),
                    );
                });

                ui.add_space(8.0);
                sub_card_frame(pal).show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Only you hold this password. File contents and filenames are encrypted on this PC before leaving it. Save it in your password manager — EntroCloud cannot reset it.",
                        )
                        .font(FontId::proportional(13.0))
                        .color(pal.ink),
                    );
                });

                ui.add_space(14.0);
                form_label(ui, pal, "Master Password");
                let show_pw = self.show_pass;
                let mut toggle_pw = false;
                let mut enter_submit = false;
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        let eye = if show_pw { Icon::EyeOff } else { Icon::Eye };
                        if icon_button(ui, pal, eye, "Show or hide password").clicked() {
                            toggle_pw = true;
                        }
                    },
                    |ui, _rem_w| {
                        let edit = ui.add(
                            egui::TextEdit::singleline(&mut *self.pass_input)
                                .password(!show_pw)
                                .margin(Margin::symmetric(10.0, 7.5))
                                .desired_width(f32::INFINITY)
                                .hint_text("Choose a strong password or memorable passphrase"),
                        );
                        if is_recover_or_existing
                            && edit.lost_focus()
                            && ctx.input(|i| i.key_pressed(Key::Enter))
                        {
                            enter_submit = true;
                        }
                    },
                );
                if toggle_pw {
                    self.show_pass = !self.show_pass;
                }

                if !is_recover_or_existing {
                    let (score, strength_label) = password_strength(&self.pass_input);
                    ui.add_space(4.0);
                    progress_bar_clean(ui, pal, score, 5.0);
                    ui.label(
                        RichText::new(strength_label)
                            .font(FontId::proportional(11.8))
                            .color(pal.muted),
                    );

                    ui.add_space(10.0);
                    form_label(ui, pal, "Repeat Master Password");
                    let confirm_edit = ui.add(
                        egui::TextEdit::singleline(&mut *self.pass_confirm)
                            .password(!self.show_pass)
                            .margin(Margin::symmetric(10.0, 7.5))
                            .desired_width(f32::INFINITY)
                            .hint_text("Type your Master Password again to confirm"),
                    );
                    if confirm_edit.lost_focus() && ctx.input(|i| i.key_pressed(Key::Enter)) {
                        enter_submit = true;
                    }
                    if !self.pass_confirm.is_empty() {
                        let matches = *self.pass_input == *self.pass_confirm;
                        ui.label(
                            RichText::new(if matches {
                                "Passwords match."
                            } else {
                                "Passwords do not match yet."
                            })
                            .font(FontId::proportional(12.0))
                            .color(if matches { pal.ok_fg } else { pal.danger_fg }),
                        );
                    }
                }

                if let Some(ref err) = self.form_error {
                    ui.add_space(8.0);
                    ui.label(RichText::new(err).color(pal.danger_fg));
                }

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, Some(Icon::ArrowLeft), "Back").clicked() {
                        self.step = WizardStep::ConnectCloud;
                    }

                    if !vault_initialized {
                        let toggle_lbl = if is_recover_or_existing {
                            "Create a new vault instead"
                        } else {
                            "Unlock an existing vault instead"
                        };
                        if small_button(ui, pal, None, toggle_lbl, false).clicked() {
                            self.flow = if is_recover_or_existing {
                                OnboardingFlow::CreateNewVault
                            } else {
                                OnboardingFlow::RecoverExistingVault
                            };
                            self.form_error = None;
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let unlocking = worker.state.lock().unlock_inflight;
                        let submit_lbl = if unlocking {
                            "Unlocking..."
                        } else if is_recover_or_existing {
                            "Unlock Vault"
                        } else {
                            "Create Vault & Unlock"
                        };
                        let submit_clicked = ui
                            .add_enabled_ui(!unlocking, |ui| {
                                primary_button(ui, pal, Some(Icon::Lock), submit_lbl)
                            })
                            .inner
                            .clicked();
                        if !unlocking && (submit_clicked || enter_submit) {
                            if self.pass_input.is_empty() {
                                self.form_error =
                                    Some("Enter your Master Password first.".to_owned());
                            } else if !is_recover_or_existing
                                && *self.pass_input != *self.pass_confirm
                            {
                                self.pass_input.zeroize();
                                self.pass_confirm.zeroize();
                                self.form_error = Some(
                                    "The two passwords did not match. Please enter them again."
                                        .to_owned(),
                                );
                            } else {
                                self.form_error = None;
                                worker.state.lock().toast_error = None;
                                let secret = Zeroizing::new((*self.pass_input).clone());
                                self.pass_input.zeroize();
                                self.pass_confirm.zeroize();
                                if is_recover_or_existing {
                                    worker.send(UiCommand::UnlockVault {
                                        passphrase: secret,
                                        current_dir: "/".to_owned(),
                                    });
                                } else {
                                    worker.send(UiCommand::InitVault { passphrase: secret });
                                }
                            }
                        }
                    });
                });
            });
        });
    }

    fn render_step_ready(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        pal: &Palette,
        remotes: &[RemoteAccountSummary],
        outcome: &mut WizardOutcome,
    ) {
        card_frame(pal).show(ui, |ui| {
            ui.horizontal(|ui| {
                status_pill(ui, pal, Some(Icon::Check), "All Set", PillTone::Ok);
                ui.label(
                    RichText::new("Your encrypted space is ready")
                        .font(semibold_font(ctx, 24.0))
                        .color(pal.ink),
                );
            });
            ui.add_space(6.0);
            let summary = if remotes.is_empty() {
                "Your local vault is unlocked. You can connect a cloud account anytime from the sidebar.".to_owned()
            } else {
                let ids: Vec<&str> = remotes.iter().map(|r| r.id.as_str()).collect();
                format!(
                    "Connected to {} ({}) and unlocked for encrypted backups.",
                    ids.join(", "),
                    remotes.len()
                )
            };
            ui.label(
                RichText::new(summary)
                    .font(FontId::proportional(14.0))
                    .color(pal.muted),
            );

            ui.add_space(18.0);
            ui.columns(3, |cols| {
                if quick_finish_card(
                    &mut cols[0],
                    pal,
                    Icon::HomeBackups,
                    "Add a PC Folder to Back Up Automatically",
                    "Pick Documents, Photos, or Work folders and back them up on a schedule.",
                )
                .clicked()
                {
                    self.zeroize_secrets();
                    self.open = false;
                    *outcome = WizardOutcome::FinishAndAddBackupFolder;
                }
                let drive_card_title = if cfg!(target_os = "windows") {
                    "Turn On EntroCloud Drive in File Explorer"
                } else {
                    "Turn On EntroCloud Drive in File Manager"
                };
                if quick_finish_card(
                    &mut cols[1],
                    pal,
                    Icon::HardDrive,
                    drive_card_title,
                    "Open your encrypted cloud files like a normal folder on this computer.",
                )
                .clicked()
                {
                    self.zeroize_secrets();
                    self.open = false;
                    *outcome = WizardOutcome::FinishAndOpenComputerDrive;
                }
                if quick_finish_card(
                    &mut cols[2],
                    pal,
                    Icon::Folder,
                    "Go to EntroCloud",
                    "Browse your vault, drag and drop files, or write encrypted notes.",
                )
                .clicked()
                {
                    self.zeroize_secrets();
                    self.open = false;
                    *outcome = WizardOutcome::FinishToWorkspace;
                }
            });
        });
    }
}

fn password_strength(pw: &str) -> (f32, &'static str) {
    let chars = pw.chars().count();
    if chars == 0 {
        return (0.0, "Enter a Master Password");
    }
    let has_upper = pw.chars().any(char::is_uppercase);
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_sym = pw.chars().any(|c| !c.is_alphanumeric());
    let variety = usize::from(has_upper) + usize::from(has_digit) + usize::from(has_sym);

    if chars < 8 {
        (0.25, "Short — consider a longer phrase (12+ characters)")
    } else if chars < 12 && variety < 2 {
        (0.50, "Fair — adding words or symbols makes this stronger")
    } else if chars < 16 {
        (0.78, "Good — strong personal encryption password")
    } else {
        (1.0, "Excellent — high-entropy passphrase")
    }
}

fn welcome_pillar_card(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    title: &str,
    desc: &str,
) {
    sub_card_frame(pal).show(ui, |ui| {
        ui.set_min_height(118.0);
        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
        paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
        ui.add_space(6.0);
        ui.label(
            RichText::new(title)
                .font(semibold_font(ui.ctx(), 14.2))
                .color(pal.ink),
        );
        ui.add_space(3.0);
        ui.label(
            RichText::new(desc)
                .font(FontId::proportional(12.4))
                .color(pal.muted),
        );
    });
}

fn onboarding_choice_card(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    title: &str,
    desc: &str,
    selected: bool,
) -> egui::Response {
    interactive_card(
        ui,
        pal,
        selected,
        88.0,
        Vec2::new(14.0, 14.0),
        10.0,
        |ui| {
            ui.horizontal_top(|ui| {
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 3.0;
                    ui.label(
                        RichText::new(title)
                            .font(semibold_font(ui.ctx(), 14.2))
                            .color(pal.ink),
                    );
                    ui.label(
                        RichText::new(desc)
                            .font(FontId::proportional(12.2))
                            .color(pal.muted),
                    );
                });
            });
        },
    )
}

fn provider_tile(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    title: &str,
    subtitle: &str,
    selected: bool,
) -> egui::Response {
    interactive_card(
        ui,
        pal,
        selected,
        60.0,
        Vec2::new(12.0, 10.0),
        9.0,
        |ui| {
            ui.horizontal(|ui| {
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(
                        RichText::new(title)
                            .font(semibold_font(ui.ctx(), 13.4))
                            .color(pal.ink),
                    );
                    ui.label(
                        RichText::new(subtitle)
                            .font(FontId::proportional(11.5))
                            .color(pal.muted),
                    );
                });
            });
        },
    )
}

fn guide_step_box(ui: &mut egui::Ui, pal: &Palette, step_num: &str, body: &str) {
    sub_card_frame(pal)
        .inner_margin(egui::Margin::symmetric(10.0, 6.5))
        .show(ui, |ui| {
            let max_w = ui.available_width();
            ui.set_width(max_w);
            ui.horizontal_top(|ui| {
                let (c_rect, _) = ui.allocate_exact_size(Vec2::splat(19.0), Sense::hover());
                ui.painter()
                    .circle_filled(c_rect.center(), 9.0, pal.primary_btn);
                ui.painter().text(
                    c_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    step_num,
                    semibold_font(ui.ctx(), 10.8),
                    Color32::WHITE,
                );
                let text_w = (max_w - 28.0).max(80.0);
                ui.allocate_ui(Vec2::new(text_w, 0.0), |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(body)
                                .font(FontId::proportional(11.9))
                                .color(pal.ink),
                        )
                        .wrap(),
                    );
                });
            });
        });
}

fn quick_finish_card(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    title: &str,
    desc: &str,
) -> egui::Response {
    interactive_card(
        ui,
        pal,
        false,
        130.0,
        Vec2::new(14.0, 14.0),
        10.0,
        |ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
            ui.add_space(6.0);
            ui.label(
                RichText::new(title)
                    .font(semibold_font(ui.ctx(), 13.8))
                    .color(pal.ink),
            );
            ui.add_space(3.0);
            ui.label(
                RichText::new(desc)
                    .font(FontId::proportional(12.1))
                    .color(pal.muted),
            );
        },
    )
}
