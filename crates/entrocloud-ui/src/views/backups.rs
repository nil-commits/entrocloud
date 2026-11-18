//! `Backups` view ("Your backup space") — modeled on CloudBridge's calm backup overview,
//! protected folder cards, preview/restore/edit actions, and folder job modal.

use std::path::Path;

use eframe::egui::{
    self, Color32, CursorIcon, FontId, Margin, Pos2, Rect, Rgba, RichText, Rounding, Sense, Stroke,
    Vec2,
};
use entrocloud_types::{BackupJobSpec, BackupJobSummary};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_icon};
use crate::session::open_in_os_default_app;
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, icon_button,
    input_row_with_right_widget, modal_dialog, primary_button, progress_bar_clean,
    secondary_button, semibold_font, small_button, status_pill, sub_card_frame, text_input_single,
};
use crate::tray_common::format_bytes_human;
use crate::views::FrameSnapshot;
use crate::wizard::{WizardProvider, WizardState};
use crate::worker::{UiCommand, UiWorkerHandle};

/// State for the Add / Edit Protected Backup Folder modal.
#[derive(Debug, Clone)]
pub struct BackupJobModalState {
    pub open: bool,
    pub editing_id: Option<String>,
    pub name: String,
    pub source_path: String,
    pub vault_folder: String,
    pub interval_minutes: u32,
    pub custom_minutes: String,
    pub enabled: bool,
    pub excludes_text: String,
    pub error: Option<String>,
    auto_derived_name: Option<String>,
    auto_derived_vault_folder: Option<String>,
}

impl Default for BackupJobModalState {
    fn default() -> Self {
        Self::new_blank()
    }
}

impl BackupJobModalState {
    #[must_use]
    pub fn new_blank() -> Self {
        Self {
            open: false,
            editing_id: None,
            name: String::new(),
            source_path: String::new(),
            vault_folder: "/Backups/Documents".to_owned(),
            interval_minutes: 15,
            custom_minutes: "15".to_owned(),
            enabled: true,
            excludes_text: "desktop.ini\nThumbs.db\n~$*\n*.tmp\n.DS_Store\nnode_modules\n.git\ntarget\n.venv\n__pycache__".to_owned(),
            error: None,
            auto_derived_name: None,
            auto_derived_vault_folder: Some("/Backups/Documents".to_owned()),
        }
    }

    pub fn open_for_new(&mut self) {
        *self = Self::new_blank();
        self.open = true;
    }

    pub fn open_for_edit(&mut self, job: &BackupJobSummary) {
        self.open = true;
        self.editing_id = Some(job.id.clone());
        self.name = job.name.clone();
        self.source_path = job.source_path.clone();
        self.vault_folder = job.vault_folder.clone();
        self.interval_minutes = job.interval_minutes;
        self.custom_minutes = job.interval_minutes.to_string();
        self.enabled = job.enabled;
        self.excludes_text = if job.excludes.is_empty() {
            "desktop.ini\nThumbs.db\n~$*".to_owned()
        } else {
            job.excludes.join("\n")
        };
        self.error = None;
        self.auto_derived_name = None;
        self.auto_derived_vault_folder = None;
    }

    pub fn set_picked_source_folder(&mut self, path: &Path) {
        self.source_path = path.display().to_string();
        self.sync_derived_from_source_path();
    }

    pub fn sync_derived_from_source_path(&mut self) {
        if self.editing_id.is_some() {
            return;
        }
        let trimmed = self.source_path.trim().trim_end_matches(['\\', '/']);
        if let Some(base) = Path::new(trimmed)
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
        {
            let can_update_name = self.name.trim().is_empty()
                || self.auto_derived_name.as_deref() == Some(self.name.trim());
            if can_update_name {
                self.name = base.to_owned();
                self.auto_derived_name = Some(base.to_owned());
            }
            let derived_vault = format!("/Backups/{base}");
            let can_update_vault = self.vault_folder.trim().is_empty()
                || self.auto_derived_vault_folder.as_deref() == Some(self.vault_folder.trim());
            if can_update_vault {
                self.vault_folder = derived_vault.clone();
                self.auto_derived_vault_folder = Some(derived_vault);
            }
        }
    }
}

/// State for the Restore Encrypted Snapshot modal.
#[derive(Debug, Clone, Default)]
pub struct RestoreModalState {
    pub open: bool,
    pub job_id: String,
    pub job_name: String,
    pub destination_parent: String,
    pub error: Option<String>,
}

/// Renders the `Backups` main view (`Your backup space`).
#[allow(clippy::too_many_arguments)]
pub fn render_backups_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    wizard: &mut WizardState,
    selected_job_id: &mut Option<String>,
    job_modal: &mut BackupJobModalState,
    restore_modal: &mut RestoreModalState,
    remove_confirm_job: &mut Option<(String, String)>,
) {
    let st = snap.status.as_ref();
    let jobs: &[BackupJobSummary] = st.map_or(&[], |s| s.backup_jobs.as_slice());
    let remotes_count = st.map_or(0, |s| s.remotes.len());
    let backups_paused = st.is_some_and(|s| s.backups_paused);
    let active_activity = st.and_then(|s| s.active_activity.as_deref());

    // Ensure selection stays valid when jobs exist
    if selected_job_id.is_none()
        && let Some(first) = jobs.first()
    {
        *selected_job_id = Some(first.id.clone());
    } else if let Some(ref cur_id) = *selected_job_id
        && !jobs.iter().any(|j| &j.id == cur_id)
    {
        *selected_job_id = jobs.first().map(|j| j.id.clone());
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // 1. CloudBridge Hero Header Row
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    ui.label(
                        RichText::new("Your backup space")
                            .font(semibold_font(ctx, 27.0))
                            .color(pal.ink),
                    );
                    ui.label(
                        RichText::new(
                            "Keep the folders you care about safely encrypted and copied to your cloud.",
                        )
                        .font(FontId::proportional(14.0))
                        .color(pal.muted),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if primary_button(ui, pal, Some(Icon::Plus), "Add folder").clicked() {
                        job_modal.open_for_new();
                    }
                });
            });

            ui.add_space(16.0);

            // 2. CloudBridge Status Banner Card
            card_frame(pal).show(ui, |ui| {
                let is_running = active_activity.is_some()
                    || snap.backup_request_inflight
                    || jobs
                        .iter()
                        .any(|j| j.status.to_ascii_lowercase().contains("backing up"));

                let (status_title, status_detail, progress_val) = if let Some(act) = active_activity
                {
                    let pct = parse_activity_progress_fraction(act).unwrap_or(0.45);
                    ("Backing up your folders...", act.to_owned(), pct)
                } else if snap.backup_request_inflight {
                    (
                        "Starting folder backup...",
                        "Scanning local folder changes and preparing encrypted chunks...".to_owned(),
                        0.12,
                    )
                } else if backups_paused {
                    (
                        "Automatic backups are paused",
                        "Scheduled background runs are paused. Click Resume whenever you are ready to continue.".to_owned(),
                        0.0,
                    )
                } else if remotes_count == 0 {
                    (
                        "Connect a cloud to start off-site backup",
                        "Link Google Drive, OneDrive, Dropbox, S3, or an external drive so your encrypted backups stay safe everywhere.".to_owned(),
                        0.0,
                    )
                } else if jobs.is_empty() {
                    let loc_word = if remotes_count == 1 {
                        "location"
                    } else {
                        "locations"
                    };
                    (
                        "Encrypted backup is ready",
                        format!(
                            "Connected to {remotes_count} cloud storage {loc_word}. Add a folder from this PC to protect it automatically."
                        ),
                        1.0,
                    )
                } else if let Some(ref rep) = snap.last_backup_report {
                    let prefix = if rep.preview {
                        "Preview complete"
                    } else {
                        "Encrypted backup is ready"
                    };
                    (prefix, rep.message.clone(), 1.0)
                } else {
                    let folder_word = if jobs.len() == 1 {
                        "folder"
                    } else {
                        "folders"
                    };
                    let cloud_word = if remotes_count == 1 {
                        "cloud"
                    } else {
                        "clouds"
                    };
                    (
                        "Encrypted backup is ready",
                        format!(
                            "Protecting {} PC {folder_word} across {remotes_count} connected {cloud_word}.",
                            jobs.len(),
                        ),
                        1.0,
                    )
                };

                let is_narrow = ui.available_width() < 620.0;
                if is_narrow {
                    ui.label(
                        RichText::new(status_title)
                            .font(semibold_font(ctx, 19.5))
                            .color(pal.ink),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(status_detail)
                            .font(FontId::proportional(13.2))
                            .color(pal.muted),
                    );
                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        if remotes_count == 0 {
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Plus),
                                "Connect a cloud",
                            )
                            .clicked()
                            {
                                wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                            }
                        } else {
                            ui.add_enabled_ui(!jobs.is_empty() && !is_running, |ui| {
                                if primary_button(ui, pal, Some(Icon::Upload), "Back up all")
                                    .clicked()
                                {
                                    worker.send(UiCommand::RunAllBackups { preview: false });
                                }
                            });

                            let pause_lbl = if backups_paused { "Resume" } else { "Pause" };
                            let pause_ic = if backups_paused {
                                Icon::Play
                            } else {
                                Icon::Pause
                            };
                            if secondary_button(ui, pal, Some(pause_ic), pause_lbl).clicked() {
                                worker.send(UiCommand::SetBackupsPaused {
                                    paused: !backups_paused,
                                });
                            }

                            if is_running
                                && danger_button(ui, pal, Some(Icon::Stop), "Stop").clicked()
                            {
                                worker.send(UiCommand::CancelActiveBackup);
                            }
                        }
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_max_width((ui.available_width() - 260.0).max(260.0));
                            ui.label(
                                RichText::new(status_title)
                                    .font(semibold_font(ctx, 19.5))
                                    .color(pal.ink),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(status_detail)
                                    .font(FontId::proportional(13.2))
                                    .color(pal.muted),
                            );
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if remotes_count == 0 {
                                if primary_button(
                                    ui,
                                    pal,
                                    Some(Icon::Plus),
                                    "Connect a cloud",
                                )
                                .clicked()
                                {
                                    wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                                }
                            } else {
                                if is_running
                                    && danger_button(ui, pal, Some(Icon::Stop), "Stop").clicked()
                                {
                                    worker.send(UiCommand::CancelActiveBackup);
                                }

                                let pause_lbl = if backups_paused { "Resume" } else { "Pause" };
                                let pause_ic = if backups_paused {
                                    Icon::Play
                                } else {
                                    Icon::Pause
                                };
                                if secondary_button(ui, pal, Some(pause_ic), pause_lbl).clicked() {
                                    worker.send(UiCommand::SetBackupsPaused {
                                        paused: !backups_paused,
                                    });
                                }

                                ui.add_enabled_ui(!jobs.is_empty() && !is_running, |ui| {
                                    if primary_button(ui, pal, Some(Icon::Upload), "Back up all")
                                        .clicked()
                                    {
                                        worker.send(UiCommand::RunAllBackups { preview: false });
                                    }
                                });
                            }
                        });
                    });
                }

                ui.add_space(12.0);
                progress_bar_clean(ui, pal, progress_val, 5.0);
            });

            ui.add_space(18.0);

            // 3. Protected PC Folders Section Header
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("PROTECTED FOLDERS")
                        .font(semibold_font(ctx, 11.5))
                        .color(pal.muted),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let count_str = if jobs.len() == 1 {
                        "1 folder".to_owned()
                    } else {
                        format!("{} folders", jobs.len())
                    };
                    ui.label(
                        RichText::new(count_str)
                            .font(FontId::proportional(12.2))
                            .color(pal.muted),
                    );
                });
            });

            ui.add_space(8.0);

            // 4. Empty State vs Protected PC Folder Cards
            if jobs.is_empty() {
                card_frame(pal)
                    .inner_margin(egui::Margin::symmetric(28.0, 30.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("A little setup. A lot of peace of mind.")
                                .font(semibold_font(ctx, 21.0))
                                .color(pal.ink),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "1. Connect Google Drive, OneDrive, Dropbox, or another cloud.\n2. Choose a folder on this PC and a backup schedule.\n3. EntroCloud keeps working quietly in your system tray.",
                            )
                            .font(FontId::proportional(14.0))
                            .color(pal.muted),
                        );
                        ui.add_space(14.0);
                        ui.label(
                            RichText::new(
                                "File contents and filenames are encrypted on your PC before upload. Conflict copies stay safe when files change.",
                            )
                            .font(semibold_font(ctx, 13.0))
                            .color(pal.primary_btn),
                        );
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Plus),
                                "Add your first folder",
                            )
                            .clicked()
                            {
                                job_modal.open_for_new();
                            }
                            if remotes_count == 0
                                && secondary_button(
                                    ui,
                                    pal,
                                    Some(Icon::CloudPlus),
                                    "Connect a cloud",
                                )
                                .clicked()
                            {
                                wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                            }
                        });
                    });
            } else {
                for job in jobs {
                    let is_selected = selected_job_id.as_deref() == Some(job.id.as_str());
                    if render_job_card(ctx, ui, pal, job, is_selected).clicked() {
                        *selected_job_id = Some(job.id.clone());
                    }
                    ui.add_space(8.0);
                }

                // Selected Folder Action Bar (modeled directly on CloudBridge's JobActions WrapPanel!)
                if let Some(sel_job) = selected_job_id
                    .as_deref()
                    .and_then(|id| jobs.iter().find(|j| j.id == id))
                {
                    let sel_clone = sel_job.clone();
                    let any_running = active_activity.is_some()
                        || snap.backup_request_inflight
                        || jobs
                            .iter()
                            .any(|j| j.status.to_ascii_lowercase().contains("backing up"));
                    ui.add_space(4.0);
                    sub_card_frame(pal).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("Selected: {}", sel_clone.name))
                                    .font(semibold_font(ctx, 13.0))
                                    .color(pal.ink),
                            );
                            ui.add_space(6.0);

                            ui.add_enabled_ui(!any_running, |ui| {
                                let run_lbl = if any_running {
                                    "Backing up..."
                                } else {
                                    "Back up"
                                };
                                if primary_button(ui, pal, Some(Icon::Upload), run_lbl).clicked() {
                                    worker.send(UiCommand::RunBackupJob {
                                        id: sel_clone.id.clone(),
                                        preview: false,
                                    });
                                }
                            });
                            if any_running
                                && danger_button(ui, pal, Some(Icon::Stop), "Stop").clicked()
                            {
                                worker.send(UiCommand::CancelActiveBackup);
                            }
                            ui.add_enabled_ui(!any_running, |ui| {
                                if secondary_button(ui, pal, Some(Icon::Search), "Preview")
                                    .clicked()
                                {
                                    worker.send(UiCommand::RunBackupJob {
                                        id: sel_clone.id.clone(),
                                        preview: true,
                                    });
                                }
                            });
                            if secondary_button(ui, pal, Some(Icon::Download), "Restore...")
                                .clicked()
                            {
                                restore_modal.open = true;
                                restore_modal.job_id = sel_clone.id.clone();
                                restore_modal.job_name = sel_clone.name.clone();
                                if restore_modal.destination_parent.is_empty() {
                                    restore_modal.destination_parent = dirs::desktop_dir()
                                        .or_else(dirs::download_dir)
                                        .or_else(dirs::home_dir)
                                        .unwrap_or_else(std::env::temp_dir)
                                        .display()
                                        .to_string();
                                }
                                restore_modal.error = None;
                            }
                            if secondary_button(ui, pal, Some(Icon::Edit), "Edit").clicked() {
                                job_modal.open_for_edit(&sel_clone);
                            }
                            if secondary_button(ui, pal, Some(Icon::FolderOpen), "Open folder")
                                .clicked()
                            {
                                let _ = open_in_os_default_app(Path::new(&sel_clone.source_path));
                            }
                            if danger_button(ui, pal, Some(Icon::Trash), "Remove").clicked() {
                                *remove_confirm_job =
                                    Some((sel_clone.id.clone(), sel_clone.name.clone()));
                            }
                        });
                    });
                }
            }

            // Recent Restore Banner if user just restored a snapshot
            if let Some((ref folder, files, bytes)) = snap.last_restored_folder {
                ui.add_space(12.0);
                let restore_summary = format!(
                    "{files} {} ({}) decrypted into {folder}",
                    if files == 1 { "file" } else { "files" },
                    format_bytes_human(bytes),
                );
                egui::Frame::none()
                    .fill(pal.ok_bg)
                    .stroke(Stroke::new(1.0, pal.ok_fg.gamma_multiply(0.35)))
                    .rounding(Rounding::same(12.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                    .show(ui, |ui| {
                        let is_narrow = ui.available_width() < 620.0;
                        if is_narrow {
                            ui.horizontal(|ui| {
                                status_pill(ui, pal, Some(Icon::Check), "Restored", PillTone::Ok);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if icon_button(ui, pal, Icon::Close, "Dismiss").clicked() {
                                            worker.state.lock().last_restored_folder = None;
                                        }
                                    },
                                );
                            });
                            ui.add_space(6.0);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&restore_summary)
                                        .font(semibold_font(ctx, 13.0))
                                        .color(pal.ink),
                                )
                                .wrap(),
                            )
                            .on_hover_text(&restore_summary);
                            ui.add_space(8.0);
                            if secondary_button(
                                ui,
                                pal,
                                Some(Icon::FolderOpen),
                                "Open Restored Folder",
                            )
                            .clicked()
                            {
                                let _ = open_in_os_default_app(Path::new(folder));
                            }
                        } else {
                            input_row_with_right_widget(
                                ui,
                                |ui| {
                                    if icon_button(ui, pal, Icon::Close, "Dismiss").clicked() {
                                        worker.state.lock().last_restored_folder = None;
                                    }
                                    if secondary_button(
                                        ui,
                                        pal,
                                        Some(Icon::FolderOpen),
                                        "Open Restored Folder",
                                    )
                                    .clicked()
                                    {
                                        let _ = open_in_os_default_app(Path::new(folder));
                                    }
                                },
                                |ui, rem_w| {
                                    ui.set_max_width(rem_w);
                                    status_pill(
                                        ui,
                                        pal,
                                        Some(Icon::Check),
                                        "Restored",
                                        PillTone::Ok,
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&restore_summary)
                                                .font(semibold_font(ctx, 13.0))
                                                .color(pal.ink),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(&restore_summary);
                                },
                            );
                        }
                    });
            }

            ui.add_space(20.0);
        });

    // Modals owned by Backups view
    render_backup_job_modal(ctx, pal, worker, dialogs, job_modal);
    render_restore_modal(ctx, pal, worker, dialogs, restore_modal);
    render_remove_job_modal(ctx, pal, worker, remove_confirm_job);
}

fn render_job_card(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    job: &BackupJobSummary,
    selected: bool,
) -> egui::Response {
    let desired = Vec2::new(ui.available_width(), if job.last_error.is_some() { 108.0 } else { 90.0 });
    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    if ui.is_rect_visible(rect) {
        let hover_t = ctx.animate_bool_with_time(
            ui.id().with(("job_card_hover", &job.id)),
            resp.hovered() && !selected,
            0.12,
        );
        let (bg, border, bw) = if selected {
            (pal.card_bg, pal.primary_btn, 1.8)
        } else {
            let bg = Color32::from(egui::lerp(
                Rgba::from(pal.card_bg)..=Rgba::from(pal.card_sub_bg),
                hover_t,
            ));
            let border = Color32::from(egui::lerp(
                Rgba::from(pal.card_border)..=Rgba::from(pal.secondary_btn_border),
                hover_t,
            ));
            let bw = egui::lerp(1.0..=1.2, hover_t);
            (bg, border, bw)
        };
        ui.painter().rect_filled(rect, Rounding::same(12.0), bg);
        ui.painter()
            .rect_stroke(rect, Rounding::same(12.0), Stroke::new(bw, border));

        if selected {
            let bar = Rect::from_min_max(
                Pos2::new(rect.left() + 3.0, rect.top() + 14.0),
                Pos2::new(rect.left() + 6.5, rect.bottom() - 14.0),
            );
            ui.painter()
                .rect_filled(bar, Rounding::same(2.0), pal.primary_btn);
        }

        let ic_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 28.0, rect.top() + 30.0),
            Vec2::splat(24.0),
        );
        paint_icon(ui.painter(), ic_rect, Icon::Folder, pal.primary_btn);

        let left_inner = Rect::from_min_max(
            Pos2::new(rect.left() + 50.0, rect.top() + 14.0),
            Pos2::new((rect.right() - 210.0).max(rect.left() + 120.0), rect.bottom() - 12.0),
        );
        let mut left_ui = ui.new_child(egui::UiBuilder::new().max_rect(left_inner));
        left_ui.set_clip_rect(left_inner.intersect(ui.clip_rect()));
        left_ui.spacing_mut().item_spacing.y = 3.0;
        left_ui.add(
            egui::Label::new(
                RichText::new(&job.name)
                    .font(semibold_font(ctx, 16.5))
                    .color(pal.ink),
            )
            .truncate(),
        );
        left_ui
            .add(
                egui::Label::new(
                    RichText::new(&job.source_path)
                        .font(FontId::proportional(12.3))
                        .color(pal.muted),
                )
                .truncate(),
            )
            .on_hover_text(&job.source_path);
        let sched = if !job.enabled || job.interval_minutes == 0 {
            format!("Manual backup only  •  Vault: {}", job.vault_folder)
        } else if job.interval_minutes.is_multiple_of(60) && job.interval_minutes >= 60 {
            let hrs = job.interval_minutes / 60;
            if hrs == 1 {
                format!("Every hour  •  Vault: {}", job.vault_folder)
            } else {
                format!("Every {hrs} hours  •  Vault: {}", job.vault_folder)
            }
        } else if job.interval_minutes == 1 {
            format!("Every minute  •  Vault: {}", job.vault_folder)
        } else {
            format!(
                "Every {} minutes  •  Vault: {}",
                job.interval_minutes, job.vault_folder
            )
        };
        left_ui
            .add(
                egui::Label::new(
                    RichText::new(&sched)
                        .font(FontId::proportional(11.6))
                        .color(pal.muted),
                )
                .truncate(),
            )
            .on_hover_text(&sched);
        if let Some(err) = job.last_error.as_deref().filter(|s| !s.is_empty()) {
            let err_line = format!("Attention: {err}");
            left_ui
                .add(
                    egui::Label::new(
                        RichText::new(&err_line)
                            .font(FontId::proportional(11.6))
                            .color(pal.danger_fg),
                    )
                    .truncate(),
                )
                .on_hover_text(err);
        }

        // Right column: Status pill + Last backup timestamp
        let right_min_x = (rect.right() - 205.0).max(left_inner.max.x + 6.0);
        let right_max_x = (rect.right() - 18.0).max(right_min_x);
        let right_inner = Rect::from_min_max(
            Pos2::new(right_min_x, rect.top() + 14.0),
            Pos2::new(right_max_x, rect.bottom() - 12.0),
        );
        let mut right_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(right_inner)
                .layout(egui::Layout::top_down(egui::Align::Max)),
        );
        right_ui.set_clip_rect(right_inner.intersect(ui.clip_rect()));
        right_ui.spacing_mut().item_spacing.y = 4.0;
        let st_lower = job.status.to_ascii_lowercase();
        let (tone, ic) = if st_lower.contains("attention") || st_lower.contains("error") {
            (PillTone::Danger, Some(Icon::Alert))
        } else if st_lower.contains("paused") {
            (PillTone::Warn, Some(Icon::Pause))
        } else if st_lower.contains("backing") {
            (PillTone::Accent, Some(Icon::Refresh))
        } else {
            (PillTone::Ok, Some(Icon::Check))
        };
        status_pill(&mut right_ui, pal, ic, &job.status, tone);

        let last_str = match job.last_success_at {
            Some(ts) => format!("Last backup: {}", ts.format("%b %d, %H:%M UTC")),
            None => "Not backed up yet".to_owned(),
        };
        right_ui.label(
            RichText::new(last_str)
                .font(FontId::proportional(11.5))
                .color(pal.muted),
        );
        if job.last_files_synced > 0 || job.last_bytes_synced > 0 {
            let file_word = if job.last_files_synced == 1 {
                "file"
            } else {
                "files"
            };
            right_ui.label(
                RichText::new(format!(
                    "{} {file_word} ({})",
                    job.last_files_synced,
                    format_bytes_human(job.last_bytes_synced)
                ))
                .font(FontId::proportional(11.3))
                .color(pal.muted),
            );
        }
    }

    resp
}

fn render_backup_job_modal(
    ctx: &egui::Context,
    pal: &Palette,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    modal: &mut BackupJobModalState,
) {
    if !modal.open {
        return;
    }

    let title = if modal.editing_id.is_some() {
        "Edit Protected Folder"
    } else {
        "Add a Folder to Back Up"
    };

    let mut close_req = false;
    modal_dialog(
        ctx,
        pal,
        "ec_backup_job_modal",
        title,
        540.0,
        &mut close_req,
        |ui| {
            ui.label(
                RichText::new("Choose what matters")
                    .font(semibold_font(ctx, 17.5))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(
                    "File contents and filenames will be encrypted on this PC using your Master Password.",
                )
                .font(FontId::proportional(12.6))
                .color(pal.muted),
            );
            ui.add_space(12.0);

            form_label(ui, pal, "Local folder on this PC");
            let mut src_changed = false;
            input_row_with_right_widget(
                ui,
                |ui| {
                    if secondary_button(ui, pal, Some(Icon::FolderOpen), "Browse folders...")
                        .clicked()
                    {
                        dialogs.pick_folder(
                            ctx,
                            "Choose a folder to back up",
                            None,
                            DialogPurpose::BackupJobSourceFolder,
                        );
                    }
                },
                |ui, _rem_w| {
                    let src_hint = if cfg!(target_os = "windows") {
                        "e.g. C:\\Users\\You\\Documents"
                    } else {
                        "e.g. /home/you/Documents"
                    };
                    if ui
                        .add(text_input_single(&mut modal.source_path, src_hint))
                        .changed()
                    {
                        src_changed = true;
                    }
                },
            );
            if src_changed {
                modal.sync_derived_from_source_path();
            }

            ui.add_space(10.0);
            ui.columns(2, |cols| {
                form_label(&mut cols[0], pal, "Backup name");
                cols[0].add(text_input_single(&mut modal.name, "Documents"));
                form_label(&mut cols[1], pal, "Destination in vault");
                cols[1].add(text_input_single(
                    &mut modal.vault_folder,
                    "/Backups/Documents",
                ));
            });

            ui.add_space(10.0);
            form_label(ui, pal, "Schedule");
            ui.horizontal_wrapped(|ui| {
                for (mins, lbl) in [
                    (15u32, "Every 15 min"),
                    (60, "Hourly"),
                    (360, "Every 6 hours"),
                    (1440, "Daily"),
                    (0, "Manual only"),
                ] {
                    let sel = modal.interval_minutes == mins;
                    if small_button(ui, pal, None, lbl, sel).clicked() {
                        modal.interval_minutes = mins;
                        modal.custom_minutes = mins.to_string();
                        modal.enabled = mins != 0;
                    }
                }
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut modal.custom_minutes)
                            .margin(Margin::symmetric(8.0, 5.5))
                            .desired_width(68.0)
                            .hint_text("Min"),
                    )
                    .changed()
                    && let Ok(parsed) = modal.custom_minutes.trim().parse::<u32>()
                {
                    modal.interval_minutes = parsed;
                    modal.enabled = parsed != 0;
                }
            });

            ui.add_space(10.0);
            form_label(ui, pal, "Ignore temporary files (one pattern per line)");
            ui.add(
                egui::TextEdit::multiline(&mut modal.excludes_text)
                    .margin(Margin::symmetric(10.0, 8.0))
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(8.0);
            if ui
                .checkbox(
                    &mut modal.enabled,
                    "Back up automatically while EntroCloud is unlocked",
                )
                .changed()
                && modal.enabled
                && modal.interval_minutes == 0
            {
                modal.interval_minutes = 15;
                modal.custom_minutes = "15".to_owned();
            }

            if let Some(ref err) = modal.error {
                ui.add_space(6.0);
                ui.label(RichText::new(err).color(pal.danger_fg));
            }

            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if secondary_button(ui, pal, None, "Cancel").clicked() {
                    modal.open = false;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if primary_button(ui, pal, Some(Icon::Check), "Save backup").clicked() {
                        let name = modal.name.trim().to_owned();
                        let src = modal.source_path.trim().to_owned();
                        let vdest = if modal.vault_folder.trim().is_empty() {
                            format!("/Backups/{name}")
                        } else {
                            modal.vault_folder.trim().to_owned()
                        };
                        if name.is_empty() || src.is_empty() {
                            modal.error = Some(
                                "Choose a local folder and enter a backup name.".to_owned(),
                            );
                        } else {
                            match modal.custom_minutes.trim().parse::<u32>() {
                                Ok(mins) => {
                                    modal.error = None;
                                    let excludes: Vec<String> = modal
                                        .excludes_text
                                        .lines()
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(str::to_owned)
                                        .collect();
                                    worker.send(UiCommand::UpsertBackupJob {
                                        spec: Box::new(BackupJobSpec {
                                            id: modal.editing_id.clone(),
                                            name,
                                            source_path: src,
                                            vault_folder: vdest,
                                            interval_minutes: mins,
                                            enabled: modal.enabled,
                                            excludes,
                                        }),
                                    });
                                    modal.open = false;
                                }
                                Err(_) => {
                                    modal.error = Some(
                                        "Enter a valid number of minutes (0 for manual).".into(),
                                    );
                                }
                            }
                        }
                    }
                });
            });
        },
    );
    if close_req {
        modal.open = false;
    }
}

fn render_restore_modal(
    ctx: &egui::Context,
    pal: &Palette,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    modal: &mut RestoreModalState,
) {
    if !modal.open {
        return;
    }

    let mut close_req = false;
    modal_dialog(
        ctx,
        pal,
        "ec_restore_backup_modal",
        "Restore Encrypted Backup",
        500.0,
        &mut close_req,
        |ui| {
            ui.label(
                RichText::new(format!("Restore '{}'", modal.job_name))
                    .font(semibold_font(ctx, 17.0))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(
                    "EntroCloud will decrypt and verify every file into a clean new subfolder inside the location you choose — never overwriting your current files.",
                )
                .font(FontId::proportional(12.6))
                .color(pal.muted),
            );
            ui.add_space(12.0);

            form_label(ui, pal, "Restore into parent folder on this PC");
            input_row_with_right_widget(
                ui,
                |ui| {
                    if secondary_button(ui, pal, Some(Icon::FolderOpen), "Choose folder...")
                        .clicked()
                    {
                        dialogs.pick_folder(
                            ctx,
                            "Choose destination folder for restored backup",
                            None,
                            DialogPurpose::RestoreDestinationParent {
                                job_id: modal.job_id.clone(),
                                job_name: modal.job_name.clone(),
                            },
                        );
                    }
                },
                |ui, _rem_w| {
                    let restore_hint = if cfg!(target_os = "windows") {
                        "e.g. C:\\Users\\You\\Desktop"
                    } else {
                        "e.g. /home/you/Desktop"
                    };
                    ui.add(text_input_single(&mut modal.destination_parent, restore_hint));
                },
            );

            if let Some(ref err) = modal.error {
                ui.add_space(6.0);
                ui.label(RichText::new(err).color(pal.danger_fg));
            }

            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if secondary_button(ui, pal, None, "Cancel").clicked() {
                    modal.open = false;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if primary_button(
                        ui,
                        pal,
                        Some(Icon::Download),
                        "Restore Decrypted Copy",
                    )
                    .clicked()
                    {
                        let dest = modal.destination_parent.trim().to_owned();
                        if dest.is_empty() {
                            modal.error = Some("Choose a destination folder first.".to_owned());
                        } else {
                            worker.send(UiCommand::RestoreBackupJob {
                                id: modal.job_id.clone(),
                                destination_parent: dest,
                            });
                            modal.open = false;
                        }
                    }
                });
            });
        },
    );
    if close_req {
        modal.open = false;
    }
}

fn render_remove_job_modal(
    ctx: &egui::Context,
    pal: &Palette,
    worker: &UiWorkerHandle,
    target: &mut Option<(String, String)>,
) {
    let Some((job_id, job_name)) = target.clone() else {
        return;
    };

    let mut close_req = false;
    modal_dialog(
        ctx,
        pal,
        "ec_remove_backup_modal",
        "Remove Backup Schedule",
        440.0,
        &mut close_req,
        |ui| {
            ui.label(
                RichText::new(format!("Stop automatic backup for '{job_name}'?"))
                    .font(semibold_font(ctx, 16.5))
                    .color(pal.ink),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Your original files on this PC and all encrypted copies already stored in your vault remain completely intact.",
                )
                .font(FontId::proportional(12.5))
                .color(pal.muted),
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if secondary_button(ui, pal, None, "Keep Schedule").clicked() {
                    *target = None;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if danger_button(ui, pal, Some(Icon::Trash), "Remove Schedule").clicked() {
                        worker.send(UiCommand::RemoveBackupJob { id: job_id });
                        *target = None;
                    }
                });
            });
        },
    );
    if close_req {
        *target = None;
    }
}

/// Parses `(done/total` progress strings (such as `"Backing up Docs (142/640 files)…"`) into `0.04..=0.99`.
fn parse_activity_progress_fraction(activity: &str) -> Option<f32> {
    let open_paren = activity.rfind('(')?;
    let inside = &activity[open_paren + 1..];
    let slash = inside.find('/')?;
    let done_str = inside[..slash].trim();
    let rest = &inside[slash + 1..];
    let total_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let total_str = rest[..total_end].trim();
    let done: u64 = done_str.parse().ok()?;
    let total: u64 = total_str.parse().ok()?;
    if total == 0 {
        return Some(1.0);
    }
    Some(((done as f32) / (total as f32)).clamp(0.04, 0.99))
}
