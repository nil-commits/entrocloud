//! `Cloud Connections` view — Connected cloud cards (`Healthy` pill, latency `ms`, quota bar,
//! `Test Connection`, `Remove`), `+ Connect a cloud` button, and plain-English Multi-Cloud
//! storage mode cards (*Combine Storage Space*, *Mirror Backup Copies*, *Organize by Folder*).

use std::collections::HashSet;

use eframe::egui::{self, FontId, Margin, RichText, Sense, Vec2};
use entrocloud_types::{RemoteAccountSummary, RoutingPolicy};

use crate::icons::{Icon, paint_icon};
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, interactive_card, modal_dialog,
    primary_button, progress_bar_clean, secondary_button, semibold_font, small_button,
    status_pill, sub_card_frame,
};
use crate::tray_common::format_bytes_human;
use crate::views::FrameSnapshot;
use crate::wizard::{WizardProvider, WizardState};
use crate::worker::{UiCommand, UiWorkerHandle};

/// Plain-English multi-cloud storage mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CloudWorkMode {
    #[default]
    CombineSpace,
    MirrorCopies,
    OrganizeByFolder,
}

/// Interactive state for the `Cloud Connections` view.
pub struct CloudsViewState {
    pub mode: CloudWorkMode,
    pub selected_backends: HashSet<String>,
    pub strict_mirror_wait_all: bool,
    pub default_backend: String,
    pub folder_rules: Vec<(String, String)>,
    pub new_rule_folder: String,
    pub new_rule_backend: String,
    pub rule_error: Option<String>,
    pub initialized_from_daemon: bool,
    pub remove_remote_confirm: Option<String>,
    last_synced_remote_ids: Vec<String>,
    last_synced_policy: Option<RoutingPolicy>,
}

impl Default for CloudsViewState {
    fn default() -> Self {
        Self {
            mode: CloudWorkMode::CombineSpace,
            selected_backends: HashSet::new(),
            strict_mirror_wait_all: true,
            default_backend: String::new(),
            folder_rules: Vec::new(),
            new_rule_folder: "/Photos".to_owned(),
            new_rule_backend: String::new(),
            rule_error: None,
            initialized_from_daemon: false,
            remove_remote_confirm: None,
            last_synced_remote_ids: Vec::new(),
            last_synced_policy: None,
        }
    }
}

impl CloudsViewState {
    pub fn sync_from_status(&mut self, remotes: &[RemoteAccountSummary], policy: Option<&RoutingPolicy>) {
        let cur_ids: Vec<String> = remotes.iter().map(|r| r.id.clone()).collect();
        let remotes_changed = cur_ids != self.last_synced_remote_ids;
        let policy_changed = policy != self.last_synced_policy.as_ref();

        if self.initialized_from_daemon && !remotes_changed && !policy_changed {
            return;
        }

        if remotes_changed {
            // Keep existing selections that still exist and automatically select newly added clouds
            let old_known: HashSet<&str> = self.last_synced_remote_ids.iter().map(String::as_str).collect();
            self.selected_backends.retain(|id| cur_ids.iter().any(|c| c == id));
            self.folder_rules
                .retain(|(_, backend)| cur_ids.iter().any(|c| c == backend));
            for r in remotes {
                if !old_known.contains(r.id.as_str()) {
                    self.selected_backends.insert(r.id.clone());
                }
            }
            if !cur_ids.iter().any(|c| c == &self.default_backend) {
                self.default_backend = cur_ids.first().cloned().unwrap_or_default();
            }
            if !cur_ids.iter().any(|c| c == &self.new_rule_backend) {
                self.new_rule_backend = cur_ids.first().cloned().unwrap_or_default();
            }
            self.last_synced_remote_ids = cur_ids;
        }

        if (!self.initialized_from_daemon || policy_changed)
            && let Some(pol) = policy
        {
            match pol {
                RoutingPolicy::QuotaPooled { pool_backends } => {
                    self.mode = CloudWorkMode::CombineSpace;
                    self.selected_backends = pool_backends.iter().cloned().collect();
                }
                RoutingPolicy::Mirrored { backends, min_ack } => {
                    self.mode = CloudWorkMode::MirrorCopies;
                    self.selected_backends = backends.iter().cloned().collect();
                    self.strict_mirror_wait_all = *min_ack >= backends.len().max(1);
                }
                RoutingPolicy::Targeted {
                    prefix_routes,
                    default_backend,
                } => {
                    self.mode = CloudWorkMode::OrganizeByFolder;
                    self.default_backend = default_backend.clone();
                    self.folder_rules = prefix_routes.clone();
                }
            }
            self.last_synced_policy = Some(pol.clone());
            self.initialized_from_daemon = true;
        }
    }
}

/// Renders the `Cloud Connections` view.
pub fn render_clouds_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    wizard: &mut WizardState,
    state: &mut CloudsViewState,
) {
    let remotes: &[RemoteAccountSummary] = snap
        .status
        .as_ref()
        .map_or(&[], |s| s.remotes.as_slice());

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Section Subtitle + Action
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - 180.0).max(160.0));
                    ui.label(
                        RichText::new(
                            "Store your encrypted backups in Google Drive, OneDrive, Dropbox, S3 / R2 / B2, NAS, or an external drive.",
                        )
                        .font(FontId::proportional(13.6))
                        .color(pal.muted),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
                });
            });

            ui.add_space(16.0);

            if remotes.is_empty() {
                card_frame(pal).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(18.0);
                        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                        paint_icon(ui.painter(), ic_r, Icon::CloudPlus, pal.primary_btn);
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("No cloud accounts connected yet")
                                .font(semibold_font(ctx, 19.0))
                                .color(pal.ink),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(
                                "Connect Google Drive, Microsoft OneDrive, Dropbox, Cloudflare R2, Backblaze B2, Nextcloud, or a synced PC folder.",
                            )
                            .font(FontId::proportional(13.2))
                            .color(pal.muted),
                        );
                        ui.add_space(14.0);
                        if primary_button(
                            ui,
                            pal,
                            Some(Icon::CloudPlus),
                            "Connect Your First Cloud",
                        )
                        .clicked()
                        {
                            wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                        }
                        ui.add_space(18.0);
                    });
                });
            } else {
                // Connected Cloud Cards
                for rem in remotes {
                    render_remote_card(ctx, ui, pal, rem, snap, worker, state);
                    ui.add_space(10.0);
                }

                ui.add_space(10.0);

                // How Should Your Clouds Work Together? Card
                let pending_policy = build_routing_policy(state, remotes);
                let daemon_policy = snap.status.as_ref().and_then(|s| s.routing_policy.as_ref());
                let has_unsaved_changes = match (&pending_policy, daemon_policy) {
                    (Some(p), Some(d)) => p != d,
                    (Some(_), None) => true,
                    (None, _) => true,
                };

                card_frame(pal).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("How Should Your Clouds Work Together?")
                                    .font(semibold_font(ctx, 18.5))
                                    .color(pal.ink),
                            );
                            let current_desc = match state.mode {
                                CloudWorkMode::CombineSpace => "Combine Storage Space",
                                CloudWorkMode::MirrorCopies => "Mirror Backup Copies",
                                CloudWorkMode::OrganizeByFolder => "Organize by Folder",
                            };
                            if has_unsaved_changes {
                                ui.label(
                                    RichText::new(format!("Unsaved changes: {current_desc}"))
                                        .font(semibold_font(ctx, 12.6))
                                        .color(pal.warn_fg),
                                );
                            } else {
                                ui.label(
                                    RichText::new(format!("Active preference: {current_desc}"))
                                        .font(FontId::proportional(12.6))
                                        .color(pal.muted),
                                );
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_enabled_ui(pending_policy.is_some(), |ui| {
                                if primary_button(ui, pal, Some(Icon::Check), "Save Changes")
                                    .clicked()
                                    && let Some(policy) = pending_policy.clone()
                                {
                                    worker.send(UiCommand::SetRoutingPolicy { policy });
                                }
                            });
                        });
                    });

                    ui.add_space(12.0);
                    ui.spacing_mut().item_spacing.x = 12.0;
                    ui.columns(3, |cols| {
                        if policy_mode_card(
                            &mut cols[0],
                            pal,
                            Icon::CloudPlus,
                            "Combine Storage Space",
                            "Pool all connected clouds together so you get more total free space automatically.",
                            state.mode == CloudWorkMode::CombineSpace,
                        )
                        .clicked()
                        {
                            state.mode = CloudWorkMode::CombineSpace;
                        }
                        if policy_mode_card(
                            &mut cols[1],
                            pal,
                            Icon::Copy,
                            "Mirror Backup Copies",
                            "Save identical encrypted copies to multiple clouds for extra peace of mind.",
                            state.mode == CloudWorkMode::MirrorCopies,
                        )
                        .clicked()
                        {
                            state.mode = CloudWorkMode::MirrorCopies;
                        }
                        if policy_mode_card(
                            &mut cols[2],
                            pal,
                            Icon::Folder,
                            "Organize by Folder",
                            "Send specific vault folders (such as /Photos or /Work) to chosen clouds.",
                            state.mode == CloudWorkMode::OrganizeByFolder,
                        )
                        .clicked()
                        {
                            state.mode = CloudWorkMode::OrganizeByFolder;
                        }
                    });

                    ui.add_space(12.0);
                    sub_card_frame(pal).show(ui, |ui| match state.mode {
                        CloudWorkMode::CombineSpace | CloudWorkMode::MirrorCopies => {
                            form_label(ui, pal, "Included Cloud Locations");
                            ui.horizontal_wrapped(|ui| {
                                for r in remotes {
                                    let mut checked = state.selected_backends.contains(&r.id);
                                    if ui.checkbox(&mut checked, &r.id).changed() {
                                        if checked {
                                            state.selected_backends.insert(r.id.clone());
                                        } else {
                                            state.selected_backends.remove(&r.id);
                                        }
                                    }
                                }
                            });
                            if state.selected_backends.is_empty() {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new("Select at least one cloud location to save.")
                                        .font(FontId::proportional(12.0))
                                        .color(pal.danger_fg),
                                );
                            }
                            if state.mode == CloudWorkMode::MirrorCopies {
                                ui.add_space(6.0);
                                ui.checkbox(
                                    &mut state.strict_mirror_wait_all,
                                    "Wait until every selected cloud finishes saving before marking complete",
                                );
                            }
                        }
                        CloudWorkMode::OrganizeByFolder => {
                            ui.horizontal(|ui| {
                                form_label(ui, pal, "Default Cloud for Everything Else:");
                                egui::ComboBox::from_id_salt("organize_default_cloud")
                                    .selected_text(&state.default_backend)
                                    .show_ui(ui, |ui| {
                                        for r in remotes {
                                            ui.selectable_value(
                                                &mut state.default_backend,
                                                r.id.clone(),
                                                &r.id,
                                            );
                                        }
                                    });
                            });
                            ui.add_space(6.0);
                            form_label(ui, pal, "Folder Rules");
                            let mut remove_idx = None;
                            for (idx, (prefix, backend)) in state.folder_rules.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("{prefix}  →  {backend}"))
                                            .font(semibold_font(ctx, 12.8))
                                            .color(pal.ink),
                                    );
                                    if small_button(ui, pal, Some(Icon::Trash), "Remove", false)
                                        .clicked()
                                    {
                                        remove_idx = Some(idx);
                                    }
                                });
                            }
                            if let Some(i) = remove_idx {
                                state.folder_rules.remove(i);
                                state.rule_error = None;
                            }
                            ui.horizontal(|ui| {
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(&mut state.new_rule_folder)
                                            .margin(Margin::symmetric(10.0, 6.5))
                                            .desired_width(150.0)
                                            .hint_text("/Photos"),
                                    )
                                    .changed()
                                {
                                    state.rule_error = None;
                                }
                                egui::ComboBox::from_id_salt("new_rule_cloud")
                                    .selected_text(&state.new_rule_backend)
                                    .show_ui(ui, |ui| {
                                        for r in remotes {
                                            ui.selectable_value(
                                                &mut state.new_rule_backend,
                                                r.id.clone(),
                                                &r.id,
                                            );
                                        }
                                    });
                                if small_button(ui, pal, Some(Icon::Plus), "Add Rule", false)
                                    .clicked()
                                {
                                    let raw = state.new_rule_folder.trim();
                                    let b = state.new_rule_backend.trim().to_owned();
                                    if !raw.is_empty() && !b.is_empty() {
                                        let p = if raw.starts_with('/') {
                                            raw.to_owned()
                                        } else {
                                            format!("/{raw}")
                                        };
                                        let duplicate = state
                                            .folder_rules
                                            .iter()
                                            .any(|(existing, _)| existing.eq_ignore_ascii_case(&p));
                                        if duplicate {
                                            state.rule_error = Some(format!(
                                                "A rule for '{p}' already exists."
                                            ));
                                        } else {
                                            state.folder_rules.push((p, b));
                                            state.rule_error = None;
                                        }
                                    }
                                }
                            });
                            if let Some(ref err) = state.rule_error {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(err)
                                        .font(FontId::proportional(11.8))
                                        .color(pal.danger_fg),
                                );
                            }
                        }
                    });
                });
            }

            ui.add_space(20.0);
        });

    // Remove Cloud Confirmation Modal
    if let Some(rem_id) = state.remove_remote_confirm.clone() {
        let mut close_req = false;
        modal_dialog(
            ctx,
            pal,
            "ec_disconnect_cloud_modal",
            "Disconnect Cloud Account",
            430.0,
            &mut close_req,
            |ui| {
                ui.label(
                    RichText::new(format!("Disconnect '{rem_id}' from this PC?"))
                        .font(semibold_font(ctx, 16.0))
                        .color(pal.ink),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Stored credentials on this PC will be removed. Encrypted files already uploaded to that cloud are not deleted.",
                    )
                    .font(FontId::proportional(12.4))
                    .color(pal.muted),
                );
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.remove_remote_confirm = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Disconnect").clicked() {
                            worker.send(UiCommand::RemoveRemote { id: rem_id });
                            state.remove_remote_confirm = None;
                        }
                    });
                });
            },
        );
        if close_req {
            state.remove_remote_confirm = None;
        }
    }
}

fn render_remote_card(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    rem: &RemoteAccountSummary,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    state: &mut CloudsViewState,
) {
    let is_testing = snap.testing_remotes.contains(&rem.id);
    let latest_test = snap.remote_tests.get(&rem.id);
    let healthy = latest_test.map_or(rem.health.healthy, |t| t.healthy);
    let latency = latest_test
        .map(|t| t.latency_ms)
        .or(rem.health.latency_ms);
    let quota = latest_test
        .map(|t| &t.quota)
        .unwrap_or(&rem.health.quota);

    card_frame(pal)
        .inner_margin(egui::Margin::symmetric(20.0, 16.0))
        .show(ui, |ui| {
            let is_narrow = ui.available_width() < 580.0;
            let folder_line = format!(
                "{}  •  Folder: {}",
                friendly_kind_label(&rem.kind),
                rem.root
            );
            ui.horizontal(|ui| {
                let icon = match rem.kind.as_str() {
                    "s3" | "webdav" => Icon::HardDrive,
                    "fs" => Icon::FolderOpen,
                    _ => Icon::Cloud,
                };
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);

                ui.vertical(|ui| {
                    let left_max_w = if is_narrow {
                        ui.available_width().max(120.0)
                    } else {
                        (ui.available_width() - 260.0).max(160.0)
                    };
                    ui.set_max_width(left_max_w);
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(&rem.id)
                                .font(semibold_font(ctx, 16.5))
                                .color(pal.ink),
                        );
                        if is_testing {
                            status_pill(
                                ui,
                                pal,
                                Some(Icon::Refresh),
                                "Testing...",
                                PillTone::Accent,
                            );
                        } else {
                            status_pill(
                                ui,
                                pal,
                                Some(if healthy { Icon::Check } else { Icon::Alert }),
                                if healthy { "Healthy" } else { "Needs attention" },
                                if healthy {
                                    PillTone::Ok
                                } else {
                                    PillTone::Danger
                                },
                            );
                        }
                        if let Some(ms) = latency {
                            status_pill(ui, pal, None, &format!("{ms} ms"), PillTone::Neutral);
                        }
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(&folder_line)
                                .font(FontId::proportional(12.3))
                                .color(pal.muted),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&rem.root);
                });

                if !is_narrow {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Remove").clicked() {
                            state.remove_remote_confirm = Some(rem.id.clone());
                        }
                        ui.add_enabled_ui(!is_testing, |ui| {
                            let test_lbl = if is_testing {
                                "Testing..."
                            } else {
                                "Test Connection"
                            };
                            if secondary_button(ui, pal, Some(Icon::Refresh), test_lbl).clicked() {
                                worker.send(UiCommand::TestRemote {
                                    id: rem.id.clone(),
                                });
                            }
                        });
                    });
                }
            });

            if is_narrow {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.add_enabled_ui(!is_testing, |ui| {
                        let test_lbl = if is_testing {
                            "Testing..."
                        } else {
                            "Test Connection"
                        };
                        if secondary_button(ui, pal, Some(Icon::Refresh), test_lbl).clicked() {
                            worker.send(UiCommand::TestRemote {
                                id: rem.id.clone(),
                            });
                        }
                    });
                    if danger_button(ui, pal, Some(Icon::Trash), "Remove").clicked() {
                        state.remove_remote_confirm = Some(rem.id.clone());
                    }
                });
            }

            ui.add_space(10.0);
            let frac = if quota.total_bytes > 0 {
                (quota.used_bytes as f32 / quota.total_bytes as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            progress_bar_clean(ui, pal, frac, 6.0);
            ui.add_space(4.0);
            let quota_txt = if quota.total_bytes > 0 {
                format!(
                    "{} used of {} ({} free)",
                    format_bytes_human(quota.used_bytes),
                    format_bytes_human(quota.total_bytes),
                    format_bytes_human(quota.available_bytes)
                )
            } else {
                format!("{} stored (no quota cap)", format_bytes_human(quota.used_bytes))
            };
            if is_narrow {
                ui.label(
                    RichText::new(quota_txt)
                        .font(FontId::proportional(11.8))
                        .color(pal.muted),
                );
                if is_testing {
                    ui.label(
                        RichText::new(format!("Testing connection to '{}'...", rem.id))
                            .font(semibold_font(ctx, 11.8))
                            .color(pal.primary_btn),
                    );
                } else if let Some(t) = latest_test {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&t.message)
                                .font(FontId::proportional(11.8))
                                .color(if t.healthy { pal.ok_fg } else { pal.danger_fg }),
                        )
                        .wrap(),
                    )
                    .on_hover_text(&t.message);
                }
            } else {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(quota_txt)
                            .font(FontId::proportional(11.8))
                            .color(pal.muted),
                    );
                    if is_testing {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("Testing connection to '{}'...", rem.id))
                                    .font(semibold_font(ctx, 11.8))
                                    .color(pal.primary_btn),
                            );
                        });
                    } else if let Some(t) = latest_test {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&t.message)
                                        .font(FontId::proportional(11.8))
                                        .color(if t.healthy { pal.ok_fg } else { pal.danger_fg }),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&t.message);
                        });
                    }
                });
            }
        });
}

fn friendly_kind_label(kind: &str) -> &'static str {
    match kind {
        "gdrive" => "Google Drive",
        "onedrive" => "Microsoft OneDrive",
        "dropbox" => "Dropbox",
        "s3" => "S3 / R2 / B2 Object Storage",
        "webdav" => "WebDAV / Nextcloud / NAS",
        "fs" => "Synced PC / External Folder",
        _ => "Cloud Storage",
    }
}

fn policy_mode_card(
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
        108.0,
        Vec2::new(13.0, 13.0),
        10.0,
        |ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
            ui.add_space(4.0);
            ui.label(
                RichText::new(title)
                    .font(semibold_font(ui.ctx(), 13.6))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(desc)
                    .font(FontId::proportional(11.9))
                    .color(pal.muted),
            );
        },
    )
}

fn build_routing_policy(
    state: &CloudsViewState,
    remotes: &[RemoteAccountSummary],
) -> Option<RoutingPolicy> {
    let chosen: Vec<String> = remotes
        .iter()
        .filter(|r| state.selected_backends.contains(&r.id))
        .map(|r| r.id.clone())
        .collect();

    match state.mode {
        CloudWorkMode::CombineSpace => {
            if chosen.is_empty() {
                return None;
            }
            Some(RoutingPolicy::QuotaPooled {
                pool_backends: chosen,
            })
        }
        CloudWorkMode::MirrorCopies => {
            if chosen.is_empty() {
                return None;
            }
            let min_ack = if state.strict_mirror_wait_all {
                chosen.len()
            } else {
                1
            };
            Some(RoutingPolicy::Mirrored {
                backends: chosen,
                min_ack,
            })
        }
        CloudWorkMode::OrganizeByFolder => {
            let default_backend = if state.default_backend.trim().is_empty() {
                remotes.first()?.id.clone()
            } else {
                state.default_backend.trim().to_owned()
            };
            Some(RoutingPolicy::Targeted {
                prefix_routes: state.folder_rules.clone(),
                default_backend,
            })
        }
    }
}
