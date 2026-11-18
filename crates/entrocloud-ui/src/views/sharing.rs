//! `Sharing` view — Plain-English **Create Private Share Link (`ec://`)**, **Accept Shared Link**,
//! and **Shared Team Vault Access** cards, with post-quantum cryptographic details (`ML-KEM-768`,
//! `Ed25519`, security epoch) neatly tucked inside a collapsible `Technical Details` section.

use std::time::{Duration, Instant};

use eframe::egui::{self, FontId, Margin, RichText, Sense, Vec2};
use entrocloud_types::CapabilityUri;
use zeroize::{Zeroize, Zeroizing};

use crate::icons::{Icon, paint_icon};
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, input_row_with_right_widget,
    modal_dialog, primary_button, secondary_button, semibold_font, small_button, status_pill,
    sub_card_frame, text_input_single,
};
use crate::views::FrameSnapshot;
use crate::worker::{UiCommand, UiWorkerHandle};

/// State for the `Accept Shared Link` form & `--open-uri` modal.
#[derive(Debug, Clone)]
pub struct ShareImportModalState {
    pub open: bool,
    pub uri: Zeroizing<String>,
    pub dest_virtual_path: String,
}

impl Default for ShareImportModalState {
    fn default() -> Self {
        Self {
            open: false,
            uri: Zeroizing::new(String::new()),
            dest_virtual_path: "/Shared/received_file".to_owned(),
        }
    }
}

/// Interactive state for the `Sharing` view.
pub struct SharingViewState {
    pub share_source_vpath: String,
    pub accept_uri: Zeroizing<String>,
    pub accept_dest_vpath: String,
    pub invite_label: String,
    pub member_invite_input: String,
    pub copied_link_notice: Option<(String, Instant)>,
    pub copied_invite_notice: Option<(String, Instant)>,
    pub revoke_confirm_recipient: Option<String>,
}

impl Default for SharingViewState {
    fn default() -> Self {
        Self {
            share_source_vpath: String::new(),
            accept_uri: Zeroizing::new(String::new()),
            accept_dest_vpath: "/Shared/received_file".to_owned(),
            invite_label: "My PC".to_owned(),
            member_invite_input: String::new(),
            copied_link_notice: None,
            copied_invite_notice: None,
            revoke_confirm_recipient: None,
        }
    }
}

impl SharingViewState {
    pub fn zeroize_secrets(&mut self) {
        self.accept_uri.zeroize();
    }
}

/// Renders the `Sharing` cards inside `ui` (used both standalone in `NavPage::Sharing` and in
/// the side-by-side showcase).
pub fn render_sharing_cards(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    state: &mut SharingViewState,
) {
    let now = Instant::now();
    if state
        .copied_link_notice
        .as_ref()
        .is_some_and(|(_, at)| now.duration_since(*at) >= Duration::from_secs(3))
    {
        state.copied_link_notice = None;
    }
    if state
        .copied_invite_notice
        .as_ref()
        .is_some_and(|(_, at)| now.duration_since(*at) >= Duration::from_secs(3))
    {
        state.copied_invite_notice = None;
    }
    if state.copied_link_notice.is_some() || state.copied_invite_notice.is_some() {
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    // Card 1: Create Private Share Link (ec://)
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, Icon::ShareLink, pal.primary_btn);
            ui.label(
                RichText::new("Create Private Share Link (ec://)")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
            if let Some((ref msg, _)) = state.copied_link_notice {
                status_pill(ui, pal, Some(Icon::Check), msg, PillTone::Ok);
            }
        });
        ui.label(
            RichText::new(
                "Share a read-only encrypted copy of any file in your vault. The decryption key stays inside the # link fragment on your device and is never sent to any server.",
            )
            .font(FontId::proportional(12.6))
            .color(pal.muted),
        );
        ui.add_space(10.0);

        form_label(ui, pal, "File inside your vault");
        let can_create = !state.share_source_vpath.trim().is_empty();
        let create_clicked = input_row_with_right_widget(
            ui,
            |ui| {
                ui.add_enabled_ui(can_create, |ui| {
                    primary_button(ui, pal, Some(Icon::ShareLink), "Create Share Link").clicked()
                })
                .inner
            },
            |ui, _rem_w| {
                ui.add(text_input_single(
                    &mut state.share_source_vpath,
                    "/Documents/Report.pdf",
                ));
            },
        );
        if create_clicked {
            let target = state.share_source_vpath.trim();
            if !target.is_empty() {
                worker.send(UiCommand::CreateCapabilityShare {
                    virtual_path: target.to_owned(),
                });
            }
        }

        if let Some((_, ref uri_secret)) = snap.latest_share_uri {
            ui.add_space(10.0);
            sub_card_frame(pal).show(ui, |ui| {
                ui.horizontal(|ui| {
                    status_pill(ui, pal, Some(Icon::Check), "Link Ready", PillTone::Ok);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, pal, Some(Icon::Copy), "Copy Private Link").clicked()
                        {
                            ctx.copy_text((**uri_secret).clone());
                            state.copied_link_notice =
                                Some(("Copied ec:// link".to_owned(), Instant::now()));
                        }
                    });
                });
                ui.add_space(4.0);
                let mut preview_copy = (**uri_secret).clone();
                ui.add(
                    egui::TextEdit::multiline(&mut preview_copy)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .interactive(false)
                        .font(FontId::monospace(11.2)),
                );
                preview_copy.zeroize();
            });
        }
    });

    ui.add_space(12.0);

    // Card 2: Accept Shared Link (ec:// or legacy zv://)
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, Icon::Download, pal.primary_btn);
            ui.label(
                RichText::new("Accept Shared Link")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
        });
        ui.label(
            RichText::new(
                "Paste an ec:// (or legacy zv://) private link someone shared with you to verify its signature and save a copy into your vault.",
            )
            .font(FontId::proportional(12.6))
            .color(pal.muted),
        );
        ui.add_space(10.0);

        form_label(ui, pal, "Private Share Link");
        ui.add(text_input_single(&mut state.accept_uri, "ec://share/v1/..."));

        let trimmed_uri = state.accept_uri.trim();
        let uri_valid = if trimmed_uri.is_empty() {
            false
        } else {
            ui.add_space(4.0);
            match CapabilityUri::parse(trimmed_uri) {
                Ok(_) => {
                    status_pill(
                        ui,
                        pal,
                        Some(Icon::Check),
                        "Valid private share link",
                        PillTone::Ok,
                    );
                    true
                }
                Err(_) => {
                    ui.label(
                        RichText::new("Check that the full ec:// link including #... was pasted.")
                            .font(FontId::proportional(11.8))
                            .color(pal.danger_fg),
                    );
                    false
                }
            }
        };

        ui.add_space(8.0);
        form_label(ui, pal, "Save into vault path");
        let can_save = uri_valid && !state.accept_dest_vpath.trim().is_empty();
        let save_clicked = input_row_with_right_widget(
            ui,
            |ui| {
                ui.add_enabled_ui(can_save, |ui| {
                    primary_button(ui, pal, Some(Icon::Download), "Save to Vault").clicked()
                })
                .inner
            },
            |ui, _rem_w| {
                ui.add(text_input_single(
                    &mut state.accept_dest_vpath,
                    "/Shared/received_file",
                ));
            },
        );
        let trimmed_uri_after = state.accept_uri.trim();
        if save_clicked
            && CapabilityUri::parse(trimmed_uri_after).is_ok()
            && !state.accept_dest_vpath.trim().is_empty()
        {
            let copy = Zeroizing::new(trimmed_uri_after.to_owned());
            state.accept_uri.zeroize();
            worker.send(UiCommand::ImportCapabilityShare {
                uri: copy,
                dest_virtual_path: state.accept_dest_vpath.trim().to_owned(),
                refresh_dir: snap.current_dir.clone(),
            });
        }
    });

    ui.add_space(12.0);

    // Card 3: Shared Team Vault Access
    card_frame(pal).show(ui, |ui| {
        let epoch = snap
            .keybox_info
            .as_ref()
            .map(|k| k.epoch)
            .or_else(|| snap.status.as_ref().map(|s| s.keybox_epoch))
            .unwrap_or(0);

        ui.horizontal(|ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, Icon::Users, pal.primary_btn);
            ui.label(
                RichText::new("Shared Team Vault Access")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
            if epoch > 0 {
                status_pill(ui, pal, Some(Icon::Check), "Active", PillTone::Ok);
            }
            if let Some((ref msg, _)) = state.copied_invite_notice {
                status_pill(ui, pal, Some(Icon::Check), msg, PillTone::Ok);
            }
        });
        ui.label(
            RichText::new(
                "Invite family members or teammates to a shared vault folder without sharing your personal Master Password.",
            )
            .font(FontId::proportional(12.6))
            .color(pal.muted),
        );
        ui.add_space(10.0);

        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.invite_label)
                    .margin(Margin::symmetric(10.0, 6.5))
                    .desired_width(140.0)
                    .hint_text("Your name or PC"),
            );
            if secondary_button(ui, pal, Some(Icon::Sparkles), "Generate My Invite Code").clicked()
            {
                worker.send(UiCommand::ExportRecipientBundle {
                    label: state.invite_label.trim().to_owned(),
                });
            }
            if epoch == 0
                && secondary_button(ui, pal, Some(Icon::Users), "Enable Team Access").clicked()
            {
                worker.send(UiCommand::InitKeybox);
            }
        });

        if let Some((ref rcpt_id, ref bundle_b64)) = snap.recipient_bundle {
            ui.add_space(8.0);
            sub_card_frame(pal).show(ui, |ui| {
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        if small_button(ui, pal, Some(Icon::Copy), "Copy Invite Code", false)
                            .clicked()
                        {
                            ctx.copy_text(bundle_b64.clone());
                            state.copied_invite_notice =
                                Some(("Copied invite code".to_owned(), Instant::now()));
                        }
                    },
                    |ui, rem_w| {
                        ui.set_max_width(rem_w);
                        let lbl = format!("Your Invite ID: {rcpt_id}");
                        ui.add(
                            egui::Label::new(
                                RichText::new(&lbl)
                                    .font(semibold_font(ctx, 12.2))
                                    .color(pal.ink),
                            )
                            .truncate(),
                        )
                        .on_hover_text(rcpt_id);
                    },
                );
            });
        }

        ui.add_space(8.0);
        form_label(ui, pal, "Add a Member by Invite Code");
        let can_grant = epoch > 0 && !state.member_invite_input.trim().is_empty();
        let grant_clicked = input_row_with_right_widget(
            ui,
            |ui| {
                ui.add_enabled_ui(can_grant, |ui| {
                    primary_button(ui, pal, Some(Icon::Plus), "Grant Access").clicked()
                })
                .inner
            },
            |ui, _rem_w| {
                ui.add(text_input_single(
                    &mut state.member_invite_input,
                    "Paste member invite code...",
                ));
            },
        );
        if grant_clicked && epoch > 0 {
            let b64 = state.member_invite_input.trim().to_owned();
            if !b64.is_empty() {
                state.member_invite_input.clear();
                worker.send(UiCommand::GrantKeyboxRecipient {
                    recipient_bundle_b64: b64,
                });
            }
        }

        if let Some(ref kb) = snap.keybox_info
            && !kb.recipient_ids.is_empty()
        {
            ui.add_space(8.0);
            form_label(ui, pal, "Authorized Members");
            for rid in &kb.recipient_ids {
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Remove Access").clicked() {
                            state.revoke_confirm_recipient = Some(rid.clone());
                        }
                    },
                    |ui, rem_w| {
                        ui.set_max_width(rem_w);
                        ui.add(
                            egui::Label::new(
                                RichText::new(rid)
                                    .font(FontId::monospace(11.8))
                                    .color(pal.ink),
                            )
                            .truncate(),
                        )
                        .on_hover_text(rid);
                    },
                );
            }
        }

        ui.add_space(8.0);
        egui::CollapsingHeader::new(
            RichText::new("Technical Details")
                .font(FontId::proportional(12.2))
                .color(pal.muted),
        )
        .id_salt("sharing_technical_details")
        .show(ui, |ui| {
            sub_card_frame(pal).show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Post-quantum hybrid key wrapping: X25519 ECDH + NIST FIPS 203 ML-KEM-768, authenticated with owner Ed25519 signatures and monotonic rollback-protected epochs.",
                    )
                    .font(FontId::proportional(11.8))
                    .color(pal.muted),
                );
                if let Some(ref kb) = snap.keybox_info {
                    ui.monospace(format!(
                        "Security Epoch: {}  •  Owner Key: {}...",
                        kb.epoch,
                        kb.owner_pubkey_hex.get(..16).unwrap_or(&kb.owner_pubkey_hex)
                    ));
                }
            });
        });
    });

    // Destructive Remove Access confirmation modal
    if let Some(recipient_id) = state.revoke_confirm_recipient.clone() {
        let mut close_req = false;
        modal_dialog(
            ctx,
            pal,
            "ec_revoke_recipient_modal",
            "Remove Member Access",
            440.0,
            &mut close_req,
            |ui| {
                ui.label(
                    RichText::new("Revoke shared vault access for this member?")
                        .font(semibold_font(ctx, 16.0))
                        .color(pal.ink),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(&recipient_id)
                            .font(FontId::monospace(11.8))
                            .color(pal.muted),
                    )
                    .wrap(),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "This rotates the team vault security epoch so the removed member can no longer decrypt future updates.",
                    )
                    .font(FontId::proportional(12.4))
                    .color(pal.muted),
                );
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.revoke_confirm_recipient = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Remove Access").clicked() {
                            worker.send(UiCommand::RevokeKeyboxRecipient { recipient_id });
                            state.revoke_confirm_recipient = None;
                        }
                    });
                });
            },
        );
        if close_req {
            state.revoke_confirm_recipient = None;
        }
    }
}

/// Renders the full scrollable `Sharing` view.
pub fn render_sharing_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    state: &mut SharingViewState,
) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            render_sharing_cards(ctx, ui, pal, snap, worker, state);
            ui.add_space(20.0);
        });
}
