//! Centered calm Unlock Card shown when an initialized vault is currently locked.

use eframe::egui::{self, FontId, Key, Margin, RichText, Rounding, Sense, Stroke, Vec2};
use zeroize::Zeroizing;

use crate::icons::{Icon, paint_brand_mark, paint_icon};
use crate::theme::{
    Palette, card_frame, form_label, icon_button, input_row_with_right_widget, primary_button,
    secondary_button, semibold_font, small_button, sub_card_frame,
};
use crate::views::FrameSnapshot;
use crate::wizard::{WizardProvider, WizardState, WizardStep};
use crate::worker::{UiCommand, UiWorkerHandle};

/// Renders the centered CloudBridge / ZeroVault-style Unlock Card.
#[allow(clippy::too_many_arguments)]
pub fn render_unlock_screen(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    wizard: &mut WizardState,
    passphrase_input: &mut Zeroizing<String>,
    show_pass: &mut bool,
    unlock_error: &mut Option<String>,
    unlock_autofocused: &mut bool,
) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space((ui.available_height() * 0.12).clamp(24.0, 96.0));

            ui.vertical_centered(|ui| {
                ui.set_max_width(500.0);

                card_frame(pal).show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    ui.horizontal(|ui| {
                        let (logo_r, _) =
                            ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                        paint_brand_mark(ui.painter(), logo_r);
                        ui.add_space(6.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(
                                RichText::new("Unlock your vault")
                                    .font(semibold_font(ctx, 23.0))
                                    .color(pal.ink),
                            );
                            ui.label(
                                RichText::new("Enter your Master Password to open your files and resume automatic backups.")
                                    .font(FontId::proportional(13.0))
                                    .color(pal.muted),
                            );
                        });
                    });

                    ui.add_space(14.0);

                    if !snap.daemon_connected {
                        sub_card_frame(pal).show(ui, |ui| {
                            ui.label(
                                RichText::new("EntroCloud background service is not running yet.")
                                    .font(semibold_font(ctx, 13.5))
                                    .color(pal.ink),
                            );
                            ui.label(
                                RichText::new(
                                    "Click below to start the background service on this PC.",
                                )
                                .font(FontId::proportional(12.3))
                                .color(pal.muted),
                            );
                            ui.add_space(8.0);
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Refresh),
                                "Start Background Service",
                            )
                            .clicked()
                            {
                                worker.send(UiCommand::ReconnectOrAutostart {
                                    current_dir: "/".to_owned(),
                                });
                            }
                        });
                        ui.add_space(12.0);
                    }

                    sub_card_frame(pal).show(ui, |ui| {
                        ui.label(
                            RichText::new(
                                "Files and filenames stay encrypted on your computer before going to any cloud. EntroCloud keeps your password in memory only while unlocked.",
                            )
                            .font(FontId::proportional(12.5))
                            .color(pal.muted),
                        );
                    });

                    ui.add_space(14.0);
                    form_label(ui, pal, "Master Password");

                    let mut submit_now = false;
                    let mut clear_daemon_err = false;
                    let show_pw = *show_pass;
                    let unlocking = snap.unlock_inflight;
                    if unlocking {
                        *unlock_autofocused = false;
                    }
                    let toggle_pw = input_row_with_right_widget(
                        ui,
                        |ui| {
                            let eye = if show_pw { Icon::EyeOff } else { Icon::Eye };
                            icon_button(ui, pal, eye, "Show or hide password").clicked()
                        },
                        |ui, _rem_w| {
                            let edit = ui.add_enabled(
                                !unlocking,
                                egui::TextEdit::singleline(&mut **passphrase_input)
                                    .password(!show_pw)
                                    .margin(Margin::symmetric(10.0, 7.5))
                                    .desired_width(f32::INFINITY)
                                    .hint_text(if unlocking {
                                        "Verifying Master Password…"
                                    } else {
                                        "Enter your Master Password"
                                    }),
                            );
                            if !*unlock_autofocused && !unlocking {
                                edit.request_focus();
                                *unlock_autofocused = true;
                            }
                            if edit.changed() {
                                *unlock_error = None;
                                if snap.toast_error.is_some() {
                                    clear_daemon_err = true;
                                }
                            }
                            if !unlocking
                                && (edit.lost_focus() || edit.has_focus())
                                && ctx.input(|i| i.key_pressed(Key::Enter))
                            {
                                submit_now = true;
                            }
                        },
                    );
                    if toggle_pw {
                        *show_pass = !*show_pass;
                    }
                    if clear_daemon_err {
                        worker.state.lock().toast_error = None;
                    }

                    let active_err = unlock_error.as_deref().or(snap.toast_error.as_deref());
                    if !unlocking
                        && let Some(err_msg) = active_err
                    {
                        ui.add_space(8.0);
                        egui::Frame::none()
                            .fill(pal.danger_bg)
                            .stroke(Stroke::new(1.0, pal.danger_fg.gamma_multiply(0.35)))
                            .rounding(Rounding::same(8.0))
                            .inner_margin(Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    let (ic_r, _) =
                                        ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                                    paint_icon(ui.painter(), ic_r, Icon::Alert, pal.danger_fg);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(err_msg)
                                                .color(pal.danger_fg)
                                                .size(12.6),
                                        )
                                        .wrap(),
                                    );
                                });
                            });
                    }

                    if unlocking || snap.busy_task.is_some() {
                        let busy_msg = snap
                            .busy_task
                            .as_deref()
                            .unwrap_or("Unlocking your vault…");
                        ui.add_space(8.0);
                        egui::Frame::none()
                            .fill(pal.accent_soft_bg)
                            .stroke(Stroke::new(1.0, pal.primary_btn.gamma_multiply(0.35)))
                            .rounding(Rounding::same(8.0))
                            .inner_margin(Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    let (ic_r, _) =
                                        ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                                    paint_icon(
                                        ui.painter(),
                                        ic_r,
                                        Icon::Refresh,
                                        pal.accent_soft_fg,
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(busy_msg).color(pal.ink).size(12.6),
                                        )
                                        .wrap(),
                                    );
                                });
                            });
                    }

                    ui.add_space(16.0);
                    ui.horizontal_wrapped(|ui| {
                        let unlock_lbl = if unlocking {
                            "Unlocking Vault…"
                        } else {
                            "Unlock My Vault"
                        };
                        if ui
                            .add_enabled_ui(!unlocking, |ui| {
                                primary_button(ui, pal, Some(Icon::Unlock), unlock_lbl)
                            })
                            .inner
                            .clicked()
                        {
                            submit_now = true;
                        }
                        if secondary_button(ui, pal, Some(Icon::CloudPlus), "Connect a Cloud")
                            .clicked()
                        {
                            wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                        }
                        if small_button(ui, pal, Some(Icon::BookOpen), "Setup Guide", false)
                            .clicked()
                        {
                            wizard.open_full(WizardStep::Welcome);
                        }
                    });

                    if submit_now && !unlocking {
                        if passphrase_input.is_empty() {
                            *unlock_error = Some("Enter your Master Password first.".to_owned());
                        } else {
                            *unlock_error = None;
                            worker.state.lock().toast_error = None;
                            let secret = Zeroizing::new((**passphrase_input).clone());
                            zeroize::Zeroize::zeroize(&mut **passphrase_input);
                            worker.send(UiCommand::UnlockVault {
                                passphrase: secret,
                                current_dir: snap.current_dir.clone(),
                            });
                        }
                    }
                });
            });

            ui.add_space(24.0);
        });
}
