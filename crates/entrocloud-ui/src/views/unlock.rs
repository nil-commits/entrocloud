//! Centered calm Unlock Card shown when an initialized vault is currently locked.

use eframe::egui::{self, FontId, Key, RichText, Sense, Vec2};
use zeroize::Zeroizing;

use crate::icons::{Icon, paint_brand_mark};
use crate::theme::{
    Palette, card_frame, form_label, icon_button, primary_button, secondary_button, semibold_font,
    small_button, sub_card_frame,
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
) {
    ui.add_space((ui.available_height() * 0.12).clamp(24.0, 96.0));

    ui.vertical_centered(|ui| {
        ui.set_max_width(500.0);

        card_frame(pal).show(ui, |ui| {
            ui.set_width(ui.available_width());

            ui.horizontal(|ui| {
                let (logo_r, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
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
                        RichText::new("Click below to start the background service on this PC.")
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
            ui.horizontal(|ui| {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut **passphrase_input)
                        .password(!*show_pass)
                        .desired_width(ui.available_width() - 42.0)
                        .hint_text("Enter your Master Password"),
                );
                if edit.lost_focus() && ctx.input(|i| i.key_pressed(Key::Enter)) {
                    submit_now = true;
                }
                let eye = if *show_pass {
                    Icon::EyeOff
                } else {
                    Icon::Eye
                };
                if icon_button(ui, pal, eye, "Show or hide password").clicked() {
                    *show_pass = !*show_pass;
                }
            });

            if let Some(ref err) = *unlock_error {
                ui.add_space(6.0);
                ui.label(RichText::new(err).color(pal.danger_fg));
            } else if let Some(ref daemon_err) = snap.toast_error {
                ui.add_space(6.0);
                ui.label(RichText::new(daemon_err).color(pal.danger_fg));
            }

            if let Some(ref busy) = snap.busy_task {
                ui.add_space(6.0);
                ui.label(RichText::new(busy).color(pal.primary_btn));
            }

            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if primary_button(ui, pal, Some(Icon::Unlock), "Unlock My Vault").clicked() {
                    submit_now = true;
                }
                if secondary_button(ui, pal, Some(Icon::CloudPlus), "Connect a Cloud").clicked() {
                    wizard.open_connect_cloud(WizardProvider::GoogleDrive);
                }
                if small_button(ui, pal, Some(Icon::BookOpen), "Setup Guide", false).clicked() {
                    wizard.open_full(WizardStep::Welcome);
                }
            });

            if submit_now {
                if passphrase_input.is_empty() {
                    *unlock_error = Some("Enter your Master Password first.".to_owned());
                } else {
                    *unlock_error = None;
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
}
