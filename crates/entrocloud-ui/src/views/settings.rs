//! `Settings` view — Appearance (`Light` / `Dark` / `System`), OS Login Autostart,
//! `Open Setup & API Guide`, `Lock Vault`, `Conflicted File Copies`, and `Test Encryption Speed`.

use eframe::egui::{self, FontId, RichText, Sense, Vec2};

use crate::icons::{Icon, paint_icon};
use crate::theme::{
    Palette, PillTone, ThemePreference, UiPrefs, card_frame, danger_button, form_label,
    primary_button, progress_bar_clean, secondary_button, semibold_font,
    set_os_autostart_enabled, small_button, status_pill, sub_card_frame,
};
use crate::views::FrameSnapshot;
use crate::wizard::{WizardState, WizardStep};
use crate::worker::{UiCommand, UiWorkerHandle};

/// Renders the `Settings` cards inside `ui`.
#[allow(clippy::too_many_arguments)]
pub fn render_settings_cards(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    wizard: &mut WizardState,
    prefs: &mut UiPrefs,
    prefs_dirty: &mut bool,
    bench_mib: &mut usize,
    gpu_adapter: &str,
) {
    // 1. Appearance & Startup Card
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
            paint_icon(ui.painter(), ic_r, Icon::Settings, pal.primary_btn);
            ui.label(
                RichText::new("Appearance & Startup")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
        });
        ui.add_space(10.0);

        form_label(ui, pal, "Color Theme");
        ui.horizontal_wrapped(|ui| {
            for (mode, ic, lbl) in [
                (ThemePreference::Light, Some(Icon::Sun), "Light"),
                (ThemePreference::Dark, Some(Icon::Moon), "Dark"),
                (ThemePreference::System, None, "System"),
            ] {
                if small_button(ui, pal, ic, lbl, prefs.theme == mode).clicked()
                    && prefs.theme != mode
                {
                    prefs.theme = mode;
                    *prefs_dirty = true;
                }
            }
        });

        ui.add_space(10.0);
        let mut autostart = prefs.start_with_os;
        if ui
            .checkbox(&mut autostart, "Start EntroCloud when I sign in")
            .changed()
        {
            prefs.start_with_os = autostart;
            *prefs_dirty = true;
            let _ = set_os_autostart_enabled(autostart);
        }
        ui.label(
            RichText::new(
                "Closing this window exits the desktop UI cleanly (0 MB background UI memory) while scheduled backups continue in your system tray.",
            )
            .font(FontId::proportional(12.0))
            .color(pal.muted),
        );

        ui.add_space(12.0);
        if secondary_button(
            ui,
            pal,
            Some(Icon::BookOpen),
            "Open Setup & API Guide",
        )
        .clicked()
        {
            wizard.open_full(WizardStep::Welcome);
        }
    });

    ui.add_space(12.0);

    // 2. Vault Protection & Session Card
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Vault Protection & Session")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if danger_button(ui, pal, Some(Icon::Lock), "Lock Vault").clicked() {
                    worker.send(UiCommand::LockVault);
                }
            });
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Locking your vault immediately clears encryption keys from memory and wipes any temporary previewed files.",
            )
            .font(FontId::proportional(12.4))
            .color(pal.muted),
        );

        if snap.active_preview_files > 0 {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                status_pill(
                    ui,
                    pal,
                    None,
                    &format!("{} temporary preview file(s)", snap.active_preview_files),
                    PillTone::Warn,
                );
                if secondary_button(ui, pal, Some(Icon::Trash), "Wipe Previews Now").clicked() {
                    worker.send(UiCommand::ScrubPreviewsNow);
                }
            });
        }
    });

    ui.add_space(12.0);

    // 3. Test Encryption Speed Card
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Test Encryption Speed")
                    .font(semibold_font(ctx, 18.0))
                    .color(pal.ink),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary_button(
                    ui,
                    pal,
                    Some(Icon::Sparkles),
                    "Test Speed",
                )
                .clicked()
                {
                    worker.send(UiCommand::RunCryptoBench {
                        total_mib: *bench_mib,
                    });
                }
            });
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Measure how quickly this computer locks and verifies files with built-in hardware encryption.",
            )
            .font(FontId::proportional(12.4))
            .color(pal.muted),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Sample size:").color(pal.muted).size(12.2));
            for sz in [64usize, 128, 256] {
                if small_button(ui, pal, None, &format!("{sz} MB"), *bench_mib == sz).clicked() {
                    *bench_mib = sz;
                }
            }
        });

        if let Some(ref rep) = snap.crypto_bench {
            ui.add_space(10.0);
            let ceiling = rep
                .encrypt_mib_per_sec
                .max(rep.decrypt_mib_per_sec)
                .max(6144.0) as f32;
            sub_card_frame(pal).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Encrypting Files")
                            .font(semibold_font(ctx, 12.8))
                            .color(pal.ink),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{:.2} GB/s", rep.encrypt_mib_per_sec / 1024.0))
                                .font(semibold_font(ctx, 13.0))
                                .color(pal.primary_btn),
                        );
                    });
                });
                progress_bar_clean(ui, pal, (rep.encrypt_mib_per_sec as f32) / ceiling, 6.0);

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Reading & Verifying Files")
                            .font(semibold_font(ctx, 12.8))
                            .color(pal.ink),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{:.2} GB/s", rep.decrypt_mib_per_sec / 1024.0))
                                .font(semibold_font(ctx, 13.0))
                                .color(pal.ok_fg),
                        );
                    });
                });
                progress_bar_clean(ui, pal, (rep.decrypt_mib_per_sec as f32) / ceiling, 6.0);
            });
        }

        ui.add_space(8.0);
        egui::CollapsingHeader::new(
            RichText::new("Technical Details")
                .font(FontId::proportional(12.2))
                .color(pal.muted),
        )
        .id_salt("settings_technical_details")
        .show(ui, |ui| {
            sub_card_frame(pal).show(ui, |ui| {
                ui.label(
                    RichText::new(format!("Graphics adapter: {gpu_adapter}"))
                        .font(FontId::proportional(11.8))
                        .color(pal.muted),
                );
                ui.label(
                    RichText::new(format!("Local service channel: {}", snap.ipc_endpoint))
                        .font(FontId::proportional(11.8))
                        .color(pal.muted),
                );
                if let Some(ref rep) = snap.crypto_bench {
                    ui.label(
                        RichText::new(format!(
                            "Cipher engine: {} ({})  •  VAES: {}  •  AVX2: {}  •  AES-HW: {}",
                            rep.caps.backend_name,
                            rep.caps.arch,
                            if rep.caps.vaes_hw { "Yes" } else { "No" },
                            if rep.caps.avx2_hw { "Yes" } else { "No" },
                            if rep.caps.aes_hw { "Yes" } else { "No" },
                        ))
                        .font(FontId::proportional(11.8))
                        .color(pal.muted),
                    );
                }
            });
        });
    });

    ui.add_space(12.0);

    // 4. Conflicted File Copies Card
    card_frame(pal).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Conflicted File Copies")
                        .font(semibold_font(ctx, 18.0))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new(
                        "If a file is edited on two devices at once, EntroCloud keeps both copies safe so nothing is lost.",
                    )
                    .font(FontId::proportional(12.4))
                    .color(pal.muted),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if secondary_button(ui, pal, Some(Icon::Refresh), "Refresh").clicked() {
                    worker.send(UiCommand::RefreshConflicts);
                }
            });
        });
        ui.add_space(10.0);
        if snap.conflicts.is_empty() {
            sub_card_frame(pal).show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Everything is synced cleanly — no conflicting file edits found.",
                    )
                    .font(FontId::proportional(12.5))
                    .color(pal.muted),
                );
            });
        } else {
            for c in &snap.conflicts {
                sub_card_frame(pal).show(ui, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{}  ->  Preserved as {}",
                            c.original_path, c.conflict_path
                        ))
                        .font(semibold_font(ctx, 12.5))
                        .color(pal.ink),
                    );
                    ui.label(
                        RichText::new(c.detected_at.format("%Y-%m-%d %H:%M UTC").to_string())
                            .font(FontId::proportional(11.5))
                            .color(pal.muted),
                    );
                });
                ui.add_space(4.0);
            }
        }
    });
}

/// Renders the full scrollable `Settings` view.
#[allow(clippy::too_many_arguments)]
pub fn render_settings_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    wizard: &mut WizardState,
    prefs: &mut UiPrefs,
    prefs_dirty: &mut bool,
    bench_mib: &mut usize,
    gpu_adapter: &str,
) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            render_settings_cards(
                ctx,
                ui,
                pal,
                snap,
                worker,
                wizard,
                prefs,
                prefs_dirty,
                bench_mib,
                gpu_adapter,
            );
            ui.add_space(20.0);
        });
}
