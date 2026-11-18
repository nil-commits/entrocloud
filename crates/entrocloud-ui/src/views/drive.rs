//! `Computer Drive` view — Mount/Unmount EntroCloud inside File Explorer (`~/EntroCloud`),
//! `Open in File Explorer`, transfer stat tiles, throughput sparkline, and tucked troubleshooting.

use std::path::Path;

use eframe::egui::{self, Color32, FontId, Pos2, RichText, Sense, Shape, Stroke, Vec2};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_icon};
use crate::session::open_in_os_default_app;
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, primary_button, secondary_button,
    semibold_font, status_pill, sub_card_frame,
};
use crate::tray_common::{format_bytes_human, format_rate_iec};
use crate::views::FrameSnapshot;
use crate::worker::{UiCommand, UiWorkerHandle};

/// Renders the `Computer Drive` view.
#[allow(clippy::too_many_arguments)]
pub fn render_drive_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    mount_point_input: &mut String,
    use_portable_sandbox: &mut bool,
) {
    let mounted = snap.status.as_ref().is_some_and(|s| s.mounted);
    let bytes_read = snap.status.as_ref().map_or(0, |s| s.drive_stats.bytes_read);
    let bytes_written = snap
        .status
        .as_ref()
        .map_or(0, |s| s.drive_stats.bytes_written);
    let up_bps = snap
        .status
        .as_ref()
        .map_or(0, |s| s.throughput.upload_bytes_per_sec);
    let down_bps = snap
        .status
        .as_ref()
        .map_or(0, |s| s.throughput.download_bytes_per_sec);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            card_frame(pal).show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                    paint_icon(ui.painter(), ic_r, Icon::HardDrive, pal.primary_btn);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.label(
                            RichText::new("Use EntroCloud Inside File Explorer")
                                .font(semibold_font(ctx, 21.0))
                                .color(pal.ink),
                        );
                        ui.label(
                            RichText::new(
                                "Mount your vault as a normal folder on this computer. Files stay encrypted in the cloud until you open them.",
                            )
                            .font(FontId::proportional(13.2))
                            .color(pal.muted),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        status_pill(
                            ui,
                            pal,
                            Some(if mounted { Icon::Check } else { Icon::HardDrive }),
                            if mounted { "Connected" } else { "Off" },
                            if mounted {
                                PillTone::Ok
                            } else {
                                PillTone::Neutral
                            },
                        );
                    });
                });

                ui.add_space(16.0);
                form_label(ui, pal, "Folder Location on This PC");
                ui.horizontal(|ui| {
                    ui.add_enabled(
                        !mounted,
                        egui::TextEdit::singleline(mount_point_input)
                            .desired_width(ui.available_width() - 155.0)
                            .hint_text("e.g. C:\\Users\\You\\EntroCloud"),
                    );
                    ui.add_enabled_ui(!mounted, |ui| {
                        if secondary_button(
                            ui,
                            pal,
                            Some(Icon::FolderOpen),
                            "Change Folder...",
                        )
                        .clicked()
                        {
                            dialogs.pick_folder(
                                ctx,
                                "Choose folder location for EntroCloud Drive",
                                None,
                                DialogPurpose::MountPointFolder,
                            );
                        }
                    });
                });

                ui.add_space(14.0);
                ui.horizontal_wrapped(|ui| {
                    if !mounted {
                        if primary_button(
                            ui,
                            pal,
                            Some(Icon::Play),
                            "Turn On Explorer Folder",
                        )
                        .clicked()
                        {
                            worker.send(UiCommand::MountDrive {
                                mount_point: mount_point_input.trim().to_owned(),
                                use_mock_vfs: *use_portable_sandbox,
                            });
                        }
                    } else if danger_button(ui, pal, Some(Icon::Stop), "Turn Off").clicked() {
                        worker.send(UiCommand::UnmountDrive);
                    }

                    if secondary_button(
                        ui,
                        pal,
                        Some(Icon::ExternalLink),
                        "Open in File Explorer",
                    )
                    .clicked()
                    {
                        let _ = open_in_os_default_app(Path::new(mount_point_input.trim()));
                    }
                });

                ui.add_space(12.0);
                egui::CollapsingHeader::new(
                    RichText::new("Advanced Troubleshooting")
                        .font(FontId::proportional(12.5))
                        .color(pal.muted),
                )
                .show(ui, |ui| {
                    sub_card_frame(pal).show(ui, |ui| {
                        ui.checkbox(
                            use_portable_sandbox,
                            "Use built-in portable sandbox drive (helpful if OS Cloud Filter or FUSE permissions are restricted)",
                        );
                    });
                });
            });

            ui.add_space(16.0);

            // 3 Clean Transfer Stat Tiles
            ui.spacing_mut().item_spacing.x = 14.0;
            ui.columns(3, |cols| {
                drive_stat_tile(
                    &mut cols[0],
                    pal,
                    Icon::Download,
                    "Read From Vault",
                    &format_bytes_human(bytes_read),
                );
                drive_stat_tile(
                    &mut cols[1],
                    pal,
                    Icon::Upload,
                    "Saved Into Vault",
                    &format_bytes_human(bytes_written),
                );
                let rate_label = if up_bps == 0 && down_bps == 0 {
                    "Idle".to_owned()
                } else {
                    format!("{} up  •  {} down", format_rate_iec(up_bps), format_rate_iec(down_bps))
                };
                drive_stat_tile(
                    &mut cols[2],
                    pal,
                    Icon::Refresh,
                    "Transfer Activity",
                    &rate_label,
                );
            });

            ui.add_space(14.0);

            // Live Transfer Activity Sparkline Card
            card_frame(pal)
                .inner_margin(egui::Margin::symmetric(20.0, 14.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Recent Transfer Throughput")
                                .font(semibold_font(ctx, 14.5))
                                .color(pal.ink),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "Peak: {:.1} MiB/s upload  •  {:.1} MiB/s download",
                                    snap.peak_up_mib_s, snap.peak_down_mib_s
                                ))
                                .font(FontId::proportional(11.8))
                                .color(pal.muted),
                            );
                        });
                    });
                    ui.add_space(8.0);
                    let scale = (snap.peak_up_mib_s.max(snap.peak_down_mib_s) as f32).max(16.0);
                    draw_clean_sparkline(
                        ui,
                        pal,
                        &snap.up_history,
                        &snap.down_history,
                        scale,
                    );
                });

            ui.add_space(20.0);
        });
}

fn drive_stat_tile(ui: &mut egui::Ui, pal: &Palette, icon: Icon, label: &str, value: &str) {
    card_frame(pal)
        .inner_margin(egui::Margin::symmetric(18.0, 15.0))
        .show(ui, |ui| {
            ui.set_min_height(56.0);
            ui.horizontal(|ui| {
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, icon, pal.primary_btn);
                ui.label(
                    RichText::new(label)
                        .font(FontId::proportional(12.5))
                        .color(pal.muted),
                );
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new(value)
                    .font(semibold_font(ui.ctx(), 16.5))
                    .color(pal.ink),
            );
        });
}

fn draw_clean_sparkline(
    ui: &mut egui::Ui,
    pal: &Palette,
    up_samples: &[f32],
    down_samples: &[f32],
    max_scale: f32,
) {
    let desired = Vec2::new(ui.available_width().max(120.0), 54.0);
    let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 8.0, pal.card_sub_bg);
    painter.rect_stroke(rect, 8.0, Stroke::new(1.0, pal.card_border));

    plot_series(&painter, rect, down_samples, max_scale, Color32::from_rgb(0x2D, 0xD4, 0xBF));
    plot_series(&painter, rect, up_samples, max_scale, pal.primary_btn);
}

fn plot_series(
    painter: &egui::Painter,
    rect: egui::Rect,
    samples: &[f32],
    max_scale: f32,
    color: Color32,
) {
    if samples.len() < 2 {
        return;
    }
    let n = samples.len();
    let step_x = (rect.width() - 8.0) / (n.saturating_sub(1).max(1) as f32);
    let pts: Vec<Pos2> = samples
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let norm = (v / max_scale.max(1.0)).clamp(0.0, 1.0);
            let x = rect.left() + 4.0 + (i as f32) * step_x;
            let y = rect.bottom() - 6.0 - norm * (rect.height() - 12.0);
            Pos2::new(x, y)
        })
        .collect();
    painter.add(Shape::line(pts, Stroke::new(1.8, color)));
}
