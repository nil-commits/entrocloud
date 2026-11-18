//! `Computer Drive` view — Mount/Unmount EntroCloud inside File Explorer (`~/EntroCloud`),
//! `Open in File Explorer`, transfer stat tiles, throughput sparkline, and tucked troubleshooting.

use std::path::Path;

use eframe::egui::{self, Align2, Color32, FontId, Pos2, RichText, Rounding, Sense, Shape, Stroke, Vec2};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_icon};
use crate::session::open_in_os_default_app;
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, input_row_with_right_widget,
    primary_button, secondary_button, semibold_font, status_pill, sub_card_frame,
    text_input_single,
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

    let has_mount_path = !mount_point_input.trim().is_empty();

    let drive_heading = if cfg!(target_os = "windows") {
        "Use EntroCloud Inside File Explorer"
    } else {
        "Use EntroCloud Inside Your File Manager"
    };
    let folder_location_label = if cfg!(target_os = "windows") {
        "Folder Location on This PC"
    } else {
        "Vault Folder Location"
    };
    let mount_path_hint = if cfg!(target_os = "windows") {
        "e.g. C:\\Users\\You\\EntroCloud"
    } else {
        "e.g. /home/you/EntroCloud"
    };
    let turn_on_label = if cfg!(target_os = "windows") {
        "Turn On Explorer Folder"
    } else {
        "Turn On Vault Folder"
    };
    let open_in_fm_label = if cfg!(target_os = "windows") {
        "Open in File Explorer"
    } else {
        "Open in File Manager"
    };

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            card_frame(pal).show(ui, |ui| {
                let header_narrow = ui.available_width() < 540.0;
                if header_narrow {
                    ui.horizontal(|ui| {
                        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                        paint_icon(ui.painter(), ic_r, Icon::HardDrive, pal.primary_btn);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 3.0;
                            ui.label(
                                RichText::new(drive_heading)
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
                    });
                    ui.add_space(8.0);
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
                } else {
                    let text_max_w = (ui.available_width() - 165.0).max(180.0);
                    ui.horizontal(|ui| {
                        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                        paint_icon(ui.painter(), ic_r, Icon::HardDrive, pal.primary_btn);
                        ui.vertical(|ui| {
                            ui.set_max_width(text_max_w);
                            ui.spacing_mut().item_spacing.y = 3.0;
                            ui.label(
                                RichText::new(drive_heading)
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
                }

                ui.add_space(16.0);
                form_label(ui, pal, folder_location_label);
                input_row_with_right_widget(
                    ui,
                    |ui| {
                        ui.add_enabled_ui(!mounted, |ui| {
                            if secondary_button(
                                ui,
                                pal,
                                Some(Icon::FolderOpen),
                                "Change Folder…",
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
                    },
                    |ui, _rem_w| {
                        ui.add_enabled(
                            !mounted,
                            text_input_single(mount_point_input, mount_path_hint),
                        );
                    },
                );

                ui.add_space(14.0);
                ui.horizontal_wrapped(|ui| {
                    if !mounted {
                        ui.add_enabled_ui(has_mount_path, |ui| {
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Play),
                                turn_on_label,
                            )
                            .clicked()
                                && has_mount_path
                            {
                                worker.send(UiCommand::MountDrive {
                                    mount_point: mount_point_input.trim().to_owned(),
                                    use_mock_vfs: *use_portable_sandbox,
                                });
                            }
                        });
                    } else if danger_button(ui, pal, Some(Icon::Stop), "Turn Off").clicked() {
                        worker.send(UiCommand::UnmountDrive);
                    }

                    ui.add_enabled_ui(mounted && has_mount_path, |ui| {
                        if secondary_button(
                            ui,
                            pal,
                            Some(Icon::ExternalLink),
                            open_in_fm_label,
                        )
                        .clicked()
                            && mounted
                            && has_mount_path
                        {
                            let _ = open_in_os_default_app(Path::new(mount_point_input.trim()));
                        }
                    });
                });

                ui.add_space(12.0);
                egui::CollapsingHeader::new(
                    RichText::new("Advanced Troubleshooting")
                        .font(FontId::proportional(12.5))
                        .color(pal.muted),
                )
                .show(ui, |ui| {
                    sub_card_frame(pal).show(ui, |ui| {
                        ui.add_enabled(
                            !mounted,
                            egui::Checkbox::new(
                                use_portable_sandbox,
                                "Use built-in portable sandbox drive (helpful if OS Cloud Filter or FUSE permissions are restricted)",
                            ),
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
                    format!(
                        "{} up  •  {} down",
                        format_rate_iec(up_bps),
                        format_rate_iec(down_bps)
                    )
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
                    let peak_text = format!(
                        "Peak: {:.1} MiB/s up  •  {:.1} MiB/s down",
                        snap.peak_up_mib_s, snap.peak_down_mib_s
                    );
                    if ui.available_width() < 560.0 {
                        ui.label(
                            RichText::new("Recent Transfer Throughput")
                                .font(semibold_font(ctx, 14.5))
                                .color(pal.ink),
                        );
                        ui.add_space(2.0);
                        ui.horizontal_wrapped(|ui| {
                            paint_sparkline_legend(ui, pal);
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(&peak_text)
                                    .font(FontId::monospace(11.4))
                                    .color(pal.muted),
                            );
                        });
                    } else {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Recent Transfer Throughput")
                                    .font(semibold_font(ctx, 14.5))
                                    .color(pal.ink),
                            );
                            ui.add_space(10.0);
                            paint_sparkline_legend(ui, pal);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(&peak_text)
                                            .font(FontId::monospace(11.4))
                                            .color(pal.muted),
                                    );
                                },
                            );
                        });
                    }
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

fn paint_sparkline_legend(ui: &mut egui::Ui, pal: &Palette) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        let (up_r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
        ui.painter()
            .rect_filled(up_r, Rounding::same(4.0), pal.primary_btn);
        ui.label(
            RichText::new("Upload")
                .font(FontId::proportional(11.5))
                .color(pal.muted),
        );
        ui.add_space(4.0);
        let (dn_r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
        ui.painter()
            .rect_filled(dn_r, Rounding::same(4.0), pal.sidebar_accent);
        ui.label(
            RichText::new("Download")
                .font(FontId::proportional(11.5))
                .color(pal.muted),
        );
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
                    .font(FontId::monospace(15.5))
                    .strong()
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
    painter.rect_filled(rect, Rounding::same(8.0), pal.card_sub_bg);
    painter.rect_stroke(rect, Rounding::same(8.0), Stroke::new(1.0, pal.card_border));

    let has_activity = up_samples
        .iter()
        .chain(down_samples.iter())
        .any(|&v| v > 0.001);
    if !has_activity {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "No recent transfer activity",
            FontId::proportional(11.6),
            pal.muted,
        );
        return;
    }

    plot_series(&painter, rect, down_samples, max_scale, pal.sidebar_accent);
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
