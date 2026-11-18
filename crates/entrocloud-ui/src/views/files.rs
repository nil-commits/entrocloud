//! `My Files` Vault File Browser — Grid View & List View, Breadcrumbs, Drag-and-Drop,
//! Search, Async File/Folder Upload, Context Menu, and Zero-Temp-File Private Note Editor.

use std::path::PathBuf;

use eframe::egui::{
    self, Align2, CursorIcon, FontId, Pos2, Rect, RichText, Rounding, Sense, Stroke, Vec2,
};
use egui_extras::{Column, TableBuilder};
use entrocloud_types::{EntryKind, HydrationState, VaultEntrySummary};
use zeroize::{Zeroize, Zeroizing};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_icon};
use crate::session::{join_ui_vpath, split_ui_parent_and_name};
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, primary_button, secondary_button,
    semibold_font, small_button, status_pill, sub_card_frame,
};
use crate::tray_common::format_bytes_human;
use crate::views::{ExplorerSortColumn, FrameSnapshot, NavPage};
use crate::wizard::{WizardProvider, WizardState};
use crate::worker::{UiCommand, UiWorkerHandle};

const MAX_NOTE_EDITOR_BYTES: usize = 2 * 1024 * 1024;

/// State for the built-in zero-temp-file Private Note Editor modal.
pub struct NoteModalState {
    pub open: bool,
    pub virtual_path: String,
    pub content: Zeroizing<String>,
    pub dirty: bool,
}

impl Default for NoteModalState {
    fn default() -> Self {
        Self {
            open: false,
            virtual_path: "/Quick Note.md".to_owned(),
            content: Zeroizing::new(String::new()),
            dirty: false,
        }
    }
}

/// Interactive state for the `My Files` explorer.
#[derive(Default)]
pub struct FilesViewState {
    pub search_filter: String,
    pub sort_col: ExplorerSortColumn,
    pub sort_asc: bool,
    pub new_folder_open: bool,
    pub new_folder_name: String,
    pub rename_target: Option<String>,
    pub rename_new_path: String,
    pub delete_target: Option<(String, bool)>,
    pub delete_recursive: bool,
    pub note_modal: NoteModalState,
    pub last_loaded_note_vpath: Option<String>,
}

impl FilesViewState {
    pub fn zeroize_secrets(&mut self) {
        self.note_modal.content.zeroize();
    }
}

/// Renders the `My Files` view (Grid & List views, drag-and-drop, and explorer modals).
#[allow(clippy::too_many_arguments)]
pub fn render_files_view(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    snap: &FrameSnapshot,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    wizard: &mut WizardState,
    state: &mut FilesViewState,
    file_view_grid: &mut bool,
    prefs_dirty: &mut bool,
    active_page: &mut NavPage,
    share_source_vpath: &mut String,
) {
    // Handle OS drag-and-drop files dropped onto the window!
    let dropped_paths: Vec<PathBuf> = ctx.input(|i| {
        i.raw
            .dropped_files
            .iter()
            .filter_map(|df| df.path.clone())
            .collect()
    });
    if !dropped_paths.is_empty() {
        worker.send(UiCommand::ImportLocalPaths {
            local_paths: dropped_paths,
            target_dir: snap.current_dir.clone(),
        });
    }
    let hovering_drop = ctx.input(|i| !i.raw.hovered_files.is_empty());

    let remotes_empty = snap.status.as_ref().is_none_or(|s| s.remotes.is_empty());

    // Guided 1-click cloud banner if no storage location is connected yet
    if remotes_empty {
        egui::Frame::none()
            .fill(pal.accent_soft_bg)
            .stroke(Stroke::new(1.0, pal.primary_btn.gamma_multiply(0.45)))
            .rounding(Rounding::same(11.0))
            .inner_margin(egui::Margin::symmetric(18.0, 13.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Where should EntroCloud save your encrypted files?")
                                .font(semibold_font(ctx, 15.0))
                                .color(pal.ink),
                        );
                        ui.label(
                            RichText::new(
                                "Connect Google Drive, OneDrive, Dropbox, S3, or a local drive so everything you add is backed up off-site.",
                            )
                            .font(FontId::proportional(12.4))
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
            });
        ui.add_space(10.0);
    }

    // Explorer Toolbar (2 tidy rows so breadcrumbs, search, view toggle, and actions never crowd)
    card_frame(pal)
        .inner_margin(egui::Margin::symmetric(16.0, 12.0))
        .show(ui, |ui| {
            // Row 1: Back + Breadcrumbs on left; Search + Grid/List toggle on right
            ui.horizontal(|ui| {
                if snap.current_dir != "/"
                    && small_button(ui, pal, Some(Icon::ArrowLeft), "Back", false).clicked()
                    && let Ok((parent, _)) = split_ui_parent_and_name(&snap.current_dir)
                {
                    worker.send(UiCommand::ListDirectory {
                        virtual_path: parent,
                    });
                }

                render_breadcrumbs(ui, pal, &snap.current_dir, worker);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if small_button(ui, pal, Some(Icon::List), "List", !*file_view_grid).clicked()
                        && *file_view_grid
                    {
                        *file_view_grid = false;
                        *prefs_dirty = true;
                    }
                    if small_button(ui, pal, Some(Icon::Grid), "Grid", *file_view_grid).clicked()
                        && !*file_view_grid
                    {
                        *file_view_grid = true;
                        *prefs_dirty = true;
                    }

                    ui.add(
                        egui::TextEdit::singleline(&mut state.search_filter)
                            .desired_width(210.0)
                            .hint_text("Search this folder..."),
                    );
                });
            });

            ui.add_space(8.0);

            // Row 2: Folder & File Creation / Upload Actions
            ui.horizontal_wrapped(|ui| {
                if primary_button(ui, pal, Some(Icon::Upload), "Add Files").clicked() {
                    dialogs.pick_files(
                        ctx,
                        "Choose files to encrypt and add to your vault",
                        DialogPurpose::ImportFiles {
                            target_vdir: snap.current_dir.clone(),
                        },
                    );
                }
                if secondary_button(ui, pal, Some(Icon::FolderOpen), "Add Folder").clicked() {
                    dialogs.pick_folder(
                        ctx,
                        "Choose a folder to encrypt and add to your vault",
                        None,
                        DialogPurpose::ImportFolder {
                            target_vdir: snap.current_dir.clone(),
                        },
                    );
                }
                if secondary_button(ui, pal, Some(Icon::FileText), "Write a Note").clicked() {
                    state.note_modal.open = true;
                    state.note_modal.virtual_path =
                        join_ui_vpath(&snap.current_dir, "Private Note.md");
                    state.note_modal.content.zeroize();
                    state.note_modal.dirty = false;
                }
                if secondary_button(ui, pal, Some(Icon::Plus), "New Folder").clicked() {
                    state.new_folder_open = true;
                    state.new_folder_name.clear();
                }
            });
        });

    ui.add_space(12.0);

    // Filter & sort entries (Directories always grouped neatly at the top)
    let needle = state.search_filter.trim().to_ascii_lowercase();
    let mut visible: Vec<VaultEntrySummary> = snap
        .entries
        .iter()
        .filter(|e| needle.is_empty() || e.name.to_ascii_lowercase().contains(&needle))
        .cloned()
        .collect();

    let sort_col = state.sort_col;
    let sort_asc = state.sort_asc;
    visible.sort_by(|a, b| {
        let a_dir = a.kind == EntryKind::Directory;
        let b_dir = b.kind == EntryKind::Directory;
        if a_dir != b_dir {
            return b_dir.cmp(&a_dir);
        }
        let ord = match sort_col {
            ExplorerSortColumn::Name => a
                .name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase()),
            ExplorerSortColumn::Size => a.size.cmp(&b.size),
            ExplorerSortColumn::Hydration => {
                hydration_rank(a.hydration).cmp(&hydration_rank(b.hydration))
            }
        };
        if sort_asc { ord } else { ord.reverse() }
    });

    if hovering_drop {
        card_frame(pal).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(36.0);
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, Icon::Upload, pal.primary_btn);
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Drop files or folders here to encrypt and add them to your vault")
                        .font(semibold_font(ctx, 18.0))
                        .color(pal.primary_btn),
                );
                ui.add_space(36.0);
            });
        });
    } else if visible.is_empty() {
        card_frame(pal).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                paint_icon(ui.painter(), ic_r, Icon::Upload, pal.primary_btn);
                ui.add_space(10.0);
                ui.label(
                    RichText::new(if needle.is_empty() {
                        "This folder is empty"
                    } else {
                        "No matching files in this folder"
                    })
                    .font(semibold_font(ctx, 19.0))
                    .color(pal.ink),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Drag and drop files from your computer, or click below to add files, folders, or write a private note.",
                    )
                    .font(FontId::proportional(13.2))
                    .color(pal.muted),
                );
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    let center_pad = ((ui.available_width() - 360.0) * 0.5).max(0.0);
                    ui.add_space(center_pad);
                    if primary_button(ui, pal, Some(Icon::Upload), "+ Add Files").clicked() {
                        dialogs.pick_files(
                            ctx,
                            "Choose files to encrypt and add to your vault",
                            DialogPurpose::ImportFiles {
                                target_vdir: snap.current_dir.clone(),
                            },
                        );
                    }
                    if secondary_button(ui, pal, Some(Icon::FileText), "Write a Note").clicked() {
                        state.note_modal.open = true;
                        state.note_modal.virtual_path =
                            join_ui_vpath(&snap.current_dir, "Private Note.md");
                        state.note_modal.content.zeroize();
                        state.note_modal.dirty = false;
                    }
                    if secondary_button(ui, pal, Some(Icon::Plus), "New Folder").clicked() {
                        state.new_folder_open = true;
                        state.new_folder_name.clear();
                    }
                });
                ui.add_space(28.0);
            });
        });
    } else if *file_view_grid {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(12.0, 12.0);
                    for entry in &visible {
                        render_grid_card(
                            ctx,
                            ui,
                            pal,
                            entry,
                            &snap.current_dir,
                            worker,
                            dialogs,
                            state,
                            active_page,
                            share_source_vpath,
                        );
                    }
                });
                ui.add_space(16.0);
            });
    } else {
        card_frame(pal)
            .inner_margin(egui::Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                render_list_table(
                    ctx,
                    ui,
                    pal,
                    &visible,
                    &snap.current_dir,
                    worker,
                    dialogs,
                    state,
                    active_page,
                    share_source_vpath,
                );
            });
    }

    // Explorer modals (Note editor, New folder, Rename, Delete)
    render_explorer_modals(ctx, pal, &snap.current_dir, worker, state);
}

fn render_breadcrumbs(
    ui: &mut egui::Ui,
    pal: &Palette,
    current_dir: &str,
    worker: &UiWorkerHandle,
) {
    if small_button(
        ui,
        pal,
        Some(Icon::Folder),
        "My Files",
        current_dir == "/",
    )
    .clicked()
        && current_dir != "/"
    {
        worker.send(UiCommand::ListDirectory {
            virtual_path: "/".to_owned(),
        });
    }

    let segments: Vec<&str> = current_dir
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut accum = String::new();
    for (idx, seg) in segments.iter().enumerate() {
        accum.push('/');
        accum.push_str(seg);
        let target = accum.clone();
        let is_last = idx + 1 == segments.len();
        let (chev_r, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        paint_icon(ui.painter(), chev_r, Icon::ChevronRight, pal.muted);
        if small_button(ui, pal, None, seg, is_last).clicked() && !is_last {
            worker.send(UiCommand::ListDirectory {
                virtual_path: target,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_grid_card(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    entry: &VaultEntrySummary,
    current_dir: &str,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    state: &mut FilesViewState,
    active_page: &mut NavPage,
    share_source_vpath: &mut String,
) {
    let card_size = Vec2::new(186.0, 142.0);
    let (rect, resp) = ui.allocate_exact_size(card_size, Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    let menu_btn_rect = Rect::from_min_size(
        Pos2::new(rect.right() - 32.0, rect.top() + 8.0),
        Vec2::splat(24.0),
    );

    if ui.is_rect_visible(rect) {
        let bg = if resp.hovered() {
            pal.card_sub_bg
        } else {
            pal.card_bg
        };
        let border = if resp.hovered() {
            pal.primary_btn
        } else {
            pal.card_border
        };
        ui.painter().rect_filled(rect, Rounding::same(11.0), bg);
        ui.painter()
            .rect_stroke(rect, Rounding::same(11.0), Stroke::new(1.0, border));

        let (icon, icon_col) = match entry.kind {
            EntryKind::Directory => (Icon::Folder, pal.primary_btn),
            EntryKind::File => {
                if is_text_note_filename(&entry.name) {
                    (Icon::FileText, pal.accent_soft_fg)
                } else {
                    (Icon::File, pal.muted)
                }
            }
        };

        let ic_rect = Rect::from_center_size(
            Pos2::new(rect.center().x, rect.top() + 44.0),
            Vec2::splat(36.0),
        );
        paint_icon(ui.painter(), ic_rect, icon, icon_col);

        if entry.pinned {
            let pin_r = Rect::from_min_size(
                Pos2::new(rect.left() + 10.0, rect.top() + 10.0),
                Vec2::splat(15.0),
            );
            paint_icon(ui.painter(), pin_r, Icon::Pin, pal.ok_fg);
        }

        // 3-dot menu icon hint in top-right corner
        paint_icon(
            ui.painter(),
            menu_btn_rect.shrink(4.5),
            Icon::MoreHorizontal,
            pal.muted,
        );

        let display_name = truncate_middle(&entry.name, 22);
        let name_galley = ui.painter().layout_no_wrap(
            display_name,
            semibold_font(ctx, 13.3),
            pal.ink,
        );
        ui.painter().galley(
            Pos2::new(
                (rect.center().x - name_galley.size().x * 0.5).max(rect.left() + 10.0),
                rect.top() + 82.0,
            ),
            name_galley,
            pal.ink,
        );

        let meta_str = match entry.kind {
            EntryKind::Directory => "Folder".to_owned(),
            EntryKind::File => format!(
                "{}  •  {}",
                format_bytes_human(entry.size),
                hydration_friendly_label(entry.hydration)
            ),
        };
        let meta_galley = ui.painter().layout_no_wrap(
            meta_str,
            FontId::proportional(11.2),
            pal.muted,
        );
        ui.painter().galley(
            Pos2::new(
                (rect.center().x - meta_galley.size().x * 0.5).max(rect.left() + 8.0),
                rect.top() + 105.0,
            ),
            meta_galley,
            pal.muted,
        );
    }

    // Clicking the top-right `...` area opens the popup menu; double-clicking (or clicking a folder) opens it!
    let popup_id = ui.make_persistent_id(("grid_entry_menu", entry.inode));
    if resp.clicked() {
        let ptr_in_menu = resp
            .interact_pointer_pos()
            .is_some_and(|p| menu_btn_rect.expand(4.0).contains(p));
        if ptr_in_menu {
            ui.memory_mut(|m| m.toggle_popup(popup_id));
        } else if entry.kind == EntryKind::Directory {
            worker.send(UiCommand::ListDirectory {
                virtual_path: entry.virtual_path.clone(),
            });
        }
    }
    if resp.double_clicked() {
        activate_entry(entry, worker, state);
    }

    egui::popup::popup_below_widget(
        ui,
        popup_id,
        &resp,
        egui::PopupCloseBehavior::CloseOnClick,
        |ui| {
            ui.set_min_width(185.0);
            render_entry_menu_items(
                ctx,
                ui,
                entry,
                current_dir,
                worker,
                dialogs,
                state,
                active_page,
                share_source_vpath,
            );
        },
    );

    resp.context_menu(|ui| {
        ui.set_min_width(185.0);
        render_entry_menu_items(
            ctx,
            ui,
            entry,
            current_dir,
            worker,
            dialogs,
            state,
            active_page,
            share_source_vpath,
        );
    });
}

#[allow(clippy::too_many_arguments)]
fn render_list_table(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    pal: &Palette,
    entries: &[VaultEntrySummary],
    current_dir: &str,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    state: &mut FilesViewState,
    active_page: &mut NavPage,
    share_source_vpath: &mut String,
) {
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::remainder().at_least(220.0))
        .column(Column::initial(100.0))
        .column(Column::initial(145.0))
        .column(Column::initial(145.0))
        .column(Column::initial(110.0))
        .header(30.0, |mut hdr| {
            hdr.col(|ui| {
                if sort_header_btn(
                    ui,
                    pal,
                    "Name",
                    state.sort_col == ExplorerSortColumn::Name,
                    state.sort_asc,
                )
                .clicked()
                {
                    toggle_sort(state, ExplorerSortColumn::Name);
                }
            });
            hdr.col(|ui| {
                if sort_header_btn(
                    ui,
                    pal,
                    "Size",
                    state.sort_col == ExplorerSortColumn::Size,
                    state.sort_asc,
                )
                .clicked()
                {
                    toggle_sort(state, ExplorerSortColumn::Size);
                }
            });
            hdr.col(|ui| {
                ui.label(
                    RichText::new("Modified")
                        .font(semibold_font(ctx, 12.5))
                        .color(pal.muted),
                );
            });
            hdr.col(|ui| {
                if sort_header_btn(
                    ui,
                    pal,
                    "PC Status",
                    state.sort_col == ExplorerSortColumn::Hydration,
                    state.sort_asc,
                )
                .clicked()
                {
                    toggle_sort(state, ExplorerSortColumn::Hydration);
                }
            });
            hdr.col(|ui| {
                ui.label(
                    RichText::new("Actions")
                        .font(semibold_font(ctx, 12.5))
                        .color(pal.muted),
                );
            });
        })
        .body(|mut body| {
            for entry in entries {
                body.row(36.0, |mut row| {
                    row.col(|ui| {
                        let ic = if entry.kind == EntryKind::Directory {
                            Icon::Folder
                        } else if is_text_note_filename(&entry.name) {
                            Icon::FileText
                        } else {
                            Icon::File
                        };
                        let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                        paint_icon(ui.painter(), ic_r, ic, pal.primary_btn);
                        let link = ui.add(
                            egui::Label::new(
                                RichText::new(&entry.name)
                                    .font(semibold_font(ctx, 13.4))
                                    .color(pal.ink),
                            )
                            .sense(Sense::click()),
                        );
                        if link.hovered() {
                            ctx.set_cursor_icon(CursorIcon::PointingHand);
                        }
                        if (link.clicked() && entry.kind == EntryKind::Directory)
                            || link.double_clicked()
                        {
                            activate_entry(entry, worker, state);
                        }
                        link.context_menu(|ui| {
                            render_entry_menu_items(
                                ctx,
                                ui,
                                entry,
                                current_dir,
                                worker,
                                dialogs,
                                state,
                                active_page,
                                share_source_vpath,
                            );
                        });
                    });

                    row.col(|ui| {
                        let sz = if entry.kind == EntryKind::Directory {
                            "--".to_owned()
                        } else {
                            format_bytes_human(entry.size)
                        };
                        ui.label(RichText::new(sz).color(pal.muted).size(12.4));
                    });

                    row.col(|ui| {
                        ui.label(
                            RichText::new(entry.modified_at.format("%Y-%m-%d %H:%M").to_string())
                                .color(pal.muted)
                                .size(12.2),
                        );
                    });

                    row.col(|ui| {
                        if entry.kind == EntryKind::Directory {
                            status_pill(ui, pal, None, "Folder", PillTone::Neutral);
                        } else {
                            let (lbl, tone) = hydration_pill(entry.hydration);
                            status_pill(ui, pal, None, lbl, tone);
                        }
                    });

                    row.col(|ui| {
                        ui.menu_button("Actions", |ui| {
                            ui.set_min_width(185.0);
                            render_entry_menu_items(
                                ctx,
                                ui,
                                entry,
                                current_dir,
                                worker,
                                dialogs,
                                state,
                                active_page,
                                share_source_vpath,
                            );
                        });
                    });
                });
            }
        });
}

#[allow(clippy::too_many_arguments)]
fn render_entry_menu_items(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    entry: &VaultEntrySummary,
    current_dir: &str,
    worker: &UiWorkerHandle,
    dialogs: &AsyncDialogs,
    state: &mut FilesViewState,
    active_page: &mut NavPage,
    share_source_vpath: &mut String,
) {
    if entry.kind == EntryKind::Directory {
        if ui.button("Open Folder").clicked() {
            worker.send(UiCommand::ListDirectory {
                virtual_path: entry.virtual_path.clone(),
            });
            ui.close_menu();
        }
    } else {
        if ui.button("Open").clicked() {
            activate_entry(entry, worker, state);
            ui.close_menu();
        }
        if ui.button("Open in Default App").clicked() {
            worker.send(UiCommand::PreviewVaultFile {
                virtual_path: entry.virtual_path.clone(),
            });
            ui.close_menu();
        }
        if ui.button("Save Copy...").clicked() {
            dialogs.save_file(
                ctx,
                "Save decrypted copy to this PC",
                &entry.name,
                DialogPurpose::ExportFileSaveCopy {
                    virtual_path: entry.virtual_path.clone(),
                    suggested_name: entry.name.clone(),
                },
            );
            ui.close_menu();
        }
        ui.separator();
        let pin_lbl = if entry.pinned {
            "Remove Offline Pin"
        } else {
            "Keep Offline"
        };
        if ui.button(pin_lbl).clicked() {
            worker.send(UiCommand::SetPinned {
                virtual_path: entry.virtual_path.clone(),
                pinned: !entry.pinned,
                refresh_dir: current_dir.to_owned(),
            });
            ui.close_menu();
        }
        if ui.button("Free Up Space").clicked() {
            worker.send(UiCommand::FreeUpSpace {
                virtual_path: entry.virtual_path.clone(),
                refresh_dir: current_dir.to_owned(),
            });
            ui.close_menu();
        }
        if ui.button("Share Link...").clicked() {
            *share_source_vpath = entry.virtual_path.clone();
            worker.send(UiCommand::CreateCapabilityShare {
                virtual_path: entry.virtual_path.clone(),
            });
            *active_page = NavPage::Sharing;
            ui.close_menu();
        }
    }

    ui.separator();
    if ui.button("Rename...").clicked() {
        state.rename_target = Some(entry.virtual_path.clone());
        state.rename_new_path = entry.virtual_path.clone();
        ui.close_menu();
    }
    if ui
        .button(RichText::new("Delete...").color(Color32::from_rgb(0xC8, 0x3E, 0x3B)))
        .clicked()
    {
        state.delete_target = Some((
            entry.virtual_path.clone(),
            entry.kind == EntryKind::Directory,
        ));
        state.delete_recursive = entry.kind == EntryKind::Directory;
        ui.close_menu();
    }
}

use eframe::egui::Color32;

fn activate_entry(
    entry: &VaultEntrySummary,
    worker: &UiWorkerHandle,
    state: &mut FilesViewState,
) {
    if entry.kind == EntryKind::Directory {
        worker.send(UiCommand::ListDirectory {
            virtual_path: entry.virtual_path.clone(),
        });
    } else if is_text_note_filename(&entry.name) && entry.size <= MAX_NOTE_EDITOR_BYTES as u64 {
        state.note_modal.open = true;
        state.note_modal.virtual_path = entry.virtual_path.clone();
        state.note_modal.dirty = false;
        worker.send(UiCommand::ReadTextNote {
            virtual_path: entry.virtual_path.clone(),
        });
    } else {
        worker.send(UiCommand::PreviewVaultFile {
            virtual_path: entry.virtual_path.clone(),
        });
    }
}

fn render_explorer_modals(
    ctx: &egui::Context,
    pal: &Palette,
    current_dir: &str,
    worker: &UiWorkerHandle,
    state: &mut FilesViewState,
) {
    // 1. Private Note Editor Modal (<= 2 MiB in-RAM Zeroizing<String>, 0 temp files)
    if state.note_modal.open {
        egui::Window::new("Private Encrypted Note")
            .collapsible(false)
            .resizable(true)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(600.0)
            .show(ctx, |ui| {
                form_label(ui, pal, "Note path in vault");
                ui.add(
                    egui::TextEdit::singleline(&mut state.note_modal.virtual_path)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(8.0);
                let byte_len = state.note_modal.content.len();
                let resp = ui.add(
                    egui::TextEdit::multiline(&mut *state.note_modal.content)
                        .desired_rows(14)
                        .desired_width(f32::INFINITY)
                        .hint_text("Write private notes, recovery codes, or personal lists here..."),
                );
                if resp.changed() {
                    state.note_modal.dirty = true;
                }
                sub_card_frame(pal)
                    .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "Edited directly in encrypted memory ({} / 2 MB max, 0 temporary files on disk).",
                                format_bytes_human(byte_len as u64)
                            ))
                            .font(FontId::proportional(11.6))
                            .color(pal.muted),
                        );
                    });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Close").clicked() {
                        state.note_modal.content.zeroize();
                        state.note_modal.open = false;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_enabled_ui(byte_len <= MAX_NOTE_EDITOR_BYTES, |ui| {
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Lock),
                                "Save Encrypted Note",
                            )
                            .clicked()
                            {
                                let copy = Zeroizing::new((*state.note_modal.content).clone());
                                worker.send(UiCommand::SaveTextNote {
                                    virtual_path: state.note_modal.virtual_path.trim().to_owned(),
                                    content: copy,
                                    refresh_dir: current_dir.to_owned(),
                                });
                                state.note_modal.content.zeroize();
                                state.note_modal.open = false;
                            }
                        });
                    });
                });
            });
    }

    // 2. New Folder Modal
    if state.new_folder_open {
        egui::Window::new("New Folder")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(360.0)
            .show(ctx, |ui| {
                form_label(ui, pal, "Folder name");
                ui.add(
                    egui::TextEdit::singleline(&mut state.new_folder_name)
                        .desired_width(f32::INFINITY)
                        .hint_text("e.g. Receipts 2026"),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.new_folder_open = false;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, pal, Some(Icon::Check), "Create Folder").clicked() {
                            let clean = state.new_folder_name.trim();
                            if !clean.is_empty() {
                                worker.send(UiCommand::CreateDirectory {
                                    virtual_path: join_ui_vpath(current_dir, clean),
                                    refresh_dir: current_dir.to_owned(),
                                });
                                state.new_folder_open = false;
                            }
                        }
                    });
                });
            });
    }

    // 3. Rename Modal
    if let Some(orig) = state.rename_target.clone() {
        egui::Window::new("Rename Item")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(400.0)
            .show(ctx, |ui| {
                form_label(ui, pal, "New path or name");
                ui.add(
                    egui::TextEdit::singleline(&mut state.rename_new_path)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.rename_target = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, pal, Some(Icon::Check), "Save Name").clicked() {
                            let dest = state.rename_new_path.trim();
                            if !dest.is_empty() {
                                let full_dest = if dest.contains('/') {
                                    dest.to_owned()
                                } else {
                                    join_ui_vpath(current_dir, dest)
                                };
                                worker.send(UiCommand::RenameEntry {
                                    virtual_path: orig,
                                    new_virtual_path: full_dest,
                                    refresh_dir: current_dir.to_owned(),
                                });
                                state.rename_target = None;
                            }
                        }
                    });
                });
            });
    }

    // 4. Delete Confirmation Modal
    if let Some((target_vpath, is_dir)) = state.delete_target.clone() {
        egui::Window::new("Delete from Vault")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(400.0)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("Delete '{target_vpath}' from your vault?"))
                        .font(semibold_font(ctx, 15.5))
                        .color(pal.ink),
                );
                if is_dir {
                    ui.add_space(4.0);
                    ui.checkbox(
                        &mut state.delete_recursive,
                        "Delete all files and subfolders inside this folder",
                    );
                }
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.delete_target = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Delete").clicked() {
                            worker.send(UiCommand::DeleteEntry {
                                virtual_path: target_vpath,
                                recursive: state.delete_recursive,
                                refresh_dir: current_dir.to_owned(),
                            });
                            state.delete_target = None;
                        }
                    });
                });
            });
    }
}

fn sort_header_btn(
    ui: &mut egui::Ui,
    pal: &Palette,
    label: &str,
    active: bool,
    asc: bool,
) -> egui::Response {
    let resp = ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        let lbl = ui.add(
            egui::Label::new(
                RichText::new(label)
                    .font(semibold_font(ui.ctx(), 12.5))
                    .color(if active { pal.primary_btn } else { pal.muted }),
            )
            .sense(Sense::click()),
        );
        if active {
            let (ic_r, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
            let ic = if asc { Icon::SortAsc } else { Icon::SortDesc };
            paint_icon(ui.painter(), ic_r, ic, pal.primary_btn);
        }
        lbl
    });
    resp.inner
}

fn toggle_sort(state: &mut FilesViewState, col: ExplorerSortColumn) {
    if state.sort_col == col {
        state.sort_asc = !state.sort_asc;
    } else {
        state.sort_col = col;
        state.sort_asc = true;
    }
}

pub fn is_text_note_filename(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".md")
        || lower.ends_with(".txt")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".csv")
        || lower.ends_with(".log")
}

fn truncate_middle(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return s.to_owned();
    }
    let head = (max_chars / 2).saturating_sub(1);
    let tail = max_chars.saturating_sub(head + 3);
    let prefix: String = chars[..head].iter().collect();
    let suffix: String = chars[chars.len() - tail..].iter().collect();
    format!("{prefix}...{suffix}")
}

fn hydration_rank(state: HydrationState) -> u8 {
    match state {
        HydrationState::Pinned => 0,
        HydrationState::DirtyLocal => 1,
        HydrationState::LocallyCached => 2,
        HydrationState::PartiallyHydrated => 3,
        HydrationState::OnlineOnly => 4,
    }
}

fn hydration_friendly_label(state: HydrationState) -> &'static str {
    match state {
        HydrationState::Pinned => "Kept offline",
        HydrationState::LocallyCached => "On this PC",
        HydrationState::PartiallyHydrated => "Partly cached",
        HydrationState::DirtyLocal => "Syncing",
        HydrationState::OnlineOnly => "In cloud",
    }
}

fn hydration_pill(state: HydrationState) -> (&'static str, PillTone) {
    match state {
        HydrationState::Pinned => ("Kept offline", PillTone::Ok),
        HydrationState::LocallyCached => ("On this PC", PillTone::Ok),
        HydrationState::PartiallyHydrated => ("Partly cached", PillTone::Accent),
        HydrationState::DirtyLocal => ("Syncing", PillTone::Warn),
        HydrationState::OnlineOnly => ("In cloud", PillTone::Neutral),
    }
}
