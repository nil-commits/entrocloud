//! `My Files` Vault File Browser — Grid View & List View, Breadcrumbs, Drag-and-Drop,
//! Search, Async File/Folder Upload, Context Menu, and Zero-Temp-File Private Note Editor.

use std::path::PathBuf;

use eframe::egui::{
    self, Color32, CursorIcon, FontId, Key, Margin, Pos2, Rect, RichText, Rounding, Sense, Stroke,
    Vec2,
};
use egui_extras::{Column, TableBuilder};
use entrocloud_types::{EntryKind, HydrationState, VaultEntrySummary};
use zeroize::{Zeroize, Zeroizing};

use crate::dialogs::{AsyncDialogs, DialogPurpose};
use crate::icons::{Icon, paint_icon};
use crate::session::{join_ui_vpath, split_ui_parent_and_name};
use crate::theme::{
    Palette, PillTone, card_frame, danger_button, form_label, modal_dialog, primary_button,
    secondary_button, segmented_control, semibold_font, small_button, status_pill, sub_card_frame,
    text_input_single,
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
    pub loading: bool,
    pub confirm_discard: bool,
    pub validation_error: Option<String>,
}

impl Default for NoteModalState {
    fn default() -> Self {
        Self {
            open: false,
            virtual_path: "/Quick Note.md".to_owned(),
            content: Zeroizing::new(String::new()),
            dirty: false,
            loading: false,
            confirm_discard: false,
            validation_error: None,
        }
    }
}

/// Interactive state for the `My Files` explorer.
pub struct FilesViewState {
    pub last_dir: String,
    pub search_filter: String,
    pub sort_col: ExplorerSortColumn,
    pub sort_asc: bool,
    pub selected_vpath: Option<String>,
    pub new_folder_open: bool,
    pub new_folder_name: String,
    pub rename_target: Option<String>,
    pub rename_new_path: String,
    pub delete_target: Option<(String, bool)>,
    pub delete_recursive: bool,
    pub note_modal: NoteModalState,
}

impl Default for FilesViewState {
    fn default() -> Self {
        Self {
            last_dir: String::new(),
            search_filter: String::new(),
            sort_col: ExplorerSortColumn::default(),
            sort_asc: true,
            selected_vpath: None,
            new_folder_open: false,
            new_folder_name: String::new(),
            rename_target: None,
            rename_new_path: String::new(),
            delete_target: None,
            delete_recursive: false,
            note_modal: NoteModalState::default(),
        }
    }
}

impl FilesViewState {
    pub fn zeroize_secrets(&mut self) {
        self.note_modal.content.zeroize();
        self.note_modal.dirty = false;
        self.note_modal.loading = false;
        self.note_modal.confirm_discard = false;
        self.note_modal.validation_error = None;
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
    // Clear folder-scoped filter & selection whenever the active directory changes
    if state.last_dir != snap.current_dir {
        state.last_dir = snap.current_dir.clone();
        state.search_filter.clear();
        state.selected_vpath = None;
    }

    // Clear note loading spinner if a daemon error surfaced or content has arrived
    if state.note_modal.loading
        && (snap.toast_error.is_some() || !state.note_modal.content.is_empty())
    {
        state.note_modal.loading = false;
    }
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
            .rounding(Rounding::same(12.0))
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
            // Row 1: Back + Breadcrumbs in bounded scroll area on left; Search + Grid/List segmented control on right
            let right_reserve_w = 340.0;
            let left_max_w = (ui.available_width() - right_reserve_w).max(120.0);
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(left_max_w, 30.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        egui::ScrollArea::horizontal()
                            .id_salt("ec_files_breadcrumbs_scroll")
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if snap.current_dir != "/"
                                        && small_button(
                                            ui,
                                            pal,
                                            Some(Icon::ArrowLeft),
                                            "Back",
                                            false,
                                        )
                                        .clicked()
                                        && let Ok((parent, _)) =
                                            split_ui_parent_and_name(&snap.current_dir)
                                    {
                                        worker.send(UiCommand::ListDirectory {
                                            virtual_path: parent,
                                        });
                                    }

                                    render_breadcrumbs(ui, pal, &snap.current_dir, worker);
                                });
                            });
                    },
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if segmented_control(ui, pal, file_view_grid, &[(true, "Grid"), (false, "List")])
                    {
                        *prefs_dirty = true;
                    }

                    egui::Frame::none()
                        .fill(pal.input_bg)
                        .stroke(Stroke::new(1.0, pal.input_border))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(8.0, 4.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 5.0;
                                let (ic_r, _) =
                                    ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                                paint_icon(ui.painter(), ic_r, Icon::Search, pal.muted);
                                let text_w = if state.search_filter.is_empty() {
                                    170.0
                                } else {
                                    148.0
                                };
                                ui.add(
                                    egui::TextEdit::singleline(&mut state.search_filter)
                                        .frame(false)
                                        .desired_width(text_w)
                                        .hint_text("Search this folder…"),
                                );
                                if !state.search_filter.is_empty() {
                                    let clear_btn = ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("×")
                                                    .font(semibold_font(ctx, 13.0))
                                                    .color(pal.muted),
                                            )
                                            .frame(false),
                                        )
                                        .on_hover_text("Clear search");
                                    if clear_btn.hovered() {
                                        ctx.set_cursor_icon(CursorIcon::PointingHand);
                                    }
                                    if clear_btn.clicked() {
                                        state.search_filter.clear();
                                    }
                                }
                            });
                        });
                });
            });

            ui.add_space(8.0);

            // Row 2: Folder & File Creation / Upload Actions + Selected File Quick Actions
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
                    state.note_modal.loading = false;
                    state.note_modal.confirm_discard = false;
                    state.note_modal.validation_error = None;
                }
                if secondary_button(ui, pal, Some(Icon::Plus), "New Folder").clicked() {
                    state.new_folder_open = true;
                    state.new_folder_name.clear();
                }

                if let Some(sel_entry) = state
                    .selected_vpath
                    .as_deref()
                    .and_then(|vp| snap.entries.iter().find(|e| e.virtual_path == vp))
                    .cloned()
                {
                    ui.separator();
                    if small_button(ui, pal, Some(Icon::ExternalLink), "Open", false).clicked() {
                        activate_entry(&sel_entry, worker, state);
                    }
                    if sel_entry.kind == EntryKind::File {
                        if small_button(ui, pal, Some(Icon::Download), "Save Copy", false).clicked()
                        {
                            dialogs.save_file(
                                ctx,
                                "Save decrypted copy to this PC",
                                &sel_entry.name,
                                DialogPurpose::ExportFileSaveCopy {
                                    virtual_path: sel_entry.virtual_path.clone(),
                                    suggested_name: sel_entry.name.clone(),
                                },
                            );
                        }
                        if small_button(ui, pal, Some(Icon::ShareLink), "Share", false).clicked() {
                            *share_source_vpath = sel_entry.virtual_path.clone();
                            worker.send(UiCommand::CreateCapabilityShare {
                                virtual_path: sel_entry.virtual_path.clone(),
                            });
                            *active_page = NavPage::Sharing;
                        }
                    }
                    if small_button(ui, pal, Some(Icon::Edit), "Rename", false).clicked() {
                        state.rename_target = Some(sel_entry.virtual_path.clone());
                        state.rename_new_path = sel_entry.name.clone();
                    }
                    if small_button(ui, pal, Some(Icon::Trash), "Delete", false).clicked() {
                        state.delete_target = Some((
                            sel_entry.virtual_path.clone(),
                            sel_entry.kind == EntryKind::Directory,
                        ));
                        state.delete_recursive = sel_entry.kind == EntryKind::Directory;
                    }
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
                let row_id = ui.make_persistent_id("ec_empty_folder_actions_w");
                let last_w = ui.data(|d| d.get_temp::<f32>(row_id)).unwrap_or(320.0);
                let avail = ui.available_width();
                let center_pad = if last_w < avail {
                    (avail - last_w) * 0.5
                } else {
                    0.0
                };
                ui.horizontal(|ui| {
                    if center_pad > 0.0 {
                        ui.add_space(center_pad);
                    }
                    let inner = ui.horizontal_wrapped(|ui| {
                        if primary_button(ui, pal, Some(Icon::Upload), "Add Files").clicked() {
                            dialogs.pick_files(
                                ctx,
                                "Choose files to encrypt and add to your vault",
                                DialogPurpose::ImportFiles {
                                    target_vdir: snap.current_dir.clone(),
                                },
                            );
                        }
                        if secondary_button(ui, pal, Some(Icon::FileText), "Write a Note")
                            .clicked()
                        {
                            state.note_modal.open = true;
                            state.note_modal.virtual_path =
                                join_ui_vpath(&snap.current_dir, "Private Note.md");
                            state.note_modal.content.zeroize();
                            state.note_modal.dirty = false;
                            state.note_modal.loading = false;
                            state.note_modal.confirm_discard = false;
                            state.note_modal.validation_error = None;
                        }
                        if secondary_button(ui, pal, Some(Icon::Plus), "New Folder").clicked() {
                            state.new_folder_open = true;
                            state.new_folder_name.clear();
                        }
                    });
                    let measured_w = inner.response.rect.width();
                    if measured_w > 1.0 && (measured_w - last_w).abs() > 0.5 {
                        ui.data_mut(|d| d.insert_temp(row_id, measured_w));
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
    let popup_id = ui.make_persistent_id(("grid_entry_menu", entry.inode));
    let menu_btn_rect = Rect::from_min_size(
        Pos2::new(rect.right() - 32.0, rect.top() + 8.0),
        Vec2::splat(24.0),
    );
    let menu_resp = ui.interact(menu_btn_rect, popup_id.with("dots_btn"), Sense::click());
    if resp.hovered() || menu_resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    let is_selected = state.selected_vpath.as_deref() == Some(entry.virtual_path.as_str());
    let display_name = truncate_middle(&entry.name, 22);
    let is_truncated = display_name != entry.name;

    if ui.is_rect_visible(rect) {
        let (bg, border, bw) = if is_selected {
            (pal.accent_soft_bg, pal.primary_btn, 1.8)
        } else if resp.hovered() || menu_resp.hovered() {
            (pal.card_sub_bg, pal.primary_btn, 1.2)
        } else {
            (pal.card_bg, pal.card_border, 1.0)
        };
        ui.painter().rect_filled(rect, Rounding::same(12.0), bg);
        ui.painter()
            .rect_stroke(rect, Rounding::same(12.0), Stroke::new(bw, border));

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

        if menu_resp.hovered() {
            ui.painter().rect_filled(
                menu_btn_rect,
                Rounding::same(8.0),
                pal.secondary_btn_hover,
            );
        }
        paint_icon(
            ui.painter(),
            menu_btn_rect.shrink(4.5),
            Icon::MoreHorizontal,
            if menu_resp.hovered() { pal.ink } else { pal.muted },
        );

        let text_painter = ui.painter_at(rect.shrink2(egui::Vec2::new(6.0, 0.0)));
        let name_galley = text_painter.layout_no_wrap(
            display_name,
            semibold_font(ctx, 13.3),
            pal.ink,
        );
        text_painter.galley(
            Pos2::new(
                (rect.center().x - name_galley.size().x * 0.5).max(rect.left() + 8.0),
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
        let meta_galley = text_painter.layout_no_wrap(
            meta_str,
            FontId::proportional(11.2),
            pal.muted,
        );
        text_painter.galley(
            Pos2::new(
                (rect.center().x - meta_galley.size().x * 0.5).max(rect.left() + 8.0),
                rect.top() + 105.0,
            ),
            meta_galley,
            pal.muted,
        );
    }

    let resp = if is_truncated {
        resp.on_hover_text(&entry.name)
    } else {
        resp
    };

    if menu_resp.clicked() {
        state.selected_vpath = Some(entry.virtual_path.clone());
        ui.memory_mut(|m| m.toggle_popup(popup_id));
    } else if resp.double_clicked() {
        activate_entry(entry, worker, state);
    } else if resp.clicked() {
        state.selected_vpath = Some(entry.virtual_path.clone());
    }

    egui::popup::popup_below_widget(
        ui,
        popup_id,
        &menu_resp,
        egui::PopupCloseBehavior::CloseOnClick,
        |ui| {
            ui.set_min_width(185.0);
            render_entry_menu_items(
                ctx,
                ui,
                pal,
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
            pal,
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
    egui::ScrollArea::horizontal()
        .id_salt("ec_files_list_table_hscroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
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
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
                                let (ic_r, _) =
                                    ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                                paint_icon(ui.painter(), ic_r, ic, pal.primary_btn);
                                let is_sel = state.selected_vpath.as_deref()
                                    == Some(entry.virtual_path.as_str());
                                let link = ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(&entry.name)
                                                .font(semibold_font(ctx, 13.4))
                                                .color(if is_sel {
                                                    pal.primary_btn
                                                } else {
                                                    pal.ink
                                                }),
                                        )
                                        .truncate()
                                        .sense(Sense::click()),
                                    )
                                    .on_hover_text(&entry.name);
                                if link.hovered() {
                                    ctx.set_cursor_icon(CursorIcon::PointingHand);
                                }
                                if link.double_clicked() {
                                    activate_entry(entry, worker, state);
                                } else if link.clicked() {
                                    state.selected_vpath = Some(entry.virtual_path.clone());
                                }
                                link.context_menu(|ui| {
                                    render_entry_menu_items(
                                        ctx,
                                        ui,
                                        pal,
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
                                    "—".to_owned()
                                } else {
                                    format_bytes_human(entry.size)
                                };
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(sz)
                                                .font(FontId::monospace(12.0))
                                                .color(pal.muted),
                                        );
                                    },
                                );
                            });

                            row.col(|ui| {
                                ui.label(
                                    RichText::new(
                                        entry.modified_at.format("%Y-%m-%d %H:%M").to_string(),
                                    )
                                    .font(FontId::monospace(11.8))
                                    .color(pal.muted),
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
                                        pal,
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
        });
}

#[allow(clippy::too_many_arguments)]
fn render_entry_menu_items(
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
    ui.visuals_mut().widgets.inactive.bg_fill = Color32::TRANSPARENT;
    ui.visuals_mut().widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    ui.visuals_mut().widgets.inactive.bg_stroke = Stroke::NONE;

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
        if ui.button("Save Copy…").clicked() {
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
        if ui.button("Share Link…").clicked() {
            *share_source_vpath = entry.virtual_path.clone();
            worker.send(UiCommand::CreateCapabilityShare {
                virtual_path: entry.virtual_path.clone(),
            });
            *active_page = NavPage::Sharing;
            ui.close_menu();
        }
    }

    ui.separator();
    if ui.button("Rename…").clicked() {
        state.rename_target = Some(entry.virtual_path.clone());
        state.rename_new_path = entry.name.clone();
        ui.close_menu();
    }
    if ui
        .button(RichText::new("Delete…").color(pal.danger_fg))
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
        state.note_modal.content.zeroize();
        state.note_modal.dirty = false;
        state.note_modal.loading = true;
        state.note_modal.confirm_discard = false;
        state.note_modal.validation_error = None;
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
        let mut close_req = false;
        let mut close_btn_clicked = false;
        let is_loading = state.note_modal.loading;
        modal_dialog(
            ctx,
            pal,
            "ec_private_note_modal",
            "Private Encrypted Note",
            600.0,
            &mut close_req,
            |ui| {
                if is_loading {
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
                                paint_icon(ui.painter(), ic_r, Icon::Refresh, pal.accent_soft_fg);
                                ui.label(
                                    RichText::new("Loading encrypted note…")
                                        .font(semibold_font(ctx, 12.6))
                                        .color(pal.ink),
                                );
                            });
                        });
                    ui.add_space(8.0);
                }

                form_label(ui, pal, "Note path in vault");
                let path_resp = ui.add_enabled(
                    !is_loading,
                    text_input_single(&mut state.note_modal.virtual_path, "/Private Note.md"),
                );
                if path_resp.changed() {
                    state.note_modal.validation_error = None;
                }
                if let Some(ref err) = state.note_modal.validation_error {
                    ui.add_space(4.0);
                    ui.label(RichText::new(err).color(pal.danger_fg).size(12.0));
                }

                ui.add_space(8.0);
                let byte_len = state.note_modal.content.len();
                let resp = ui.add_enabled(
                    !is_loading,
                    egui::TextEdit::multiline(&mut *state.note_modal.content)
                        .margin(Margin::symmetric(10.0, 8.0))
                        .desired_rows(12)
                        .desired_width(f32::INFINITY)
                        .hint_text(if is_loading {
                            "Loading encrypted note…"
                        } else {
                            "Write private notes, recovery codes, or personal lists here…"
                        }),
                );
                if resp.changed() {
                    state.note_modal.dirty = true;
                    state.note_modal.confirm_discard = false;
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

                if state.note_modal.confirm_discard {
                    ui.add_space(8.0);
                    egui::Frame::none()
                        .fill(pal.warn_bg)
                        .stroke(Stroke::new(1.0, pal.warn_fg.gamma_multiply(0.35)))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let (ic_r, _) =
                                    ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                                paint_icon(ui.painter(), ic_r, Icon::Alert, pal.warn_fg);
                                ui.label(
                                    RichText::new("Discard unsaved changes?")
                                        .font(semibold_font(ctx, 12.8))
                                        .color(pal.warn_fg),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if danger_button(ui, pal, None, "Discard").clicked() {
                                            state.note_modal.content.zeroize();
                                            state.note_modal.dirty = false;
                                            state.note_modal.loading = false;
                                            state.note_modal.confirm_discard = false;
                                            state.note_modal.validation_error = None;
                                            state.note_modal.open = false;
                                        }
                                        if secondary_button(ui, pal, None, "Keep Editing").clicked()
                                        {
                                            state.note_modal.confirm_discard = false;
                                        }
                                    },
                                );
                            });
                        });
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Close").clicked() {
                        close_btn_clicked = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_enabled_ui(!is_loading && byte_len <= MAX_NOTE_EDITOR_BYTES, |ui| {
                            if primary_button(
                                ui,
                                pal,
                                Some(Icon::Lock),
                                "Save Encrypted Note",
                            )
                            .clicked()
                            {
                                let trimmed_path = state.note_modal.virtual_path.trim();
                                if trimmed_path.is_empty() || trimmed_path.ends_with('/') {
                                    state.note_modal.validation_error = Some(
                                        "Enter a valid note file path (for example, /Private Note.md)."
                                            .to_owned(),
                                    );
                                } else {
                                    let copy = Zeroizing::new((*state.note_modal.content).clone());
                                    worker.send(UiCommand::SaveTextNote {
                                        virtual_path: trimmed_path.to_owned(),
                                        content: copy,
                                        refresh_dir: current_dir.to_owned(),
                                    });
                                    state.note_modal.content.zeroize();
                                    state.note_modal.dirty = false;
                                    state.note_modal.loading = false;
                                    state.note_modal.confirm_discard = false;
                                    state.note_modal.validation_error = None;
                                    state.note_modal.open = false;
                                }
                            }
                        });
                    });
                });
            },
        );
        if close_req || close_btn_clicked {
            if state.note_modal.dirty && !state.note_modal.loading {
                state.note_modal.confirm_discard = true;
            } else {
                state.note_modal.content.zeroize();
                state.note_modal.dirty = false;
                state.note_modal.loading = false;
                state.note_modal.confirm_discard = false;
                state.note_modal.validation_error = None;
                state.note_modal.open = false;
            }
        }
    }

    // 2. New Folder Modal
    if state.new_folder_open {
        let mut close_req = false;
        modal_dialog(
            ctx,
            pal,
            "ec_new_folder_modal",
            "New Folder",
            380.0,
            &mut close_req,
            |ui| {
                form_label(ui, pal, "Folder name");
                let edit = ui.add(text_input_single(
                    &mut state.new_folder_name,
                    "e.g. Receipts 2026",
                ));
                let enter_submit = edit.lost_focus() && ctx.input(|i| i.key_pressed(Key::Enter));
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.new_folder_open = false;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, pal, Some(Icon::Check), "Create Folder").clicked()
                            || enter_submit
                        {
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
            },
        );
        if close_req {
            state.new_folder_open = false;
        }
    }

    // 3. Rename Modal
    if let Some(orig) = state.rename_target.clone() {
        let mut close_req = false;
        modal_dialog(
            ctx,
            pal,
            "ec_rename_item_modal",
            "Rename Item",
            420.0,
            &mut close_req,
            |ui| {
                form_label(ui, pal, "New name");
                let edit = ui.add(text_input_single(
                    &mut state.rename_new_path,
                    "Enter new file or folder name",
                ));
                let enter_submit = edit.lost_focus() && ctx.input(|i| i.key_pressed(Key::Enter));
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.rename_target = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, pal, Some(Icon::Check), "Save Name").clicked()
                            || enter_submit
                        {
                            let dest = state.rename_new_path.trim();
                            if !dest.is_empty() {
                                let parent_dir = split_ui_parent_and_name(&orig)
                                    .map(|(p, _)| p)
                                    .unwrap_or_else(|_| current_dir.to_owned());
                                let full_dest = if dest.contains('/') {
                                    if dest.starts_with('/') {
                                        dest.to_owned()
                                    } else {
                                        format!("/{dest}")
                                    }
                                } else {
                                    join_ui_vpath(&parent_dir, dest)
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
            },
        );
        if close_req {
            state.rename_target = None;
        }
    }

    // 4. Delete Confirmation Modal
    if let Some((target_vpath, is_dir)) = state.delete_target.clone() {
        let mut close_req = false;
        modal_dialog(
            ctx,
            pal,
            "ec_delete_entry_modal",
            "Delete from Vault",
            420.0,
            &mut close_req,
            |ui| {
                ui.label(
                    RichText::new(format!("Delete '{target_vpath}' from your vault?"))
                        .font(semibold_font(ctx, 15.5))
                        .color(pal.ink),
                );
                if is_dir {
                    ui.add_space(6.0);
                    ui.checkbox(
                        &mut state.delete_recursive,
                        "Delete all files and subfolders inside this folder",
                    );
                }
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, None, "Cancel").clicked() {
                        state.delete_target = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_button(ui, pal, Some(Icon::Trash), "Delete").clicked() {
                            if state.selected_vpath.as_deref() == Some(target_vpath.as_str()) {
                                state.selected_vpath = None;
                            }
                            worker.send(UiCommand::DeleteEntry {
                                virtual_path: target_vpath,
                                recursive: state.delete_recursive,
                                refresh_dir: current_dir.to_owned(),
                            });
                            state.delete_target = None;
                        }
                    });
                });
            },
        );
        if close_req {
            state.delete_target = None;
        }
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
    let tail = max_chars.saturating_sub(head + 1);
    let prefix: String = chars[..head].iter().collect();
    let suffix: String = chars[chars.len() - tail..].iter().collect();
    format!("{prefix}…{suffix}")
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
