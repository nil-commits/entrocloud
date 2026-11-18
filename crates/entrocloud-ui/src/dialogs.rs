//! Non-blocking asynchronous OS file, folder, and save dialogs (`rfd` on background threads).
//!
//! Guarantees ZERO synchronous `rfd::FileDialog` calls on the `egui` GPU render thread.
//! Every dialog runs on a short-lived background thread and delivers its result over an `mpsc`
//! channel while triggering `ctx.request_repaint()`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;

/// Semantic target for an asynchronous OS file/folder picker request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogPurpose {
    /// Import one or more local files into `target_vdir` inside the vault.
    ImportFiles { target_vdir: String },
    /// Import a local directory recursively into `target_vdir` inside the vault.
    ImportFolder { target_vdir: String },
    /// Export/decrypt a vault file to a chosen local destination path.
    ExportFileSaveCopy {
        virtual_path: String,
        suggested_name: String,
    },
    /// Choose a local or USB folder for 1-click backup storage in the Setup Wizard.
    WizardLocalCloudFolder,
    /// Choose a local PC source folder to protect in the Add/Edit Backup Folder modal.
    BackupJobSourceFolder,
    /// Choose a local destination parent folder to restore an encrypted backup snapshot into.
    RestoreDestinationParent { job_id: String, job_name: String },
    /// Choose a local folder mount location for Computer Drive (`~/EntroCloud`).
    MountPointFolder,
}

/// Completed outcome delivered from a background `rfd` dialog thread to `EntroCloudApp::update()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogOutcome {
    /// User selected one or more local files.
    FilesPicked {
        purpose: DialogPurpose,
        paths: Vec<PathBuf>,
    },
    /// User selected a local folder.
    FolderPicked {
        purpose: DialogPurpose,
        path: PathBuf,
    },
    /// User selected a destination file path for saving a copy.
    SaveFilePicked {
        purpose: DialogPurpose,
        path: PathBuf,
    },
    /// User dismissed the OS dialog without choosing a path.
    Cancelled,
}

/// Asynchronous OS dialog dispatcher owned by `EntroCloudApp`.
pub struct AsyncDialogs {
    tx: Sender<DialogOutcome>,
    rx: Receiver<DialogOutcome>,
    active: Arc<AtomicBool>,
}

impl Default for AsyncDialogs {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncDialogs {
    /// Creates an idle [`AsyncDialogs`] channel pair.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx,
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` if a native OS file/folder dialog is currently open on a background thread.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Polls for a completed dialog result without blocking the GPU render thread.
    #[must_use]
    pub fn try_recv(&self) -> Option<DialogOutcome> {
        self.rx.try_recv().ok()
    }

    /// Injects a synthetic [`DialogOutcome`] (used in automated unit tests to verify non-blocking
    /// dialog handling without popping interactive OS windows).
    pub fn inject_for_test(&self, outcome: DialogOutcome) {
        let _ = self.tx.send(outcome);
    }

    /// Spawns a background thread to pick one or more local files (`rfd::FileDialog::pick_files`).
    pub fn pick_files(&self, ctx: &egui::Context, title: &str, purpose: DialogPurpose) {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let tx = self.tx.clone();
        let active = Arc::clone(&self.active);
        let ctx_clone = ctx.clone();
        let title_owned = title.to_owned();

        let _ = thread::Builder::new()
            .name("ec-dialog-files".to_owned())
            .spawn(move || {
                let picked = rfd::FileDialog::new().set_title(&title_owned).pick_files();
                active.store(false, Ordering::SeqCst);
                let outcome = match picked {
                    Some(paths) if !paths.is_empty() => {
                        DialogOutcome::FilesPicked { purpose, paths }
                    }
                    _ => DialogOutcome::Cancelled,
                };
                let _ = tx.send(outcome);
                ctx_clone.request_repaint();
            });
    }

    /// Spawns a background thread to pick a single folder (`rfd::FileDialog::pick_folder`).
    pub fn pick_folder(
        &self,
        ctx: &egui::Context,
        title: &str,
        initial_dir: Option<PathBuf>,
        purpose: DialogPurpose,
    ) {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let tx = self.tx.clone();
        let active = Arc::clone(&self.active);
        let ctx_clone = ctx.clone();
        let title_owned = title.to_owned();

        let _ = thread::Builder::new()
            .name("ec-dialog-folder".to_owned())
            .spawn(move || {
                let mut dlg = rfd::FileDialog::new().set_title(&title_owned);
                if let Some(dir) = initial_dir.filter(|p| p.is_dir()) {
                    dlg = dlg.set_directory(dir);
                }
                let picked = dlg.pick_folder();
                active.store(false, Ordering::SeqCst);
                let outcome = match picked {
                    Some(path) => DialogOutcome::FolderPicked { purpose, path },
                    None => DialogOutcome::Cancelled,
                };
                let _ = tx.send(outcome);
                ctx_clone.request_repaint();
            });
    }

    /// Spawns a background thread to pick a destination save path (`rfd::FileDialog::save_file`).
    pub fn save_file(
        &self,
        ctx: &egui::Context,
        title: &str,
        suggested_file_name: &str,
        purpose: DialogPurpose,
    ) {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let tx = self.tx.clone();
        let active = Arc::clone(&self.active);
        let ctx_clone = ctx.clone();
        let title_owned = title.to_owned();
        let name_owned = suggested_file_name.to_owned();

        let _ = thread::Builder::new()
            .name("ec-dialog-save".to_owned())
            .spawn(move || {
                let mut dlg = rfd::FileDialog::new().set_title(&title_owned);
                if !name_owned.is_empty() {
                    dlg = dlg.set_file_name(&name_owned);
                }
                let picked = dlg.save_file();
                active.store(false, Ordering::SeqCst);
                let outcome = match picked {
                    Some(path) => DialogOutcome::SaveFilePicked { purpose, path },
                    None => DialogOutcome::Cancelled,
                };
                let _ = tx.send(outcome);
                ctx_clone.request_repaint();
            });
    }
}
