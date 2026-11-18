//! Secure owner-only temporary preview workspace, zero-overwrite scrubber,
//! OS default-application launcher, and symlink-safe recursive directory importer.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;
use entrocloud_types::{DaemonRequest, DaemonResponse};

use crate::ipc_client::IpcClient;

static SESSION_OP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Normalizes a user-supplied virtual vault path (`/` or `/a/b/c`).
#[must_use]
pub fn normalize_ui_vpath(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_owned()
    } else {
        let parts: Vec<&str> = trimmed
            .split(['/', '\\'])
            .filter(|seg| !seg.is_empty() && *seg != ".")
            .collect();
        if parts.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", parts.join("/"))
        }
    }
}

/// Joins a normalized parent virtual path and a child basename.
#[must_use]
pub fn join_ui_vpath(parent: &str, name: &str) -> String {
    let norm_parent = normalize_ui_vpath(parent);
    let clean_name = name.trim_matches(['/', '\\']);
    if clean_name.is_empty() {
        norm_parent
    } else if norm_parent == "/" {
        format!("/{clean_name}")
    } else {
        format!("{norm_parent}/{clean_name}")
    }
}

/// Splits a non-root normalized virtual path into `(parent_dir, entry_name)`.
pub fn split_ui_parent_and_name(virtual_path: &str) -> Result<(String, String), String> {
    let norm = normalize_ui_vpath(virtual_path);
    if norm == "/" {
        return Err("Operation cannot target the vault root folder '/' directly".to_owned());
    }
    let Some(idx) = norm.rfind('/') else {
        return Err("Invalid virtual path".to_owned());
    };
    let parent = if idx == 0 {
        "/".to_owned()
    } else {
        norm[..idx].to_owned()
    };
    let name = norm[idx + 1..].to_owned();
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        return Err("Invalid virtual entry name".to_owned());
    }
    Ok((parent, name))
}

/// Returns the default owner-private session preview directory (`<local_data_dir>/EntroCloud/ui_session`).
#[must_use]
pub fn default_session_preview_dir() -> PathBuf {
    #[cfg(unix)]
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
        && !rt.is_empty()
    {
        return PathBuf::from(rt).join("entrocloud").join("ui_session");
    }

    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("EntroCloud").join("ui_session")
}

/// Ensures `dir` exists with owner-only `0700` permissions on Unix.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::symlink_metadata(dir)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "Refusing symlinked session preview directory: {}",
            dir.display()
        ));
    }
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("Failed creating private session directory: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("Failed setting 0700 permissions on session dir: {err}"))?;
    }
    Ok(())
}

/// Creates a unique per-preview subdirectory inside `session_root` so filenames never collide.
pub fn create_unique_preview_subdir(session_root: &Path) -> Result<PathBuf, String> {
    ensure_private_dir(session_root)?;
    let seq = SESSION_OP_SEQ.fetch_add(1, Ordering::Relaxed);
    let sub = session_root.join(format!("preview_{}_{}", std::process::id(), seq));
    ensure_private_dir(&sub)?;
    Ok(sub)
}

/// Overwrites all `len` bytes of a regular file on disk with `0x00`, flushes data to storage,
/// and unlinks the file.
///
/// Returns `true` only if both the zero-overwrite (when `len > 0`) and `remove_file` succeeded.
pub fn zero_wipe_and_remove_file(path: &Path, len: u64, zero_buf: &[u8]) -> bool {
    let chunk_buf = if zero_buf.is_empty() {
        &[0u8; 4096][..]
    } else {
        zero_buf
    };

    #[cfg(target_os = "windows")]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    #[cfg(unix)]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o200 == 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o200));
        }
    }

    let mut wipe_ok = true;
    if len > 0 {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(mut file) => {
                let mut remaining = len;
                while remaining > 0 {
                    let n = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(chunk_buf.len());
                    if file.write_all(&chunk_buf[..n]).is_err() {
                        wipe_ok = false;
                        break;
                    }
                    remaining = remaining.saturating_sub(n as u64);
                }
                let _ = file.sync_data();
            }
            Err(_) => {
                wipe_ok = false;
            }
        }
    }
    let removed = std::fs::remove_file(path).is_ok();
    wipe_ok && removed
}

/// Recursively zero-overwrites and deletes every regular file inside `session_root`
/// (unlinking symlinks without following them!) and removes `session_root`.
///
/// Returns the count of regular files zero-wiped and removed.
pub fn scrub_session_dir(session_root: &Path) -> usize {
    if !session_root.exists() {
        return 0;
    }
    let Ok(root_meta) = std::fs::symlink_metadata(session_root) else {
        return 0;
    };
    if root_meta.file_type().is_symlink() {
        let _ = std::fs::remove_file(session_root);
        return 0;
    }

    let zero_buf = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut stack = vec![session_root.to_path_buf()];
    let mut wiped_files = 0usize;

    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_symlink() {
                let _ = std::fs::remove_file(&path);
            } else if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file()
                && zero_wipe_and_remove_file(&path, meta.len(), &zero_buf)
            {
                wiped_files += 1;
            }
        }
    }

    let _ = std::fs::remove_dir_all(session_root);
    wiped_files
}

/// Counts active temporary preview files inside `session_root`.
#[must_use]
pub fn count_session_preview_files(session_root: &Path) -> usize {
    if !session_root.exists() {
        return 0;
    }
    let mut count = 0usize;
    let mut stack = vec![session_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file() {
                count += 1;
            }
        }
    }
    count
}

/// Summary of a recursive local file/folder import operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    /// Number of regular files imported via `DaemonRequest::ImportLocalFile`.
    pub imported_files: usize,
    /// Number of virtual directories created via `DaemonRequest::CreateDirectory`.
    pub created_dirs: usize,
    /// Number of symbolic links safely skipped.
    pub skipped_symlinks: usize,
    /// Human-readable completion message.
    pub message: String,
}

/// Recursively walks `local_paths` (skipping all symlinks so directory cycles or host file leaks
/// cannot occur) and dispatches `DaemonRequest::CreateDirectory` + `DaemonRequest::ImportLocalFile`
/// into `target_virtual_dir`.
pub fn import_local_paths_recursive(
    client: &IpcClient,
    local_paths: &[PathBuf],
    target_virtual_dir: &str,
) -> Result<ImportSummary, String> {
    if local_paths.is_empty() {
        return Err("No local files or folders selected for import".to_owned());
    }

    let base_vdir = normalize_ui_vpath(target_virtual_dir);
    let mut imported_files = 0usize;
    let mut created_dirs = 0usize;
    let mut skipped_symlinks = 0usize;
    let mut last_msg = String::new();

    for src_path in local_paths {
        if src_path.as_os_str().is_empty() {
            continue;
        }
        let meta = std::fs::symlink_metadata(src_path)
            .map_err(|err| format!("Failed inspecting {}: {err}", src_path.display()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            skipped_symlinks += 1;
            continue;
        }

        if ft.is_file() {
            let Some(file_name) = valid_utf8_basename(src_path) else {
                return Err(format!(
                    "File has an unsupported or non-UTF-8 name: {}",
                    src_path.display()
                ));
            };
            let dest_vpath = join_ui_vpath(&base_vdir, file_name);
            last_msg = send_import_file(client, src_path, &dest_vpath)?;
            imported_files += 1;
            continue;
        }

        if ft.is_dir() {
            let Some(dir_name) = valid_utf8_basename(src_path) else {
                return Err(format!(
                    "Folder has an unsupported or non-UTF-8 name: {}",
                    src_path.display()
                ));
            };
            let root_vpath = join_ui_vpath(&base_vdir, dir_name);
            if create_dir_idempotent(client, &root_vpath)? {
                created_dirs += 1;
            }

            let mut stack: Vec<(PathBuf, String)> = vec![(src_path.clone(), root_vpath)];
            while let Some((cur_local, cur_vpath)) = stack.pop() {
                let rd = std::fs::read_dir(&cur_local)
                    .map_err(|err| format!("Failed reading folder {}: {err}", cur_local.display()))?;
                let mut children: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                children.sort();

                for child in children {
                    let Ok(cmeta) = std::fs::symlink_metadata(&child) else {
                        continue;
                    };
                    let cft = cmeta.file_type();
                    if cft.is_symlink() {
                        skipped_symlinks += 1;
                        continue;
                    }
                    let Some(cname) = valid_utf8_basename(&child) else {
                        continue;
                    };
                    let child_vpath = join_ui_vpath(&cur_vpath, cname);
                    if cft.is_dir() {
                        if create_dir_idempotent(client, &child_vpath)? {
                            created_dirs += 1;
                        }
                        stack.push((child, child_vpath));
                    } else if cft.is_file() {
                        last_msg = send_import_file(client, &child, &child_vpath)?;
                        imported_files += 1;
                    }
                }
            }
        }
    }

    if imported_files == 0 && created_dirs == 0 {
        return Err(format!(
            "No regular files or folders imported ({skipped_symlinks} symlink(s) skipped)"
        ));
    }

    let message = if imported_files == 1 && created_dirs == 0 && !last_msg.is_empty() {
        last_msg
    } else {
        format!(
            "Encrypted & imported {imported_files} file(s) across {created_dirs} folder(s) ({skipped_symlinks} symlinks skipped)"
        )
    };

    Ok(ImportSummary {
        imported_files,
        created_dirs,
        skipped_symlinks,
        message,
    })
}

fn valid_utf8_basename(path: &Path) -> Option<&str> {
    path.file_name()
        .and_then(|os| os.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
}

fn create_dir_idempotent(client: &IpcClient, virtual_path: &str) -> Result<bool, String> {
    let resp = client
        .request(&DaemonRequest::CreateDirectory {
            virtual_path: virtual_path.to_owned(),
        })
        .map_err(|err| err.to_string())?;
    match resp {
        DaemonResponse::Ok { .. } => Ok(true),
        DaemonResponse::Error { code, .. }
            if code == "already_exists" || code.contains("exists") =>
        {
            Ok(false)
        }
        DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
        other => Err(format!("Unexpected CreateDirectory response: {other:?}")),
    }
}

fn send_import_file(
    client: &IpcClient,
    local_file: &Path,
    dest_virtual_path: &str,
) -> Result<String, String> {
    let local_str = local_file
        .to_str()
        .ok_or_else(|| format!("Local path is not valid UTF-8: {}", local_file.display()))?
        .to_owned();
    let resp = client
        .request(&DaemonRequest::ImportLocalFile {
            local_path: local_str,
            virtual_dest_path: dest_virtual_path.to_owned(),
        })
        .map_err(|err| err.to_string())?;
    match resp {
        DaemonResponse::Ok { message } => Ok(message),
        DaemonResponse::Error { code, message } => Err(format!("[{code}] {message}")),
        other => Err(format!("Unexpected ImportLocalFile response: {other:?}")),
    }
}

/// Exports `virtual_path` from `zerovaultd` into a fresh owner-only temporary preview directory
/// and returns the exported file path (ready for `open_in_os_default_app`).
pub fn export_for_secure_preview(
    client: &IpcClient,
    session_root: &Path,
    virtual_path: &str,
) -> Result<PathBuf, String> {
    let norm = normalize_ui_vpath(virtual_path);
    let (_, file_name) = split_ui_parent_and_name(&norm)?;
    let subdir = create_unique_preview_subdir(session_root)?;
    let dest_path = subdir.join(&file_name);
    let dest_str = dest_path
        .to_str()
        .ok_or_else(|| "Session preview path is not valid UTF-8".to_owned())?
        .to_owned();

    let resp = client
        .request(&DaemonRequest::ExportVaultFile {
            virtual_path: norm,
            local_dest_path: dest_str,
        })
        .map_err(|err| err.to_string())?;

    match resp {
        DaemonResponse::Ok { .. } => Ok(dest_path),
        DaemonResponse::Error { code, message } => {
            let _ = std::fs::remove_dir_all(&subdir);
            Err(format!("[{code}] {message}"))
        }
        other => {
            let _ = std::fs::remove_dir_all(&subdir);
            Err(format!("Unexpected ExportVaultFile response: {other:?}"))
        }
    }
}

/// Opens a file or folder in the operating system's default desktop handler (`ShellExecuteW` on Windows, `xdg-open` on Linux).
pub fn open_in_os_default_app(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path does not exist on disk: {}", path.display()));
    }

    #[cfg(target_os = "windows")]
    {
        use widestring::U16CString;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::PCWSTR;

        let wide_path = U16CString::from_os_str(path.as_os_str())
            .map_err(|err| format!("Invalid path for ShellExecuteW: {err}"))?;
        // SAFETY: `wide_path` is null-terminated UTF-16 valid for the call duration.
        let res = unsafe {
            ShellExecuteW(
                None,
                windows::core::w!("open"),
                PCWSTR(wide_path.as_ptr()),
                None,
                None,
                SW_SHOWNORMAL,
            )
        };
        if (res.0 as isize) <= 32 {
            return Err(format!(
                "Windows ShellExecuteW could not open path (code {})",
                res.0 as isize
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|err| format!("Failed launching macOS open: {err}"))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        spawn_xdg_open_detached(path.as_os_str(), "path")
    }
}

/// Safely opens an `https://` documentation or cloud console URL in the user's default browser.
pub fn open_https_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return Err("Refusing to open non-HTTPS external link".to_owned());
    }

    #[cfg(target_os = "windows")]
    {
        use widestring::U16CString;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::PCWSTR;

        let wide_url = U16CString::from_str(trimmed)
            .map_err(|err| format!("Invalid URL string: {err}"))?;
        // SAFETY: `wide_url` is null-terminated UTF-16 valid for the call duration.
        let res = unsafe {
            ShellExecuteW(
                None,
                windows::core::w!("open"),
                PCWSTR(wide_url.as_ptr()),
                None,
                None,
                SW_SHOWNORMAL,
            )
        };
        if (res.0 as isize) <= 32 {
            return Err(format!(
                "Could not open browser for URL (code {})",
                res.0 as isize
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(trimmed)
            .spawn()
            .map_err(|err| format!("Failed launching browser: {err}"))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        spawn_xdg_open_detached(std::ffi::OsStr::new(trimmed), "browser URL")
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_xdg_open_detached(target: &std::ffi::OsStr, kind_label: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("xdg-open")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                format!("Failed opening {kind_label}: xdg-open was not found (install xdg-utils)")
            } else {
                format!("Failed launching xdg-open for {kind_label}: {err}")
            }
        })?;

    // Reap the short-lived `xdg-open` wrapper asynchronously so we stay non-blocking
    // on the UI thread without accumulating `<defunct>` zombie processes.
    let _ = std::thread::Builder::new()
        .name("ec-xdg-reap".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
    Ok(())
}
