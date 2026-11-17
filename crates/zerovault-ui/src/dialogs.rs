//! Native OS file/folder/save dialogs and default application launcher.
//!
//! Uses Win32 Common Item Dialogs (`IFileOpenDialog` / `IFileSaveDialog`) on Windows
//! inside dedicated STA COM threads and `ShellExecuteW` to open decrypted session files,
//! avoiding console popups or non-native folder browsers.

use std::path::Path;

/// Opens the native OS multi-file picker dialog.
///
/// Returns:
/// - `Ok(Some(paths))` when native dialog is available (`paths` empty when user cancelled),
/// - `Ok(None)` when no native dialog helper is installed on the host OS (triggers built-in fallback),
/// - `Err(msg)` if dialog initialization failed unexpectedly.
pub fn pick_files_native(title: &str) -> Result<Option<Vec<String>>, String> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::pick_files(title).map(Some)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_impl::pick_files(title)
    }
    #[cfg(not(any(target_os = "windows", all(unix, not(target_os = "macos")))))]
    {
        let _ = title;
        Ok(None)
    }
}

/// Opens the native OS folder picker dialog.
///
/// Returns `Ok(Some(Some(path)))` when chosen, `Ok(Some(None))` when cancelled, or
/// `Ok(None)` when no native dialog helper is present.
pub fn pick_folder_native(title: &str) -> Result<Option<Option<String>>, String> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::pick_folder(title).map(Some)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_impl::pick_folder(title)
    }
    #[cfg(not(any(target_os = "windows", all(unix, not(target_os = "macos")))))]
    {
        let _ = title;
        Ok(None)
    }
}

/// Opens the native OS "Save As" file dialog prefilled with `suggested_name`.
///
/// Returns `Ok(Some(Some(path)))` when chosen, `Ok(Some(None))` when cancelled, or
/// `Ok(None)` when no native dialog helper is present.
pub fn pick_save_file_native(
    title: &str,
    suggested_name: &str,
) -> Result<Option<Option<String>>, String> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::pick_save_file(title, suggested_name).map(Some)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_impl::pick_save_file(title, suggested_name)
    }
    #[cfg(not(any(target_os = "windows", all(unix, not(target_os = "macos")))))]
    {
        let _ = (title, suggested_name);
        Ok(None)
    }
}

/// Opens an exported/session file in the host operating system's default application.
pub fn open_file_in_os_default_app(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("File does not exist on disk".to_owned());
    }

    #[cfg(target_os = "windows")]
    {
        windows_impl::shell_open_path(path)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|err| format!("Failed opening file: {err}"))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|err| format!("Failed opening file: {err}"))?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::path::Path;

    use widestring::U16CString;
    use windows::Win32::Foundation::ERROR_CANCELLED;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoTaskMemFree, CoUninitialize,
    };
    use windows::Win32::UI::Shell::{
        FOS_ALLOWMULTISELECT, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT,
        FOS_PATHMUSTEXIST, FOS_PICKFOLDERS, FileOpenDialog, FileSaveDialog, IFileDialog,
        IFileOpenDialog, IFileSaveDialog, IShellItem, SIGDN_FILESYSPATH, ShellExecuteW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HRESULT, Interface, PCWSTR};

    struct ComApartmentGuard(bool);

    impl ComApartmentGuard {
        fn init_sta() -> Result<Self, String> {
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            if hr.is_err() {
                return Err(format!("Failed initializing Windows file dialog runtime ({hr:?})"));
            }
            Ok(Self(true))
        }
    }

    impl Drop for ComApartmentGuard {
        fn drop(&mut self) {
            if self.0 {
                unsafe { CoUninitialize() };
            }
        }
    }

    fn is_cancelled(err: &windows::core::Error) -> bool {
        err.code() == HRESULT::from_win32(ERROR_CANCELLED.0)
    }

    fn shell_item_to_string(item: &IShellItem) -> Result<String, String> {
        let wide_ptr = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }
            .map_err(|err| format!("Failed reading selected path: {err}"))?;
        let text = unsafe { wide_ptr.to_string() }
            .map_err(|err| format!("Selected path is not valid UTF-16: {err}"));
        unsafe { CoTaskMemFree(Some(wide_ptr.as_ptr().cast())) };
        text
    }

    fn run_on_sta_thread<T, F>(work: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, String> + Send + 'static,
    {
        std::thread::spawn(work)
            .join()
            .map_err(|_| "Windows file dialog worker thread terminated unexpectedly".to_owned())?
    }

    pub fn pick_files(title: &str) -> Result<Vec<String>, String> {
        let owned_title = title.to_owned();
        run_on_sta_thread(move || {
            let _com = ComApartmentGuard::init_sta()?;
            let wide_title = U16CString::from_str(&owned_title)
                .map_err(|err| format!("Invalid dialog title: {err}"))?;

            let dialog: IFileOpenDialog =
                unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|err| format!("Failed creating Windows Open File dialog: {err}"))?;
            let file_dialog: IFileDialog = dialog
                .cast()
                .map_err(|err| format!("Failed accessing IFileDialog interface: {err}"))?;

            unsafe {
                let opts = file_dialog
                    .GetOptions()
                    .map_err(|err| format!("Failed reading dialog options: {err}"))?;
                file_dialog
                    .SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_ALLOWMULTISELECT)
                    .map_err(|err| format!("Failed configuring dialog options: {err}"))?;
                file_dialog
                    .SetTitle(PCWSTR(wide_title.as_ptr()))
                    .map_err(|err| format!("Failed setting dialog title: {err}"))?;
                if let Err(err) = file_dialog.Show(None) {
                    if is_cancelled(&err) {
                        return Ok(Vec::new());
                    }
                    return Err(format!("Failed showing Open File dialog: {err}"));
                }

                let results = dialog
                    .GetResults()
                    .map_err(|err| format!("Failed reading selected files: {err}"))?;
                let count = results
                    .GetCount()
                    .map_err(|err| format!("Failed counting selected files: {err}"))?;
                let mut paths = Vec::with_capacity(count as usize);
                for idx in 0..count {
                    let item = results
                        .GetItemAt(idx)
                        .map_err(|err| format!("Failed inspecting selected file {idx}: {err}"))?;
                    paths.push(shell_item_to_string(&item)?);
                }
                Ok(paths)
            }
        })
    }

    pub fn pick_folder(title: &str) -> Result<Option<String>, String> {
        let owned_title = title.to_owned();
        run_on_sta_thread(move || {
            let _com = ComApartmentGuard::init_sta()?;
            let wide_title = U16CString::from_str(&owned_title)
                .map_err(|err| format!("Invalid dialog title: {err}"))?;

            let dialog: IFileOpenDialog =
                unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|err| format!("Failed creating Windows Folder dialog: {err}"))?;
            let file_dialog: IFileDialog = dialog
                .cast()
                .map_err(|err| format!("Failed accessing IFileDialog interface: {err}"))?;

            unsafe {
                let opts = file_dialog
                    .GetOptions()
                    .map_err(|err| format!("Failed reading dialog options: {err}"))?;
                file_dialog
                    .SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST)
                    .map_err(|err| format!("Failed configuring folder dialog options: {err}"))?;
                file_dialog
                    .SetTitle(PCWSTR(wide_title.as_ptr()))
                    .map_err(|err| format!("Failed setting dialog title: {err}"))?;
                if let Err(err) = file_dialog.Show(None) {
                    if is_cancelled(&err) {
                        return Ok(None);
                    }
                    return Err(format!("Failed showing Folder dialog: {err}"));
                }

                let item = file_dialog
                    .GetResult()
                    .map_err(|err| format!("Failed reading selected folder: {err}"))?;
                shell_item_to_string(&item).map(Some)
            }
        })
    }

    pub fn pick_save_file(title: &str, suggested_name: &str) -> Result<Option<String>, String> {
        let owned_title = title.to_owned();
        let owned_name = suggested_name.to_owned();
        run_on_sta_thread(move || {
            let _com = ComApartmentGuard::init_sta()?;
            let wide_title = U16CString::from_str(&owned_title)
                .map_err(|err| format!("Invalid dialog title: {err}"))?;
            let wide_name = U16CString::from_str(&owned_name)
                .map_err(|err| format!("Invalid suggested file name: {err}"))?;

            let dialog: IFileSaveDialog =
                unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|err| format!("Failed creating Windows Save dialog: {err}"))?;
            let file_dialog: IFileDialog = dialog
                .cast()
                .map_err(|err| format!("Failed accessing IFileDialog interface: {err}"))?;

            unsafe {
                let opts = file_dialog
                    .GetOptions()
                    .map_err(|err| format!("Failed reading dialog options: {err}"))?;
                file_dialog
                    .SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT)
                    .map_err(|err| format!("Failed configuring save dialog options: {err}"))?;
                file_dialog
                    .SetTitle(PCWSTR(wide_title.as_ptr()))
                    .map_err(|err| format!("Failed setting dialog title: {err}"))?;
                if !owned_name.trim().is_empty() {
                    file_dialog
                        .SetFileName(PCWSTR(wide_name.as_ptr()))
                        .map_err(|err| format!("Failed prefilling file name: {err}"))?;
                }
                if let Err(err) = file_dialog.Show(None) {
                    if is_cancelled(&err) {
                        return Ok(None);
                    }
                    return Err(format!("Failed showing Save dialog: {err}"));
                }

                let item = file_dialog
                    .GetResult()
                    .map_err(|err| format!("Failed reading destination file path: {err}"))?;
                shell_item_to_string(&item).map(Some)
            }
        })
    }

    pub fn shell_open_path(path: &Path) -> Result<(), String> {
        let wide_path = U16CString::from_os_str(path.as_os_str())
            .map_err(|err| format!("Invalid Windows path for ShellExecute: {err}"))?;
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
                "Windows could not open this file with a default program (code {})",
                res.0 as isize
            ));
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux_impl {
    use std::io::ErrorKind;
    use std::process::Command;

    pub fn pick_files(title: &str) -> Result<Option<Vec<String>>, String> {
        let output = match Command::new("zenity")
            .args([
                "--file-selection",
                "--multiple",
                "--separator=\n",
                "--title",
                title,
            ])
            .output()
        {
            Ok(out) => out,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("Failed launching file picker: {err}")),
        };
        if !output.status.success() {
            return Ok(Some(Vec::new()));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let paths = stdout
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(Some(paths))
    }

    pub fn pick_folder(title: &str) -> Result<Option<Option<String>>, String> {
        let output = match Command::new("zenity")
            .args(["--file-selection", "--directory", "--title", title])
            .output()
        {
            Ok(out) => out,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("Failed launching folder picker: {err}")),
        };
        if !output.status.success() {
            return Ok(Some(None));
        }
        let selected = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if selected.is_empty() {
            Ok(Some(None))
        } else {
            Ok(Some(Some(selected)))
        }
    }

    pub fn pick_save_file(
        title: &str,
        suggested_name: &str,
    ) -> Result<Option<Option<String>>, String> {
        let filename_arg = format!("--filename={suggested_name}");
        let output = match Command::new("zenity")
            .args([
                "--file-selection",
                "--save",
                "--confirm-overwrite",
                "--title",
                title,
                &filename_arg,
            ])
            .output()
        {
            Ok(out) => out,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("Failed launching save dialog: {err}")),
        };
        if !output.status.success() {
            return Ok(Some(None));
        }
        let selected = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if selected.is_empty() {
            Ok(Some(None))
        } else {
            Ok(Some(Some(selected)))
        }
    }
}
