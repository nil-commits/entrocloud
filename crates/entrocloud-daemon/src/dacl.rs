//! Cross-platform owner-only security descriptor (`PROTECTED_DACL` / `0700` / `0600`) hardening
//! for `zerovaultd` IPC Named Pipes, `state_dir`, `staging_dir`, and state files.

use std::path::Path;

use entrocloud_types::{ZeroVaultError, ZeroVaultResult};

/// Protected owner-only SDDL (`SYSTEM` + `OWNER RIGHTS`, inheritance blocked) for Windows Named Pipes.
pub const OWNER_ONLY_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;OW)";

/// Protected owner-only SDDL with container/object inheritance (`OICI`) for `state_dir` and `staging_dir`
/// so SQLite WAL (`metadata.db-wal`) and `.zvpart` files automatically inherit strict owner-only ACEs.
pub const OWNER_ONLY_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)";

/// Protected owner-only SDDL for individual local state files on Windows.
pub const OWNER_ONLY_FILE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;OW)";

/// Returns `true` if `meta` represents a symlink or Windows NTFS reparse point / junction.
#[must_use]
pub fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

/// Creates `dir` if missing, rejects symlinks/reparse points fail-closed, and applies strict
/// owner-only permissions (`D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)` on Windows, `0o700` on Unix).
pub fn ensure_owner_only_dir(dir: &Path) -> ZeroVaultResult<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(ZeroVaultError::InvalidPath(format!(
                    "refusing to use symlink or reparse point directory: {}",
                    dir.display()
                )));
            }
            if !meta.is_dir() {
                return Err(ZeroVaultError::InvalidPath(format!(
                    "expected directory at {}, found non-directory",
                    dir.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(dir)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(dir)?;
            }
        }
        Err(err) => return Err(err.into()),
    }

    let post_meta = std::fs::symlink_metadata(dir)?;
    if is_symlink_or_reparse(&post_meta) || !post_meta.is_dir() {
        return Err(ZeroVaultError::InvalidPath(format!(
            "directory validation failed after creation: {}",
            dir.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }

    #[cfg(target_os = "windows")]
    {
        win_acl::apply_sddl_dacl_to_path(dir, OWNER_ONLY_DIR_SDDL)?;
    }

    Ok(())
}

/// Applies strict owner-only permissions (`D:P(A;;GA;;;SY)(A;;GA;;;OW)` on Windows, `0o600` on Unix)
/// to an existing regular state file, rejecting symlinks/reparse points fail-closed.
pub fn ensure_owner_only_file(path: &Path) -> ZeroVaultResult<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(ZeroVaultError::InvalidPath(format!(
            "refusing to harden non-regular or symlink file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(target_os = "windows")]
    {
        win_acl::apply_sddl_dacl_to_path(path, OWNER_ONLY_FILE_SDDL)?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub mod win_acl {
    //! Win32 SDDL parsing, Named Pipe `SECURITY_ATTRIBUTES`, and `SetNamedSecurityInfoW` helpers.

    use std::ffi::c_void;
    use std::path::Path;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use widestring::U16CString;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    };
    use windows::core::{BOOL, PCWSTR, PWSTR};
    use entrocloud_types::{ZeroVaultError, ZeroVaultResult};

    use super::OWNER_ONLY_PIPE_SDDL;

    struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl OwnedSecurityDescriptor {
        fn from_sddl(sddl: &str) -> ZeroVaultResult<Self> {
            let wide_sddl = U16CString::from_str(sddl).map_err(|e| {
                ZeroVaultError::ConfigError(format!("invalid SDDL string '{sddl}': {e}"))
            })?;
            let mut raw_sd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `wide_sddl` is a valid NUL-terminated UTF-16 string and `raw_sd` receives
            // heap memory allocated with `LocalAlloc` by Win32 on success.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide_sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut raw_sd,
                    None,
                )
                .map_err(|e| {
                    ZeroVaultError::IpcError(format!(
                        "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for '{sddl}': {e}"
                    ))
                })?;
            }
            if raw_sd.is_invalid() {
                return Err(ZeroVaultError::IpcError(
                    "Win32 returned null PSECURITY_DESCRIPTOR".into(),
                ));
            }
            Ok(Self(raw_sd))
        }

        fn as_raw(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
                // and must be released once via `LocalFree`.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0.0)));
                }
            }
        }
    }

    /// Creates a Windows Named Pipe server instance protected by `D:P(A;;GA;;;SY)(A;;GA;;;OW)`,
    /// `first_pipe_instance(first_instance)`, and `reject_remote_clients(true)`.
    pub fn create_owner_only_named_pipe(
        pipe_name: &str,
        first_instance: bool,
    ) -> ZeroVaultResult<NamedPipeServer> {
        let sd = OwnedSecurityDescriptor::from_sddl(OWNER_ONLY_PIPE_SDDL)?;
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
            lpSecurityDescriptor: sd.as_raw().0,
            bInheritHandle: BOOL(0),
        };

        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first_instance)
            .reject_remote_clients(true);

        // SAFETY: `sa` points to a valid `SECURITY_ATTRIBUTES` whose `lpSecurityDescriptor`
        // outlives `create_with_security_attributes_raw` (`sd` drops after this call).
        let server = unsafe {
            opts.create_with_security_attributes_raw(
                pipe_name,
                (&raw mut sa).cast::<c_void>(),
            )
        }
        .map_err(|e| {
            ZeroVaultError::IpcError(format!(
                "failed to create owner-only Windows named pipe '{pipe_name}': {e}"
            ))
        })?;

        Ok(server)
    }

    /// Applies `sddl` as a `PROTECTED_DACL` on `path` using `SetNamedSecurityInfoW`.
    pub fn apply_sddl_dacl_to_path(path: &Path, sddl: &str) -> ZeroVaultResult<()> {
        let sd = OwnedSecurityDescriptor::from_sddl(sddl)?;
        let mut dacl_present = BOOL(0);
        let mut dacl_defaulted = BOOL(0);
        let mut p_dacl: *mut ACL = std::ptr::null_mut();

        // SAFETY: `sd` is a valid security descriptor constructed by Win32; `p_dacl` borrows internal memory of `sd`.
        unsafe {
            GetSecurityDescriptorDacl(
                sd.as_raw(),
                &mut dacl_present,
                &mut p_dacl,
                &mut dacl_defaulted,
            )
            .map_err(|e| {
                ZeroVaultError::Io(std::io::Error::other(format!(
                    "GetSecurityDescriptorDacl failed: {e}"
                )))
            })?;
        }

        if !dacl_present.as_bool() || p_dacl.is_null() {
            return Err(ZeroVaultError::ConfigError(format!(
                "SDDL '{sddl}' did not yield a non-null DACL"
            )));
        }

        let wide_path = U16CString::from_os_str(path.as_os_str()).map_err(|e| {
            ZeroVaultError::InvalidPath(format!("path contains interior NUL: {e}"))
        })?;

        // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 path and `p_dacl` remains valid until `sd` drops.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide_path.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(p_dacl.cast_const()),
                None,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(ZeroVaultError::Io(std::io::Error::from_raw_os_error(
                status.0 as i32,
            )));
        }

        Ok(())
    }

    /// Reads the current DACL SDDL string from `path` via `GetNamedSecurityInfoW` (for verification).
    pub fn query_path_dacl_sddl(path: &Path) -> ZeroVaultResult<String> {
        let wide_path = U16CString::from_os_str(path.as_os_str()).map_err(|e| {
            ZeroVaultError::InvalidPath(format!("path contains interior NUL: {e}"))
        })?;
        let mut raw_sd = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `wide_path` is NUL-terminated UTF-16; `raw_sd` is allocated by Win32 on `ERROR_SUCCESS`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide_path.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut raw_sd,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(ZeroVaultError::Io(std::io::Error::from_raw_os_error(
                status.0 as i32,
            )));
        }
        let sd_guard = OwnedSecurityDescriptor(raw_sd);

        let mut str_ptr = PWSTR::null();
        // SAFETY: `sd_guard` holds a valid security descriptor; `str_ptr` is allocated by Win32 on success.
        let conv_res = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_guard.as_raw(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut str_ptr,
                None,
            )
        };
        conv_res.map_err(|e| {
            ZeroVaultError::Io(std::io::Error::other(format!(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {e}"
            )))
        })?;

        if str_ptr.is_null() {
            return Err(ZeroVaultError::Io(std::io::Error::other(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW returned null",
            )));
        }

        // SAFETY: `str_ptr` is a valid NUL-terminated UTF-16 buffer allocated with `LocalAlloc`.
        let sddl_string = unsafe {
            let mut len = 0usize;
            while *str_ptr.0.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(str_ptr.0, len);
            let s = String::from_utf16_lossy(slice);
            let _ = LocalFree(Some(HLOCAL(str_ptr.0.cast::<c_void>())));
            s
        };

        Ok(sddl_string)
    }
}
