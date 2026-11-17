//! Placeholder identity encoding, metadata conversion, and 4 KiB-aligned streaming hydration.

use std::ops::Range;
use std::path::{Component, Path, PathBuf, Prefix};

use chrono::{DateTime, Utc};
use cloud_filter::error::CloudErrorKind;
use cloud_filter::filter::ticket;
use cloud_filter::metadata::Metadata;
use cloud_filter::placeholder_create_info::PlaceholderCreateInfo;
use cloud_filter::utility::WriteAt;
use nt_time::FileTime;
use uuid::Uuid;
use windows::Win32::Foundation;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
};
use zerovault_types::{
    EntryKind, HydrationState, InodeId, InodeRecord, PLAINTEXT_CHUNK_SIZE, VfsBackend,
    ZeroVaultError, ZeroVaultResult,
};

/// 4-byte magic prefix for Zerovault NTFS `FileIdentity` blobs.
pub const FILE_IDENTITY_MAGIC: [u8; 4] = *b"ZVID";

/// Fixed binary byte length of an encoded [`FileIdentity`] (`4B magic + 8B inode LE + 16B file_id`).
pub const FILE_IDENTITY_LEN: usize = 28;

/// Windows Cloud Filter (`CfTransferData`) required block alignment in bytes (4 KiB).
pub const CFAPI_BLOCK_ALIGN: u64 = 4096;

/// Maximum plaintext slice streamed per `CfTransferData` call (4 MiB = `1024 * 4 KiB`).
pub const MAX_HYDRATION_STREAM_SLICE: usize = PLAINTEXT_CHUNK_SIZE;

/// Compact binary identity stored inside each NTFS placeholder's `FileIdentity` blob.
///
/// Layout (28 bytes total):
/// - `[0..4]`: magic `b"ZVID"`
/// - `[4..12]`: `inode` (`u64` little-endian)
/// - `[12..28]`: `file_id` (`[u8; 16]` big-endian UUID bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// Virtual inode identifier inside [`VfsBackend`].
    pub inode: InodeId,
    /// Stable cryptographic file UUID bound into chunk AADs.
    pub file_id: Uuid,
}

impl FileIdentity {
    /// Constructs a [`FileIdentity`] from an inode number and cryptographic [`Uuid`].
    #[must_use]
    pub const fn new(inode: InodeId, file_id: Uuid) -> Self {
        Self { inode, file_id }
    }

    /// Constructs a [`FileIdentity`] from an inode number and raw 16-byte UUID array.
    #[must_use]
    pub const fn from_raw(inode: InodeId, file_id: [u8; 16]) -> Self {
        Self {
            inode,
            file_id: Uuid::from_bytes(file_id),
        }
    }

    /// Extracts a [`FileIdentity`] from an [`InodeRecord`].
    #[must_use]
    pub const fn from_record(record: &InodeRecord) -> Self {
        Self {
            inode: record.inode,
            file_id: record.file_id,
        }
    }

    /// Returns the raw 16-byte UUID payload.
    #[must_use]
    pub const fn file_id_bytes(&self) -> &[u8; 16] {
        self.file_id.as_bytes()
    }

    /// Encodes the identity into its exact 28-byte binary representation.
    #[must_use]
    pub fn encode(&self) -> [u8; FILE_IDENTITY_LEN] {
        let mut out = [0u8; FILE_IDENTITY_LEN];
        out[0..4].copy_from_slice(&FILE_IDENTITY_MAGIC);
        out[4..12].copy_from_slice(&self.inode.to_le_bytes());
        out[12..28].copy_from_slice(self.file_id.as_bytes());
        out
    }

    /// Encodes the identity into a freshly allocated 28-byte vector for CfApi blob APIs.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.encode().to_vec()
    }

    /// Decodes and validates a 28-byte [`FileIdentity`] blob.
    pub fn decode(bytes: &[u8]) -> ZeroVaultResult<Self> {
        if bytes.len() != FILE_IDENTITY_LEN {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "file identity length must be {FILE_IDENTITY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[0..4] != FILE_IDENTITY_MAGIC {
            return Err(ZeroVaultError::InvalidWireFormat(
                "invalid file identity magic".into(),
            ));
        }

        let inode = u64::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let file_id_bytes: [u8; 16] = bytes[12..28]
            .try_into()
            .map_err(|_| ZeroVaultError::InvalidWireFormat("invalid file_id slice".into()))?;

        Ok(Self {
            inode,
            file_id: Uuid::from_bytes(file_id_bytes),
        })
    }
}

/// Converts a UTC timestamp into a signed-safe Windows `nt_time::FileTime`.
///
/// `cloud_filter::metadata::Metadata` stores timestamps as `i64`, so values above
/// `FileTime::SIGNED_MAX` or before the Windows epoch (`1601-01-01`) are clamped.
#[must_use]
pub fn datetime_to_file_time(dt: DateTime<Utc>) -> FileTime {
    let ft = FileTime::from_unix_time(dt.timestamp(), dt.timestamp_subsec_nanos())
        .unwrap_or(FileTime::NT_TIME_EPOCH);
    if ft > FileTime::SIGNED_MAX {
        FileTime::SIGNED_MAX
    } else {
        ft
    }
}

/// Inspectable placeholder creation specification derived from an [`InodeRecord`].
///
/// `cloud_filter::placeholder_create_info::PlaceholderCreateInfo` keeps its inner Win32 struct
/// private; [`PlaceholderSpec`] exposes deterministic fields for testing and converts cleanly into
/// [`PlaceholderCreateInfo`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderSpec {
    /// Child basename relative to parent directory.
    pub relative_name: String,
    /// `true` for directory placeholders, `false` for sparse regular file placeholders.
    pub is_directory: bool,
    /// Logical plaintext file size (`0` for directories).
    pub file_size: u64,
    /// Win32 file attributes (`FILE_ATTRIBUTE_NORMAL`, `FILE_ATTRIBUTE_DIRECTORY`, etc.).
    pub file_attributes: u32,
    /// Creation timestamp as Windows `FileTime`.
    pub created_at: FileTime,
    /// Last write / modification timestamp as Windows `FileTime`.
    pub modified_at: FileTime,
    /// Whether `CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC` should be set.
    pub mark_in_sync: bool,
    /// Compact 28-byte identity embedded in the placeholder.
    pub identity: FileIdentity,
}

impl PlaceholderSpec {
    /// Builds a validated [`PlaceholderSpec`] from an [`InodeRecord`].
    pub fn from_record(record: &InodeRecord) -> ZeroVaultResult<Self> {
        validate_windows_entry_name(&record.name)?;

        let is_directory = record.kind == EntryKind::Directory;
        let mut file_attributes = if is_directory {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };
        if !is_directory && (record.mode & 0o200) == 0 {
            file_attributes |= FILE_ATTRIBUTE_READONLY.0;
        }

        Ok(Self {
            relative_name: record.name.clone(),
            is_directory,
            file_size: if is_directory { 0 } else { record.size },
            file_attributes,
            created_at: datetime_to_file_time(record.created_at),
            modified_at: datetime_to_file_time(record.modified_at),
            mark_in_sync: record.hydration != HydrationState::DirtyLocal,
            identity: FileIdentity::from_record(record),
        })
    }

    /// Builds `cloud_filter::metadata::Metadata` matching this specification.
    #[must_use]
    pub fn to_cf_metadata(&self) -> Metadata {
        let base = if self.is_directory {
            Metadata::directory()
        } else {
            Metadata::file().size(self.file_size)
        };
        base.created(self.created_at)
            .written(self.modified_at)
            .changed(self.modified_at)
            .accessed(self.modified_at)
            .attributes(self.file_attributes)
    }

    /// Converts this specification into a [`PlaceholderCreateInfo`] ready for CfApi.
    #[must_use]
    pub fn into_create_info(&self) -> PlaceholderCreateInfo {
        let mut info = PlaceholderCreateInfo::new(&self.relative_name)
            .metadata(self.to_cf_metadata())
            .blob(self.identity.to_vec());

        if self.mark_in_sync {
            info = info.mark_in_sync();
        }
        info
    }
}

/// Validates a single path segment for Windows NTFS placeholder creation.
pub fn validate_windows_entry_name(name: &str) -> ZeroVaultResult<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ZeroVaultError::InvalidPath(format!(
            "invalid Windows placeholder name: {name:?}"
        )));
    }
    Ok(())
}

/// Builds `cloud_filter::metadata::Metadata` directly from an [`InodeRecord`].
#[must_use]
pub fn metadata_from_record(record: &InodeRecord) -> Metadata {
    let is_directory = record.kind == EntryKind::Directory;
    let mut attrs = if is_directory {
        FILE_ATTRIBUTE_DIRECTORY.0
    } else {
        FILE_ATTRIBUTE_NORMAL.0
    };
    if !is_directory && (record.mode & 0o200) == 0 {
        attrs |= FILE_ATTRIBUTE_READONLY.0;
    }

    let created = datetime_to_file_time(record.created_at);
    let modified = datetime_to_file_time(record.modified_at);
    let base = if is_directory {
        Metadata::directory()
    } else {
        Metadata::file().size(record.size)
    };
    base.created(created)
        .written(modified)
        .changed(modified)
        .accessed(modified)
        .attributes(attrs)
}

/// Converts an [`InodeRecord`] into a sparse NTFS [`PlaceholderCreateInfo`].
///
/// Directories keep on-demand child population enabled so `fetch_placeholders` is triggered when
/// the user opens subdirectories under `PopulationType::Full`.
pub fn placeholder_create_info_from_record(
    record: &InodeRecord,
) -> ZeroVaultResult<PlaceholderCreateInfo> {
    let spec = PlaceholderSpec::from_record(record)?;
    Ok(spec.into_create_info())
}

/// Aligns a requested `[start, end)` hydration byte range to Windows Cloud Filter's 4 KiB
/// transfer rules.
///
/// CfApi requires:
/// - `offset` is a multiple of 4 KiB (`4096`),
/// - `length` is a multiple of 4 KiB unless `offset + length == file_size` (EOF).
///
/// Returns `Ok(None)` when `file_size == 0`, `requested.start >= file_size`, or `requested` is
/// empty (`start == end`). Returns `Err(ZeroVaultError::InvalidRange)` if `requested.start > requested.end`.
pub fn align_cfapi_transfer_range(
    requested: Range<u64>,
    file_size: u64,
) -> ZeroVaultResult<Option<Range<u64>>> {
    if requested.start > requested.end {
        return Err(ZeroVaultError::InvalidRange {
            offset: requested.start,
            len: 0,
            size: file_size,
        });
    }
    if file_size == 0 || requested.is_empty() || requested.start >= file_size {
        return Ok(None);
    }

    let clamped_end = requested.end.min(file_size);
    let align_mask = CFAPI_BLOCK_ALIGN - 1;
    let aligned_start = requested.start & !align_mask;

    let rem = clamped_end & align_mask;
    let rounded_end = if rem == 0 {
        clamped_end
    } else {
        clamped_end
            .checked_add(CFAPI_BLOCK_ALIGN - rem)
            .unwrap_or(file_size)
    };
    let aligned_end = rounded_end.min(file_size);

    if aligned_start >= aligned_end {
        Ok(None)
    } else {
        Ok(Some(aligned_start..aligned_end))
    }
}

/// Clamps and aligns a streaming slice size to `4 KiB..=4 MiB` so every non-EOF transfer
/// satisfies CfApi alignment without full-file buffering.
#[must_use]
pub fn clamp_stream_slice_size(requested_slice_bytes: usize) -> usize {
    let min_align = CFAPI_BLOCK_ALIGN as usize;
    let capped = requested_slice_bytes.clamp(min_align, MAX_HYDRATION_STREAM_SLICE);
    let aligned = capped - (capped % min_align);
    aligned.max(min_align)
}

/// Abstraction over CfApi `ticket::FetchData` transfer & progress calls for unit-testability.
pub trait TransferSink {
    /// Transfers a 4 KiB-aligned slice (or final slice reaching EOF) at `offset`.
    fn write_slice(&self, offset: u64, data: &[u8]) -> Result<(), CloudErrorKind>;

    /// Reports cumulative hydration progress (`completed` out of `total` bytes).
    fn report_progress(&self, total: u64, completed: u64);
}

impl TransferSink for ticket::FetchData {
    fn write_slice(&self, offset: u64, data: &[u8]) -> Result<(), CloudErrorKind> {
        self.write_at(data, offset)
            .map_err(win32_error_to_cloud_error)
    }

    fn report_progress(&self, total: u64, completed: u64) {
        let _ = ticket::FetchData::report_progress(self, total, completed);
    }
}

/// Streams `[requested.start, requested.end)` aligned to 4 KiB boundaries from `backend.read_range`
/// in bounded `<= 4 MiB` slices into `sink`, never buffering the full file in RAM.
///
/// Fails closed if `backend.read_range` returns [`ZeroVaultError::CryptoTamperDetected`] or any
/// short read before `chunk_len`, or if `is_cancelled()` becomes `true`.
pub async fn stream_chunked_hydration<S, C>(
    backend: &dyn VfsBackend,
    inode: InodeId,
    requested: Range<u64>,
    file_size: u64,
    max_slice_bytes: usize,
    is_cancelled: C,
    sink: &S,
) -> Result<u64, CloudErrorKind>
where
    S: TransferSink + ?Sized,
    C: Fn() -> bool,
{
    if is_cancelled() {
        return Err(CloudErrorKind::RequestCancelled);
    }

    let Some(aligned) = align_cfapi_transfer_range(requested, file_size)
        .map_err(|err| zerovault_error_to_cloud_error(&err))?
    else {
        return Ok(0);
    };

    let step = clamp_stream_slice_size(max_slice_bytes);
    let total = aligned.end - aligned.start;
    sink.report_progress(total, 0);

    let mut cursor = aligned.start;
    let mut completed = 0u64;

    while cursor < aligned.end {
        if is_cancelled() {
            return Err(CloudErrorKind::RequestCancelled);
        }

        let remaining = aligned.end - cursor;
        let slice_len = usize::try_from(remaining.min(step as u64)).unwrap_or(step);

        let chunk = backend
            .read_range(inode, cursor, slice_len)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))?;

        if chunk.len() != slice_len {
            return Err(CloudErrorKind::Unsuccessful);
        }

        if is_cancelled() {
            return Err(CloudErrorKind::RequestCancelled);
        }

        sink.write_slice(cursor, &chunk)?;
        drop(chunk);

        cursor += slice_len as u64;
        completed += slice_len as u64;
        sink.report_progress(total, completed);
    }

    Ok(completed)
}

/// Strips Windows verbatim prefixes (`\\?\C:\...` or `\\?\UNC\server\share`) for normalized comparison.
#[must_use]
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let mut comps = path.components();
    let Some(Component::Prefix(prefix)) = comps.next() else {
        return path.to_path_buf();
    };

    let mut normalized = match prefix.kind() {
        Prefix::VerbatimDisk(drive) => {
            PathBuf::from(format!("{}:\\", char::from(drive).to_ascii_uppercase()))
        }
        Prefix::VerbatimUNC(server, share) => {
            let mut unc = PathBuf::from(r"\\");
            unc.push(server);
            unc.push(share);
            unc
        }
        _ => return path.to_path_buf(),
    };

    for comp in comps {
        if !matches!(comp, Component::RootDir) {
            normalized.push(comp.as_os_str());
        }
    }
    normalized
}

/// Converts a full Windows path inside `mount_point` into a normalized Zerovault virtual path
/// (e.g. `"/Docs/report.pdf"`, or `"/"` for `mount_point` itself).
pub fn windows_path_to_virtual_path(mount_point: &Path, full_path: &Path) -> ZeroVaultResult<String> {
    let mount_norm = strip_verbatim_prefix(mount_point);
    let full_norm = strip_verbatim_prefix(full_path);

    let mount_comps: Vec<Component<'_>> = mount_norm
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    let full_comps: Vec<Component<'_>> = full_norm
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();

    if full_comps.len() < mount_comps.len() {
        return Err(ZeroVaultError::InvalidPath(format!(
            "path {} is outside mount point {}",
            full_path.display(),
            mount_point.display()
        )));
    }

    for (m, f) in mount_comps.iter().zip(full_comps.iter()) {
        let m_lower = m.as_os_str().to_string_lossy().to_ascii_lowercase();
        let f_lower = f.as_os_str().to_string_lossy().to_ascii_lowercase();
        if m_lower != f_lower {
            return Err(ZeroVaultError::InvalidPath(format!(
                "path {} is outside mount point {}",
                full_path.display(),
                mount_point.display()
            )));
        }
    }

    let mut segments = Vec::new();
    for comp in &full_comps[mount_comps.len()..] {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or_else(|| {
                    ZeroVaultError::InvalidPath(format!(
                        "non-UTF-8 Windows path segment in {}",
                        full_path.display()
                    ))
                })?;
                if s.is_empty() || s.contains('/') || s.contains('\\') || s.contains('\0') {
                    return Err(ZeroVaultError::InvalidPath(format!(
                        "invalid virtual path segment {s:?}"
                    )));
                }
                segments.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ZeroVaultError::InvalidPath(format!(
                    "disallowed component in relative path {}",
                    full_path.display()
                )));
            }
        }
    }

    if segments.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", segments.join("/")))
    }
}

/// Converts a normalized Zerovault virtual path (e.g. `"/Docs/report.pdf"`) into a Windows path
/// under `mount_point`.
pub fn virtual_path_to_windows_path(
    mount_point: &Path,
    virtual_path: &str,
) -> ZeroVaultResult<PathBuf> {
    if !virtual_path.starts_with('/') {
        return Err(ZeroVaultError::InvalidPath(format!(
            "virtual path must start with '/': {virtual_path}"
        )));
    }
    if virtual_path == "/" {
        return Ok(mount_point.to_path_buf());
    }

    let mut out = mount_point.to_path_buf();
    for seg in virtual_path.trim_start_matches('/').split('/') {
        validate_windows_entry_name(seg)?;
        out.push(seg);
    }
    Ok(out)
}

/// Splits a normalized non-root virtual path (e.g. `"/Docs/report.pdf"`) into `(parent_vpath, name)`.
pub fn split_virtual_parent_and_name(virtual_path: &str) -> ZeroVaultResult<(String, String)> {
    if virtual_path == "/" || !virtual_path.starts_with('/') {
        return Err(ZeroVaultError::InvalidPath(format!(
            "virtual path has no parent/basename: {virtual_path}"
        )));
    }
    let trimmed = virtual_path.trim_end_matches('/');
    let Some(pos) = trimmed.rfind('/') else {
        return Err(ZeroVaultError::InvalidPath(format!(
            "malformed virtual path: {virtual_path}"
        )));
    };
    let name = &trimmed[pos + 1..];
    validate_windows_entry_name(name)?;
    let parent = if pos == 0 {
        "/".to_owned()
    } else {
        trimmed[..pos].to_owned()
    };
    Ok((parent, name.to_owned()))
}

/// Maps domain [`ZeroVaultError`] values to fail-closed Cloud Filter [`CloudErrorKind`] codes.
#[must_use]
pub fn zerovault_error_to_cloud_error(err: &ZeroVaultError) -> CloudErrorKind {
    match err {
        ZeroVaultError::CryptoTamperDetected(_) => CloudErrorKind::Unsuccessful,
        ZeroVaultError::VaultLocked | ZeroVaultError::PinnedDehydrationDenied(_) => {
            CloudErrorKind::AccessDenied
        }
        ZeroVaultError::InvalidPassphrase | ZeroVaultError::KdfPolicyViolation { .. } => {
            CloudErrorKind::AuthenticationFailed
        }
        ZeroVaultError::InvalidWireFormat(_) => CloudErrorKind::MetadataCorrupt,
        ZeroVaultError::InvalidRange { .. }
        | ZeroVaultError::InvalidPath(_)
        | ZeroVaultError::DirectoryNotEmpty(_)
        | ZeroVaultError::AlreadyExists(_)
        | ZeroVaultError::NotADirectory(_)
        | ZeroVaultError::IsADirectory(_) => CloudErrorKind::InvalidRequest,
        ZeroVaultError::StorageNotFound(_)
        | ZeroVaultError::InodeNotFound(_)
        | ZeroVaultError::StorageQuotaExceeded(_)
        | ZeroVaultError::StorageConflict(_)
        | ZeroVaultError::StorageBackendError(_)
        | ZeroVaultError::HardwareAccelerationUnavailable(_)
        | ZeroVaultError::KeyringError(_)
        | ZeroVaultError::OAuthError(_)
        | ZeroVaultError::VfsError(_)
        | ZeroVaultError::MetadataError(_)
        | ZeroVaultError::IpcError(_)
        | ZeroVaultError::ConfigError(_)
        | ZeroVaultError::Io(_) => CloudErrorKind::Unsuccessful,
    }
}

/// Maps Win32 / Cloud Filter `windows::core::Error` values to [`CloudErrorKind`].
#[must_use]
pub fn win32_error_to_cloud_error(err: windows::core::Error) -> CloudErrorKind {
    let code = err.code();
    if code == Foundation::ERROR_CLOUD_FILE_REQUEST_CANCELED.to_hresult()
        || code == Foundation::STATUS_CLOUD_FILE_REQUEST_CANCELED.to_hresult()
    {
        CloudErrorKind::RequestCancelled
    } else if code == Foundation::ERROR_CLOUD_FILE_REQUEST_ABORTED.to_hresult()
        || code == Foundation::STATUS_CLOUD_FILE_REQUEST_ABORTED.to_hresult()
    {
        CloudErrorKind::RequestAborted
    } else if code == Foundation::ERROR_CLOUD_FILE_REQUEST_TIMEOUT.to_hresult()
        || code == Foundation::STATUS_CLOUD_FILE_REQUEST_TIMEOUT.to_hresult()
    {
        CloudErrorKind::RequestTimeout
    } else if code == Foundation::ERROR_CLOUD_FILE_ACCESS_DENIED.to_hresult()
        || code == Foundation::ERROR_ACCESS_DENIED.to_hresult()
    {
        CloudErrorKind::AccessDenied
    } else {
        CloudErrorKind::Unsuccessful
    }
}

/// Wraps a Win32 error into [`ZeroVaultError::VfsError`] with context.
#[must_use]
pub fn win32_error_to_vfs(context: &str, err: windows::core::Error) -> ZeroVaultError {
    ZeroVaultError::VfsError(format!("{context}: {err}"))
}
