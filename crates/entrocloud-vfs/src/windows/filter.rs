//! Cloud Filter (`CfApi`) callback engine and non-blocking state-watcher worker.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::ops::Range;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use cloud_filter::error::{CResult, CloudErrorKind};
use cloud_filter::filter::{Filter, Request, StateWatchEvent, info, ticket};
use cloud_filter::placeholder::{ConvertOptions, PinOptions, PinState, Placeholder, UpdateOptions};
use dashmap::DashMap;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use windows::Win32::Foundation::ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_UNPINNED,
};
use entrocloud_types::{
    CreateEntrySpec, EntryKind, HydrationState, InodeId, InodeRecord, ROOT_INODE, SetAttrSpec,
    VfsBackend, ZeroVaultError, ZeroVaultResult,
};

use super::placeholder::{
    FileIdentity, MAX_HYDRATION_STREAM_SLICE, placeholder_create_info_from_record,
    split_virtual_parent_and_name, stream_chunked_hydration, win32_error_to_cloud_error,
    windows_path_to_virtual_path, zerovault_error_to_cloud_error,
};

const PLACEHOLDER_BATCH_SIZE: usize = 128;

type ActiveFlagMap = DashMap<u64, Arc<AtomicBool>>;
type FileFetchRangeMap = DashMap<i64, Vec<(u64, Range<u64>)>>;

/// RAII cancellation token for an in-flight `CfApi` progressive `fetch_data` transfer.
///
/// Tracks an `Arc<AtomicBool>` inside a `DashMap<u64, Arc<AtomicBool>>` keyed by monotonic
/// `fetch_id`, paired with per-NTFS-file range metadata so overlapping `cancel_fetch_data`
/// requests set the atomic flag immediately and `Drop` removes the active entry cleanly.
pub struct ActiveFetchGuard {
    active_flags: Arc<ActiveFlagMap>,
    file_ranges: Arc<FileFetchRangeMap>,
    ntfs_file_id: i64,
    fetch_id: u64,
    cancelled: Arc<AtomicBool>,
}

impl std::fmt::Debug for ActiveFetchGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveFetchGuard")
            .field("ntfs_file_id", &self.ntfs_file_id)
            .field("fetch_id", &self.fetch_id)
            .field("cancelled", &self.cancelled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ActiveFetchGuard {
    fn register(
        active_flags: Arc<ActiveFlagMap>,
        file_ranges: Arc<FileFetchRangeMap>,
        next_id: &AtomicU64,
        ntfs_file_id: i64,
        range: Range<u64>,
    ) -> Self {
        let fetch_id = next_id.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        active_flags.insert(fetch_id, Arc::clone(&cancelled));
        file_ranges
            .entry(ntfs_file_id)
            .or_default()
            .push((fetch_id, range));
        Self {
            active_flags,
            file_ranges,
            ntfs_file_id,
            fetch_id,
            cancelled,
        }
    }

    /// Unique monotonic fetch identifier assigned to this in-flight transfer.
    #[must_use]
    pub const fn fetch_id(&self) -> u64 {
        self.fetch_id
    }

    /// Returns `true` once `cancel_fetch_data` has flagged an overlapping byte range.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for ActiveFetchGuard {
    fn drop(&mut self) {
        self.active_flags.remove(&self.fetch_id);
        let mut remove_key = false;
        if let Some(mut list) = self.file_ranges.get_mut(&self.ntfs_file_id) {
            list.retain(|(id, _)| *id != self.fetch_id);
            remove_key = list.is_empty();
        }
        if remove_key {
            self.file_ranges
                .remove_if(&self.ntfs_file_id, |_, list| list.is_empty());
        }
    }
}

/// Work queued by [`WindowsCfFilter::state_changed`] for the background Tokio worker.
#[derive(Debug)]
pub enum WatchWork {
    /// Batch of changed filesystem paths reported by `ReadDirectoryChangesW` or overflow scan.
    Changed(Vec<PathBuf>),
    /// Directory watcher terminated with an OS error.
    Stopped(String),
}

/// Windows Cloud Filter callback adapter delegating all file operations to [`VfsBackend`].
pub struct WindowsCfFilter {
    backend: Arc<dyn VfsBackend>,
    mount_point: PathBuf,
    active_flags: Arc<ActiveFlagMap>,
    file_ranges: Arc<FileFetchRangeMap>,
    next_fetch_id: AtomicU64,
    watch_tx: mpsc::UnboundedSender<WatchWork>,
}

impl std::fmt::Debug for WindowsCfFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsCfFilter")
            .field("mount_point", &self.mount_point)
            .field("active_fetches", &self.active_flags.len())
            .finish_non_exhaustive()
    }
}

impl WindowsCfFilter {
    /// Creates a new [`WindowsCfFilter`] wired to `backend` and a background watcher queue.
    #[must_use]
    pub fn new(
        backend: Arc<dyn VfsBackend>,
        mount_point: PathBuf,
        watch_tx: mpsc::UnboundedSender<WatchWork>,
    ) -> Self {
        Self {
            backend,
            mount_point,
            active_flags: Arc::new(DashMap::new()),
            file_ranges: Arc::new(DashMap::new()),
            next_fetch_id: AtomicU64::new(1),
            watch_tx,
        }
    }

    /// Creates a [`WindowsCfFilter`] and spawns its background state-watcher worker on `handle`.
    #[must_use]
    pub fn with_background_watcher(
        backend: Arc<dyn VfsBackend>,
        mount_point: PathBuf,
        handle: &tokio::runtime::Handle,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (watch_tx, watch_rx) = mpsc::unbounded_channel();
        let worker_backend = Arc::clone(&backend);
        let worker_mount = mount_point.clone();
        let join = handle.spawn(async move {
            run_state_watcher_worker(worker_mount, worker_backend, watch_rx).await;
        });
        (Self::new(backend, mount_point, watch_tx), join)
    }

    /// Registers an [`ActiveFetchGuard`] for `ntfs_file_id` and `range`.
    #[must_use]
    pub fn register_fetch_guard(&self, ntfs_file_id: i64, range: Range<u64>) -> ActiveFetchGuard {
        ActiveFetchGuard::register(
            Arc::clone(&self.active_flags),
            Arc::clone(&self.file_ranges),
            &self.next_fetch_id,
            ntfs_file_id,
            range,
        )
    }

    /// Returns the number of currently active in-flight hydration guards.
    #[must_use]
    pub fn active_fetch_count(&self) -> usize {
        self.active_flags.len()
    }

    /// Cancels active hydration transfers on `ntfs_file_id` overlapping `cancel_range`.
    pub fn mark_cancelled(&self, ntfs_file_id: i64, cancel_range: Range<u64>) {
        if let Some(list) = self.file_ranges.get(&ntfs_file_id) {
            for (fetch_id, entry_range) in list.iter() {
                let overlaps = cancel_range.is_empty()
                    || (entry_range.start < cancel_range.end
                        && cancel_range.start < entry_range.end);
                if overlaps
                    && let Some(flag) = self.active_flags.get(fetch_id)
                {
                    flag.store(true, Ordering::Release);
                }
            }
        }
    }
}

/// Resolves an inode record using the placeholder's embedded [`FileIdentity`] blob when present,
/// falling back to normalized mount-relative path resolution when the blob is empty (e.g. root).
pub async fn resolve_inode_from_blob_or_path(
    backend: &dyn VfsBackend,
    mount_point: &Path,
    file_blob: &[u8],
    full_path: &Path,
) -> Result<InodeRecord, CloudErrorKind> {
    if !file_blob.is_empty() {
        let identity =
            FileIdentity::decode(file_blob).map_err(|_| CloudErrorKind::MetadataCorrupt)?;
        let rec = backend
            .getattr(identity.inode)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))?;
        if rec.file_id != identity.file_id {
            return Err(CloudErrorKind::MetadataCorrupt);
        }
        return Ok(rec);
    }

    let vpath = windows_path_to_virtual_path(mount_point, full_path)
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;
    backend
        .resolve_path(&vpath)
        .await
        .map_err(|err| zerovault_error_to_cloud_error(&err))
}

/// Validates and executes backend dehydration for `inode`, denying pinned files cleanly.
pub async fn guard_dehydrate_inode(
    backend: &dyn VfsBackend,
    inode: InodeId,
) -> Result<(), CloudErrorKind> {
    match backend.dehydrate(inode).await {
        Ok(()) => Ok(()),
        Err(ZeroVaultError::PinnedDehydrationDenied(_)) => Err(CloudErrorKind::AccessDenied),
        Err(err) => Err(zerovault_error_to_cloud_error(&err)),
    }
}

/// Validates and applies a pre-delete / undelete callback against [`VfsBackend`].
pub async fn apply_delete_inode(
    backend: &dyn VfsBackend,
    inode: InodeId,
    is_directory: bool,
    is_undelete: bool,
) -> Result<(), CloudErrorKind> {
    if is_undelete {
        return backend
            .getattr(inode)
            .await
            .map(|_| ())
            .map_err(|_| CloudErrorKind::NotSupported);
    }

    let rec = backend
        .getattr(inode)
        .await
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;

    if rec.kind == EntryKind::Directory || is_directory {
        backend
            .rmdir(rec.parent_inode, &rec.name)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))
    } else {
        backend
            .unlink(rec.parent_inode, &rec.name)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))
    }
}

/// Validates and applies a pre-rename / move callback against [`VfsBackend`].
pub async fn apply_rename_inode(
    backend: &dyn VfsBackend,
    mount_point: &Path,
    src_inode: InodeId,
    source_in_scope: bool,
    target_in_scope: bool,
    target_path: &Path,
) -> Result<(), CloudErrorKind> {
    if !source_in_scope {
        return Err(CloudErrorKind::NotSupported);
    }

    let src_rec = backend
        .getattr(src_inode)
        .await
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;

    if !target_in_scope {
        return if src_rec.kind == EntryKind::Directory {
            backend
                .rmdir(src_rec.parent_inode, &src_rec.name)
                .await
                .map_err(|err| zerovault_error_to_cloud_error(&err))
        } else {
            backend
                .unlink(src_rec.parent_inode, &src_rec.name)
                .await
                .map_err(|err| zerovault_error_to_cloud_error(&err))
        };
    }

    let target_vpath = windows_path_to_virtual_path(mount_point, target_path)
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;
    let (new_parent_vpath, new_name) = split_virtual_parent_and_name(&target_vpath)
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;
    let new_parent = backend
        .resolve_path(&new_parent_vpath)
        .await
        .map_err(|err| zerovault_error_to_cloud_error(&err))?;

    backend
        .rename(
            src_rec.parent_inode,
            &src_rec.name,
            new_parent.inode,
            &new_name,
        )
        .await
        .map(|_| ())
        .map_err(|err| zerovault_error_to_cloud_error(&err))
}

impl Filter for WindowsCfFilter {
    async fn fetch_data(
        &self,
        request: Request,
        ticket: ticket::FetchData,
        info: info::FetchData,
    ) -> CResult<()> {
        let identity = FileIdentity::decode(request.file_blob())
            .map_err(|_| CloudErrorKind::MetadataCorrupt)?;
        let rec = self
            .backend
            .getattr(identity.inode)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))?;

        if rec.file_id != identity.file_id {
            return Err(CloudErrorKind::MetadataCorrupt);
        }
        if rec.kind != EntryKind::File {
            return Err(CloudErrorKind::Unsuccessful);
        }

        let req_range = info.required_file_range();
        let guard = self.register_fetch_guard(request.file_id(), req_range.clone());

        let file_size = request.file_size();
        if rec.size != file_size {
            return Err(CloudErrorKind::NotInSync);
        }

        stream_chunked_hydration(
            &*self.backend,
            identity.inode,
            req_range,
            file_size,
            MAX_HYDRATION_STREAM_SLICE,
            || guard.is_cancelled(),
            &ticket,
        )
        .await?;

        Ok(())
    }

    async fn cancel_fetch_data(&self, request: Request, info: info::CancelFetchData) {
        self.mark_cancelled(request.file_id(), info.file_range());
    }

    async fn fetch_placeholders(
        &self,
        request: Request,
        ticket: ticket::FetchPlaceholders,
        _info: info::FetchPlaceholders,
    ) -> CResult<()> {
        let dir_rec = resolve_inode_from_blob_or_path(
            &*self.backend,
            &self.mount_point,
            request.file_blob(),
            &request.path(),
        )
        .await?;

        if dir_rec.kind != EntryKind::Directory {
            return Err(CloudErrorKind::InvalidRequest);
        }

        let children = self
            .backend
            .readdir(dir_rec.inode)
            .await
            .map_err(|err| zerovault_error_to_cloud_error(&err))?;

        let mut placeholders = Vec::with_capacity(children.len());
        for child in &children {
            let item = placeholder_create_info_from_record(child)
                .map_err(|err| zerovault_error_to_cloud_error(&err))?;
            placeholders.push(item);
        }

        for batch in placeholders.chunks_mut(PLACEHOLDER_BATCH_SIZE) {
            ticket
                .pass_with_placeholders(batch)
                .map_err(win32_error_to_cloud_error)?;
        }

        Ok(())
    }

    async fn dehydrate(
        &self,
        request: Request,
        ticket: ticket::Dehydrate,
        info: info::Dehydrate,
    ) -> CResult<()> {
        let full_path = request.path();
        let rec = resolve_inode_from_blob_or_path(
            &*self.backend,
            &self.mount_point,
            request.file_blob(),
            &full_path,
        )
        .await?;

        // When a user clicks "Free up space" in File Explorer on a previously pinned file,
        // Explorer sets FILE_ATTRIBUTE_UNPINNED and cldflt.sys fires `dehydrate` synchronously
        // before the directory watcher's `state_changed` notification runs. Honor explicit user
        // unpin attributes while still blocking background Storage Sense eviction of pinned files.
        if rec.pinned && !info.background() {
            let explicitly_unpinned = tokio::fs::symlink_metadata(&full_path)
                .await
                .is_ok_and(|meta| {
                    let attrs = meta.file_attributes();
                    (attrs & FILE_ATTRIBUTE_UNPINNED.0) != 0
                        && (attrs & FILE_ATTRIBUTE_PINNED.0) == 0
                });
            if explicitly_unpinned {
                self.backend
                    .unpin(rec.inode)
                    .await
                    .map_err(|err| zerovault_error_to_cloud_error(&err))?;
            }
        }

        guard_dehydrate_inode(&*self.backend, rec.inode).await?;
        ticket.pass().map_err(win32_error_to_cloud_error)?;
        Ok(())
    }

    async fn dehydrated(&self, request: Request, info: info::Dehydrated) {
        debug!(
            path = %request.path().display(),
            reason = ?info.reason(),
            background = info.background(),
            "CfApi placeholder dehydrated"
        );
    }

    async fn delete(
        &self,
        request: Request,
        ticket: ticket::Delete,
        info: info::Delete,
    ) -> CResult<()> {
        let rec = resolve_inode_from_blob_or_path(
            &*self.backend,
            &self.mount_point,
            request.file_blob(),
            &request.path(),
        )
        .await?;

        apply_delete_inode(
            &*self.backend,
            rec.inode,
            info.is_directory(),
            info.is_undelete(),
        )
        .await?;

        ticket.pass().map_err(win32_error_to_cloud_error)?;
        Ok(())
    }

    async fn deleted(&self, request: Request, _info: info::Deleted) {
        debug!(path = %request.path().display(), "CfApi placeholder deleted");
    }

    async fn rename(
        &self,
        request: Request,
        ticket: ticket::Rename,
        info: info::Rename,
    ) -> CResult<()> {
        let rec = resolve_inode_from_blob_or_path(
            &*self.backend,
            &self.mount_point,
            request.file_blob(),
            &request.path(),
        )
        .await?;

        apply_rename_inode(
            &*self.backend,
            &self.mount_point,
            rec.inode,
            info.source_in_scope(),
            info.target_in_scope(),
            &info.target_path(),
        )
        .await?;

        ticket.pass().map_err(win32_error_to_cloud_error)?;
        Ok(())
    }

    async fn renamed(&self, request: Request, info: info::Renamed) {
        debug!(
            from = %info.source_path().display(),
            to = %request.path().display(),
            "CfApi placeholder renamed"
        );
    }

    async fn opened(&self, request: Request, info: info::Opened) {
        if info.metadata_corrupt() || info.metadata_unsupported() {
            warn!(
                path = %request.path().display(),
                corrupt = info.metadata_corrupt(),
                unsupported = info.metadata_unsupported(),
                "CfApi opened placeholder with metadata warning"
            );
        }
    }

    async fn closed(&self, request: Request, info: info::Closed) {
        debug!(
            path = %request.path().display(),
            deleted = info.deleted(),
            "CfApi placeholder handle closed"
        );
    }

    async fn state_changed(&self, event: StateWatchEvent) {
        let work = match event {
            StateWatchEvent::Changed(paths) => WatchWork::Changed(paths),
            StateWatchEvent::Stopped(err) => WatchWork::Stopped(err.to_string()),
        };
        if let Err(err) = self.watch_tx.send(work) {
            debug!(error = %err, "state watcher channel closed");
        }
    }
}

/// Async worker loop draining [`WatchWork`] without blocking the native directory-watcher thread.
pub async fn run_state_watcher_worker(
    mount_point: PathBuf,
    backend: Arc<dyn VfsBackend>,
    mut rx: mpsc::UnboundedReceiver<WatchWork>,
) {
    while let Some(item) = rx.recv().await {
        match item {
            WatchWork::Stopped(reason) => {
                warn!(reason = %reason, "Windows Cloud Filter state watcher stopped");
            }
            WatchWork::Changed(paths) => {
                let mut seen = HashSet::with_capacity(paths.len());
                for path in paths {
                    if !seen.insert(path.clone()) {
                        continue;
                    }
                    if let Err(err) =
                        process_state_change_path(&mount_point, &path, &*backend).await
                    {
                        debug!(
                            path = %path.display(),
                            error = %err,
                            "state_changed path reconciliation returned non-fatal error"
                        );
                    }
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct LocalPlaceholderSnapshot {
    is_placeholder: bool,
    is_in_sync: bool,
    modified_data_size: i64,
    on_disk_data_size: i64,
    pin_state: Option<PinState>,
    partial_on_disk: bool,
}

fn probe_local_placeholder(path: &Path) -> LocalPlaceholderSnapshot {
    let Ok(placeholder) = Placeholder::open(path) else {
        return LocalPlaceholderSnapshot::default();
    };
    let info = match placeholder.info() {
        Ok(Some(info)) => info,
        _ => return LocalPlaceholderSnapshot::default(),
    };
    let partial_on_disk = placeholder
        .state()
        .ok()
        .flatten()
        .is_some_and(|st| st.partial_on_disk());

    LocalPlaceholderSnapshot {
        is_placeholder: true,
        is_in_sync: info.is_in_sync(),
        modified_data_size: info.modified_data_size(),
        on_disk_data_size: info.on_disk_data_size(),
        pin_state: Some(info.pin_state()),
        partial_on_disk,
    }
}

fn mark_local_placeholder_in_sync(path: &Path) {
    if let Ok(mut placeholder) = Placeholder::open(path) {
        let _ = placeholder.mark_in_sync(true, None);
    }
}

fn dehydrate_local_placeholder_best_effort(path: &Path) {
    if let Ok(mut ph) = Placeholder::options().exclusive().open(path) {
        let _ = ph.mark_pin(PinState::Unpinned, PinOptions::default());
        let _ = ph.update(UpdateOptions::default().dehydrate().mark_in_sync(), None);
    }
}

fn convert_local_to_placeholder(path: &Path, rec: &InodeRecord) {
    let Ok(mut placeholder) = Placeholder::open(path) else {
        return;
    };
    let is_already_placeholder = matches!(placeholder.info(), Ok(Some(_)));
    if is_already_placeholder {
        return;
    }
    let identity = FileIdentity::from_record(rec);
    let mut opts = ConvertOptions::default()
        .blob(identity.to_vec())
        .mark_in_sync();
    if rec.kind == EntryKind::Directory {
        opts = opts.has_children();
    }
    if let Err(err) = placeholder.convert_to_placeholder(opts, None)
        && err.code() != ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT.to_hresult()
    {
        debug!(path = %path.display(), error = %err, "convert_to_placeholder skipped");
    }
}

async fn ensure_parent_inodes(
    backend: &dyn VfsBackend,
    parent_vpath: &str,
) -> ZeroVaultResult<InodeRecord> {
    if parent_vpath == "/" {
        return backend.getattr(ROOT_INODE).await;
    }
    if let Ok(existing) = backend.resolve_path(parent_vpath).await {
        return Ok(existing);
    }

    let mut current = backend.getattr(ROOT_INODE).await?;
    for segment in parent_vpath.trim_start_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        current = match backend.lookup(current.inode, segment).await {
            Ok(child) => child,
            Err(_) => backend.mkdir(current.inode, segment, 0o755).await?,
        };
    }
    Ok(current)
}

/// Streams a modified local NTFS file into `backend` in bounded `4 MiB` chunks without buffering
/// the entire file in RAM, truncating via `setattr` if `offset < existing_size`, and flushing.
pub async fn sync_local_file_contents_streaming(
    path: &Path,
    backend: &dyn VfsBackend,
    inode: InodeId,
    existing_size: u64,
) -> ZeroVaultResult<u64> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; MAX_HYDRATION_STREAM_SLICE];
    let mut offset = 0u64;

    loop {
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        backend.write_range(inode, offset, &buf[..filled]).await?;
        offset += filled as u64;
    }

    if offset < existing_size {
        backend
            .setattr(
                inode,
                SetAttrSpec {
                    size: Some(offset),
                    ..Default::default()
                },
            )
            .await?;
    }

    backend.flush(inode).await?;
    Ok(offset)
}

/// Inspects a changed path under `mount_point` and reconciles content modifications as well as
/// `FILE_ATTRIBUTE_PINNED` / `FILE_ATTRIBUTE_UNPINNED` attribute transitions with `backend`.
///
/// Implements the `NEW-H02` (`VFS-1`) remediation: whenever `wants_unpin` (`FILE_ATTRIBUTE_UNPINNED`
/// or `PinState::Unpinned`) is detected, `backend.unpin(rec.inode)` is invoked **before**
/// `backend.dehydrate(rec.inode)` so previously pinned files cleanly unpin and dehydrate to
/// [`HydrationState::OnlineOnly`] instead of failing with [`ZeroVaultError::PinnedDehydrationDenied`].
pub async fn process_state_change_path(
    mount_point: &Path,
    path: &Path,
    backend: &dyn VfsBackend,
) -> ZeroVaultResult<()> {
    let vpath = windows_path_to_virtual_path(mount_point, path)?;
    if vpath == "/" {
        return Ok(());
    }

    let meta = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ZeroVaultError::Io(err)),
    };

    let attrs = meta.file_attributes();
    let is_pinned_attr = (attrs & FILE_ATTRIBUTE_PINNED.0) != 0;
    let is_unpinned_attr = (attrs & FILE_ATTRIBUTE_UNPINNED.0) != 0;
    let is_recall_on_data_access = (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0) != 0;
    let is_offline = (attrs & FILE_ATTRIBUTE_OFFLINE.0) != 0;

    let path_owned = path.to_path_buf();
    let snapshot = tokio::task::spawn_blocking(move || probe_local_placeholder(&path_owned))
        .await
        .map_err(|err| ZeroVaultError::VfsError(format!("placeholder probe join failed: {err}")))?;

    match backend.resolve_path(&vpath).await {
        Ok(rec) => {
            if meta.is_dir() || rec.kind == EntryKind::Directory {
                let wants_pin = is_pinned_attr || snapshot.pin_state == Some(PinState::Pinned);
                let wants_unpin =
                    is_unpinned_attr || snapshot.pin_state == Some(PinState::Unpinned);
                if wants_pin && !rec.pinned {
                    backend.pin(rec.inode).await?;
                } else if wants_unpin && !wants_pin {
                    backend.unpin(rec.inode).await?;
                    match backend.dehydrate(rec.inode).await {
                        Ok(()) | Err(ZeroVaultError::PinnedDehydrationDenied(_)) => {}
                        Err(err) => return Err(err),
                    }
                }
                return Ok(());
            }

            let content_modified = if snapshot.is_placeholder {
                snapshot.modified_data_size > 0
                    || (!snapshot.is_in_sync
                        && !snapshot.partial_on_disk
                        && !is_recall_on_data_access
                        && (snapshot.on_disk_data_size > 0 || meta.len() == 0))
            } else {
                let pin_stub_zero_len =
                    meta.len() == 0 && rec.size > 0 && (is_pinned_attr || is_unpinned_attr);
                !is_recall_on_data_access && !is_offline && !pin_stub_zero_len
            };

            if content_modified {
                let _ =
                    sync_local_file_contents_streaming(path, backend, rec.inode, rec.size).await?;
                if snapshot.is_placeholder {
                    let sync_path = path.to_path_buf();
                    let _ = tokio::task::spawn_blocking(move || {
                        mark_local_placeholder_in_sync(&sync_path);
                    })
                    .await;
                }
            }

            let wants_pin = is_pinned_attr || snapshot.pin_state == Some(PinState::Pinned);
            let wants_unpin = is_unpinned_attr || snapshot.pin_state == Some(PinState::Unpinned);

            if wants_pin && (!rec.pinned || rec.hydration != HydrationState::Pinned) {
                backend.pin(rec.inode).await?;
            } else if wants_unpin && !wants_pin {
                // NEW-H02 (VFS-1): MUST clear backend pin flag BEFORE dehydrating so files
                // previously marked "Always keep on this device" do not fail with
                // PinnedDehydrationDenied.
                backend.unpin(rec.inode).await?;
                backend.dehydrate(rec.inode).await?;
                if snapshot.is_placeholder && snapshot.on_disk_data_size > 0 {
                    let dehydrate_path = path.to_path_buf();
                    let _ = tokio::task::spawn_blocking(move || {
                        dehydrate_local_placeholder_best_effort(&dehydrate_path);
                    })
                    .await;
                }
            }
            Ok(())
        }
        Err(ZeroVaultError::InvalidPath(_)) | Err(ZeroVaultError::InodeNotFound(_)) => {
            let (parent_vpath, name) = split_virtual_parent_and_name(&vpath)?;
            let parent_rec = ensure_parent_inodes(backend, &parent_vpath).await?;

            if meta.is_dir() {
                let new_rec = backend.mkdir(parent_rec.inode, &name, 0o755).await?;
                let p = path.to_path_buf();
                let _ =
                    tokio::task::spawn_blocking(move || convert_local_to_placeholder(&p, &new_rec))
                        .await;
                return Ok(());
            }

            if meta.is_file() {
                let new_rec = backend
                    .create_entry(CreateEntrySpec {
                        parent_inode: parent_rec.inode,
                        name,
                        mode: 0o644,
                    })
                    .await?;
                let _ = sync_local_file_contents_streaming(path, backend, new_rec.inode, 0).await?;
                if is_pinned_attr {
                    backend.pin(new_rec.inode).await?;
                }
                let p = path.to_path_buf();
                let _ =
                    tokio::task::spawn_blocking(move || convert_local_to_placeholder(&p, &new_rec))
                        .await;
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}
