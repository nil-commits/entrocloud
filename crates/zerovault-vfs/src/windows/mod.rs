//! Windows Cloud Files API (`cloud-filter` / `CfApi`) virtual filesystem adapter.
//!
//! Exposes [`WindowsCfDrive`] implementing [`zerovault_types::VirtualDrive`], [`WindowsCfFilter`]
//! implementing [`cloud_filter::filter::Filter`], and placeholder / 4 KiB-aligned streaming
//! hydration helpers under [`placeholder`].

pub mod drive;
pub mod filter;
pub mod placeholder;

pub use drive::{WindowsCfConfig, WindowsCfDrive};
pub use filter::{
    WatchWork, WindowsCfFilter, apply_delete_inode, apply_rename_inode, guard_dehydrate_inode,
    process_state_change_path, resolve_inode_from_blob_or_path, run_state_watcher_worker,
};
pub use placeholder::{
    CFAPI_BLOCK_ALIGN, FILE_IDENTITY_LEN, FILE_IDENTITY_MAGIC, FileIdentity,
    MAX_HYDRATION_STREAM_SLICE, PlaceholderSpec, TransferSink, align_cfapi_transfer_range,
    clamp_stream_slice_size, datetime_to_file_time, metadata_from_record,
    placeholder_create_info_from_record, split_virtual_parent_and_name, stream_chunked_hydration,
    strip_verbatim_prefix, validate_windows_entry_name, virtual_path_to_windows_path,
    win32_error_to_cloud_error, win32_error_to_vfs, windows_path_to_virtual_path,
    zerovault_error_to_cloud_error,
};
