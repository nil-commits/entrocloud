//! ZeroVault v0.2 sync engine, zero-knowledge SQLite WAL store, AEAD `.zvpart` chunk cache,
//! full-capacity zeroizing buffer pool (`mimalloc` idle reclamation), and serverless sharing helpers.

#![deny(
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod cache;
pub mod conflict;
pub mod db;
pub mod engine;
pub mod pool;

pub use cache::{ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES};
pub use conflict::{
    ConflictResolver, ReconcileSummary, format_conflict_filename, sanitize_device_id,
};
pub use db::SqliteMetadataStore;
pub use engine::{
    EPOCH_SCOPE_KEYBOX, EPOCH_SCOPE_MANIFEST, SyncEngine, SyncEngineConfig, SyncReport,
    compute_manifest_id,
};
pub use pool::{
    BoundedBufferPool, DEFAULT_BUFFER_SLOTS, PooledBuffer, PooledBufferPair,
    reclaim_process_memory,
};
pub use entrocloud_types;
