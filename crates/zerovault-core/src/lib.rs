//! Zerovault sync engine, SQLite WAL state store, bounded chunk cache, and conflict resolver.

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
pub use engine::{SyncEngine, SyncEngineConfig, SyncReport};
pub use pool::{BoundedBufferPool, DEFAULT_BUFFER_SLOTS, PooledBuffer, PooledBufferPair};
pub use zerovault_types;
