//! Strictly byte-bounded LRU decrypted chunk cache and disk-backed dirty chunk staging.

use std::fmt;
use std::io::SeekFrom;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;
use zerovault_types::{InodeId, PLAINTEXT_CHUNK_SIZE, ZeroVaultError, ZeroVaultResult};

/// Default in-memory decrypted chunk LRU cache budget: 32 MiB (`8 * 4 MiB`).
pub const DEFAULT_MAX_RAM_CACHE_BYTES: usize = 32 * 1024 * 1024;

struct RamCacheInner {
    lru: LruCache<(Uuid, u64), Bytes>,
    used_bytes: usize,
    max_ram_bytes: usize,
}

/// Byte-bounded in-memory LRU cache of verified plaintext chunks paired with a
/// per-4-MiB-chunk dirty staging directory (`staging_dir/dirty/<inode>/<chunk_index>.part`).
pub struct ChunkCache {
    staging_dir: PathBuf,
    ram: Mutex<RamCacheInner>,
}

impl fmt::Debug for ChunkCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.ram.lock();
        f.debug_struct("ChunkCache")
            .field("staging_dir", &self.staging_dir)
            .field("max_ram_bytes", &guard.max_ram_bytes)
            .field("used_ram_bytes", &guard.used_bytes)
            .field("entry_count", &guard.lru.len())
            .finish()
    }
}

impl ChunkCache {
    /// Creates a new [`ChunkCache`] backed by `staging_dir/dirty` and capped at `max_ram_bytes`.
    pub fn new(staging_dir: impl Into<PathBuf>, max_ram_bytes: usize) -> ZeroVaultResult<Self> {
        let staging_dir = staging_dir.into();
        let dirty_root = staging_dir.join("dirty");
        std::fs::create_dir_all(&dirty_root)?;

        // Use `LruCache::unbounded()` so eviction is strictly governed by byte count,
        // unless `NonZeroUsize` is needed only as an internal sanity cap (unused here).
        let _ = NonZeroUsize::MIN;
        Ok(Self {
            staging_dir,
            ram: Mutex::new(RamCacheInner {
                lru: LruCache::unbounded(),
                used_bytes: 0,
                max_ram_bytes,
            }),
        })
    }

    /// Root staging directory path.
    #[must_use]
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Dirty chunk staging directory for a single inode (`staging_dir/dirty/<inode>`).
    #[must_use]
    pub fn dirty_inode_dir(&self, inode: InodeId) -> PathBuf {
        self.staging_dir.join("dirty").join(inode.to_string())
    }

    /// Path to a single 4 MiB dirty chunk `.part` file.
    #[must_use]
    pub fn dirty_chunk_path(&self, inode: InodeId, chunk_index: u64) -> PathBuf {
        self.dirty_inode_dir(inode)
            .join(format!("{chunk_index}.part"))
    }

    /// Looks up a verified plaintext chunk in the in-memory LRU cache, promoting it on hit.
    #[must_use]
    pub fn get(&self, file_id: Uuid, chunk_index: u64) -> Option<Bytes> {
        let mut guard = self.ram.lock();
        guard.lru.get(&(file_id, chunk_index)).cloned()
    }

    /// Inserts a verified plaintext chunk into the LRU cache, evicting oldest entries until
    /// `used_bytes + data.len() <= max_ram_bytes`.
    ///
    /// Returns `false` (skipping caching) if `data.len() > max_ram_bytes`.
    pub fn insert(&self, file_id: Uuid, chunk_index: u64, data: Bytes) -> bool {
        let mut guard = self.ram.lock();
        let entry_len = data.len();
        if entry_len > guard.max_ram_bytes {
            return false;
        }

        if let Some(prev) = guard.lru.pop(&(file_id, chunk_index)) {
            guard.used_bytes = guard.used_bytes.saturating_sub(prev.len());
        }

        while guard.used_bytes.saturating_add(entry_len) > guard.max_ram_bytes {
            if let Some((_k, evicted)) = guard.lru.pop_lru() {
                guard.used_bytes = guard.used_bytes.saturating_sub(evicted.len());
            } else {
                break;
            }
        }

        guard.used_bytes = guard.used_bytes.saturating_add(entry_len);
        guard.lru.put((file_id, chunk_index), data);
        true
    }

    /// Removes a specific chunk from the RAM cache.
    pub fn invalidate_chunk(&self, file_id: Uuid, chunk_index: u64) {
        let mut guard = self.ram.lock();
        if let Some(removed) = guard.lru.pop(&(file_id, chunk_index)) {
            guard.used_bytes = guard.used_bytes.saturating_sub(removed.len());
        }
    }

    /// Evicts all RAM-cached chunks belonging to `file_id`.
    pub fn invalidate_file(&self, file_id: Uuid) {
        let mut guard = self.ram.lock();
        let keys: Vec<(Uuid, u64)> = guard
            .lru
            .iter()
            .filter_map(|(k, _)| if k.0 == file_id { Some(*k) } else { None })
            .collect();
        for key in keys {
            if let Some(removed) = guard.lru.pop(&key) {
                guard.used_bytes = guard.used_bytes.saturating_sub(removed.len());
            }
        }
    }

    /// Clears all entries from the RAM LRU cache.
    pub fn clear_ram(&self) {
        let mut guard = self.ram.lock();
        guard.lru.clear();
        guard.used_bytes = 0;
    }

    /// Current total bytes stored in the RAM LRU cache.
    #[must_use]
    pub fn used_ram_bytes(&self) -> usize {
        self.ram.lock().used_bytes
    }

    /// Configured maximum byte budget of the RAM LRU cache.
    #[must_use]
    pub fn max_ram_bytes(&self) -> usize {
        self.ram.lock().max_ram_bytes
    }

    /// Number of chunk entries currently cached in RAM.
    #[must_use]
    pub fn ram_entry_count(&self) -> usize {
        self.ram.lock().lru.len()
    }

    /// Returns `true` if a dirty staging `.part` file exists for `(inode, chunk_index)`.
    pub async fn has_dirty_chunk(&self, inode: InodeId, chunk_index: u64) -> bool {
        fs::try_exists(self.dirty_chunk_path(inode, chunk_index))
            .await
            .unwrap_or(false)
    }

    /// Lists sorted dirty chunk indices currently staged on disk for `inode`.
    pub async fn list_dirty_chunk_indices(&self, inode: InodeId) -> ZeroVaultResult<Vec<u64>> {
        let dir = self.dirty_inode_dir(inode);
        let mut rd = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };

        let mut indices = Vec::new();
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Some(stem) = name_str.strip_suffix(".part")
                && let Ok(idx) = stem.parse::<u64>()
            {
                indices.push(idx);
            }
        }
        indices.sort_unstable();
        Ok(indices)
    }

    /// Returns `true` if `inode` has at least one `.part` dirty staging file.
    pub async fn has_any_dirty_chunks(&self, inode: InodeId) -> ZeroVaultResult<bool> {
        Ok(!self.list_dirty_chunk_indices(inode).await?.is_empty())
    }

    /// Streams `data` directly into `staging_dir/dirty/<inode>/<chunk_index>.part` at `in_chunk_offset`.
    pub async fn write_dirty_chunk_slice(
        &self,
        inode: InodeId,
        chunk_index: u64,
        in_chunk_offset: usize,
        data: &[u8],
    ) -> ZeroVaultResult<()> {
        let end = in_chunk_offset
            .checked_add(data.len())
            .ok_or(ZeroVaultError::InvalidRange {
                offset: in_chunk_offset as u64,
                len: data.len(),
                size: PLAINTEXT_CHUNK_SIZE as u64,
            })?;
        if end > PLAINTEXT_CHUNK_SIZE {
            return Err(ZeroVaultError::InvalidRange {
                offset: in_chunk_offset as u64,
                len: data.len(),
                size: PLAINTEXT_CHUNK_SIZE as u64,
            });
        }

        let dir = self.dirty_inode_dir(inode);
        fs::create_dir_all(&dir).await?;
        let part_path = self.dirty_chunk_path(inode, chunk_index);

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&part_path)
            .await?;
        file.seek(SeekFrom::Start(in_chunk_offset as u64)).await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    /// Overwrites `staging_dir/dirty/<inode>/<chunk_index>.part` with an entire chunk buffer.
    pub async fn write_full_dirty_chunk(
        &self,
        inode: InodeId,
        chunk_index: u64,
        data: &[u8],
    ) -> ZeroVaultResult<()> {
        if data.len() > PLAINTEXT_CHUNK_SIZE {
            return Err(ZeroVaultError::InvalidRange {
                offset: 0,
                len: data.len(),
                size: PLAINTEXT_CHUNK_SIZE as u64,
            });
        }
        let dir = self.dirty_inode_dir(inode);
        fs::create_dir_all(&dir).await?;
        let part_path = self.dirty_chunk_path(inode, chunk_index);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&part_path)
            .await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    /// Reads `staging_dir/dirty/<inode>/<chunk_index>.part` into a caller-provided [`BytesMut`] buffer.
    ///
    /// Returns `Ok(None)` if the chunk is not present in dirty staging.
    pub async fn read_dirty_chunk_into(
        &self,
        inode: InodeId,
        chunk_index: u64,
        out: &mut BytesMut,
    ) -> ZeroVaultResult<Option<usize>> {
        let part_path = self.dirty_chunk_path(inode, chunk_index);
        let mut file = match OpenOptions::new().read(true).open(&part_path).await {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        let meta_len = file.metadata().await?.len();
        if meta_len > PLAINTEXT_CHUNK_SIZE as u64 {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "dirty staging chunk {chunk_index} exceeds 4 MiB ({meta_len} bytes)"
            )));
        }
        let len = meta_len as usize;
        out.clear();
        out.resize(len, 0);
        if len > 0 {
            file.read_exact(out.as_mut()).await?;
        }
        Ok(Some(len))
    }

    /// Truncates or prunes dirty staging `.part` files beyond `new_size`.
    pub async fn truncate_dirty_chunks(
        &self,
        inode: InodeId,
        new_size: u64,
    ) -> ZeroVaultResult<()> {
        if new_size == 0 {
            return self.clear_dirty_inode(inode).await;
        }
        let last_chunk = (new_size - 1) / (PLAINTEXT_CHUNK_SIZE as u64);
        let last_len = ((new_size - 1) % (PLAINTEXT_CHUNK_SIZE as u64)) + 1;

        for idx in self.list_dirty_chunk_indices(inode).await? {
            let path = self.dirty_chunk_path(inode, idx);
            if idx > last_chunk {
                let _ = fs::remove_file(&path).await;
            } else if idx == last_chunk {
                let file = OpenOptions::new().write(true).open(&path).await?;
                let cur_len = file.metadata().await?.len();
                if cur_len > last_len {
                    file.set_len(last_len).await?;
                }
            }
        }
        Ok(())
    }

    /// Removes all dirty `.part` staging files for `inode`.
    pub async fn clear_dirty_inode(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let dir = self.dirty_inode_dir(inode);
        match fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn byte_bounded_lru_evicts_oldest_and_skips_oversized() {
        let dir = TempDir::new().expect("tempdir");
        let max_bytes = 5 * 1024;
        let cache = ChunkCache::new(dir.path(), max_bytes).expect("cache");
        let file_a = Uuid::new_v4();

        // Single chunk larger than max_ram_bytes is skipped cleanly.
        assert!(!cache.insert(file_a, 99, Bytes::from(vec![0xAA; max_bytes + 1])));
        assert_eq!(cache.used_ram_bytes(), 0);
        assert_eq!(cache.ram_entry_count(), 0);

        // Insert 3 chunks of 2 KiB each (6 KiB > 5 KiB budget) -> chunk 0 evicted!
        assert!(cache.insert(file_a, 0, Bytes::from(vec![1u8; 2048])));
        assert!(cache.insert(file_a, 1, Bytes::from(vec![2u8; 2048])));
        assert_eq!(cache.used_ram_bytes(), 4096);

        // Promote chunk 0 by reading it, so chunk 1 becomes oldest.
        assert!(cache.get(file_a, 0).is_some());

        assert!(cache.insert(file_a, 2, Bytes::from(vec![3u8; 2048])));
        assert!(cache.used_ram_bytes() <= max_bytes);
        assert_eq!(cache.used_ram_bytes(), 4096);
        assert!(cache.get(file_a, 1).is_none());
        assert!(cache.get(file_a, 0).is_some());
        assert!(cache.get(file_a, 2).is_some());

        cache.invalidate_file(file_a);
        assert_eq!(cache.used_ram_bytes(), 0);
        assert_eq!(cache.ram_entry_count(), 0);
    }

    #[tokio::test]
    async fn dirty_staging_streams_partial_slices_and_truncates() {
        let dir = TempDir::new().expect("tempdir");
        let cache = ChunkCache::new(dir.path(), DEFAULT_MAX_RAM_CACHE_BYTES).expect("cache");

        cache
            .write_dirty_chunk_slice(42, 0, 10, b"hello")
            .await
            .expect("write slice");
        let mut buf = BytesMut::new();
        let len = cache
            .read_dirty_chunk_into(42, 0, &mut buf)
            .await
            .expect("read")
            .expect("exists");
        assert_eq!(len, 15);
        assert_eq!(&buf[..10], &[0u8; 10]);
        assert_eq!(&buf[10..15], b"hello");

        cache
            .write_dirty_chunk_slice(42, 1, 0, b"second-chunk")
            .await
            .expect("write chunk 1");
        assert_eq!(
            cache.list_dirty_chunk_indices(42).await.expect("list"),
            vec![0, 1]
        );

        cache.truncate_dirty_chunks(42, 12).await.expect("truncate");
        assert_eq!(
            cache.list_dirty_chunk_indices(42).await.expect("list"),
            vec![0]
        );
        let truncated_len = cache
            .read_dirty_chunk_into(42, 0, &mut buf)
            .await
            .expect("read")
            .expect("exists");
        assert_eq!(truncated_len, 12);
        assert_eq!(&buf[10..12], b"he");

        cache.clear_dirty_inode(42).await.expect("clear");
        assert!(!cache.has_dirty_chunk(42, 0).await);
    }
}
