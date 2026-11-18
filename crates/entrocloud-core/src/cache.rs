//! Strictly byte-bounded LRU decrypted chunk cache and AEAD-encrypted `.zvpart` local disk staging (`NEW-H01`).

use std::fmt;
use std::io::SeekFrom;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};
use entrocloud_types::{
    CryptoEngine, InodeId, MAX_ENCRYPTED_CHUNK_SIZE, PLAINTEXT_CHUNK_SIZE, ZeroVaultError,
    ZeroVaultResult,
};

/// Default in-memory decrypted chunk LRU cache budget: 32 MiB (`8 * 4 MiB`).
pub const DEFAULT_MAX_RAM_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Maximum permitted on-disk `.zvpart` envelope size (`4 MiB + 1 KiB` pre-allocation DoS guard).
const MAX_STAGING_FILE_BYTES: u64 = (MAX_ENCRYPTED_CHUNK_SIZE + 1024) as u64;

/// Zero-fill block size used when securely wiping staged or `.partial` temporary files.
const WIPE_BLOCK_BYTES: usize = 64 * 1024;

struct RamCacheInner {
    lru: LruCache<(Uuid, u64), Arc<Zeroizing<Vec<u8>>>>,
    used_bytes: usize,
    max_ram_bytes: usize,
}

/// Byte-bounded in-memory LRU cache of verified plaintext chunks paired with an
/// AEAD-encrypted per-4-MiB-chunk dirty staging directory (`staging_dir/dirty/<inode>/<chunk_index>.zvpart`).
pub struct ChunkCache {
    staging_dir: PathBuf,
    crypto: Arc<dyn CryptoEngine>,
    ram: Mutex<RamCacheInner>,
    inode_locks: DashMap<InodeId, Arc<AsyncMutex<()>>>,
}

impl Drop for ChunkCache {
    fn drop(&mut self) {
        self.clear_ram();
    }
}

impl fmt::Debug for ChunkCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.ram.lock();
        f.debug_struct("ChunkCache")
            .field("staging_dir", &self.staging_dir)
            .field("max_ram_bytes", &guard.max_ram_bytes)
            .field("used_ram_bytes", &guard.used_bytes)
            .field("entry_count", &guard.lru.len())
            .finish_non_exhaustive()
    }
}

impl ChunkCache {
    /// Creates a new [`ChunkCache`] capped at `max_ram_bytes` and backed by encrypted `.zvpart` files
    /// under `staging_dir/dirty`.
    pub fn new(
        max_ram_bytes: usize,
        staging_dir: impl Into<PathBuf>,
        crypto: Arc<dyn CryptoEngine>,
    ) -> ZeroVaultResult<Self> {
        let staging_dir = staging_dir.into();
        let dirty_root = staging_dir.join("dirty");
        std::fs::create_dir_all(&dirty_root)?;
        restrict_dir_perms(&staging_dir);
        restrict_dir_perms(&dirty_root);
        cleanup_orphaned_temp_files_sync(&staging_dir);

        let _ = NonZeroUsize::MIN;
        Ok(Self {
            staging_dir,
            crypto,
            ram: Mutex::new(RamCacheInner {
                lru: LruCache::unbounded(),
                used_bytes: 0,
                max_ram_bytes,
            }),
            inode_locks: DashMap::new(),
        })
    }

    fn inode_staging_lock(&self, inode: InodeId) -> Arc<AsyncMutex<()>> {
        self.inode_locks
            .entry(inode)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
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

    /// Path to a single 4 MiB AEAD-encrypted dirty chunk `.zvpart` file.
    #[must_use]
    pub fn dirty_chunk_path(&self, inode: InodeId, chunk_index: u64) -> PathBuf {
        self.dirty_inode_dir(inode)
            .join(format!("{chunk_index}.zvpart"))
    }

    /// Looks up a verified plaintext chunk in the in-memory LRU cache, promoting it on hit.
    #[must_use]
    pub fn get(&self, file_id: Uuid, chunk_index: u64) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let mut guard = self.ram.lock();
        guard.lru.get(&(file_id, chunk_index)).cloned()
    }

    /// Inserts a verified plaintext chunk into the LRU cache (wrapped in `Zeroizing`),
    /// evicting oldest entries until `used_bytes + data.len() <= max_ram_bytes`.
    ///
    /// Returns `false` (skipping caching) if `data.len() > max_ram_bytes`.
    pub fn insert(&self, file_id: Uuid, chunk_index: u64, data: Bytes) -> bool {
        let wrapped = Arc::new(Zeroizing::new(data.to_vec()));
        self.insert_zeroizing(file_id, chunk_index, wrapped)
    }

    /// Inserts an already-zeroizing chunk slice into the bounded LRU cache.
    pub fn insert_zeroizing(
        &self,
        file_id: Uuid,
        chunk_index: u64,
        data: Arc<Zeroizing<Vec<u8>>>,
    ) -> bool {
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

    /// Returns `true` if an encrypted dirty staging `.zvpart` file exists for `(inode, chunk_index)`.
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
            if let Some(stem) = name_str.strip_suffix(".zvpart")
                && let Ok(idx) = stem.parse::<u64>()
            {
                indices.push(idx);
            }
        }
        indices.sort_unstable();
        Ok(indices)
    }

    /// Returns `true` if `inode` has at least one `.zvpart` dirty staging file.
    pub async fn has_any_dirty_chunks(&self, inode: InodeId) -> ZeroVaultResult<bool> {
        Ok(!self.list_dirty_chunk_indices(inode).await?.is_empty())
    }

    /// Updates `data` at `in_chunk_offset` inside `staging_dir/dirty/<inode>/<chunk_index>.zvpart`,
    /// decrypting/verifying any existing `.zvpart` first and re-sealing with `StagingKey` before disk write.
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

        let lock = self.inode_staging_lock(inode);
        let _guard = lock.lock().await;

        let part_path = self.dirty_chunk_path(inode, chunk_index);
        let mut pt: Zeroizing<Vec<u8>> = match read_raw_staging_file(&part_path).await? {
            Some(sealed) => {
                let opened = self.crypto.open_staging_chunk(inode, chunk_index, &sealed)?;
                if opened.len() > PLAINTEXT_CHUNK_SIZE {
                    return Err(ZeroVaultError::InvalidWireFormat(format!(
                        "decrypted staging chunk {chunk_index} exceeds 4 MiB ({} bytes)",
                        opened.len()
                    )));
                }
                opened
            }
            None => Zeroizing::new(Vec::with_capacity(end)),
        };

        if pt.len() < end {
            pt.resize(end, 0u8);
        }
        pt[in_chunk_offset..end].copy_from_slice(data);

        let sealed = self.crypto.seal_staging_chunk(inode, chunk_index, &pt)?;
        let dir = self.dirty_inode_dir(inode);
        write_sealed_staging_file(&dir, &part_path, &sealed).await
    }

    /// Encrypts `data` via `seal_staging_chunk` and writes `staging_dir/dirty/<inode>/<chunk_index>.zvpart`.
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

        let lock = self.inode_staging_lock(inode);
        let _guard = lock.lock().await;

        let sealed = self.crypto.seal_staging_chunk(inode, chunk_index, data)?;
        let dir = self.dirty_inode_dir(inode);
        let part_path = self.dirty_chunk_path(inode, chunk_index);
        write_sealed_staging_file(&dir, &part_path, &sealed).await
    }

    /// Reads and AEAD-verifies `staging_dir/dirty/<inode>/<chunk_index>.zvpart` into `out`.
    ///
    /// Returns `Ok(None)` if the chunk is not present in dirty staging.
    pub async fn read_dirty_chunk_into(
        &self,
        inode: InodeId,
        chunk_index: u64,
        out: &mut BytesMut,
    ) -> ZeroVaultResult<Option<usize>> {
        let lock = self.inode_staging_lock(inode);
        let _guard = lock.lock().await;

        let part_path = self.dirty_chunk_path(inode, chunk_index);
        let Some(sealed) = read_raw_staging_file(&part_path).await? else {
            return Ok(None);
        };

        let pt = self.crypto.open_staging_chunk(inode, chunk_index, &sealed)?;
        if pt.len() > PLAINTEXT_CHUNK_SIZE {
            return Err(ZeroVaultError::InvalidWireFormat(format!(
                "dirty staging chunk {chunk_index} exceeds 4 MiB ({} bytes)",
                pt.len()
            )));
        }

        let len = pt.len();
        out.clear();
        out.extend_from_slice(&pt);
        Ok(Some(len))
    }

    /// Truncates or prunes encrypted dirty staging `.zvpart` files beyond `new_size`.
    pub async fn truncate_dirty_chunks(
        &self,
        inode: InodeId,
        new_size: u64,
    ) -> ZeroVaultResult<()> {
        if new_size == 0 {
            return self.clear_dirty_inode(inode).await;
        }
        let last_chunk = (new_size - 1) / (PLAINTEXT_CHUNK_SIZE as u64);
        let last_len = (((new_size - 1) % (PLAINTEXT_CHUNK_SIZE as u64)) + 1) as usize;

        let indices = self.list_dirty_chunk_indices(inode).await?;
        let lock = self.inode_staging_lock(inode);
        let _guard = lock.lock().await;

        let dir = self.dirty_inode_dir(inode);
        for idx in indices {
            let path = self.dirty_chunk_path(inode, idx);
            if idx > last_chunk {
                let _ = secure_wipe_and_remove_file(&path).await;
            } else if idx == last_chunk
                && let Some(sealed) = read_raw_staging_file(&path).await?
            {
                let mut pt = self.crypto.open_staging_chunk(inode, idx, &sealed)?;
                if pt.len() > last_len {
                    pt[last_len..].zeroize();
                    pt.truncate(last_len);
                    let resealed = self.crypto.seal_staging_chunk(inode, idx, &pt)?;
                    write_sealed_staging_file(&dir, &path, &resealed).await?;
                }
            }
        }
        Ok(())
    }

    /// Overwrites with zeros and removes all dirty `.zvpart` staging files for `inode`.
    pub async fn clear_dirty_inode(&self, inode: InodeId) -> ZeroVaultResult<()> {
        let lock = self.inode_staging_lock(inode);
        let _guard = lock.lock().await;
        let dir = self.dirty_inode_dir(inode);
        secure_wipe_and_remove_dir(&dir).await
    }

    /// Purges the RAM LRU cache, overwrites all staged/temporary files in `staging_dir` with zeros,
    /// and removes `staging_dir/dirty` so `0` bytes of staged data remain after lock or crash cleanup.
    pub async fn purge_all(&self) -> ZeroVaultResult<()> {
        self.clear_ram();
        let dirty_root = self.staging_dir.join("dirty");
        secure_wipe_and_remove_dir(&dirty_root).await?;

        // Also zero-wipe and delete any stray temporary files directly under `staging_dir`.
        if let Ok(mut rd) = fs::read_dir(&self.staging_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if let Ok(ft) = entry.file_type().await
                    && ft.is_file()
                {
                    let _ = secure_wipe_and_remove_file(&path).await;
                }
            }
        }
        self.inode_locks.clear();
        Ok(())
    }
}

async fn read_raw_staging_file(path: &Path) -> ZeroVaultResult<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new().read(true).open(path).await {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let meta_len = file.metadata().await?.len();
    if meta_len > MAX_STAGING_FILE_BYTES {
        return Err(ZeroVaultError::InvalidWireFormat(format!(
            "staging file exceeds safety ceiling ({meta_len} bytes)"
        )));
    }
    let len = usize::try_from(meta_len)
        .map_err(|_| ZeroVaultError::InvalidWireFormat("staging file size overflow".into()))?;
    let mut buf = vec![0u8; len];
    if len > 0 {
        file.read_exact(&mut buf).await?;
    }
    Ok(Some(buf))
}

async fn write_sealed_staging_file(
    dir: &Path,
    part_path: &Path,
    sealed: &[u8],
) -> ZeroVaultResult<()> {
    fs::create_dir_all(dir).await?;
    restrict_dir_perms(dir);

    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(part_path).await?;
    file.write_all(sealed).await?;
    file.flush().await?;
    Ok(())
}

/// Overwrites `path` with `0u8` across its full byte length, flushes to disk, and removes the file.
pub(crate) async fn secure_wipe_and_remove_file(path: &Path) -> ZeroVaultResult<()> {
    match OpenOptions::new().write(true).truncate(false).open(path).await {
        Ok(mut file) => {
            if let Ok(meta) = file.metadata().await {
                let total_len = meta.len();
                if total_len > 0 {
                    let _ = file.seek(SeekFrom::Start(0)).await;
                    let zeros = [0u8; WIPE_BLOCK_BYTES];
                    let mut remaining = total_len;
                    while remaining > 0 {
                        let step = (remaining.min(WIPE_BLOCK_BYTES as u64)) as usize;
                        if file.write_all(&zeros[..step]).await.is_err() {
                            break;
                        }
                        remaining -= step as u64;
                    }
                    let _ = file.sync_all().await;
                }
            }
            drop(file);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {}
    }

    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn secure_wipe_and_remove_dir(root: &Path) -> ZeroVaultResult<()> {
    if !fs::try_exists(root).await.unwrap_or(false) {
        return Ok(());
    }

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut files: Vec<PathBuf> = Vec::new();

    while let Some(dir) = stack.pop() {
        let mut rd = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            let p = entry.path();
            let ft = entry.file_type().await?;
            if ft.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }

    for file_path in files {
        let _ = secure_wipe_and_remove_file(&file_path).await;
    }

    match fs::remove_dir_all(root).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn cleanup_orphaned_temp_files_sync(staging_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(staging_dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if matches!(ext, "tmp" | "partial") && path.is_file() {
            if let Ok(meta) = std::fs::metadata(&path)
                && meta.len() > 0
                && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
            {
                use std::io::Write;
                let zeros = [0u8; 8192];
                let mut rem = meta.len();
                while rem > 0 {
                    let step = (rem.min(8192)) as usize;
                    if f.write_all(&zeros[..step]).is_err() {
                        break;
                    }
                    rem -= step as u64;
                }
                let _ = f.sync_all();
            }
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn restrict_dir_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
