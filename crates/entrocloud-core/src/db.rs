//! Zero-knowledge persistent SQLite WAL metadata store implementing [`entrocloud_types::MetadataStore`].
//!
//! All sensitive metadata (filenames, virtual paths, dirty-op target paths, and conflict records)
//! are AEAD-encrypted at rest under `MetadataKey` with context-bound AAD, and indexed via keyed
//! `BLAKE3` blind indexes (`BlindIndexKey`) so zero plaintext filenames ever touch `.db` or `.db-wal`.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::Uuid;
use zeroize::Zeroizing;
use entrocloud_types::{
    BackendId, ChunkDescriptor, ConflictRecord, CryptoEngine, DirtyOp, DirtyOpKind, EntryKind,
    HydrationState, InodeId, InodeRecord, MetadataStore, ROOT_INODE, WrappedDek, ZeroVaultError,
    ZeroVaultResult,
};

const INODE_AAD_PREFIX: &[u8; 11] = b"ZV-INODE-V2";
const DIRTY_AAD_PREFIX: &[u8; 11] = b"ZV-DIRTY-V2";
const CONFLICT_AAD: &[u8; 14] = b"ZV-CONFLICT-V2";

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS sequences (
    name TEXT PRIMARY KEY,
    val INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS inodes (
    inode INTEGER PRIMARY KEY,
    parent_inode INTEGER NOT NULL,
    file_id TEXT NOT NULL,
    name_blind_idx BLOB NOT NULL,
    enc_meta BLOB NOT NULL,
    kind INTEGER NOT NULL,
    size INTEGER NOT NULL,
    mode INTEGER NOT NULL,
    hydration INTEGER NOT NULL,
    pinned INTEGER NOT NULL,
    version INTEGER NOT NULL,
    wrapped_dek BLOB,
    modified_at_ns INTEGER NOT NULL,
    created_at_ns INTEGER NOT NULL,
    UNIQUE (parent_inode, name_blind_idx)
);

CREATE INDEX IF NOT EXISTS idx_inodes_parent
    ON inodes (parent_inode);

CREATE TABLE IF NOT EXISTS chunks (
    inode INTEGER NOT NULL REFERENCES inodes(inode) ON DELETE CASCADE,
    file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    plaintext_len INTEGER NOT NULL,
    ciphertext_len INTEGER NOT NULL,
    blake3_plaintext BLOB NOT NULL,
    backends_json TEXT NOT NULL,
    locally_hydrated INTEGER NOT NULL,
    PRIMARY KEY (inode, chunk_index)
);

CREATE TABLE IF NOT EXISTS dirty_ops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inode INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    enc_path BLOB NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    queued_at_ns INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dirty_ops_inode
    ON dirty_ops (inode);

CREATE TABLE IF NOT EXISTS manifest_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    etag TEXT,
    parent_manifest_id TEXT
);

CREATE TABLE IF NOT EXISTS conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enc_conflict BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS security_epochs (
    scope TEXT PRIMARY KEY,
    min_epoch INTEGER NOT NULL
);
";

struct RawInodeRow {
    inode_i64: i64,
    parent_i64: i64,
    file_id_str: String,
    enc_meta: Vec<u8>,
    kind_i64: i64,
    size_i64: i64,
    mode_i64: i64,
    hydration_i64: i64,
    pinned_i64: i64,
    version_i64: i64,
    wrapped_blob: Option<Vec<u8>>,
    modified_ns: i64,
    created_ns: i64,
}

struct RawDirtyRow {
    id: i64,
    inode_i64: i64,
    kind_i64: i64,
    enc_path: Vec<u8>,
    retry_i64: i64,
    last_error: Option<String>,
    queued_ns: i64,
}

/// Zero-knowledge SQLite WAL-backed implementation of [`MetadataStore`].
///
/// Wraps a `rusqlite::Connection` in `parking_lot::Mutex` and dispatches queries onto
/// `tokio::task::spawn_blocking` so async tasks never block the Tokio executor or hold a
/// synchronous mutex guard across `.await`.
pub struct SqliteMetadataStore {
    conn: Arc<Mutex<Connection>>,
    crypto: Arc<dyn CryptoEngine>,
    in_memory: bool,
}

impl fmt::Debug for SqliteMetadataStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteMetadataStore")
            .field("in_memory", &self.in_memory)
            .finish_non_exhaustive()
    }
}

impl SqliteMetadataStore {
    /// Opens (or creates) an on-disk zero-knowledge SQLite WAL database at `db_path`.
    pub fn open(db_path: impl AsRef<Path>, crypto: Arc<dyn CryptoEngine>) -> ZeroVaultResult<Self> {
        let path_ref = db_path.as_ref();
        if let Some(parent) = path_ref.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path_ref).map_err(sqlite_err)?;
        Self::init_connection(conn, crypto, false)
    }

    /// Opens a volatile in-memory zero-knowledge SQLite database (intended for fast unit tests).
    pub fn open_in_memory(crypto: Arc<dyn CryptoEngine>) -> ZeroVaultResult<Self> {
        let conn = Connection::open_in_memory().map_err(sqlite_err)?;
        Self::init_connection(conn, crypto, true)
    }

    fn init_connection(
        conn: Connection,
        crypto: Arc<dyn CryptoEngine>,
        in_memory: bool,
    ) -> ZeroVaultResult<Self> {
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .map_err(sqlite_err)?;

        conn.execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(sqlite_err)?;

        if !in_memory && !mode.eq_ignore_ascii_case("wal") {
            return Err(ZeroVaultError::MetadataError(format!(
                "expected SQLite WAL journal_mode on file-backed DB, got '{mode}'"
            )));
        }

        conn.execute_batch(SCHEMA_SQL).map_err(sqlite_err)?;

        if crypto.is_unlocked() {
            ensure_root_seeded(&conn, crypto.as_ref())?;
        }

        let max_inode: i64 = conn
            .query_row("SELECT COALESCE(MAX(inode), 1) FROM inodes", [], |row| {
                row.get(0)
            })
            .map_err(sqlite_err)?;
        let initial_next = max_inode.saturating_add(1).max(2);

        conn.execute(
            "INSERT OR IGNORE INTO sequences (name, val) VALUES ('next_inode', ?1)",
            params![initial_next],
        )
        .map_err(sqlite_err)?;

        conn.execute(
            "INSERT OR IGNORE INTO manifest_cursor (id, revision, etag, parent_manifest_id)
             VALUES (1, 0, NULL, NULL)",
            [],
        )
        .map_err(sqlite_err)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            crypto,
            in_memory,
        })
    }

    /// Queries the active SQLite `PRAGMA journal_mode` (returns `"wal"` on file-backed DBs).
    pub fn journal_mode(&self) -> ZeroVaultResult<String> {
        let guard = self.conn.lock();
        guard
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .map_err(sqlite_err)
    }

    /// Queries the active SQLite `PRAGMA secure_delete` setting (`1` when enabled).
    pub fn secure_delete_mode(&self) -> ZeroVaultResult<i64> {
        let guard = self.conn.lock();
        guard
            .pragma_query_value(None, "secure_delete", |row| row.get::<_, i64>(0))
            .map_err(sqlite_err)
    }

    /// Forces a truncating WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`).
    pub fn wal_checkpoint_truncate(&self) -> ZeroVaultResult<()> {
        let guard = self.conn.lock();
        guard
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sqlite_err)
    }

    async fn run_blocking<T, F>(&self, f: F) -> ZeroVaultResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &dyn CryptoEngine) -> ZeroVaultResult<T> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        let crypto = Arc::clone(&self.crypto);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock();
            f(&mut guard, crypto.as_ref())
        })
        .await
        .map_err(|e| ZeroVaultError::MetadataError(format!("sqlite worker task failed: {e}")))?
    }
}

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    async fn get_inode(&self, inode: InodeId) -> ZeroVaultResult<Option<InodeRecord>> {
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            query_inode_by_id(conn, crypto, inode)
        })
        .await
    }

    async fn lookup_child(
        &self,
        parent_inode: InodeId,
        name: &str,
    ) -> ZeroVaultResult<Option<InodeRecord>> {
        let name = name.to_owned();
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            lookup_child_sync(conn, crypto, parent_inode, &name)
        })
        .await
    }

    async fn get_by_path(&self, virtual_path: &str) -> ZeroVaultResult<Option<InodeRecord>> {
        let path = virtual_path.to_owned();
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            if path == "/" {
                return query_inode_by_id(conn, crypto, ROOT_INODE);
            }
            if !path.starts_with('/') || path.ends_with('/') {
                return Ok(None);
            }
            let segments: Vec<&str> = path[1..].split('/').collect();
            if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
                return Ok(None);
            }

            let mut cur_parent = ROOT_INODE;
            let mut found: Option<InodeRecord> = None;
            for seg in segments {
                let Some(child) = lookup_child_sync(conn, crypto, cur_parent, seg)? else {
                    return Ok(None);
                };
                cur_parent = child.inode;
                found = Some(child);
            }

            if let Some(rec) = found
                && rec.virtual_path == path
            {
                return Ok(Some(rec));
            }
            Ok(None)
        })
        .await
    }

    async fn list_children(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            let parent_i64 = to_i64(parent_inode)?;
            let root_i64 = to_i64(ROOT_INODE)?;
            let mut stmt = conn
                .prepare(
                    "SELECT inode, parent_inode, file_id, enc_meta, kind,
                            size, mode, hydration, pinned, version, wrapped_dek,
                            modified_at_ns, created_at_ns
                     FROM inodes
                     WHERE inode != ?1 AND parent_inode = ?2",
                )
                .map_err(sqlite_err)?;
            let raw_rows = stmt
                .query_map(params![root_i64, parent_i64], read_raw_inode_row)
                .map_err(sqlite_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_err)?;

            let mut out = Vec::with_capacity(raw_rows.len());
            for raw in raw_rows {
                out.push(decode_inode_row(raw, crypto)?);
            }
            out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.inode.cmp(&b.inode)));
            Ok(out)
        })
        .await
    }

    async fn upsert_inode(&self, record: InodeRecord) -> ZeroVaultResult<InodeRecord> {
        let record_clone = record.clone();
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            let tx = conn.transaction().map_err(sqlite_err)?;
            let inode_i64 = to_i64(record_clone.inode)?;
            let parent_i64 = to_i64(record_clone.parent_inode)?;
            let size_i64 = to_i64(record_clone.size)?;
            let mode_i64 = i64::from(record_clone.mode);
            let version_i64 = to_i64(record_clone.version)?;

            let blind_idx: [u8; 32] = if record_clone.inode == ROOT_INODE {
                [0u8; 32]
            } else {
                crypto.compute_blind_index(record_clone.parent_inode, &record_clone.name)?
            };
            let enc_meta = seal_inode_meta(
                crypto,
                record_clone.inode,
                record_clone.parent_inode,
                &record_clone.name,
                &record_clone.virtual_path,
            )?;

            let wrapped_bytes: Option<Vec<u8>> = match &record_clone.wrapped_dek {
                Some(wd) => Some(postcard::to_allocvec(wd).map_err(|e| {
                    ZeroVaultError::MetadataError(format!("failed to encode wrapped_dek: {e}"))
                })?),
                None => None,
            };
            let next_floor = inode_i64.saturating_add(1).max(2);

            tx.execute(
                "INSERT INTO inodes (
                    inode, parent_inode, file_id, name_blind_idx, enc_meta, kind,
                    size, mode, hydration, pinned, version, wrapped_dek, modified_at_ns, created_at_ns
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(inode) DO UPDATE SET
                    parent_inode = excluded.parent_inode,
                    file_id = excluded.file_id,
                    name_blind_idx = excluded.name_blind_idx,
                    enc_meta = excluded.enc_meta,
                    kind = excluded.kind,
                    size = excluded.size,
                    mode = excluded.mode,
                    hydration = excluded.hydration,
                    pinned = excluded.pinned,
                    version = excluded.version,
                    wrapped_dek = excluded.wrapped_dek,
                    modified_at_ns = excluded.modified_at_ns,
                    created_at_ns = excluded.created_at_ns",
                params![
                    inode_i64,
                    parent_i64,
                    record_clone.file_id.to_string(),
                    blind_idx.as_slice(),
                    enc_meta,
                    entry_kind_to_code(record_clone.kind),
                    size_i64,
                    mode_i64,
                    hydration_to_code(record_clone.hydration),
                    i64::from(record_clone.pinned),
                    version_i64,
                    wrapped_bytes,
                    datetime_to_ns(record_clone.modified_at),
                    datetime_to_ns(record_clone.created_at),
                ],
            )
            .map_err(sqlite_upsert_err)?;

            tx.execute(
                "UPDATE sequences SET val = MAX(val, ?1) WHERE name = 'next_inode'",
                params![next_floor],
            )
            .map_err(sqlite_err)?;

            tx.commit().map_err(sqlite_err)?;
            Ok(record_clone)
        })
        .await
    }

    async fn allocate_inode_id(&self) -> ZeroVaultResult<InodeId> {
        self.run_blocking(move |conn, _crypto| {
            let tx = conn.transaction().map_err(sqlite_err)?;
            let current: i64 = tx
                .query_row(
                    "SELECT val FROM sequences WHERE name = 'next_inode'",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_err)?;
            let max_existing: i64 = tx
                .query_row("SELECT COALESCE(MAX(inode), 1) FROM inodes", [], |row| {
                    row.get(0)
                })
                .map_err(sqlite_err)?;
            let allocated = current.max(max_existing.saturating_add(1)).max(2);
            let next_val = allocated
                .checked_add(1)
                .ok_or_else(|| ZeroVaultError::MetadataError("inode sequence overflow".into()))?;
            tx.execute(
                "UPDATE sequences SET val = ?1 WHERE name = 'next_inode'",
                params![next_val],
            )
            .map_err(sqlite_err)?;
            tx.commit().map_err(sqlite_err)?;
            to_u64(allocated)
        })
        .await
    }

    async fn delete_inode(&self, inode: InodeId) -> ZeroVaultResult<()> {
        if inode == ROOT_INODE {
            return Err(ZeroVaultError::MetadataError(
                "cannot delete root inode".into(),
            ));
        }
        self.run_blocking(move |conn, _crypto| {
            let inode_i64 = to_i64(inode)?;
            conn.execute("DELETE FROM inodes WHERE inode = ?1", params![inode_i64])
                .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn replace_chunks(
        &self,
        inode: InodeId,
        chunks: Vec<ChunkDescriptor>,
    ) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, crypto| {
            if crypto.is_unlocked() {
                ensure_root_seeded(conn, crypto)?;
            }
            let tx = conn.transaction().map_err(sqlite_err)?;
            let inode_i64 = to_i64(inode)?;
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT inode FROM inodes WHERE inode = ?1",
                    params![inode_i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_err)?;
            if exists.is_none() {
                return Err(ZeroVaultError::InodeNotFound(inode));
            }

            tx.execute("DELETE FROM chunks WHERE inode = ?1", params![inode_i64])
                .map_err(sqlite_err)?;

            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO chunks (
                            inode, file_id, chunk_index, blob_id, plaintext_len,
                            ciphertext_len, blake3_plaintext, backends_json, locally_hydrated
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    )
                    .map_err(sqlite_err)?;

                for chunk in chunks {
                    let backends_json =
                        serde_json::to_string(&chunk.backend_ids).map_err(|e| {
                            ZeroVaultError::MetadataError(format!(
                                "failed to serialize backend_ids: {e}"
                            ))
                        })?;
                    stmt.execute(params![
                        inode_i64,
                        chunk.file_id.to_string(),
                        to_i64(chunk.chunk_index)?,
                        chunk.blob_id.to_string(),
                        i64::from(chunk.plaintext_len),
                        i64::from(chunk.ciphertext_len),
                        chunk.blake3_plaintext.as_slice(),
                        backends_json,
                        i64::from(chunk.locally_hydrated),
                    ])
                    .map_err(sqlite_err)?;
                }
            }

            tx.commit().map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_chunks(&self, inode: InodeId) -> ZeroVaultResult<Vec<ChunkDescriptor>> {
        self.run_blocking(move |conn, _crypto| {
            let inode_i64 = to_i64(inode)?;
            let mut stmt = conn
                .prepare(
                    "SELECT inode, file_id, chunk_index, blob_id, plaintext_len,
                            ciphertext_len, blake3_plaintext, backends_json, locally_hydrated
                     FROM chunks
                     WHERE inode = ?1
                     ORDER BY chunk_index ASC",
                )
                .map_err(sqlite_err)?;
            let rows = stmt
                .query_map(params![inode_i64], row_to_chunk)
                .map_err(sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_err)
        })
        .await
    }

    async fn set_chunk_hydrated(
        &self,
        inode: InodeId,
        chunk_index: u64,
        hydrated: bool,
    ) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, _crypto| {
            let tx = conn.transaction().map_err(sqlite_err)?;
            let inode_i64 = to_i64(inode)?;
            let chunk_i64 = to_i64(chunk_index)?;

            let row: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT pinned, hydration FROM inodes WHERE inode = ?1",
                    params![inode_i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(sqlite_err)?;

            let Some((pinned_i64, hydration_code)) = row else {
                return Err(ZeroVaultError::InodeNotFound(inode));
            };
            let pinned = pinned_i64 != 0;
            let current_hydration = code_to_hydration(hydration_code)?;

            tx.execute(
                "UPDATE chunks SET locally_hydrated = ?1 WHERE inode = ?2 AND chunk_index = ?3",
                params![i64::from(hydrated), inode_i64, chunk_i64],
            )
            .map_err(sqlite_err)?;

            let (total, hydrated_count): (i64, i64) = tx
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN locally_hydrated != 0 THEN 1 ELSE 0 END), 0)
                     FROM chunks WHERE inode = ?1",
                    params![inode_i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(sqlite_err)?;

            if !pinned && current_hydration != HydrationState::DirtyLocal {
                let next_hydration = if total > 0 && hydrated_count == total {
                    HydrationState::LocallyCached
                } else if hydrated_count > 0 {
                    HydrationState::PartiallyHydrated
                } else {
                    HydrationState::OnlineOnly
                };
                tx.execute(
                    "UPDATE inodes SET hydration = ?1 WHERE inode = ?2",
                    params![hydration_to_code(next_hydration), inode_i64],
                )
                .map_err(sqlite_err)?;
            }

            tx.commit().map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn set_hydration_and_pin(
        &self,
        inode: InodeId,
        hydration: HydrationState,
        pinned: bool,
    ) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, crypto| {
            if inode == ROOT_INODE && crypto.is_unlocked() {
                ensure_root_seeded(conn, crypto)?;
            }
            let inode_i64 = to_i64(inode)?;
            let updated = conn
                .execute(
                    "UPDATE inodes SET hydration = ?1, pinned = ?2 WHERE inode = ?3",
                    params![hydration_to_code(hydration), i64::from(pinned), inode_i64],
                )
                .map_err(sqlite_err)?;
            if updated == 0 {
                return Err(ZeroVaultError::InodeNotFound(inode));
            }
            Ok(())
        })
        .await
    }

    async fn enqueue_dirty(
        &self,
        inode: InodeId,
        kind: DirtyOpKind,
        virtual_path: &str,
    ) -> ZeroVaultResult<i64> {
        let vpath = virtual_path.to_owned();
        self.run_blocking(move |conn, crypto| {
            let inode_i64 = to_i64(inode)?;
            let aad = dirty_aad(inode);
            let enc_path = crypto.seal_metadata(&aad, vpath.as_bytes())?;
            let now_ns = datetime_to_ns(Utc::now());
            conn.execute(
                "INSERT INTO dirty_ops (inode, kind, enc_path, retry_count, last_error, queued_at_ns)
                 VALUES (?1, ?2, ?3, 0, NULL, ?4)",
                params![inode_i64, dirty_kind_to_code(kind), enc_path, now_ns],
            )
            .map_err(sqlite_err)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    async fn list_dirty_ops(&self) -> ZeroVaultResult<Vec<DirtyOp>> {
        self.run_blocking(move |conn, crypto| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, inode, kind, enc_path, retry_count, last_error, queued_at_ns
                     FROM dirty_ops
                     ORDER BY id ASC",
                )
                .map_err(sqlite_err)?;
            let raw_rows = stmt
                .query_map([], read_raw_dirty_row)
                .map_err(sqlite_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_err)?;

            let mut out = Vec::with_capacity(raw_rows.len());
            for raw in raw_rows {
                out.push(decode_dirty_row(raw, crypto)?);
            }
            Ok(out)
        })
        .await
    }

    async fn complete_dirty_op(&self, id: i64) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, _crypto| {
            conn.execute("DELETE FROM dirty_ops WHERE id = ?1", params![id])
                .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn mark_dirty_retry(&self, id: i64, error: &str) -> ZeroVaultResult<()> {
        let err_msg = error.to_owned();
        self.run_blocking(move |conn, _crypto| {
            conn.execute(
                "UPDATE dirty_ops
                 SET retry_count = retry_count + 1, last_error = ?1
                 WHERE id = ?2",
                params![err_msg, id],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn manifest_cursor(&self) -> ZeroVaultResult<(u64, Option<String>)> {
        self.run_blocking(move |conn, _crypto| {
            let (rev, etag): (i64, Option<String>) = conn
                .query_row(
                    "SELECT revision, etag FROM manifest_cursor WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sqlite_err)?;
            Ok((to_u64(rev)?, etag))
        })
        .await
    }

    async fn update_manifest_cursor(
        &self,
        revision: u64,
        remote_etag: Option<String>,
    ) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, _crypto| {
            let rev_i64 = to_i64(revision)?;
            conn.execute(
                "UPDATE manifest_cursor SET revision = ?1, etag = ?2 WHERE id = 1",
                params![rev_i64, remote_etag],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn parent_manifest_id(&self) -> ZeroVaultResult<Option<Uuid>> {
        self.run_blocking(move |conn, _crypto| {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT parent_manifest_id FROM manifest_cursor WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_err)?;
            match raw {
                Some(s) => {
                    let parsed = Uuid::parse_str(&s).map_err(|e| {
                        ZeroVaultError::MetadataError(format!(
                            "corrupt persisted parent_manifest_id: {e}"
                        ))
                    })?;
                    Ok(Some(parsed))
                }
                None => Ok(None),
            }
        })
        .await
    }

    async fn set_parent_manifest_id(&self, manifest_id: Option<Uuid>) -> ZeroVaultResult<()> {
        let id_str = manifest_id.map(|id| id.to_string());
        self.run_blocking(move |conn, _crypto| {
            conn.execute(
                "UPDATE manifest_cursor SET parent_manifest_id = ?1 WHERE id = 1",
                params![id_str],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn epoch_floor(&self, scope: &str) -> ZeroVaultResult<u64> {
        let scope_owned = scope.to_owned();
        self.run_blocking(move |conn, _crypto| {
            let min_epoch: Option<i64> = conn
                .query_row(
                    "SELECT min_epoch FROM security_epochs WHERE scope = ?1",
                    params![scope_owned],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_err)?;
            match min_epoch {
                Some(v) => to_u64(v),
                None => Ok(0),
            }
        })
        .await
    }

    async fn advance_epoch_floor(&self, scope: &str, new_epoch: u64) -> ZeroVaultResult<()> {
        let scope_owned = scope.to_owned();
        self.run_blocking(move |conn, _crypto| {
            let tx = conn.transaction().map_err(sqlite_err)?;
            let cur_opt: Option<i64> = tx
                .query_row(
                    "SELECT min_epoch FROM security_epochs WHERE scope = ?1",
                    params![scope_owned],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_err)?;
            let current = match cur_opt {
                Some(v) => to_u64(v)?,
                None => 0,
            };
            if new_epoch < current {
                return Err(ZeroVaultError::CryptoTamperDetected(format!(
                    "security epoch rollback rejected for scope '{scope_owned}': new={new_epoch} < floor={current}"
                )));
            }
            let new_i64 = to_i64(new_epoch)?;
            tx.execute(
                "INSERT INTO security_epochs (scope, min_epoch) VALUES (?1, ?2)
                 ON CONFLICT(scope) DO UPDATE SET min_epoch = excluded.min_epoch",
                params![scope_owned, new_i64],
            )
            .map_err(sqlite_err)?;
            tx.commit().map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_all_inodes(&self) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.run_blocking(move |conn, crypto| {
            ensure_root_seeded(conn, crypto)?;
            let mut stmt = conn
                .prepare(
                    "SELECT inode, parent_inode, file_id, enc_meta, kind,
                            size, mode, hydration, pinned, version, wrapped_dek,
                            modified_at_ns, created_at_ns
                     FROM inodes
                     ORDER BY inode ASC",
                )
                .map_err(sqlite_err)?;
            let raw_rows = stmt
                .query_map([], read_raw_inode_row)
                .map_err(sqlite_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_err)?;

            let mut out = Vec::with_capacity(raw_rows.len());
            for raw in raw_rows {
                out.push(decode_inode_row(raw, crypto)?);
            }
            Ok(out)
        })
        .await
    }

    async fn record_conflict(&self, conflict: ConflictRecord) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn, crypto| {
            let serialized = Zeroizing::new(postcard::to_allocvec(&conflict).map_err(|e| {
                ZeroVaultError::MetadataError(format!("failed to serialize ConflictRecord: {e}"))
            })?);
            let enc_conflict = crypto.seal_metadata(CONFLICT_AAD, &serialized)?;
            conn.execute(
                "INSERT INTO conflicts (enc_conflict) VALUES (?1)",
                params![enc_conflict],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_conflicts(&self) -> ZeroVaultResult<Vec<ConflictRecord>> {
        self.run_blocking(move |conn, crypto| {
            let mut stmt = conn
                .prepare("SELECT enc_conflict FROM conflicts ORDER BY id ASC")
                .map_err(sqlite_err)?;
            let blobs = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(sqlite_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_err)?;

            let mut out = Vec::with_capacity(blobs.len());
            for enc in blobs {
                let pt = crypto.open_metadata(CONFLICT_AAD, &enc)?;
                let rec: ConflictRecord = postcard::from_bytes(&pt).map_err(|e| {
                    ZeroVaultError::CryptoTamperDetected(format!(
                        "corrupt decrypted ConflictRecord: {e}"
                    ))
                })?;
                out.push(rec);
            }
            Ok(out)
        })
        .await
    }
}

fn ensure_root_seeded(conn: &Connection, crypto: &dyn CryptoEngine) -> ZeroVaultResult<()> {
    let root_i64 = to_i64(ROOT_INODE)?;
    let exists: Option<i64> = conn
        .query_row(
            "SELECT inode FROM inodes WHERE inode = ?1",
            params![root_i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if exists.is_some() {
        return Ok(());
    }

    let now_ns = datetime_to_ns(Utc::now());
    let blind_idx = [0u8; 32];
    let enc_meta = seal_inode_meta(crypto, ROOT_INODE, ROOT_INODE, "", "/")?;
    conn.execute(
        "INSERT OR IGNORE INTO inodes (
            inode, parent_inode, file_id, name_blind_idx, enc_meta, kind,
            size, mode, hydration, pinned, version, wrapped_dek, modified_at_ns, created_at_ns
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, 1, 1, NULL, ?9, ?10)",
        params![
            root_i64,
            root_i64,
            Uuid::nil().to_string(),
            blind_idx.as_slice(),
            enc_meta,
            entry_kind_to_code(EntryKind::Directory),
            i64::from(0o755u32),
            hydration_to_code(HydrationState::Pinned),
            now_ns,
            now_ns,
        ],
    )
    .map_err(sqlite_err)?;
    Ok(())
}

fn query_inode_by_id(
    conn: &Connection,
    crypto: &dyn CryptoEngine,
    inode: InodeId,
) -> ZeroVaultResult<Option<InodeRecord>> {
    let inode_i64 = to_i64(inode)?;
    let raw = conn
        .query_row(
            "SELECT inode, parent_inode, file_id, enc_meta, kind,
                    size, mode, hydration, pinned, version, wrapped_dek,
                    modified_at_ns, created_at_ns
             FROM inodes WHERE inode = ?1",
            params![inode_i64],
            read_raw_inode_row,
        )
        .optional()
        .map_err(sqlite_err)?;
    raw.map(|r| decode_inode_row(r, crypto)).transpose()
}

fn lookup_child_sync(
    conn: &Connection,
    crypto: &dyn CryptoEngine,
    parent_inode: InodeId,
    name: &str,
) -> ZeroVaultResult<Option<InodeRecord>> {
    let parent_i64 = to_i64(parent_inode)?;
    let root_i64 = to_i64(ROOT_INODE)?;
    let blind_idx = crypto.compute_blind_index(parent_inode, name)?;
    let raw = conn
        .query_row(
            "SELECT inode, parent_inode, file_id, enc_meta, kind,
                    size, mode, hydration, pinned, version, wrapped_dek,
                    modified_at_ns, created_at_ns
             FROM inodes
             WHERE inode != ?1 AND parent_inode = ?2 AND name_blind_idx = ?3",
            params![root_i64, parent_i64, blind_idx.as_slice()],
            read_raw_inode_row,
        )
        .optional()
        .map_err(sqlite_err)?;

    let Some(raw_row) = raw else {
        return Ok(None);
    };
    let rec = decode_inode_row(raw_row, crypto)?;
    if rec.name == name {
        Ok(Some(rec))
    } else {
        Ok(None)
    }
}

fn inode_aad(inode: InodeId, parent_inode: InodeId) -> [u8; 27] {
    let mut aad = [0u8; 27];
    aad[0..11].copy_from_slice(INODE_AAD_PREFIX);
    aad[11..19].copy_from_slice(&inode.to_le_bytes());
    aad[19..27].copy_from_slice(&parent_inode.to_le_bytes());
    aad
}

fn dirty_aad(inode: InodeId) -> [u8; 19] {
    let mut aad = [0u8; 19];
    aad[0..11].copy_from_slice(DIRTY_AAD_PREFIX);
    aad[11..19].copy_from_slice(&inode.to_le_bytes());
    aad
}

fn seal_inode_meta(
    crypto: &dyn CryptoEngine,
    inode: InodeId,
    parent_inode: InodeId,
    name: &str,
    virtual_path: &str,
) -> ZeroVaultResult<Vec<u8>> {
    let payload = Zeroizing::new(
        postcard::to_allocvec(&(name.to_owned(), virtual_path.to_owned())).map_err(|e| {
            ZeroVaultError::MetadataError(format!("failed to serialize inode metadata: {e}"))
        })?,
    );
    let aad = inode_aad(inode, parent_inode);
    crypto.seal_metadata(&aad, &payload)
}

fn open_inode_meta(
    crypto: &dyn CryptoEngine,
    inode: InodeId,
    parent_inode: InodeId,
    enc_meta: &[u8],
) -> ZeroVaultResult<(String, String)> {
    let aad = inode_aad(inode, parent_inode);
    let pt = crypto.open_metadata(&aad, enc_meta)?;
    postcard::from_bytes::<(String, String)>(&pt).map_err(|e| {
        ZeroVaultError::CryptoTamperDetected(format!("corrupt decrypted inode metadata: {e}"))
    })
}

fn read_raw_inode_row(row: &Row<'_>) -> rusqlite::Result<RawInodeRow> {
    Ok(RawInodeRow {
        inode_i64: row.get(0)?,
        parent_i64: row.get(1)?,
        file_id_str: row.get(2)?,
        enc_meta: row.get(3)?,
        kind_i64: row.get(4)?,
        size_i64: row.get(5)?,
        mode_i64: row.get(6)?,
        hydration_i64: row.get(7)?,
        pinned_i64: row.get(8)?,
        version_i64: row.get(9)?,
        wrapped_blob: row.get(10)?,
        modified_ns: row.get(11)?,
        created_ns: row.get(12)?,
    })
}

fn decode_inode_row(raw: RawInodeRow, crypto: &dyn CryptoEngine) -> ZeroVaultResult<InodeRecord> {
    let inode = to_u64(raw.inode_i64)?;
    let parent_inode = to_u64(raw.parent_i64)?;
    let file_id = Uuid::parse_str(&raw.file_id_str)
        .map_err(|e| ZeroVaultError::MetadataError(format!("invalid inode file_id UUID: {e}")))?;
    let (name, virtual_path) = open_inode_meta(crypto, inode, parent_inode, &raw.enc_meta)?;
    let kind = code_to_entry_kind(raw.kind_i64)?;
    let size = to_u64(raw.size_i64)?;
    let mode = u32::try_from(raw.mode_i64).map_err(int_conv_err)?;
    let hydration = code_to_hydration(raw.hydration_i64)?;
    let version = to_u64(raw.version_i64)?;
    let wrapped_dek = match raw.wrapped_blob {
        Some(bytes) => {
            let dek: WrappedDek = postcard::from_bytes(&bytes).map_err(|e| {
                ZeroVaultError::MetadataError(format!("invalid wrapped_dek blob: {e}"))
            })?;
            Some(dek)
        }
        None => None,
    };

    Ok(InodeRecord {
        inode,
        parent_inode,
        file_id,
        name,
        virtual_path,
        kind,
        size,
        mode,
        hydration,
        pinned: raw.pinned_i64 != 0,
        version,
        wrapped_dek,
        modified_at: ns_to_datetime(raw.modified_ns),
        created_at: ns_to_datetime(raw.created_ns),
    })
}

fn read_raw_dirty_row(row: &Row<'_>) -> rusqlite::Result<RawDirtyRow> {
    Ok(RawDirtyRow {
        id: row.get(0)?,
        inode_i64: row.get(1)?,
        kind_i64: row.get(2)?,
        enc_path: row.get(3)?,
        retry_i64: row.get(4)?,
        last_error: row.get(5)?,
        queued_ns: row.get(6)?,
    })
}

fn decode_dirty_row(raw: RawDirtyRow, crypto: &dyn CryptoEngine) -> ZeroVaultResult<DirtyOp> {
    let inode = to_u64(raw.inode_i64)?;
    let kind = code_to_dirty_kind(raw.kind_i64)?;
    let aad = dirty_aad(inode);
    let pt = crypto.open_metadata(&aad, &raw.enc_path)?;
    let virtual_path = String::from_utf8(pt.to_vec()).map_err(|e| {
        ZeroVaultError::CryptoTamperDetected(format!("invalid UTF-8 in decrypted dirty path: {e}"))
    })?;
    let retry_count = u32::try_from(raw.retry_i64).map_err(int_conv_err)?;

    Ok(DirtyOp {
        id: raw.id,
        inode,
        kind,
        virtual_path,
        retry_count,
        last_error: raw.last_error,
        queued_at: ns_to_datetime(raw.queued_ns),
    })
}

fn row_to_chunk(row: &Row<'_>) -> rusqlite::Result<ChunkDescriptor> {
    let inode_i64: i64 = row.get(0)?;
    let file_id_str: String = row.get(1)?;
    let chunk_idx_i64: i64 = row.get(2)?;
    let blob_id_str: String = row.get(3)?;
    let pt_len_i64: i64 = row.get(4)?;
    let ct_len_i64: i64 = row.get(5)?;
    let blake3_vec: Vec<u8> = row.get(6)?;
    let backend_json: String = row.get(7)?;
    let hydrated_i64: i64 = row.get(8)?;

    let blake3_plaintext: [u8; 32] = blake3_vec.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Blob,
            "expected 32-byte blake3 digest".into(),
        )
    })?;
    let backend_ids: Vec<BackendId> = serde_json::from_str(&backend_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(ChunkDescriptor {
        inode: u64::try_from(inode_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        file_id: parse_uuid(&file_id_str, 1)?,
        chunk_index: u64::try_from(chunk_idx_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        blob_id: parse_uuid(&blob_id_str, 3)?,
        plaintext_len: u32::try_from(pt_len_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        ciphertext_len: u32::try_from(ct_len_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        blake3_plaintext,
        backend_ids,
        locally_hydrated: hydrated_i64 != 0,
    })
}

fn sqlite_err(err: rusqlite::Error) -> ZeroVaultError {
    ZeroVaultError::MetadataError(err.to_string())
}

fn sqlite_upsert_err(err: rusqlite::Error) -> ZeroVaultError {
    if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err
        && ffi_err.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return ZeroVaultError::AlreadyExists("inode blind-index constraint violation".into());
    }
    sqlite_err(err)
}

fn int_conv_err(err: std::num::TryFromIntError) -> ZeroVaultError {
    ZeroVaultError::MetadataError(format!("integer range conversion failed: {err}"))
}

fn to_i64(val: u64) -> ZeroVaultResult<i64> {
    i64::try_from(val).map_err(int_conv_err)
}

fn to_u64(val: i64) -> ZeroVaultResult<u64> {
    u64::try_from(val).map_err(int_conv_err)
}

fn datetime_to_ns(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_nanos_opt()
        .unwrap_or_else(|| dt.timestamp().saturating_mul(1_000_000_000))
}

fn ns_to_datetime(ns: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(ns)
}

const fn entry_kind_to_code(kind: EntryKind) -> i64 {
    match kind {
        EntryKind::File => 0,
        EntryKind::Directory => 1,
    }
}

fn code_to_entry_kind(code: i64) -> ZeroVaultResult<EntryKind> {
    match code {
        0 => Ok(EntryKind::File),
        1 => Ok(EntryKind::Directory),
        other => Err(ZeroVaultError::MetadataError(format!(
            "invalid entry kind code: {other}"
        ))),
    }
}

const fn hydration_to_code(state: HydrationState) -> i64 {
    match state {
        HydrationState::OnlineOnly => 0,
        HydrationState::PartiallyHydrated => 1,
        HydrationState::LocallyCached => 2,
        HydrationState::Pinned => 3,
        HydrationState::DirtyLocal => 4,
    }
}

fn code_to_hydration(code: i64) -> ZeroVaultResult<HydrationState> {
    match code {
        0 => Ok(HydrationState::OnlineOnly),
        1 => Ok(HydrationState::PartiallyHydrated),
        2 => Ok(HydrationState::LocallyCached),
        3 => Ok(HydrationState::Pinned),
        4 => Ok(HydrationState::DirtyLocal),
        other => Err(ZeroVaultError::MetadataError(format!(
            "invalid hydration state code: {other}"
        ))),
    }
}

const fn dirty_kind_to_code(kind: DirtyOpKind) -> i64 {
    match kind {
        DirtyOpKind::UpsertFile => 0,
        DirtyOpKind::UpsertMetadata => 1,
        DirtyOpKind::Delete => 2,
    }
}

fn code_to_dirty_kind(code: i64) -> ZeroVaultResult<DirtyOpKind> {
    match code {
        0 => Ok(DirtyOpKind::UpsertFile),
        1 => Ok(DirtyOpKind::UpsertMetadata),
        2 => Ok(DirtyOpKind::Delete),
        other => Err(ZeroVaultError::MetadataError(format!(
            "invalid dirty op kind code: {other}"
        ))),
    }
}

fn parse_uuid(raw: &str, col: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}
