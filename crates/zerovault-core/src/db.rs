//! Persistent SQLite WAL metadata store implementing [`zerovault_types::MetadataStore`].

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::Uuid;
use zerovault_types::{
    BackendId, ChunkDescriptor, ConflictRecord, DirtyOp, DirtyOpKind, EntryKind, HydrationState,
    InodeId, InodeRecord, MetadataStore, ROOT_INODE, WrappedDek, ZeroVaultError, ZeroVaultResult,
};

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS sequences (
    name TEXT PRIMARY KEY,
    val INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS inodes (
    inode INTEGER PRIMARY KEY,
    parent_inode INTEGER NOT NULL,
    file_id TEXT NOT NULL,
    name TEXT NOT NULL,
    virtual_path TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    mode INTEGER NOT NULL,
    hydration TEXT NOT NULL,
    pinned INTEGER NOT NULL,
    version INTEGER NOT NULL,
    wrapped_dek BLOB,
    modified_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inodes_parent_name
    ON inodes (parent_inode, name);

CREATE TABLE IF NOT EXISTS chunks (
    inode INTEGER NOT NULL REFERENCES inodes(inode) ON DELETE CASCADE,
    file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    plaintext_len INTEGER NOT NULL,
    ciphertext_len INTEGER NOT NULL,
    blake3_plaintext BLOB NOT NULL,
    backend_ids TEXT NOT NULL,
    locally_hydrated INTEGER NOT NULL,
    PRIMARY KEY (inode, chunk_index)
);

CREATE TABLE IF NOT EXISTS dirty_ops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inode INTEGER NOT NULL,
    kind TEXT NOT NULL,
    virtual_path TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    queued_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dirty_ops_inode
    ON dirty_ops (inode);

CREATE TABLE IF NOT EXISTS manifest_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    remote_etag TEXT
);

CREATE TABLE IF NOT EXISTS conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    conflict_path TEXT NOT NULL,
    remote_revision INTEGER NOT NULL,
    detected_at TEXT NOT NULL
);
";

/// SQLite WAL-backed implementation of [`MetadataStore`].
///
/// Wraps a `rusqlite::Connection` in `parking_lot::Mutex` and dispatches queries onto
/// `tokio::task::spawn_blocking` so async tasks never block the Tokio executor or hold a
/// synchronous mutex guard across `.await`.
pub struct SqliteMetadataStore {
    conn: Arc<Mutex<Connection>>,
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
    /// Opens (or creates) an on-disk SQLite WAL database at `path`, creating parent directories.
    pub fn open(path: impl AsRef<Path>) -> ZeroVaultResult<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path_ref).map_err(sqlite_err)?;
        Self::init_connection(conn, false)
    }

    /// Opens a volatile in-memory SQLite database (intended for fast unit tests).
    pub fn open_in_memory() -> ZeroVaultResult<Self> {
        let conn = Connection::open_in_memory().map_err(sqlite_err)?;
        Self::init_connection(conn, true)
    }

    fn init_connection(conn: Connection, in_memory: bool) -> ZeroVaultResult<Self> {
        // Configure mandatory SQLite concurrency, durability, and FK pragmas.
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .map_err(sqlite_err)?;

        conn.execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(sqlite_err)?;

        if !in_memory && !mode.eq_ignore_ascii_case("wal") {
            return Err(ZeroVaultError::MetadataError(format!(
                "expected SQLite WAL journal_mode on file-backed DB, got '{mode}'"
            )));
        }

        conn.execute_batch(SCHEMA_SQL).map_err(sqlite_err)?;

        // Seed root `/` inode (`ROOT_INODE = 1`), sequence counter, and singleton manifest cursor.
        let now = Utc::now().to_rfc3339();
        let root_file_id = Uuid::nil().to_string();
        conn.execute(
            "INSERT OR IGNORE INTO inodes (
                inode, parent_inode, file_id, name, virtual_path, kind,
                size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, 1, 1, NULL, ?9, ?10)",
            params![
                i64::try_from(ROOT_INODE).map_err(int_conv_err)?,
                i64::try_from(ROOT_INODE).map_err(int_conv_err)?,
                root_file_id,
                "",
                "/",
                entry_kind_to_str(EntryKind::Directory),
                i64::from(0o755u32),
                HydrationState::Pinned.as_xattr_str(),
                now,
                now,
            ],
        )
        .map_err(sqlite_err)?;

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
            "INSERT OR IGNORE INTO manifest_cursor (id, revision, remote_etag) VALUES (1, 0, NULL)",
            [],
        )
        .map_err(sqlite_err)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
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

    async fn run_blocking<T, F>(&self, f: F) -> ZeroVaultResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> ZeroVaultResult<T> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock();
            f(&mut guard)
        })
        .await
        .map_err(|e| ZeroVaultError::MetadataError(format!("sqlite worker task failed: {e}")))?
    }
}

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    async fn get_inode(&self, inode: InodeId) -> ZeroVaultResult<Option<InodeRecord>> {
        self.run_blocking(move |conn| {
            let inode_i64 = to_i64(inode)?;
            conn.query_row(
                "SELECT inode, parent_inode, file_id, name, virtual_path, kind,
                        size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                 FROM inodes WHERE inode = ?1",
                params![inode_i64],
                row_to_inode,
            )
            .optional()
            .map_err(sqlite_err)
        })
        .await
    }

    async fn lookup_child(
        &self,
        parent_inode: InodeId,
        name: &str,
    ) -> ZeroVaultResult<Option<InodeRecord>> {
        let name = name.to_owned();
        self.run_blocking(move |conn| {
            let parent_i64 = to_i64(parent_inode)?;
            let root_i64 = to_i64(ROOT_INODE)?;
            conn.query_row(
                "SELECT inode, parent_inode, file_id, name, virtual_path, kind,
                        size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                 FROM inodes
                 WHERE inode != ?1 AND parent_inode = ?2 AND name = ?3",
                params![root_i64, parent_i64, name],
                row_to_inode,
            )
            .optional()
            .map_err(sqlite_err)
        })
        .await
    }

    async fn get_by_path(&self, virtual_path: &str) -> ZeroVaultResult<Option<InodeRecord>> {
        let path = virtual_path.to_owned();
        self.run_blocking(move |conn| {
            conn.query_row(
                "SELECT inode, parent_inode, file_id, name, virtual_path, kind,
                        size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                 FROM inodes WHERE virtual_path = ?1",
                params![path],
                row_to_inode,
            )
            .optional()
            .map_err(sqlite_err)
        })
        .await
    }

    async fn list_children(&self, parent_inode: InodeId) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.run_blocking(move |conn| {
            let parent_i64 = to_i64(parent_inode)?;
            let root_i64 = to_i64(ROOT_INODE)?;
            let mut stmt = conn
                .prepare(
                    "SELECT inode, parent_inode, file_id, name, virtual_path, kind,
                            size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                     FROM inodes
                     WHERE inode != ?1 AND parent_inode = ?2
                     ORDER BY name ASC, inode ASC",
                )
                .map_err(sqlite_err)?;
            let rows = stmt
                .query_map(params![root_i64, parent_i64], row_to_inode)
                .map_err(sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_err)
        })
        .await
    }

    async fn upsert_inode(&self, record: InodeRecord) -> ZeroVaultResult<InodeRecord> {
        let record_clone = record.clone();
        self.run_blocking(move |conn| {
            let tx = conn.transaction().map_err(sqlite_err)?;
            let inode_i64 = to_i64(record_clone.inode)?;
            let parent_i64 = to_i64(record_clone.parent_inode)?;
            let size_i64 = to_i64(record_clone.size)?;
            let mode_i64 = i64::from(record_clone.mode);
            let version_i64 = to_i64(record_clone.version)?;
            let wrapped_bytes: Option<Vec<u8>> = match &record_clone.wrapped_dek {
                Some(wd) => Some(postcard::to_allocvec(wd).map_err(|e| {
                    ZeroVaultError::MetadataError(format!("failed to encode wrapped_dek: {e}"))
                })?),
                None => None,
            };
            let next_floor = inode_i64.saturating_add(1).max(2);

            tx.execute(
                "INSERT INTO inodes (
                    inode, parent_inode, file_id, name, virtual_path, kind,
                    size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(inode) DO UPDATE SET
                    parent_inode = excluded.parent_inode,
                    file_id = excluded.file_id,
                    name = excluded.name,
                    virtual_path = excluded.virtual_path,
                    kind = excluded.kind,
                    size = excluded.size,
                    mode = excluded.mode,
                    hydration = excluded.hydration,
                    pinned = excluded.pinned,
                    version = excluded.version,
                    wrapped_dek = excluded.wrapped_dek,
                    modified_at = excluded.modified_at,
                    created_at = excluded.created_at",
                params![
                    inode_i64,
                    parent_i64,
                    record_clone.file_id.to_string(),
                    record_clone.name,
                    record_clone.virtual_path,
                    entry_kind_to_str(record_clone.kind),
                    size_i64,
                    mode_i64,
                    record_clone.hydration.as_xattr_str(),
                    i64::from(record_clone.pinned),
                    version_i64,
                    wrapped_bytes,
                    record_clone.modified_at.to_rfc3339(),
                    record_clone.created_at.to_rfc3339(),
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
        self.run_blocking(move |conn| {
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
        self.run_blocking(move |conn| {
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
        self.run_blocking(move |conn| {
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
                            ciphertext_len, blake3_plaintext, backend_ids, locally_hydrated
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
        self.run_blocking(move |conn| {
            let inode_i64 = to_i64(inode)?;
            let mut stmt = conn
                .prepare(
                    "SELECT inode, file_id, chunk_index, blob_id, plaintext_len,
                            ciphertext_len, blake3_plaintext, backend_ids, locally_hydrated
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
        self.run_blocking(move |conn| {
            let tx = conn.transaction().map_err(sqlite_err)?;
            let inode_i64 = to_i64(inode)?;
            let chunk_i64 = to_i64(chunk_index)?;

            let row: Option<(i64, String)> = tx
                .query_row(
                    "SELECT pinned, hydration FROM inodes WHERE inode = ?1",
                    params![inode_i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(sqlite_err)?;

            let Some((pinned_i64, hydration_str)) = row else {
                return Err(ZeroVaultError::InodeNotFound(inode));
            };
            let pinned = pinned_i64 != 0;
            let current_hydration = str_to_hydration(&hydration_str)?;

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
                    params![next_hydration.as_xattr_str(), inode_i64],
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
        self.run_blocking(move |conn| {
            let inode_i64 = to_i64(inode)?;
            let updated = conn
                .execute(
                    "UPDATE inodes SET hydration = ?1, pinned = ?2 WHERE inode = ?3",
                    params![hydration.as_xattr_str(), i64::from(pinned), inode_i64],
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
        self.run_blocking(move |conn| {
            let inode_i64 = to_i64(inode)?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO dirty_ops (inode, kind, virtual_path, retry_count, last_error, queued_at)
                 VALUES (?1, ?2, ?3, 0, NULL, ?4)",
                params![inode_i64, dirty_kind_to_str(kind), vpath, now],
            )
            .map_err(sqlite_err)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    async fn list_dirty_ops(&self) -> ZeroVaultResult<Vec<DirtyOp>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, inode, kind, virtual_path, retry_count, last_error, queued_at
                     FROM dirty_ops
                     ORDER BY id ASC",
                )
                .map_err(sqlite_err)?;
            let rows = stmt.query_map([], row_to_dirty_op).map_err(sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_err)
        })
        .await
    }

    async fn complete_dirty_op(&self, id: i64) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn| {
            conn.execute("DELETE FROM dirty_ops WHERE id = ?1", params![id])
                .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn mark_dirty_retry(&self, id: i64, error: &str) -> ZeroVaultResult<()> {
        let err_msg = error.to_owned();
        self.run_blocking(move |conn| {
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
        self.run_blocking(move |conn| {
            let (rev, etag): (i64, Option<String>) = conn
                .query_row(
                    "SELECT revision, remote_etag FROM manifest_cursor WHERE id = 1",
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
        self.run_blocking(move |conn| {
            let rev_i64 = to_i64(revision)?;
            conn.execute(
                "UPDATE manifest_cursor SET revision = ?1, remote_etag = ?2 WHERE id = 1",
                params![rev_i64, remote_etag],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_all_inodes(&self) -> ZeroVaultResult<Vec<InodeRecord>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT inode, parent_inode, file_id, name, virtual_path, kind,
                            size, mode, hydration, pinned, version, wrapped_dek, modified_at, created_at
                     FROM inodes
                     ORDER BY inode ASC",
                )
                .map_err(sqlite_err)?;
            let rows = stmt.query_map([], row_to_inode).map_err(sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_err)
        })
        .await
    }

    async fn record_conflict(&self, conflict: ConflictRecord) -> ZeroVaultResult<()> {
        self.run_blocking(move |conn| {
            let rev_i64 = to_i64(conflict.remote_revision)?;
            conn.execute(
                "INSERT INTO conflicts (original_path, conflict_path, remote_revision, detected_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    conflict.original_path,
                    conflict.conflict_path,
                    rev_i64,
                    conflict.detected_at.to_rfc3339(),
                ],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_conflicts(&self) -> ZeroVaultResult<Vec<ConflictRecord>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT original_path, conflict_path, remote_revision, detected_at
                     FROM conflicts
                     ORDER BY id ASC",
                )
                .map_err(sqlite_err)?;
            let rows = stmt.query_map([], row_to_conflict).map_err(sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_err)
        })
        .await
    }
}

fn sqlite_err(err: rusqlite::Error) -> ZeroVaultError {
    ZeroVaultError::MetadataError(err.to_string())
}

fn sqlite_upsert_err(err: rusqlite::Error) -> ZeroVaultError {
    if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err
        && ffi_err.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return ZeroVaultError::AlreadyExists("inode path constraint violation".into());
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

fn entry_kind_to_str(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
    }
}

fn str_to_entry_kind(raw: &str) -> rusqlite::Result<EntryKind> {
    match raw {
        "file" => Ok(EntryKind::File),
        "directory" => Ok(EntryKind::Directory),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("invalid entry kind: {other}").into(),
        )),
    }
}

fn str_to_hydration(raw: &str) -> ZeroVaultResult<HydrationState> {
    match raw {
        "online-only" => Ok(HydrationState::OnlineOnly),
        "partially-hydrated" => Ok(HydrationState::PartiallyHydrated),
        "cached" => Ok(HydrationState::LocallyCached),
        "pinned" => Ok(HydrationState::Pinned),
        "dirty" => Ok(HydrationState::DirtyLocal),
        other => Err(ZeroVaultError::MetadataError(format!(
            "invalid hydration state: {other}"
        ))),
    }
}

fn dirty_kind_to_str(kind: DirtyOpKind) -> &'static str {
    match kind {
        DirtyOpKind::UpsertFile => "upsert_file",
        DirtyOpKind::UpsertMetadata => "upsert_metadata",
        DirtyOpKind::Delete => "delete",
    }
}

fn str_to_dirty_kind(raw: &str) -> rusqlite::Result<DirtyOpKind> {
    match raw {
        "upsert_file" => Ok(DirtyOpKind::UpsertFile),
        "upsert_metadata" => Ok(DirtyOpKind::UpsertMetadata),
        "delete" => Ok(DirtyOpKind::Delete),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("invalid dirty op kind: {other}").into(),
        )),
    }
}

fn parse_uuid(raw: &str, col: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_datetime(raw: &str, col: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
        })
}

fn row_to_inode(row: &Row<'_>) -> rusqlite::Result<InodeRecord> {
    let inode_i64: i64 = row.get(0)?;
    let parent_i64: i64 = row.get(1)?;
    let file_id_str: String = row.get(2)?;
    let name: String = row.get(3)?;
    let virtual_path: String = row.get(4)?;
    let kind_str: String = row.get(5)?;
    let size_i64: i64 = row.get(6)?;
    let mode_i64: i64 = row.get(7)?;
    let hydration_str: String = row.get(8)?;
    let pinned_i64: i64 = row.get(9)?;
    let version_i64: i64 = row.get(10)?;
    let wrapped_blob: Option<Vec<u8>> = row.get(11)?;
    let modified_str: String = row.get(12)?;
    let created_str: String = row.get(13)?;

    let wrapped_dek = match wrapped_blob {
        Some(bytes) => {
            let dek: WrappedDek = postcard::from_bytes(&bytes).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })?;
            Some(dek)
        }
        None => None,
    };

    let hydration = str_to_hydration(&hydration_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(InodeRecord {
        inode: u64::try_from(inode_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        parent_inode: u64::try_from(parent_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        file_id: parse_uuid(&file_id_str, 2)?,
        name,
        virtual_path,
        kind: str_to_entry_kind(&kind_str)?,
        size: u64::try_from(size_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        mode: u32::try_from(mode_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        hydration,
        pinned: pinned_i64 != 0,
        version: u64::try_from(version_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Integer,
                Box::new(e),
            )
        })?,
        wrapped_dek,
        modified_at: parse_datetime(&modified_str, 12)?,
        created_at: parse_datetime(&created_str, 13)?,
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

fn row_to_dirty_op(row: &Row<'_>) -> rusqlite::Result<DirtyOp> {
    let id: i64 = row.get(0)?;
    let inode_i64: i64 = row.get(1)?;
    let kind_str: String = row.get(2)?;
    let virtual_path: String = row.get(3)?;
    let retry_i64: i64 = row.get(4)?;
    let last_error: Option<String> = row.get(5)?;
    let queued_str: String = row.get(6)?;

    Ok(DirtyOp {
        id,
        inode: u64::try_from(inode_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        kind: str_to_dirty_kind(&kind_str)?,
        virtual_path,
        retry_count: u32::try_from(retry_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        last_error,
        queued_at: parse_datetime(&queued_str, 6)?,
    })
}

fn row_to_conflict(row: &Row<'_>) -> rusqlite::Result<ConflictRecord> {
    let original_path: String = row.get(0)?;
    let conflict_path: String = row.get(1)?;
    let rev_i64: i64 = row.get(2)?;
    let detected_str: String = row.get(3)?;

    Ok(ConflictRecord {
        original_path,
        conflict_path,
        remote_revision: u64::try_from(rev_i64).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Integer, Box::new(e))
        })?,
        detected_at: parse_datetime(&detected_str, 3)?,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn file_backed_sqlite_enables_wal_and_persists_across_reopen() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("nested").join("zerovault.db");

        let file_id = Uuid::new_v4();
        let blob_id = Uuid::new_v4();
        let inode_id;

        {
            let store = SqliteMetadataStore::open(&db_path).expect("open sqlite");
            assert_eq!(store.journal_mode().expect("journal_mode").to_lowercase(), "wal");

            let root = store
                .get_inode(ROOT_INODE)
                .await
                .expect("get root")
                .expect("root seeded");
            assert_eq!(root.virtual_path, "/");
            assert_eq!(root.kind, EntryKind::Directory);

            inode_id = store.allocate_inode_id().await.expect("alloc inode");
            assert!(inode_id >= 2);
            let now = Utc::now();
            let rec = InodeRecord {
                inode: inode_id,
                parent_inode: ROOT_INODE,
                file_id,
                name: "secret.bin".to_owned(),
                virtual_path: "/secret.bin".to_owned(),
                kind: EntryKind::File,
                size: 4096,
                mode: 0o644,
                hydration: HydrationState::OnlineOnly,
                pinned: false,
                version: 1,
                wrapped_dek: Some(WrappedDek {
                    nonce: [7u8; 12],
                    ciphertext_and_tag: vec![9u8; 48],
                }),
                modified_at: now,
                created_at: now,
            };
            store.upsert_inode(rec).await.expect("upsert");

            store
                .replace_chunks(
                    inode_id,
                    vec![ChunkDescriptor {
                        inode: inode_id,
                        file_id,
                        chunk_index: 0,
                        blob_id,
                        plaintext_len: 4096,
                        ciphertext_len: 4144,
                        blake3_plaintext: [0xAB; 32],
                        backend_ids: vec!["s3-main".to_owned()],
                        locally_hydrated: false,
                    }],
                )
                .await
                .expect("replace chunks");

            store
                .set_chunk_hydrated(inode_id, 0, true)
                .await
                .expect("mark hydrated");
            store
                .update_manifest_cursor(5, Some("etag-5".to_owned()))
                .await
                .expect("cursor");
        }

        // Reopen from disk and verify WAL + full state persistence.
        let reopened = SqliteMetadataStore::open(&db_path).expect("reopen sqlite");
        assert_eq!(
            reopened.journal_mode().expect("journal_mode").to_lowercase(),
            "wal"
        );
        let rec = reopened
            .get_by_path("/secret.bin")
            .await
            .expect("get by path")
            .expect("persisted inode");
        assert_eq!(rec.inode, inode_id);
        assert_eq!(rec.hydration, HydrationState::LocallyCached);
        assert!(rec.wrapped_dek.is_some());

        let chunks = reopened.list_chunks(inode_id).await.expect("chunks");
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].locally_hydrated);
        assert_eq!(chunks[0].blob_id, blob_id);

        assert_eq!(
            reopened.manifest_cursor().await.expect("cursor"),
            (5, Some("etag-5".to_owned()))
        );

        // Deleting inode cascades chunk rows cleanly.
        reopened.delete_inode(inode_id).await.expect("delete");
        assert!(reopened.list_chunks(inode_id).await.expect("empty").is_empty());
        assert!(reopened.allocate_inode_id().await.expect("next") > inode_id);
    }

    #[tokio::test]
    async fn dirty_ops_and_conflicts_roundtrip() {
        let store = SqliteMetadataStore::open_in_memory().expect("in-memory");
        let id = store
            .enqueue_dirty(2, DirtyOpKind::UpsertFile, "/a.txt")
            .await
            .expect("enqueue");
        store
            .mark_dirty_retry(id, "network timeout")
            .await
            .expect("retry");
        let ops = store.list_dirty_ops().await.expect("list ops");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].retry_count, 1);
        assert_eq!(ops[0].last_error.as_deref(), Some("network timeout"));
        store.complete_dirty_op(id).await.expect("complete");
        assert!(store.list_dirty_ops().await.expect("empty").is_empty());

        store
            .record_conflict(ConflictRecord {
                original_path: "/report.pdf".to_owned(),
                conflict_path: "/report (conflict-host-20261117-120000).pdf".to_owned(),
                remote_revision: 7,
                detected_at: Utc::now(),
            })
            .await
            .expect("conflict");
        assert_eq!(store.list_conflicts().await.expect("list").len(), 1);
    }
}
