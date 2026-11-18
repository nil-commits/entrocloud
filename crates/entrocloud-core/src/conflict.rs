//! Deterministic non-destructive conflict formatting and manifest reconciliation.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use uuid::Uuid;
use entrocloud_types::{
    BlobObjectKey, ChunkDescriptor, ConflictRecord, CryptoEngine, DirtyOpKind, EntryKind,
    HydrationState, InodeId, InodeRecord, ManifestNode, MetadataStore, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, StorageRouterTrait, VaultManifest, ZeroVaultResult,
};

use crate::cache::ChunkCache;
use crate::engine::fetch_and_decrypt_chunk;
use crate::pool::BoundedBufferPool;

/// Summary produced by reconciling a remote [`VaultManifest`] into local SQLite metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Number of remote nodes inserted or updated locally.
    pub applied_remote_nodes: usize,
    /// Number of clean local entries pruned because they were deleted remotely.
    pub pruned_local_nodes: usize,
    /// Number of dirty-vs-remote conflicts resolved by preserving both copies.
    pub conflicts_recorded: usize,
}

/// Sanitizes `device_id` so only ASCII `[A-Za-z0-9_-]` characters appear in conflict filenames.
#[must_use]
pub fn sanitize_device_id(device_id: &str) -> String {
    let mut out = String::with_capacity(device_id.len());
    for ch in device_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    while out.ends_with('-') && !device_id.ends_with('-') {
        out.pop();
    }
    if out.is_empty() || out.chars().all(|c| c == '-') {
        "device".to_owned()
    } else {
        out
    }
}

/// Formats a deterministic conflict copy filename preserving extensions cleanly:
/// - `"report.pdf"` -> `"report (conflict-<device>-<YYYYMMDD-HHMMSS>).pdf"`
/// - `"Makefile"` -> `"Makefile (conflict-<device>-<YYYYMMDD-HHMMSS>)"`
/// - `".env"` -> `".env (conflict-<device>-<YYYYMMDD-HHMMSS>)"`
#[must_use]
pub fn format_conflict_filename(
    original_name: &str,
    device_id: &str,
    timestamp: DateTime<Utc>,
) -> String {
    let dev = sanitize_device_id(device_id);
    let ts = timestamp.format("%Y%m%d-%H%M%S");
    let tag = format!("conflict-{dev}-{ts}");

    match original_name.rfind('.') {
        // Leading dotfiles (`.env`, `.gitignore`) and trailing-dot names (`foo.`) do not split.
        Some(dot_idx) if dot_idx > 0 && dot_idx < original_name.len() - 1 => {
            let stem = &original_name[..dot_idx];
            let ext = &original_name[dot_idx + 1..];
            format!("{stem} ({tag}).{ext}")
        }
        _ => format!("{original_name} ({tag})"),
    }
}

fn format_disambiguated_conflict_filename(
    original_name: &str,
    device_id: &str,
    timestamp: DateTime<Utc>,
    suffix_num: usize,
) -> String {
    let base = format_conflict_filename(original_name, device_id, timestamp);
    if suffix_num <= 1 {
        return base;
    }
    match base.rfind('.') {
        Some(dot_idx) if dot_idx > 0 && dot_idx < base.len() - 1 => {
            let prefix = &base[..dot_idx];
            let ext = &base[dot_idx + 1..];
            format!("{prefix}-{suffix_num}.{ext}")
        }
        _ => format!("{base}-{suffix_num}"),
    }
}

pub(crate) fn join_virtual_path(parent_path: &str, name: &str) -> String {
    if parent_path == "/" {
        format!("/{name}")
    } else {
        format!("{parent_path}/{name}")
    }
}

fn manifest_chunks_to_descriptors(
    local_inode: InodeId,
    file_id: Uuid,
    node: &ManifestNode,
) -> Vec<ChunkDescriptor> {
    node.chunks
        .iter()
        .map(|c| ChunkDescriptor {
            inode: local_inode,
            file_id,
            chunk_index: c.chunk_index,
            blob_id: c.blob_id,
            plaintext_len: c.plaintext_len,
            ciphertext_len: c.ciphertext_len,
            blake3_plaintext: c.blake3_plaintext,
            backend_ids: c.backend_ids.clone(),
            locally_hydrated: false,
        })
        .collect()
}

fn chunks_match_node(local_chunks: &[ChunkDescriptor], remote_node: &ManifestNode) -> bool {
    if local_chunks.len() != remote_node.chunks.len() {
        return false;
    }
    local_chunks
        .iter()
        .zip(remote_node.chunks.iter())
        .all(|(l, r)| {
            l.chunk_index == r.chunk_index
                && l.blob_id == r.blob_id
                && l.plaintext_len == r.plaintext_len
                && l.ciphertext_len == r.ciphertext_len
                && l.blake3_plaintext == r.blake3_plaintext
        })
}

/// Deterministic conflict resolver reconciling remote [`VaultManifest`] snapshots
/// against local zero-knowledge SQLite WAL metadata and encrypted `.zvpart` dirty staging state.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConflictResolver;

impl ConflictResolver {
    /// Reconciles `remote_manifest` into `meta`, preserving any conflicting local dirty files
    /// under deterministic conflict filenames with fresh `file_id`s and queued dirty uploads.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_remote_manifest(
        meta: &dyn MetadataStore,
        crypto: &dyn CryptoEngine,
        storage: &dyn StorageRouterTrait,
        pool: &BoundedBufferPool,
        cache: &ChunkCache,
        device_id: &str,
        remote_manifest: &VaultManifest,
        now: DateTime<Utc>,
    ) -> ZeroVaultResult<ReconcileSummary> {
        let mut summary = ReconcileSummary::default();

        // Build remote parent -> children adjacency list (excluding ROOT_INODE itself).
        let mut children_by_parent: HashMap<u64, Vec<&ManifestNode>> = HashMap::new();
        for node in &remote_manifest.nodes {
            if node.inode == ROOT_INODE {
                continue;
            }
            children_by_parent
                .entry(node.parent_inode)
                .or_default()
                .push(node);
        }
        for children in children_by_parent.values_mut() {
            children.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.inode.cmp(&b.inode)));
        }

        // BFS from ROOT_INODE to produce topologically ordered `(node, virtual_path)`.
        let mut ordered_remote: Vec<(&ManifestNode, String)> =
            Vec::with_capacity(remote_manifest.nodes.len());
        let mut remote_paths: HashSet<String> = HashSet::new();
        remote_paths.insert("/".to_owned());

        let mut queue: VecDeque<(u64, String)> = VecDeque::new();
        queue.push_back((ROOT_INODE, "/".to_owned()));
        let mut visited_remote_inodes: HashSet<u64> = HashSet::new();
        visited_remote_inodes.insert(ROOT_INODE);

        while let Some((parent_remote_ino, parent_vpath)) = queue.pop_front() {
            if let Some(children) = children_by_parent.get(&parent_remote_ino) {
                for &child in children {
                    if !visited_remote_inodes.insert(child.inode) {
                        continue;
                    }
                    let vpath = join_virtual_path(&parent_vpath, &child.name);
                    remote_paths.insert(vpath.clone());
                    ordered_remote.push((child, vpath.clone()));
                    if child.kind == EntryKind::Directory {
                        queue.push_back((child.inode, vpath));
                    }
                }
            }
        }

        // Snapshot current dirty ops and local inodes before applying remote changes.
        let initial_dirty_ops = meta.list_dirty_ops().await?;
        let mut dirty_inodes: HashSet<InodeId> = HashSet::new();
        let mut dirty_upsert_paths: HashSet<String> = HashSet::new();
        let mut dirty_ops_by_inode: HashMap<InodeId, Vec<i64>> = HashMap::new();
        for op in &initial_dirty_ops {
            dirty_ops_by_inode.entry(op.inode).or_default().push(op.id);
            if matches!(op.kind, DirtyOpKind::UpsertFile | DirtyOpKind::UpsertMetadata) {
                dirty_inodes.insert(op.inode);
                dirty_upsert_paths.insert(op.virtual_path.clone());
            }
        }

        let initial_inodes = meta.list_all_inodes().await?;
        let mut local_by_file_id: HashMap<Uuid, InodeRecord> = HashMap::new();
        for rec in &initial_inodes {
            if rec.inode != ROOT_INODE {
                local_by_file_id.insert(rec.file_id, rec.clone());
            }
        }

        let mut remote_to_local_inode: HashMap<u64, InodeId> = HashMap::new();
        remote_to_local_inode.insert(ROOT_INODE, ROOT_INODE);

        for (remote_node, vpath) in ordered_remote {
            let local_parent_inode = remote_to_local_inode
                .get(&remote_node.parent_inode)
                .copied()
                .unwrap_or(ROOT_INODE);

            let existing_local = meta.get_by_path(&vpath).await?;
            let local_is_dirty = existing_local.as_ref().is_some_and(|loc| {
                loc.hydration == HydrationState::DirtyLocal
                    || dirty_inodes.contains(&loc.inode)
                    || dirty_upsert_paths.contains(&vpath)
            });

            match existing_local {
                Some(local)
                    if local.kind == EntryKind::Directory
                        && remote_node.kind == EntryKind::Directory =>
                {
                    remote_to_local_inode.insert(remote_node.inode, local.inode);
                    if !local_is_dirty && local.version != remote_node.version {
                        let mut updated = local.clone();
                        updated.mode = remote_node.mode;
                        updated.modified_at = remote_node.modified_at;
                        updated.version = remote_node.version;
                        meta.upsert_inode(updated).await?;
                        summary.applied_remote_nodes += 1;
                    }
                }
                Some(mut local) if local_is_dirty => {
                    // CONFLICT: Preserve local dirty copy under deterministic conflict filename
                    // with a fresh file_id + queued dirty upload, then apply remote node at original path.
                    if local.kind == EntryKind::File {
                        materialize_missing_dirty_chunks(
                            meta, crypto, storage, pool, cache, &local,
                        )
                        .await?;
                    }

                    let parent_vpath = match meta.get_inode(local.parent_inode).await? {
                        Some(p) => p.virtual_path,
                        None => "/".to_owned(),
                    };

                    let mut suffix_num = 1usize;
                    let (conflict_name, conflict_vpath) = loop {
                        let cand_name = format_disambiguated_conflict_filename(
                            &local.name,
                            device_id,
                            now,
                            suffix_num,
                        );
                        let cand_vpath = join_virtual_path(&parent_vpath, &cand_name);
                        let exists_locally = meta.get_by_path(&cand_vpath).await?.is_some();
                        if !exists_locally && !remote_paths.contains(&cand_vpath) {
                            break (cand_name, cand_vpath);
                        }
                        suffix_num += 1;
                    };

                    let old_file_id = local.file_id;
                    let fresh_file_id = Uuid::new_v4();
                    cache.invalidate_file(old_file_id);

                    local.name = conflict_name;
                    local.virtual_path = conflict_vpath.clone();
                    local.file_id = fresh_file_id;
                    local.wrapped_dek = None;
                    local.hydration = HydrationState::DirtyLocal;
                    local.modified_at = now;
                    local.version = local.version.saturating_add(1);

                    meta.replace_chunks(local.inode, Vec::new()).await?;
                    meta.upsert_inode(local.clone()).await?;

                    if let Some(old_op_ids) = dirty_ops_by_inode.remove(&local.inode) {
                        for old_id in old_op_ids {
                            meta.complete_dirty_op(old_id).await?;
                        }
                    }
                    let op_kind = if local.kind == EntryKind::Directory {
                        DirtyOpKind::UpsertMetadata
                    } else {
                        DirtyOpKind::UpsertFile
                    };
                    meta.enqueue_dirty(local.inode, op_kind, &conflict_vpath)
                        .await?;

                    if local.kind == EntryKind::Directory {
                        rebase_descendant_paths(meta, local.inode, &vpath, &conflict_vpath).await?;
                    }

                    let remote_local_inode = meta.allocate_inode_id().await?;
                    let remote_rec = build_remote_inode_record(
                        remote_local_inode,
                        local_parent_inode,
                        &vpath,
                        remote_node,
                        false,
                    );
                    meta.upsert_inode(remote_rec).await?;
                    if remote_node.kind == EntryKind::File {
                        let descriptors = manifest_chunks_to_descriptors(
                            remote_local_inode,
                            remote_node.file_id,
                            remote_node,
                        );
                        meta.replace_chunks(remote_local_inode, descriptors).await?;
                    }
                    remote_to_local_inode.insert(remote_node.inode, remote_local_inode);

                    meta.record_conflict(ConflictRecord {
                        original_path: vpath,
                        conflict_path: conflict_vpath,
                        remote_revision: remote_manifest.revision,
                        detected_at: now,
                    })
                    .await?;

                    summary.conflicts_recorded += 1;
                    summary.applied_remote_nodes += 1;
                }
                Some(local) => {
                    remote_to_local_inode.insert(remote_node.inode, local.inode);
                    let local_chunks = if local.kind == EntryKind::File {
                        meta.list_chunks(local.inode).await?
                    } else {
                        Vec::new()
                    };
                    let changed = local.kind != remote_node.kind
                        || local.file_id != remote_node.file_id
                        || local.size != remote_node.size
                        || local.version != remote_node.version
                        || local.mode != remote_node.mode
                        || !chunks_match_node(&local_chunks, remote_node);

                    if changed {
                        cache.invalidate_file(local.file_id);
                        cache.invalidate_file(remote_node.file_id);

                        let updated = build_remote_inode_record(
                            local.inode,
                            local_parent_inode,
                            &vpath,
                            remote_node,
                            local.pinned,
                        );
                        meta.upsert_inode(updated).await?;
                        if remote_node.kind == EntryKind::File {
                            let descriptors = manifest_chunks_to_descriptors(
                                local.inode,
                                remote_node.file_id,
                                remote_node,
                            );
                            meta.replace_chunks(local.inode, descriptors).await?;
                        } else {
                            meta.replace_chunks(local.inode, Vec::new()).await?;
                        }
                        summary.applied_remote_nodes += 1;
                    }
                }
                None => {
                    let moved_clean_local = local_by_file_id.get(&remote_node.file_id).filter(|r| {
                        r.hydration != HydrationState::DirtyLocal
                            && !dirty_inodes.contains(&r.inode)
                    });

                    let local_inode = if let Some(prev) = moved_clean_local {
                        cache.invalidate_file(prev.file_id);
                        let updated = build_remote_inode_record(
                            prev.inode,
                            local_parent_inode,
                            &vpath,
                            remote_node,
                            prev.pinned,
                        );
                        meta.upsert_inode(updated).await?;
                        prev.inode
                    } else {
                        let new_ino = meta.allocate_inode_id().await?;
                        let rec = build_remote_inode_record(
                            new_ino,
                            local_parent_inode,
                            &vpath,
                            remote_node,
                            false,
                        );
                        meta.upsert_inode(rec).await?;
                        new_ino
                    };

                    if remote_node.kind == EntryKind::File {
                        let descriptors = manifest_chunks_to_descriptors(
                            local_inode,
                            remote_node.file_id,
                            remote_node,
                        );
                        meta.replace_chunks(local_inode, descriptors).await?;
                    }
                    remote_to_local_inode.insert(remote_node.inode, local_inode);
                    summary.applied_remote_nodes += 1;
                }
            }
        }

        // Prune clean local entries absent from the remote manifest, protecting dirty subtrees.
        let post_ops = meta.list_dirty_ops().await?;
        let mut protected_inodes: HashSet<InodeId> = post_ops.iter().map(|o| o.inode).collect();
        let all_local = meta.list_all_inodes().await?;
        let by_inode: HashMap<InodeId, InodeRecord> =
            all_local.iter().map(|r| (r.inode, r.clone())).collect();

        for rec in &all_local {
            if rec.hydration == HydrationState::DirtyLocal || protected_inodes.contains(&rec.inode)
            {
                let mut cur = Some(rec);
                while let Some(node) = cur {
                    protected_inodes.insert(node.inode);
                    if node.inode == ROOT_INODE || node.parent_inode == node.inode {
                        break;
                    }
                    cur = by_inode.get(&node.parent_inode);
                }
            }
        }

        let mut to_prune: Vec<InodeRecord> = all_local
            .into_iter()
            .filter(|rec| {
                rec.inode != ROOT_INODE
                    && !remote_paths.contains(&rec.virtual_path)
                    && !protected_inodes.contains(&rec.inode)
            })
            .collect();
        to_prune.sort_by(|a, b| {
            b.virtual_path
                .matches('/')
                .count()
                .cmp(&a.virtual_path.matches('/').count())
                .then_with(|| b.virtual_path.len().cmp(&a.virtual_path.len()))
        });

        for rec in to_prune {
            cache.invalidate_file(rec.file_id);
            meta.delete_inode(rec.inode).await?;
            summary.pruned_local_nodes += 1;
        }

        Ok(summary)
    }
}

fn build_remote_inode_record(
    local_inode: InodeId,
    local_parent_inode: InodeId,
    virtual_path: &str,
    node: &ManifestNode,
    preserve_pinned: bool,
) -> InodeRecord {
    let (hydration, pinned) = if node.kind == EntryKind::Directory || preserve_pinned {
        (HydrationState::Pinned, true)
    } else {
        (HydrationState::OnlineOnly, false)
    };

    InodeRecord {
        inode: local_inode,
        parent_inode: local_parent_inode,
        file_id: node.file_id,
        name: node.name.clone(),
        virtual_path: virtual_path.to_owned(),
        kind: node.kind,
        size: node.size,
        mode: node.mode,
        hydration,
        pinned,
        version: node.version,
        wrapped_dek: node.wrapped_dek.clone(),
        modified_at: node.modified_at,
        created_at: node.created_at,
    }
}

pub(crate) async fn rebase_descendant_paths(
    meta: &dyn MetadataStore,
    dir_inode: InodeId,
    old_prefix: &str,
    new_prefix: &str,
) -> ZeroVaultResult<()> {
    let mut queue = VecDeque::new();
    queue.push_back(dir_inode);
    while let Some(parent) = queue.pop_front() {
        let children = meta.list_children(parent).await?;
        for mut child in children {
            if let Some(suffix) = child.virtual_path.strip_prefix(old_prefix) {
                child.virtual_path = format!("{new_prefix}{suffix}");
                let child_ino = child.inode;
                let is_dir = child.kind == EntryKind::Directory;
                meta.upsert_inode(child).await?;
                if is_dir {
                    queue.push_back(child_ino);
                }
            }
        }
    }
    Ok(())
}

/// Ensures every chunk of a dirty local file is staged in `staging_dir/dirty/<inode>/<idx>.zvpart`
/// before its `file_id` is rotated for conflict preservation, using AEAD-verified mirror failover.
async fn materialize_missing_dirty_chunks(
    meta: &dyn MetadataStore,
    crypto: &dyn CryptoEngine,
    storage: &dyn StorageRouterTrait,
    pool: &BoundedBufferPool,
    cache: &ChunkCache,
    local: &InodeRecord,
) -> ZeroVaultResult<()> {
    if local.size == 0 {
        if !cache.has_dirty_chunk(local.inode, 0).await {
            cache.write_full_dirty_chunk(local.inode, 0, &[]).await?;
        }
        return Ok(());
    }

    let old_chunks = meta.list_chunks(local.inode).await?;
    if old_chunks.is_empty() {
        return Ok(());
    }
    let Some(ref wrapped_dek) = local.wrapped_dek else {
        return Ok(());
    };
    let dek = crypto.unwrap_dek(local.file_id, wrapped_dek)?;
    let num_chunks = local.size.div_ceil(PLAINTEXT_CHUNK_SIZE as u64);

    for desc in old_chunks {
        if desc.chunk_index >= num_chunks {
            continue;
        }
        if cache.has_dirty_chunk(local.inode, desc.chunk_index).await {
            continue;
        }
        if let Some(cached) = cache.get(local.file_id, desc.chunk_index) {
            cache
                .write_full_dirty_chunk(local.inode, desc.chunk_index, &cached)
                .await?;
            continue;
        }

        let blob_key = BlobObjectKey::from_uuid(desc.blob_id);
        let (pt_buf, _wire_len) = fetch_and_decrypt_chunk(
            storage,
            crypto,
            pool,
            &dek,
            local.file_id,
            desc.chunk_index,
            desc.plaintext_len,
            &desc.blake3_plaintext,
            blob_key.as_str(),
            &desc.backend_ids,
        )
        .await?;
        cache
            .write_full_dirty_chunk(local.inode, desc.chunk_index, pt_buf.as_slice())
            .await?;
    }
    Ok(())
}
