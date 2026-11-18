//! Property-based tests (`proptest`) for `entrocloud-core` invariants, tamper rejection,
//! monotonic epoch floors, conflict naming, and cross-chunk streaming equivalence.

use std::sync::Arc;

use bytes::BytesMut;
use chrono::Utc;
use proptest::prelude::*;
use tempfile::TempDir;
use tokio::runtime::Builder;
use uuid::Uuid;
use entrocloud_core::{
    ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES, SqliteMetadataStore, SyncEngine, SyncEngineConfig,
    format_conflict_filename, sanitize_device_id,
};
use entrocloud_types::mocks::{MockCryptoEngine, MockStorageRouter};
use entrocloud_types::{
    CreateEntrySpec, EntryKind, HydrationState, InodeRecord, MetadataStore, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, VfsBackend, ZeroVaultError, validate_portable_entry_name,
};

fn small_rt() -> tokio::runtime::Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("failed to build current_thread runtime: {e}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_sanitize_device_id_and_conflict_filename_are_portable(
        raw_device in ".*",
        stem in "[A-Za-z0-9_-]{1,24}",
        maybe_ext in proptest::option::of("[a-z0-9]{1,8}"),
    ) {
        let sanitized = sanitize_device_id(&raw_device);
        prop_assert!(!sanitized.is_empty());
        prop_assert!(
            sanitized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );

        let orig = match &maybe_ext {
            Some(ext) => format!("{stem}.{ext}"),
            None => stem,
        };
        let formatted = format_conflict_filename(&orig, &raw_device, Utc::now());
        prop_assert!(validate_portable_entry_name(&formatted, false).is_ok());
        if let Some(ext) = maybe_ext {
            let suffix = format!(".{ext}");
            prop_assert!(formatted.ends_with(&suffix));
        }
    }

    #[test]
    fn prop_zvpart_any_single_bit_tamper_fails_closed(
        payload in proptest::collection::vec(any::<u8>(), 0..8192),
        inode in 2u64..10_000,
        chunk_idx in 0u64..64,
        tamper_seed in any::<usize>(),
        bit_mask in 1u8..=255u8,
    ) {
        let rt = small_rt();
        rt.block_on(async {
            let dir = TempDir::new().expect("tempdir");
            let crypto = Arc::new(MockCryptoEngine::default());
            let cache = ChunkCache::new(DEFAULT_MAX_RAM_CACHE_BYTES, dir.path(), crypto)
                .expect("chunk cache");

            cache
                .write_full_dirty_chunk(inode, chunk_idx, &payload)
                .await
                .expect("write zvpart");

            let zvpart_path = cache.dirty_chunk_path(inode, chunk_idx);
            let mut raw = std::fs::read(&zvpart_path).expect("read raw zvpart");
            assert!(raw.len() >= 28);

            // Verify AAD binding: reading under wrong chunk_index or inode MUST fail closed!
            let mut out = BytesMut::new();
            let swapped_path = cache.dirty_chunk_path(inode, chunk_idx + 1);
            std::fs::write(&swapped_path, &raw).expect("write swapped zvpart");
            let swap_res = cache.read_dirty_chunk_into(inode, chunk_idx + 1, &mut out).await;
            assert!(matches!(swap_res, Err(ZeroVaultError::CryptoTamperDetected(_))));

            // Verify ciphertext + tag tamper rejection (`12..raw.len()` authenticated by MockCryptoEngine).
            let auth_span = raw.len() - 12;
            let pos = 12 + (tamper_seed % auth_span);
            raw[pos] ^= bit_mask;
            std::fs::write(&zvpart_path, &raw).expect("write tampered zvpart");

            let res = cache.read_dirty_chunk_into(inode, chunk_idx, &mut out).await;
            assert!(matches!(res, Err(ZeroVaultError::CryptoTamperDetected(_))));
        });
    }

    #[test]
    fn prop_sqlite_security_epochs_strictly_monotonic(
        candidates in proptest::collection::vec(0u64..500, 1..40),
    ) {
        let rt = small_rt();
        rt.block_on(async {
            let crypto = Arc::new(MockCryptoEngine::default());
            let store = SqliteMetadataStore::open_in_memory(crypto).expect("sqlite mem");
            let mut max_floor = 0u64;

            for cand in candidates {
                let res = store.advance_epoch_floor("keybox", cand).await;
                if cand < max_floor {
                    assert!(matches!(res, Err(ZeroVaultError::CryptoTamperDetected(_))));
                } else {
                    assert!(res.is_ok());
                    max_floor = cand;
                }
                let persisted = store.epoch_floor("keybox").await.expect("epoch_floor");
                assert_eq!(persisted, max_floor);
            }
        });
    }

    #[test]
    fn prop_sqlite_blind_index_lookup_roundtrip(
        names in proptest::collection::btree_set("[A-Za-z0-9._-]{2,24}", 1..20),
    ) {
        let rt = small_rt();
        rt.block_on(async {
            let crypto = Arc::new(MockCryptoEngine::default());
            let store = SqliteMetadataStore::open_in_memory(crypto).expect("sqlite mem");
            let now = Utc::now();

            for name in &names {
                if name == "." || name == ".." {
                    continue;
                }
                let ino = store.allocate_inode_id().await.expect("alloc");
                let vpath = format!("/{name}");
                store
                    .upsert_inode(InodeRecord {
                        inode: ino,
                        parent_inode: ROOT_INODE,
                        file_id: Uuid::new_v4(),
                        name: name.clone(),
                        virtual_path: vpath.clone(),
                        kind: EntryKind::File,
                        size: 128,
                        mode: 0o644,
                        hydration: HydrationState::OnlineOnly,
                        pinned: false,
                        version: 1,
                        wrapped_dek: None,
                        modified_at: now,
                        created_at: now,
                    })
                    .await
                    .expect("upsert");

                let by_child = store
                    .lookup_child(ROOT_INODE, name)
                    .await
                    .expect("lookup_child")
                    .expect("present");
                assert_eq!(&by_child.name, name);

                let by_path = store
                    .get_by_path(&vpath)
                    .await
                    .expect("get_by_path")
                    .expect("present");
                assert_eq!(by_path.inode, ino);
            }
        });
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_cross_chunk_write_flush_dehydrate_seek_matches_reference_model(
        ops in proptest::collection::vec(
            (0usize..(PLAINTEXT_CHUNK_SIZE + 128 * 1024), proptest::collection::vec(any::<u8>(), 1..16_384)),
            1..8
        ),
        reads in proptest::collection::vec(
            (0u64..((PLAINTEXT_CHUNK_SIZE + 256 * 1024) as u64), 0usize..32_768),
            1..10
        ),
    ) {
        let rt = small_rt();
        rt.block_on(async {
            let dir = TempDir::new().expect("tempdir");
            let crypto = Arc::new(MockCryptoEngine::default());
            let storage = Arc::new(MockStorageRouter::default());
            let meta = Arc::new(SqliteMetadataStore::open_in_memory(crypto.clone()).expect("meta"));
            let engine = SyncEngine::new(
                SyncEngineConfig {
                    staging_dir: dir.path().join("stage"),
                    device_id: "prop-dev".to_owned(),
                    max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
                    max_concurrent_transfers: 4,
                },
                meta,
                crypto,
                storage,
            )
            .expect("engine");

            let rec = engine
                .create_entry(CreateEntrySpec {
                    parent_inode: ROOT_INODE,
                    name: "model.bin".to_owned(),
                    mode: 0o644,
                })
                .await
                .expect("create");

            let mut model: Vec<u8> = Vec::new();
            for (off, data) in ops {
                let end = off + data.len();
                if model.len() < end {
                    model.resize(end, 0u8);
                }
                model[off..end].copy_from_slice(&data);
                engine
                    .write_range(rec.inode, off as u64, &data)
                    .await
                    .expect("write_range");
            }

            engine.flush(rec.inode).await.expect("flush");
            engine.dehydrate(rec.inode).await.expect("dehydrate");

            for (r_off, r_len) in reads {
                let actual = engine
                    .read_range(rec.inode, r_off, r_len)
                    .await
                    .expect("read_range");
                let expected: &[u8] = if r_len == 0 || (r_off as usize) >= model.len() {
                    &[]
                } else {
                    let start = r_off as usize;
                    let end = (start + r_len).min(model.len());
                    &model[start..end]
                };
                assert_eq!(actual.as_ref(), expected);
            }
        });
    }
}
