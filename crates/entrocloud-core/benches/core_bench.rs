//! Criterion micro-benchmarks for `entrocloud-core` zero-knowledge metadata, `.zvpart` staging,
//! full-capacity zeroizing buffer pool, and 4 MiB streaming `SyncEngine` I/O.

use std::sync::Arc;

use bytes::BytesMut;
use chrono::Utc;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use uuid::Uuid;
use entrocloud_core::{
    BoundedBufferPool, ChunkCache, DEFAULT_MAX_RAM_CACHE_BYTES, SqliteMetadataStore, SyncEngine,
    SyncEngineConfig,
};
use entrocloud_types::mocks::{MockCryptoEngine, MockStorageRouter};
use entrocloud_types::{
    CreateEntrySpec, EntryKind, HydrationState, InodeRecord, MetadataStore, PLAINTEXT_CHUNK_SIZE,
    ROOT_INODE, VfsBackend,
};

fn bench_sqlite_blind_index_lookup(c: &mut Criterion) {
    let Ok(rt) = Runtime::new() else {
        return;
    };
    let crypto = Arc::new(MockCryptoEngine::default());
    let Ok(store) = SqliteMetadataStore::open_in_memory(crypto) else {
        return;
    };

    rt.block_on(async {
        let now = Utc::now();
        for idx in 0..64u64 {
            let name = format!("bench-entry-{idx:04}.dat");
            let vpath = format!("/{name}");
            let _ = store
                .upsert_inode(InodeRecord {
                    inode: idx + 2,
                    parent_inode: ROOT_INODE,
                    file_id: Uuid::new_v4(),
                    name,
                    virtual_path: vpath,
                    kind: EntryKind::File,
                    size: 4096,
                    mode: 0o644,
                    hydration: HydrationState::OnlineOnly,
                    pinned: false,
                    version: 1,
                    wrapped_dek: None,
                    modified_at: now,
                    created_at: now,
                })
                .await;
        }
    });

    c.bench_function("sqlite_blind_index_get_by_path", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.get_by_path("/bench-entry-0042.dat").await;
            });
        });
    });
}

fn bench_pool_full_capacity_zeroize(c: &mut Criterion) {
    let Ok(rt) = Runtime::new() else {
        return;
    };
    let mut group = c.benchmark_group("buffer_pool_zeroize");
    for &cap in &[64 * 1024usize, PLAINTEXT_CHUNK_SIZE] {
        group.throughput(Throughput::Bytes(cap as u64));
        let pool = BoundedBufferPool::with_buffer_capacity(4, cap);
        group.bench_with_input(BenchmarkId::from_parameter(cap), &cap, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    if let Ok(mut buf) = pool.acquire_buffer().await {
                        buf.extend_from_slice(&[0x5Au8; 64]);
                        drop(buf);
                    }
                });
            });
        });
    }
    group.finish();
}

fn bench_zvpart_staging_roundtrip(c: &mut Criterion) {
    let Ok(rt) = Runtime::new() else {
        return;
    };
    let Ok(dir) = TempDir::new() else {
        return;
    };
    let crypto = Arc::new(MockCryptoEngine::default());
    let Ok(cache) = ChunkCache::new(DEFAULT_MAX_RAM_CACHE_BYTES, dir.path(), crypto) else {
        return;
    };
    let payload = vec![0xA7u8; 256 * 1024];

    let mut group = c.benchmark_group("zvpart_encrypted_staging_256kib");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("seal_and_open_zvpart", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = cache.write_full_dirty_chunk(9, 0, &payload).await;
                let mut out = BytesMut::with_capacity(payload.len());
                let _ = cache.read_dirty_chunk_into(9, 0, &mut out).await;
            });
        });
    });
    group.finish();
}

fn bench_sync_engine_o1_seek(c: &mut Criterion) {
    let Ok(rt) = Runtime::new() else {
        return;
    };
    let Ok(dir) = TempDir::new() else {
        return;
    };
    let crypto = Arc::new(MockCryptoEngine::default());
    let storage = Arc::new(MockStorageRouter::default());
    let Ok(meta) = SqliteMetadataStore::open_in_memory(crypto.clone()) else {
        return;
    };
    let cfg = SyncEngineConfig {
        staging_dir: dir.path().join("stage"),
        device_id: "bench-dev".to_owned(),
        max_ram_cache_bytes: DEFAULT_MAX_RAM_CACHE_BYTES,
        max_concurrent_transfers: 4,
    };
    let Ok(engine) = SyncEngine::new(cfg, Arc::new(meta), crypto, storage) else {
        return;
    };

    let inode = rt.block_on(async {
        let Ok(rec) = engine
            .create_entry(CreateEntrySpec {
                parent_inode: ROOT_INODE,
                name: "stream.bin".to_owned(),
                mode: 0o644,
            })
            .await
        else {
            return 0;
        };
        let chunk_data = vec![0x3Cu8; PLAINTEXT_CHUNK_SIZE];
        let _ = engine.write_range(rec.inode, 0, &chunk_data).await;
        let _ = engine.flush(rec.inode).await;
        rec.inode
    });
    if inode == 0 {
        return;
    }

    let mut group = c.benchmark_group("sync_engine_cached_read_range");
    group.throughput(Throughput::Bytes(65_536));
    group.bench_function("read_64kib_slice", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine.read_range(inode, 1024 * 1024, 65_536).await;
            });
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_sqlite_blind_index_lookup,
    bench_pool_full_capacity_zeroize,
    bench_zvpart_staging_roundtrip,
    bench_sync_engine_o1_seek
);
criterion_main!(benches);
