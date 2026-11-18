//! Criterion micro-benchmarks for `entrocloud-storage` multi-cloud routing, bounded streaming I/O,
//! byte-range reads, verified RAID-1 failover, and SplitMix64 chaos overhead.

use std::sync::Arc;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use uuid::Uuid;

use entrocloud_storage::{
    ChaosStorageRouter, CloudBackend, StorageRouter, max_wire_bytes_for_object_key,
};
use entrocloud_types::{
    BackendConfig, BackendKind, BlobObjectKey, PLAINTEXT_CHUNK_SIZE, RoutingPolicy,
    StorageRouterTrait, validate_remote_object_key,
};

fn mem_cfg(id: &str) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::Memory,
        root: "/".to_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes: None,
        min_free_reserve_bytes: 0,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

fn bench_object_key_validation(c: &mut Criterion) {
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());
    let key_str = key.as_str().to_owned();

    c.bench_function("validate_and_cap_remote_object_key", |b| {
        b.iter(|| {
            validate_remote_object_key(black_box(&key_str)).expect("valid");
            black_box(max_wire_bytes_for_object_key(black_box(&key_str)).expect("cap"))
        });
    });
}

fn bench_memory_streaming_and_range(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let backend = Arc::new(CloudBackend::from_config(&mem_cfg("mem-bench")).expect("mem backend"));
    let chunk_4mib = Bytes::from(vec![0x5Au8; PLAINTEXT_CHUNK_SIZE]);
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());

    rt.block_on(async {
        backend
            .put_object(key.as_str(), chunk_4mib.clone(), false)
            .await
            .expect("seed 4 MiB blob");
    });

    let mut group = c.benchmark_group("backend_memory_4mib");
    group.throughput(Throughput::Bytes(PLAINTEXT_CHUNK_SIZE as u64));

    group.bench_function("bounded_stream_get_4mib", |b| {
        let backend = backend.clone();
        let k = key.as_str().to_owned();
        b.iter(|| {
            rt.block_on(async {
                let got = backend.get_object(&k).await.expect("get_object");
                black_box(got.len())
            })
        });
    });

    group.finish();

    let mut range_group = c.benchmark_group("backend_memory_range_64kib");
    range_group.throughput(Throughput::Bytes(65_536));
    range_group.bench_function("get_object_range_64kib", |b| {
        let backend = backend.clone();
        let k = key.as_str().to_owned();
        b.iter(|| {
            rt.block_on(async {
                let slice = backend
                    .get_object_range(&k, 1_048_576, 65_536)
                    .await
                    .expect("get_object_range");
                black_box(slice.len())
            })
        });
    });
    range_group.finish();
}

fn bench_router_mirrored_and_verified(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let m0 = CloudBackend::from_config(&mem_cfg("m0")).expect("m0");
    let m1 = CloudBackend::from_config(&mem_cfg("m1")).expect("m1");
    let router = Arc::new(
        StorageRouter::new(
            vec![m0, m1],
            RoutingPolicy::Mirrored {
                backends: vec!["m0".to_owned(), "m1".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router"),
    );

    let payload = Bytes::from(vec![0xA5u8; 64 * 1024]);
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());
    rt.block_on(async {
        router
            .put_blob("/bench/chunk.zv", key.as_str(), payload.clone())
            .await
            .expect("seed mirrored");
    });

    let chaos = Arc::new(ChaosStorageRouter::from_storage_router(
        router.clone(),
        0x1234_5678,
        0,
    ));

    let mut group = c.benchmark_group("router_mirrored_64kib");
    group.throughput(Throughput::Bytes(65_536));

    group.bench_with_input(
        BenchmarkId::new("get_blob_verified", "64KiB"),
        &key,
        |b, k| {
            let router = router.clone();
            b.iter(|| {
                rt.block_on(async {
                    let bytes = router
                        .get_blob_verified(k.as_str(), &[], |raw| raw.len() == 65_536)
                        .await
                        .expect("verified get");
                    black_box(bytes.len())
                })
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("chaos_zero_drop_get_blob", "64KiB"),
        &key,
        |b, k| {
            let chaos = chaos.clone();
            b.iter(|| {
                rt.block_on(async {
                    let bytes = chaos.get_blob(k.as_str(), &[]).await.expect("chaos get");
                    black_box(bytes.len())
                })
            });
        },
    );

    group.finish();
}

criterion_group!(
    storage_benches,
    bench_object_key_validation,
    bench_memory_streaming_and_range,
    bench_router_mirrored_and_verified
);
criterion_main!(storage_benches);
