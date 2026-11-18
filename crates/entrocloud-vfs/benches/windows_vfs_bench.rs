#[cfg(target_os = "windows")]
mod bench_impl {
    use std::hint::black_box;
    use std::sync::Arc;

    use chrono::{TimeZone, Utc};
    use cloud_filter::error::CloudErrorKind;
    use criterion::{Criterion, Throughput};
    use tokio::runtime::Runtime;
    use uuid::Uuid;
    use entrocloud_types::mocks::MockVfsBackend;
    use entrocloud_types::{EntryKind, HydrationState, InodeRecord, ROOT_INODE};
    use entrocloud_vfs::windows::{
        FileIdentity, MAX_HYDRATION_STREAM_SLICE, PlaceholderSpec, TransferSink,
        align_cfapi_transfer_range, stream_chunked_hydration,
    };

    struct NullSink;

    impl TransferSink for NullSink {
        fn write_slice(&self, offset: u64, data: &[u8]) -> Result<(), CloudErrorKind> {
            black_box((offset, data.len()));
            Ok(())
        }

        fn report_progress(&self, total: u64, completed: u64) {
            black_box((total, completed));
        }
    }

    pub fn register_benches(c: &mut Criterion) {
        let mut group = c.benchmark_group("windows_cfapi_vfs");

        group.bench_function("align_cfapi_transfer_range", |b| {
            b.iter(|| {
                let r1 = align_cfapi_transfer_range(
                    black_box(5_001..9_123),
                    black_box(16 * 1024 * 1024),
                );
                let r2 = align_cfapi_transfer_range(
                    black_box(4_190_000..4_200_000),
                    black_box(4_195_111),
                );
                black_box((r1, r2))
            });
        });

        let sample_identity = FileIdentity::new(42_4242, Uuid::from_u128(0x0123_4567_89ab_cdef));
        group.bench_function("file_identity_encode_decode", |b| {
            b.iter(|| {
                let wire = black_box(sample_identity).encode();
                FileIdentity::decode(black_box(&wire))
            });
        });

        let ts = Utc
            .with_ymd_and_hms(2026, 11, 17, 12, 0, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let sample_record = InodeRecord {
            inode: 77,
            parent_inode: ROOT_INODE,
            file_id: Uuid::from_u128(0xfedc_ba98_7654_3210),
            name: "Q4_Financial_Statement_2026.pdf".to_owned(),
            virtual_path: "/Finance/Q4_Financial_Statement_2026.pdf".to_owned(),
            kind: EntryKind::File,
            size: 12_582_912,
            mode: 0o644,
            hydration: HydrationState::OnlineOnly,
            pinned: false,
            version: 1,
            wrapped_dek: None,
            modified_at: ts,
            created_at: ts,
        };
        group.bench_function("placeholder_spec_from_record", |b| {
            b.iter(|| PlaceholderSpec::from_record(black_box(&sample_record)));
        });

        group.finish();

        let rt = Runtime::new().expect("tokio runtime for benchmark");
        let backend = Arc::new(MockVfsBackend::new());
        let payload = vec![0xA5u8; MAX_HYDRATION_STREAM_SLICE];
        let seeded = rt.block_on(async {
            backend
                .seed_remote_file(ROOT_INODE, "stream_bench.bin", &payload)
                .await
                .expect("seed 4 MiB benchmark file")
        });

        let mut stream_group = c.benchmark_group("windows_cfapi_hydration");
        stream_group.throughput(Throughput::Bytes(MAX_HYDRATION_STREAM_SLICE as u64));
        stream_group.bench_function("stream_chunked_hydration_4mib", |b| {
            let sink = NullSink;
            b.iter(|| {
                rt.block_on(stream_chunked_hydration(
                    &*backend,
                    black_box(seeded.inode),
                    black_box(0..seeded.size),
                    black_box(seeded.size),
                    MAX_HYDRATION_STREAM_SLICE,
                    || false,
                    &sink,
                ))
            });
        });
        stream_group.finish();
    }
}

#[cfg(target_os = "windows")]
fn main() {
    let mut criterion = criterion::Criterion::default().configure_from_args();
    bench_impl::register_benches(&mut criterion);
    criterion.final_summary();
}

#[cfg(not(target_os = "windows"))]
fn main() {}
