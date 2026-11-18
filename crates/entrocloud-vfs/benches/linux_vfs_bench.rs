//! Criterion micro-benchmarks for the cross-platform Linux FUSE3 state-machine and
//! zeroizing 4 MiB [`DirtyWriteBuffer`] coalescer.

use std::sync::Arc;

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use entrocloud_types::mocks::MockVfsBackend;
use entrocloud_types::{
    PLAINTEXT_CHUNK_SIZE, ROOT_INODE, XATTR_ZEROVAULT_FILE_ID, XATTR_ZEROVAULT_PIN,
    XATTR_ZEROVAULT_STATE,
};
use entrocloud_vfs::linux::{
    DirtyWriteBuffer, LINUX_O_RDWR, PortableErrno, PortableFuseState, PortableOpenFlags,
};

fn bench_dirty_write_buffer_coalesce_and_zeroize(c: &mut Criterion) {
    let mut group = c.benchmark_group("linux_vfs_dirty_write_buffer");
    group.throughput(Throughput::Bytes(PLAINTEXT_CHUNK_SIZE as u64));

    let frame = vec![0x6Bu8; 64 * 1024];
    let frames_per_chunk = PLAINTEXT_CHUNK_SIZE / frame.len();

    group.bench_function("coalesce_64kib_writes_to_4mib_and_zeroize", |b| {
        b.iter_batched(
            DirtyWriteBuffer::new,
            |mut buf| {
                let mut flushed_bytes = 0usize;
                for idx in 0..frames_per_chunk {
                    let offset = (idx * frame.len()) as u64;
                    let n = buf
                        .write_with::<PortableErrno, _>(
                            offset,
                            black_box(&frame),
                            |_flush_off, slice| {
                                flushed_bytes += slice.len();
                                Ok(slice.len())
                            },
                        )
                        .expect("write_with");
                    black_box(n);
                }
                debug_assert_eq!(flushed_bytes, PLAINTEXT_CHUNK_SIZE);
                black_box(flushed_bytes)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_portable_fuse_state_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let backend = Arc::new(MockVfsBackend::new());
    let state = Arc::new(PortableFuseState::new(backend, 1000, 1000));

    let (upper_ino, lower_ino) = rt.block_on(async {
        let (a1, fh1) = state
            .create(ROOT_INODE, "Makefile", 0o644, LINUX_O_RDWR)
            .await
            .expect("Makefile");
        let (a2, fh2) = state
            .create(ROOT_INODE, "makefile", 0o644, LINUX_O_RDWR)
            .await
            .expect("makefile");
        state
            .write(a1.ino, fh1, 0, b"all:\n\tcargo build\n")
            .await
            .expect("w1");
        state
            .write(a2.ino, fh2, 0, b"clean:\n\trm -rf target\n")
            .await
            .expect("w2");
        state.release(a1.ino, fh1).await.expect("r1");
        state.release(a2.ino, fh2).await.expect("r2");
        (a1.ino, a2.ino)
    });

    let mut meta_group = c.benchmark_group("linux_vfs_metadata_and_xattr");
    meta_group.bench_function("case_sensitive_lookup_and_xattr_query", |b| {
        b.iter(|| {
            rt.block_on(async {
                let upper = state
                    .lookup(ROOT_INODE, black_box("Makefile"))
                    .await
                    .expect("lookup upper");
                let lower = state
                    .lookup(ROOT_INODE, black_box("makefile"))
                    .await
                    .expect("lookup lower");
                let st = state
                    .getxattr(upper.ino, XATTR_ZEROVAULT_STATE)
                    .await
                    .expect("state");
                let pin = state
                    .getxattr(lower.ino, XATTR_ZEROVAULT_PIN)
                    .await
                    .expect("pin");
                let fid = state
                    .getxattr(upper_ino, XATTR_ZEROVAULT_FILE_ID)
                    .await
                    .expect("file_id");
                black_box((upper.ino, lower_ino, st, pin, fid))
            })
        });
    });
    meta_group.finish();

    let mut io_group = c.benchmark_group("linux_vfs_streaming_4mib");
    io_group.throughput(Throughput::Bytes(PLAINTEXT_CHUNK_SIZE as u64));
    let block = vec![0x9Cu8; 256 * 1024];
    let stream_ino = rt.block_on(async {
        let (attr, fh) = state
            .create(ROOT_INODE, "stream.bin", 0o644, LINUX_O_RDWR)
            .await
            .expect("stream.bin");
        state.release(attr.ino, fh).await.expect("rel");
        attr.ino
    });

    io_group.bench_function("buffered_write_flush_and_read_4mib", |b| {
        b.iter(|| {
            rt.block_on(async {
                let fh = state
                    .open(stream_ino, PortableOpenFlags::read_write())
                    .await
                    .expect("open");
                let steps = PLAINTEXT_CHUNK_SIZE / block.len();
                for step in 0..steps {
                    let off = (step * block.len()) as u64;
                    state
                        .write(stream_ino, fh, off, black_box(&block))
                        .await
                        .expect("write");
                }
                state.flush(stream_ino, fh).await.expect("flush");
                let out = state
                    .read(stream_ino, 0, PLAINTEXT_CHUNK_SIZE as u32)
                    .await
                    .expect("read");
                state.release(stream_ino, fh).await.expect("release");
                black_box(out.len())
            })
        });
    });
    io_group.finish();
}

criterion_group!(
    benches,
    bench_dirty_write_buffer_coalesce_and_zeroize,
    bench_portable_fuse_state_operations
);
criterion_main!(benches);
