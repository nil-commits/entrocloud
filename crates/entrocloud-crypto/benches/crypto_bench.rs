use std::hint::black_box;
use std::time::Duration;

use bytes::BytesMut;
use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use uuid::Uuid;
use entrocloud_crypto::RingHybridCryptoEngine;
use entrocloud_types::{
    ChunkAad, CryptoEngine, MAX_ENCRYPTED_CHUNK_SIZE, PLAINTEXT_CHUNK_SIZE, ShareDescriptor,
    WrappedDek,
};

fn bench_bulk_aes256_gcm_4mib(c: &mut Criterion) {
    let engine = RingHybridCryptoEngine::new().expect("hardware crypto available");
    let dek = engine.generate_dek().expect("generate DEK");
    let file_id = Uuid::new_v4();

    let mut plaintext = vec![0u8; PLAINTEXT_CHUNK_SIZE];
    for (i, b) in plaintext.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(13);
    }

    let aad = ChunkAad {
        file_id,
        chunk_index: 0,
        is_final_chunk: true,
    };

    let mut wire_buf = BytesMut::with_capacity(MAX_ENCRYPTED_CHUNK_SIZE);
    engine
        .encrypt_chunk_into(&dek, aad, &plaintext, &mut wire_buf)
        .expect("warmup encrypt");
    let valid_wire = wire_buf.to_vec();
    let mut out_pt = BytesMut::with_capacity(PLAINTEXT_CHUNK_SIZE);

    let mut group = c.benchmark_group("aes256_gcm_ring_4mib");
    group.throughput(Throughput::Bytes(PLAINTEXT_CHUNK_SIZE as u64));
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(25);

    group.bench_function("encrypt_chunk_into", |b| {
        b.iter(|| {
            let hdr = engine
                .encrypt_chunk_into(
                    black_box(&dek),
                    black_box(aad),
                    black_box(&plaintext),
                    &mut wire_buf,
                )
                .expect("encrypt 4 MiB");
            black_box(hdr);
            black_box(&wire_buf);
        });
    });

    group.bench_function("decrypt_chunk_into", |b| {
        b.iter(|| {
            let hdr = engine
                .decrypt_chunk_into(
                    black_box(&dek),
                    black_box(file_id),
                    Some(0),
                    black_box(&valid_wire),
                    &mut out_pt,
                )
                .expect("decrypt 4 MiB");
            black_box(hdr);
            black_box(&out_pt);
        });
    });

    group.finish();
}

fn bench_metadata_and_pq_sharing(c: &mut Criterion) {
    let engine = RingHybridCryptoEngine::new().expect("hardware crypto available");
    let vault_id = Uuid::new_v4();
    let frk = [0x5Au8; 32];
    engine
        .unlock_with_folder_key(vault_id, &frk)
        .expect("unlock with folder key");

    let mut meta_group = c.benchmark_group("metadata_sqlite_v2");
    meta_group.warm_up_time(Duration::from_millis(300));
    meta_group.measurement_time(Duration::from_secs(1));

    meta_group.bench_function("compute_blind_index", |b| {
        b.iter(|| {
            let idx = engine
                .compute_blind_index(black_box(42), black_box("quarterly-financials-2026.pdf"))
                .expect("blind index");
            black_box(idx);
        });
    });

    let meta_aad = b"inode:42:virtual_path";
    let meta_pt = b"/Finance/2026/quarterly-financials-2026.pdf";
    meta_group.bench_function("seal_and_open_metadata", |b| {
        b.iter(|| {
            let ct = engine
                .seal_metadata(black_box(meta_aad), black_box(meta_pt))
                .expect("seal metadata");
            let pt = engine
                .open_metadata(black_box(meta_aad), black_box(&ct))
                .expect("open metadata");
            black_box(pt);
        });
    });
    meta_group.finish();

    let owner = engine
        .generate_recipient_identity("owner")
        .expect("owner identity");
    let alice = engine
        .generate_recipient_identity("alice")
        .expect("alice identity");
    let keybox = engine
        .seal_keybox(
            &owner,
            vault_id,
            1,
            &frk,
            std::slice::from_ref(&alice.public),
        )
        .expect("seal keybox");

    let mut pq_group = c.benchmark_group("pq_sharing_awslc_mlkem768");
    pq_group.warm_up_time(Duration::from_millis(300));
    pq_group.measurement_time(Duration::from_secs(1));
    pq_group.sample_size(25);

    pq_group.bench_function("generate_recipient_identity", |b| {
        b.iter(|| {
            let id = engine
                .generate_recipient_identity(black_box("bench-user"))
                .expect("generate identity");
            black_box(id);
        });
    });

    pq_group.bench_function("seal_keybox_1_recipient", |b| {
        b.iter(|| {
            let kb = engine
                .seal_keybox(
                    black_box(&owner),
                    black_box(vault_id),
                    black_box(1),
                    black_box(&frk),
                    black_box(std::slice::from_ref(&alice.public)),
                )
                .expect("seal keybox");
            black_box(kb);
        });
    });

    pq_group.bench_function("open_keybox_1_recipient", |b| {
        b.iter(|| {
            let unwrapped = engine
                .open_keybox(
                    black_box(&keybox),
                    Some(&owner.public.ed25519_pubkey),
                    1,
                    black_box(&alice),
                )
                .expect("open keybox");
            black_box(unwrapped);
        });
    });

    let dek = engine.generate_dek().expect("generate DEK");
    let desc = ShareDescriptor {
        share_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        filename: "architecture.pdf".to_owned(),
        size: 1_048_576,
        created_at: Utc::now(),
        wrapped_dek: WrappedDek {
            nonce: [0u8; 12],
            ciphertext_and_tag: vec![0u8; 48],
        },
        chunks: Vec::new(),
    };
    pq_group.bench_function("create_and_open_capability_share", |b| {
        b.iter(|| {
            let (uri, env) = engine
                .create_capability_share(&owner, "s3", "bucket-alpha", &dek, &desc)
                .expect("create share");
            let opened = engine
                .open_capability_share(black_box(&uri), black_box(&env))
                .expect("open share");
            black_box(opened);
        });
    });

    pq_group.finish();
}

criterion_group!(
    crypto_benches,
    bench_bulk_aes256_gcm_4mib,
    bench_metadata_and_pq_sharing
);
criterion_main!(crypto_benches);
