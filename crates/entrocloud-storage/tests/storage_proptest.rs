//! Property-based chaos, failover, quota-conservation, and OAuth2 resilience tests (`proptest`).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use entrocloud_storage::{
    ChaosStorageRouter, CloudBackend, LoopbackOAuthListener, OAuthPkceAuthenticator,
    OAuthProviderConfig, OAuthProviderPreset, StorageRouter, constant_time_csrf_eq,
    retry_transient,
};
use entrocloud_types::mocks::MockCryptoEngine;
use entrocloud_types::{
    BackendConfig, BackendKind, BlobObjectKey, CHUNK_HEADER_LEN, ChunkAad, CryptoEngine,
    MANIFEST_HEAD_OBJECT_KEY, RedactedSecret, RoutingPolicy, StorageRouterTrait, ZeroVaultError,
};

fn memory_backend_config(
    id: &str,
    quota_limit_bytes: Option<u64>,
    min_free_reserve_bytes: u64,
) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::Memory,
        root: "/".to_owned(),
        endpoint: None,
        bucket: None,
        region: None,
        quota_limit_bytes,
        min_free_reserve_bytes,
        username: None,
        access_key_id: None,
        secret_access_key: None,
        secret_account_key: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_mirrored_bitrot_aead_failover(
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
        corrupt_offset in 0usize..8192,
        xor_mask in 1u8..=255u8,
        corrupt_which in 0u8..3u8,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            let b0 = CloudBackend::from_config(&memory_backend_config("m0", None, 0)).expect("m0");
            let b1 = CloudBackend::from_config(&memory_backend_config("m1", None, 0)).expect("m1");
            let b2 = CloudBackend::from_config(&memory_backend_config("m2", None, 0)).expect("m2");

            let router = Arc::new(
                StorageRouter::new(
                    vec![b0, b1, b2],
                    RoutingPolicy::Mirrored {
                        backends: vec!["m0".to_owned(), "m1".to_owned(), "m2".to_owned()],
                        min_ack: 3,
                    },
                )
                .expect("mirrored router"),
            );

            let crypto = MockCryptoEngine::default();
            let dek = crypto.generate_dek().expect("dek");
            let file_id = Uuid::new_v4();
            let expected_blake3 = *blake3::hash(&plaintext).as_bytes();
            let (_hdr, wire_chunk) = crypto
                .encrypt_chunk(
                    &dek,
                    ChunkAad {
                        file_id,
                        chunk_index: 0,
                        is_final_chunk: true,
                    },
                    &plaintext,
                )
                .expect("encrypt chunk");

            let verify_fn = |bytes: &[u8]| -> bool {
                match crypto.decrypt_chunk(&dek, file_id, Some(0), bytes) {
                    Ok((_h, pt)) => *blake3::hash(&pt).as_bytes() == expected_blake3,
                    Err(_) => false,
                }
            };

            let key = BlobObjectKey::from_uuid(Uuid::new_v4());
            router
                .put_blob("/prop/file.bin", key.as_str(), wire_chunk.clone())
                .await
                .expect("put_blob");

            // Corrupt up to 2 of the 3 mirrors directly in their underlying Memory operators
            // across ANY byte of the wire chunk (header, nonce, ciphertext, or AEAD tag)
            // and verify StorageRouter::get_blob_verified marks bad mirrors unhealthy and recovers!
            let target_ids = match corrupt_which {
                0 => vec!["m0"],
                1 => vec!["m0", "m1"],
                _ => vec!["m1"],
            };

            for id in &target_ids {
                let backend = router.backend(id).expect("mirror exists");
                let mut tampered = wire_chunk.to_vec();
                let idx = corrupt_offset % tampered.len();
                tampered[idx] ^= xor_mask;
                backend
                    .operator()
                    .write(key.as_str(), tampered)
                    .await
                    .expect("inject raw bit-rot");
            }

            let recovered_wire = router
                .get_blob_verified(key.as_str(), &[target_ids[0].to_owned()], verify_fn)
                .await
                .expect("verified failover must recover from intact mirror");

            let (_hdr_dec, recovered_pt) = crypto
                .decrypt_chunk(&dek, file_id, Some(0), &recovered_wire)
                .expect("decrypt recovered");
            prop_assert_eq!(recovered_pt.as_ref(), plaintext.as_slice());

            // Preferred corrupted mirror that was tried first must now be marked unhealthy!
            prop_assert!(!router.backend(target_ids[0]).expect("first target").is_healthy());

            // Upload a fresh intact blob and verify ChaosStorageRouter targeted bit-flip
            // fails closed with CryptoTamperDetected when ALL 3 mirrors are corrupted.
            let key_all_bad = BlobObjectKey::from_uuid(Uuid::new_v4());
            router
                .put_blob("/prop/all_bad.bin", key_all_bad.as_str(), wire_chunk.clone())
                .await
                .expect("put all_bad");

            let ct_tag_offset =
                CHUNK_HEADER_LEN + (corrupt_offset % (wire_chunk.len() - CHUNK_HEADER_LEN));
            let chaos = ChaosStorageRouter::from_storage_router(router.clone(), 42, 0);
            chaos.corrupt_backend("m0", ct_tag_offset, xor_mask);
            chaos.corrupt_backend("m1", ct_tag_offset, xor_mask);
            chaos.corrupt_backend("m2", ct_tag_offset, xor_mask);

            let err = chaos
                .get_blob_verified(key_all_bad.as_str(), &[], verify_fn)
                .await
                .expect_err("all mirrors corrupted must fail closed");
            prop_assert!(err.is_tamper());
            Ok(())
        })?;
    }

    #[test]
    fn prop_quota_pooled_spillover_conservation(
        caps in proptest::array::uniform3(4096u64..24576u64),
        reserves in proptest::array::uniform3(0u64..1536u64),
        blob_sizes in proptest::collection::vec(128usize..6144usize, 1..16),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            let b0 = CloudBackend::from_config(&memory_backend_config("p0", Some(caps[0]), reserves[0])).expect("p0");
            let b1 = CloudBackend::from_config(&memory_backend_config("p1", Some(caps[1]), reserves[1])).expect("p1");
            let b2 = CloudBackend::from_config(&memory_backend_config("p2", Some(caps[2]), reserves[2])).expect("p2");

            let router = StorageRouter::new(
                vec![b0, b1, b2],
                RoutingPolicy::QuotaPooled {
                    pool_backends: vec!["p0".to_owned(), "p1".to_owned(), "p2".to_owned()],
                },
            )
            .expect("quota pooled router");

            let mut placed: Vec<(String, Bytes, String)> = Vec::new();
            let mut expected_used_total = 0u64;

            for (idx, sz) in blob_sizes.into_iter().enumerate() {
                let key = BlobObjectKey::from_uuid(Uuid::new_v4());
                let payload = Bytes::from(vec![(idx as u8).wrapping_mul(17).wrapping_add(3); sz]);
                match router.put_blob("/pool/item.bin", key.as_str(), payload.clone()).await {
                    Ok(placement) => {
                        let chosen = placement.replicas[0].backend_id.clone();
                        expected_used_total += sz as u64;
                        placed.push((key.as_str().to_owned(), payload, chosen));
                    }
                    Err(ZeroVaultError::StorageQuotaExceeded(_)) => {}
                    Err(other) => prop_assert!(false, "unexpected error in QuotaPooled: {other}"),
                }

                // Invariant 1: Every account strictly preserves its min_free_reserve_bytes headroom.
                for (i, id) in ["p0", "p1", "p2"].iter().enumerate() {
                    let b = router.backend(id).expect("pool backend");
                    if b.used_bytes() > 0 {
                        prop_assert!(
                            b.used_bytes() + reserves[i] <= caps[i],
                            "account {id} violated cap+reserve: used={} reserve={} cap={}",
                            b.used_bytes(),
                            reserves[i],
                            caps[i]
                        );
                    }
                }
            }

            // Invariant 2: Total pooled quota equals exact sum of placed blobs.
            let pooled = router.pooled_quota().await.expect("pooled_quota");
            prop_assert_eq!(pooled.used_bytes, expected_used_total);

            // Invariant 3: Every placed blob reads back bit-for-bit identical.
            for (key, expected_bytes, backend_id) in &placed {
                let got = router.get_blob(key, &[]).await.expect("get_blob");
                prop_assert_eq!(&got, expected_bytes);
                let direct = router.get_blob_from_backend(backend_id, key).await.expect("direct get");
                prop_assert_eq!(&direct, expected_bytes);
            }

            // Invariant 4: Deleting every even-indexed placed blob reclaims exact quota bytes.
            for (idx, (key, bytes, _)) in placed.iter().enumerate() {
                if idx % 2 == 0 {
                    router.delete_blob(key, &[]).await.expect("delete_blob");
                    expected_used_total -= bytes.len() as u64;
                }
            }
            let pooled_after = router.pooled_quota().await.expect("pooled_quota after delete");
            prop_assert_eq!(pooled_after.used_bytes, expected_used_total);
            Ok(())
        })?;
    }

    #[test]
    fn prop_chaos_30pct_packet_loss_retry_convergence(
        seed in any::<u64>(),
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..1024), 2..8),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            let b0 = CloudBackend::from_config(&memory_backend_config("c0", None, 0)).expect("c0");
            let b1 = CloudBackend::from_config(&memory_backend_config("c1", None, 0)).expect("c1");
            let inner = Arc::new(
                StorageRouter::new(
                    vec![b0, b1],
                    RoutingPolicy::Mirrored {
                        backends: vec!["c0".to_owned(), "c1".to_owned()],
                        min_ack: 2,
                    },
                )
                .expect("router"),
            );

            // 3000 bps = 30.00% packet drop rate across put_blob, get_blob, and put_manifest_cas.
            let chaos = ChaosStorageRouter::new(inner, seed, 3_000);
            let chaos_ref = &chaos;
            let mut stored_keys = Vec::with_capacity(payloads.len());

            for raw in &payloads {
                let key = BlobObjectKey::from_uuid(Uuid::new_v4());
                let key_ref = key.as_str();
                let data = Bytes::from(raw.clone());
                retry_transient(48, Duration::ZERO, || {
                    let d = data.clone();
                    async move { chaos_ref.put_blob("/chaos/blob.zv", key_ref, d).await }
                })
                .await
                .expect("put_blob must converge under 30% packet loss");
                stored_keys.push((key.as_str().to_owned(), data));
            }

            // Converge 3 sequential optimistic manifest CAS updates under 30% packet loss!
            let mut cursor_etag: Option<String> = None;
            for rev in 1u64..=3 {
                let manifest_bytes = Bytes::from(format!("ZVM1-chaos-rev-{rev}"));
                let expected_ref = cursor_etag.clone();
                let ver = retry_transient(48, Duration::ZERO, || {
                    let mb = manifest_bytes.clone();
                    let exp = expected_ref.clone();
                    async move {
                        chaos_ref
                            .put_manifest_cas(MANIFEST_HEAD_OBJECT_KEY, mb, exp.as_deref())
                            .await
                    }
                })
                .await
                .expect("put_manifest_cas must converge under 30% packet loss");
                cursor_etag = ver.etag;
            }

            for (key, expected) in &stored_keys {
                let downloaded = retry_transient(48, Duration::ZERO, || async {
                    chaos_ref.get_blob(key, &[]).await
                })
                .await
                .expect("get_blob must converge under 30% packet loss");
                prop_assert_eq!(&downloaded, expected);
            }

            let final_manifest = retry_transient(48, Duration::ZERO, || async {
                chaos_ref.get_blob(MANIFEST_HEAD_OBJECT_KEY, &[]).await
            })
            .await
            .expect("read final manifest");
            prop_assert_eq!(final_manifest.as_ref(), b"ZVM1-chaos-rev-3");
            prop_assert!(chaos.stats().total_ops >= (payloads.len() * 2 + 3) as u64);
            Ok(())
        })?;
    }

    #[test]
    fn prop_byte_range_reads_exact_subslice(
        payload in proptest::collection::vec(any::<u8>(), 1..8192),
        raw_offset in 0usize..8192,
        raw_len in 0usize..4096,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            let backend = CloudBackend::from_config(&memory_backend_config("mem", None, 0))
                .expect("mem backend");
            let key = BlobObjectKey::from_uuid(Uuid::new_v4());
            backend
                .put_object(key.as_str(), Bytes::from(payload.clone()), false)
                .await
                .expect("put");

            let offset = raw_offset % payload.len();
            let max_rem = payload.len() - offset;
            let len = raw_len % (max_rem + 1);

            let got = backend
                .get_object_range(key.as_str(), offset as u64, len)
                .await
                .expect("range read");
            prop_assert_eq!(got.as_ref(), &payload[offset..offset + len]);
            Ok(())
        })?;
    }

    #[test]
    fn prop_targeted_segment_prefix_routing(
        seg_a in "[a-zA-Z0-9_-]{2,10}",
        seg_b in "[a-zA-Z0-9_-]{2,10}",
        leaf in "[a-zA-Z0-9_-]{2,12}",
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            let b_def = CloudBackend::from_config(&memory_backend_config("def", None, 0)).expect("def");
            let b_lvl1 = CloudBackend::from_config(&memory_backend_config("lvl1", None, 0)).expect("lvl1");
            let b_lvl2 = CloudBackend::from_config(&memory_backend_config("lvl2", None, 0)).expect("lvl2");

            let router = StorageRouter::new(
                vec![b_def, b_lvl1, b_lvl2],
                RoutingPolicy::Targeted {
                    prefix_routes: vec![
                        (format!("/{seg_a}"), "lvl1".to_owned()),
                        (format!("{seg_a}/{seg_b}/"), "lvl2".to_owned()),
                    ],
                    default_backend: "def".to_owned(),
                },
            )
            .expect("targeted router");

            // Longest match wins (`/<seg_a>/<seg_b>/<leaf>` -> `lvl2`).
            let p_deep = router
                .put_blob(
                    &format!("/{seg_a}/{seg_b}/{leaf}"),
                    BlobObjectKey::from_uuid(Uuid::new_v4()).as_str(),
                    Bytes::from_static(b"deep"),
                )
                .await
                .expect("put deep");
            prop_assert_eq!(&p_deep.replicas[0].backend_id, "lvl2");

            // Sibling prefix (`/<seg_a>_extra/<leaf>`) must NOT match `/<seg_a>` -> goes to `def`.
            let p_sibling = router
                .put_blob(
                    &format!("/{seg_a}_extra/{leaf}"),
                    BlobObjectKey::from_uuid(Uuid::new_v4()).as_str(),
                    Bytes::from_static(b"sib"),
                )
                .await
                .expect("put sibling");
            prop_assert_eq!(&p_sibling.replicas[0].backend_id, "def");
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_oauth_probe_survival_and_ssrf_rejection(
        forged_states in proptest::collection::vec("[a-zA-Z0-9_-]{4,24}", 1..5),
        valid_code in "[a-zA-Z0-9_-]{8,24}",
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        rt.block_on(async move {
            // Spawn mock token server returning valid JSON bundle.
            let token_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind token");
            let token_addr = token_listener.local_addr().expect("token addr");
            let token_task = tokio::spawn(async move {
                let (mut s, _) = token_listener.accept().await.expect("accept");
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"access_token":"prop-tok","token_type":"Bearer","expires_in":3600,"refresh_token":"prop-rt"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(resp.as_bytes()).await.expect("write");
                let _ = s.shutdown().await;
            });

            let cfg = OAuthProviderConfig::for_preset(
                OAuthProviderPreset::GoogleDrive,
                "prop-client",
                Some(RedactedSecret::new("prop-secret")),
            )
            .with_endpoints(
                "https://accounts.google.com/o/oauth2/v2/auth",
                format!("http://{token_addr}/token"),
            );

            let listener = LoopbackOAuthListener::bind_ephemeral(cfg)
                .await
                .expect("bind loopback")
                .with_per_socket_read_timeout(Duration::from_millis(200));
            let port = listener.local_addr().port();
            let query: HashMap<String, String> = listener
                .authorize_url()
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let real_state = query.get("state").expect("csrf state").clone();

            let wait_handle = tokio::spawn(async move {
                listener
                    .wait_for_callback_and_exchange(Duration::from_secs(5))
                    .await
            });

            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http");

            for forged in &forged_states {
                if !constant_time_csrf_eq(&real_state, forged) {
                    let resp = http
                        .get(format!(
                            "http://127.0.0.1:{port}/callback?code=bad&state={forged}"
                        ))
                        .send()
                        .await
                        .expect("forged probe");
                    prop_assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
                }
            }

            // Missing code probe also returns 400 and keeps listener alive.
            let enc_state: String =
                url::form_urlencoded::byte_serialize(real_state.as_bytes()).collect();
            let miss_code = http
                .get(format!("http://127.0.0.1:{port}/callback?state={enc_state}"))
                .send()
                .await
                .expect("missing code probe");
            prop_assert_eq!(miss_code.status(), reqwest::StatusCode::BAD_REQUEST);

            // Genuine callback succeeds!
            let ok_resp = http
                .get(format!(
                    "http://127.0.0.1:{port}/callback?code={valid_code}&state={enc_state}"
                ))
                .send()
                .await
                .expect("genuine callback");
            prop_assert_eq!(ok_resp.status(), reqwest::StatusCode::OK);

            let bundle = wait_handle.await.expect("join").expect("exchange ok");
            token_task.await.expect("token task");
            prop_assert_eq!(bundle.access_token.as_str(), "prop-tok");

            // Also verify 302 redirect rejection (SSRF protection).
            let trap_hit = Arc::new(AtomicBool::new(false));
            let trap_clone = trap_hit.clone();
            let trap = TcpListener::bind(("127.0.0.1", 0)).await.expect("trap");
            let trap_addr = trap.local_addr().expect("trap addr");
            tokio::spawn(async move {
                if trap.accept().await.is_ok() {
                    trap_clone.store(true, Ordering::SeqCst);
                }
            });

            let redir = TcpListener::bind(("127.0.0.1", 0)).await.expect("redir");
            let redir_addr = redir.local_addr().expect("redir addr");
            tokio::spawn(async move {
                if let Ok((mut s, _)) = redir.accept().await {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let r = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{trap_addr}/ssrf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = s.write_all(r.as_bytes()).await;
                }
            });

            let ssrf_auth = OAuthPkceAuthenticator::new(
                OAuthProviderConfig::for_preset(OAuthProviderPreset::OneDrive, "cid", None)
                    .with_endpoints(
                        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                        format!("http://{redir_addr}/token"),
                    ),
            )
            .expect("ssrf auth");
            prop_assert!(
                ssrf_auth
                    .refresh_tokens(&RedactedSecret::new("rt"))
                    .await
                    .is_err()
            );
            prop_assert!(!trap_hit.load(Ordering::SeqCst));
            Ok(())
        })?;
    }
}
