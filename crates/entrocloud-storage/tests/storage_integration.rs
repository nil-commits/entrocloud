//! Comprehensive integration and security verification suite for `entrocloud-storage`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{Duration as ChronoDuration, Utc};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use opendal::raw::{
    Layer, OpCompose, OpCopy, OpCreateDir, OpList, OpPresign, OpRead, OpRename, OpRestore, OpStat,
    OpWrite, RpCreateDir, RpPresign, RpRead, RpRename, RpRestore, RpStat, Service, ServiceInfo,
    Servicer, oio,
};
use opendal::{BytesRange, Capability, OperationContext, Operator, services};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use entrocloud_storage::{
    ChaosStorageRouter, CloudBackend, DEFAULT_TOKEN_SECRET_SERVICE, LoopbackOAuthListener,
    MAX_KEYBOX_BYTES, MAX_SEALED_MANIFEST_BYTES, MAX_SHARE_OBJECT_BYTES, MIRROR_CAS_PREFIX,
    OAuthPkceAuthenticator, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenBundle,
    PER_SOCKET_READ_TIMEOUT, QuotaSelectionStrategy, StorageRouter, constant_time_csrf_eq,
    delete_tokens, load_tokens, max_wire_bytes_for_object_key, persist_tokens, retry_transient,
};
use entrocloud_types::mocks::{InMemorySecretStore, MockCryptoEngine};
use entrocloud_types::{
    BackendConfig, BackendKind, BlobObjectKey, ChunkAad, CryptoEngine, KEYBOX_OBJECT_KEY,
    MANIFEST_HEAD_OBJECT_KEY, MAX_ENCRYPTED_CHUNK_SIZE, ManifestObjectKey, RedactedSecret,
    RoutingPolicy, SecretStore, ShareObjectKey, StorageRouterTrait, VAULT_HEADER_LEN,
    VAULT_HEADER_OBJECT_KEY, ZeroVaultError,
};

fn base_config(id: &str, kind: BackendKind, root: &str) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind,
        root: root.to_owned(),
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

fn local_fs_config(
    id: &str,
    dir: &std::path::Path,
    quota_limit_bytes: Option<u64>,
    min_free_reserve_bytes: u64,
) -> BackendConfig {
    BackendConfig {
        id: id.to_owned(),
        kind: BackendKind::LocalFs,
        root: dir.to_string_lossy().into_owned(),
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

#[derive(Debug, Default)]
struct MockTokenServerCapture {
    grant_type: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
}

async fn spawn_mock_oauth_token_server(
    capture: Arc<Mutex<MockTokenServerCapture>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock oauth token server");
    let addr = listener.local_addr().expect("mock server local_addr");

    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept token request");
        let mut raw = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = sock.read(&mut tmp).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&tmp[..n]);
            if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let hdr_str = String::from_utf8_lossy(&raw[..hdr_end]);
                let content_len = hdr_str
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let body_start = hdr_end + 4;
                while raw.len() < body_start + content_len {
                    let m = sock.read(&mut tmp).await.expect("read body");
                    if m == 0 {
                        break;
                    }
                    raw.extend_from_slice(&tmp[..m]);
                }
                let body = String::from_utf8_lossy(&raw[body_start..]).into_owned();
                let mut guard = capture.lock().await;
                for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
                    match k.as_ref() {
                        "grant_type" => guard.grant_type = Some(v.into_owned()),
                        "code" => guard.code = Some(v.into_owned()),
                        "code_verifier" => guard.code_verifier = Some(v.into_owned()),
                        "redirect_uri" => guard.redirect_uri = Some(v.into_owned()),
                        _ => {}
                    }
                }
                break;
            }
        }

        let resp_body = r#"{
            "access_token": "mock-access-token-secret-xyz",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock-refresh-token-secret-abc",
            "scope": "https://www.googleapis.com/auth/drive.file"
        }"#;
        let http_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
            resp_body.len()
        );
        sock.write_all(http_resp.as_bytes())
            .await
            .expect("write token response");
        let _ = sock.shutdown().await;
    });

    (addr, handle)
}

#[tokio::test]
async fn builds_all_seven_backend_kinds_and_unwraps_wrapped_oauth_tokens() {
    let tmp = TempDir::new().expect("tempdir");
    let fs_root = tmp.path().join("auto_created_root");
    assert!(!fs_root.exists());

    let fs_cfg = base_config(
        "local-fs",
        BackendKind::LocalFs,
        &fs_root.to_string_lossy(),
    );
    let fs_backend = CloudBackend::from_config(&fs_cfg).expect("build LocalFs");
    assert!(fs_root.exists());

    let mem_cfg = base_config("mem", BackendKind::Memory, "/");
    let mem_backend = CloudBackend::from_config(&mem_cfg).expect("build Memory");
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());
    mem_backend
        .put_object(key.as_str(), Bytes::from_static(b"cipher"), false)
        .await
        .expect("put memory");
    assert_eq!(
        mem_backend
            .get_object(key.as_str())
            .await
            .expect("get memory")
            .as_ref(),
        b"cipher"
    );

    fs_backend
        .put_object(key.as_str(), Bytes::from_static(b"fs-cipher"), false)
        .await
        .expect("put fs");
    assert_eq!(
        fs_backend
            .get_object(key.as_str())
            .await
            .expect("get fs")
            .as_ref(),
        b"fs-cipher"
    );
    assert_eq!(fs_backend.used_bytes(), 9);
    fs_backend
        .delete_object(key.as_str())
        .await
        .expect("delete fs");
    assert_eq!(fs_backend.used_bytes(), 0);

    let mut s3_cfg = base_config("s3", BackendKind::S3, "vault");
    s3_cfg.bucket = Some("zerovault-test-bucket".to_owned());
    s3_cfg.region = Some("us-east-1".to_owned());
    s3_cfg.endpoint = Some("http://127.0.0.1:9000".to_owned());
    s3_cfg.access_key_id = Some("minioadmin".to_owned());
    s3_cfg.secret_access_key = Some(RedactedSecret::new("minioadmin-secret"));
    CloudBackend::from_config(&s3_cfg).expect("build S3");

    let mut webdav_cfg = base_config("dav", BackendKind::WebDav, "/zerovault");
    webdav_cfg.endpoint = Some("https://cloud.example.com/remote.php/dav".to_owned());
    webdav_cfg.username = Some("alice".to_owned());
    webdav_cfg.secret_access_key = Some(RedactedSecret::new("app-password"));
    CloudBackend::from_config(&webdav_cfg).expect("build WebDAV");

    let crypto = MockCryptoEngine::default();
    let secrets = InMemorySecretStore::default();
    for (id, kind, preset) in [
        (
            "gdrive-1",
            BackendKind::GoogleDrive,
            OAuthProviderPreset::GoogleDrive,
        ),
        (
            "onedrive-1",
            BackendKind::OneDrive,
            OAuthProviderPreset::OneDrive,
        ),
        (
            "dropbox-1",
            BackendKind::Dropbox,
            OAuthProviderPreset::Dropbox,
        ),
    ] {
        let bundle = OAuthTokenBundle {
            provider: preset,
            access_token: RedactedSecret::new("secret-access-token"),
            refresh_token: Some(RedactedSecret::new("secret-refresh-token")),
            token_type: "bearer".to_owned(),
            expires_at: Some(Utc::now() + ChronoDuration::hours(1)),
            scopes: preset.default_scopes(),
            client_id: Some("client-id".to_owned()),
            client_secret: Some(RedactedSecret::new("client-secret")),
        };
        persist_tokens(&bundle, &secrets, &crypto, DEFAULT_TOKEN_SECRET_SERVICE, id)
            .await
            .expect("persist tokens");

        let mut cfg = base_config(id, kind, "/zerovault");
        cfg.secret_account_key = Some(id.to_owned());
        let backend = CloudBackend::from_config_with_secrets(&cfg, Some(&secrets), Some(&crypto))
            .await
            .expect("build OAuth backend from wrapped SecretStore tokens");
        let dbg = format!("{backend:?}");
        assert!(!dbg.contains("secret-access-token"));
        assert!(!dbg.contains("secret-refresh-token"));
        assert!(!dbg.contains("client-secret"));
    }
}

#[tokio::test]
async fn max_wire_bytes_enforces_keybox_shares_header_blobs_and_manifests() {
    let blob_key = BlobObjectKey::from_uuid(Uuid::new_v4());
    let share_key = ShareObjectKey::from_uuid(Uuid::new_v4());
    let manifest_snap_key = ManifestObjectKey::from_uuid(Uuid::new_v4());

    assert_eq!(
        max_wire_bytes_for_object_key(VAULT_HEADER_OBJECT_KEY).expect("header ceiling"),
        VAULT_HEADER_LEN
    );
    assert_eq!(
        max_wire_bytes_for_object_key(KEYBOX_OBJECT_KEY).expect("keybox ceiling"),
        MAX_KEYBOX_BYTES
    );
    assert_eq!(
        max_wire_bytes_for_object_key(share_key.as_str()).expect("share ceiling"),
        MAX_SHARE_OBJECT_BYTES
    );
    assert_eq!(
        max_wire_bytes_for_object_key(blob_key.as_str()).expect("blob ceiling"),
        MAX_ENCRYPTED_CHUNK_SIZE
    );
    assert_eq!(
        max_wire_bytes_for_object_key(MANIFEST_HEAD_OBJECT_KEY).expect("manifest head ceiling"),
        MAX_SEALED_MANIFEST_BYTES
    );
    assert_eq!(
        max_wire_bytes_for_object_key(manifest_snap_key.as_str()).expect("manifest snap ceiling"),
        MAX_SEALED_MANIFEST_BYTES
    );
    assert!(max_wire_bytes_for_object_key("Finance/taxes.pdf").is_err());

    // Verify bounded streaming read rejects oversized remote header and keybox payloads before OOM.
    let backend = CloudBackend::from_config(&base_config("mem", BackendKind::Memory, "/"))
        .expect("memory backend");

    // Valid keybox and share object roundtrip cleanly.
    backend
        .put_object(KEYBOX_OBJECT_KEY, Bytes::from_static(b"ZVK1-keybox-payload"), false)
        .await
        .expect("put keybox.zv");
    assert_eq!(
        backend
            .get_object(KEYBOX_OBJECT_KEY)
            .await
            .expect("get keybox.zv")
            .as_ref(),
        b"ZVK1-keybox-payload"
    );

    backend
        .put_object(share_key.as_str(), Bytes::from_static(b"ZVS1-share-payload"), false)
        .await
        .expect("put share object");
    assert_eq!(
        backend
            .get_object(share_key.as_str())
            .await
            .expect("get share object")
            .as_ref(),
        b"ZVS1-share-payload"
    );

    // Plant an oversized 200-byte header directly via raw operator to simulate rogue cloud response.
    backend
        .operator()
        .write(VAULT_HEADER_OBJECT_KEY, vec![0xAAu8; VAULT_HEADER_LEN + 88])
        .await
        .expect("raw write oversized header");
    let err = backend
        .get_object(VAULT_HEADER_OBJECT_KEY)
        .await
        .expect_err("oversized header must be rejected during bounded stream read");
    assert!(matches!(err, ZeroVaultError::InvalidWireFormat(_)));

    // Plant an oversized (> 4 MiB) keybox directly via raw operator.
    backend
        .operator()
        .write(KEYBOX_OBJECT_KEY, vec![0xBBu8; MAX_KEYBOX_BYTES + 128])
        .await
        .expect("raw write oversized keybox");
    let kb_err = backend
        .get_object(KEYBOX_OBJECT_KEY)
        .await
        .expect_err("oversized keybox must be rejected");
    assert!(matches!(kb_err, ZeroVaultError::InvalidWireFormat(_)));
}

#[tokio::test]
async fn backend_and_router_get_object_range_reads_exact_byte_slices() {
    let tmp = TempDir::new().expect("tempdir");
    let fs_backend = CloudBackend::from_config(&local_fs_config("fs-range", tmp.path(), None, 0))
        .expect("fs backend");
    let mem_backend = CloudBackend::from_config(&base_config("mem-range", BackendKind::Memory, "/"))
        .expect("mem backend");

    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());

    for backend in [&fs_backend, &mem_backend] {
        backend
            .put_object(key.as_str(), Bytes::from(payload.clone()), false)
            .await
            .expect("put payload");

        let slice_head = backend
            .get_object_range(key.as_str(), 0, 32)
            .await
            .expect("read head range");
        assert_eq!(slice_head.as_ref(), &payload[0..32]);

        let slice_mid = backend
            .get_object_range(key.as_str(), 1337, 512)
            .await
            .expect("read middle range");
        assert_eq!(slice_mid.as_ref(), &payload[1337..1337 + 512]);

        let slice_empty = backend
            .get_object_range(key.as_str(), 100, 0)
            .await
            .expect("zero-length range");
        assert!(slice_empty.is_empty());

        // Overflowing offset + len rejected.
        let overflow_err = backend
            .get_object_range(key.as_str(), u64::MAX - 4, 16)
            .await
            .expect_err("overflow range rejected");
        assert!(matches!(overflow_err, ZeroVaultError::InvalidRange { .. }));

        // Exceeding wire ceiling rejected before allocation.
        let cap_err = backend
            .get_object_range(key.as_str(), 0, MAX_ENCRYPTED_CHUNK_SIZE + 1)
            .await
            .expect_err("oversized range rejected");
        assert!(matches!(cap_err, ZeroVaultError::InvalidRange { .. }));

        // Plaintext key rejected.
        let bad_key_err = backend
            .get_object_range("Plaintext/secret.bin", 0, 16)
            .await
            .expect_err("plaintext key rejected");
        assert!(matches!(bad_key_err, ZeroVaultError::InvalidPath(_)));
    }

    let router = StorageRouter::new(
        vec![mem_backend],
        RoutingPolicy::Targeted {
            prefix_routes: vec![],
            default_backend: "mem-range".to_owned(),
        },
    )
    .expect("router");
    let routed_slice = router
        .get_blob_range(key.as_str(), 500, 250, &[])
        .await
        .expect("router range read");
    assert_eq!(routed_slice.as_ref(), &payload[500..750]);
}

#[test]
fn oauth_presets_enforce_least_privilege_cloudbridge_scopes() {
    assert_eq!(
        OAuthProviderPreset::GoogleDrive.default_scopes(),
        vec!["https://www.googleapis.com/auth/drive.file".to_owned()]
    );
    assert_eq!(
        OAuthProviderPreset::OneDrive.default_scopes(),
        vec![
            "Files.ReadWrite.AppFolder".to_owned(),
            "offline_access".to_owned(),
        ]
    );
    assert_eq!(
        OAuthProviderPreset::Dropbox.default_scopes(),
        vec![
            "files.content.write".to_owned(),
            "files.content.read".to_owned(),
        ]
    );
    assert_eq!(PER_SOCKET_READ_TIMEOUT, Duration::from_secs(5));
    assert!(constant_time_csrf_eq("state-token-123", "state-token-123"));
    assert!(!constant_time_csrf_eq("state-token-123", "state-token-124"));
}

#[tokio::test]
async fn oauth_new_l01_survives_slowloris_and_malicious_probes_until_valid_state_arrives() {
    let capture = Arc::new(Mutex::new(MockTokenServerCapture::default()));
    let (token_addr, token_server) = spawn_mock_oauth_token_server(capture.clone()).await;

    let config = OAuthProviderConfig::for_preset(
        OAuthProviderPreset::OneDrive,
        "entrocloud-client",
        Some(RedactedSecret::new("client-secret")),
    )
    .with_endpoints(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        format!("http://{token_addr}/token"),
    );

    // Use default 5s per-socket timeout to verify exact NEW-L01 5s slowloris mitigation!
    let listener = LoopbackOAuthListener::bind_ephemeral(config)
        .await
        .expect("bind loopback");
    let port = listener.local_addr().port();
    let auth_url = listener.authorize_url().clone();

    let query: HashMap<String, String> = auth_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let expected_challenge = query.get("code_challenge").expect("challenge").clone();
    let valid_state = query.get("state").expect("state").clone();

    let login_task = tokio::spawn(async move {
        listener
            .wait_for_callback_and_exchange(Duration::from_secs(20))
            .await
    });

    // 1. Slowloris 1-byte hang attack: send 1 byte ('G') and never send CRLFCRLF!
    let mut slow_sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect slowloris");
    slow_sock.write_all(b"G").await.expect("write 1 byte");
    let slow_started = Instant::now();
    let mut slow_resp = Vec::new();
    let _ = slow_sock.read_to_end(&mut slow_resp).await;
    let slow_elapsed = slow_started.elapsed();
    assert!(
        slow_elapsed >= Duration::from_millis(4800) && slow_elapsed < Duration::from_secs(8),
        "expected ~5s per-socket timeout, got {slow_elapsed:?}"
    );

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");

    // 2. Missing `state` probe -> 400 Bad Request, listener stays alive!
    let r_missing_state = http
        .get(format!("http://127.0.0.1:{port}/callback?code=attacker-code"))
        .send()
        .await
        .expect("missing state request");
    assert_eq!(r_missing_state.status(), reqwest::StatusCode::BAD_REQUEST);

    // 3. Mismatched `state` probe -> 400 Bad Request, listener stays alive!
    let r_bad_state = http
        .get(format!(
            "http://127.0.0.1:{port}/callback?code=attacker-code&state=forged-csrf-token"
        ))
        .send()
        .await
        .expect("forged state request");
    assert_eq!(r_bad_state.status(), reqwest::StatusCode::BAD_REQUEST);

    // 4. Forged `error=access_denied` with wrong `state` -> 400 Bad Request, does NOT abort!
    let r_forged_err = http
        .get(format!(
            "http://127.0.0.1:{port}/callback?error=access_denied&state=forged-csrf-token"
        ))
        .send()
        .await
        .expect("forged error request");
    assert_eq!(r_forged_err.status(), reqwest::StatusCode::BAD_REQUEST);

    // 5. Valid `state` but missing `code` -> 400 Bad Request, listener STILL stays alive!
    let encoded_state: String =
        url::form_urlencoded::byte_serialize(valid_state.as_bytes()).collect();
    let r_missing_code = http
        .get(format!(
            "http://127.0.0.1:{port}/callback?state={encoded_state}"
        ))
        .send()
        .await
        .expect("missing code request");
    assert_eq!(r_missing_code.status(), reqwest::StatusCode::BAD_REQUEST);

    // 6. Genuine browser redirect arrives with matching `state` + `code` -> 200 OK & token exchange!
    let r_genuine = http
        .get(format!(
            "http://127.0.0.1:{port}/callback?code=genuine-auth-code-99&state={encoded_state}"
        ))
        .send()
        .await
        .expect("genuine callback");
    assert_eq!(r_genuine.status(), reqwest::StatusCode::OK);

    let bundle = login_task
        .await
        .expect("join login task")
        .expect("genuine login succeeds after surviving slowloris and probes");
    token_server.await.expect("token server join");

    assert_eq!(bundle.access_token.as_str(), "mock-access-token-secret-xyz");
    assert_eq!(
        bundle.refresh_token.as_ref().map(RedactedSecret::as_str),
        Some("mock-refresh-token-secret-abc")
    );

    let captured = capture.lock().await;
    let verifier = captured.code_verifier.as_deref().expect("pkce verifier");
    let derived_challenge =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.to_owned()));
    assert_eq!(derived_challenge.as_str(), expected_challenge);
}

#[tokio::test]
async fn oauth_ssrf_302_redirect_rejected_and_token_refresh_preserves_refresh_token() {
    let trap_hit = Arc::new(AtomicBool::new(false));
    let trap_flag = trap_hit.clone();
    let trap_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("trap");
    let trap_addr = trap_listener.local_addr().expect("trap addr");
    let _trap_task = tokio::spawn(async move {
        if let Ok((mut s, _)) = trap_listener.accept().await {
            trap_flag.store(true, Ordering::SeqCst);
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let redir_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("redir");
    let redir_addr = redir_listener.local_addr().expect("redir addr");
    let redir_task = tokio::spawn(async move {
        let (mut s, _) = redir_listener.accept().await.expect("accept");
        let mut buf = [0u8; 2048];
        let _ = s.read(&mut buf).await;
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{trap_addr}/internal-metadata\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        s.write_all(resp.as_bytes()).await.expect("write 302");
        let _ = s.shutdown().await;
    });

    let cfg = OAuthProviderConfig::for_preset(
        OAuthProviderPreset::Dropbox,
        "cid",
        Some(RedactedSecret::new("csec")),
    )
    .with_endpoints(
        "https://www.dropbox.com/oauth2/authorize",
        format!("http://{redir_addr}/token"),
    );

    let auth = OAuthPkceAuthenticator::new(cfg).expect("authenticator");
    let err = auth
        .refresh_tokens(&RedactedSecret::new("existing-rt"))
        .await
        .expect_err("302 redirect at token endpoint must fail closed");
    assert!(matches!(err, ZeroVaultError::OAuthError(_)));
    redir_task.await.expect("redir join");
    assert!(
        !trap_hit.load(Ordering::SeqCst),
        "SSRF redirect target must never be contacted"
    );

    // Verify refresh_and_persist_tokens preserves prior refresh_token when server omits it.
    let refresh_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("refresh server");
    let refresh_addr = refresh_listener.local_addr().expect("refresh addr");
    let refresh_task = tokio::spawn(async move {
        let (mut s, _) = refresh_listener.accept().await.expect("accept");
        let mut buf = [0u8; 2048];
        let _ = s.read(&mut buf).await;
        let body = r#"{"access_token":"rotated-access-token","token_type":"Bearer","expires_in":3600}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(resp.as_bytes()).await.expect("write");
        let _ = s.shutdown().await;
    });

    let crypto = MockCryptoEngine::default();
    let secrets = InMemorySecretStore::default();
    let initial_bundle = OAuthTokenBundle {
        provider: OAuthProviderPreset::GoogleDrive,
        access_token: RedactedSecret::new("initial-access"),
        refresh_token: Some(RedactedSecret::new("persistent-refresh-token")),
        token_type: "bearer".to_owned(),
        expires_at: Some(Utc::now() - ChronoDuration::minutes(5)),
        scopes: OAuthProviderPreset::GoogleDrive.default_scopes(),
        client_id: Some("cid".to_owned()),
        client_secret: Some(RedactedSecret::new("csec")),
    };
    assert!(initial_bundle.is_expired(60));
    persist_tokens(
        &initial_bundle,
        &secrets,
        &crypto,
        DEFAULT_TOKEN_SECRET_SERVICE,
        "gd-acct",
    )
    .await
    .expect("persist initial");

    let refresh_cfg = OAuthProviderConfig::for_preset(
        OAuthProviderPreset::GoogleDrive,
        "cid",
        Some(RedactedSecret::new("csec")),
    )
    .with_endpoints(
        "https://accounts.google.com/o/oauth2/v2/auth",
        format!("http://{refresh_addr}/token"),
    );
    let refresh_auth = OAuthPkceAuthenticator::new(refresh_cfg).expect("refresh auth");
    let updated = refresh_auth
        .refresh_and_persist_tokens(
            &secrets,
            &crypto,
            DEFAULT_TOKEN_SECRET_SERVICE,
            "gd-acct",
        )
        .await
        .expect("refresh and persist");
    refresh_task.await.expect("refresh server join");

    assert_eq!(updated.access_token.as_str(), "rotated-access-token");
    assert_eq!(
        updated.refresh_token.as_ref().map(RedactedSecret::as_str),
        Some("persistent-refresh-token")
    );

    let reloaded = load_tokens(&secrets, &crypto, DEFAULT_TOKEN_SECRET_SERVICE, "gd-acct")
        .await
        .expect("load")
        .expect("present");
    assert_eq!(reloaded.access_token.as_str(), "rotated-access-token");
    assert_eq!(
        reloaded.refresh_token.as_ref().map(RedactedSecret::as_str),
        Some("persistent-refresh-token")
    );

    delete_tokens(&secrets, DEFAULT_TOKEN_SECRET_SERVICE, "gd-acct")
        .await
        .expect("delete");
    assert!(
        load_tokens(&secrets, &crypto, DEFAULT_TOKEN_SECRET_SERVICE, "gd-acct")
            .await
            .expect("load after delete")
            .is_none()
    );
}

#[tokio::test]
async fn mirrored_min_ack_rollback_cleans_partial_replica_and_quota_on_failure() {
    let tmp = TempDir::new().expect("tempdir");
    let dir_a = tmp.path().join("mirror_a");
    let dir_b = tmp.path().join("mirror_b");

    // Mirror A has ample quota; Mirror B only has 64 bytes so a 512-byte blob fails on B.
    let ba = CloudBackend::from_config(&local_fs_config("mirror-a", &dir_a, Some(65_536), 0))
        .expect("mirror a");
    let bb = CloudBackend::from_config(&local_fs_config("mirror-b", &dir_b, Some(64), 0))
        .expect("mirror b");

    let router = StorageRouter::new(
        vec![ba, bb],
        RoutingPolicy::Mirrored {
            backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
            min_ack: 2,
        },
    )
    .expect("mirrored router");

    let key = BlobObjectKey::from_uuid(Uuid::new_v4());
    let err = router
        .put_blob(
            "/Critical/secret.bin",
            key.as_str(),
            Bytes::from(vec![0xCCu8; 512]),
        )
        .await
        .expect_err("min_ack=2 must fail when mirror-b exceeds quota");
    assert!(matches!(err, ZeroVaultError::StorageQuotaExceeded(_)));

    // Verify rollback deleted the partial replica on mirror-a and restored mirror-a used_bytes to 0!
    assert_eq!(
        router.backend("mirror-a").expect("mirror-a").used_bytes(),
        0
    );
    assert!(!dir_a.join(key.as_str()).exists());
    assert!(!dir_b.join(key.as_str()).exists());
}

#[tokio::test]
async fn new_m02_get_blob_verified_marks_bitrotted_fast_mirror_unhealthy_and_fails_over() {
    #[derive(Debug, Clone)]
    struct SlowReadLayer {
        delay: Duration,
    }
    impl Layer for SlowReadLayer {
        fn apply_service(&self, inner: Servicer) -> Servicer {
            Arc::new(SlowReadService {
                inner,
                delay: self.delay,
            })
        }
    }
    #[derive(Debug)]
    struct SlowReadService {
        inner: Servicer,
        delay: Duration,
    }
    impl Service for SlowReadService {
        type Reader = DelayedReader;
        type Writer = oio::Writer;
        type Lister = oio::Lister;
        type Deleter = oio::Deleter;
        type Copier = oio::Copier;
        type Composer = oio::Composer;

        fn info(&self) -> ServiceInfo {
            self.inner.info()
        }
        fn capability(&self) -> Capability {
            self.inner.capability()
        }
        async fn create_dir(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpCreateDir,
        ) -> opendal::Result<RpCreateDir> {
            self.inner.create_dir(ctx, path, args).await
        }
        fn read(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpRead,
        ) -> opendal::Result<Self::Reader> {
            let inner = self.inner.read(ctx, path, args)?;
            Ok(DelayedReader {
                inner,
                delay: self.delay,
            })
        }
        fn write(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpWrite,
        ) -> opendal::Result<Self::Writer> {
            self.inner.write(ctx, path, args)
        }
        fn copy(
            &self,
            ctx: &OperationContext,
            from: &str,
            to: &str,
            args: OpCopy,
        ) -> opendal::Result<Self::Copier> {
            self.inner.copy(ctx, from, to, args)
        }
        fn compose(
            &self,
            ctx: &OperationContext,
            to: &str,
            args: OpCompose,
        ) -> opendal::Result<Self::Composer> {
            self.inner.compose(ctx, to, args)
        }
        async fn rename(
            &self,
            ctx: &OperationContext,
            from: &str,
            to: &str,
            args: OpRename,
        ) -> opendal::Result<RpRename> {
            self.inner.rename(ctx, from, to, args).await
        }
        async fn restore(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpRestore,
        ) -> opendal::Result<RpRestore> {
            self.inner.restore(ctx, path, args).await
        }
        async fn stat(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpStat,
        ) -> opendal::Result<RpStat> {
            self.inner.stat(ctx, path, args).await
        }
        fn delete(&self, ctx: &OperationContext) -> opendal::Result<Self::Deleter> {
            self.inner.delete(ctx)
        }
        fn list(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpList,
        ) -> opendal::Result<Self::Lister> {
            self.inner.list(ctx, path, args)
        }
        async fn presign(
            &self,
            ctx: &OperationContext,
            path: &str,
            args: OpPresign,
        ) -> opendal::Result<RpPresign> {
            self.inner.presign(ctx, path, args).await
        }
    }
    struct DelayedReader {
        inner: oio::Reader,
        delay: Duration,
    }
    impl oio::Read for DelayedReader {
        async fn open(
            &self,
            range: BytesRange,
        ) -> opendal::Result<(RpRead, Box<dyn oio::ReadStreamDyn>)> {
            tokio::time::sleep(self.delay).await;
            self.inner.open(range).await
        }
        async fn read(&self, range: BytesRange) -> opendal::Result<(RpRead, opendal::Buffer)> {
            tokio::time::sleep(self.delay).await;
            self.inner.read(range).await
        }
    }

    let tmp = TempDir::new().expect("tempdir");
    let dir_fast_a = tmp.path().join("fast_mirror_a");
    let dir_slow_b = tmp.path().join("slow_mirror_b");
    std::fs::create_dir_all(&dir_fast_a).expect("dir a");
    std::fs::create_dir_all(&dir_slow_b).expect("dir b");

    let fast_a =
        CloudBackend::from_config(&local_fs_config("mirror-a", &dir_fast_a, None, 0)).expect("a");
    let slow_op = Operator::new(services::Fs::default().root(&dir_slow_b.to_string_lossy()))
        .expect("slow op")
        .layer(SlowReadLayer {
            delay: Duration::from_millis(80),
        });
    let slow_b =
        CloudBackend::from_operator(local_fs_config("mirror-b", &dir_slow_b, None, 0), slow_op);

    let router = StorageRouter::new(
        vec![fast_a, slow_b],
        RoutingPolicy::Mirrored {
            backends: vec!["mirror-a".to_owned(), "mirror-b".to_owned()],
            min_ack: 2,
        },
    )
    .expect("router");

    let crypto = MockCryptoEngine::default();
    let dek = crypto.generate_dek().expect("dek");
    let file_id = Uuid::new_v4();
    let plaintext = b"ZeroVault RAID-1 AEAD verified failover payload";
    let aad = ChunkAad {
        file_id,
        chunk_index: 0,
        is_final_chunk: true,
    };
    let (_hdr, wire_chunk) = crypto
        .encrypt_chunk(&dek, aad, plaintext)
        .expect("encrypt chunk");

    let blob_key = BlobObjectKey::from_uuid(Uuid::new_v4());
    router
        .put_blob("/Vault/doc.txt", blob_key.as_str(), wire_chunk.clone())
        .await
        .expect("mirrored put");

    // Flip a bit on the FAST mirror A on disk!
    let path_a = dir_fast_a.join(blob_key.as_str());
    let mut corrupted_a = std::fs::read(&path_a).expect("read mirror-a file");
    let target_idx = corrupted_a.len() - 5;
    corrupted_a[target_idx] ^= 0x40;
    std::fs::write(&path_a, &corrupted_a).expect("write bit-rotted mirror-a");

    // Unverified get_blob wins on fast mirror A and returns corrupted bytes.
    let raw_unverified = router
        .get_blob(blob_key.as_str(), &[])
        .await
        .expect("unverified get");
    assert!(
        crypto
            .decrypt_chunk(&dek, file_id, Some(0), &raw_unverified)
            .is_err()
    );

    // Verified get_blob_verified detects AEAD failure on fast mirror A, marks mirror A unhealthy,
    // and automatically fails over to slower intact mirror B!
    let verified_wire = router
        .get_blob_verified(blob_key.as_str(), &[], |bytes| {
            crypto.decrypt_chunk(&dek, file_id, Some(0), bytes).is_ok()
        })
        .await
        .expect("get_blob_verified must fail over to intact mirror-b");

    let (_hdr2, recovered_pt) = crypto
        .decrypt_chunk(&dek, file_id, Some(0), &verified_wire)
        .expect("decrypt recovered wire");
    assert_eq!(recovered_pt.as_ref(), plaintext);

    // Mirror A is now marked unhealthy and demoted behind Mirror B in candidate_backends!
    assert!(!router.backend("mirror-a").expect("a").is_healthy());
    assert!(router.backend("mirror-b").expect("b").is_healthy());
    assert_eq!(
        router.candidate_backends(&[]),
        vec!["mirror-b".to_owned(), "mirror-a".to_owned()]
    );

    // Now corrupt Mirror B too -> get_blob_verified MUST fail closed with CryptoTamperDetected!
    let path_b = dir_slow_b.join(blob_key.as_str());
    let mut corrupted_b = std::fs::read(&path_b).expect("read mirror-b file");
    corrupted_b[target_idx] ^= 0x01;
    std::fs::write(&path_b, &corrupted_b).expect("write bit-rotted mirror-b");

    let both_bad = router
        .get_blob_verified(blob_key.as_str(), &[], |bytes| {
            crypto.decrypt_chunk(&dek, file_id, Some(0), bytes).is_ok()
        })
        .await
        .expect_err("all mirrors corrupted must fail closed");
    assert!(both_bad.is_tamper());
}

#[tokio::test]
async fn mirrored_manifest_cas_uses_composite_json_etag_and_enforces_optimistic_concurrency() {
    let b1 = CloudBackend::from_config(&base_config("m1", BackendKind::Memory, "/")).expect("m1");
    let b2 = CloudBackend::from_config(&base_config("m2", BackendKind::Memory, "/")).expect("m2");

    let router = Arc::new(
        StorageRouter::new(
            vec![b1, b2],
            RoutingPolicy::Mirrored {
                backends: vec!["m1".to_owned(), "m2".to_owned()],
                min_ack: 2,
            },
        )
        .expect("mirrored router"),
    );

    let v1 = router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            Bytes::from_static(b"ZVM1-rev1"),
            None,
        )
        .await
        .expect("publish rev1");
    let etag1 = v1.etag.expect("composite etag");
    assert!(etag1.starts_with(MIRROR_CAS_PREFIX));

    let stat_v1 = router
        .stat_object(MANIFEST_HEAD_OBJECT_KEY, &[])
        .await
        .expect("stat")
        .expect("exists");
    assert_eq!(stat_v1.etag.as_deref(), Some(etag1.as_str()));

    let v2 = router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            Bytes::from_static(b"ZVM1-rev2"),
            Some(&etag1),
        )
        .await
        .expect("publish rev2");
    let etag2 = v2.etag.expect("etag2");
    assert_ne!(etag1, etag2);

    // Stale CAS write with etag1 fails with StorageConflict.
    let stale_err = router
        .put_manifest_cas(
            MANIFEST_HEAD_OBJECT_KEY,
            Bytes::from_static(b"ZVM1-stale"),
            Some(&etag1),
        )
        .await
        .expect_err("stale composite etag must conflict");
    assert!(matches!(stale_err, ZeroVaultError::StorageConflict(_)));
}

#[tokio::test]
async fn chaos_storage_router_deterministic_faults_and_replica_bitflip_failover() {
    let b1 = CloudBackend::from_config(&base_config("replica-1", BackendKind::Memory, "/"))
        .expect("r1");
    let b2 = CloudBackend::from_config(&base_config("replica-2", BackendKind::Memory, "/"))
        .expect("r2");

    let base_router = Arc::new(
        StorageRouter::new(
            vec![b1, b2],
            RoutingPolicy::Mirrored {
                backends: vec!["replica-1".to_owned(), "replica-2".to_owned()],
                min_ack: 2,
            },
        )
        .expect("base router"),
    );

    let chaos = ChaosStorageRouter::from_storage_router(base_router.clone(), 0xDEAD_BEEF_CAFE_1234, 3_000);

    let crypto = MockCryptoEngine::default();
    let dek = crypto.generate_dek().expect("dek");
    let file_id = Uuid::new_v4();
    let key = BlobObjectKey::from_uuid(Uuid::new_v4());
    let plaintext = b"chaos-resilient-encrypted-chunk";
    let (_hdr, wire) = crypto
        .encrypt_chunk(
            &dek,
            ChunkAad {
                file_id,
                chunk_index: 0,
                is_final_chunk: true,
            },
            plaintext,
        )
        .expect("encrypt");

    // Upload under 30% packet loss using bounded retry_transient.
    retry_transient(32, Duration::ZERO, || {
        let w = wire.clone();
        async { chaos.put_blob("/Chaos/file.bin", key.as_str(), w).await }
    })
    .await
    .expect("put_blob converges under 30% chaos");

    // Inject targeted bit-flip on replica-1 and disable random drops for deterministic bit-rot check.
    chaos.set_failure_rate_bps(0);
    chaos.corrupt_backend("replica-1", 40, 0x80);

    let verified = chaos
        .get_blob_verified(key.as_str(), &[], |candidate_wire| {
            crypto
                .decrypt_chunk(&dek, file_id, Some(0), candidate_wire)
                .is_ok()
        })
        .await
        .expect("chaos verified read fails over from corrupted replica-1 to replica-2");

    let (_hdr2, pt) = crypto
        .decrypt_chunk(&dek, file_id, Some(0), &verified)
        .expect("decrypt");
    assert_eq!(pt.as_ref(), plaintext);
    assert!(chaos.is_backend_degraded("replica-1"));
    assert_eq!(chaos.stats().injected_bit_flips, 1);

    let health = chaos.list_backend_health().await.expect("health");
    let r1_health = health
        .iter()
        .find(|h| h.backend_id == "replica-1")
        .expect("r1 health");
    assert!(!r1_health.healthy);
}

#[tokio::test]
async fn targeted_longest_prefix_and_quota_pooled_strategies_and_tampered_secret_rejection() {
    let tmp = TempDir::new().expect("tempdir");

    // 1. Tampered wrapped OAuth token in SecretStore must fail closed with CryptoTamperDetected.
    let crypto = MockCryptoEngine::default();
    let secrets = InMemorySecretStore::default();
    let bundle = OAuthTokenBundle {
        provider: OAuthProviderPreset::GoogleDrive,
        access_token: RedactedSecret::new("secret-access"),
        refresh_token: None,
        token_type: "bearer".to_owned(),
        expires_at: None,
        scopes: OAuthProviderPreset::GoogleDrive.default_scopes(),
        client_id: Some("cid".to_owned()),
        client_secret: None,
    };
    persist_tokens(
        &bundle,
        &secrets,
        &crypto,
        DEFAULT_TOKEN_SECRET_SERVICE,
        "tampered-acct",
    )
    .await
    .expect("persist");
    let mut raw = secrets
        .get_secret(DEFAULT_TOKEN_SECRET_SERVICE, "tampered-acct")
        .await
        .expect("get")
        .expect("present")
        .to_vec();
    let last = raw.len() - 1;
    raw[last] ^= 0xFF;
    secrets
        .set_secret(DEFAULT_TOKEN_SECRET_SERVICE, "tampered-acct", &raw)
        .await
        .expect("overwrite tampered");

    let mut bad_gd_cfg = base_config("gd", BackendKind::GoogleDrive, "/vault");
    bad_gd_cfg.secret_account_key = Some("tampered-acct".to_owned());
    let tamper_err =
        CloudBackend::from_config_with_secrets(&bad_gd_cfg, Some(&secrets), Some(&crypto))
            .await
            .expect_err("tampered token must fail closed");
    assert!(tamper_err.is_tamper());

    // 2. Targeted longest segment-aware prefix routing + sync_used_bytes + probe_all_health.
    let dir_def = tmp.path().join("def");
    let dir_fin = tmp.path().join("fin");
    let dir_arch = tmp.path().join("arch");
    let b_def = CloudBackend::from_config(&local_fs_config("def", &dir_def, None, 0)).expect("def");
    let b_fin = CloudBackend::from_config(&local_fs_config("fin", &dir_fin, None, 0)).expect("fin");
    let b_arch =
        CloudBackend::from_config(&local_fs_config("arch", &dir_arch, None, 0)).expect("arch");

    let targeted = StorageRouter::new(
        vec![b_def, b_fin, b_arch],
        RoutingPolicy::Targeted {
            prefix_routes: vec![
                ("/Finance/".to_owned(), "fin".to_owned()),
                ("Finance/2026/".to_owned(), "arch".to_owned()),
            ],
            default_backend: "def".to_owned(),
        },
    )
    .expect("targeted router");

    let ka = BlobObjectKey::from_uuid(Uuid::new_v4());
    let kb = BlobObjectKey::from_uuid(Uuid::new_v4());
    let kc = BlobObjectKey::from_uuid(Uuid::new_v4());

    assert_eq!(
        targeted
            .put_blob("/Finance/2026/q4.pdf", ka.as_str(), Bytes::from_static(b"a"))
            .await
            .expect("ka")
            .replicas[0]
            .backend_id,
        "arch"
    );
    assert_eq!(
        targeted
            .put_blob("/Finance/q1.pdf", kb.as_str(), Bytes::from_static(b"bb"))
            .await
            .expect("kb")
            .replicas[0]
            .backend_id,
        "fin"
    );
    assert_eq!(
        targeted
            .put_blob("/FinanceBackup/old.zip", kc.as_str(), Bytes::from_static(b"ccc"))
            .await
            .expect("kc")
            .replicas[0]
            .backend_id,
        "def"
    );

    let fresh_arch =
        CloudBackend::from_config(&local_fs_config("arch2", &dir_arch, None, 0)).expect("arch2");
    assert_eq!(fresh_arch.sync_used_bytes().await.expect("sync"), 1);
    let probed = targeted.probe_all_health().await.expect("probe_all_health");
    assert_eq!(probed.len(), 3);
    assert!(probed.iter().all(|h| h.healthy));

    // 3. QuotaPooled MaxAvailable balancing.
    let small = CloudBackend::from_config(&base_config("small", BackendKind::Memory, "/"))
        .expect("small");
    let mut small_cfg = base_config("small", BackendKind::Memory, "/");
    small_cfg.quota_limit_bytes = Some(10 * 1024);
    let mut large_cfg = base_config("large", BackendKind::Memory, "/");
    large_cfg.quota_limit_bytes = Some(16 * 1024);
    drop(small);

    let pooled = StorageRouter::new(
        vec![
            CloudBackend::from_config(&small_cfg).expect("small"),
            CloudBackend::from_config(&large_cfg).expect("large"),
        ],
        RoutingPolicy::QuotaPooled {
            pool_backends: vec!["small".to_owned(), "large".to_owned()],
        },
    )
    .expect("pooled")
    .with_quota_strategy(QuotaSelectionStrategy::MaxAvailable);

    let p1 = pooled
        .put_blob(
            "/x",
            BlobObjectKey::from_uuid(Uuid::new_v4()).as_str(),
            Bytes::from(vec![1u8; 8 * 1024]),
        )
        .await
        .expect("p1");
    assert_eq!(p1.replicas[0].backend_id, "large");

    let p2 = pooled
        .put_blob(
            "/y",
            BlobObjectKey::from_uuid(Uuid::new_v4()).as_str(),
            Bytes::from(vec![2u8; 8 * 1024]),
        )
        .await
        .expect("p2");
    assert_eq!(p2.replicas[0].backend_id, "small");
}

