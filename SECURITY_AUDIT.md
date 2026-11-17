# Zerovault Security & Verification Audit (`SECURITY_AUDIT.md`)

**Project:** `cloud.entropy.rs / Zerovault`  
**Audit Date:** 2026-11-17  
**Auditor:** `Agent-SecQA` (Red-Team & Verification Auditor)  
**Scope:** Static source audit of all workspace crates (`crates/zerovault-{types,crypto,storage,vfs,core,daemon,cli,ui}/src/**`), packaging scripts (`packaging/**`), and live end-to-end / red-team integration verification (`tests/e2e/**`).

---

## 1. Executive Summary

Zerovault enforces strong cryptographic foundations (`aws-lc-rs` AES-256-GCM with mandatory runtime CPUID AES/GHASH verification, Argon2id >= 64 MiB / 3 / 4, HKDF-SHA256 domain separation, 25-byte `ChunkAad` chunk/file/EOF binding, and strict zero-knowledge remote object key grammar), clean Rust 2024 hygiene (`0` clippy warnings under `-D warnings`, `0` hand-written `unsafe` blocks in production crate sources, `0` `std::env::set_var`/`remove_var` calls), and passes all end-to-end multi-cloud, failover, spillover, conflict-preservation, and daemon IPC tests.

However, the red-team audit identified **0 Critical**, **3 High**, **4 Medium**, **6 Low**, and **3 Informational** findings requiring remediation or architectural attention before production release—most notably:
1. **Manifest rollback/downgrade acceptance** in `SyncEngine::sync_once` when an untrusted cloud replays an older sealed manifest revision (`H-01`).
2. **Multi-revision CAS failure under `RoutingPolicy::Mirrored`** caused by comparing a single scalar ETag across heterogeneous/synthetic mirror ETags (`H-02`).
3. **Post-lock plaintext cache/staging exposure** where `SyncEngine::read_range` / `write_range` do not check `crypto.is_unlocked()` on cache hits and dirty staging `.part` files persist plaintext on local disk (`H-03`).

---

## 2. Automated Verification Results

All checks were executed on `x86_64` Windows (`CARGO_TARGET_DIR="target/swarm/agent-secqa"`):

### 2.1 Workspace Clippy (`-D warnings`)
```powershell
$env:CARGO_TARGET_DIR = "target/swarm/agent-secqa"; cargo clippy --workspace --all-targets -- -D warnings
```
- **Result:** `Command exited with code 0` (0 warnings, 0 errors across all 9 workspace packages).

### 2.2 End-to-End & Red-Team Suite (`zerovault-e2e`)
```powershell
$env:CARGO_TARGET_DIR = "target/swarm/agent-secqa"; cargo test -p zerovault-e2e -- --nocapture
```
- **Result:** `Command exited with code 0` — **11 passed, 0 failed, 0 ignored**:
  - `tests/e2e_multicloud_zero_knowledge.rs` (6 passed, 6.10s in workspace run / 6.02s standalone):
    1. `e2e_zero_knowledge_remote_audit_and_o1_cross_chunk_hydration` — Real `AwsLcCryptoEngine` (Argon2id 64 MiB/3/4), `SqliteMetadataStore` WAL, `Mirrored` `LocalFs` clouds (`cloud-a`, `cloud-b`), > 9 MiB 3-chunk file `/Finance/Confidential/TopSecret_TaxReturn_2026.pdf`, byte-level audit confirming zero plaintext leaks and strict `validate_remote_object_key` compliance on every remote file, dehydration + O(1) 64 KiB read across 4 MiB boundary leaving chunk 2 unhydrated.
    2. `e2e_fail_closed_aead_tamper_bitflip_swap_and_manifest_corruption` — Real AEAD rejection (`ZeroVaultError::CryptoTamperDetected`) on 1-bit `.zv` payload flip, chunk 0 <-> chunk 1 swap, and 1-byte `manifests/head.zvm` corruption.
    3. `e2e_mirrored_raid1_outage_failover` — Complete wipe of `cloud-a` followed by seamless multi-chunk recovery from `cloud-b`.
    4. `e2e_quota_pooled_spillover_reassembly` — Automatic spillover of > 9.5 MiB 3-chunk file across `cloud-c` (9 MiB cap) and `cloud-d` (20 MiB cap) with exact reassembly.
    5. `e2e_concurrent_device_conflict_preservation` — Independent `device-win` and `device-arch` `SyncEngine` instances preserving both remote `v2` and `budget (conflict-device-arch-...).xlsx` with recorded `ConflictRecord`.
    6. `e2e_full_daemon_ipc_production_stack_lifecycle` — Full `DaemonRuntime` (`CoreSyncEngineFactory`, `AwsLcCryptoEngine`, `InMemorySecretStore`, `with_mock_vfs(true)`) + `IpcServer`/`IpcClient` (`InitVault -> AddRemote -> Mount -> Status -> SyncNow -> LockVault -> Shutdown`).
  - `tests/redteam_security_audit.rs` (5 passed, 4.59s):
    1. `redteam_cross_file_chunk_and_dek_transplant_rejected`
    2. `redteam_kdf_downgrade_exact_4mib_final_flag_and_manifest_rev_tamper_rejected`
    3. `redteam_storage_router_and_vfs_path_traversal_rejected`
    4. `redteam_secret_redaction_and_oauth_ssrf_csrf_guards`
    5. `redteam_daemon_ipc_frame_bounds_and_os_native_pipe_or_uds_lifecycle`

### 2.3 Full Workspace Test Suite
```powershell
$env:CARGO_TARGET_DIR = "target/swarm/agent-secqa"; cargo test --workspace
```
- **Result:** `Command exited with code 0` — **80 passed, 0 failed, 1 ignored** on Windows host:
  - `zerovault-cli`: 3 passed
  - `zerovault-core`: 10 passed
  - `zerovault-crypto`: 9 passed
  - `zerovault-daemon`: 5 passed
  - `zerovault-e2e`: 11 passed (6 + 5)
  - `zerovault-storage`: 20 passed
  - `zerovault-types`: 6 passed
  - `zerovault-ui`: 2 passed
  - `zerovault-vfs`: 1 unit passed + 13 `windows_vfs_tests` passed (1 `#[ignore]`: `live_cfapi_sync_root_mount_and_unmount_integration`, requires live Windows Explorer SyncRoot context; `linux_vfs_tests` gated by `#![cfg(target_os = "linux")]`).

---

## 3. Positive Security Controls Verification Matrix

| Control Area | Verification Outcome | Evidence / Location |
|---|---|---|
| Hardware Crypto Enforcement | **PASS** | `crates/zerovault-crypto/src/hw.rs:107-135` enforces `aes` + `pclmulqdq` (`x86_64`/`x86`) and `aes` + `pmull` (`aarch64`) via `cpufeatures` + `std::arch`, failing closed with `HardwareAccelerationUnavailable`; called at `AwsLcCryptoEngine::new()` and every crypto entry point. |
| Argon2id Policy Floor | **PASS** | `crates/zerovault-types/src/wire.rs:45-49,170-182` & `crates/zerovault-crypto/src/engine.rs:216-243` reject `m_cost_kib < 65_536`, `t_cost < 3`, or `p_cost < 4` in `VaultHeader::decode`, `init_vault`, `unlock_with_passphrase`, `derive_master_seed`, and `publish_vault_header`. |
| HKDF-SHA256 Domain Separation | **PASS** | `crates/zerovault-crypto/src/engine.rs:103-125` derives distinct 256-bit keys (`MasterKek`, `ManifestKey`, `TokenWrapKey`, `HeaderVerifierKey`) using `argon2_salt` and canonical info labels (`zerovault.v1.{kek,manifest,token-wrap,verifier}`). |
| Nonce Generation & AEAD AADs | **PASS** | `crates/zerovault-crypto/src/engine.rs:201-207` generates fresh 96-bit CSPRNG nonces via `aws_lc_rs::rand::fill`. 25-byte `ChunkAad` (`file_id \|\| chunk_index LE \|\| is_final_chunk`), 25-byte `ZV-DEK-V1 \|\| file_id`, 28-byte `ZVM1 \|\| vault_id \|\| revision LE`, and 20-byte `ZVH1 \|\| vault_id` match `SPEC_CRYPTO.md`. |
| Fail-Closed Decrypt Scrubbing | **PASS** | `crates/zerovault-crypto/src/engine.rs:272-292,651-665` zeroizes `out_plaintext` and clears `BytesMut` immediately on GCM tag mismatch; `ChunkHeader::decode` validates `wire_chunk.len() == header.expected_wire_len()` before buffer allocation. |
| Key Wrapper Hygiene & Redacted `Debug` | **PASS** | `MasterSeed`, `MasterKek`, `ManifestKey`, `TokenWrapKey`, `HeaderVerifierKey`, `KeyRingState`, `DekBytes`, `RedactedSecret`, `OAuthTokenBundle`, `OAuthProviderConfig`, `AddRemoteParams`, and `DaemonRequest` implement `Zeroize`/`ZeroizeOnDrop` (where key-bearing) and redact secrets (`[REDACTED]`) in `Debug`. |
| Zero Plaintext/Secret Logging | **PASS** | Static scan of all `tracing::*` calls across `crates/**` confirmed zero passphrases, OAuth tokens, key bytes, or `virtual_hint_path`/filenames logged at `INFO`/`DEBUG` (note: Windows/Linux VFS debug traces emit local path names only at `debug!` during local placeholder/watcher diagnostics). |
| Remote Key Grammar Enforcement | **PASS** | `crates/zerovault-types/src/wire.rs:631-644` and `crates/zerovault-storage/src/{backend,router}.rs` enforce `validate_remote_object_key` on every `put`/`get`/`stat`/`delete`/`put_manifest_cas` before invoking OpenDAL. |
| OAuth2 + PKCE SSRF & CSRF | **PASS** | `crates/zerovault-storage/src/oauth.rs:307-323,411-418` configures `redirect::Policy::none()`, S256 PKCE, and `subtle::ConstantTimeEq` CSRF checks. |
| SQLite WAL & Foreign Keys | **PASS** | `crates/zerovault-core/src/db.rs:121-140` enforces `PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000`, and parameterized SQL queries. |
| IPC Frame Bounds & Rust 2024 Hygiene | **PASS** | `crates/zerovault-daemon/src/ipc.rs:204-259` validates `1..=16 MiB` (`MAX_IPC_FRAME_BYTES`) before allocating; `0` `std::env::set_var`/`remove_var` and `0` hand-written `unsafe` blocks in production `crates/**/src/*.rs` (two `#[allow(unsafe_op_in_unsafe_fn)]` attributes exist solely for `cpufeatures::new!` macros in `hw.rs:14,47`). |

---

## 4. Detailed Findings

### High Severity

#### [H-01] Manifest Rollback / Downgrade Attack Accepted by `SyncEngine::sync_once`
- **Location:** `crates/zerovault-core/src/engine.rs:315-360` (specifically lines `333-359`)
- **Description:** During `sync_once()`, if remote `manifests/head.zvm` has a changed ETag, `SyncEngine` decrypts the manifest via `open_manifest` and verifies `manifest.vault_id`. It computes `remote_changed` (`manifest.revision > local_rev || ...`), skipping `ConflictResolver::reconcile_remote_manifest` when `manifest.revision < local_rev`. However, lines `356-358` unconditionally overwrite the local cursor:
  ```rust
  self.meta
      .update_manifest_cursor(manifest.revision, remote_ver.etag.clone())
      .await?;
  ```
  An active adversary on an untrusted cloud backend can replace `manifests/head.zvm` with an older genuinely-sealed manifest (`revision < local_rev`) from an earlier snapshot. `sync_once()` silently rewinds `manifest_cursor.revision` and `remote_etag` to the old revision without raising an error; the client's next write then publishes `old_rev + 1` via CAS against the attacker's replayed ETag, permanently dropping intervening file creations/updates.
- **Remediation:** In `SyncEngine::sync_once`, after `open_manifest` and `vault_id` check, enforce monotonic revision progression: if `local_rev > 0 && manifest.revision < local_rev`, fail closed with `Err(ZeroVaultError::CryptoTamperDetected(...))`. Optionally also validate `parent_manifest_id` lineage.

#### [H-02] `StorageRouter::put_manifest_cas` Fails on Revision >= 2 Under `RoutingPolicy::Mirrored`
- **Location:** `crates/zerovault-storage/src/router.rs:556-641` (`stat_futs` check at lines `566-597`, ETag return at line `626`, per-mirror `put_object_cas` at line `602`); `crates/zerovault-storage/src/backend.rs:463-528, 632-644`
- **Description:** Under `RoutingPolicy::Mirrored`, `put_manifest_cas` writes `manifests/head.zvm` to each mirror. Each backend produces an independent ETag (`CloudBackend::record_etag_after_write` generates a distinct `Uuid::new_v4()` per backend on `LocalFs`/`Memory`, and heterogeneous providers like S3 + Google Drive also generate unrelated ETags). `router.rs:626` returns only `versions.into_iter().next()`, which `SyncEngine` persists in `manifest_cursor.remote_etag`. On any subsequent manifest publish (`rev >= 2`, `expected_etag = Some(etag_0)`), `router.rs:574-581` stats all mirrors and immediately fails with `ZeroVaultError::StorageConflict("manifest ETag mismatch for manifests/head.zvm")` as soon as mirror 1 returns `etag_1 != etag_0` (and line `602` also passes `etag_0` to mirror 1's `put_object_cas`).
- **Impact:** Multi-revision writes (`flush` twice, `sync_once` after `flush`, or multi-device updates) cannot advance past manifest revision `1` when using `RoutingPolicy::Mirrored` across 2+ backends. (Note: `tests/e2e/tests/e2e_multicloud_zero_knowledge.rs` specifically exercises single-publish setup in Test 2 so Mirrored tamper checks pass pending this fix.)
- **Remediation:** Track per-backend manifest ETags (e.g., serialized map in `manifest_cursor.remote_etag` or primary-mirror CAS arbitration) so each mirror validates against its own last-observed ETag.

#### [H-03] Post-Lock Plaintext Cache Bypass in `SyncEngine` & Unencrypted Local Dirty Staging Files
- **Location:** `crates/zerovault-core/src/engine.rs:878-965` (`read_range`), `967-1030` (`write_range`); `crates/zerovault-core/src/cache.rs:19-30, 204-270`; `crates/zerovault-daemon/src/service.rs:812-823`
- **Description:**
  1. `SyncEngine::read_range` and `write_range` do not check `self.crypto.is_unlocked()` before serving RAM LRU hits (`self.cache.get`) or dirty staging `.part` files (`self.cache.read_dirty_chunk_into`). Only a RAM/disk cache miss reaches `unwrap_dek`, which fails with `VaultLocked`. While `DaemonRuntime::lock_and_unmount_locked` mitigates this at the daemon layer by unmounting and dropping `sync_bundle`, any direct holder of `Arc<SyncEngine>` (or racy/unmounted VFS callback) can continue reading/writing cached plaintext after `crypto.lock_vault()`.
  2. `ChunkCache` stores plaintext chunks in RAM as `bytes::Bytes` (not `Zeroizing`) without scrubbing on eviction or `Drop`.
  3. `ChunkCache::write_dirty_chunk_slice` and `write_full_dirty_chunk` write unencrypted plaintext chunk bytes to `staging_dir/dirty/<inode>/<chunk_index>.part` (matching `ARCHITECTURE.md` §2.5's noted "optional encrypted disk cache" gap). Additionally, `ChunkCache::new` and dirty `.part` creation do not enforce `0o700`/`0o600` Unix permissions or explicit Windows user ACLs when `SyncEngine` is constructed outside `DaemonRuntime`. If `LockVault` is invoked while offline dirty writes remain un-synced, unencrypted `.part` files stay on disk.
- **Remediation:** Check `if !self.crypto.is_unlocked() { return Err(ZeroVaultError::VaultLocked); }` at entry to `read_range`/`write_range`/`setattr`; implement `Drop` on `ChunkCache` to clear RAM cache (and store `Zeroizing<Vec<u8>>` or `Arc<Zeroizing<...>>`); encrypt staged `.part` chunks under a session/ephemeral or `MasterKek`-wrapped staging key and apply strict `0o700`/`0o600` (Unix) / owner-only DACL (Windows) permissions.

---

### Medium Severity

#### [M-01] `SyncEngine::flush(inode)` Publishes Incomplete Metadata for Other Concurrently-Dirty Inodes
- **Location:** `crates/zerovault-core/src/engine.rs:751-790` (`publish_manifest_locked`) and `1259-1298` (`flush`)
- **Description:** Calling `flush(inode_a)` uploads dirty blobs only for `inode_a`, then calls `publish_manifest_locked()`, which serializes **all** rows from `meta.list_all_inodes()` into the remote manifest. If `inode_b` is concurrently `DirtyLocal` (written via `write_range` without `flush` yet), `inode_b` is published to `manifests/head.zvm` with its new `size`/`version` paired with `wrapped_dek = None` / `chunks = []` (or stale chunks from an earlier revision).
- **Remediation:** Either flush all pending dirty inodes before sealing a manifest snapshot, or maintain last-committed manifest node snapshots for dirty inodes not yet uploaded.

#### [M-02] Potential `BoundedBufferPool` Deadlock When `max_concurrent_transfers == 1`
- **Location:** `crates/zerovault-core/src/engine.rs:610, 635, 662`; `crates/zerovault-core/src/pool.rs:54, 67-90`
- **Description:** `SyncEngine::upload_dirty_inode_blobs` sets `concurrency = (self.pool.max_slots() / 2).max(1)` and acquires `pt_buf` (`engine.rs:635`) **while holding** it across `let mut wire_buf = self.pool.acquire_buffer().await?` (`engine.rs:662`) from the same `BoundedBufferPool` semaphore. If `SyncEngineConfig::max_concurrent_transfers` is set to `1`, the single worker holds the sole permit for `pt_buf` and deadlocks indefinitely waiting for `wire_buf`. (Default `8` uses `4 * 2 = 8` serialized under `sync_lock`, avoiding deadlock unless `max_concurrent_transfers == 1` or the pool is shared with concurrent dual-buffer callers.)
- **Remediation:** Clamp `BoundedBufferPool::new(max_slots)` to `>= 2` when used for dual-buffer encryption, or acquire both permits atomically (`semaphore.acquire_many_owned(2)`), or perform `upload_dirty_inode_blobs` with `(max_slots / 2)` bounded only when `max_slots >= 2`.

#### [M-03] Unbounded Remote Object Download (`operator.read`) Enables OOM DoS by Malicious Cloud
- **Location:** `crates/zerovault-storage/src/backend.rs:531-545` (`CloudBackend::get_object`)
- **Description:** `CloudBackend::get_object` invokes `self.operator.read(object_key).await`, buffering the entire response in memory without an upper byte bound before `VaultHeader::decode`, `ChunkHeader::decode`, or `open_manifest` checks the size. A malicious or compromised cloud server returning a multi-gigabyte body for `vault/header.zvh` (expected 112 B) or a `.zv` chunk (max 4,194,352 B) can exhaust client/daemon RAM.
- **Remediation:** Enforce strict maximum download limits using `operator.read_with(key).range(0..max_len)` or a bounded streaming reader (`VAULT_HEADER_LEN` for `.zvh`, `MAX_ENCRYPTED_CHUNK_SIZE` for `.zv`, and a configurable cap such as `64 MiB` for `.zvm`).

#### [M-04] Windows Named Pipe Server Uses Default Process DACL Without Explicit User-SID Restriction
- **Location:** `crates/zerovault-daemon/src/ipc.rs:428-450, 563-593`
- **Description:** On Windows, `IpcServer::bind` creates `\\.\pipe\zerovaultd` via `tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(true).reject_remote_clients(true).create(&pipe_name)`. While `reject_remote_clients(true)` blocks network SMB clients and `first_pipe_instance(true)` prevents pre-emption once `zerovaultd` owns the pipe, no explicit `SECURITY_ATTRIBUTES` (user-SID-restricted DACL) is supplied, and the global `\\.\pipe\zerovaultd` name is shared across all Windows sessions on multi-user hosts (meaning an unprivileged local user could pre-create the pipe before `zerovaultd` starts to intercept `InitVault`/`UnlockVault` passphrases).
- **Remediation:** Use a per-user SID-scoped pipe name (e.g., `\\.\pipe\zerovaultd-<SID>`) and/or supply explicit `SECURITY_ATTRIBUTES` restricting access strictly to the current user SID.

---

### Low Severity

#### [L-01] Interactive CLI Passphrase Prompt Echoes Plaintext to Terminal
- **Location:** `crates/zerovault-cli/src/cli.rs:199-220` (`read_secret_line`)
- **Description:** When `zv init` or `zv unlock` is invoked interactively (without `--passphrase-stdin`), `read_secret_line` reads from `BufRead` without disabling terminal echo (`ENABLE_ECHO_INPUT` on Windows / `termios` `ECHO` on Unix), visibly displaying typed passphrases on screen.
- **Remediation:** Disable console echo when stdin is a TTY (e.g. `rpassword::prompt_password` or platform console mode toggle) while preserving `BufRead` injection for tests.

#### [L-02] Transient Unzeroized Plaintext/Secret `Vec<u8>`/`String` Buffers in IPC & VFS Paths
- **Location:**
  - `crates/zerovault-types/src/ipc.rs:67-90` (`AddRemoteParams.secret: Option<String>`), `115-157` (`DaemonRequest::InitVault`/`UnlockVault` `passphrase: String`); `crates/zerovault-cli/src/cli.rs:236-255` (`pass.to_string()`).
  - `crates/zerovault-vfs/src/linux/fs.rs:235-240` (`DirtyWriteBuffer::buf: Vec<u8>`) and `844-863` (`handle_read` `out: Vec<u8>`).
  - `crates/zerovault-vfs/src/windows/filter.rs:631` (`let mut buf = vec![0u8; MAX_HYDRATION_STREAM_SLICE]` in `stream_local_file_to_backend`).
  - `crates/zerovault-core/src/pool.rs:181-189` (`PooledBuffer::drop` calls `buf.as_mut().zeroize()`, scrubbing `0..len` but not spare capacity `len..cap` if a caller shrunk `buf` prior to drop).
- **Description:** Although `DaemonRuntime::dispatch_inner` immediately moves IPC passphrases/secrets into `RedactedSecret`, deserialized `DaemonRequest`/`AddRemoteParams` variants themselves do not implement `ZeroizeOnDrop` on early error paths; similarly, VFS 4 MiB streaming buffers in `DirtyWriteBuffer` and `stream_local_file_to_backend` are plain `Vec<u8>`. Additionally, `LinuxFuseFilesystem::handle_read` loops up to `size: u32` if called directly outside kernel FUSE `max_read` limits.
- **Remediation:** Wrap `DirtyWriteBuffer::buf` and `stream_local_file_to_backend` staging buffers in `Zeroizing<Vec<u8>>`, scrub `DirtyWriteBuffer` on `flush_with`/`Drop`, implement `ZeroizeOnDrop` on `DaemonRequest`/`AddRemoteParams` secret fields, and scrub full spare capacity in `PooledBuffer::drop` (if `buf.capacity() > 0`).

#### [L-03] Unix Domain Socket `/tmp/zerovault-<uid>` Fallback Directory Lacks Ownership Validation
- **Location:** `crates/zerovault-daemon/src/ipc.rs:192-201, 306-344, 415-421`
- **Description:** When `XDG_RUNTIME_DIR` is unset, `default_unix_socket_path` falls back to `/tmp/zerovault-<uid>/zerovaultd.sock`. `prepare_unix_socket_dir_and_path` creates `parent` and calls `set_permissions(0o700)` without checking that an already-existing directory is not a symlink and is owned by `geteuid()`. Also `set_unix_socket_permissions(0o600)` runs immediately after `UnixListener::bind(&path)` rather than enforcing umask beforehand.
- **Remediation:** Verify `symlink_metadata(parent)` is a real directory owned by `geteuid()` (failing closed if not), and set tight process/thread socket permissions prior to `bind()`.

#### [L-04] Production `.expect()` Calls in Linux FUSE `RuntimeBridge` & `PooledBuffer::deref`
- **Location:**
  - `crates/zerovault-vfs/src/linux/fs.rs:456, 480` (`RuntimeBridge::new_owned()` and `block_on()`).
  - `crates/zerovault-core/src/pool.rs:167, 175` (`PooledBuffer::deref` / `deref_mut` — unreachable after drop in safe Rust).
- **Description:** Outside test code, only these 4 `.expect()` calls exist across the entire workspace. In `linux/fs.rs`, thread-spawn failure or Tokio runtime init failure inside a FUSE callback worker panics the FUSE thread instead of returning `Errno::EIO`.
- **Remediation:** Propagate initialization/bridge errors in `LinuxFuseFilesystem::block_on` as `Result<..., Errno>` (`Errno::EIO`).

#### [L-05] OAuth2 Loopback Listener Single-Request Abort & Non-HTTPS Endpoint Acceptance
- **Location:** `crates/zerovault-storage/src/oauth.rs:334-337, 633-766, 768-795`
- **Description:**
  1. In `accept_callback_code`, only non-`/callback` GET paths (such as `/favicon.ico`) continue listening; any malformed local TCP connection, non-GET `/callback`, or mismatched CSRF probe terminates the listener immediately (local DoS against an active OAuth browser flow), and `read_http_request` lacks a short per-connection read deadline.
  2. `OAuthProviderConfig` (and S3/WebDAV `BackendConfig.endpoint`) accepts plain `http://` URLs for non-loopback hosts without requiring TLS.
- **Remediation:** Continue listening after invalid/forged local probes (with per-connection read timeout) until overall timeout or valid state+code succeeds; reject non-HTTPS non-loopback endpoints unless explicitly enabled for local testing.

#### [L-06] Loopback TCP IPC Endpoint Has No Session Cookie Authentication
- **Location:** `crates/zerovault-daemon/src/ipc.rs:152-160, 388-405`
- **Description:** While `IpcEndpoint` restricts TCP strictly to loopback (`127.0.0.1`/`::1`), running `zerovaultd --endpoint tcp://127.0.0.1:<port>` exposes unauthenticated IPC commands (`Status`, `LockVault`, `Shutdown`, etc.) to any local user or local process on shared hosts.
- **Remediation:** Restrict `--endpoint tcp://...` to explicit `--allow-insecure-loopback-tcp` / test builds, or enforce a random `0600` IPC cookie handshake.

---

### Informational

#### [I-01] Per-File DEK Reuse Across Incremental Chunk Updates vs. `SPEC_CRYPTO.md` §4.2
- **Location:** `crates/zerovault-core/src/engine.rs:586-594`; `SPEC_CRYPTO.md:84`
- **Details:** `SPEC_CRYPTO.md` §4.2 specifies a fresh DEK per file revision. `SyncEngine::upload_dirty_inode_blobs` intentionally reuses the existing `wrapped_dek` when updating a subset of chunks so unmodified 4 MiB chunks need not be re-encrypted, while generating fresh 96-bit CSPRNG nonces and fresh `blob_id`s for every re-encrypted chunk. Safe within standard 96-bit random-nonce AES-GCM invocation bounds ($< 2^{32}$ encryptions per DEK); document this optimization in `SPEC_CRYPTO.md` or rotate DEK after high invocation counts.

#### [I-02] `persist_session` Stores `master_seed` Integrity-Protected Inside OS Keyring
- **Location:** `crates/zerovault-crypto/src/engine.rs:406-509`
- **Details:** The 129-byte `ZVS1` session secret placed into `SecretStore` stores `master_seed` alongside an AES-256-GCM tag over `vault_id` keyed by `header_verifier_key`. Confidentiality relies on the OS credential store (Windows Credential Manager / Linux Secret Service / `keyutils`), while integrity is cryptographically enforced on `restore_session`.

#### [I-03] Mirrored Read Does Not Auto-Fallback on Bit-Rot Tamper, No Remote Blob GC, and Tauri CSP `'unsafe-inline'`
- **Location:** `crates/zerovault-storage/src/router.rs:368-444, 736-758`; `crates/zerovault-core/src/engine.rs`; `crates/zerovault-ui/tauri.conf.json:23`
- **Details:**
  - `StorageRouter::get_blob` races mirrors via `select_ok` without verifying AEAD (zero-knowledge storage has no DEK). If one mirror suffers silent bit-rot and responds first, `SyncEngine` safely fails closed (`CryptoTamperDetected`) rather than automatically retrying alternate mirrors.
  - Replaced/deleted `.zv` chunk blobs and historical `.zvm` manifests accumulate monotonically on remote storage until garbage collection / retention pruning is implemented.
  - `zerovault-ui/tauri.conf.json` permits `'unsafe-inline'` in `script-src`/`style-src` for its self-contained `dist/index.html`; `dist/index.html` safely uses `textContent` and DOM element creation with zero `innerHTML` or `eval` sinks. Moving inline JS/CSS to external bundled assets allows dropping `'unsafe-inline'`.

---

## 5. Remediation Verification Log (`Lead-Architect`)

| Finding ID | Status | Implemented Fix & Verification |
|---|---|---|
| `[H-01]` | **Remediated** | `SyncEngine::sync_once` ([`crates/zerovault-core/src/engine.rs`](file:///c:/Users/Nick/Downloads/cloud.entropy.rs/crates/zerovault-core/src/engine.rs)) now rejects `manifest.revision < local_rev` with `ZeroVaultError::CryptoTamperDetected` before mutating metadata or cursors. Verified by `redteam_remediation_mirrored_cas_rollback_locked_cache_pool_and_bounded_get`. |
| `[H-02]` | **Remediated** | `StorageRouter::stat_object` and `put_manifest_cas` ([`crates/zerovault-storage/src/router.rs`](file:///c:/Users/Nick/Downloads/cloud.entropy.rs/crates/zerovault-storage/src/router.rs)) now use per-mirror composite ETags (`zv-mirror-cas:<json>`), allowing multi-revision (`rev 1 -> 2 -> 3+`) Mirrored RAID-1 publishes while preserving conflict detection (`StorageConflict`). Verified by E2E regression test. |
| `[H-03]` | **Remediated (RAM & Lock Gate)** | `SyncEngine` now checks `ensure_unlocked()` (calling `cache.clear_ram()`) across `read_range`, `write_range`, `setattr`, `create_entry`, `mkdir`, `unlink`, `rmdir`, `rename`, `flush`, `pin`, `unpin`, `dehydrate`, and `sync_once`; `ChunkCache` wraps RAM entries in `Arc<Zeroizing<Vec<u8>>>`, clears on `Drop`, and restricts Unix dirty staging permissions (`0o700`/`0o600`). Note: offline dirty `.part` staging files on disk remain plaintext until flushed & encrypted remotely (cleared upon flush). |
| `[M-01]` | **Remediated** | `SyncEngine` tracks `committed_nodes` so `publish_manifest_locked(&[inode])` preserves previously committed node snapshots (or omits new uncommitted files) for other concurrently `DirtyLocal` inodes. Verified in E2E regression test. |
| `[M-02]` | **Remediated** | `BoundedBufferPool::acquire_pair` ([`crates/zerovault-core/src/pool.rs`](file:///c:/Users/Nick/Downloads/cloud.entropy.rs/crates/zerovault-core/src/pool.rs)) atomically acquires 2 permits via `acquire_many_owned(2)`, `SyncEngine::new` clamps min pool slots to `>= 2`, and `upload_dirty_inode_blobs` hydrates any prior chunk before acquiring the `(pt, wire)` pair. Verified with `max_concurrent_transfers = 1`. |
| `[M-03]` | **Remediated** | `CloudBackend::get_object` ([`crates/zerovault-storage/src/backend.rs`](file:///c:/Users/Nick/Downloads/cloud.entropy.rs/crates/zerovault-storage/src/backend.rs)) now streams responses through `operator.reader(..).into_stream(..)` with strict per-object-type byte ceilings (`VAULT_HEADER_LEN`, `MAX_ENCRYPTED_CHUNK_SIZE`, `64 MiB` for manifests). Verified with a 4 KiB oversized `vault/header.zvh` payload test. |
| `[L-03]` | **Remediated** | `prepare_unix_socket_dir_and_path` ([`crates/zerovault-daemon/src/ipc.rs`](file:///c:/Users/Nick/Downloads/cloud.entropy.rs/crates/zerovault-daemon/src/ipc.rs)) validates `symlink_metadata` (rejects symlinks) and enforces `uid == current_uid_raw()` on non-system-tmp parent directories. |
| `[L-04]` | **Remediated** | Removed all 4 production `.expect()` calls (`PooledBuffer::deref`/`deref_mut` via `std::mem::take` in `pool.rs` and error-propagating `RuntimeBridge` returning `ZeroVaultError::VfsError` -> `Errno::EIO` in `linux/fs.rs`). |
