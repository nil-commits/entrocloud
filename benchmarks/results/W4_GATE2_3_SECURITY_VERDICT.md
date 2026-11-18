# Wave 4 Gate 2 & Gate 3 Adversarial Security Verdict (`Zero-Knowledge Storage Inspection` & `5-Attack Cryptographic Tamper / Rollback Rejection`)

- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier — Zero-Trust Empirical Merger Swarm)
- **Final Verification Timestamp (UTC):** `2026-11-17T21:46:11Z`
- **Host Hardware:** AMD Ryzen 9 7950X3D (`16C/32T`, `AES-NI` + `PCLMULQDQ` + `AVX2` + `VAES` + `VPCLMULQDQ`) + Windows 11 x64 (`x86_64-pc-windows-msvc`, `rustc 1.94.1`)
- **Adversarial Torture Suite:** [w4_gate2_3_zk_and_tamper.rs](tests/e2e/tests/w4_gate2_3_zk_and_tamper.rs) (`7` async torture tests, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]`)
- **Isolated Target Dir:** `<workspace>\target\swarm\judge\w4-zk-tamper`
- **Read-Only Source Baseline Integrity:** **PASS (`0` mutations across `184` files / `298,766,349` bytes)** — verified against [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt).
- **Final Gate Decision:** **`PASS (0 Active Vetoes — 7/7 Torture Tests PASS EXIT=0; W4-VETO-KEYBOX-SIG Verified Remediated)`**

---

## Executive Verdict Summary

| Wave 4 Security Gate | Final Decision | Empirical Summary |
| :--- | :---: | :--- |
| **Wave 4 Gate 2 — Zero-Knowledge Storage Inspection (`t01`)** | **`PASS`** | **`0` matches** across **`22` UTF-8 + UTF-16LE canary byte patterns** and **`19,514,194` bytes (`18.610 MiB` @ `10.68 MiB/s`)** scanned across `30` remote cloud objects (`9` `.zv`, `14` `.zvm`, `3` `.zvh`, `2` `.zvs`, `2` `keybox.zv`) on `Mirrored` + `QuotaPooled` `LocalFs`, `1` live un-flushed `.zvpart` (`23,748 B`), `14` SQLite `sqlite_master` DDL entries, `8` SQLite tables / `17` rows / `134` columns (including live `conflicts` & `dirty_ops` rows), and raw `metadata.db` (`61,440 B`), `metadata.db-wal` (`189,552 B` pre-checkpoint -> `0 B` post-`PRAGMA wal_checkpoint(TRUNCATE)`), and `metadata.db-shm` (`32,768 B`). |
| **Wave 4 Gate 3 — 5 Mandatory Cryptographic Tamper & Rollback Attacks (`t02`..`t06`)** | **`5 / 5 PASS`** | All `5` mandatory attacks (1-bit ciphertext/tag flip, `24 MiB` chunk `3 <-> 4` swap + forged-header 25B `ChunkAad` probe, final chunk truncation + `CHUNK_FLAG_FINAL` bit-flip on chunk `N-2`, unsigned/forged `ZVM1`/`ZVS1`/`ZVK1` on `sync_once()`/`open_capability_share`/`open_keybox`, and `keybox.zv` `epoch = 1` rollback replay after revocation at `epoch = 2` across `open_keybox` + `SyncEngine` + `DaemonRuntime`) **deterministically fail closed with `ZeroVaultError::CryptoTamperDetected` (`0` plaintext bytes leaked)**. |
| **Wave 4 Gate 3 — Red-Team Veto Remediation Audit (`W4-VETO-KEYBOX-SIG`, `t07`)** | **`PASS (REMEDIATED)`** | Initial `Agent-Judge` red-team audit caught unauthenticated `ZVK1` `epoch`-floor poisoning (`W4-VETO-KEYBOX-SIG`). Post-remediation static inspection + live silicon torture test `t07` across **3 adversarial vectors** (garbage `[0xDE; 64]` signature on `KeyboxStatus` at `epoch = 999,999`, garbage signature on single-user `UnlockVault` at `epoch = 888,888`, and Mallory's *cryptographically valid* `Ed25519` self-signed `ZVK1` at `epoch = 777,777` against both pinned multi-recipient and unpinned single-user vaults) confirm **100% fail-closed `crypto_tamper` rejection with `0` SQLite `security_epochs` poisoning**. |

---

## 1. Read-Only Legacy & Source Baseline Integrity (`0` Mutations)

- **Command Executed:**
  ```powershell
  Get-ExactBaseline "cloudbridge"       "<donor-root>\cloudbridge"
  Get-ExactBaseline "cloudbridge linux" "<donor-root>\cloudbridge linux"
  Get-ExactBaseline "zerovault"         "<donor-root>\zerovault"
  ```
- **Exit Code:** `0` | **Wall-Clock Latency:** `701.50 ms` | **Throughput:** `406.15 MiB/s` (`298,766,349 B` across `184` files) | **Process RSS (`WorkingSet64` / Peak):** `119,910,400 B` (`114.36 MiB`)
- **Verbatim Stdout:**
  ```text
  cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
  cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
  zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
  === BASELINE_EXIT=0 | ELAPSED_MS=701,50 ===
  ```

---

## 2. Static Production Audit, Clippy & Execution Telemetry Summary

- **Production Panic / Unwrap Scan Across Remediated Crates (`zerovault-crypto/src`, `zerovault-core/src`, `zerovault-daemon/src`):**
  ```text
  STATIC_FORBIDDEN_PROD_HITS=0 (across 17 .rs files)
  ```

| Command Executed | Exit Code | Wall-Clock Latency | Test Binary Exec Time | Peak RSS (`PeakWorkingSetSize`) | Active / Post-Reclaim RSS (`WorkingSet64`) |
| :--- | :---: | ---: | ---: | ---: | ---: |
| `cargo clippy --manifest-path ...\Cargo.toml -p zerovault-e2e --test w4_gate2_3_zk_and_tamper --locked -- -D warnings` | **`0`** | `5,528.59 ms` | — (`0` warnings / `0` errors) | — | — |
| `cargo test --manifest-path ...\Cargo.toml --release -p zerovault-e2e --test w4_gate2_3_zk_and_tamper --locked -- --nocapture` *(Incremental Release Rebuild + Run)* | **`0`** | `71,546.37 ms` *(incl. thin-LTO link)* | **`3,510.00 ms`** (`7/7 passed`) | **`105.11 MiB`** | `21.43–67.49 MiB` active / **`31.03 MiB`** post-reclaim |
| `cargo test --manifest-path ...\Cargo.toml --release -p zerovault-e2e --test w4_gate2_3_zk_and_tamper --locked -- --nocapture` *(Warm Binary Run)* | **`0`** | `4,008.41 ms` | **`3,450.00 ms`** (`7/7 passed`) | **`104.64 MiB`** | `20.89–66.95 MiB` active / **`30.43 MiB`** post-reclaim |

---

## 3. Wave 4 Gate 2 — Zero-Knowledge Storage Inspection (`t01` — `PASS`)

### 3.1 Real Subsystems & Canary Injection Topology
- **Subsystems Exercised:** Real `DaemonRuntime` + real `SyncEngine` + real `RingHybridCryptoEngine` (`VAES + VPCLMULQDQ` `ring` `AES-256-GCM` + `aws-lc-rs` `ML-KEM-768/X25519/Ed25519`) + real `SqliteMetadataStore` (`PRAGMA journal_mode = WAL`, `PRAGMA secure_delete = ON`) + real `StorageRouter` across **both**:
  1. `RoutingPolicy::Mirrored { min_ack: 2 }` (`mirror-a`, `mirror-b` `LocalFs` clouds), and
  2. `RoutingPolicy::QuotaPooled` (`pool-1` capped at `6 MiB`, `pool-2` capped at `128 MiB`, empirically spilling a `9 MiB` 3-chunk canary file across both backends).
- **Mandatory Plaintext Canaries Populated & Decryption-Verified:**
  - Directory names: `"CANARY_DIR_OMEGA_SUBMARINE"`, `"CANARY_DIR_FINANCE_2026"`
  - Filenames: `"CANARY_FILE_NUCLEAR_LAUNCH_CODES.txt"`, `"CANARY_CONFLICT_DOC_SECRET.md"`
  - File plaintext contents: `"CANARY_PAYLOAD_PLAINTEXT_NEVER_LEAK_9988776655"`
  - Plus 6 partial substring stems (`"CANARY_"`, `"OMEGA_SUBMARINE"`, `"FINANCE_2026"`, `"NUCLEAR_LAUNCH_CODES"`, `"CONFLICT_DOC_SECRET"`, `"NEVER_LEAK_9988776655"`) — **`11` strings × `2` encodings (`UTF-8` & `UTF-16LE`) = `22` byte-window needles** scanned at every byte offset (`haystack.windows(needle.len())`).
- **Simultaneous Live Artifacts Materialized & Scanned:**
  1. **Remote Cloud Objects (`30` files, `100%` passing `validate_remote_object_key`):**
     - `9` `.zv` chunk blobs (`ZVC1`)
     - `14` `.zvm` encrypted manifests (`ZVM1` `head.zvm` + content-addressed snapshots)
     - `3` `vault/header.zvh` bootstrap headers (`ZVH1`: `2` mirrored + `1` pooled)
     - `2` `shares/<aa>/<bb>/<uuid>.zvs` capability share envelopes (`ZVS1` wrapping `"CANARY_FILE_NUCLEAR_LAUNCH_CODES.txt"`)
     - `2` `vault/keybox.zv` post-quantum multi-recipient keyboxes (`ZVK1`)
  2. **Local Dirty Staging (`.zvpart`):**
     - `1` un-flushed `staging/dirty/<inode>/0.zvpart` (`23,748` bytes) created via `SyncEngine::write_range` without `flush` + live `dirty_ops` row.
  3. **Conflict Preservation (`conflicts` Table):**
     - Concurrent update between `beta-peer` and `alpha-host` on `"/CANARY_DIR_OMEGA_SUBMARINE/CANARY_CONFLICT_DOC_SECRET.md"` resolved via `ConflictResolver::reconcile_remote_manifest`, persisting encrypted `ConflictRecord` in SQLite `conflicts` (`enc_conflict` under `MetadataKey`).
  4. **SQLite Logical & Physical Files (Pre- AND Post-`PRAGMA wal_checkpoint(TRUNCATE)`):**
     - `14` `sqlite_master` DDL objects (`SELECT type, name, tbl_name, sql FROM sqlite_master`)
     - `8` tables, `17` rows, `134` column cells (`inodes`, `chunks`, `dirty_ops`, `conflicts`, `manifest_cursor`, `security_epochs`, `sequences`, `sqlite_sequence`)
     - Raw `metadata.db` (`61,440 B`), `metadata.db-wal` (**`189,552 B` pre-checkpoint -> `0 B` post-`wal_checkpoint(TRUNCATE)`**), and `metadata.db-shm` (`32,768 B`).

### 3.2 Empirical Proof Log (`t01`)
```text
[PROOF-GATE2-ZK] status=PASS matches=0 needles=22 (UTF-8+UTF-16LE) remote_files=30 (.zv=9, .zvm=14, .zvh=3, .zvs=2, keybox.zv=2) staging_zvpart=1 staging_bytes=23748 sqlite_ddl=14 tables=8 rows=17 cols=134 pre_ckpt_wal_bytes=189552 post_ckpt_wal_bytes=0 raw_db_bytes=61440 raw_shm_bytes=32768 total_scanned_bytes=19514194 (18.610 MiB @ 10.68 MiB/s) elapsed_ms=1742.38 rss_before_mib=8.95 rss_active_mib=43.72 rss_peak_mib=101.20 priv_active_mib=31.42 rss_post_reclaim_mib=30.43
test t01_gate2_zero_knowledge_storage_sqlite_and_staging_inspection ... ok
```

---

## 4. Wave 4 Gate 3 — Cryptographic Tamper, Rollback & Red-Team Suite (`t02`..`t07` — `6/6 PASS`)

| Attack / Probe | Test Function | Adversary Action | Verified Fail-Closed Result | Latency / Throughput / RSS |
| :---: | :--- | :--- | :--- | :--- |
| **Attack 1** | `t02_gate3_attack1_single_bit_ciphertext_flip_fails_closed` | Flip `1` bit (`^= 0x01`) at byte offset `2,097,184` in `4 MiB` `.zv` chunk ciphertext body (plus `1`-bit GCM tag flip `^= 0x80`). | Single-mirror flip heals via RAID-1 failover; all-replica flip fails closed in `read_range` with `Err(CryptoTamperDetected("... AES-256-GCM authentication tag mismatch"))`, **`0` plaintext bytes returned**, RAM cache empty, and `decrypt_chunk_into` scrubs `out_plaintext` to `0` bytes. | `188.88 ms` \| Active RSS `44.72 MiB` \| Peak `101.20 MiB` |
| **Attack 2** | `t03_gate3_attack2_chunk_3_and_4_swap_fails_closed` | Write `24 MiB` (`6` chunks `0..=5`) file; **(2A)** swap remote `.zv` blobs for chunk `3` and chunk `4`; **(2B)** swap blobs **and** rewrite unencrypted `ZVC1` `header.chunk_index` (`bytes[8..16]`) to `3` and `4` to test the 25-byte `ChunkAad` (`file_id \|\| chunk_index_le \|\| is_final`) directly. | **(2A)** `read_range` on chunks `3` & `4` -> `Err(CryptoTamperDetected("... chunk index mismatch: expected 3, got 4"))`; **(2B)** `read_range` on chunks `3` & `4` -> `Err(CryptoTamperDetected("... AES-256-GCM authentication tag mismatch"))`, **`0` plaintext bytes returned**. | `272.41 ms` \| **`88.10 MiB/s`** \| Active RSS `66.95 MiB` \| Peak `104.64 MiB` |
| **Attack 3** | `t04_gate3_attack3_final_chunk_truncation_and_is_final_bitflip_fail_closed` | Write `18 MiB` (`N = 5` chunks) file; **(3A)** truncate `128 B` off final chunk `4` (both raw & with forged `header.plaintext_len`) + truncate to `12 B` header; **(3B)** delete final chunk `4` and flip `CHUNK_FLAG_FINAL` (`0x01`) on chunk `N-2 = 3`. | **(3A)** `128 B` truncation -> `CryptoTamperDetected` (`wire chunk length mismatch`); forged-header truncation -> `CryptoTamperDetected` (`tag mismatch`); `12 B` truncation -> `InvalidWireFormat`. **(3B)** Both stream-level `decrypt_chunk` and `SyncEngine::read_range` on chunk `3` -> `Err(CryptoTamperDetected("... AES-256-GCM authentication tag mismatch"))` via `is_final` in 25B `ChunkAad`, **`0` plaintext bytes**. | `213.48 ms` \| Active RSS `52.45 MiB` \| Peak `104.64 MiB` |
| **Attack 4** | `t05_gate3_attack4_unsigned_manifest_and_forged_share_keybox_injection_fail_closed` | **(4A)** Inject unsigned `manifests/head.zvm`, valid-header forged-tag `ZVM1`, Mallory-key-sealed `ZVM1`, and replayed `rev = 1` `ZVM1` after `rev = 2`; **(4B)** inject bit-flipped & Mallory-`Ed25519`-signed `ZVS1` share envelope; **(4C)** inject bit-flipped & Mallory-`Ed25519`-signed `ZVK1` keybox. | `sync_once()`, `DaemonRuntime::SyncNow`, `open_manifest`, `open_capability_share`, `SyncEngine::import_capability_share`, `open_keybox`, and `SyncEngine::fetch_and_open_keybox` **all deterministically fail closed with `ZeroVaultError::CryptoTamperDetected` (`code = "crypto_tamper"`)**. | `235.99 ms` \| Active RSS `20.89 MiB` \| Peak `104.64 MiB` |
| **Attack 5** | `t06_gate3_attack5_keybox_epoch1_rollback_replay_after_epoch2_revocation_fails_closed` | Initialize `keybox.zv` at `epoch = 1` granting Alice & Bob (`ML-KEM-768 + X25519 + Ed25519`), capture valid signed `keybox_epoch1_bytes`, verify Bob opens `epoch = 1`; revoke Bob (`RevokeKeyboxRecipient` -> `epoch = 2`, rotated `FRK_2 != FRK_1`, SQLite `epoch_floor("keybox") = 2`); overwrite `vault/keybox.zv` with valid signed `keybox_epoch1_bytes`. | **(a)** Bob rejected on `epoch = 2` with `UnauthorizedRecipient` (`open_keybox` & `fetch_and_open_keybox`) and Bob's retained `FRK_1` fails `open_manifest` on rotated `epoch = 2` `head.zvm` (`CryptoTamperDetected`); **(b)** Replaying valid signed `epoch = 1` `keybox.zv` fails closed with **`CryptoTamperDetected` (`got 1, minimum floor is 2`)** across `open_keybox`, `SyncEngine::fetch_and_open_keybox`, `SyncEngine::publish_keybox`, `DaemonRuntime::KeyboxStatus`, and `DaemonRuntime::UnlockVault`. | `334.76 ms` \| Active RSS `31.57 MiB` \| Peak `104.64 MiB` |
| **Red-Team `t07`** | `t07_gate3_redteam_daemon_keybox_forged_signature_epoch_poisoning_audit` | **(Vec A)** Plant `[0xDE; 64]` forged `ZVK1` (`epoch = 999,999`) -> poll `KeyboxStatus`, restore `epoch = 1`, `LockVault -> UnlockVault`; **(Vec B)** plant `[0xDE; 64]` forged `ZVK1` (`epoch = 888,888`) on single-user vault -> `UnlockVault`; **(Vec C)** plant Mallory's *valid* `Ed25519`-signed `ZVK1` (`epoch = 777,777`) on both pinned & single-user vaults. | **(Vec A)** `KeyboxStatus` -> `Error(crypto_tamper: "keybox Ed25519 signature verification failed")`, SQLite `epoch_floor("keybox") == 1` unpoisoned, subsequent `UnlockVault` -> `Ok`; **(Vec B)** `UnlockVault` -> `Error(crypto_tamper)`, `floor == 0`; **(Vec C)** pinned `KeyboxStatus` -> `Error(crypto_tamper: "keybox owner Ed25519 public key mismatch")`, single-user `UnlockVault` -> `Error(crypto_tamper: "unexpected remote keybox.zv present on single-user vault...")`. | Included in `3,450 ms` suite (`0` leaks, `0` poisoning) |

---

## 5. Remediation Audit Trail for `W4-VETO-KEYBOX-SIG` (Resolved)

1. **`zerovault-crypto` ([sharing.rs:294-349](crates/zerovault-crypto/src/sharing.rs#L294-L349)):** Added `verify_keybox_envelope` enforcing hardware crypto check, `KEYBOX_VERSION`, `epoch >= min_epoch_floor.max(1)`, optional `expected_vault_id`, constant-time `expected_owner_pubkey`, stanza structural invariants, and 64-byte `aws-lc-rs` `Ed25519` signature verification over `SignedKeybox::signing_transcript()`.
2. **`zerovault-core` ([engine.rs:554-609](crates/zerovault-core/src/engine.rs#L554-L609)):** Hardened `SyncEngine::fetch_keybox` to call `self.crypto.verify_keybox_envelope(&kb, expected_vault_id, None, floor)` before advancing SQLite `security_epochs("keybox")`, with automatic mirror failover across healthy replicas when a primary mirror serves a tampered `ZVK1`.
3. **`zerovault-daemon` ([service.rs:1182-1275, 2861-3261, 3396-3470, 3829-3888](crates/zerovault-daemon/src/service.rs#L3396-L3470)):** Hardened `fetch_remote_keybox`, `reconcile_keybox_on_unlock`, `init_keybox`, `grant_keybox_recipient`, `revoke_keybox_recipient`, and `keybox_status` to verify `Ed25519` signatures, `vault_id`, pinned `owner_ed25519_pubkey`, missing-keybox-after-floor deletion (`sql_floor > 0`), and unexpected remote `keybox.zv` on unpinned single-user vaults **strictly before** opening or advancing SQLite `security_epochs("keybox")`.

---

## 6. Verbatim Post-Remediation Raw Test Runner Output (`7/7 PASS`, `EXIT=0`)

```text
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
=== BASELINE_EXIT=0 | ELAPSED_MS=701,50 ===
    Checking zerovault-types v0.2.0 (<workspace>\crates\zerovault-types)
    Checking zerovault-storage v0.2.0 (<workspace>\crates\zerovault-storage)
    Checking zerovault-vfs v0.2.0 (<workspace>\crates\zerovault-vfs)
    Checking zerovault-crypto v0.2.0 (<workspace>\crates\zerovault-crypto)
    Checking zerovault-core v0.2.0 (<workspace>\crates\zerovault-core)
    Checking zerovault-daemon v0.2.0 (<workspace>\crates\zerovault-daemon)
    Checking zerovault-e2e v0.2.0 (<workspace>\tests\e2e)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.41s
=== CLIPPY_EXIT=0 | ELAPSED_MS=5528,59 ===
STATIC_FORBIDDEN_PROD_HITS=0 (across 17 .rs files)
    Finished `release` profile [optimized] target(s) in 0.48s
     Running tests\w4_gate2_3_zk_and_tamper.rs (entrocloud merge\target\swarm\judge\w4-zk-tamper\release\deps\w4_gate2_3_zk_and_tamper-75a1f8fcbfb05c63.exe)

running 7 tests
[PROOF-GATE2-ZK] status=PASS matches=0 needles=22 (UTF-8+UTF-16LE) remote_files=30 (.zv=9, .zvm=14, .zvh=3, .zvs=2, keybox.zv=2) staging_zvpart=1 staging_bytes=23748 sqlite_ddl=14 tables=8 rows=17 cols=134 pre_ckpt_wal_bytes=189552 post_ckpt_wal_bytes=0 raw_db_bytes=61440 raw_shm_bytes=32768 total_scanned_bytes=19514194 (18.610 MiB @ 10.68 MiB/s) elapsed_ms=1742.38 rss_before_mib=8.95 rss_active_mib=43.72 rss_peak_mib=101.20 priv_active_mib=31.42 rss_post_reclaim_mib=30.43
test t01_gate2_zero_knowledge_storage_sqlite_and_staging_inspection ... ok
[PROOF-GATE3-ATTACK1] status=PASS flip_offset=2097184 xor_mask=0x01 read_range_result=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/b5/a0/b5a0b086-21be-4e3f-b768-c26e0f26ed46.zv: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) plaintext_bytes_returned=0 decrypt_chunk_into_out_len=0 mirror_failover_verified=true elapsed_ms=188.88 rss_mib=44.72 peak_rss_mib=101.20
test t02_gate3_attack1_single_bit_ciphertext_flip_fails_closed ... ok
[PROOF-GATE3-ATTACK2] status=PASS file_mib=24 chunks=6 raw_swap_c3=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/15/33/15337001-1614-46c8-a47f-d3607933187c.zv: cryptographic tamper detected: chunk index mismatch: expected 3, got 4")) raw_swap_c4=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/bf/ab/bfab16bd-58c5-46f2-9bc1-0c9372e65cc5.zv: cryptographic tamper detected: chunk index mismatch: expected 4, got 3")) forged_hdr_25b_aad_c3=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/15/33/15337001-1614-46c8-a47f-d3607933187c.zv: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) forged_hdr_25b_aad_c4=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/bf/ab/bfab16bd-58c5-46f2-9bc1-0c9372e65cc5.zv: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) plaintext_bytes_returned=0 throughput_mib_s=88.10 elapsed_ms=272.41 rss_mib=66.95 peak_rss_mib=104.64
test t03_gate3_attack2_chunk_3_and_4_swap_fails_closed ... ok
[PROOF-GATE3-ATTACK3] status=PASS chunks=5 trunc_128b=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/db/60/db603613-b6c6-4782-b148-5534d20a626a.zv: cryptographic tamper detected: wire chunk length mismatch: expected 2097200, got 2097072")) trunc_forged_hdr=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/db/60/db603613-b6c6-4782-b148-5534d20a626a.zv: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) trunc_12b_hdr=Err(InvalidWireFormat) is_final_flip_chunk3_direct=Err(CryptoTamperDetected("AES-256-GCM authentication tag mismatch")) is_final_flip_chunk3_engine=Err(CryptoTamperDetected("all mirror replicas failed chunk verification for blobs/5d/25/5d258ed8-8a81-4c78-aa0c-a25e44a933dd.zv: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) plaintext_bytes_returned=0 elapsed_ms=213.48 rss_mib=52.45 peak_rss_mib=104.64
test t04_gate3_attack3_final_chunk_truncation_and_is_final_bitflip_fail_closed ... ok
[PROOF-GATE3-ATTACK4] status=PASS unsigned_zvm_sync=Err(CryptoTamperDetected("all mirror replicas failed manifest verification for manifests/head.zvm: invalid wire format: sealed manifest too short: 40 bytes")) forged_zvm1_tag=Err(CryptoTamperDetected("all mirror replicas failed manifest verification for manifests/head.zvm: cryptographic tamper detected: AES-256-GCM authentication tag mismatch")) manifest_rev1_rollback=Err(CryptoTamperDetected("remote manifest revision rollback detected: floor=2, remote=1")) forged_zvs1_sig=Err(CryptoTamperDetected("share envelope Ed25519 signature verification failed")) forged_zvk1_sig=Err(CryptoTamperDetected("keybox Ed25519 signature verification failed")) daemon_sync_code=crypto_tamper elapsed_ms=235.99 rss_mib=20.89 peak_rss_mib=104.64
test t05_gate3_attack4_unsigned_manifest_and_forged_share_keybox_injection_fail_closed ... ok
[PROOF-GATE3-ATTACK5] status=PASS bob_revoked_ep2=Err(UnauthorizedRecipient("537f6b607dfca1f2822beee793bf8dff")) bob_old_frk_manifest=Err(CryptoTamperDetected) sqlite_epoch_floor=2 open_keybox_replay=Err(CryptoTamperDetected("keybox epoch rollback detected: got 1, minimum floor is 2")) sync_engine_replay=Err(CryptoTamperDetected("keybox epoch rollback detected: got 1, minimum floor is 2")) daemon_status_replay=Err(crypto_tamper: "cryptographic tamper detected: keybox epoch rollback detected: got 1, minimum floor is 2") daemon_unlock_replay=Err(crypto_tamper: "cryptographic tamper detected: keybox epoch rollback detected: got 1, minimum floor is 2") elapsed_ms=334.76 rss_mib=31.57 peak_rss_mib=104.64
test t06_gate3_attack5_keybox_epoch1_rollback_replay_after_epoch2_revocation_fails_closed ... ok
[PROOF-REDTEAM-T07] status=PASS vector_a(forged_zvk1_epoch=999999 sig=[0xDE;64]): keybox_status_resp=Error { code: "crypto_tamper", message: "cryptographic tamper detected: keybox Ed25519 signature verification failed" } persisted_sqlite_epoch_floor=1 subsequent_legit_unlock_resp=Ok { message: "vault 4fa2574b-256c-43e3-b23a-d3db31c88fdc unlocked" } | vector_b(single_user_unlock_on_forged_zvk1_epoch=888888): unlock_resp=Error { code: "crypto_tamper", message: "cryptographic tamper detected: keybox Ed25519 signature verification failed" } poisoned_single_user_floor=0 | vector_c(mallory_valid_ed25519_zvk1_epoch=777777): pinned_status_resp=Error { code: "crypto_tamper", message: "cryptographic tamper detected: keybox owner Ed25519 public key mismatch" } single_unlock_resp=Error { code: "crypto_tamper", message: "cryptographic tamper detected: unexpected remote keybox.zv present on single-user vault without pinned owner or recipient identity" }
test t07_gate3_redteam_daemon_keybox_forged_signature_epoch_poisoning_audit ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.45s

=== WARM_SUITE_EXIT=0 | ELAPSED_MS=4008,41 ===
```
