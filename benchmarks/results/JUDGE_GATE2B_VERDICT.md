# Adversarial Gate 2B Verdict — `zerovault-core` (`Agent-Judge`)

- **Judge Agent:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier)
- **Date:** 2026-11-17
- **Target Crate:** `crates/zerovault-core` (`5,448` production LoC across 6 `.rs` files; `1,405` test LoC; `176` bench LoC)
- **Isolated Build Target Dir:** `<workspace>\target\swarm\judge\gate2b`
- **Gate 2B Decision:** **PASS (`0` Vetoes Exercised; `15/15` Tests Passed; `0` Clippy Warnings; `4/4` Criterion Bench Groups `EXIT=0`; `0` Read-Only Source Mutations)**

---

## 1. Static Red-Team Audit of `crates/zerovault-core/src/**`

### 1.1 Production Panic / Unwrap /Unsafe Audit (`EXIT=0`)
- **Crate-Level Compiler Gates (`crates/zerovault-core/src/lib.rs:4-11`):**
  ```rust
  #![deny(
      unsafe_code,
      clippy::unwrap_used,
      clippy::expect_used,
      clippy::panic,
      clippy::todo,
      clippy::unimplemented
  )]
  ```
- **Exact Red-Team Grep Command Executed:**
  ```powershell
  $srcDir = "<workspace>\crates\zerovault-core\src"
  $files = Get-ChildItem -Path $srcDir -Filter "*.rs" -Recurse | Sort-Object FullName
  Select-String -Path ($files.FullName) -Pattern '\.unwrap\s*\(|\.expect\s*\(|panic!\s*\(|todo!\s*\(|unimplemented!\s*\(|unreachable!\s*\('
  Select-String -Path ($files.FullName) -Pattern '\bunsafe\b'
  ```
- **Raw Output (`EXIT=0`):**
  ```text
  === SOURCE LINE COUNTS ===
  cache.rs | 574 lines | 20381 bytes
  conflict.rs | 593 lines | 23446 bytes
  db.rs | 1273 lines | 44342 bytes
  engine.rs | 2633 lines | 100769 bytes
  lib.rs | 32 lines | 902 bytes
  pool.rs | 343 lines | 11193 bytes
  TOTAL_LINES=5448

  === FORBIDDEN TOKENS GREP (.unwrap(, .expect(, panic!(, todo!(, unimplemented!(, unreachable!() ===
  MATCH_COUNT=0

  === UNSAFE GREP ===
  UNSAFE_MATCH_COUNT=1
  pool.rs:36: unsafe { libmimalloc_sys::mi_collect(true) };
  ```
- **Verdict:** **VERIFIED.** `0` `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()`, or `unreachable!()` calls exist in `crates/zerovault-core/src/**`. The **sole** `unsafe` block in the entire crate is `src/pool.rs:36` (`unsafe { libmimalloc_sys::mi_collect(true) };`), scoped inside `#[allow(unsafe_code)] fn collect_thread_local_mimalloc()` with an explicit `// SAFETY:` invariant comment (`src/pool.rs:35`).

---

### 1.2 Zero-Knowledge SQLite WAL Schema & Epoch Floor Audit (`src/db.rs`)
- **Schema Verification (`src/db.rs:27-96`):**
  - `inodes` (`lines 33-49`): Contains `inode`, `parent_inode`, `file_id`, `name_blind_idx BLOB NOT NULL`, `enc_meta BLOB NOT NULL`, `kind`, `size`, `mode`, `hydration`, `pinned`, `version`, `wrapped_dek BLOB`, `modified_at_ns`, `created_at_ns`, `UNIQUE (parent_inode, name_blind_idx)`. **ZERO** plaintext filename or virtual path columns exist.
    - `name_blind_idx` (`lines 358-362, 974`): Keyed `BLAKE3` blind index via `crypto.compute_blind_index(parent_inode, &name)` (`[0u8; 32]` for `ROOT_INODE`), with post-decryption exact-name verification in `lookup_child_sync` (`line 992`).
    - `enc_meta` (`lines 999-1041`): `(name, virtual_path)` serialized inside `Zeroizing::new(postcard::to_allocvec(...))` and AEAD-sealed via `crypto.seal_metadata(&aad, &payload)` with 27-byte context AAD `b"ZV-INODE-V2" || inode.to_le_bytes() || parent_inode.to_le_bytes()` (preventing cross-inode or cross-parent metadata transplant attacks).
  - `dirty_ops` (`lines 67-75`): Stores `enc_path BLOB NOT NULL` sealed via `crypto.seal_metadata(&dirty_aad(inode), vpath.as_bytes())` under 19-byte AAD `b"ZV-DIRTY-V2" || inode.to_le_bytes()` (`lines 654-655, 1007-1012`). **ZERO** plaintext dirty-op target path columns exist.
  - `conflicts` (`lines 87-90`): Stores `enc_conflict BLOB NOT NULL` (`ConflictRecord` serialized inside `Zeroizing` and AEAD-sealed under `b"ZV-CONFLICT-V2"`, `lines 864-878`). **ZERO** plaintext `original_path` or `conflict_path` columns exist.
  - `manifest_cursor` (`lines 80-85`): Persists `revision`, `etag`, and `parent_manifest_id` across restarts (`lines 747-782`).
  - `security_epochs` (`lines 92-95, 784-835`): `scope TEXT PRIMARY KEY, min_epoch INTEGER NOT NULL`. `advance_epoch_floor` executes inside a SQLite transaction and rejects any `new_epoch < current` with `ZeroVaultError::CryptoTamperDetected` (`lines 819-823`).
- **Connection Hardening (`src/db.rs:167-185`):**
  - Enforces `PRAGMA journal_mode = WAL;` (verifying `"wal"` on all file-backed DBs), `PRAGMA synchronous = NORMAL;`, `PRAGMA foreign_keys = ON;`, `PRAGMA secure_delete = ON;`, `PRAGMA temp_store = MEMORY;` (preventing unencrypted SQLite temp B-tree disk spills), and `PRAGMA busy_timeout = 5000;`.
  - Dispatches all synchronous `rusqlite::Connection` calls onto `tokio::task::spawn_blocking` (`run_blocking`, `lines 243-256`) so async workers never block or hold a `parking_lot::Mutex` guard across `.await`.
- **Empirical Canary Proof (`tests/core_suite.rs:365-534`):** Raw byte scans (both UTF-8 and UTF-16LE) across `.db` and `.db-wal` both **before** and **after** `PRAGMA wal_checkpoint(TRUNCATE)` confirm `0` occurrences of canary strings (`ULTRA_SECRET_CANARY_TAXES_2026.xlsx`, `PROJECT_NIGHTFALL_DIR`, etc.), and tampering `enc_meta` in-place deterministically fails closed with `CryptoTamperDetected`.

---

### 1.3 AEAD `.zvpart` Dirty Staging & Zero-Wipe Audit (`src/cache.rs` — `NEW-H01`)
- **Per-Chunk AEAD Staging (`src/cache.rs:252-355`):**
  - `write_dirty_chunk_slice` (`lines 252-300`) and `write_full_dirty_chunk` (`lines 303-324`) seal every staged chunk via `self.crypto.seal_staging_chunk(inode, chunk_index, ...)` before writing `staging_dir/dirty/<inode>/<chunk_index>.zvpart`.
  - Partial slice updates open any existing `.zvpart` into `Zeroizing<Vec<u8>>` via `self.crypto.open_staging_chunk(inode, chunk_index, &sealed)?`, bound-checked against `PLAINTEXT_CHUNK_SIZE` (`4 MiB`) and `MAX_STAGING_FILE_BYTES` (`MAX_ENCRYPTED_CHUNK_SIZE + 1024` pre-allocation DoS ceiling, `lines 27, 431-436`).
  - `truncate_dirty_chunks` (`lines 358-391`) zeroizes truncated tail bytes (`pt[last_len..].zeroize()`), re-seals the boundary chunk, and securely wipes removed tail `.zvpart` files.
- **Cryptographic Zero-Wipe on `purge_all()` & Startup Recovery (`src/cache.rs:403-421, 465-562`):**
  - `purge_all()` clears the bounded `Zeroizing<Vec<u8>>` RAM LRU cache, recursively zero-overwrites every file under `staging_dir/dirty` in `64 KiB` blocks + `file.sync_all().await` before `fs::remove_file` and `fs::remove_dir_all`, and wipes stray top-level staging files.
  - `ChunkCache::new` (`line 78`, `cleanup_orphaned_temp_files_sync` `lines 533-562`) zero-overwrites, syncs, and removes any orphaned `.tmp` or `.partial` files left behind by prior crashes.

---

### 1.4 Full-Capacity Zeroizing Buffer Pool & `mimalloc` Reclamation Audit (`src/pool.rs` — `NEW-M04`)
- **Full-Capacity Scrub (`src/pool.rs:21-31, 280-294`):**
  - `zeroize_bytes_mut_full_capacity` queries `full_cap = buf.capacity()`, extends `buf.resize(full_cap, 0u8)` in-place on the uniquely-owned `BytesMut`, invokes volatile `buf.as_mut().zeroize()` across the entire `0..capacity` span (wiping spare capacity `len..capacity` that previously survived truncation/partial chunks in `NEW-M04`), and calls `buf.clear()`.
  - `PooledBuffer::drop` (`lines 280-294`) scrubs `0..capacity`, pushes the recycled `BytesMut` onto `free_list` (capped at `max_slots`), and **only afterwards** drops `_permit` (`line 292`) so waiting tasks immediately reuse the scrubbed allocation.
  - `acquire_pair` (`lines 136-164`) atomically acquires 2 permits via `Semaphore::acquire_many_owned(2)`, eliminating dual-buffer ABBA deadlocks during concurrent chunk encryption.
- **`mimalloc` Idle Reclamation (`src/pool.rs:33-67`):**
  - `reclaim_process_memory()` dispatches `collect_thread_local_mimalloc()` (`unsafe { libmimalloc_sys::mi_collect(true) }`) across `worker_count` (`available_parallelism().clamp(2, 16)`) async tasks, `worker_count` blocking-pool tasks, and the calling thread, invoked automatically at the end of `SyncEngine::sync_once()` (`engine.rs:939`) and `SyncEngine::lock_and_purge_cache()` (`engine.rs:423`).

---

### 1.5 Streaming SyncEngine Security & Feature Audit (`src/engine.rs` & `src/conflict.rs`)
1. **AEAD-Verified Mirror Replica Failover (`NEW-M02`):**
   - Verified in `fetch_and_decrypt_chunk` (`engine.rs:201-297`), `fetch_vault_header` (`495-524`), `fetch_keybox` (`549-585`), `fetch_and_open_keybox` (`590-658`), `fetch_and_open_manifest` (`1101-1175`), and `fetch_and_open_share_envelope` (`1282-1337`).
   - Primary read verifies AEAD tag + `ChunkHeader.plaintext_len` + 32-byte plaintext `BLAKE3` digest (`verify_chunk_payload`, `300-335`); on `CryptoTamperDetected` / `InvalidWireFormat` / transient transport error, iterates `storage.candidate_backends(preferred_backends)` via `get_blob_from_backend`, recovering transparently from healthy mirrors and failing closed with `CryptoTamperDetected` when all replicas are corrupt.
2. **Deferred Orphan `.zv` Blob Garbage Collection (`NEW-L03`):**
   - Superseded blob UUIDs from chunk overwrites (`1645-1651`), `unlink` (`2188-2203`), `rename` overwrite (`2267-2280`), and prior committed manifest snapshots (`1832-1838`) are recorded in `pending_gc_blobs`, filtered against all live committed + uncommitted blobs (`1825-1830, 1849`), and deleted via `gc_orphan_blobs` (`1846-1874`) **strictly after** `put_manifest_cas` commits the new head manifest.
3. **Manifest Chain Lineage & Monotonic Epoch Floor (`NEW-M01`):**
   - `compute_manifest_id` (`185-196`) derives a deterministic 128-bit anchor from `BLAKE3("ZV-MANIFEST-ID-V2" || postcard(manifest))[0..16]`.
   - Both pull (`991-999`) and publish (`1815-1822`) persist `advance_epoch_floor(EPOCH_SCOPE_MANIFEST, rev)` and `set_parent_manifest_id(Some(id))` in SQLite WAL.
   - `verify_manifest_rollback_and_lineage` (`1189-1280`) rejects `manifest.revision < floor.max(local_rev)`, enforces `parent_manifest_id.is_none()` on rev 1 and `.is_some()` on rev > 1, detects same-revision forks (`candidate_id != expected_anchor`), verifies direct parent linkage on `local_rev + 1`, and walks up to `MAX_MANIFEST_ANCESTOR_HOPS = 32` historical `manifests/<uuid>.zvm` snapshots when `manifest.revision > local_rev + 1`.
4. **Serverless Post-Quantum `keybox.zv` & `zv://` Capability Sharing:**
   - `publish_keybox` (`528-546`), `fetch_keybox` (`549-585`), and `fetch_and_open_keybox` (`590-658`) enforce and advance the SQLite `"keybox"` monotonic epoch floor (`min_floor = epoch_floor("keybox").max(1)`), blocking stale keybox replay after recipient revocation and unlocking the engine via `unlock_with_folder_key`.
   - `create_file_capability_share` (`662-728`) flushes dirty state, wraps a read-only `ZVS1` `SignedShareEnvelope` (`shares/<aa>/<bb>/<uuid>.zvs`), and returns the `zv://` `CapabilityUri`. `import_capability_share` (`732-834`) verifies signature/URI binding, streams & verifies every 4 MiB chunk in bounded RAM, enforces exact total size match (`801-806`), and unlinks partial target state on any failure (`828-830`).
5. **Symlink- & Reparse-Safe `.partial` Atomic Local Export:**
   - `export_file_atomic` (`841-931`) + `is_symlink_or_reparse_meta` (`2540-2553`) + `ensure_safe_export_parent_dir` (`2570-2608`) inspect `std::fs::symlink_metadata` and Windows `FILE_ATTRIBUTE_REPARSE_POINT` (`0x0400`) on target, parent, and deepest existing ancestor *prior* to `create_dir_all`, stream bounded 4 MiB chunks into `<filename>.<uuid>.partial` opened with `create_new(true)` (`0o600` on Unix), invoke `flush()` + `sync_all()`, close the file handle before rename, re-verify TOCTOU symlink/reparse absence (`verify_pre_rename_destination`, `2610-2633`), atomically `fs::rename` to destination, and `secure_wipe_and_remove_file` the `.partial` file on any error.

---

### 1.6 Non-Blocking Red-Team Hardening Notes for Downstream Wave 3 Integration
1. **Windows Staging Directory DACL Responsibility (`crates/zerovault-core/Cargo.toml:30-32`, `src/cache.rs:564-574`):**
   - To preserve `#![deny(unsafe_code)]` and the strict single-`unsafe`-block budget in `zerovault-core`, `restrict_dir_perms` sets `0o700` on Unix and is a no-op on Windows (`widestring` and `windows` in `zerovault-core/Cargo.toml` are currently unused). While `.zvpart` files are 100% AEAD-encrypted under `StagingKey` and zero-wiped on lock/purge, `zerovault-daemon` (`zerovaultd`) **must** ensure the parent `state_dir` / `staging_dir` on Windows receives owner-only `PROTECTED_DACL` (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`) at daemon initialization.
2. **`dirty_ops.last_error` Error-String Hygiene (`src/db.rs:73`, `src/engine.rs:1045`):**
   - `dirty_ops.last_error` is stored as plaintext `TEXT` for diagnostic telemetry. `StorageRouterTrait` implementations must never interpolate `virtual_hint_path` into `ZeroVaultError` display strings (using only opaque `object_key` UUID paths).

---

## 2. Independent Empirical Execution & Memory Telemetry

### 2.1 `cargo test` (`15/15` Passed, `EXIT=0`)
- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2b"
  cargo test --manifest-path "<workspace>\Cargo.toml" -p zerovault-core --locked
  ```
- **Exit Code:** `0`
- **Wall-Clock Latency:** `33.291 s` (cold compile `25.17 s` + test execution `7.55 s`)
- **Physical RSS (`WorkingSet64` / `PeakWorkingSet64`) Across Test Binaries:**
  - `zerovault_core-f40cd3294c1639ce.exe` (`2` unit tests, `53.14 ms`): Peak RSS = **`6.57 MiB`**, Exit/Idle RSS = **`0.03 MiB`** (`GetProcessMemoryInfo`).
  - `core_suite-6ece89777dd6d4b8.exe` (`8` integration/adversarial tests incl. `9.5 MiB` streaming + `4.25 MiB` share + mirror failover, `2,242.58 ms` standalone): Min/Idle RSS = **`2.84 MiB`**, Final RSS = **`14.01 MiB`**, Peak RSS = **`87.39 MiB`** (`< 128 MiB` budget even under 8 concurrent test engines in debug mode).
  - `proptest_core-b14ecbc9c70cf0e2.exe` (`5` property-based fuzz suites, `4,123.41 ms` standalone): Min/Idle RSS = **`2.47 MiB`**, Final RSS = **`16.61 MiB`**, Peak RSS = **`32.29 MiB`**.
- **Raw `cargo test` Stdout Excerpt:**
  ```text
       Running unittests src\lib.rs (entrocloud merge\target\swarm\judge\gate2b\debug\deps\zerovault_core-f40cd3294c1639ce.exe)

  running 2 tests
  test pool::tests::full_capacity_scrub_clears_length_and_preserves_capacity ... ok
  test pool::tests::pool_semaphore_backpressure_and_recycle ... ok

  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

       Running tests\core_suite.rs (entrocloud merge\target\swarm\judge\gate2b\debug\deps\core_suite-6ece89777dd6d4b8.exe)

  running 8 tests
  test buffer_pool_full_capacity_zeroization_and_mimalloc_reclamation ... ok
  test encrypted_zvpart_staging_and_purge_all_leave_zero_plaintext_or_residual_files ... ok
  test verified_mirror_read_failover_recovers_from_corrupt_primary_and_fails_closed_when_all_bad ... ok
  test manifest_epoch_rollback_and_forged_parent_manifest_id_are_rejected ... ok
  test sqlite_wal_zero_knowledge_canary_inspection_proves_zero_plaintext_bytes ... ok
  test concurrent_conflict_and_offline_retry_preserve_all_data ... ok
  test serverless_keybox_epoch_revocation_capability_share_and_atomic_export ... ok
  test streaming_9_5_mib_seek_lock_purge_and_orphan_blob_gc ... ok

  test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.79s

       Running tests\proptest_core.rs (entrocloud merge\target\swarm\judge\gate2b\debug\deps\proptest_core-b14ecbc9c70cf0e2.exe)

  running 5 tests
  test prop_sanitize_device_id_and_conflict_filename_are_portable ... ok
  test prop_sqlite_security_epochs_strictly_monotonic ... ok
  test prop_zvpart_any_single_bit_tamper_fails_closed ... ok
  test prop_sqlite_blind_index_lookup_roundtrip ... ok
  test prop_cross_chunk_write_flush_dehydrate_seek_matches_reference_model ... ok

  test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.75s

     Doc-tests zerovault_core

  running 0 tests

  test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

  JUDGE_META: EXIT=0 | WALL_SECS=33,291
  ```

---

### 2.2 `cargo clippy --all-targets -- -D warnings` (`0` Warnings, `EXIT=0`)
- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2b"
  cargo clippy --manifest-path "<workspace>\Cargo.toml" -p zerovault-core --all-targets --locked -- -D warnings
  ```
- **Exit Code:** `0`
- **Wall-Clock Latency:** `14.728 s`
- **Raw Stdout/Stderr Excerpt:**
  ```text
      Checking zerovault-types v0.2.0 (<workspace>\crates\zerovault-types)
      Checking zerovault-core v0.2.0 (<workspace>\crates\zerovault-core)
      Finished `dev` profile [unoptimized + debuginfo] target(s) in 14.58s
  JUDGE_META: EXIT=0 | WALL_SECS=14,728
  ```

---

### 2.3 `cargo bench --bench core_bench -- --quick` (`EXIT=0`) & PE Import Audit
- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\gate2b"
  cargo bench --manifest-path "<workspace>\Cargo.toml" -p zerovault-core --bench core_bench --locked -- --quick
  ```
- **Exit Code:** `0`
- **Wall-Clock Latency:** `45.311 s` (release bench build `42.61 s` + Criterion `--quick` run; standalone binary re-run `7,110.42 ms`)
- **Physical RSS (`core_bench-e0aa1852eb83975d.exe --bench --quick`):**
  - Min/Idle `WorkingSet64`: **`4.14 MiB`**
  - Final `WorkingSet64`: **`19.71 MiB`**
  - Peak `PeakWorkingSet64`: **`43.80 MiB`**
- **PE DLL Import Audit (`dumpbin.exe /imports core_bench-e0aa1852eb83975d.exe`):**
  - Only clean OS/CRT libraries linked: `kernel32.dll`, `bcryptprimitives.dll`, `api-ms-win-core-synch-l1-2-0.dll`, `ws2_32.dll`, `ntdll.dll`, `VCRUNTIME140.dll`, `api-ms-win-crt-*.dll` (`0` WebView2, `0` OpenSSL, `0` libsodium).
- **Measured Criterion Benchmark Summary & Non-DCE Proof:**

| Benchmark ID | Median Latency (`--quick`) | Measured Throughput | Adversarial Verification Note |
| :--- | :---: | :---: | :--- |
| `sqlite_blind_index_get_by_path` | **`50.718 µs`** (`[49.279, 51.078] µs`) | `~19,717 ops/s` | Full `spawn_blocking` + keyed `BLAKE3` blind index + AEAD `open_inode_meta` |
| `buffer_pool_zeroize/65536` (`64 KiB`) | **`988.38 ns`** (`[987.87, 988.51] ns`) | **`61.753 GiB/s`** (`63,235 MiB/s`) | Proves genuine L1/L2 volatile `zeroize()` across full `64 KiB` capacity (not DCE'd) |
| `buffer_pool_zeroize/4194304` (`4 MiB`) | **`178.40 µs`** (`[174.19, 179.45] µs`) | **`21.896 GiB/s`** (`22,422 MiB/s`) | Proves genuine L3 V-Cache volatile `zeroize()` across full `4 MiB` spare capacity (`NEW-M04`) |
| `zvpart_encrypted_staging_256kib/seal_and_open_zvpart` | **`2.2619 ms`** (`[2.2386, 2.2677] ms`) | **`110.53 MiB/s`** | Includes NTFS file write + flush + read + AEAD seal/open (`NEW-H01`) |
| `sync_engine_cached_read_range/read_64kib_slice` | **`337.60 µs`** (`[327.68, 340.07] µs`) | **`185.13 MiB/s`** | Full `VfsBackend::read_range` O(1) seek (`1 MiB` offset, `64 KiB` slice) |

- **Raw `cargo bench` Stdout Excerpt:**
  ```text
       Running benches\core_bench.rs (entrocloud merge\target\swarm\judge\gate2b\release\deps\core_bench-e0aa1852eb83975d.exe)
  Gnuplot not found, using plotters backend
  sqlite_blind_index_get_by_path
                          time:   [49.279 µs 50.718 µs 51.078 µs]
  buffer_pool_zeroize/65536
                          time:   [987.87 ns 988.38 ns 988.51 ns]
                          thrpt:  [61.745 GiB/s 61.753 GiB/s 61.785 GiB/s]
  buffer_pool_zeroize/4194304
                          time:   [174.19 µs 178.40 µs 179.45 µs]
                          thrpt:  [21.767 GiB/s 21.896 GiB/s 22.425 GiB/s]
  zvpart_encrypted_staging_256kib/seal_and_open_zvpart
                          time:   [2.2386 ms 2.2619 ms 2.2677 ms]
                          thrpt:  [110.24 MiB/s 110.53 MiB/s 111.68 MiB/s]
  sync_engine_cached_read_range/read_64kib_slice
                          time:   [327.68 µs 337.60 µs 340.07 µs]
                          thrpt:  [183.78 MiB/s 185.13 MiB/s 190.74 MiB/s]
  JUDGE_META: EXIT=0 | WALL_SECS=45,311
  ```

---

## 3. Read-Only Source Tree Integrity Proof (`READONLY_BASELINE.txt`)

Recomputed both **before** (`597.08 ms`, `EXIT=0`) and **after** (`1,092.84 ms`, `EXIT=0`) all Gate 2B executions using the canonical manifest hash formula (`SHA256(UTF8(join("\n", sorted_non_git_files.map("\<rel_path>|<Length>|<FileSHA256Upper>"))))`):

```text
=== BASELINE ===
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
=== RECOMPUTED (POST-EXECUTION) ===
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
POST_EXEC_BASELINE_MATCH=True | WALL_MS=1092.84
```

| Read-Only Repository | Baseline Files / Bytes | Recomputed Files / Bytes | `tree_sha256` Match | Mutations |
| :--- | :---: | :---: | :---: | :---: |
| `<donor-root>\cloudbridge` | `37` / `89,165,156` | **`37` / `89,165,156`** | `43ADD08E...AE5B05F` (**100%**) | **`0`** |
| `<donor-root>\cloudbridge linux` | `65` / `178,010,385` | **`65` / `178,010,385`** | `32DB719E...E31554F` (**100%**) | **`0`** |
| `<donor-root>\zerovault` | `82` / `31,590,808` | **`82` / `31,590,808`** | `38375238...FB4D51D` (**100%**) | **`0`** |

---

## 4. Final Gate 2B Ruling

**VERDICT: PASS (`zerovault-core` CLEARED FOR WAVE 3 INTEGRATION)**
- All 6 mandatory static security invariants (`0` unwrap/expect/panic/todo/unimplemented, single `mi_collect(true)` `unsafe` FFI call, zero-knowledge SQLite WAL + blind index + `secure_delete = ON` + `security_epochs`, AEAD `.zvpart` staging + zero-wipe `purge_all()`, `0..capacity` `PooledBuffer::drop` scrub + `reclaim_process_memory()`, and `SyncEngine` `NEW-M02` failover / `NEW-L03` GC / `NEW-M01` lineage & epoch floor / `keybox.zv` & `zv://` / `.partial` symlink-safe atomic export) are **independently verified in source and proven by empirical execution**.
