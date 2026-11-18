# Wave 4 Gate 4 Adversarial Verification Verdict (`W4_GATE4_CHAOS_VERDICT.md`)

- **Gate:** Wave 4 Gate 4 — Adversarial Crash & Network Chaos Recovery (`Mid-Upload TerminateProcess Crash Recovery` & `30% Packet Failure Chaos Resilience`)
- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier — Zero-Trust Empirical Merger Swarm)
- **Audit Timestamp (UTC):** `2026-11-17T21:14:36Z`
- **Host Hardware & Toolchain:** AMD Ryzen 9 7950X3D (`16C/32T`, `VAES` + `VPCLMULQDQ` + `AVX2` + `AES-NI`), Windows 11 x64 (`10.0.26300`), `rustc 1.94.1 (e408947bf 2026-03-25)` (`edition = "2024"`, target `x86_64-pc-windows-msvc`)
- **Isolated Target Dir:** `<workspace>\target\swarm\judge\w4-chaos`
- **Torture Test Artifact:** [w4_gate4_crash_and_chaos.rs](tests/e2e/tests/w4_gate4_crash_and_chaos.rs)
- **Compiled Production Daemon Binary:** `target\swarm\judge\w4-chaos\release\zerovaultd.exe` (`14,663,168 B` / `13.984 MiB`, `SHA-256 = adc751756b6ef6d6a83665c38504ffd3e04cc7a73a9c25460de233a9df90940f`)
- **Read-Only Source Baseline Integrity:** **PASS (`EXACT_DIFF_COUNT = 0` across `184` files / `298,766,349` bytes)** — verified against [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt).

---

## Executive Gate 4 Decision: **`PASS (ZERO VETOES — 100% EMPIRICAL RECOVERY PROVEN)`**

Both mandatory Wave 4 Gate 4 adversarial torture scenarios passed `100%` of cryptographic, SQLite WAL, manifest atomicity, and zero-plaintext forensic checks across both parallel (`--nocapture`) and non-interleaved sequential (`--nocapture --test-threads=1`) release executions:

1. **Part A — Real OS `TerminateProcess` (`SIGKILL` Equivalent) Mid-Upload Against `zerovaultd.exe` (`PASS`):**
   - Spawned real release `zerovaultd.exe` (`PID=32860`) bound to owner-only Windows Named Pipe `\\.\pipe\zerovaultd-w4-kill-ccc463a58de843ba9851e8b29ae70b1d` (`Idle WorkingSet64 = 11.902 MiB`), committed `/baseline.bin` (`5,256,217 B`) at `rev = 1`, and launched a `128 MiB` (`134,217,728 B` = `32 × 4 MiB` chunks) `ImportLocalFile` carrying `32,768` embedded `PLAINTEXT_KILL_CANARY_884422` markers.
   - At `182.03 ms` — with all `32` `.zvpart` chunks (`134,218,624 B`) staged in `staging_dir/dirty`, **`655,112 B` (`639.76 KiB`)** of live uncheckpointed frames in `metadata.db-wal`, and **`4` of `32` new `.zv` blobs (`6` total remote `.zv` files)** actively written to `remote_cloud/blobs` — forcefully terminated `zerovaultd.exe` via Win32 `TerminateProcess` (`ExitStatus(1)`, `code = Some(1)`), severing the active Named Pipe RPC (`early eof`).
   - **Pre-Restart Forensics:** Byte-level UTF-8 + UTF-16LE scan across `state_dir` (`37` files, `134,911,234 B`), `staging_dir` (`32` files, `134,218,624 B`), and `remote_dir` (`9` files, `22,034,699 B`) proved **`0` orphaned partial plaintext bytes** (`0` canary hits, `0` filename hits). Remote `manifests/head.zvm` (`433 B`) and historical `.zvm` snapshot (`2` files total) decrypted and authenticated with **`0` corruption** (`rev = 1`).
   - **Restart & SQLite WAL Recovery:** Fresh `zerovaultd.exe` (`PID=45256`) bound the exact same Named Pipe in `32.58 ms` and unlocked in `79.34 ms`. Direct `rusqlite` audit confirmed `PRAGMA journal_mode = wal`, **`PRAGMA integrity_check = ok`**, `PRAGMA quick_check = ok`, `foreign_key_violations = 0`, and preserved dirty queue (`dirty_ops = 1`, `cursor_rev = 1`). Cold `Dehydrate` + `ExportVaultFile` of `/baseline.bin` matched `SHA-256` bit-for-bit; re-import + sync of the `128 MiB` payload (`976.67 ms`, **`131.06 MiB/s`**) advanced cleanly to **`rev = 2`**, cold dehydrate + export (`175.20 ms`, **`730.60 MiB/s`**) matched `SHA-256` bit-for-bit, and `Shutdown` exited cleanly (`code = Some(0)`) with `0` leftover `.zvpart` files.

2. **Part B — `30%` (`3000 bps`) Packet-Failure Network Chaos Recovery (`PASS`):**
   - Wrapped a 3-cloud `StorageRouter` (`cloud-alpha`, `cloud-beta`, `cloud-gamma`, `RoutingPolicy::Mirrored { min_ack: 2 }`) inside [`ChaosStorageRouter`](crates/zerovault-storage/src/chaos.rs) at **`failure_rate_bps = 3000` (`30.0%` fault injection across `put_blob`, `get_blob`, `get_blob_from_backend`, and `put_manifest_cas`)**.
   - Streamed `24 MiB` (`25,165,824 B` = `6 × 4 MiB` chunks) into [`SyncEngine`](crates/zerovault-core/src/engine.rs) in `31.83 ms`, converged `sync_once()` in **`4` attempts** (`3` transient errors) over `210.76 ms` (**`113.87 MiB/s`**) despite `3` injected upload/CAS failures (`25.0%` of `12` upload ops), draining `dirty_ops` to `0` at `rev = 1`.
   - Purged local caches across two cold passes — Pass 1 after `dehydrate()` (`HydrationState::OnlineOnly`) and Pass 2 after `dehydrate()` + `lock_and_purge_cache()` (`0 B` RAM cache, `0` `.zvpart` files) + `unlock_with_passphrase()` — and read back `2 × 24 MiB` (`48 MiB` cold) under active `30%` chaos in `223.65 ms` (**`214.62 MiB/s`**) despite **`5` injected `get_blob` failures (`29.4%` of `17` read ops; `11 / 33 = 33.3%` total injected faults)**, achieving a **`100%` bit-exact `SHA-256` match** (`0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd`), **`6` verified `.zvm` manifests (`0` corrupted)**, `PRAGMA integrity_check = ok`, and **`0` orphaned plaintext bytes** across `33` files (`88,506,968 B`).

---

## 1. Read-Only Donor Source Tree Integrity (`0` Mutations)

- **Command Executed (`EXIT = 0`, Wall-Clock `638.65 ms`, Throughput `446.23 MiB/s`):**
  ```powershell
  Get-ExactBaseline "cloudbridge"       "<donor-root>\cloudbridge"
  Get-ExactBaseline "cloudbridge linux" "<donor-root>\cloudbridge linux"
  Get-ExactBaseline "zerovault"         "<donor-root>\zerovault"
  Compare-Object -ReferenceObject (Get-Content "<workspace>\audit\READONLY_BASELINE.txt") -DifferenceObject @($r1, $r2, $r3)
  ```
- **Judge Process Physical RSS (`WorkingSet64` / `PeakWorkingSet64`):** `119,644,160 B` (`114.10 MiB`) / `119,857,152 B` (`114.30 MiB`)
- **Verbatim Output:**
  ```text
  cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
  cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
  zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
  EXACT_DIFF_COUNT=0 | ELAPSED_MS=638,65 | RSS_BYTES=119644160 | PEAK_RSS_BYTES=119857152
  ```

---

## 2. Build, Static Lint & Torture Execution Summary Matrix

| Step / Command | Exact Command Executed | Exit Code | Wall-Clock Latency | Throughput | Physical RSS (`WorkingSet64` / Peak) | Verdict |
| :--- | :--- | :---: | ---: | ---: | ---: | :---: |
| **1. Release `zerovaultd.exe` Build** | `cargo build --manifest-path "...\Cargo.toml" --release -p zerovault-daemon --locked` | **`0`** | `92,948.79 ms` *(cold)* | — | Stripped bin: `14,663,168 B` (`13.984 MiB`) | **PASS** |
| **2. Torture Harness Clippy Gate** | `cargo clippy --manifest-path "...\Cargo.toml" -p zerovault-e2e --test w4_gate4_crash_and_chaos --locked -- -D warnings` | **`0`** | `38,168.46 ms` | `0` warnings / `0` errors | — | **PASS** |
| **3. Parallel E2E Torture Run** | `cargo test --manifest-path "...\Cargo.toml" --release -p zerovault-e2e --test w4_gate4_crash_and_chaos --locked -- --nocapture` | **`0`** | `43,885.84 ms` *(`6,840 ms` exec)* | Part A: `140.50` / `601.84 MiB/s`; Part B: `109.64` / `218.77 MiB/s` | Daemon #1 Idle `11.949 MiB` / Peak `111.531 MiB`; Harness Idle `23.414 MiB` / Peak `213.000 MiB` | **PASS (`2/2`)** |
| **4. Sequential E2E Torture Run** | `cargo test --manifest-path "...\Cargo.toml" --release -p zerovault-e2e --test w4_gate4_crash_and_chaos --locked -- --nocapture --test-threads=1` | **`0`** | `9,417.02 ms` *(`8,660 ms` exec)* | Part A: `131.06` / `730.60 MiB/s`; Part B: `113.87` / `214.62 MiB/s` | Daemon #1 Idle `11.902 MiB` / Peak `111.379 MiB`; Daemon #2 `57.969 MiB` / Peak `134.906 MiB`; Harness `15.961 MiB` / Peak `141.555 MiB` | **PASS (`2/2`)** |

---

## 3. Detailed Empirical Breakdown

### 3.1 Part A — Real OS `TerminateProcess` Mid-Upload & SQLite WAL Recovery

| Metric / Forensic Invariant | Parallel Run Empirical Value | Sequential Run Empirical Value | Requirement / Gate Threshold |
| :--- | :--- | :--- | :--- |
| **Named Pipe Endpoint** | `\\.\pipe\zerovaultd-w4-kill-cd6821c093f44034a2e4f16372b6bbde` | `\\.\pipe\zerovaultd-w4-kill-ccc463a58de843ba9851e8b29ae70b1d` | Dedicated owner-ACL Windows Named Pipe |
| **Daemon #1 Cold Startup (`main -> Ping`)** | `35.20 ms` (`PID=34692`) | `33.77 ms` (`PID=32860`) | Sub-second cold IPC bind |
| **Daemon #1 Idle / Mid-128-MiB Peak `WorkingSet64`** | **`11.949 MiB`** / **`111.531 MiB`** | **`11.902 MiB`** / **`111.379 MiB`** | Bounded 4 MiB streaming pool (`< 128 MiB`) |
| **Baseline Commit (`/baseline.bin`)** | `5,256,217 B`, `rev = 1`, `2` `.zv` blobs | `5,256,217 B`, `rev = 1`, `2` `.zv` blobs | Committed `rev 1` anchor |
| **Mid-Upload `TerminateProcess` Strike** | `195.71 ms` (`reap = 5.58 ms`), **`ExitStatus(1)` (`Some(1)`)** | `182.03 ms` (`reap = 5.22 ms`), **`ExitStatus(1)` (`Some(1)`)** | Active upload killed via `Child::kill()` |
| **In-Flight State at Exact Moment of Kill** | `32` `.zvpart` staged, `6` `.zv` blobs (`4/32` new uploaded), IPC `early eof` | `32` `.zvpart` staged, `6` `.zv` blobs (`4/32` new uploaded), IPC `early eof` | Killed mid-upload to cloud |
| **Pre-Restart `metadata.db` / `metadata.db-wal` Size** | `4,096 B` / **`655,112 B`** *(live uncheckpointed WAL)* | `4,096 B` / **`655,112 B`** *(live uncheckpointed WAL)* | Genuine uncheckpointed WAL recovery |
| **Pre-Restart Plaintext Canary Scan (`state_dir`)** | `37` files (`134,911,234 B`) -> **`0` hits** | `37` files (`134,911,234 B`) -> **`0` hits** | **`0` orphaned partial plaintext** |
| **Pre-Restart Plaintext Canary Scan (`staging_dir`)** | `32` files (`134,218,624 B`) -> **`0` hits** | `32` files (`134,218,624 B`) -> **`0` hits** | **`0` orphaned partial plaintext** |
| **Pre-Restart Plaintext Canary Scan (`remote_dir`)** | `9` files (`22,034,705 B`) -> **`0` hits** | `9` files (`22,034,699 B`) -> **`0` hits** | **`0` orphaned partial plaintext** |
| **Pre-Restart Remote `.zvm` Manifest Verification** | `2` `.zvm` files verified -> **`0` corrupted** (`head.zvm` `rev = 1`, `436 B`) | `2` `.zvm` files verified -> **`0` corrupted** (`head.zvm` `rev = 1`, `433 B`) | **`0` half-written / corrupted manifests** |
| **Daemon #2 Restart & `UnlockVault` Latency** | Ready `32.68 ms`, Unlock `83.51 ms` (`PID=29564`) | Ready `32.58 ms`, Unlock `79.34 ms` (`PID=45256`) | Clean pipe re-bind & Argon2id unlock |
| **Post-Unlock SQLite WAL Integrity Audit** | `journal_mode=wal`, **`integrity_check=ok`**, `quick_check=ok`, `fk_violations=0`, `dirty_ops=1`, `cursor_rev=1` | `journal_mode=wal`, **`integrity_check=ok`**, `quick_check=ok`, `fk_violations=0`, `dirty_ops=1`, `cursor_rev=1` | Clean SQLite WAL replay (`ok`) |
| **Post-Crash `/baseline.bin` Cold `SHA-256`** | `a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d` (**MATCH**) | `a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d` (**MATCH**) | `100%` bit-exact baseline preservation |
| **`128 MiB` Re-Import + Sync & Cold Export** | Re-sync `911.06 ms` (**`140.50 MiB/s`**), Export `212.68 ms` (**`601.84 MiB/s`**), **`rev = 2`** | Re-sync `976.67 ms` (**`131.06 MiB/s`**), Export `175.20 ms` (**`730.60 MiB/s`**), **`rev = 2`** | Clean `rev` advancement + `SHA-256` match |
| **Recovered `128 MiB` `SHA-256` Digest** | `6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b` (**MATCH**) | `6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b` (**MATCH**) | `100%` bit-exact across `134,217,728 B` |
| **Graceful `Shutdown` & Post-Shutdown Audit** | `ExitCode = 0`, `integrity_check = ok`, `leftover_.zvpart = 0`, `canary_hits = 0` | `ExitCode = 0`, `integrity_check = ok`, `leftover_.zvpart = 0`, `canary_hits = 0` | Zero leaked staging or plaintext |

### 3.2 Part B — `30%` (`3000 bps`) Packet-Failure Network Chaos Recovery

| Metric / Forensic Invariant | Parallel Run Empirical Value | Sequential Run Empirical Value | Requirement / Gate Threshold |
| :--- | :--- | :--- | :--- |
| **Multi-Cloud Topology & Chaos Config** | 3 × `LocalFs` (`Mirrored`, `min_ack = 2`), `ChaosStorageRouter` `failure_rate_bps = 3000` (`30.0%`) | 3 × `LocalFs` (`Mirrored`, `min_ack = 2`), `ChaosStorageRouter` `failure_rate_bps = 3000` (`30.0%`) | `30%` across `put_blob`, `get_blob`, `put_manifest_cas` |
| **`24 MiB` (`6 × 4 MiB`) Local Staging** | `29.56 ms` (`6` `.zvpart` files, `1` `UpsertFile` dirty op) | `31.83 ms` (`6` `.zvpart` files, `1` `UpsertFile` dirty op) | Bounded 4 MiB AEAD `.zvpart` staging |
| **`sync_once()` Retry Convergence Under 30% Chaos** | **`4` attempts** (`3` transient errors) in `218.89 ms` (**`109.64 MiB/s`**), `rev = 1`, `dirty_ops = 0` | **`4` attempts** (`3` transient errors) in `210.76 ms` (**`113.87 MiB/s`**), `rev = 1`, `dirty_ops = 0` | Complete `dirty_ops` drain |
| **Injected Upload / Manifest CAS Faults** | **`3` injected failures / `12` ops (`25.0%`)** | **`3` injected failures / `12` ops (`25.0%`)** | Genuine injected faults `> 0` |
| **Cold Cache Purge (`dehydrate` + `lock_and_purge_cache`)** | `OnlineOnly`, `locally_hydrated = false`, `0 B` RAM cache, `0` `.zvpart` files | `OnlineOnly`, `locally_hydrated = false`, `0 B` RAM cache, `0` `.zvpart` files | Zero local cached plaintext before readback |
| **Cold Readback (`2 × 24 MiB = 48 MiB`) Under 30% Chaos** | `219.41 ms` (**`218.77 MiB/s`**), **`5` injected failures / `17` ops (`29.4%`)** | `223.65 ms` (**`214.62 MiB/s`**), **`5` injected failures / `17` ops (`29.4%`)** | Cold hydration + transient retry convergence |
| **Cumulative `ChaosStats` Across Run** | `total_ops = 33`, **`injected_transient_failures = 11` (`33.3%`)**, `injected_bit_flips = 0` | `total_ops = 33`, **`injected_transient_failures = 11` (`33.3%`)**, `injected_bit_flips = 0` | ~30% packet failure across all storage ops |
| **Rehydrated `24 MiB` `SHA-256` Digest** | `0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd` (**`100%` MATCH**) | `0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd` (**`100%` MATCH**) | `100%` bit-exact across both cold passes |
| **Multi-Cloud `.zvm` Manifest Verification** | **`6` `.zvm` files verified across 3 clouds -> `0` corrupted** | **`6` `.zvm` files verified across 3 clouds -> `0` corrupted** | **`0` corrupted manifests** |
| **Post-Chaos SQLite WAL & Zero-Plaintext Scan** | `integrity_check = ok`, `33` files (`88,506,968 B`) -> **`0` plaintext hits** | `integrity_check = ok`, `33` files (`88,506,968 B`) -> **`0` plaintext hits** | **`0` orphaned plaintext files** |
| **Harness Process Physical RSS (`WorkingSet64` / Peak)** | `23.414 MiB` / `213.000 MiB` *(shared w/ Part A)* | **`15.961 MiB`** / **`141.555 MiB`** *(isolated)* | Idle reclamation verified |

---

## 4. Verbatim Raw Stdout Excerpts

### 4.1 Exact Mandatory Command Execution (`Parallel --nocapture`, `EXIT = 0`)
```powershell
$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-chaos"
cargo test --manifest-path "<workspace>\Cargo.toml" --release -p zerovault-e2e --test w4_gate4_crash_and_chaos --locked -- --nocapture
```
```text
    Finished `release` profile [optimized] target(s) in 36.86s
     Running tests\w4_gate4_crash_and_chaos.rs (entrocloud merge\target\swarm\judge\w4-chaos\release\deps\w4_gate4_crash_and_chaos-6f04202521a9dd76.exe)

running 2 tests
=== [PART B] 30% (3000 bps) PACKET FAILURE NETWORK CHAOS TORTURE TEST ===
=== [PART A] REAL TerminateProcess MID-UPLOAD TORTURE TEST ===
[PART A] zerovaultd binary: <workspace>\target\swarm\judge\w4-chaos\release\zerovaultd.exe (14663168 bytes, sha256=adc751756b6ef6d6a83665c38504ffd3e04cc7a73a9c25460de233a9df90940f)
[PART B][UPLOAD CONVERGENCE] Staged 24 MiB in 29.56 ms | Converged in 4 sync_once() attempts (3 transient errors) over 218.89 ms (109.64 MiB/s) | upload_chaos_ops=12 injected_failures=3 (25.0%) | sample_fault="storage backend error: chaos injected transient packet failure during put_blob on 'blobs/af/3f/af3f835f-8155-4b0a-98ef-c23881e978ec.zv'"
[PART B][COLD READBACK] Hydrated & verified 2 × 24 MiB (48 MiB cold) in 219.41 ms (218.77 MiB/s) | read_chaos_ops=17 injected_failures=5 (29.4%) | total_chaos_stats=ChaosStats { total_ops: 33, injected_transient_failures: 11, injected_bit_flips: 0 } | sha256=0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd (100% MATCH)
[PART A] Pipe endpoint=\\.\pipe\zerovaultd-w4-kill-cd6821c093f44034a2e4f16372b6bbde | baseline=5256217 B (sha256=a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d) | kill_target=134217728 B / 128.00 MiB (sha256=6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b)
[PART A] Daemon #1 (PID=34692) ready in 35.20 ms | Idle WorkingSet64=11.949 MiB (Peak=11.949 MiB)
[PART A] Committed `/baseline.bin` at manifest rev=1 | remote_blobs=2
[PART A] TerminateProcess struck at 195.71 ms (reap=5.58 ms) | exit_status=ExitStatus(ExitStatus(1)) (code=Some(1)) | Peak WorkingSet64=111.531 MiB | staged_at_kill=32 | remote_blobs_at_kill=6 | interrupted_ipc_err=IPC error: failed reading IPC frame length header: early eof
[PART B] PASS in 1323.91 ms | verified_manifests=6 (corrupted=0) | SQLite integrity_check=ok | scanned 33 files (88506968 B) -> 0 orphaned plaintext bytes | Harness WorkingSet64=23.414 MiB (Peak=213.000 MiB)
test part_b_thirty_percent_packet_failure_network_chaos_recovery ... ok
[PART A][FORENSIC PRE-RESTART] metadata.db=4096 B | metadata.db-wal=655112 B | staged_.zvpart=32 | remote_.zv=6
[PART A][FORENSIC PRE-RESTART] Plaintext Canary Scan -> state_dir: 37 files (134911234 B, 0 hits) | staging_dir: 32 files (134218624 B, 0 hits) | remote_dir: 9 files (22034705 B, 0 hits)
[PART A][FORENSIC PRE-RESTART] Verified 2 remote .zvm manifest files (0 corrupted) | head.zvm rev=1 id=69058399-a2d9-5e31-18c1-92cc33116816 (436 B)
[PART A][WAL RECOVERY] Daemon #2 (PID=29564) ready in 32.68 ms, unlocked in 83.51 ms | journal_mode=wal | integrity_check=ok | quick_check=ok | fk_violations=0 | inodes=3 chunks=2 dirty_ops=1 cursor_rev=1
[PART A][RECOVERY] `/baseline.bin` verified 100% bit-exact (5256217 B, sha256=a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d)
[PART A][RECOVERY] 128 MiB re-import+sync=911.06 ms (140.50 MiB/s) | cold dehydrate+export=212.68 ms (601.84 MiB/s) | rev=2 | sha256=6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b (MATCH) | PID #2 WorkingSet64=56.520 MiB (Peak=113.934 MiB)
[PART A] PASS in 6748.19 ms | Daemon #2 exit=Some(0) | final SQLite integrity_check=ok | leftover_.zvpart=0 | plaintext_canary_hits=0
test part_a_real_terminate_process_mid_upload_and_sqlite_wal_recovery ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.84s
TEST_EXIT_CODE=0 WALL_MS=43885,84
```

### 4.2 Non-Interleaved Sequential Execution (`--nocapture --test-threads=1`, `EXIT = 0`)
```powershell
$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-chaos"
cargo test --manifest-path "<workspace>\Cargo.toml" --release -p zerovault-e2e --test w4_gate4_crash_and_chaos --locked -- --nocapture --test-threads=1
```
```text
    Finished `release` profile [optimized] target(s) in 0.65s
     Running tests\w4_gate4_crash_and_chaos.rs (entrocloud merge\target\swarm\judge\w4-chaos\release\deps\w4_gate4_crash_and_chaos-6f04202521a9dd76.exe)

running 2 tests
test part_a_real_terminate_process_mid_upload_and_sqlite_wal_recovery ... === [PART A] REAL TerminateProcess MID-UPLOAD TORTURE TEST ===
[PART A] zerovaultd binary: <workspace>\target\swarm\judge\w4-chaos\release\zerovaultd.exe (14663168 bytes, sha256=adc751756b6ef6d6a83665c38504ffd3e04cc7a73a9c25460de233a9df90940f)
[PART A] Pipe endpoint=\\.\pipe\zerovaultd-w4-kill-ccc463a58de843ba9851e8b29ae70b1d | baseline=5256217 B (sha256=a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d) | kill_target=134217728 B / 128.00 MiB (sha256=6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b)
[PART A] Daemon #1 (PID=32860) ready in 33.77 ms | Idle WorkingSet64=11.902 MiB (Peak=11.902 MiB)
[PART A] Committed `/baseline.bin` at manifest rev=1 | remote_blobs=2
[PART A] TerminateProcess struck at 182.03 ms (reap=5.22 ms) | exit_status=ExitStatus(ExitStatus(1)) (code=Some(1)) | Peak WorkingSet64=111.379 MiB | staged_at_kill=32 | remote_blobs_at_kill=6 | interrupted_ipc_err=IPC error: failed reading IPC frame length header: early eof
[PART A][FORENSIC PRE-RESTART] metadata.db=4096 B | metadata.db-wal=655112 B | staged_.zvpart=32 | remote_.zv=6
[PART A][FORENSIC PRE-RESTART] Plaintext Canary Scan -> state_dir: 37 files (134911234 B, 0 hits) | staging_dir: 32 files (134218624 B, 0 hits) | remote_dir: 9 files (22034699 B, 0 hits)
[PART A][FORENSIC PRE-RESTART] Verified 2 remote .zvm manifest files (0 corrupted) | head.zvm rev=1 id=7cfb4e46-0eb2-45ee-7da1-7925ad2c3383 (433 B)
[PART A][WAL RECOVERY] Daemon #2 (PID=45256) ready in 32.58 ms, unlocked in 79.34 ms | journal_mode=wal | integrity_check=ok | quick_check=ok | fk_violations=0 | inodes=3 chunks=2 dirty_ops=1 cursor_rev=1
[PART A][RECOVERY] `/baseline.bin` verified 100% bit-exact (5256217 B, sha256=a6c341a31cc378b2b9bfd07bf366976aa8aa00d30bee765ab0eee5e607b5b37d)
[PART A][RECOVERY] 128 MiB re-import+sync=976.67 ms (131.06 MiB/s) | cold dehydrate+export=175.20 ms (730.60 MiB/s) | rev=2 | sha256=6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b (MATCH) | PID #2 WorkingSet64=57.969 MiB (Peak=134.906 MiB)
[PART A] PASS in 6864.54 ms | Daemon #2 exit=Some(0) | final SQLite integrity_check=ok | leftover_.zvpart=0 | plaintext_canary_hits=0
ok
test part_b_thirty_percent_packet_failure_network_chaos_recovery ... === [PART B] 30% (3000 bps) PACKET FAILURE NETWORK CHAOS TORTURE TEST ===
[PART B][UPLOAD CONVERGENCE] Staged 24 MiB in 31.83 ms | Converged in 4 sync_once() attempts (3 transient errors) over 210.76 ms (113.87 MiB/s) | upload_chaos_ops=12 injected_failures=3 (25.0%) | sample_fault="storage backend error: chaos injected transient packet failure during put_blob on 'blobs/16/64/16640ae8-0653-47ac-9153-f499fb460246.zv'"
[PART B][COLD READBACK] Hydrated & verified 2 × 24 MiB (48 MiB cold) in 223.65 ms (214.62 MiB/s) | read_chaos_ops=17 injected_failures=5 (29.4%) | total_chaos_stats=ChaosStats { total_ops: 33, injected_transient_failures: 11, injected_bit_flips: 0 } | sha256=0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd (100% MATCH)
[PART B] PASS in 1675.75 ms | verified_manifests=6 (corrupted=0) | SQLite integrity_check=ok | scanned 33 files (88506968 B) -> 0 orphaned plaintext bytes | Harness WorkingSet64=15.961 MiB (Peak=141.555 MiB)
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.66s
CLIPPY_EXIT=0 CLIPPY_MS=38168,46
SEQ_TEST_EXIT=0 SEQ_WALL_MS=9417,02
```
