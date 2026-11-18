# EntroCloud v1.0 Final Adversarial Verification Verdict (`ENTROCLOUD_V1_FINAL_VERDICT.md`)

**Auditor:** `Agent-Judge` (Adversarial Red-Team & Empirical Proof Verifier)  
**Audit Date (UTC):** `2026-11-17T23:52:41Z`  
**Workspace Root:** [`<workspace>`](.)  
**Isolated Cargo Target Dir:** `<workspace>\target\swarm\judge\ec-v1`  
**Host Hardware & Toolchain:** AMD Ryzen 9 7950X3D (`16C/32T`, `31.6 GiB` DDR5, `VAES+VPCLMULQDQ+AVX2`) + NVIDIA GeForce RTX 4080 SUPER (`OpenGL 3.3.0 NVIDIA 621.01`) + Windows 11 x64 (`10.0.26300.0`) + `rustc 1.94.1 (e408947bf 2026-03-25)` (`edition = "2024"`, `x86_64-pc-windows-msvc` & `x86_64-unknown-linux-musl`)  
**Executive Verdict:** **`PASS — GATES A, B, C, D & E EMPIRICALLY VERIFIED ON SILICON (`0` ACTIVE VETOES; `EC-V1-VETO-01` CAUGHT IN ROUND 1, REMEDIATED & RE-VERIFIED IN ROUND 2; `DIFF_COUNT = 0` ON ALL READ-ONLY TREES)`**

---

## Executive Summary Matrix

| Gate | Mandatory Empirical Verification Scope | Final Status | Exit Code | Wall-Clock Latency | Throughput | Idle / Peak Physical RSS (`WorkingSet64`) | Empirical Proof Summary |
| :-: | :--- | :---: | :---: | ---: | ---: | ---: | :--- |
| **A** | **8-Crate Static Production Audit** (`crates/entrocloud-*/src/**/*.rs`, `66` files, `45,678` LOC) | **`PASS`** | `0` | `1,326.88 ms` | `1.21 MiB/s` (`1,688,234 B`) | `67.14 MiB` / `158.81 MiB` | **`0`** prod `.unwrap()`/`.expect()`/`panic!()`/`todo!()`/`unimplemented!()`; **`27`** documented `unsafe` blocks (`0` undocumented); **`0`** Unicode emojis in `entrocloud-ui/src/**`; **`0`** sync `rfd::FileDialog` on UI thread (`8` async `AsyncDialogs` dispatches) |
| **B.1** | **Full-Workspace MSVC Clippy** (`--workspace --all-targets --locked -- -D warnings`) | **`PASS`** | `0` | `4,946.88 ms` *(R2; `42,736.84 ms` R1 cold)* | — | `2.57 MiB` / `1,252.39 MiB` *(`3,522.00 MiB` cold)* | **`0` warnings / `0` errors** across all `9` workspace crates (`8` prod + `entrocloud-e2e`), all tests, & all benches |
| **B.2** | **Arch Linux `x86_64-unknown-linux-musl` Clippy** (`-p entrocloud-types -p entrocloud-vfs --all-targets --locked -- -D warnings`) | **`PASS`** | `0` | `15,545.37 ms` | — | `2.57 MiB` / `2,148.77 MiB` | **`0` warnings / `0` errors** on `x86_64-unknown-linux-musl` (`fuser v0.18.0`, `nix v0.31.4`, `libc v0.2.191`) |
| **C.1** | **Full 8-Crate Unit / Integration / Proptest Suite** (`--workspace --exclude entrocloud-e2e --locked` + R2 daemon/cli regression) | **`PASS`** | `0` | `116,708.00 ms` *(R1 full)* + `55,219.40 ms` *(R2 daemon+cli)* | — | `2.57 MiB` / `7,651.30 MiB` *(parallel Argon2id)* | **`126 passed / 0 failed / 1 ignored`** (`10/10` `entrocloud-ui` [`9` `ui_integration` + `1` bin], `18/18` `entrocloud-daemon` incl. `BackupJob` lifecycle, `TestRemote`, `CancelOAuth`, `ec://`+`zv://`, & `debug` `entrocloudd` stack-safety subprocess test) |
| **C.2** | **Release E2E Security, Crash/WAL & `30%` Chaos Suites** (`w4_gate2_3_zk_and_tamper` + `w4_gate4_crash_and_chaos`, `--release --test-threads=1`) | **`PASS`** *(R1 `EXIT=101` -> `EC-V1-VETO-01` -> R2 `EXIT=0`)* | `0` | `107,978.59 ms` *(incl. on-demand `release\entrocloudd.exe` build; `8.23 s` warm)* | `145.33 MiB/s` re-sync / **`733.12 MiB/s`** cold export / `258.50 MiB/s` chaos hydration | `2.58 MiB` / `142.73 MiB` *(runtime; `3,490.13 MiB` build)* | **`9 / 9` passed (`7/7` ZK+Tamper + `2/2` Kill+Chaos)**; with `release\entrocloudd.exe` deleted & `debug\entrocloudd.exe` present, refused `debug`, built `release\entrocloudd.exe` on demand, & passed `100%` |
| **D** | **Portable Release Bundle (`bundle-portable.ps1`), Zero-WebView Audit, `10×` Cold Start, `3×` Tray & Live `WM_CLOSE`** | **`PASS`** | `0` | `51,729.65 ms` *(R2 bundle; `100,823.26 ms` R1 cold)* | `0.564 MiB/s` (`29.197 MiB` stripped code) | Cold UI: **`76.313 MiB`** p50 \| Tray: **`8.762 MiB`** p50 \| Closed UI: **`0 B`** | **`4/4` `Assert-ZeroWebViewBinary` PASS**; `EntroCloud.exe` (`5.917 MiB` GUI) & `entrocloud-tray.exe` (`0.848 MiB` GUI); `10×` cold open **`p50 = 150.064 ms` (R1) / `159.710 ms` (R2)**; `0` child processes (`0` `conhost`, `0` WebView2); `WM_CLOSE` exits `0` in **`83.165 ms`** -> **`0 B` RAM** |
| **E** | **Final `READONLY_BASELINE.txt` Source Preservation Check** (`cloudbridge`, `cloudbridge linux`, `zerovault`) | **`PASS`** | `0` | `656.81 ms` *(R2; `584.09 ms` R1)* | **`433.80 MiB/s`** *(`487.81 MiB/s` R1)* | `64.23 MiB` / `114.88 MiB` | **`DIFF_COUNT = 0`** across all `184` non-`.git` files (`298,766,349` bytes) |

---

## 1. Adversarial Veto & Remediation Log (`EC-V1-VETO-01`: Caught in Round 1 -> Remediated & Verified in Round 2)

Under strict Separation of Powers (`Agent-Judge` never writing production code and distrusting all unverified claims), Round 1 execution in a clean `CARGO_TARGET_DIR` (`target\swarm\judge\ec-v1`) caught a concrete two-part defect (**`EC-V1-VETO-01`**) during **Gate C.2**:

| Veto ID | Defect Caught Empirically by `Agent-Judge` (Round 1) | Exact Root-Cause Remediation Applied | Round 2 Clean-State Re-Verification Proof |
| :--- | :--- | :--- | :--- |
| **`EC-V1-VETO-01` (Part A)** | Direct invocation of unoptimized `debug\entrocloudd.exe` immediately crashed before binding its Named Pipe with `thread 'main' (48140) has overflowed its stack` (`EXIT = -1073741571` / `0xC00000FD STATUS_STACK_OVERFLOW`) because `#[tokio::main] async fn main()` ran `block_on(...)` on the Windows `1 MiB` default PE main-thread stack with an unboxed multi-arm `DaemonRuntime::handle_request` state machine. | [`crates/entrocloud-daemon/src/main.rs:25-133`](crates/entrocloud-daemon/src/main.rs#L25-L133) now spawns a dedicated `8 MiB` host thread (`entrocloudd-main`) + `8 MiB` Tokio worker stacks (`DAEMON_THREAD_STACK_BYTES = 8 * 1024 * 1024`) with `Box::pin(async_main(args))`, `Box::pin(ctrl_c_shutdown)`, and `Box::pin` per-request handler; [`service.rs:1012-1017`](crates/entrocloud-daemon/src/service.rs#L1012-L1017) returns a `16`-byte `Pin<Box<dyn Future<Output = DaemonResponse> + Send + '_>>`; added subprocess regression test [`debug_entrocloudd_binary_boots_and_answers_ping_without_stack_overflow`](crates/entrocloud-daemon/tests/daemon_integration.rs#L2031-L2133). | `cargo test -p entrocloud-daemon -p entrocloud-cli --locked` -> **`EXIT=0` (`24/24` passed)**; `size_of_val(&fut) == 16 B` verified; live `debug\entrocloudd.exe` subprocess booted on `\\.\pipe\entrocloudd-subproc-<uuid>`, answered `Ping` (`"pong"`), `Status`, and `Shutdown`, and exited cleanly with `code = Some(0)`. Stripped `release\entrocloudd.exe` also shrank by `184,320 B` (`14.221 MiB -> 14.045 MiB`). |
| **`EC-V1-VETO-01` (Part B)** | When Gate C.2 (`cargo test --release -p entrocloud-e2e ...`) ran immediately after Gate C.1 (`cargo test --workspace ...`) prior to Gate D, `resolve_entrocloudd_binary()` in `w4_gate4_crash_and_chaos.rs` checked `CARGO_TARGET_DIR/debug/entrocloudd.exe` *before* checking `is_release_profile`, silently downgrading the `--release` torture test to `debug\entrocloudd.exe` (`EXIT=101`). | [`tests/e2e/tests/w4_gate4_crash_and_chaos.rs:404-485`](tests/e2e/tests/w4_gate4_crash_and_chaos.rs#L404-L485) now computes `is_release_profile` FIRST (`!cfg!(debug_assertions)` / `release` parent directory) and strictly resolves or builds `entrocloudd(.exe)` inside the matching `release` or `debug` profile subdirectory (zero cross-profile fallback). | Deleted `release\entrocloudd.exe` (`release_entrocloudd_exists=False`, `debug_entrocloudd_exists=True`) and ran Gate C.2: harness ignored `debug\entrocloudd.exe`, invoked `cargo build --release --locked -p entrocloud-daemon --bin entrocloudd`, printed `[PART A] entrocloudd binary: ...\release\entrocloudd.exe`, and passed **`9/9` (`EXIT=0`)**. |

---

## 2. Gate A — Static Production Audit Across All 8 Crates (`PASS`)

- **Exact Command Executed (Round 2 Post-Remediation):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\target\swarm\judge\ec-v1\scripts\gate_a_audit.ps1"
  ```
- **Exit Code:** `0` | **Wall-Clock Latency:** `1,326.88 ms` | **Throughput:** `1.21 MiB/s` (`1,688,234 B` across `66` `.rs` files / `45,678` LOC) | **Process RSS (`WorkingSet64`):** Idle `70,406,144 B` (`67.14 MiB`) / End `128,061,440 B` (`122.13 MiB`) / Peak `166,522,880 B` (`158.81 MiB`).

### 2.1 Per-Crate Production Panic-Safety & `unsafe` Audit Table

| Production Crate | `src/` `.rs` Files | Total LOC | Total Bytes | Prod `.unwrap()` / `.expect()` / `panic!()` / `todo!()` / `unimplemented!()` | `#[cfg(test)]` Matches | Prod `unsafe` Blocks | Undocumented `unsafe` | Audited `unsafe` FFI Locations |
| :--- | ---: | ---: | ---: | :---: | ---: | :---: | :---: | :--- |
| [`entrocloud-cli`](crates/entrocloud-cli/src/lib.rs) | `3` | `1,533` | `54,672` | **`0`** | `0` | **`0`** | **`0`** | Pure safe Rust (`ec` CLI: backup jobs, OAuth PKCE, routing, `ec://`/`zv://` shares) |
| [`entrocloud-core`](crates/entrocloud-core/src/lib.rs) | `6` | `5,485` | `202,276` | **`0`** | `0` | **`1`** | **`0`** | `pool.rs:36` (`libmimalloc_sys::mi_collect(true)`) |
| [`entrocloud-crypto`](crates/entrocloud-crypto/src/lib.rs) | `6` | `2,068` | `74,499` | **`0`** | `0` | **`0`** | **`0`** | Safe Rust over `ring 0.17.14` (`VAES+VPCLMULQDQ`), `aws-lc-rs 1.19.0` (`ML-KEM-768+X25519+Ed25519`), `argon2` |
| [`entrocloud-daemon`](crates/entrocloud-daemon/src/lib.rs) | `6` | `8,310` | `304,328` | **`0`** | `0` | **`8`** | **`0`** | `dacl.rs:150,181,207,230,255,284,305,327` (Win32 owner-only DACL `D:P(A;;GA;;;SY)(A;;GA;;;OW)`) |
| [`entrocloud-storage`](crates/entrocloud-storage/src/lib.rs) | `5` | `4,143` | `150,007` | **`0`** | `0` | **`0`** | **`0`** | Pure safe Rust OpenDAL (`GDrive`, `OneDrive`, `Dropbox`, `S3`, `WebDAV`, `LocalFs`), PKCE, `ChaosStorageRouter` |
| [`entrocloud-types`](crates/entrocloud-types/src/lib.rs) | `7` | `5,098` | `191,239` | **`0`** | `25` | **`0`** | **`0`** | Pure safe Rust wire envelopes (`ZVH1`/`ZVC1`/`ZVM1`/`ZVS1`/`ZVK1`), `BackupJobSpec`, `ec://`+`zv://` `CapabilityUri` |
| [`entrocloud-ui`](crates/entrocloud-ui/src/lib.rs) | `24` | `13,600` | `519,683` | **`0`** | `0` | **`18`** | **`0`** | `app.rs:1258`, `bin/entrocloud_tray.rs:303`, `ipc_client.rs:551,564,569,572`, `metrics.rs:111,134,166,296`, `session.rs:449,504`, `theme.rs:400,498,523,530,546,557` |
| [`entrocloud-vfs`](crates/entrocloud-vfs/src/lib.rs) | `9` | `5,441` | `191,530` | **`0`** | `8` | **`0`** | **`0`** | Pure safe Rust Windows `cloud-filter` (`CfApi`) & Arch Linux `fuser v0.18.0` (`FUSE3`) |
| **TOTAL (`8` Crates)** | **`66`** | **`45,678`** | **`1,688,234`** | **`0`** | `33` *(100% unit tests)* | **`27`** | **`0`** | **`100%` documented with explicit `// SAFETY:` invariants** |

### 2.2 Verbatim Gate A Output (Zero Emojis & Zero Synchronous UI-Thread `rfd::FileDialog`)
```text
TOTAL_8_CRATES: CRATES=8 | FILES=66 | LOC=45678 | BYTES=1688234 | PROD_VIOLATIONS=0 | TEST_MATCHES=33 | PROD_UNSAFE=27 | UNDOC_UNSAFE=0

=== GATE A.2: UNICODE EMOJI & NON-ASCII AUDIT IN crates/entrocloud-ui/src/**/*.rs ===
UI_RS_FILES_SCANNED=24 | UNICODE_EMOJI_HITS=0 | DISTINCT_NON_ASCII_CODEPOINTS=2
  NON_ASCII: U+2014 ('—') count=21 sample=app.rs:5
  NON_ASCII: U+2022 ('•') count=9 sample=demo.rs:394

=== GATE A.3: SYNCHRONOUS rfd::FileDialog AUDIT IN crates/entrocloud-ui/src/** ===
UI_THREAD_FILES_SCANNED=10 (app.rs, wizard.rs, views/backups.rs, views/clouds.rs, views/drive.rs, views/files.rs, views/mod.rs, views/settings.rs, views/sharing.rs, views/unlock.rs)
UI_THREAD_SYNC_RFD_FILEDIALOG_HITS=0 | NON_BLOCKING_ASYNC_DIALOG_DISPATCHES=8
ALL_RFD_REFERENCES_IN_ENTROCLOUD_UI_SRC:
  dialogs.rs:119: let picked = rfd::FileDialog::new().set_title(&title_owned).pick_files();
  dialogs.rs:155: let mut dlg = rfd::FileDialog::new().set_title(&title_owned);
  dialogs.rs:194: let mut dlg = rfd::FileDialog::new().set_title(&title_owned);
GATE_A_TELEMETRY: EXIT_CODE=0 | ELAPSED_MS=1326.88 | THROUGHPUT_MIB_S=1.21 | IDLE_RSS_BYTES=70406144 (67.14 MiB) | END_RSS_BYTES=128061440 (122.13 MiB) | PEAK_RSS_BYTES=166522880 (158.81 MiB)
```

---

## 3. Gate B — Full-Workspace Zero-Warning Clippy (`MSVC` + Arch Linux `x86_64-unknown-linux-musl`) (`PASS`)

- **Exact Commands Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\ec-v1"
  cargo clippy --manifest-path "<workspace>\Cargo.toml" --workspace --all-targets --locked -- -D warnings
  cargo clippy --manifest-path "<workspace>\Cargo.toml" -p entrocloud-types -p entrocloud-vfs --all-targets --locked --target x86_64-unknown-linux-musl -- -D warnings
  ```

| Target Triple & Scope | Exit Code | Wall-Clock Latency | Initial / End / Peak Tree RSS (`WorkingSet64`) | Empirical Result |
| :--- | :---: | ---: | ---: | :--- |
| **`x86_64-pc-windows-msvc` (`--workspace --all-targets --locked -- -D warnings`)** | **`0`** | `42,736.84 ms` *(R1 cold)* \| **`4,946.88 ms`** *(R2 final)* | `2.58 MiB` / `63.87 MiB` / `3,522.00 MiB` *(cold)* \| `2.57 MiB` / `145.41 MiB` / `1,252.39 MiB` *(R2)* | **`0` warnings / `0` errors** across all `9` crates |
| **`x86_64-unknown-linux-musl` (`-p entrocloud-types -p entrocloud-vfs --all-targets --locked -- -D warnings`)** | **`0`** | **`15,545.37 ms`** | `2.57 MiB` / `2.65 MiB` / `2,148.77 MiB` | **`0` warnings / `0` errors** (`fuser v0.18.0`, `nix v0.31.4`) |

### Verbatim Gate B Stdout/Stderr Excerpts
```text
HOST_MSVC_CLIPPY (R1 Cold): EXIT=0 | ELAPSED_MS=42736.84 | INITIAL_RSS_BYTES=2703360 (2.58 MiB) | PEAK_TREE_RSS_BYTES=3693088768 (3522.00 MiB) | END_RSS_BYTES=66973696 (63.87 MiB)
R2_CLIPPY (Final):          EXIT=0 | ELAPSED_MS=4946.88  | INIT_RSS_BYTES=2695168 (2.57 MiB)    | PEAK_TREE_RSS_BYTES=1313226752 (1252.39 MiB) | END_RSS_BYTES=152469504 (145.41 MiB)
    Checking entrocloud-daemon v1.0.0 (<workspace>\crates\entrocloud-daemon)
    Checking entrocloud-cli v1.0.0 (<workspace>\crates\entrocloud-cli)
    Checking entrocloud-e2e v1.0.0 (<workspace>\tests\e2e)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.78s

LINUX_MUSL_CLIPPY:          EXIT=0 | ELAPSED_MS=15545.37 | INITIAL_RSS_BYTES=2699264 (2.57 MiB) | PEAK_TREE_RSS_BYTES=2253148160 (2148.77 MiB) | END_RSS_BYTES=2777088 (2.65 MiB)
    Checking entrocloud-types v1.0.0 (<workspace>\crates\entrocloud-types)
    Checking entrocloud-vfs v1.0.0 (<workspace>\crates\entrocloud-vfs)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.39s
```

---

## 4. Gate C — Full 8-Crate Test Suite (`126/126` Active) + Release E2E Suites (`9/9` Security, Kill/WAL & `30%` Chaos) (`PASS`)

### 4.1 Gate C.1 — Full 8-Crate Unit, Integration & Proptest Suite
- **Exact Commands Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\ec-v1"
  cargo test --manifest-path "<workspace>\Cargo.toml" --workspace --exclude entrocloud-e2e --locked
  cargo test --manifest-path "<workspace>\Cargo.toml" -p entrocloud-daemon -p entrocloud-cli --locked
  ```
- **Exit Code:** `0` | **Wall-Clock Latency:** `116,708.00 ms` (full 8-crate cold compile + run) + `55,219.40 ms` (Round 2 `entrocloud-daemon` + `entrocloud-cli` re-run) | **Process Tree RSS (`WorkingSet64`):** Initial `2,699,264 B` (`2.57 MiB`) / Peak `8,022,970,368 B` (`7,651.30 MiB` parallel compile + Argon2id suites) / End `45,473,792 B` (`43.37 MiB`).
- **Per-Crate Active Test Breakdown (`126 passed / 0 failed / 1 ignored`):**
  - `entrocloud-cli`: **`6 / 6`** (`1` lib + `1` `ec` bin + `4` `cli_integration` covering `ec backup`, `ec remote test`, `ec share`, `Zeroizing` secrets)
  - `entrocloud-core`: **`16 / 16`** (`2` lib + `9` `core_suite` + `5` `proptest_core`)
  - `entrocloud-crypto`: **`19 / 19`** (`19` `crypto_suite` covering `ring` VAES+VPCLMULQDQ, `aws-lc-rs` `ML-KEM-768+X25519+Ed25519`, Argon2id, `ZVS2` keyring)
  - `entrocloud-daemon`: **`18 / 18`** (`7` lib + `1` `entrocloudd` bin + `10` `daemon_integration` including `cloudbridge_pc_folder_backup_incremental_preview_retention_restore_and_scheduler`, `pre_vault_remote_onboarding_test_remote_and_cancel_oauth`, `capability_uri_share_and_post_quantum_keybox_epoch_1_to_2_revocation` [`ec://` + `zv://`], and `debug_entrocloudd_binary_boots_and_answers_ping_without_stack_overflow`)
  - `entrocloud-storage`: **`22 / 22`** (`5` lib + `11` `storage_integration` + `6` `storage_proptest`)
  - `entrocloud-types`: **`7 / 7`** (`7` lib wire format & `ec://`/`zv://` `CapabilityUri` tests)
  - `entrocloud-ui`: **`9 / 9` `ui_integration` (`+ 0` lib/bin = `9` integration tests, `EXIT=0` in `4.41 s`)** covering Light/Dark themes, all 4 Wizard steps & 6 cloud setup guides, Backup views, Grid/List explorer, non-blocking `OAuthLogin` + `CancelOAuth`, `AsyncDialogs`, immediate passphrase zeroization, `ec://` + `zv://` `--open-uri`, zero-emoji/zero-sync-`rfd` source audit, and live `--bench-cold`/`--bench-tray` PE `.rdata` verification!
  - `entrocloud-vfs`: **`29 / 29` active** (`1` lib + `8` `linux_vfs_tests` + `20` `windows_vfs_tests` + `1` live Explorer CfApi SyncRoot ignored)
  - `Doc-tests`: **`0` failed** across all `8` crates.

### 4.2 Gate C.2 — Release E2E Security, `TerminateProcess` Crash/WAL Recovery & `30%` Chaos (`9/9 PASS`)
- **Exact Command Executed (with `release\entrocloudd.exe` deleted & `debug\entrocloudd.exe` present):**
  ```powershell
  Remove-Item -Force "<workspace>\target\swarm\judge\ec-v1\release\entrocloudd.exe"
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\ec-v1"
  cargo test --manifest-path "<workspace>\Cargo.toml" --release -p entrocloud-e2e --test w4_gate2_3_zk_and_tamper --test w4_gate4_crash_and_chaos --locked -- --nocapture --test-threads=1
  ```
- **Exit Code:** **`0`** (`7/7` in `w4_gate2_3_zk_and_tamper` [`3.40 s`] + `2/2` in `w4_gate4_crash_and_chaos` [`59.39 s` incl. on-demand `cargo build --release -p entrocloud-daemon --bin entrocloudd`; `8.23 s` warm] = **`9 / 9` passed**) | **Wall-Clock Latency:** `107,978.59 ms` | **Runtime E2E RSS (`WorkingSet64`):** `w4_gate2_3_zk_and_tamper` `9.93 MiB` idle -> `104.62 MiB` peak -> `30.01 MiB` post-reclaim; `entrocloudd.exe` #1 `12.609 MiB` idle -> `97.719 MiB` mid-`128 MiB` kill peak; `w4_gate4_crash_and_chaos` harness `16.328 MiB` idle -> `142.734 MiB` peak.

#### Verbatim Gate C.2 Raw Stdout Excerpts
```text
PRE_E2E_STATE: release_entrocloudd_exists=False | debug_entrocloudd_exists=True
R2_RELEASE_E2E_9OF9: EXIT=0 | ELAPSED_MS=107978.59 | INIT_RSS_BYTES=2703360 (2.58 MiB) | PEAK_TREE_RSS_BYTES=3659669504 (3490.13 MiB) | END_RSS_BYTES=56258560 (53.65 MiB)

test t01_gate2_zero_knowledge_storage_sqlite_and_staging_inspection ... [PROOF-GATE2-ZK] status=PASS matches=0 needles=22 (UTF-8+UTF-16LE) remote_files=30 (.zv=9, .zvm=14, .zvh=3, .zvs=2, keybox.zv=2) staging_zvpart=1 staging_bytes=23748 sqlite_ddl=14 tables=8 rows=17 cols=134 pre_ckpt_wal_bytes=189552 post_ckpt_wal_bytes=0 raw_db_bytes=61440 raw_shm_bytes=32768 total_scanned_bytes=19514434 (18.610 MiB @ 10.51 MiB/s) elapsed_ms=1770.54 rss_before_mib=9.93 rss_active_mib=42.99 rss_peak_mib=100.60 priv_active_mib=29.89 rss_post_reclaim_mib=30.01
test t03_gate3_attack2_chunk_3_and_4_swap_fails_closed ... [PROOF-GATE3-ATTACK2] status=PASS file_mib=24 chunks=6 ... forged_hdr_25b_aad_c3=Err(CryptoTamperDetected("... AES-256-GCM authentication tag mismatch")) plaintext_bytes_returned=0 throughput_mib_s=102.42 elapsed_ms=234.32 rss_mib=66.64 peak_rss_mib=104.62
test t06_gate3_attack5_keybox_epoch1_rollback_replay_after_epoch2_revocation_fails_closed ... [PROOF-GATE3-ATTACK5] status=PASS bob_revoked_ep2=Err(UnauthorizedRecipient("a5187de35f377164ad5dd67037dcda47")) sqlite_epoch_floor=2 daemon_unlock_replay=Err(crypto_tamper: "cryptographic tamper detected: keybox epoch rollback detected: got 1, minimum floor is 2") elapsed_ms=324.58 rss_mib=31.86 peak_rss_mib=104.62
test t07_gate3_redteam_daemon_keybox_forged_signature_epoch_poisoning_audit ... [PROOF-REDTEAM-T07] status=PASS ... persisted_sqlite_epoch_floor=1 ... poisoned_single_user_floor=0
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.40s

[PART A] entrocloudd binary: <workspace>\target\swarm\judge\ec-v1\release\entrocloudd.exe (14727168 bytes, sha256=844be797000032cf3dc9307f0d846455518123553b7d52dff70a9854668b0a75)
[PART A] Daemon #1 (PID=56416) ready in 102.84 ms | Idle WorkingSet64=12.609 MiB (Peak=12.609 MiB)
[PART A] TerminateProcess struck at 203.52 ms (reap=5.36 ms) | exit_status=ExitStatus(ExitStatus(1)) | Peak WorkingSet64=97.719 MiB | staged_at_kill=32 | remote_blobs_at_kill=6
[PART A][FORENSIC PRE-RESTART] metadata.db=4096 B | metadata.db-wal=655112 B | Plaintext Canary Scan -> state_dir: 37 files (134911234 B, 0 hits) | staging_dir: 32 files (134218624 B, 0 hits) | remote_dir: 9 files (22034711 B, 0 hits) | Verified 2 remote .zvm (0 corrupted)
[PART A][RECOVERY] 128 MiB re-import+sync=880.72 ms (145.33 MiB/s) | cold dehydrate+export=174.60 ms (733.12 MiB/s) | rev=2 | sha256=6155eeeaf039f2bafa6298e73da21573229474e217b065b83162704782fece2b (MATCH) | PID #2 WorkingSet64=55.160 MiB (Peak=116.266 MiB)
[PART B][UPLOAD CONVERGENCE] Staged 24 MiB in 24.78 ms | Converged in 4 sync_once() attempts (3 transient errors) over 161.01 ms (149.06 MiB/s)
[PART B][COLD READBACK] Hydrated & verified 2 × 24 MiB (48 MiB cold) in 185.69 ms (258.50 MiB/s) | total_chaos_stats=ChaosStats { total_ops: 33, injected_transient_failures: 11, injected_bit_flips: 0 } | sha256=0e57be2995cfeefab6771707b0cb3ff1e2a909428289f9e926272eff5f9ab9dd (100% MATCH)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 59.39s
```

---

## 5. Gate D — Portable Release Bundle (`bundle-portable.ps1`), Zero-WebView Binary Audit, Cold-Start & `0 B` Closed-Window RAM (`PASS`)

### 5.1 Portable Bundle Build, `dumpbin` PE Headers/Imports & `Assert-ZeroWebViewBinary` (`4/4 PASS`)
- **Exact Command Executed (Final Round 2 Release Bundle):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\packaging\windows\bundle-portable.ps1" -TargetDir "<workspace>\target\swarm\judge\ec-v1" -OutputDir "<workspace>\target\swarm\judge\ec-v1\dist"
  ```
- **Exit Code:** `0` | **Wall-Clock Latency:** `51,729.65 ms` (`100,823.26 ms` Round 1 cold) | **Throughput:** `0.564 MiB/s` (`30,615,552 B` stripped ThinLTO native code) | **Build Tree RSS (`WorkingSet64`):** Initial `2,805,760 B` (`2.68 MiB`) / Peak `2,209,587,200 B` (`2,107.23 MiB`; `5,189.81 MiB` R1 cold).

| Release Artifact (`lto = "thin"`, `strip = "symbols"`, `panic = "abort"`) | Exact Size (`Bytes`) | Size (`MiB`) | `SHA-256` Digest | PE Subsystem (`dumpbin /headers`) | `dumpbin /dependents` Imports | `Assert-ZeroWebViewBinary` |
| :--- | ---: | ---: | :--- | :---: | :--- | :---: |
| **`EntroCloud.exe`** | `6,204,416` | **`5.917 MiB`** | `d6803070153871121550bbb2f878a080372cfc6732b97def69111841fff4a963` | **`2 subsystem (Windows GUI)`** | `28` Win32/OpenGL/UCRT DLLs (`opengl32.dll`, `uiautomationcore.dll`, `dwmapi.dll`, `uxtheme.dll`, ...) | **`PASS` (`0` WebView2)** |
| **`entrocloudd.exe`** | `14,727,680` | **`14.045 MiB`** | `82bd8681c56dfe425ab04058121408e55acda73d3dafb5f4ec9a24ebacbfb8b0` | `3 subsystem (Windows CUI)` | `26` Win32/UCRT DLLs (`cldapi.dll`, `bcrypt.dll`, `crypt32.dll`, `ws2_32.dll`, ...) | **`PASS` (`0` WebView2)** |
| **`ec.exe`** | `8,794,624` | **`8.387 MiB`** | `1f4cae36cb8e590de4b3aa2e882c7b88a7bf4128f180130997a06ed6a25c04b2` | `3 subsystem (Windows CUI)` | `22` Win32/UCRT DLLs (`bcrypt.dll`, `crypt32.dll`, `ws2_32.dll`, `advapi32.dll`, ...) | **`PASS` (`0` WebView2)** |
| **`entrocloud-tray.exe`** | `888,832` | **`0.848 MiB`** | `d112ef0242e03e1606b6025d39a8489c21b8c3bf8fac5bc794247f7e00dc56b0` | **`2 subsystem (Windows GUI)`** | `19` Win32/UCRT DLLs (`shell32.dll`, `comctl32.dll`, `gdi32.dll`, `user32.dll`, ...) | **`PASS` (`0` WebView2)** |
| **Combined 4 Binaries** | **`30,615,552`** | **`29.197 MiB`** | *(86.23% smaller than `212.01 MiB` `CloudBridge.Desktop`)* | GUI + CUI verified | **`0` WebView2 / Browser / `.NET` Runtime DLLs** | **`4/4 PASS`** |
| **`entrocloud-windows-x86_64-portable.zip`** | **`14,862,959`** | **`14.174 MiB`** | `bc0b940859b92b7c355b01986faa0f4ff1cccf2a56e82a7f649a84cc726fee57` | — | `10` entries (`EntroCloud.exe`, `entrocloudd.exe`, `ec.exe`, `entrocloud-tray.exe`, `GOOGLE-DRIVE-SETUP.md`, `install.ps1`, `register-uri.ps1`, `unregister-uri.ps1`, `README-WINDOWS.txt`, `SHA256SUMS.txt`) | **`PASS`** *(Negative control on `Zerovault.exe` REJECTED)* |

### 5.2 `10×` `EntroCloud.exe --bench-cold`, `3×` `entrocloud-tray.exe --bench-tray` & Live `1.0s` Interactive `WM_CLOSE` Audit

| UI Zero-Bloat & Lifecycle Benchmark | Round 1 (`10×` / `3×`) | Round 2 Final (`10×` / `3×`) | Target / Invariant | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| **`EntroCloud.exe --bench-cold` (`main() -> Frame #1` swap)** | **`p50 = 150.064 ms`** (`min 144.669`, `p95 180.221`, `max 201.960`) | **`p50 = 159.710 ms`** (`min 146.853`, `p95 222.124` [Run 1 fresh-exe scan], Runs 7–10 `146.85–149.40 ms`) | Fast native OpenGL (`glow`) cold frame | **`PASS`** |
| **External `CreateProcess -> Frame #1` Latency** | **`p50 = 165.363 ms`** (`min 158.866`) | **`p50 = 175.530 ms`** (`min 162.044`) | Sub-200 ms cold OS spawn-to-GPU | **`PASS`** |
| **Frame #1 `egui` CPU Layout/Paint Time** | **`p50 = 0.294 ms`** (`max 0.347 ms`) | **`p50 = 0.303 ms`** (`max 0.352 ms`) | `< 16.6 ms` (`60+ FPS`) | **`PASS`** |
| **Active UI Resident RAM (`WorkingSet64` @ Frame #1)** | **`p50 = 76.305 MiB`** (`79,941,632–81,252,352 B`) | **`p50 = 76.313 MiB`** (`79,958,016–80,064,512 B`) | `< 128 MiB`, **`webview2_modules == 0`** (`10/10`) | **`PASS`** |
| **`entrocloud-tray.exe --bench-tray` (`3×`)** | **`p50 = 8.762 MiB`** (`9,187,328 B`, `4.711 MiB` Priv, `2.189 ms` init) | **`p50 = 8.762 MiB`** (`9,187,328 B`, `4.711 MiB` Priv, `1.956 ms` init) | `webview2_modules == 0`, `closed_window_ui_process_rss_bytes == 0` | **`PASS`** |
| **Live `1.0s` `Start-Process` + `Win32_Process` + `WM_CLOSE`** | `WS = 90.504 MiB`, `Children = 0`, `WM_CLOSE = 96.289 ms` (`Exit 0`) -> **`0 B`** | `WS = 90.379 MiB` (`91` OS/GL DLLs, `0` bad), **`Children = 0` (`conhost=0`, `webview2=0`)**, `WM_CLOSE = 83.165 ms` (`Exit 0`) -> **`POST_CLOSE_UI_RSS_BYTES = 0`** | `0` child processes, **`0 B` closed-window RAM** | **`PASS`** |

#### Verbatim Gate D Raw Telemetry Excerpts
```text
Verified 0 WebView2 DLLs & markers: EntroCloud.exe       ( 5.917 MiB, sha256=d680307015387112)
Verified 0 WebView2 DLLs & markers: entrocloudd.exe      (14.045 MiB, sha256=82bd8681c56dfe42)
Verified 0 WebView2 DLLs & markers: ec.exe               ( 8.387 MiB, sha256=1f4cae36cb8e590d)
Verified 0 WebView2 DLLs & markers: entrocloud-tray.exe  ( 0.848 MiB, sha256=d112ef0242e03e16)
NEGATIVE_CONTROL legacy Zerovault.exe: REJECTED AS EXPECTED (caught embedded marker '__TAURI_INTERNALS__')
CLI_SMOKE: ec.exe --version -> EXIT=0 (124.08 ms) 'ec 1.0.0' | entrocloudd.exe --version -> EXIT=0 (96.63 ms) 'entrocloudd 1.0.0'

SAMPLE_COLD_JSON_10: {"mode":"bench-cold","renderer":"glow","backend":"glow","gpu_adapter":"NVIDIA GeForce RTX 4080 SUPER/PCIe/SSE2 [3.3.0 NVIDIA 621.01]","ipc_endpoint":"\\\\.\\pipe\\entrocloudd","ipc_connected":false,"ipc_roundtrip_ms":0.101,"cold_open_latency_ms":149.401,"internal_cold_start_ms":149.401,"external_cold_start_ms":163.66,"frame1_update_cpu_ms":0.288,"working_set_64":79978496,"working_set_bytes":79978496,"working_set_mib":76.273,"peak_working_set_bytes":79978496,"peak_working_set_mib":76.273,"private_usage_bytes":95551488,"private_usage_mib":91.125,"webview2_modules":0,"webview2_detected":false,"loaded_webview_modules":[],"memory":{"working_set_bytes":79978496,"working_set_mib":76.273,"peak_working_set_bytes":79978496,"peak_working_set_mib":76.273,"private_usage_bytes":95551488,"private_usage_mib":91.125,"page_fault_count":22069}}
TRAY_RUN 3/3: exit=0 json={"mode":"bench-tray","binary_role":"entrocloud-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.956,"settle_duration_ms":400,"working_set_64":9187328,"working_set_mib":8.762,"webview2_modules":0,"memory":{"working_set_bytes":9187328,"working_set_mib":8.762,"peak_working_set_bytes":9187328,"peak_working_set_mib":8.762,"private_usage_bytes":4939776,"private_usage_mib":4.711,"page_fault_count":2318}}

LIVE_UI: PID=20904 | HWND=0x3F12B8 | WS_BYTES=94769152 (90.379 MiB) | PEAK_WS_BYTES=94769152 (90.379 MiB) | PRIVATE_BYTES=102883328 (98.117 MiB) | MODULES=91 | BAD_MODULES=0
LIVE_UI_CHILD_PROCESS_COUNT=0 (conhost=0, webview2=0, new_system_msedgewebview2=0)
WM_CLOSE_SHUTDOWN: Exited=True | ElapsedMs=83.165 | ExitCode=0
POST_CLOSE_UI_PROCESSES=0 | POST_CLOSE_UI_RSS_BYTES=0
```

---

## 6. Gate E — Final `READONLY_BASELINE.txt` Verification (`DIFF_COUNT = 0`) (`PASS`)

- **Exact Command Executed (Final Post-Bundle Check):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\target\swarm\judge\ec-v1\scripts\gate_e_readonly.ps1"
  ```
- **Exit Code:** **`0`** (`DIFF_COUNT = 0`) | **Wall-Clock Latency:** `656.81 ms` | **Throughput:** `433.80 MiB/s` (`298,766,349 B` across `184` files) | **Judge Process RSS (`WorkingSet64`):** Idle `67,350,528 B` (`64.23 MiB`) / Active `120,315,904 B` (`114.74 MiB`) / Peak `120,463,360 B` (`114.88 MiB`).

```text
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
DIFF_COUNT=0 | EXIT=0 | ElapsedMs=656.81 | ThroughputMiBs=433.80 | IdleWorkingSet64=67350528 (64.23 MiB) | WorkingSet64=120315904 (114.74 MiB) | PeakWorkingSet64=120463360 (114.88 MiB)
```

---

**FINAL `Agent-Judge` RELEASE VERDICT (`EntroCloud v1.0`):** **`APPROVED — ALL 5 EMPIRICAL GATES (A, B, C, D & E) VERIFIED ON SILICON WITH 0 ACTIVE VETOES AND 0 READ-ONLY SOURCE MUTATIONS.`**
