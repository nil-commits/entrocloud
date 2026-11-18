# Gate 3 & Wave 4 Gate 6 — Final Workspace Static, Cross-Target, Unit/Integration Suite & Portable Release Bundle Verdict (`Agent-Judge`)

**Auditor:** `Agent-Judge` (Adversarial Red-Team & Empirical Proof Verifier)  
**Audit Timestamp (UTC):** `2026-11-17T21:59:49Z`  
**Workspace Root:** [`<workspace>`](.)  
**Isolated Cargo Target Dir:** `<workspace>\target\swarm\judge\w4-gate6`  
**Host Toolchain:** `rustc 1.94.1 (e408947bf 2026-03-25)` (`edition = "2024"`, `x86_64-pc-windows-msvc` + cross-target `x86_64-unknown-linux-musl`)  
**Overall Verdict:** **`PASS — 6/6 SUB-GATES PASS (0 ACTIVE VETOES; W4-VETO-CLIPPY-E2E Remediated & Empirically Re-Verified)`**

---

## Executive Summary Matrix

| # | Mandatory Verification Gate | Status | Exit Code | Wall-Clock Latency | Throughput | Idle / Peak Physical RSS (`WorkingSet64`) | Empirical Summary |
| :-: | :--- | :---: | :---: | ---: | ---: | ---: | :--- |
| **1** | **Full-Workspace Static Audit** (`crates/*/src/**/*.rs`, 8 crates) | **`PASS`** | `0` | `273.24 ms` | `4.46 MiB/s` (`52` files, `35,283` LOC) | `91.22 MiB` / `91.75 MiB` | **`0`** prod `.unwrap()` / `.expect()` / `panic!()` / `todo!()` / `unimplemented!()`; **`20`** audited `unsafe` blocks (`0` in `types/crypto/storage/vfs/cli`, `1` in `core`, `8` in `daemon`, `11` in `ui`) |
| **2** | **Wave 4 Gate 6 — Workspace Clippy (`--workspace --all-targets -- -D warnings`)** | **`PASS`** | **`0`** | `2,814.79 ms` *(Round 2)* / `38,985.20 ms` *(Round 1 cold)* | — | `56.86 MiB` / `332.74 MiB` *(Round 2; `3,731.70 MiB` cold)* | **`0` warnings across all 9 workspace crates, all unit/integration/e2e tests & all 5 Criterion benches** (`Round 1 EXIT=101 -> W4-VETO-CLIPPY-E2E remediated -> Round 2 EXIT=0`) |
| **3** | **Cross-Target Arch Linux `x86_64-unknown-linux-musl` Clippy** | **`PASS`** | `0` | `13,603.49 ms` | — | `107.21 MiB` / `1,517.45 MiB` | **`0` warnings** across `zerovault-types` & `zerovault-vfs` (`fuser v0.18.0`, `nix v0.31.4`, `libc v0.2.191`) |
| **4** | **Full Workspace 8-Crate Test Suite (`Gate 3` + `Gate 6`)** | **`PASS`** | `0` | `110,612.06 ms` *(`56.78 s` exec)* | — | `88.54 MiB` / `8,228.51 MiB` *(build+parallel Argon2id)* | **`117 passed / 0 failed / 1 ignored`** across `22` binary test suites + `8` doc-test suites (`0` failed) |
| **5** | **Release Build & `bundle-portable.ps1` Verification** | **`PASS`** | `0` | `110,515.88 ms` | `0.258 MiB/s` (`28.481 MiB` stripped out) | `84.69 MiB` / `4,126.32 MiB` | All 4 release binaries built (`LTO=thin`, `strip=symbols`, `panic=abort`), **`Assert-ZeroWebViewBinary` PASSED 4/4**, portable `.zip` = **`13.879 MiB`** |
| **6** | **Read-Only Legacy & Source Preservation Final Check** | **`PASS`** | `0` | `533.40 ms` | `534.17 MiB/s` (`298,766,349 B` / `184` files) | `114.23 MiB` / `114.37 MiB` | **100% bit-exact match** (`DIFF_COUNT=0`) with `audit/READONLY_BASELINE.txt` across `cloudbridge`, `cloudbridge linux`, and `zerovault` (**`0` mutations**) |

---

## 1. Sub-Gate 1: Full-Workspace Static Audit (`crates/*/src/**/*.rs`) — **`PASS`**

### 1.1 Methodology & Execution Telemetry
Two independent static analyzers were executed across all `52` Rust source files (`35,283` lines) under `crates/*/src/**/*.rs`:
1. **AST/Lexical Scanner (`RustStaticScanner` inline C# lexer):** Strips `//` line comments, nested `/* ... */` block comments, raw byte/string literals (`r#"..."#`, `br#"..."#`), regular string literals, and character literals while tracking `#[cfg(test)]` item/module brace intervals.
2. **Unfiltered Raw Grep Cross-Check (`Select-String`):** Zero AST filtering across all `52` files to independently verify that every raw match resides strictly inside `#[cfg(test)]` unit test modules.

- **Exact Command Executed (Raw Cross-Check):**
  ```powershell
  $files = Get-ChildItem -Path "<workspace>\crates" -Recurse -Filter "*.rs" |
      Where-Object { $_.FullName -match "\\src\\" } | Sort-Object FullName
  Select-String -Path $files.FullName -Pattern '(\.unwrap\s*\(|\.expect\s*\(|\bpanic!\s*[\(\[\{]|\btodo!\s*[\(\[\{]|\bunimplemented!\s*[\(\[\{])'
  ```
- **Exit Code:** `0` | **Wall-Clock Latency:** `273.24 ms` (AST lexer) | **Throughput:** `4.46 MiB/s` | **RSS (`WorkingSet64` / Peak):** `95,653,888 B` (`91.22 MiB`) / `96,202,752 B` (`91.75 MiB`)

### 1.2 Per-Crate Production Panic-Safety & `unsafe` Audit Table

| Production Crate | `.rs` Files in `src/` | Total LOC | Prod `.unwrap()` / `.expect()` / `panic!()` / `todo!()` / `unimplemented!()` | `#[cfg(test)]` Matches | Prod `unsafe` Blocks | `#[cfg(test)]` `unsafe` Blocks | Verdict |
| :--- | ---: | ---: | :---: | ---: | :---: | :---: | :---: |
| [`zerovault-types`](crates/zerovault-types/src/lib.rs) | `7` | `4,870` | **`0`** | `23` *(lines 67–252 of `src/lib.rs` inside `#[cfg(test)] mod tests`)* | **`0`** | `0` | **`PASS`** |
| [`zerovault-crypto`](crates/zerovault-crypto/src/lib.rs) | `6` | `2,068` | **`0`** | `0` | **`0`** | `0` | **`PASS`** |
| [`zerovault-storage`](crates/zerovault-storage/src/lib.rs) | `5` | `4,143` | **`0`** | `0` | **`0`** | `0` | **`PASS`** |
| [`zerovault-vfs`](crates/zerovault-vfs/src/lib.rs) | `9` | `5,441` | **`0`** | `8` *(lines 135–153 of `src/lib.rs` inside `#[cfg(test)] mod tests`)* | **`0`** | `0` | **`PASS`** |
| [`zerovault-core`](crates/zerovault-core/src/lib.rs) | `6` | `5,485` | **`0`** | `0` | **`1`** | `0` | **`PASS`** |
| [`zerovault-daemon`](crates/zerovault-daemon/src/lib.rs) | `5` | `6,065` | **`0`** | `0` | **`8`** | `0` | **`PASS`** |
| [`zerovault-cli`](crates/zerovault-cli/src/lib.rs) | `3` | `1,197` | **`0`** | `0` | **`0`** | `0` | **`PASS`** |
| [`zerovault-ui`](crates/zerovault-ui/src/lib.rs) | `11` | `6,014` | **`0`** | `0` | **`11`** | `0` | **`PASS`** |
| **TOTAL (8 Production Crates)** | **`52`** | **`35,283`** | **`0`** | `31` *(100% unit tests)* | **`20`** | **`0`** | **`PASS`** |

### 1.3 Complete Workspace `unsafe` Block Catalog (`20` Blocks Across Production Crates)

Every single `unsafe` block across `crates/*/src/**/*.rs` carries an explicit `// SAFETY:` invariant comment and wraps an audited FFI boundary:

| # | Crate | Source File & Line | FFI Symbol / Operation | Audited Safety Invariant |
| :-: | :--- | :--- | :--- | :--- |
| `1` | `zerovault-core` | [`pool.rs:36`](crates/zerovault-core/src/pool.rs#L35-L36) | `libmimalloc_sys::mi_collect(true)` | Thread-safe `mimalloc` arena reclamation returning idle thread-local pages to OS kernel (`RSS <= 35 MiB` post-4 GiB burst). |
| `2` | `zerovault-daemon` | [`dacl.rs:150`](crates/zerovault-daemon/src/dacl.rs#L148-L162) | `ConvertStringSecurityDescriptorToSecurityDescriptorW` | Valid NUL-terminated UTF-16 `U16CString` SDDL (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`); output wrapped in RAII `OwnedSecurityDescriptor`. |
| `3` | `zerovault-daemon` | [`dacl.rs:181`](crates/zerovault-daemon/src/dacl.rs#L179-L184) | `LocalFree` (`Drop for OwnedSecurityDescriptor`) | Releases non-invalid Win32 `LocalAlloc` security descriptor exactly once on drop. |
| `4` | `zerovault-daemon` | [`dacl.rs:207`](crates/zerovault-daemon/src/dacl.rs#L205-L212) | `ServerOptions::create_with_security_attributes_raw` | `SECURITY_ATTRIBUTES` stack struct borrows live `OwnedSecurityDescriptor` (`sd` drops after pipe creation); enforces `first_pipe_instance` + `reject_remote_clients(true)`. |
| `5` | `zerovault-daemon` | [`dacl.rs:230`](crates/zerovault-daemon/src/dacl.rs#L229-L242) | `GetSecurityDescriptorDacl` | Extracts internal `PACL` pointer bounded by `sd` lifetime; null/absent DACL checked before use. |
| `6` | `zerovault-daemon` | [`dacl.rs:255`](crates/zerovault-daemon/src/dacl.rs#L254-L265) | `SetNamedSecurityInfoW` | Applies `DACL_SECURITY_INFORMATION \| PROTECTED_DACL_SECURITY_INFORMATION` to NUL-terminated UTF-16 filesystem path while `sd` outlives call. |
| `7` | `zerovault-daemon` | [`dacl.rs:284`](crates/zerovault-daemon/src/dacl.rs#L283-L295) | `GetNamedSecurityInfoW` | Reads file DACL into `raw_sd`, immediately wrapped in RAII `OwnedSecurityDescriptor` on `ERROR_SUCCESS`. |
| `8` | `zerovault-daemon` | [`dacl.rs:305`](crates/zerovault-daemon/src/dacl.rs#L304-L313) | `ConvertSecurityDescriptorToStringSecurityDescriptorW` | Formats valid `sd_guard` DACL into Win32 `LocalAlloc` UTF-16 string pointer `str_ptr`. |
| `9` | `zerovault-daemon` | [`dacl.rs:327`](crates/zerovault-daemon/src/dacl.rs#L326-L336) | `slice::from_raw_parts` + `LocalFree` | Computes UTF-16 NUL length on non-null `str_ptr`, copies via `String::from_utf16_lossy`, and immediately frees via `LocalFree`. |
| `10` | `zerovault-ui` | [`app.rs:2522`](crates/zerovault-ui/src/app.rs#L2521-L2527) | `glow::HasContext::get_parameter_string` | Queries `RENDERER` and `VERSION` on active OpenGL context supplied by `eframe::CreationContext`. |
| `11` | `zerovault-ui` | [`bin/zerovault_tray.rs:298`](crates/zerovault-ui/src/bin/zerovault_tray.rs#L297-L304) | `PeekMessageW` / `TranslateMessage` / `DispatchMessageW` | Non-blocking Win32 thread message loop required for `Shell_NotifyIconW` tray events. |
| `12` | `zerovault-ui` | [`ipc_client.rs:527`](crates/zerovault-ui/src/ipc_client.rs#L525-L537) | `CreateFileW` | Opens `\\.\pipe\...` with `SECURITY_SQOS_PRESENT` (`SECURITY_ANONYMOUS == 0`) preventing Named Pipe impersonation. |
| `13` | `zerovault-ui` | [`ipc_client.rs:540`](crates/zerovault-ui/src/ipc_client.rs#L539-L540) | `std::fs::File::from_raw_handle` | Transfers exclusive handle ownership immediately after validating `handle != INVALID_HANDLE_VALUE && !handle.is_null()`. |
| `14` | `zerovault-ui` | [`ipc_client.rs:545`](crates/zerovault-ui/src/ipc_client.rs#L544-L545) | `GetLastError` | Reads thread-local Win32 error code immediately after failed `CreateFileW`. |
| `15` | `zerovault-ui` | [`ipc_client.rs:548`](crates/zerovault-ui/src/ipc_client.rs#L547-L550) | `WaitNamedPipeW` | Bounded 25 ms wait on NUL-terminated UTF-16 pipe path when `ERROR_PIPE_BUSY`. |
| `16` | `zerovault-ui` | [`metrics.rs:111`](crates/zerovault-ui/src/metrics.rs#L110-L115) | `QueryPerformanceCounter` | Writes monotonic ticks into stack `i64`. |
| `17` | `zerovault-ui` | [`metrics.rs:134`](crates/zerovault-ui/src/metrics.rs#L133-L138) | `QueryPerformanceFrequency` | Writes counter frequency into stack `i64` clamped via `.max(1)`. |
| `18` | `zerovault-ui` | [`metrics.rs:166`](crates/zerovault-ui/src/metrics.rs#L165-L189) | `K32GetProcessMemoryInfo` | Queries `PROCESS_MEMORY_COUNTERS_EX` (`cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>()`) on `GetCurrentProcess()`. |
| `19` | `zerovault-ui` | [`metrics.rs:296`](crates/zerovault-ui/src/metrics.rs#L295-L325) | `K32EnumProcessModules` / `K32GetModuleBaseNameW` | Enumerates loaded `HMODULE`s into bounded 1,024-slot buffer and `[0u16; 260]` stack name buffer to prove `0` loaded WebView2 DLLs at runtime. |
| `20` | `zerovault-ui` | [`session.rs:449`](crates/zerovault-ui/src/session.rs#L448-L458) | `ShellExecuteW` | Opens validated existing local directory/file path via `U16CString` (`open` verb). |

*(Note: Outside `crates/*/src/**`, integration/e2e test suites contain `7` `unsafe` blocks for Win32 `TerminateProcess`/`K32GetProcessMemoryInfo` telemetry and spare-capacity zeroization checks: `crates/zerovault-vfs/tests/linux_vfs_tests.rs:214,1206`, `crates/zerovault-vfs/tests/windows_vfs_tests.rs:201`, `tests/e2e/tests/w4_gate1_4gib_roundtrip.rs:57`, `tests/e2e/tests/w4_gate2_3_zk_and_tamper.rs:114`, and `tests/e2e/tests/w4_gate4_crash_and_chaos.rs:134,168`.)*

---

## 2. Sub-Gate 2: Wave 4 Gate 6 — Workspace-Wide Clippy (`-- -D warnings`) — **`PASS (Round 1 EXIT=101 -> W4-VETO-CLIPPY-E2E Remediated -> Round 2 EXIT=0)`**

### 2.1 Post-Remediation Final Verification (`Round 2 — PASS`)
- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-gate6"
  cargo clippy --manifest-path "<workspace>\Cargo.toml" --workspace --all-targets --locked -- -D warnings
  ```
- **Exit Code:** **`0` (`PASS — 0 warnings across all 9 workspace crates, all 25 test binaries, and all 5 Criterion benchmark suites`)**
- **Wall-Clock Latency:** `2,814.79 ms` (`2.62 s` cargo incremental re-check of `zerovault-e2e` on top of Round 1 `38,985.20 ms` full workspace check)
- **Compiler Tree RSS (`WorkingSet64`):** Initial `59,621,376 B` (`56.86 MiB`) | Peak `348,901,376 B` (`332.74 MiB`; cold full-workspace Peak `3,912,974,336 B` / `3,731.70 MiB`)
- **Verbatim Round 2 Raw Output:**
  ```text
  ROUND2_GATE2_CLIPPY_EXIT=0 | ELAPSED_MS=2,814.79 | INITIAL_WS_BYTES=59621376 (56.86 MiB) | PEAK_TREE_WS_BYTES=348901376 (332.74 MiB)
  === STDOUT ===

  === STDERR ===
      Checking zerovault-e2e v0.2.0 (<workspace>\tests\e2e)
      Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.62s
  ```

### 2.2 Veto & Remediation Audit Trail (`W4-VETO-CLIPPY-E2E`: `Round 1 EXIT=101 -> Round 2 EXIT=0`)
- **Round 1 Execution (`EXIT=101`, `38,985.20 ms` cold / `1,303.69 ms` `--keep-going`):**
  - All 8 production crates (`types`, `crypto`, `storage`, `vfs`, `core`, `daemon`, `cli`, `ui`), all 22 unit/integration test targets, and all 5 Criterion benchmark targets (`core_bench`, `crypto_bench`, `storage_bench`, `linux_vfs_bench`, `windows_vfs_bench`) passed `--exclude zerovault-e2e --all-targets --locked -- -D warnings` with **`EXIT=0` (`0` warnings) in `728.39 ms`**.
  - However, `Agent-Judge` caught `5` `rustc 1.94.1` Clippy `-D warnings` style lints in [`tests/e2e/tests/w4_gate1_4gib_roundtrip.rs`](tests/e2e/tests/w4_gate1_4gib_roundtrip.rs#L444-L837) (`3× clippy::manual_is_multiple_of` at lines `444`, `503`, `837` and `2× clippy::manual_range_contains` at lines `598`, `763`) and exercised `W4-VETO-CLIPPY-E2E` while strictly preserving write-scope isolation.
- **Remediation & Round 2 Verification:** `Agent-Judge-W4-4GiB` replaced lines `444`, `503`, `837` with `.is_multiple_of(...)` and lines `598`, `763` with `(600..=640).contains(&blobs_on_a)` and `(1..=2).contains(&delta_chunks)`. Independent `Agent-Judge` Round 2 re-execution confirmed **`EXIT=0` (`0` warnings)** across the entire 9-crate workspace.

---

## 3. Sub-Gate 3: Cross-Target Arch Linux `x86_64-unknown-linux-musl` Gate — **`PASS`**

- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-gate6"
  cargo clippy --manifest-path "<workspace>\Cargo.toml" -p zerovault-types -p zerovault-vfs --all-targets --locked --target x86_64-unknown-linux-musl -- -D warnings
  ```
- **Exit Code:** **`0`** | **Wall-Clock Latency:** `13,603.49 ms` (`13.38 s` cargo) | **Warnings:** **`0`**
- **Compiler Tree RSS (`WorkingSet64`):** Initial `112,414,720 B` (`107.21 MiB`) | Peak `1,591,164,928 B` (`1,517.45 MiB`)
- **Verbatim Raw Stderr Excerpt:**
  ```text
     Compiling nix v0.31.4
     Compiling fuser v0.18.0
     Compiling blake3 v1.8.7
      Checking criterion v0.5.1
      Checking zerovault-types v0.2.0 (<workspace>\crates\zerovault-types)
      Checking zerovault-vfs v0.2.0 (<workspace>\crates\zerovault-vfs)
      Finished `dev` profile [unoptimized + debuginfo] target(s) in 13.38s
  ```

---

## 4. Sub-Gate 4: Full Workspace Crate Test Execution (`Gate 3` + `Gate 6`) — **`PASS`**

- **Exact Command Executed:**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-gate6"
  cargo test --manifest-path "<workspace>\Cargo.toml" --workspace --exclude zerovault-e2e --locked
  ```
- **Exit Code:** **`0`** | **Wall-Clock Latency:** `110,612.06 ms` (`56.78 s` pure test execution across `30` suites)
- **Process Tree RSS (`WorkingSet64`):** Initial `92,839,936 B` (`88.54 MiB`) | Peak `8,628,219,904 B` (`8,228.51 MiB` during parallel debug link + Argon2id test suites)

### 4.1 Per-Crate & Per-Suite Test Breakdown (`117 Passed / 0 Failed / 1 Ignored`)

| Crate | Suite / Target | Passed | Failed | Ignored | Exec Time | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| **`zerovault-cli`** | `src/lib.rs` (unit) | `1` | `0` | `0` | `0.00 s` | Clap schema + zeroizing secret reader |
| **`zerovault-cli`** | `src/main.rs` (`zv` bin unit) | `1` | `0` | `0` | `0.00 s` | `zv` CLI binary parser verification |
| **`zerovault-cli`** | `tests/cli_integration.rs` | `4` | `0` | `0` | `0.66 s` | Subprocess `ZV_PASSPHRASE`, `share`, `routing`, `mount` |
| **`zerovault-core`** | `src/lib.rs` (unit) | `2` | `0` | `0` | `0.00 s` | `ChunkBufferPool` semaphore backpressure & full-cap zeroize |
| **`zerovault-core`** | `tests/core_suite.rs` | `9` | `0` | `0` | `1.90 s` | 9.5 MiB streaming seek, lock+purge, WAL, conflict fork, GC |
| **`zerovault-core`** | `tests/proptest_core.rs` | `5` | `0` | `0` | `5.21 s` | Property-based cross-chunk write/flush/dehydrate/seek oracle |
| **`zerovault-crypto`** | `src/lib.rs` (unit) | `0` | `0` | `0` | `0.00 s` | — |
| **`zerovault-crypto`** | `tests/crypto_suite.rs` | `19` | `0` | `0` | `6.17 s` | `ring` AES-256-GCM, `aws-lc-rs` ML-KEM-768+X25519+Ed25519, KDF floor/ceiling |
| **`zerovault-daemon`** | `src/lib.rs` (unit) | `2` | `0` | `0` | `0.00 s` | Backend kind & IPC endpoint validation |
| **`zerovault-daemon`** | `src/main.rs` (`zerovaultd` unit) | `1` | `0` | `0` | `0.00 s` | Daemon CLI flag validation |
| **`zerovault-daemon`** | `tests/daemon_integration.rs` | `7` | `0` | `0` | `27.22 s` | Owner-only Named Pipe DACL (`D:P(A;;GA;;;SY)(A;;GA;;;OW)`), 16 MiB frame cap, lifecycle |
| **`zerovault-storage`** | `src/lib.rs` (unit) | `5` | `0` | `0` | `0.00 s` | Router & OAuth PKCE unit checks |
| **`zerovault-storage`** | `tests/storage_integration.rs` | `11` | `0` | `0` | `5.02 s` | `QuotaPooled`, `Mirrored` (`RAID-1`), `Targeted`, CAS, Chaos fault wrapper |
| **`zerovault-storage`** | `tests/storage_proptest.rs` | `6` | `0` | `0` | `0.06 s` | Property-based routing & failover invariants |
| **`zerovault-types`** | `src/lib.rs` (unit) | `7` | `0` | `0` | `0.01 s` | Wire headers, `SignedKeybox`, `CapabilityUri` redacted `Debug`, range spans |
| **`zerovault-ui`** | `src/lib.rs` / `main.rs` / `tray` (unit) | `0` | `0` | `0` | `0.00 s` | — |
| **`zerovault-ui`** | `tests/ui_integration.rs` | `8` | `0` | `0` | `2.99 s` | Cold-launch `eframe`/`glow` GPU render, tray RSS, `zv://` `--open-uri`, `0` WebView2 |
| **`zerovault-vfs`** | `src/lib.rs` (unit) | `1` | `0` | `0` | `0.00 s` | `VirtualDrive` pin/unpin/dehydrate contract |
| **`zerovault-vfs`** | `tests/linux_vfs_tests.rs` | `8` | `0` | `0` | `7.46 s` | Portable Linux FUSE3 state machine, xattrs, dirty coalescer zeroize, `close()` error latch |
| **`zerovault-vfs`** | `tests/windows_vfs_tests.rs` | `20` | `0` | `1` | `0.08 s` | CfApi 4 KiB alignment, `NEW-H02` unpin->dehydrate, streaming hydration *(1 ignored: `live_cfapi_sync_root_mount_and_unmount_integration` — requires live Explorer SyncRoot context)* |
| **All 8 Crates** | `Doc-tests` (`8` crates) | `0` | `0` | `0` | `0.00 s` | `0` doc-test errors |
| **TOTAL** | **`30` Test Targets** | **`117`** | **`0`** | **`1`** | **`56.78 s`** | **`100% PASS` (`0` failures)** |

---

## 5. Sub-Gate 5: Production Release Build & `bundle-portable.ps1` Verification — **`PASS`**

- **Exact Command Executed:**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\packaging\windows\bundle-portable.ps1" -TargetDir "<workspace>\target\swarm\judge\w4-gate6" -OutputDir "<workspace>\target\swarm\judge\w4-gate6\dist"
  ```
- **Exit Code:** **`0`** | **Wall-Clock Latency:** `110,515.88 ms` (`110.516 s`) | **Throughput:** `0.258 MiB/s` (`29,864,960 B` stripped native code emitted)
- **Build Tree RSS (`WorkingSet64`):** Initial `88,805,376 B` (`84.69 MiB`) | Peak `4,326,764,544 B` (`4,126.32 MiB` ThinLTO `codegen-units = 1` link)

### 5.1 Verbatim `bundle-portable.ps1` Stdout
```text
Using PE import verifier: C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe
Verified 0 WebView2 DLLs & markers: zerovaultd.exe       (13,997 MiB, sha256=a9ad47ea3476d07f)
Verified 0 WebView2 DLLs & markers: zv.exe               ( 8,192 MiB, sha256=59a76384228768fa)
Verified 0 WebView2 DLLs & markers: zerovault-ui.exe     ( 5,482 MiB, sha256=73104c00b23cbcef)
Verified 0 WebView2 DLLs & markers: zerovault-tray.exe   (  0,81 MiB, sha256=2c8549ee8af058bc)
Staged portable bundle: <workspace>\target\swarm\judge\w4-gate6\dist\zerovault-portable
Created archive:        <workspace>\target\swarm\judge\w4-gate6\dist\zerovault-windows-x86_64-portable.zip
```

### 5.2 Stripped Release Binary & Portable Archive Size, Hash & PE Import Audit Table

| Release Artifact | Exact Size (`Bytes`) | Size (`MiB`) | SHA-256 Digest | PE DLL Imports (`dumpbin /dependents`) | `Assert-ZeroWebViewBinary` | Cold Smoke Exec |
| :--- | ---: | ---: | :--- | :--- | :---: | :---: |
| **`zerovaultd.exe`** | `14,676,992` | **`13.997 MiB`** | `a9ad47ea3476d07fe455da0913a1db92ee81baa7b6850bcadbee283f4ef1de1f` | `26` OS/UCRT DLLs (`cldapi.dll`, `bcrypt.dll`, `crypt32.dll`, `ws2_32.dll`, `advapi32.dll`, `kernel32.dll`, ...) | **`PASS` (`0` WebView2)** | `--help` -> `EXIT=0` (`113.40 ms`) |
| **`zv.exe`** | `8,590,336` | **`8.192 MiB`** | `59a76384228768fa55df6e7d76a0af87a5eed1a16030a077771c949c40e2267d` | `22` OS/UCRT DLLs (`bcrypt.dll`, `crypt32.dll`, `ws2_32.dll`, `advapi32.dll`, `shell32.dll`, `kernel32.dll`, ...) | **`PASS` (`0` WebView2)** | `--version` -> `zv 0.2.0`, `EXIT=0` (`106.70 ms`) |
| **`zerovault-ui.exe`** | `5,748,224` | **`5.482 MiB`** | `73104c00b23cbcef50b3a3e8563fe233c3ed739ca421c6dcc0f84d8295b9d0dc` | `28` OS/OpenGL/UCRT DLLs (`opengl32.dll`, `uiautomationcore.dll`, `dwmapi.dll`, `uxtheme.dll`, `gdi32.dll`, `user32.dll`, ...) | **`PASS` (`0` WebView2)** | `--help` -> `EXIT=0` (`73.10 ms`) |
| **`zerovault-tray.exe`** | `849,408` | **`0.810 MiB`** | `2c8549ee8af058bc57d78b7e788a2512f69f3c810c0e6334ef642f1e0e3b05dd` | `19` OS/UCRT DLLs (`shell32.dll`, `comctl32.dll`, `gdi32.dll`, `user32.dll`, `ws2_32.dll`, `advapi32.dll`, ...) | **`PASS` (`0` WebView2)** | `--help` -> `EXIT=0` (`40.32 ms`) |
| **Combined 4 Binaries** | **`29,864,960`** | **`28.481 MiB`** | — | **100% Pure Rust + Win32/OpenGL OS DLLs (`0` Browser / `.NET` Runtime)** | **`4/4 PASS`** | **`4/4 EXIT=0`** |
| **`zerovault-windows-x86_64-portable.zip`** | **`14,553,413`** | **`13.879 MiB`** | `93f2f6d76c186a490e6655c8390e183d51c5de69f00dcf5bc8031b194fbf3c28` | `9` entries (`4` `.exe` + `install.ps1`, `register-uri.ps1`, `unregister-uri.ps1`, `SHA256SUMS.txt`, `README-WINDOWS.txt`) | **`PASS`** | Verified |

---

## 6. Sub-Gate 6: Read-Only Legacy & Source Preservation Final Check — **`PASS`**

- **Baseline Reference:** [`audit/READONLY_BASELINE.txt`](audit/READONLY_BASELINE.txt)
- **Exact Command Executed (Final Post-Remediation Re-Verification):**
  ```powershell
  Get-ExactBaseline "cloudbridge"       "<donor-root>\cloudbridge"
  Get-ExactBaseline "cloudbridge linux" "<donor-root>\cloudbridge linux"
  Get-ExactBaseline "zerovault"         "<donor-root>\zerovault"
  Compare-Object -ReferenceObject $expectedLines -DifferenceObject $actualLines -SyncWindow 0
  ```
- **Exit Code:** **`0`** (`DIFF_COUNT=0`) | **Wall-Clock Latency:** `533.40 ms` | **Throughput:** `534.17 MiB/s` (`298,766,349` bytes across `184` files) | **Judge Process RSS (`WorkingSet64` / Peak):** `119,783,424 B` (`114.23 MiB`) / `119,922,688 B` (`114.37 MiB`)

### Verbatim Final Baseline Stdout
```text
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
DIFF_COUNT=0 | EXIT=0 | ElapsedMs=533.40 | ThroughputMiBs=534.17 | WorkingSet64=119783424 (114.23 MiB) | PeakWorkingSet64=119922688 (114.37 MiB)
```

---

## Final `Agent-Judge` Determination — **`6/6 SUB-GATES PASS (0 ACTIVE VETOES)`**

All 6 mandatory Gate 3 & Wave 4 Gate 6 empirical verification checks — full-workspace panic/unwrap/unsafe audit (`0` prod panics, `20` documented FFI `unsafe` blocks), zero-warning full-workspace Clippy (`--workspace --all-targets --locked -- -D warnings`, `EXIT=0`), cross-target Arch Linux `x86_64-unknown-linux-musl` Clippy (`EXIT=0`), full 8-crate test suite (`117 passed / 0 failed / 1 ignored`), stripped ThinLTO Windows portable bundle build + `Assert-ZeroWebViewBinary` (`4/4 PASS`, `13.879 MiB` `.zip`), and `READONLY_BASELINE.txt` source preservation (`DIFF_COUNT=0`) — **PASS 100% with ZERO ACTIVE VETOES.**
