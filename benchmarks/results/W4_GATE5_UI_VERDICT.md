# Wave 4 Gate 5 Adversarial Verification Verdict (`UI Zero-Bloat, Process Tree & zv:// URI Verification`)

- **Gate:** Wave 4 Gate 5 — Production `zerovault-ui` & `zerovault-tray` Zero-Bloat, OS Process Tree, Cold Latency & `zv://` Packaging Verification
- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier)
- **Audit Timestamp (UTC):** `2026-11-17T21:06:00Z`
- **Host Hardware:** AMD Ryzen 9 7950X3D (`16C/32T`, `31.6 GiB` DDR5) + NVIDIA GeForce RTX 4080 SUPER (`OpenGL 3.3.0 NVIDIA 621.01`) + Windows 11 (`10.0.26300`, `x86_64-pc-windows-msvc`)
- **Isolated Target Dir:** `<workspace>\target\swarm\judge\w4-ui`
- **Machine-Readable Proof Ledger:** [w4_gate5_ui.json](benchmarks/results/w4_gate5_ui.json)
- **Read-Only Source Baseline Integrity:** **PASS (`0` mutations across `184` files / `298,766,349` bytes)** — verified against [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt).

---

## Executive Gate 5 Decision: **PASS (`0` Active Vetoes — `W4-VETO-01` & `W4-VETO-02` Remediated & Empirically Re-Verified)**

| Gate 5 Verification Pillar | Empirical Measurement / Proof | Verdict |
| :--- | :--- | :---: |
| **1. Static Panic / Unwrap Audit (`crates/zerovault-ui/src/**`)** | **`0` `.unwrap()`, `0` `.expect()`, `0` `panic!()`, `0` `todo!()`, `0` `unimplemented!()`** across all `11` `.rs` files; `cargo clippy --all-targets --locked -- -D warnings` `EXIT=0` (`0` warnings) | **PASS** |
| **2. Dependency Tree Zero-Browser Audit (`Cargo.toml` / `Cargo.lock`)** | `cargo tree -p zerovault-ui --locked` on Windows (`465` lines) & `x86_64-unknown-linux-gnu` (`925` lines): **`0` `tauri`, `wry`, `webview2`, `webkit2gtk`, or `cef` crates** | **PASS** |
| **3. Stripped Release Sizes & PE Subsystem (`dumpbin /headers`)** | `zerovault-ui.exe` = **`5,748,224 B` (`5.482 MiB`)**; `zerovault-tray.exe` = **`849,408 B` (`0.810 MiB`)**; both confirmed **`2 subsystem (Windows GUI)`** | **PASS** |
| **4. PE Imports & `bundle-portable.ps1` Positive/Negative Control** | `dumpbin /dependents`: **`0` browser DLLs** (`28` & `19` native Win32/OpenGL/UCRT DLLs); `Assert-ZeroWebViewBinary` **PASSES** both `.exe`s (`0` raw markers) and **REJECTS** legacy `zerovault\Zerovault.exe` (`'WebView2Loader.dll'`) | **PASS** |
| **5. 20× Cold Window Open Latency & RSS (`--bench-cold`)** | Internal `main() -> Frame #1`: **`p50 = 149.330 ms`** (`min = 140.075 ms`, `p95 = 179.065 ms`, `max = 194.390 ms`); External `CreateProcess -> Frame #1`: **`p50 = 163.382 ms`**; `WorkingSet64`: **`p50 = 69.637 MiB`** (`< 128 MiB`) | **PASS** |
| **6. Live `Win32_Process` Tree (`1.0s` Hold) & Post-Close `0 B` RAM** | Live `zerovault-ui.exe` (`86.762 MiB` RSS, `91` OS/GL DLLs): **`0` child processes (`0` `conhost.exe`, `0` WebView2/WebKit)**; `WM_CLOSE` exits `0` in **`81.737 ms`**, leaving **`0` processes (`0 bytes` UI RAM)** | **PASS** |
| **7. System Tray Companion (`zerovault-tray.exe --bench-tray`)** | **`8.758 MiB` `WorkingSet64` p50** (`9,183,232 B`), **`4.727 MiB` Private Usage**, `1.751 ms` init p50, `25` Win32 DLLs, **`0` child processes (`0` `conhost.exe`, `0` WebView2)** | **PASS** |
| **8. OS `zv://` Protocol Packaging & `--open-uri` CLI Tests** | `zerovault.desktop` (`MimeType=x-scheme-handler/zv;`, `Exec=/usr/bin/zerovault-ui %u`), `PKGBUILD` (`0` `webkit2gtk`), `register-uri.ps1` / `zerovault.wxs` (`HKCU:\Software\Classes\zv`), `8/8` tests pass (`EXIT=0`) | **PASS** |

### Adversarial Red-Team Veto Resolution Log (`Round 1 -> Round 2`)
1. **`W4-VETO-01` (`RESOLVED`):** Round 1 caught `packaging/windows/bundle-portable.ps1` throwing a false-positive exception on `zerovault-ui.exe` and `zerovault-tray.exe` because `metrics.rs` embedded raw lowercase strings `"embeddedbrowserwebview"` and `"webkit2gtk"` in `.rdata`. Remediated in [metrics.rs:239-279](crates/zerovault-ui/src/metrics.rs#L239-L279) using `0x5A`-XOR-masked byte patterns (`std::hint::black_box(0x5Au8)`) + regression test in [ui_integration.rs:504-544](crates/zerovault-ui/tests/ui_integration.rs#L504-L544) + refined runtime loader checks in [bundle-portable.ps1:133-145](packaging/windows/bundle-portable.ps1#L133-L145). Independently re-verified: `RAW_FORBIDDEN_ASCII_MARKERS=0` on both `.exe`s, positive control **PASS**, negative control on `zerovault\Zerovault.exe` **REJECTED AS EXPECTED**.
2. **`W4-VETO-02` (`RESOLVED`):** Round 1 caught both binaries compiling as `3 subsystem (Windows CUI)` and spawning child `conhost.exe` console processes. Remediated via `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` in [main.rs:6](crates/zerovault-ui/src/main.rs#L6) and [zerovault_tray.rs:6](crates/zerovault-ui/src/bin/zerovault_tray.rs#L6). Independently re-verified via `dumpbin.exe /headers` (`2 subsystem (Windows GUI)`) and live `Start-Process` `Win32_Process` inspection (`LIVE_UI_CHILD_PROCESS_COUNT=0`, `LIVE_TRAY ChildCount=0`).

---

## 1. Read-Only Legacy & Source Baseline Integrity (`0` Mutations)

```text
cloudbridge | files=37 | bytes=89165156 | tree_sha256=43ADD08E502AC76DF469BDCEF9C8DC11914880DB8288C28C204345E69AE5B05F
cloudbridge linux | files=65 | bytes=178010385 | tree_sha256=32DB719E53848B03BBDAC67B33423DE9D4161F660FBFF91A1B005126CE31554F
zerovault | files=82 | bytes=31590808 | tree_sha256=383752380A143E34B124F1CA365BD6D5F9F43C570DE0E8D89D00C0632FB4D51D
```

---

## 2. Step 1: Static Audit of `crates/zerovault-ui/src/**` & Dependency Trees

- **Forbidden Token Scan (`11` production `.rs` files):**
  ```text
  STATIC_FORBIDDEN_HITS=0   (.unwrap(): 0 | .expect(): 0 | panic!(): 0 | todo!(): 0 | unimplemented!(): 0)
  CLIPPY_EXIT=0 ELAPSED_MS=1790.703 (0 warnings across --all-targets --locked -- -D warnings)
  ```
- **Dependency Tree Scan (`Cargo.toml`, `Cargo.lock`, `cargo tree`):**
  ```text
  CARGO_TOML_LOCK_WEBVIEW_HITS=0
  CARGO_TREE_EXIT=0 TOTAL_LINES=465 | CARGO_TREE_WIN_FORBIDDEN_HITS=0
  CARGO_TREE_LINUX_EXIT=0 TOTAL_LINES=925 | CARGO_TREE_LINUX_FORBIDDEN_HITS=0
  ```

---

## 3. Step 2: Release Build, PE Subsystem, `dumpbin /dependents` & `bundle-portable.ps1` Proof

- **Release Build Command (`EXIT=0`, `26,970.54 ms`):**
  ```powershell
  $env:CARGO_TARGET_DIR = "<workspace>\target\swarm\judge\w4-ui"
  cargo build --release --manifest-path "<workspace>\Cargo.toml" -p zerovault-ui --locked
  ```

### Verbatim PE Header, Size, SHA-256 & Positive/Negative Bundler Control Output
```text
=== 1. PE HEADERS, SIZES, SHA256 & SUBSYSTEM VERIFICATION ===
BINARY=zerovault-ui.exe BYTES=5748224 MIB=5.482 SHA256=595c73b5133d026863225d751abceb0541dcae7a9bfd635060d19b919cfb00ae
  SUBSYSTEM_HEADERS:             6.00 subsystem version |                2 subsystem (Windows GUI)
  RAW_FORBIDDEN_ASCII_MARKERS=0
BINARY=zerovault-tray.exe BYTES=849408 MIB=0.810 SHA256=b1712a0a1b562d33a7a0f59bf7ebb0b1988676503082a2394bb644a8bd7e627e
  SUBSYSTEM_HEADERS:             6.00 subsystem version |                2 subsystem (Windows GUI)
  RAW_FORBIDDEN_ASCII_MARKERS=0

=== 2. BUNDLE-PORTABLE.PS1 Assert-ZeroWebViewBinary POSITIVE & NEGATIVE CONTROL ===
POSITIVE_CONTROL zerovault-ui.exe: PASS (0 WebView2 imports & 0 runtime markers)
POSITIVE_CONTROL zerovault-tray.exe: PASS (0 WebView2 imports & 0 runtime markers)
NEGATIVE_CONTROL <donor-root>\zerovault\Zerovault.exe: REJECTED AS EXPECTED -> ZERO-WEBVIEW STRING AUDIT FAILED: '<donor-root>\zerovault\Zerovault.exe' contains embedded runtime marker 'WebView2Loader.dll'.
```

### Verbatim `dumpbin.exe /dependents` Imports (`0` Browser / WebView DLLs)
- **`zerovault-ui.exe` (`28` native DLLs):** `oleaut32.dll`, `kernel32.dll`, `user32.dll`, `advapi32.dll`, `api-ms-win-core-synch-l1-2-0.dll`, `shell32.dll`, `combase.dll`, `ole32.dll`, `ntdll.dll`, `shlwapi.dll`, `bcryptprimitives.dll`, `uiautomationcore.dll`, `ws2_32.dll`, `gdi32.dll`, `uxtheme.dll`, `USER32.dll`, `opengl32.dll`, `imm32.dll`, `dwmapi.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `api-ms-win-crt-{math,string,runtime,stdio,heap,convert,locale}-l1-1-0.dll`.
- **`zerovault-tray.exe` (`19` native DLLs, `0` GPU/`egui` DLLs):** `shell32.dll`, `combase.dll`, `kernel32.dll`, `api-ms-win-core-synch-l1-2-0.dll`, `gdi32.dll`, `user32.dll`, `comctl32.dll`, `ws2_32.dll`, `ntdll.dll`, `advapi32.dll`, `bcryptprimitives.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `api-ms-win-crt-{math,runtime,stdio,heap,convert,locale}-l1-1-0.dll`.

---

## 4. Step 3: 20× Cold Window Open Latency, Live `Win32_Process` Tree & Tray RSS Audit

### 4.1 20× Cold Window Open Benchmark (`zerovault-ui.exe --bench-cold --spawn-qpc <QPC>`)

| Metric | `min` | `p50` (Median) | `p95` | `max` | `mean` | Target / Ceiling | Status |
| :--- | ---: | ---: | ---: | ---: | ---: | :---: | :---: |
| **Internal Cold Open (`main() -> Frame #1` swap)** | **`140.075 ms`** | **`149.330 ms`** | **`179.065 ms`** | **`194.390 ms`** | `153.588 ms` | Beat Wave 1 (`174.66 ms`) | **PASS** |
| **External Cold Start (`CreateProcess -> Frame #1`)** | **`153.475 ms`** | **`163.382 ms`** | **`194.458 ms`** | **`210.199 ms`** | `167.953 ms` | Beat Wave 1 (`191.81 ms`) | **PASS** |
| **Frame #1 `egui` CPU Layout/Paint** | `0.373 ms` | `0.390 ms` | `0.417 ms` | `0.425 ms` | `0.391 ms` | `< 16.6 ms` | **PASS** |
| **Resident `WorkingSet64` at Frame #1** | **`69.535 MiB`** | **`69.637 MiB`** | **`69.711 MiB`** | **`69.738 MiB`** | `69.644 MiB` | `< 128 MiB` | **PASS** |
| **Private Commit (`PrivateUsage`)** | `80.652 MiB` | `81.404 MiB` | `82.109 MiB` | `82.367 MiB` | `81.425 MiB` | — | **PASS** |
| **Loaded WebView2 / Browser Modules** | **`0`** | **`0`** | **`0`** | **`0`** | **`0`** | **`0`** | **PASS** |

#### Verbatim 20-Run Log & Sample JSON (`SUBSYSTEM:WINDOWS` Release Binary)
```text
RUN  1/20: exit=0 internal_cold_ms=162.686 spawn_to_frame1_ms=183.736 frame1_cpu_ms=0.388 ws_mib=69.691 (73076736 B) priv_mib=80.652 webview2_mods=0
RUN  2/20: exit=0 internal_cold_ms=155.621 spawn_to_frame1_ms=169.798 frame1_cpu_ms=0.417 ws_mib=69.680 (73064448 B) priv_mib=81.102 webview2_mods=0
RUN  3/20: exit=0 internal_cold_ms=194.390 spawn_to_frame1_ms=210.199 frame1_cpu_ms=0.392 ws_mib=69.637 (73019392 B) priv_mib=82.109 webview2_mods=0
RUN  4/20: exit=0 internal_cold_ms=166.586 spawn_to_frame1_ms=182.174 frame1_cpu_ms=0.387 ws_mib=69.637 (73019392 B) priv_mib=82.367 webview2_mods=0
RUN  5/20: exit=0 internal_cold_ms=150.998 spawn_to_frame1_ms=165.626 frame1_cpu_ms=0.380 ws_mib=69.641 (73023488 B) priv_mib=81.434 webview2_mods=0
RUN  6/20: exit=0 internal_cold_ms=153.165 spawn_to_frame1_ms=166.915 frame1_cpu_ms=0.405 ws_mib=69.590 (72970240 B) priv_mib=81.809 webview2_mods=0
RUN  7/20: exit=0 internal_cold_ms=179.065 spawn_to_frame1_ms=194.458 frame1_cpu_ms=0.393 ws_mib=69.648 (73031680 B) priv_mib=80.715 webview2_mods=0
RUN  8/20: exit=0 internal_cold_ms=164.557 spawn_to_frame1_ms=179.319 frame1_cpu_ms=0.398 ws_mib=69.738 (73125888 B) priv_mib=80.953 webview2_mods=0
RUN  9/20: exit=0 internal_cold_ms=153.688 spawn_to_frame1_ms=168.795 frame1_cpu_ms=0.376 ws_mib=69.637 (73019392 B) priv_mib=81.379 webview2_mods=0
RUN 10/20: exit=0 internal_cold_ms=141.035 spawn_to_frame1_ms=154.197 frame1_cpu_ms=0.382 ws_mib=69.629 (73011200 B) priv_mib=81.387 webview2_mods=0
RUN 11/20: exit=0 internal_cold_ms=147.413 spawn_to_frame1_ms=160.504 frame1_cpu_ms=0.375 ws_mib=69.613 (72994816 B) priv_mib=82.008 webview2_mods=0
RUN 12/20: exit=0 internal_cold_ms=142.166 spawn_to_frame1_ms=155.523 frame1_cpu_ms=0.396 ws_mib=69.535 (72912896 B) priv_mib=82.023 webview2_mods=0
RUN 13/20: exit=0 internal_cold_ms=146.836 spawn_to_frame1_ms=159.766 frame1_cpu_ms=0.405 ws_mib=69.637 (73019392 B) priv_mib=81.633 webview2_mods=0
RUN 14/20: exit=0 internal_cold_ms=142.500 spawn_to_frame1_ms=155.570 frame1_cpu_ms=0.396 ws_mib=69.711 (73097216 B) priv_mib=80.738 webview2_mods=0
RUN 15/20: exit=0 internal_cold_ms=147.663 spawn_to_frame1_ms=161.137 frame1_cpu_ms=0.383 ws_mib=69.637 (73019392 B) priv_mib=82.063 webview2_mods=0
RUN 16/20: exit=0 internal_cold_ms=140.883 spawn_to_frame1_ms=154.226 frame1_cpu_ms=0.373 ws_mib=69.621 (73003008 B) priv_mib=81.301 webview2_mods=0
RUN 17/20: exit=0 internal_cold_ms=146.323 spawn_to_frame1_ms=160.963 frame1_cpu_ms=0.375 ws_mib=69.656 (73039872 B) priv_mib=81.801 webview2_mods=0
RUN 18/20: exit=0 internal_cold_ms=140.075 spawn_to_frame1_ms=153.475 frame1_cpu_ms=0.375 ws_mib=69.605 (72986624 B) priv_mib=80.848 webview2_mods=0
RUN 19/20: exit=0 internal_cold_ms=143.283 spawn_to_frame1_ms=156.411 frame1_cpu_ms=0.392 ws_mib=69.676 (73060352 B) priv_mib=81.422 webview2_mods=0
RUN 20/20: exit=0 internal_cold_ms=152.828 spawn_to_frame1_ms=166.260 frame1_cpu_ms=0.425 ws_mib=69.668 (73052160 B) priv_mib=80.758 webview2_mods=0

SAMPLE_JSON_20:
{"mode":"bench-cold","renderer":"glow","backend":"glow","gpu_adapter":"NVIDIA GeForce RTX 4080 SUPER/PCIe/SSE2 [3.3.0 NVIDIA 621.01]","ipc_endpoint":"\\\\.\\pipe\\zerovaultd","ipc_connected":false,"ipc_roundtrip_ms":0.095,"cold_open_latency_ms":152.828,"internal_cold_start_ms":152.828,"external_cold_start_ms":166.26,"frame1_update_cpu_ms":0.425,"working_set_64":73052160,"working_set_bytes":73052160,"working_set_mib":69.668,"peak_working_set_bytes":73052160,"peak_working_set_mib":69.668,"private_usage_bytes":84680704,"private_usage_mib":80.758,"webview2_modules":0,"webview2_detected":false,"loaded_webview_modules":[],"memory":{"working_set_bytes":73052160,"working_set_mib":69.668,"peak_working_set_bytes":73052160,"peak_working_set_mib":69.668,"private_usage_bytes":84680704,"private_usage_mib":80.758,"page_fault_count":20363}}
```

### 4.2 Live Interactive Window (`1.0s` Hold), `Win32_Process` Tree (`0` Children) & Post-Close `0 Bytes` Proof
```text
=== 3. LIVE INTERACTIVE WINDOW & TRAY OS PROCESS TREE (SUBSYSTEM:WINDOWS — 0 CONHOST, 0 WEBVIEW2) ===
LIVE_UI: PID=48424 PPID=30804 WS=90976256 (86.762 MiB) Private=90411008 (86.223 MiB) Modules=91 BadModules=0
LIVE_UI_CHILD_PROCESS_COUNT=0 (conhost=0, webview2=0)
NEW_SYSTEM_WEBVIEW_PROCESSES=0
ZEROVAULT_HWND=30412060
WM_CLOSE_SHUTDOWN: Exited=True ElapsedMs=81.737 ExitCode=0
POST_CLOSE_UI_PROCESSES=0 POST_CLOSE_UI_RSS_BYTES=0
LIVE_TRAY: PID=29864 WS=9728000 (9.277 MiB) Private=5042176 (4.809 MiB) Modules=25 ChildCount=0
```

### 4.3 5× `zerovault-tray.exe --bench-tray` (`SUBSYSTEM:WINDOWS` Release Binary)
```text
TRAY_RUN 1/5: exit=0 json={"mode":"bench-tray","binary_role":"zerovault-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.909,"settle_duration_ms":400,"working_set_64":9183232,"working_set_mib":8.758,"webview2_modules":0,"memory":{"working_set_bytes":9183232,"working_set_mib":8.758,"peak_working_set_bytes":9183232,"peak_working_set_mib":8.758,"private_usage_bytes":4956160,"private_usage_mib":4.727,"page_fault_count":2321}}
TRAY_RUN 2/5: exit=0 json={"mode":"bench-tray","binary_role":"zerovault-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.738,"settle_duration_ms":400,"working_set_64":9183232,"working_set_mib":8.758,"webview2_modules":0,"memory":{"working_set_bytes":9183232,"working_set_mib":8.758,"peak_working_set_bytes":9183232,"peak_working_set_mib":8.758,"private_usage_bytes":4988928,"private_usage_mib":4.758,"page_fault_count":2321}}
TRAY_RUN 3/5: exit=0 json={"mode":"bench-tray","binary_role":"zerovault-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.675,"settle_duration_ms":400,"working_set_64":9183232,"working_set_mib":8.758,"webview2_modules":0,"memory":{"working_set_bytes":9183232,"working_set_mib":8.758,"peak_working_set_bytes":9183232,"peak_working_set_mib":8.758,"private_usage_bytes":4980736,"private_usage_mib":4.75,"page_fault_count":2319}}
TRAY_RUN 4/5: exit=0 json={"mode":"bench-tray","binary_role":"zerovault-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.815,"settle_duration_ms":400,"working_set_64":9179136,"working_set_mib":8.754,"webview2_modules":0,"memory":{"working_set_bytes":9179136,"working_set_mib":8.754,"peak_working_set_bytes":9179136,"peak_working_set_mib":8.754,"private_usage_bytes":4935680,"private_usage_mib":4.707,"page_fault_count":2317}}
TRAY_RUN 5/5: exit=0 json={"mode":"bench-tray","binary_role":"zerovault-tray","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.751,"settle_duration_ms":400,"working_set_64":9183232,"working_set_mib":8.758,"webview2_modules":0,"memory":{"working_set_bytes":9183232,"working_set_mib":8.758,"peak_working_set_bytes":9183232,"peak_working_set_mib":8.758,"private_usage_bytes":4947968,"private_usage_mib":4.719,"page_fault_count":2319}}
```

---

## 5. Step 4: OS `zv://` Protocol Registration, Arch Packaging & `--open-uri` CLI Verification

- **Arch Linux Desktop Entry ([packaging/arch/zerovault.desktop](packaging/arch/zerovault.desktop)):** `Exec=/usr/bin/zerovault-ui %u`, `TryExec=/usr/bin/zerovault-ui`, `MimeType=x-scheme-handler/zv;`.
- **Arch Linux `PKGBUILD` ([packaging/arch/PKGBUILD](packaging/arch/PKGBUILD)):** `depends=('fuse3' 'gcc-libs' 'glibc' 'libsecret' 'libglvnd' 'wayland' 'libxkbcommon')` — **`0` `webkit2gtk`**.
- **Windows Per-User `zv://` Registration ([register-uri.ps1](packaging/windows/register-uri.ps1) & [zerovault.wxs](packaging/windows/zerovault.wxs)):** `HKCU\Software\Classes\zv\shell\open\command` -> `"<UiExe>" --open-uri "%1"` (`0` UAC elevation).
- **Integration Suite (`cargo test -p zerovault-ui --locked`, `EXIT=0` in `6,872.97 ms`):** `8/8` tests pass (including the new XOR-masked browser-detector + PE `.rdata` zero-marker regression check in `bench_cold_and_bench_tray_executables_render_and_verify_zero_webview2`); adversarial malformed `--open-uri` and non-loopback `--ipc` fail closed (`EXIT=2`).
