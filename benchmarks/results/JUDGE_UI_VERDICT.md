# Adversarial Gate 1 UI Verification Verdict (`Agent-Judge` — UI Shard)

- **Gate:** Wave 1 Gate 1 — Native Desktop UI Silicon Bake-Off Adversarial Audit & Empirical Stack Selection
- **Auditor:** `Agent-Judge` (Adversarial Red-Team & Proof Verifier — UI Shard)
- **Host Silicon:** AMD Ryzen 9 7950X3D (16C/32T, 31.6 GiB DDR5) + NVIDIA GeForce RTX 4080 SUPER (`2560x1440 @ 540 Hz`) + Windows 11 (`10.0.26300`, `x86_64-pc-windows-msvc`)
- **Raw Machine-Readable Ledger:** [judge_ui_verification.json](benchmarks/results/judge_ui_verification.json)
- **Judge Independent Harness & Raw Logs:** [run_judge_ui_benchmarks.ps1](target/swarm/judge/ui/run_judge_ui_benchmarks.ps1) / [judge_raw_runs.json](target/swarm/judge/ui/judge_raw_runs.json)
- **Read-Only Source Baseline Integrity:** **PASS (`0` mutations)** — verified against [READONLY_BASELINE.txt](audit/READONLY_BASELINE.txt) (`cloudbridge`: `37` files / `89,165,156 B`; `cloudbridge linux`: `65` files / `178,010,385 B`; `zerovault`: `82` files / `31,590,808 B`).

---

## 1. Executive Gate Verdict & Final Ranking

> **EMPIRICAL UI STACK WINNER: Candidate B2 — Pure Rust `eframe 0.29.1` / `egui` (`glow` Native OpenGL/WGL/EGL Backend) + `tray-icon 0.26.1` + `AccessKit`**

| Rank | Candidate & Backend | Verdict | UI `.exe` / Total Dist Size | Judge Cold TTI `p50` (Int / Ext) | Judge 60fps Pacing `p50 / p99` | Judge 60fps User CPU (`5.0s`) | Judge Active / Peak RSS | Judge Private Commit | Closed-Window UI RAM / Live Tray RSS |
| :---: | :--- | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **#1** | **Candidate B2 (`glow`):** Pure Rust `eframe 0.29.1` / `egui` + `glow` OpenGL + `tray-icon 0.26.1` | **WINNER** | **`5.115 MiB`** (`5.528 MiB` w/ tray `.exe`, or `5.115 MiB` single-`.exe`) | **`174.66 ms` / `191.81 ms`** (`265.68 ms` exit) | **`16.667 / 17.115 ms`** (`300/300` frames) | **`437.50 ms`** *(Lowest CPU)* | **`96.43 / 96.55 MiB`** *(Cold: `68.78 MiB`)* | **`88.40 MiB`** *(Cold: `69.31 MiB`)* | **`0 B` UI** / **`8.07 MiB` RSS (`1.39 MiB` Private)** |
| **#2** | **Candidate B1 (`tiny-skia`):** Pure Rust `iced 0.13.1` + `tiny-skia` SIMD CPU (`softbuffer`) | **RUNNER-UP** | **`3.710 MiB`** (`3.710 MiB` total; *no tray built*) | **`121.39 ms` / `145.02 ms`** (exit) | **`16.662 / 16.921 ms`** (`300/300` frames) | `1,828.13 ms` *(4.18x higher CPU)* | **`42.34 / 42.34 MiB`** *(Cold: `34.50 MiB`)* | **`18.04 MiB`** *(Cold: `16.17 MiB`)* | **`0 B` UI** / *Tray unimplemented* |
| **#3** | **Candidate A:** `.NET 9.0.320` NativeAOT + `Avalonia 12.1.6` (`PublishAot=true`, Skia + ANGLE) | **ELIMINATED** | `19.281 MiB` (**`37.247 MiB`** across 4 files) | `228.68 ms`* / `293.46 ms` (exit) | `16.665 / 16.911 ms` (`300/300` frames) | `875.00 ms` (`+27.05 MiB` GC alloc) | `142.28 / 142.28 MiB` *(Exceeds 128 MiB)* | `144.36 MiB` *(Cold: `76.25 MiB`)* | **`0 B` UI** / *Tray unimplemented* |
| **#4** | **`wgpu` Backends:** Candidate B1 `iced + wgpu(vulkan)` & Candidate B2 `eframe + wgpu` | **VETOED BACKEND** | `9.544 MiB` (`iced`) / `11.689 MiB` (`egui`) | `474.52 ms` (`iced`) / `546.40 ms` (`egui`) | `16.665 / 17.208 ms` (`iced`) | `468.75 ms` (`iced`) | `164.96 MiB` (`iced`) / `307.66 MiB` (`egui`) | `212.06 MiB` (`iced`) / `342.15 MiB` (`egui`) | **`0 B` UI** / `11.56 MiB` (`egui`) |

*\*Note: Candidate A's internal `228.68 ms` fires inside `TopLevel.RequestAnimationFrame` prior to Avalonia's Skia/ANGLE composition pass (see Flag A1).*

---

## 2. Check 1: Anti-Cheat Source Code Inspection

`Agent-Judge` audited every line of source code across all three candidates ([MainWindow.axaml.cs](benchmarks/ui_dotnet/Views/MainWindow.axaml.cs), [PipeIpcService.cs](benchmarks/ui_dotnet/Services/PipeIpcService.cs), [iced/src/main.rs](benchmarks/ui_rust/iced/src/main.rs), [egui/src/main.rs](benchmarks/ui_rust/egui/src/main.rs), [egui/src/ipc.rs](benchmarks/ui_rust/egui/src/ipc.rs), [egui/src/ui.rs](benchmarks/ui_rust/egui/src/ui.rs), [egui/src/tray.rs](benchmarks/ui_rust/egui/src/tray.rs)).

### Core Authenticity Matrix (All 3 Candidates Verified Genuine)
| Anti-Cheat Criterion | Candidate A (`.NET 9` + `Avalonia 12.1.6`) | Candidate B1 (`iced 0.13.1`) | Candidate B2 (`eframe/egui 0.29.1`) |
| :--- | :--- | :--- | :--- |
| **Visible OS Window Created?** | **YES** — `1080x740` Win32/ANGLE window (`MainWindow.axaml:7-14`) | **YES** — `1120x760` centered `winit` window (`src/main.rs:1546-1547`) | **YES** — `1040x680` `with_visible(true)` `winit` window (`src/main.rs:159-161`) |
| **Real Windows Named Pipe IPC?** | **YES** — `NamedPipeClientStream` (`PipeIpcService.cs:209`) | **YES** — `tokio::net::windows::named_pipe::ClientOptions` (`src/main.rs:811`) | **YES** — Win32 `CreateFileW` over `\\.\pipe\...` (`src/ipc.rs:241`) |
| **300 Distinct Payloads Parsed?** | **YES** — AOT source-gen `BakeoffJsonContext` (`PipeIpcService.cs:232`) | **YES** — `serde_json::from_str::<TelemetryFrame>` (`src/main.rs:829`) | **YES** — `serde_json::from_str::<TelemetryFrame>` (`src/ipc.rs:354`) |
| **All Required Widgets Visible on Frame 1?** | **YES** — Status/Mount/PQ badges, 3 progress bars, 3 cloud quota cards, ComboBox, Slider, Lock button (*no waveform canvas*) | **YES** — All badges, 3 progress bars, **120-sample dual waveform canvas**, 3 cloud quota cards, PickList + pills, Slider, Lock button | **YES** — All badges, 3 progress bars, **two 72-sample GPU vector sparklines**, 3 cloud quota cards, Policy pills, Slider, Lock button |

### Red-Team Flags Raised During Source Inspection
1. **`FLAG-A1` (Candidate A — Pre-Composite Callback Timing):** In [MainWindow.axaml.cs](benchmarks/ui_dotnet/Views/MainWindow.axaml.cs#L223-L227) and [L269-L280](benchmarks/ui_dotnet/Views/MainWindow.axaml.cs#L269-L280), `ColdFirstFrameIpcMs` and `RenderLatencyMs` (`0.214 ms` p50) are sampled inside `TopLevel.RequestAnimationFrame`. In Avalonia's rendering architecture, `RequestAnimationFrame` fires on the UI dispatcher thread at the beginning of an animation tick *before* the render thread rasterizes Skia display lists and invokes ANGLE `eglSwapBuffers`. Thus `0.214 ms` measures IPC-to-UI-dispatcher wakeup, not GPU frame render time.
2. **`FLAG-A2` (Candidate A — Managed GC Nursery Churn):** Over the 5.0-second (`300`-frame) stream, Candidate A allocated **`28,359,400 bytes` (`27.05 MiB`, `~92.4 KiB/frame`, `5.41 MiB/s`)** on the managed heap via per-frame `string.Create` allocations ([MainWindowViewModel.cs](benchmarks/ui_dotnet/ViewModels/MainWindowViewModel.cs#L246-L282)) and visual invalidation. It reported `0` Gen0 collections solely because the 5-second test stopped just shy of exhausting the ~32 MiB Gen0 budget.
3. **`FLAG-B1-2` (Candidate B1 `tiny-skia` — Hidden CPU Rasterization Cost):** While `iced` + `tiny-skia` achieved tiny RAM (`42.34 MiB`) and fast cold start (`121.39 ms`), Candidate B1's JSON telemetry did not record process CPU time. Judge's external `GetProcessTimes` instrumentation exposed **`1,828.125 ms` user CPU (`2,187.50 ms` total CPU)** over the 5.0s stream at `1120x760` (**4.18x higher user CPU** than `egui + glow`'s `437.50 ms`), which scales linearly `O(width * height)` on 4K HiDPI displays (`3840x2160` = `9.75x` pixel count).
4. **`FLAG-B2-1` (Candidate B2 `egui` — `vsync=false` Default in Benchmark Modes):** In [egui/src/main.rs](benchmarks/ui_rust/egui/src/main.rs#L147-L151), Candidate B2 defaulted `vsync` to `false` during `--bench-cold` and `--bench-60fps` (exposing `--vsync` as an opt-in CLI flag). `Agent-Judge` ran an adversarial counter-test **forcing `--vsync` ON**: cold internal `p50` rose from `174.66 ms` to `326.68 ms` (`347.09 ms` external Frame #1) due to Windows 11 WGL/DWM swap-interval handshaking—still beating every `wgpu` binary (`474.5–546.4 ms`)—while 60fps pacing (`16.668 ms` p50 / `17.441 ms` p99) and RSS (`96.16 MiB`) were virtually unchanged.
5. **`FLAG-B2-2` (Candidate B2 `egui` — Double GPU Pass per IPC Wakeup):** In `--bench-60fps`, `total_gpu_frames` was `600` for `300` rendered IPC frames because `egui` runs 1 immediate repaint + 1 settle pass per `ctx.request_repaint()`. Even across `600` GPU frames, `egui + glow` consumed only **`437.50 ms` total user CPU** (`0.576 ms` p50 per GPU frame) — the lowest user CPU of all candidates.
6. **`FLAG-B1-3` & `FLAG-B2-3` (Platform `#[cfg]` Hygiene for Arch Linux Wayland):** Both Rust benchmark crates placed Win32 Named Pipe / memory FFI (`windows-sys` or `#[link(name = "kernel32")]`) unconditionally in their Windows bake-off manifests; Wave 2 `crates/zerovault-ui` must gate Windows IPC/metrics under `#[cfg(windows)]` and Unix Domain Socket IPC (`$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock`) under `#[cfg(unix)]`.

---

## 3. Check 2: Zero-WebView Binary & String Scan Proof

Command executed across all 9 PE binaries (`.exe` + companion `.dll`s):
```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe" /dependents <BINARY>
# Plus raw byte scan (ASCII + UTF-16LE) for: WebView2|EmbeddedBrowserWebView|msedgewebview2|CefSharp|libcef|WebKit|wry::|tauri::
```

| Binary File | Exact Bytes (`MiB`) | SHA-256 Digest | WebView / Browser DLLs (`dumpbin`) | ASCII / UTF-16 Browser String Hits | Key Native Imports |
| :--- | ---: | :--- | :---: | :---: | :--- |
| `publish\ZeroVaultUi.exe` | `20,217,344` (`19.281`) | `8B3BDA3C...33D0CC36` | **`0`** | `0` / `1`* | `KERNEL32`, `ADVAPI32`, `bcrypt`, `ole32`, `OLEAUT32`, UCRT |
| `publish\libSkiaSharp.dll` | `11,628,896` (`11.090`) | `7DEC3BA9...FFDBBE1C` | **`0`** | `0` / `0` | `USER32`, `FONTSUB`, `ole32`; delay-load `d3d12`, `D3DCOMPILER_47` |
| `publish\av_libglesv2.dll` | `5,394,096` (`5.144`) | `53191A77...4A0B73E3` | **`0`** | `0` / `0` | `dxgi.dll`, `USER32`, `KERNEL32` |
| `publish\libHarfBuzzSharp.dll` | `1,816,088` (`1.732`) | `145ADE96...20DA246F` | **`0`** | `0` / `0` | `KERNEL32.dll` |
| `iced\release\zerovault-ui-iced.exe` (`wgpu`) | `10,008,064` (`9.544`) | `F0A63FF6...3959053` | **`0`** | `0` / `0` | `USER32`, `GDI32`, `opengl32`, `d3dcompiler_47`, `dwmapi`, `uxtheme` |
| `iced-tiny-skia\release\zerovault-ui-iced.exe` | `3,890,688` (`3.710`) | `D257362D...B4222FB9` | **`0`** | `0` / `0` | `USER32`, `gdi32`, `dwmapi`, `uxtheme`, `imm32` *(zero GPU DLLs)* |
| `egui\release\zerovault_ui_egui_glow.exe` | `5,363,712` (`5.115`) | `5617FFB1...75847E09` | **`0`** | `0` / `0` | `user32`, `gdi32`, `opengl32`, `uiautomationcore`, `dwmapi`, `uxtheme` |
| `egui\release\zerovault_ui_egui_wgpu.exe` | `12,257,280` (`11.689`) | `1685BEFF...60605530` | **`0`** | `0` / `0` | `user32`, `opengl32`, `d3dcompiler_47`, `uiautomationcore`, `dwmapi` |
| `egui\release\zerovault_tray_egui.exe` | `433,152` (`0.413`) | `6A7705E9...AF73B3B` | **`0`** | `0` / `0` | `user32`, `shell32`, `gdi32`, `comctl32`, `kernel32`, UCRT |

*\*Forensic context check on the single UTF-16 match inside `ZeroVaultUi.exe`: `".-.Renderer: Avalonia Skia GPU . 0 WebView2 DLL..."` — proven to be the literal UI status-bar text in [MainWindow.axaml:299](benchmarks/ui_dotnet/Views/MainWindow.axaml#L299). **Zero** WebView2, CefSharp, WebKit, or `wry` code exists in any candidate.*

---

## 4. Check 3: Independent Judge Re-Execution (`\\.\pipe\zerovault-judge-ipc`)

Instead of relying on any candidate's internal mock server or self-reported scripts, `Agent-Judge` compiled an independent C#/Win32 `CreateWaitableTimerExW(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION)` multi-instance Named Pipe server on `\\.\pipe\zerovault-judge-ipc` ([run_judge_ui_benchmarks.ps1](target/swarm/judge/ui/run_judge_ui_benchmarks.ps1)) and executed:
1. **1 warmup launch per binary** (isolating one-time Windows Defender PE hash caching equally across all contenders).
2. **20 fresh OS cold launches (`--bench-cold`)** per contender, recording exit codes, external wall-clock latency, OS kernel+user CPU time (`GetProcessTimes`), and first-frame memory.
3. **300-frame (`5.0s` @ `60.00 Hz`) live Named Pipe transfer-meter runs (`--bench-60fps`)**, including an **external mid-stream parent-process `WorkingSet64` / `PrivateMemorySize64` probe at `t = 2.5s`** to defeat any hypothetical memory under-reporting.
4. **External live tray & closed-window OS process audit** (`Get-Process` + live `900 ms` `--interactive` hold on `zerovault_tray_egui.exe`).

### 4.1 Candidate-Claimed vs. Judge-Verified Cold Launch (`N = 20`, Exit Code `0` on `80/80` Runs)

| Candidate Variant | Claimed Int `p50` | **Judge Int `p50 / p95 / max`** | Claimed Ext `p50` | **Judge Ext `p50 / p95 / max`** | **Judge Cold RSS `p50`** | **Judge Cold Private `p50`** |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **B1 (`iced` + `tiny-skia`)** | `131.83 ms` | **`121.39 / 129.63 / 133.43 ms`** | `158.17 ms` | **`145.02 / 155.68 / 158.87 ms`** (exit) | **`34.50 MiB`** | **`16.17 MiB`** |
| **B2 (`egui` + `glow`)** | `155.22 ms` | **`174.66 / 246.50 / 410.76 ms`** | `166.52 ms` (F1) / `238.07 ms` (exit) | **`191.81 / 266.45 / 428.96 ms`** (F1) / `265.68 ms` (exit) | **`68.78 MiB`** | **`69.31 MiB`** |
| **A (`.NET 9` + `Avalonia`)** | `245.24 ms` | **`228.68 / 239.44 / 240.94 ms`** | `300.76 ms` | **`293.46 / 321.26 / 332.34 ms`** (exit) | `79.08 MiB` | `76.25 MiB` |
| **B1 (`iced` + `wgpu` Vulkan)** | `461.64 ms` | **`474.52 / 846.02 / 1151.69 ms`** | `605.35 ms` | **`629.29 / 991.82 / 1290.65 ms`** (exit) | `152.14 MiB` | `207.46 MiB` |
| **B2 (`egui` + `wgpu`, N=5)** | `332.71 ms` (DX12) | **`546.40 / 1249.74 / 1422.41 ms`** (Vulkan auto) | `344.68 ms` (DX12) | **`565.30 / 1271.59 / 1445.13 ms`** (F1) | `295.90 MiB` | `336.52 MiB` |

### 4.2 Sustaining 60 FPS Live Named Pipe IPC (`300` Frames / `5.0s`, External Mid-Stream Memory Verified)

| Candidate Variant | Exit Code | Wall Time (`ms`) | Frame Pacing `p50 / p95 / p99` (`ms`) | **Judge User / Total CPU (`ms`)** | **External Mid-Stream RSS (`t=2.5s`)** | **Final Active / Peak RSS (`MiB`)** | **Private Commit (`MiB`)** |
| :--- | :---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **B2 (`egui` + `glow`)** | `0` | `5,391.58` | **`16.667 / 16.924 / 17.115`** | **`437.50 / 1,375.00`** | **`96.430 MiB`** | **`96.430 / 96.551`** | **`88.402`** |
| **B2 (`egui` + `glow --vsync`)** | `0` | `~5,400` | **`16.668 / 17.045 / 17.441`** | **`~500 / 1,578.13`** | — | **`96.156 / 96.375`** | **`89.121`** |
| **B1 (`iced` + `tiny-skia`)** | `0` | `5,114.24` | **`16.662 / 16.818 / 16.921`** | `1,828.13 / 2,187.50` | **`42.281 MiB`** | **`42.340 / 42.340`** | **`18.043`** |
| **B1 (`iced` + `wgpu` Vulkan)** | `0` | `5,673.96` | `16.665 / 17.069 / 17.208` | `468.75 / 1,156.25` | `164.656 MiB` | `164.957 / 164.957` | `212.059` |
| **A (`.NET 9` + `Avalonia`)** | `0` | `5,398.06` | `16.665 / 16.795 / 16.911` | `875.00 / 1,468.75` | `123.617 MiB` *(growing)* | `142.277 / 142.277` | `144.363` |
| **B2 (`egui` + `wgpu` Vulkan)** | `0` | `5,706.97` | `16.663 / 16.910 / 17.050` | `~500 / 1,531.25` | `306.453 MiB` | `307.664 / 307.664` | `342.152` |

### 4.3 Raw Command & Stdout Excerpts (Judge Independent Run)

- **Candidate B2 (`egui + glow` — Winner) 60fps Command (`ExitCode = 0`):**
  ```text
  Command: "<workspace>\target\swarm\bakeoff-ui-rust\egui\release\zerovault_ui_egui_glow.exe" --bench-60fps --pipe "\\.\pipe\zerovault-judge-ipc" --frames 300
  Stdout:  {"mode":"bench-60fps","backend":"glow","gpu_adapter":"NVIDIA GeForce RTX 4080 SUPER/PCIe/SSE2 [3.3.0 NVIDIA 621.01]","ipc_pipe":"\\\\.\\pipe\\zerovault-judge-ipc","ipc_mode":"external_named_pipe","target_ipc_frames":300,"rendered_ipc_frames":300,"total_gpu_frames":600,"elapsed_wall_ms":5069.567,"achieved_fps":59.177,"frame_pacing_ms":{"count":299,"min":1.505,"p50":16.667,"p95":16.924,"p99":17.115,"max":115.922,"mean":16.948},"frame_render_cpu_ms":{"count":599,"min":0.241,"p50":0.576,"p95":1.089,"p99":1.392,"max":32.873,"mean":0.657},"memory":{"working_set_bytes":101113856,"working_set_mib":96.43,"peak_working_set_bytes":101240832,"peak_working_set_mib":96.551,"private_usage_bytes":92696576,"private_usage_mib":88.402,"page_fault_count":74076}}
  ```
- **Candidate B1 (`iced + tiny-skia` — Runner-Up) 60fps Command (`ExitCode = 0`):**
  ```text
  Command: "<workspace>\target\swarm\bakeoff-ui-rust\iced-tiny-skia\release\zerovault-ui-iced.exe" --bench-60fps --pipe "\\.\pipe\zerovault-judge-ipc" --frames 300
  Stdout:  {"candidate":"B1","framework":"iced 0.13.1","renderer_backend":"tiny-skia","mode":"bench-60fps","pipe_name":"\\\\.\\pipe\\zerovault-judge-ipc","ipc_source":"external-win32-named-pipe-server","ipc_frames_received":300,"rendered_frames":300,"elapsed_wall_ms":4982.712,"effective_fps":60.007,"frame_time_min_ms":16.164,"frame_time_p50_ms":16.662,"frame_time_p95_ms":16.818,"frame_time_p99_ms":16.921,"frame_time_max_ms":17.017,"frame_time_mean_ms":16.665,"memory":{"working_set_bytes":44396544,"peak_working_set_bytes":44396544,"private_usage_bytes":18919424,"working_set_mib":42.34,"peak_working_set_mib":42.34,"private_usage_mib":18.043}}
  ```
- **Candidate A (`.NET 9 + Avalonia 12.1.6`) Cold Run #1 & 60fps Excerpt (`ExitCode = 0`):**
  ```text
  Command: "<workspace>\target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe" --bench-cold --pipe zerovault-judge-ipc
  Stdout:  {"mode":"bench-cold","dotnet_sdk":"9.0.320","runtime_framework":".NET 9.0.22","avalonia_version":"12.1.6.0","is_native_aot":true,"pipe_path":"\\\\.\\pipe\\zerovault-judge-ipc","ipc_server_mode":"external_named_pipe","cold_first_frame_ipc_ms":228.257,"window_opened_ms":227.059,"first_ipc_received_ms":211.606,"first_frame_seq":1,"working_set_bytes":82927616,"working_set_mib":79.086,"peak_working_set_bytes":82927616,"peak_working_set_mib":79.086,"private_memory_bytes":80072704,"private_memory_mib":76.363,"timestamp_utc":"2026-11-17T18:48:41.1148090Z"}
  ```
- **Closed-Window `0-Byte` UI Surface & Live Tray External Probe (`ExitCode = 0`):**
  ```text
  Lingering UI Processes Post-Close: 0 (closed_window_ui_surface_ram_bytes = 0)
  External Parent Probe of "zerovault_tray_egui.exe --interactive" @ t=900ms:
    WorkingSet64 = 8,466,432 bytes (8.074 MiB) | PeakWorkingSet64 = 8,466,432 bytes (8.074 MiB) | PrivateMemorySize64 = 1,458,176 bytes (1.391 MiB)
  Single-Binary Mode ("zerovault_ui_egui_glow.exe --bench-tray"):
    Stdout: {"mode":"bench-tray","binary_role":"single_exe_tray_mode","closed_window_ui_process_rss_bytes":0,"tray_init_ms":1.785,"settle_duration_ms":400,"memory":{"working_set_bytes":10375168,"working_set_mib":9.895,"peak_working_set_bytes":10375168,"peak_working_set_mib":9.895,"private_usage_bytes":2072576,"private_usage_mib":1.977,"page_fault_count":2614}}
  ```

---

## 5. Architectural Rationale: Why `eframe/egui (glow)` Defeats `iced (tiny-skia)` and `Avalonia NativeAOT`

1. **Why Candidate A (`.NET 9 NativeAOT + Avalonia 12.1.6`) is Eliminated (#3):**
   - **7.28x larger distribution** (`37.247 MiB` across 4 files vs `5.115 MiB` single `.exe`).
   - **Exceeds 128 MiB RSS ceiling under load** (`142.28 MiB` Peak RSS, `144.36 MiB` Private Commit) with **`5.41 MiB/s` of managed GC heap allocation churn** during live 60fps streaming.
   - **Polyglot build & packaging debt:** Introduces `.NET 9 SDK`, MSBuild, NuGet restore, `ilc`, and 3 third-party C++ DLLs alongside a Pure Rust daemon/CLI workspace, duplicating IPC schemas across C# and Rust.
2. **Why `wgpu` Backends (`iced+wgpu` & `egui+wgpu`) are Vetoed (#4):**
   - On Windows 11, initializing DX12/Vulkan drivers + `naga` shader pipelines inflates binaries to `9.54–11.69 MiB`, cold launches to `474.5–546.4 ms` (`> 1.2s` uncached/probed), RSS to `165.0–307.7 MiB`, and Private Commit to `212.1–481.6 MiB`.
3. **Why Candidate B2 (`eframe 0.29.1 / egui + glow + tray-icon`) Defeats Runner-Up B1 (`iced 0.13.1 + tiny-skia`):**
   - **4.18x Lower User CPU & 4K HiDPI Scalability:** `iced (tiny-skia)` rasterizes every pixel on the CPU and copies full RGBA framebuffers via `softbuffer`, burning **`1,828.13 ms` user CPU** (`2,187.5 ms` total CPU = `43.8%` of a logical core) over 5 seconds at `1120x760`. On 4K `3840x2160` (`9.75x` pixel count), CPU rasterization hits severe thermal/frame-budget walls. Hardware-accelerated `egui (glow)` renders vector meshes via OpenGL/WGL (Windows) and Khronos EGL/Wayland (Arch Linux) in **`0.576 ms/frame`** (**`437.50 ms` user CPU over 5s**).
   - **True `0-Byte` Background RAM Neutralizes Open-Window RSS Gap:** Both `egui (glow)` (`96.55 MiB` Peak RSS) and `iced (tiny-skia)` (`42.34 MiB` Peak RSS) sit comfortably beneath ZeroVault's `128 MiB` ceiling while open, and **both drop to `0 bytes` (`0.000 MiB`) the instant the window closes**. Candidate B2 is the **only candidate** that delivered and empirically proved the complete closed-window tray architecture (`8.07 MiB` RSS / `1.39 MiB` Private Commit).
   - **Wave 2/3 Feature Velocity & Accessibility (`MERGER_PLAN.md` §2.5):** ZeroVault's production UI requires an **encrypted multiline note editor**, multi-cloud routing tables, conflict resolution dialogs, `zv://` capability URI builders, and `keybox.zv` PQ recipient stanza managers, plus **OS screen-reader accessibility (`AccessKit` / `uiautomationcore.dll` / AT-SPI)**. `eframe 0.29.1` ships built-in `AccessKit` and rich `TextEdit::multiline` / `Table` / modal widgets with zero Elm message boilerplate, compiling inside the single Pure Rust Cargo workspace on both Windows 10/11 and Arch Linux Wayland (`0` `webkit2gtk` dependencies).

### Mandatory Gate 1 Conditions for Wave 2 (`crates/zerovault-ui`)
1. Gate Windows Named Pipe / `K32GetProcessMemoryInfo` dependencies under `[target.'cfg(windows)'.dependencies]` and pair with Unix Domain Socket (`$XDG_RUNTIME_DIR/zerovault/zerovaultd.sock`) + `tray-icon` DBus `StatusNotifierItem` under `[target.'cfg(unix)'.dependencies]` for Arch Linux Wayland.
2. Keep `vsync: true` in interactive production mode and repaint strictly on input or incoming daemon telemetry events (`0.0%` idle CPU when open; **`0 bytes` UI surface RAM** when closed).
