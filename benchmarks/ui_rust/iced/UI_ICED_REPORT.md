# Wave 1 UI Silicon Bake-Off — Candidate B1: Pure Rust `iced` Native Desktop UI

- **Candidate ID:** `B1` (`zerovault-ui-iced`)
- **Framework:** `iced 0.13.1` (`iced_wgpu 0.13.5` GPU renderer + `iced_tiny_skia 0.13.0` SIMD software renderer ablation)
- **Crate Directory:** `<workspace>\benchmarks\ui_rust\iced`
- **Cargo Target Dir (`wgpu` Primary):** `<workspace>\target\swarm\bakeoff-ui-rust\iced`
- **Cargo Target Dir (`tiny-skia` Variant):** `<workspace>\target\swarm\bakeoff-ui-rust\iced-tiny-skia`
- **Raw JSON Telemetry:** `<workspace>\benchmarks\ui_rust\iced\ui_iced_results.json`
- **WebView2 / Browser Engine Dependency Count:** **`0` DLLs** (verified via MSVC `dumpbin.exe /dependents`)

---

## 1. Executive Summary & Empirical Findings

Candidate B1 implements the complete dark-themed **ZeroVault Status & Settings** desktop surface in pure safe Rust (`iced 0.13.1` + `tokio` Windows Named Pipes over `\\.\pipe\zerovault-bakeoff-iced`), compiled with `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, and `opt-level = 3` on `x86_64-pc-windows-msvc` (`rustc 1.94.1`).

Testing both `iced`'s GPU backend (`wgpu`) and `iced`'s pure-Rust SIMD software backend (`tiny-skia`) uncovered two major architectural findings on Windows 11 (`AMD Ryzen 9 7950X3D` + `NVIDIA GeForce RTX 4080 SUPER`):

1. **`wgpu` Backend Probing Overhead on Windows (`WGPU_BACKEND` Discovery):**
   - By default, `iced_wgpu` initializes `wgpu::Backends::all()`, simultaneously loading **Vulkan + Direct3D 12 + legacy OpenGL (`opengl32.dll` WGL)** user-mode drivers across all display adapters (including virtual display drivers). That stock probe costs **`812.2 ms` internal (`981.3 ms` external) p50 cold launch**.
   - Pinning `WGPU_BACKEND=vulkan` (or `dx12` fallback when `vulkan-1.dll` is absent) cuts GPU cold launch to **`461.6 ms` internal (`605.3 ms` external) p50** with **`150.3 MiB` RSS**, and achieves **`16.663 ms` p50 / `16.951 ms` p99 (`60.006 FPS`, 300/300 frames)** under live 60Hz Named Pipe IPC streaming at **`165.6 MiB` Peak RSS**.
2. **`iced` `tiny-skia` Feature Ablation (`--no-default-features --features cpu-tiny-skia`):**
   - Disabling `wgpu` in favor of `iced`'s `tiny-skia` + `softbuffer` backend eliminates all GPU driver initialization and shader compilation overhead:
     - **Clean `--release` compile time drops 63%:** **`39.68 s`** (vs `107.11 s` for `wgpu`).
     - **Stripped `.exe` size drops 61%:** **`3.710 MiB`** (`3,890,688 B` vs `9.544 MiB` for `wgpu`).
     - **Cold launch drops 71%:** **`131.8 ms` internal (`158.2 ms` external) p50** across 20 runs (`min 118.1 ms` internal / `141.0 ms` external).
     - **Memory footprint drops 75–92%:** **`33.2 MiB` cold RSS** (`16.1 MiB` `PrivateUsage`), and **`42.0 MiB` Peak RSS** (`17.7 MiB` `PrivateUsage`) after 300 live 60Hz frames while still maintaining **`16.667 ms` p50 / `17.037 ms` p99 (`59.999 FPS`)**!

### Headline Comparison Matrix

| Metric | `iced` + `wgpu(vulkan)` *(Primary GPU)* | `iced` + `wgpu(dx12)` *(DX12 GPU)* | `iced` + `wgpu(all)` *(Stock Unfiltered)* | `iced` + `tiny-skia` *(SIMD CPU Feature)* |
| :--- | :---: | :---: | :---: | :---: |
| **Clean `--release` Build** | `107.11 s` | `107.11 s` | `107.11 s` | **`39.68 s`** |
| **Incremental LTO Rebuild** | `38.17 s` | `38.17 s` | `38.17 s` | **`13.02 s`** |
| **Stripped `.exe` Size** | `9.544 MiB` (`10,008,064 B`) | `9.544 MiB` | `9.544 MiB` | **`3.710 MiB` (`3,890,688 B`)** |
| **WebView2 / Browser DLLs** | **`0`** | **`0`** | **`0`** | **`0`** |
| **Cold Launch Internal `ms` (min / p50 / p95 / max)** | `451.1 / 461.6 / 563.1 / 1051.4` | `520.5 / 538.0 / 656.0 / 1133.8` | `774.3 / 812.2 / 1257.0 / 1361.7` | **`118.1 / 131.8 / 144.6 / 148.0`** |
| **Cold Launch External `ms` (min / p50 / p95 / max)** | `593.9 / 605.3 / 708.6 / 1194.6` | `636.8 / 669.5 / 780.2 / 1257.4` | `933.7 / 981.3 / 1414.2 / 1515.0` | **`141.0 / 158.2 / 171.9 / 174.9`** |
| **Cold Active RSS (`WorkingSet` p50)** | `150.34 MiB` | `182.16 MiB` | `172.41 MiB` | **`33.22 MiB`** |
| **Cold Commit (`PrivateUsage` p50)** | `206.18 MiB` | `466.23 MiB` | `237.04 MiB` | **`16.07 MiB`** |
| **60Hz 5s Rendered Frames** | **`300 / 300` (`60.01 FPS`)** | **`300 / 300` (`60.06 FPS`)** | — | **`300 / 300` (`60.00 FPS`)** |
| **60Hz Frame Pacing `p50 / p95 / p99` (`ms`)** | **`16.663 / 16.882 / 16.951`** | **`16.667 / 16.777 / 16.885`** | — | **`16.667 / 16.799 / 17.037`** |
| **60Hz Peak Physical RSS (`MiB`)** | `165.56 MiB` | `191.91 MiB` | — | **`42.03 MiB`** |
| **60Hz Active Physical RSS (`MiB`)** | `165.56 MiB` | `191.91 MiB` | — | **`42.03 MiB`** |
| **60Hz Commit (`PrivateUsage` `MiB`)** | `211.09 MiB` | `472.70 MiB` | — | **`17.72 MiB`** |

---

## 2. Testbed Environment & Build Configuration

- **OS:** Microsoft Windows 11 (`10.0.26300.0`)
- **CPU:** AMD Ryzen 9 7950X3D 16-Core Processor (`32` logical threads)
- **GPU:** NVIDIA GeForce RTX 4080 SUPER (`Driver 32.0.16.2101`) + Meta Virtual Monitor (`5.3.57.114`)
- **System Memory:** `31.6 GiB` DDR5
- **Toolchain:** `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1 (29ea6fb6a 2026-03-24)` (`x86_64-pc-windows-msvc`)
- **Release Profile (`Cargo.toml`):**
  ```toml
  [profile.release]
  lto = "thin"
  codegen-units = 1
  strip = "symbols"
  opt-level = 3
  ```

---

## 3. UI Functional Surface & Deterministic IPC Instrumentation

### Implemented Desktop UI Surface (`1120x760` Dark TokyoNight Surface)
All required ZeroVault panels are active and rendered simultaneously on frame 1 in the default **Unified Dashboard** view (with interactive view-filtering tabs for `Unified Dashboard`, `Live Transfer Meter`, and `Vault Settings`):

1. **Header & Cryptographic Status Bar:**
   - Interactive **Vault Lock/Unlock Status Badge** (`● VAULT UNLOCKED` emerald pill / `● VAULT LOCKED` crimson pill)
   - **Active Mount Badge:** `MOUNT: Z:\ZeroVault` (transitions to `MOUNT: OFFLINE (SEALED)` when locked)
   - **Post-Quantum + Hardware AEAD Encryption Badge:** `AES-256-GCM VAES + ML-KEM-768`
2. **Live 60Hz Transfer Telemetry Panel:**
   - Upload (`▲ ENCRYPTED UPLOAD MiB/s`) and Download (`▼ DECRYPTED DOWNLOAD MiB/s`) throughput readouts and styled progress bars
   - AEAD Chunk Pipeline progress bar (`0–100%`), live `Active Chunks` counter, and IPC sequence counter (`Seq #N`)
   - **Custom 60Hz GPU `canvas::Program` (`ThroughputWaveform`):** Dual-series rolling 120-sample upload/download waveform tessellated via `lyon` (`iced_wgpu`) or rasterized via `tiny-skia`
3. **3-Provider Multi-Cloud Quota Cards:**
   - **Google Drive** (`TLS 1.3 • Chunk Shard A`, used/total GiB + progress bar)
   - **Microsoft OneDrive** (`TLS 1.3 • Chunk Shard B`, used/total GiB + progress bar)
   - **Amazon S3** (`eu-central-1 • Chunk Shard C`, used/total GiB + progress bar)
4. **Vault Security & Routing Settings Section:**
   - **Routing Policy Selector:** Interactive `pick_list` dropdown + quick-select pill buttons (`Targeted`, `Mirrored RAID-1`, `Quota-Pooled`)
   - **Local Encrypted NVMe Cache Limit Slider:** Interactive `1.0 ..= 64.0 GiB` `slider` (`16.0 GiB` default)
   - **Lock / Unlock Vault Button:** Interactive keyring zeroization toggle

### Zero-Cheat Frame & IPC Measurement Architecture
- **Windows Named Pipe Client:** Connects via `tokio::net::windows::named_pipe::ClientOptions` to `\\.\pipe\zerovault-bakeoff-iced` (overrideable via `--pipe <PATH>`), parsing newline-delimited JSON frames (`{"seq":N,"up_mib_s":...,"down_mib_s":...,"progress":...,"active_chunks":...}`).
- **Embedded High-Resolution Win32 Pipe Harness (`--mock-server`):** Calls `CreateNamedPipeW` synchronously in the kernel namespace before spawning a dedicated producer thread backed by Win32 `CreateWaitableTimerExW(..., CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, ...)` + sub-millisecond spin completion for sub-10µs `16.6667 ms` (60.000 Hz) emission accuracy without Windows' default `15.625 ms` sleep quantum jitter. Also probes `WaitNamedPipeW` (without consuming external single-client pipes) to seamlessly interoperate with external `Agent-Judge` servers.
- **Post-Present GPU Completion Gate:** Frame draw timestamps are captured inside `ThroughputWaveform::draw()` (invoked inside `iced_winit`'s `WindowEvent::RedrawRequested` pass immediately prior to `compositor.present()`), and exit in `--bench-cold` / `--bench-60fps` waits for the subsequent `window::frames()` post-present wakeup after `last_recorded_seq >= required_seq`, guaranteeing `compositor.present()` has completed on the visible OS swapchain before querying `K32GetProcessMemoryInfo`.

---

## 4. Binary Size & MSVC `dumpbin.exe /dependents` Audit

### 4.1 Primary GPU Binary (`wgpu`)
- **Binary:** `<workspace>\target\swarm\bakeoff-ui-rust\iced\release\zerovault-ui-iced.exe`
- **Exact Size:** `10,008,064 bytes` (**`9.544 MiB`**)
- **SHA-256:** `F0A63FF6B470D2D81202A3A65E43239AF5C7BDF841C1A615BF0E569EA3959053`
- **WebView2 / Browser DLLs:** **`0`**

```text
Dump of file <workspace>\target\swarm\bakeoff-ui-rust\iced\release\zerovault-ui-iced.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    KERNEL32.dll
    advapi32.dll
    api-ms-win-core-synch-l1-2-0.dll
    ntdll.dll
    oleaut32.dll
    bcryptprimitives.dll
    USER32.dll
    SHELL32.dll
    GDI32.dll
    opengl32.dll
    d3dcompiler_47.dll
    ole32.dll
    dwmapi.dll
    imm32.dll
    uxtheme.dll
    VCRUNTIME140.dll
    api-ms-win-crt-math-l1-1-0.dll
    api-ms-win-crt-string-l1-1-0.dll
    api-ms-win-crt-runtime-l1-1-0.dll
    api-ms-win-crt-stdio-l1-1-0.dll
    api-ms-win-crt-locale-l1-1-0.dll
    api-ms-win-crt-heap-l1-1-0.dll

  Summary

        4000 .data
       3C000 .pdata
      1F1000 .rdata
        8000 .reloc
      754000 .text
```

### 4.2 Feature Variant Binary (`tiny-skia`)
- **Binary:** `<workspace>\target\swarm\bakeoff-ui-rust\iced-tiny-skia\release\zerovault-ui-iced.exe`
- **Exact Size:** `3,890,688 bytes` (**`3.710 MiB`**)
- **SHA-256:** `D257362D33DBB8878648A443774EF1A7E68FF561DB7445A8EB72D4DBB4222FB9`
- **WebView2 / Browser DLLs:** **`0`** (also zero `d3dcompiler_47.dll` / `opengl32.dll` imports)

---

## 5. Cold Launch Benchmark (`--bench-cold`, 20 Runs Each)

### 5.1 Summary Percentiles Across 20 Cold Launches

| Backend Variant | Metric | Min | p50 | p95 | Max | Mean |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`wgpu(vulkan)` (Primary GPU, N=20)** | External Wall-Clock (`ms`) | `593.928` | **`605.346`** | `708.603` | `1194.608` | `640.990` |
| *(First post-link Defender scan: `1472.3 ms` ext)* | Internal Interactive (`ms`) | `451.087` | **`461.636`** | `563.098` | `1051.410` | `496.811` |
| | `WorkingSetSize` (`MiB`) | `149.141` | **`150.344`** | `152.202` | `152.617` | `150.344` |
| | `PeakWorkingSetSize` (`MiB`) | `149.141` | **`150.344`** | `152.202` | `152.617` | `150.344` |
| | `PrivateUsage` (`MiB`) | `204.891` | **`206.176`** | `207.010` | `207.273` | `206.047` |
| **`wgpu(dx12)` (DX12 GPU, N=20)** | External Wall-Clock (`ms`) | `636.800` | **`669.514`** | `780.218` | `1257.445` | `704.190` |
| | Internal Interactive (`ms`) | `520.512` | **`537.996`** | `655.997` | `1133.849` | `571.483` |
| | `WorkingSetSize` (`MiB`) | `180.363` | **`182.156`** | `183.427` | `184.258` | `182.339` |
| | `PeakWorkingSetSize` (`MiB`) | `181.484` | **`183.074`** | `184.444` | `185.316` | `183.188` |
| | `PrivateUsage` (`MiB`) | `465.215` | **`466.230`** | `466.803` | `467.301` | `466.132` |
| **`tiny-skia` (SIMD CPU Feature, N=20)** | External Wall-Clock (`ms`) | `141.006` | **`158.166`** | `171.912` | `174.904` | `157.862` |
| *(First post-link Defender scan: `219.8 ms` ext)* | Internal Interactive (`ms`) | `118.124` | **`131.829`** | `144.557` | `148.033` | `131.547` |
| | `WorkingSetSize` (`MiB`) | `31.023` | **`33.216`** | `35.845` | `35.934` | `33.612` |
| | `PeakWorkingSetSize` (`MiB`) | `31.023` | **`33.216`** | `35.845` | `35.934` | `33.612` |
| | `PrivateUsage` (`MiB`) | `15.777` | **`16.074`** | `16.831` | `16.887` | `16.224` |

### 5.2 Raw 20-Run Cold Launch Log — Primary `wgpu(vulkan)` GPU Binary

| Run | External Wall (`ms`) | Internal Interactive (`ms`) | Window Open (`ms`) | First GPU Draw (`ms`) | First IPC Msg (`ms`) | WorkingSet (`MiB`) | Peak RSS (`MiB`) | PrivateUsage (`MiB`) |
| :-: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `625.922` | `481.206` | `479.996` | `467.150` | `9.762` | `150.371` | `150.371` | `206.395` |
| 2 | `598.670` | `454.162` | `452.933` | `439.277` | `9.548` | `150.129` | `150.129` | `205.035` |
| 3 | `598.828` | `455.841` | `454.706` | `441.273` | `8.437` | `150.645` | `150.645` | `205.285` |
| 4 | `606.225` | `463.950` | `462.876` | `449.653` | `8.375` | `150.461` | `150.461` | `206.891` |
| 5 | `632.798` | `485.244` | `483.957` | `469.588` | `8.045` | `150.359` | `150.359` | `206.566` |
| 6 | `604.466` | `459.323` | `458.163` | `444.538` | `8.147` | `150.488` | `150.488` | `205.113` |
| 7 | `610.247` | `467.019` | `465.876` | `452.579` | `8.127` | `150.207` | `150.207` | `205.656` |
| 8 | `622.959` | `475.384` | `473.953` | `458.993` | `8.681` | `152.617` | `152.617` | `207.273` |
| 9 | `623.423` | `477.989` | `476.807` | `463.592` | `9.523` | `149.984` | `149.984` | `205.805` |
| 10 | `601.605` | `458.885` | `457.839` | `444.839` | `8.522` | `149.332` | `149.332` | `206.875` |
| 11 | `593.928` | `451.087` | `449.941` | `436.942` | `7.945` | `150.527` | `150.527` | `205.730` |
| 12 | `609.561` | `466.042` | `464.935` | `451.639` | `8.095` | `150.578` | `150.578` | `206.543` |
| 13 | `596.462` | `453.068` | `451.929` | `438.919` | `8.146` | `149.141` | `149.141` | `205.051` |
| 14 | `683.024` | `537.397` | `535.878` | `521.314` | `8.844` | `150.328` | `150.328` | `206.387` |
| 15 | `1194.608` | `1051.410` | `1050.401` | `1037.340` | `8.042` | `149.555` | `149.555` | `206.605` |
| 16 | `623.723` | `476.883` | `475.640` | `461.464` | `8.298` | `152.180` | `152.180` | `205.965` |
| 17 | `600.561` | `457.373` | `456.270` | `442.842` | `8.526` | `150.516` | `150.516` | `206.996` |
| 18 | `595.381` | `452.439` | `451.367` | `438.631` | `8.131` | `149.199` | `149.199` | `205.285` |
| 19 | `598.633` | `455.025` | `453.930` | `441.162` | `8.179` | `150.273` | `150.273` | `204.891` |
| 20 | `598.778` | `456.497` | `455.321` | `442.067` | `8.009` | `149.996` | `149.996` | `206.602` |

*(Full raw 20-run tables for `wgpu(dx12)`, `wgpu(all)`, and `tiny-skia` are stored in `ui_iced_results.json`.)*

---

## 6. Sustained 60Hz Live Named Pipe Transfer-Meter Benchmark (`--bench-60fps`)

Streams **300 live JSON telemetry frames** at `60.00 Hz` (`16.6667 ms` period) over `\\.\pipe\zerovault-bakeoff-iced` for `5.0 seconds`, redrawing upload/download throughput meters, progress bars, multi-cloud quota cards, and the 120-sample waveform canvas each frame:

| Metric | `wgpu(vulkan)` *(Primary GPU)* | `wgpu(dx12)` *(DX12 GPU)* | `tiny-skia` *(SIMD CPU)* |
| :--- | :---: | :---: | :---: |
| **IPC Frames Received** | `300` | `300` | `300` |
| **Rendered Swapchain Frames** | **`300`** (`0` dropped) | **`300`** (`0` dropped) | **`300`** (`0` dropped) |
| **Stream Elapsed (`ms`)** | `4982.866` | `4978.229` | `4983.453` |
| **Effective FPS** | **`60.006`** | **`60.062`** | **`59.999`** |
| **Frame Time Min (`ms`)** | `16.189` | `11.537` | `13.812` |
| **Frame Time p50 (`ms`)** | **`16.663`** | **`16.667`** | **`16.667`** |
| **Frame Time p95 (`ms`)** | **`16.882`** | **`16.777`** | **`16.799`** |
| **Frame Time p99 (`ms`)** | **`16.951`** | **`16.885`** | **`17.037`** |
| **Frame Time Max (`ms`)** | `17.019` | `17.104` | `19.528` |
| **Frame Time Mean (`ms`)** | `16.665` | `16.650` | `16.667` |
| **Active Physical RSS (`WorkingSetSize`)** | `165.563 MiB` (`173,604,864 B`) | `191.914 MiB` (`201,236,480 B`) | **`42.027 MiB`** (`44,068,864 B`) |
| **Peak Physical RSS (`PeakWorkingSetSize`)** | `165.563 MiB` (`173,604,864 B`) | `191.914 MiB` (`201,236,480 B`) | **`42.027 MiB`** (`44,068,864 B`) |
| **Private Commit (`PrivateUsage`)** | `211.090 MiB` (`221,343,744 B`) | `472.699 MiB` (`495,661,056 B`) | **`17.719 MiB`** (`18,579,456 B`) |

---

## 7. Reproducible Commands for `Agent-Judge`

### Build Standalone `--release` Binaries
```powershell
Set-Location "<workspace>\benchmarks\ui_rust\iced"

# Primary Candidate B1: Pure Rust iced + wgpu GPU backend
$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\bakeoff-ui-rust\iced"
cargo build --release

# Optional Ablation: Pure Rust iced + tiny-skia SIMD backend
$env:CARGO_TARGET_DIR = "<workspace>\target\swarm\bakeoff-ui-rust\iced-tiny-skia"
cargo build --release --no-default-features --features cpu-tiny-skia
```

### Single-Command Deterministic Benchmarks
```powershell
$Exe = "<workspace>\target\swarm\bakeoff-ui-rust\iced\release\zerovault-ui-iced.exe"

# 1. Cold Launch Benchmark (opens visible window + connects Named Pipe + renders frame 1 + prints JSON + exits 0)
& $Exe --bench-cold --mock-server

# 2. Live 60Hz 5.0-Second (300-Frame) Transfer-Meter IPC Benchmark
& $Exe --bench-60fps --mock-server

# 3. Verify Zero WebView2 / Browser DLLs
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe" /dependents $Exe

# 4. Full Automated Multi-Run Suite (regenerates ui_iced_results.json)
powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\benchmarks\ui_rust\iced\run_benchmarks.ps1"
```
