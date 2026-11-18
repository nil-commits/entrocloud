# Wave 1 UI Silicon Bake-Off — Candidate A: `.NET 9 NativeAOT + Avalonia 12.1.6`

## 1. Executive Summary

| Metric | Empirical Measurement |
| :--- | :--- |
| **Toolchain & SDK** | `.NET SDK 9.0.320` (Runtime `.NET 9.0.22`) + MSVC `14.44.35207` (`ilc` + `link.exe`) |
| **Avalonia NuGet Version** | **`12.1.6`** (`12.1.6.0`, latest stable on NuGet; ships `net8.0` + `net10.0` assets, fully NativeAOT-compatible on `net9.0`) |
| **WebView2 / Browser DLLs** | **`0`** (verified via `dumpbin.exe /dependents` and publish manifest; pure Skia + ANGLE Direct3D11) |
| **Stripped NativeAOT `.exe` Size** | **`19.281 MiB`** (`20,217,344` bytes) |
| **Total Publish Directory Size** | **`37.247 MiB`** (`39,056,424` bytes across 4 files: `.exe` + Skia + ANGLE + HarfBuzz) |
| **Cold Start — Internal First-Frame + IPC (20 runs)** | **min `238.75 ms` / p50 `245.24 ms` / p95 `315.43 ms` / max `1214.16 ms`** *(Runs 2–20 max: `268.13 ms`; Run 1 includes Windows Defender first-seen PE hash scan)* |
| **Cold Start — External Launcher Wall-Clock (20 runs)** | **min `290.70 ms` / p50 `300.76 ms` / p95 `372.22 ms` / max `1268.64 ms`** |
| **Cold Start Memory (First Rendered IPC Frame)** | **`WorkingSet64` p50: `80.30 MiB`** (`PrivateMemorySize64` p50: `76.18 MiB`) |
| **60 FPS 5.0s Stream — UI Render Latency (300 frames)** | **p50 `0.214 ms` / p95 `0.842 ms` / p99 `5.197 ms` / max `16.588 ms`** (`0` render overruns > `16.67 ms`) |
| **60 FPS 5.0s Stream — Inter-Frame Cadence Delta** | **p50 `16.661 ms` / p95 `17.004 ms` / p99 `19.104 ms` / max `33.088 ms`** (`59.82 FPS`, `2` frames > `25 ms`) |
| **60 FPS 5.0s Stream — Peak RSS / Active WorkingSet** | **`PeakWorkingSet64`: `142.102 MiB` / Active `WorkingSet64`: `142.102 MiB`** (`0` Gen0/Gen1/Gen2 GC pauses) |

---

## 2. Host Silicon & Avalonia Version Verification

### Hardware & OS Environment
- **OS:** Microsoft Windows `10.0.26300` (`win-x64`)
- **CPU:** AMD Ryzen 9 7950X3D 16-Core Processor (32 logical threads, 31.6 GiB physical RAM)
- **GPU & Display:** NVIDIA GeForce RTX 4080 SUPER (`2560 x 1440 @ 540 Hz` refresh rate)
- **Compiler Toolchain:**
  - `dotnet --version`: `9.0.320` (MSBuild `17.14.60+43b635718`, Host/Runtime `9.0.22`)
  - NativeAOT Linker & COFF Inspector: MSVC `14.44.35207` (`C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe` & `dumpbin.exe`)

### Empirical NuGet Investigation (`Avalonia 11.3.x` vs `12.x`)
1. **Local Host Cache Check:** `C:\Users\User\.nuget\packages\avalonia` contained pre-cached versions `11.1.3` and `11.3.22`.
2. **Live NuGet v3 Index Query (`https://api.nuget.org/v3-flatcontainer/avalonia/index.json`):**
   - Returned `166` published versions.
   - Latest `11.3.x` patch: `11.3.23` (`net6.0`, `net8.0`, `.NETStandard2.0`).
   - Latest stable `12.x` release: **`12.1.6`** (`12.0.0` through `12.1.6` are published stable on NuGet).
3. **TFM Compatibility Proof:** Inspecting the `.nuspec` dependency groups of `Avalonia`, `Avalonia.Desktop`, `Avalonia.Themes.Fluent`, `Avalonia.Fonts.Inter`, `Avalonia.Win32`, and `Avalonia.Skia` at version **`12.1.6`** confirmed every package ships multi-targeted **`net10.0` and `net8.0`** asset groups. Under `.NET SDK 9.0.320` (`<TargetFramework>net9.0</TargetFramework>`), NuGet resolves the `net8.0` asset group cleanly and `ilc.exe` + `link.exe` compile **`Avalonia 12.1.6`** into a standalone `win-x64` NativeAOT PE executable with **0 compiler warnings, 0 XAML binding warnings, and 0 IL trim/AOT warnings**.
4. **Strict Write-Scope Isolation:** `Directory.Build.props` and `nuget.config` pin `BaseIntermediateOutputPath`, `BaseOutputPath`, `PublishDir`, and NuGet `globalPackagesFolder` into `target\swarm\bakeoff-ui-dotnet\**` while referencing `C:\Users\User\.nuget\packages` strictly as a read-only `RestoreFallbackFolders` source.

---

## 3. NativeAOT Configuration, Functional UI & Named Pipe IPC

### Zero-Reflection NativeAOT Flags (`ZeroVaultUi.csproj`)
- `<PublishAot>true</PublishAot>`
- `<AvaloniaUseCompiledBindingsByDefault>true</AvaloniaUseCompiledBindingsByDefault>`
- `<InvariantGlobalization>true</InvariantGlobalization>`
- `<StripSymbols>true</StripSymbols>`, `<DebugType>none</DebugType>`, `<DebugSymbols>false</DebugSymbols>`
- `<BuiltInComInteropSupport>false</BuiltInComInteropSupport>` (Avalonia Win32 uses MicroCom vtables)
- `<JsonSerializerIsReflectionEnabledByDefault>false</JsonSerializerIsReflectionEnabledByDefault>` (all IPC and benchmark JSON serialized via source-generated `BakeoffJsonContext`)
- `x:CompileBindings="True"` and explicit `x:DataType` across `MainWindow.axaml` and item `DataTemplate`s.

### Functional Desktop Surface (Zero WebView2)
`Views/MainWindow.axaml` renders a dark-themed (`#0B0F19` / `#111827`) **ZeroVault Status & Settings** desktop window with all sections visible simultaneously in the viewport (no hidden off-tab widgets during benchmarks):
- **Header Status Bar:** Interactive Vault Lock/Unlock status badge (`● VAULT UNLOCKED` / `■ VAULT LOCKED`), active mount path badge (`Z:\ZeroVault`), and post-quantum cipher suite badge (`AES-256-GCM VAES + ML-KEM-768`).
- **Live Transfer Meter Panel:** Encrypted Upload (`MiB/s` + `ProgressBar`), Authenticated Download (`MiB/s` + `ProgressBar`), Active Merkle Tree Commit `ProgressBar`, in-flight AEAD chunk counter badge, and frame sequence counter.
- **3-Provider Multi-Cloud Quota Cards:** Live usage (`GiB`), percentage `ProgressBar`s, and per-shard upload/download stripe rates for **Google Drive**, **Microsoft OneDrive**, and **Amazon S3**.
- **Vault Policy & Settings Panel:** Multi-Cloud Routing Policy `ComboBox` (`Targeted`, `Mirrored RAID-1`, `Quota-Pooled`) with dynamic policy description, Encrypted Staging Cache Limit `Slider` (`1–64 GiB`), and interactive `Lock Vault & Zeroize Keys` button.

### Windows Named Pipe IPC (`\\.\pipe\zerovault-bakeoff-dotnet`)
- Connects via asynchronous `NamedPipeClientStream` receiving newline-delimited UTF-8 JSON frames:
  `{"seq":1,"up_mib_s":193.54,"down_mib_s":579.61,"progress":0.0033,"active_chunks":17}`
- Includes a built-in `--mock-server` mode using Win32 `CreateWaitableTimerExW(..., CREATE_WAITABLE_TIMER_HIGH_RESOLUTION)` + `Stopwatch` absolute deadline scheduling to avoid Windows' 15.625 ms coarse sleep granularity and emit deterministic 60.00 Hz (`16.667 ms`) IPC frames.
- If `--bench-cold` or `--bench-60fps` is invoked when no external `--mock-server` is listening on the pipe, the binary automatically spawns an embedded kernel `NamedPipeServerStream` fallback on `\\.\pipe\zerovault-bakeoff-dotnet` so single-command execution always works out of the box.

---

## 4. Binary Size & `dumpbin.exe /dependents` Verification

### Published Runtime File Manifest (`target\swarm\bakeoff-ui-dotnet\publish`)

| File | Role | Size (Bytes) | Size (MiB) |
| :--- | :--- | ---: | ---: |
| `ZeroVaultUi.exe` | Stripped NativeAOT x64 PE executable (App + .NET 9 AOT runtime + Avalonia 12.1.6) | `20,217,344` | **`19.281 MiB`** |
| `libSkiaSharp.dll` | Skia 2D/GPU raster & Ganesh backend | `11,628,896` | `11.090 MiB` |
| `av_libglesv2.dll` | ANGLE OpenGL ES -> Direct3D 11 translation layer | `5,394,096` | `5.144 MiB` |
| `libHarfBuzzSharp.dll` | HarfBuzz OpenType text shaping engine | `1,816,088` | `1.732 MiB` |
| **Total (4 files)** | **Complete standalone NativeAOT deployment** | **`39,056,424`** | **`37.247 MiB`** |

### `dumpbin.exe /dependents ZeroVaultUi.exe` Output
```text
Dump of file <workspace>\target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    ADVAPI32.dll
    bcrypt.dll
    KERNEL32.dll
    ole32.dll
    OLEAUT32.dll
    api-ms-win-crt-math-l1-1-0.dll
    api-ms-win-crt-heap-l1-1-0.dll
    api-ms-win-crt-string-l1-1-0.dll
    api-ms-win-crt-convert-l1-1-0.dll
    api-ms-win-crt-runtime-l1-1-0.dll
    api-ms-win-crt-stdio-l1-1-0.dll
    api-ms-win-crt-locale-l1-1-0.dll
```
**Verification:** `0` WebView2 (`WebView2Loader.dll`, `msedgewebview2.exe`), `0` CefSharp (`libcef.dll`), `0` HTML/browser engines, and `0` JIT CLR (`mscoree.dll` / `hostfxr.dll`) dependencies.

---

## 5. Benchmark 1: 20 Cold Launches (`--bench-cold`)

Each iteration launches a fresh `ZeroVaultUi.exe --bench-cold` process connecting over `\\.\pipe\zerovault-bakeoff-dotnet` to an external `--mock-server` daemon, opens the real visible `1080x740` Avalonia Win32/ANGLE window, receives and deserializes IPC frame `seq=1`, updates all ViewModel compiled bindings, executes a full layout + GPU render frame via `TopLevel.RequestAnimationFrame`, queries `Process.GetCurrentProcess()`, emits JSON telemetry, and exits cleanly (`0`).

### Cold-Launch Statistical Summary (All 20 Runs Included)

| Metric | Min | Median (p50) | p95 | Max | Mean |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Internal `Main()` -> First Rendered IPC Frame (`ms`)** | **`238.748`** | **`245.242`** | **`315.434`** | `1214.162`* | `294.700` |
| **External Launcher `CreateProcess` -> Exit (`ms`)** | **`290.698`** | **`300.762`** | **`372.221`** | `1268.636`* | `350.592` |
| **First-Frame `WorkingSet64` (`MiB`)** | `79.918` | **`80.301`** | `80.484` | `80.488` | `80.273` |
| **First-Frame `PrivateMemorySize64` (`MiB`)** | `75.340` | **`76.176`** | `76.726` | `76.777` | `76.093` |

*\*Note on Run 1 (`1214.16 ms`): Run 1 was executed immediately (`< 1s`) after `link.exe` produced a brand-new unsigned PE binary hash, capturing Windows Defender (`MsMpEng.exe`) synchronous first-execution scan + initial Direct3D11 shader cache creation. Across Runs 2–20, internal first-rendered-IPC-frame latency stayed tightly bounded between **`238.75 ms` and `268.13 ms`**.*

### Raw 20-Run Cold Telemetry Table

| Run | Internal First-Frame + IPC (`ms`) | `OnOpened` (`ms`) | First IPC Recv (`ms`) | External Wall (`ms`) | `WorkingSet64` (`MiB`) | `PrivateMemory` (`MiB`) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | `1214.162` | `1213.046` | `1173.362` | `1268.636` | `79.918` | `76.668` |
| 2 | `249.972` | `248.561` | `231.403` | `304.611` | `80.102` | `76.152` |
| 3 | `238.748` | `237.600` | `221.843` | `292.731` | `80.359` | `76.418` |
| 4 | `240.657` | `239.501` | `222.762` | `295.516` | `80.488` | `76.777` |
| 5 | `239.868` | `238.761` | `222.736` | `293.998` | `80.145` | `76.172` |
| 6 | `240.520` | `239.342` | `223.140` | `295.501` | `80.445` | `75.531` |
| 7 | `240.625` | `239.483` | `223.496` | `295.248` | `80.355` | `76.605` |
| 8 | `248.801` | `247.256` | `230.100` | `304.868` | `80.137` | `76.012` |
| 9 | `239.522` | `238.387` | `222.160` | `292.661` | `80.238` | `75.453` |
| 10 | `242.483` | `241.334` | `224.886` | `295.112` | `80.191` | `75.340` |
| 11 | `246.045` | `244.716` | `227.035` | `301.800` | `80.371` | `76.590` |
| 12 | `239.729` | `238.610` | `222.144` | `293.669` | `80.484` | `76.723` |
| 13 | `247.587` | `246.481` | `230.013` | `304.048` | `80.477` | `76.633` |
| 14 | `258.795` | `257.506` | `240.642` | `317.111` | `80.395` | `76.574` |
| 15 | `244.440` | `243.266` | `226.431` | `299.724` | `80.305` | `75.398` |
| 16 | `248.321` | `247.263` | `232.026` | `309.411` | `80.004` | `76.180` |
| 17 | `246.676` | `245.282` | `226.087` | `312.076` | `80.207` | `75.398` |
| 18 | `259.715` | `258.366` | `239.983` | `319.378` | `80.297` | `75.410` |
| 19 | `239.192` | `238.076` | `221.930` | `290.698` | `80.180` | `76.336` |
| 20 | `268.132` | `266.923` | `248.997` | `325.041` | `80.348` | `75.473` |

---

## 6. Benchmark 2: 60 FPS 5.0-Second Live IPC Stream (`--bench-60fps`)

Connected to external `--mock-server` over `\\.\pipe\zerovault-bakeoff-dotnet` streaming 60 updates/sec for 5.0 seconds (`300` rendered GPU frames, updating 6 `ProgressBar`s and 12 live throughput/quota `TextBlock`s every frame):

| Metric | Value | Notes |
| :--- | ---: | :--- |
| **Rendered Frames / Target Frames** | `300 / 300` | `305` IPC packets received across `4,997.964 ms` |
| **Effective Stream Frame Rate** | **`59.82 FPS`** | `299` inter-frame intervals over `4.998 s` |
| **UI Render Latency (IPC -> GPU Frame Callback)** | **min `0.104 ms` / p50 `0.214 ms` / p95 `0.842 ms` / p99 `5.197 ms` / max `16.588 ms`** | **`0` frames exceeded the `16.67 ms` 60 FPS render budget** |
| **Inter-Frame Cadence Delta (`t[i] - t[i-1]`)** | **min `5.620 ms` / p50 `16.661 ms` / p95 `17.004 ms` / p99 `19.104 ms` / max `33.088 ms`** | Mean `16.716 ms` (`139/299` intervals > `16.67 ms` due to normal ±0.2 ms oscillation around `16.667 ms` mean; **`2/299` missed VSyncs > `25.0 ms`**) |
| **Peak Physical RSS (`PeakWorkingSet64`)** | **`142.102 MiB`** | `149,004,288` bytes |
| **Active Working Set (`WorkingSet64`)** | **`142.102 MiB`** | `149,004,288` bytes |
| **Private Commit (`PrivateMemorySize64`)** | **`146.203 MiB`** | `153,305,088` bytes |
| **GC Activity During 300-Frame Stream** | **`0` Gen0 / `0` Gen1 / `0` Gen2** | `26.81 MiB` (`~91.5 KiB/frame`) allocated in Gen0 nursery from Skia/HarfBuzz text shaping & display lists without triggering any GC pause |

---

## 7. Reproducible Commands for `Agent-Judge`

### One-Command Full Build + 20-Cold + 60-FPS Benchmark Suite
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<workspace>\benchmarks\ui_dotnet\run_benchmarks.ps1" -Rebuild
```

### Direct Individual CLI Invocations
```powershell
# 1. NativeAOT Release Publish (outputs to target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe)
cd "<workspace>\benchmarks\ui_dotnet"
dotnet publish -c Release -r win-x64

# 2. Single Self-Contained Cold-Start Benchmark (auto-starts pipe if no external server is running)
& "<workspace>\target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe" --bench-cold

# 3. Single Self-Contained 60 FPS 5-Second (300-Frame) Live IPC Benchmark
& "<workspace>\target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe" --bench-60fps

# 4. Explicit External Mock IPC Server + Client Pair
$exe = "<workspace>\target\swarm\bakeoff-ui-dotnet\publish\ZeroVaultUi.exe"
$srv = Start-Process $exe -ArgumentList "--mock-server --pipe zerovault-bakeoff-dotnet --hz 60 --frames 350" -PassThru -WindowStyle Hidden
& $exe --bench-60fps --pipe zerovault-bakeoff-dotnet
Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue

# 5. Verify Zero WebView2 / Browser Dependencies
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe" /dependents $exe
```
