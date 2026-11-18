$ErrorActionPreference = "Stop"

$CrateDir = "<workspace>\benchmarks\ui_rust\iced"
$WgpuExe = "<workspace>\target\swarm\bakeoff-ui-rust\iced\release\zerovault-ui-iced.exe"
$TinySkiaExe = "<workspace>\target\swarm\bakeoff-ui-rust\iced-tiny-skia\release\zerovault-ui-iced.exe"
$DumpbinExe = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
$JsonOutPath = Join-Path $CrateDir "ui_iced_results.json"

function Get-Percentile {
    param(
        [double[]]$Values,
        [double]$Percent
    )
    if ($Values.Count -eq 0) { return 0.0 }
    $sorted = $Values | Sort-Object
    if ($sorted.Count -eq 1) { return [math]::Round([double]$sorted[0], 3) }
    $rank = ($Percent / 100.0) * ($sorted.Count - 1)
    $lo = [math]::Floor($rank)
    $hi = [math]::Ceiling($rank)
    $frac = $rank - $lo
    $val = [double]$sorted[$lo] + ([double]$sorted[$hi] - [double]$sorted[$lo]) * $frac
    return [math]::Round($val, 3)
}

function Get-DistributionStats {
    param([double[]]$Values)
    $sorted = $Values | Sort-Object
    $avg = ($sorted | Measure-Object -Average).Average
    return [ordered]@{
        count = $sorted.Count
        min   = [math]::Round([double]$sorted[0], 3)
        p50   = Get-Percentile -Values $sorted -Percent 50
        p95   = Get-Percentile -Values $sorted -Percent 95
        max   = [math]::Round([double]$sorted[-1], 3)
        mean  = [math]::Round([double]$avg, 3)
    }
}

function Inspect-Binary {
    param([string]$ExePath)
    $item = Get-Item $ExePath
    $hash = (Get-FileHash -Algorithm SHA256 -Path $ExePath).Hash
    $rawDump = (& $DumpbinExe /dependents $ExePath) -join "`n"
    $dlls = @()
    foreach ($line in ($rawDump -split "`r?`n")) {
        if ($line -match "^\s+([A-Za-z0-9_\-\.]+\.dll)\s*$") {
            $dlls += $Matches[1]
        }
    }
    $webviewDlls = $dlls | Where-Object { $_ -match "webview|msedge|cef|blink|webkit|wry" }
    return [ordered]@{
        path               = $ExePath
        size_bytes         = $item.Length
        size_mib           = [math]::Round($item.Length / 1MB, 3)
        sha256             = $hash
        dependent_dlls     = $dlls
        webview_dll_count  = @($webviewDlls).Count
        dumpbin_raw        = $rawDump
    }
}

function Invoke-ColdSeries {
    param(
        [string]$ExePath,
        [int]$Runs,
        [string[]]$ExtraArgs = @()
    )
    # Initial post-link OS Defender scan warmup captured separately
    $swWarm = [System.Diagnostics.Stopwatch]::StartNew()
    $warmJsonRaw = & $ExePath --bench-cold --mock-server @ExtraArgs
    $swWarm.Stop()
    $warmParsed = $warmJsonRaw | ConvertFrom-Json

    $samples = @()
    for ($i = 1; $i -le $Runs; $i++) {
        Start-Sleep -Milliseconds 80
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $outRaw = & $ExePath --bench-cold --mock-server @ExtraArgs
        $sw.Stop()
        if ($LASTEXITCODE -ne 0) {
            throw "Cold benchmark run $i failed with exit code $LASTEXITCODE"
        }
        $parsed = $outRaw | ConvertFrom-Json
        $samples += [ordered]@{
            run                             = $i
            external_wall_ms                = [math]::Round($sw.Elapsed.TotalMilliseconds, 3)
            internal_cold_to_interactive_ms = [double]$parsed.internal_cold_to_interactive_ms
            window_open_ms                  = [double]$parsed.window_open_ms
            first_gpu_draw_ms               = [double]$parsed.first_gpu_draw_ms
            first_ipc_message_ms            = [double]$parsed.first_ipc_message_ms
            working_set_mib                 = [double]$parsed.memory.working_set_mib
            peak_working_set_mib            = [double]$parsed.memory.peak_working_set_mib
            private_usage_mib               = [double]$parsed.memory.private_usage_mib
            working_set_bytes               = [int64]$parsed.memory.working_set_bytes
            peak_working_set_bytes          = [int64]$parsed.memory.peak_working_set_bytes
            private_usage_bytes             = [int64]$parsed.memory.private_usage_bytes
        }
    }

    $extArr = [double[]]($samples | ForEach-Object { $_.external_wall_ms })
    $intArr = [double[]]($samples | ForEach-Object { $_.internal_cold_to_interactive_ms })
    $rssArr = [double[]]($samples | ForEach-Object { $_.working_set_mib })
    $peakArr = [double[]]($samples | ForEach-Object { $_.peak_working_set_mib })
    $privArr = [double[]]($samples | ForEach-Object { $_.private_usage_mib })

    return [ordered]@{
        renderer_backend            = $warmParsed.renderer_backend
        post_link_first_scan_ext_ms = [math]::Round($swWarm.Elapsed.TotalMilliseconds, 3)
        post_link_first_scan_int_ms = [double]$warmParsed.internal_cold_to_interactive_ms
        external_wall_ms            = Get-DistributionStats -Values $extArr
        internal_interactive_ms     = Get-DistributionStats -Values $intArr
        working_set_mib             = Get-DistributionStats -Values $rssArr
        peak_working_set_mib        = Get-DistributionStats -Values $peakArr
        private_usage_mib           = Get-DistributionStats -Values $privArr
        raw_runs                    = $samples
    }
}

function Invoke-60FpsBench {
    param(
        [string]$ExePath,
        [string[]]$ExtraArgs = @()
    )
    Start-Sleep -Milliseconds 120
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $raw = & $ExePath --bench-60fps --mock-server @ExtraArgs
    $sw.Stop()
    if ($LASTEXITCODE -ne 0) {
        throw "60fps benchmark failed with exit code $LASTEXITCODE"
    }
    $parsed = $raw | ConvertFrom-Json
    return [ordered]@{
        external_wall_ms     = [math]::Round($sw.Elapsed.TotalMilliseconds, 3)
        renderer_backend     = $parsed.renderer_backend
        ipc_frames_received  = $parsed.ipc_frames_received
        rendered_frames      = $parsed.rendered_frames
        stream_elapsed_ms    = $parsed.elapsed_wall_ms
        effective_fps        = $parsed.effective_fps
        frame_time_min_ms    = $parsed.frame_time_min_ms
        frame_time_p50_ms    = $parsed.frame_time_p50_ms
        frame_time_p95_ms    = $parsed.frame_time_p95_ms
        frame_time_p99_ms    = $parsed.frame_time_p99_ms
        frame_time_max_ms    = $parsed.frame_time_max_ms
        frame_time_mean_ms   = $parsed.frame_time_mean_ms
        memory               = $parsed.memory
    }
}

Write-Host "[1/6] Inspecting stripped binaries and DLL imports..."
$wgpuBinInfo = Inspect-Binary -ExePath $WgpuExe
$tinyBinInfo = Inspect-Binary -ExePath $TinySkiaExe

Write-Host "[2/6] Running 20 cold launches for Primary Candidate B1 (iced + wgpu GPU)..."
$wgpuVulkanCold = Invoke-ColdSeries -ExePath $WgpuExe -Runs 20 -ExtraArgs @("--wgpu-backend", "vulkan")

Write-Host "[3/6] Running cold launch ablations for wgpu(dx12) and wgpu(all)..."
$wgpuDx12Cold = Invoke-ColdSeries -ExePath $WgpuExe -Runs 20 -ExtraArgs @("--wgpu-backend", "dx12")
$wgpuAllCold = Invoke-ColdSeries -ExePath $WgpuExe -Runs 5 -ExtraArgs @("--wgpu-backend", "all")

Write-Host "[4/6] Running 20 cold launches for iced + tiny-skia feature variant..."
$tinyCold = Invoke-ColdSeries -ExePath $TinySkiaExe -Runs 20

Write-Host "[5/6] Running 5.0s 60Hz (300-frame) live IPC transfer-meter benchmarks..."
$wgpuVulkan60 = Invoke-60FpsBench -ExePath $WgpuExe -ExtraArgs @("--wgpu-backend", "vulkan")
$wgpuDx1260   = Invoke-60FpsBench -ExePath $WgpuExe -ExtraArgs @("--wgpu-backend", "dx12")
$tiny60       = Invoke-60FpsBench -ExePath $TinySkiaExe

Write-Host "[6/6] Verifying external Named Pipe server interop..."
$extPipe = "\\.\pipe\zerovault-bakeoff-iced-extcheck"
$srvProc = Start-Process -FilePath $WgpuExe -ArgumentList @("--serve-only", "--pipe", $extPipe) -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 250
try {
    $extOut = & $WgpuExe --bench-cold --pipe $extPipe | ConvertFrom-Json
} finally {
    if ($srvProc -and !$srvProc.HasExited) {
        Stop-Process -Id $srvProc.Id -Force
    }
}

$results = [ordered]@{
    candidate                = "B1"
    name                     = "Pure Rust iced Native Desktop UI"
    timestamp_utc            = (Get-Date).ToUniversalTime().ToString("o")
    environment              = [ordered]@{
        os                   = [System.Environment]::OSVersion.VersionString
        cpu                  = "AMD Ryzen 9 7950X3D 16-Core Processor (32 threads)"
        gpu                  = "NVIDIA GeForce RTX 4080 SUPER (Driver 32.0.16.2101)"
        ram_gib              = 31.6
        rustc                = (& rustc --version)
        cargo                = (& cargo --version)
        release_profile      = [ordered]@{
            lto              = "thin"
            codegen_units    = 1
            strip            = "symbols"
            opt_level        = 3
        }
    }
    compilation              = [ordered]@{
        wgpu_clean_release_s      = 107.113
        wgpu_incremental_s        = 38.170
        tiny_skia_clean_release_s = 39.680
    }
    binaries                 = [ordered]@{
        wgpu_gpu             = $wgpuBinInfo
        tiny_skia_cpu        = $tinyBinInfo
    }
    benchmarks               = [ordered]@{
        wgpu_vulkan_primary  = [ordered]@{
            cold_20_runs     = $wgpuVulkanCold
            live_60fps_5s    = $wgpuVulkan60
        }
        wgpu_dx12            = [ordered]@{
            cold_20_runs     = $wgpuDx12Cold
            live_60fps_5s    = $wgpuDx1260
        }
        wgpu_stock_all_probe = [ordered]@{
            cold_5_runs      = $wgpuAllCold
        }
        tiny_skia_variant    = [ordered]@{
            cold_20_runs     = $tinyCold
            live_60fps_5s    = $tiny60
        }
        external_pipe_interop = [ordered]@{
            verified         = ($extOut.ipc_source -eq "external-win32-named-pipe-server")
            ipc_source       = $extOut.ipc_source
            first_ipc_seq    = $extOut.first_ipc_seq
            cold_ms          = $extOut.internal_cold_to_interactive_ms
        }
    }
}

$results | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonOutPath -Encoding UTF8
Write-Host "=== BENCHMARK SUITE COMPLETE -> $JsonOutPath ==="
