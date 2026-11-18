param(
    [int]$ColdIterations = 20,
    [string]$PipeName = "zerovault-bakeoff-dotnet",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"

$ProjectDir = $PSScriptRoot
$TargetRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectDir "..\..\target\swarm\bakeoff-ui-dotnet"))
$PublishDir = Join-Path $TargetRoot "publish"
$ExePath = Join-Path $PublishDir "ZeroVaultUi.exe"
$ResultsJsonPath = Join-Path $ProjectDir "ui_dotnet_results.json"

if ($Rebuild -or -not (Test-Path $ExePath)) {
    Write-Host "[1/5] Publishing NativeAOT Release win-x64..."
    if (Test-Path $PublishDir) {
        Remove-Item (Join-Path $PublishDir "*") -Recurse -Force
    }
    Push-Location $ProjectDir
    try {
        $buildSw = [System.Diagnostics.Stopwatch]::StartNew()
        dotnet publish -c Release -r win-x64
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }
        $buildSw.Stop()
        Write-Host "Published in $([Math]::Round($buildSw.Elapsed.TotalSeconds, 2))s"
    }
    finally {
        Pop-Location
    }
}

Get-ChildItem $PublishDir -Filter "*.pdb" -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "[2/5] Inspecting PE binary sizes and DLL dependents..."
$dumpbinPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
$dependentsRaw = ""
if (Test-Path $dumpbinPath) {
    $dependentsRaw = (& $dumpbinPath /dependents $ExePath | Out-String).Trim()
}

$publishFiles = Get-ChildItem $PublishDir -File | Sort-Object Length -Descending
$exeItem = Get-Item $ExePath
$totalPublishBytes = ($publishFiles | Measure-Object -Property Length -Sum).Sum

$fileManifest = @()
foreach ($f in $publishFiles) {
    $fileManifest += [ordered]@{
        name = $f.Name
        bytes = $f.Length
        mib = [Math]::Round($f.Length / 1MB, 3)
    }
}

$hasWebView = (($publishFiles.Name -join " ") + " " + $dependentsRaw) -match "(?i)(webview2|cefsharp|libcef|msedgewebview|chakra)"

Write-Host "[3/5] Starting external Named Pipe mock server daemon (\\.\pipe\$PipeName)..."
$serverProc = Start-Process -FilePath $ExePath -ArgumentList "--mock-server --pipe $PipeName --hz 60 --frames 20 --loop" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 250

$coldRuns = @()
try {
    Write-Host "[4/5] Running $ColdIterations cold launches (--bench-cold)..."
    for ($i = 1; $i -le $ColdIterations; $i++) {
        $extSw = [System.Diagnostics.Stopwatch]::StartNew()
        $rawOut = & $ExePath --bench-cold --pipe $PipeName
        $exitCode = $LASTEXITCODE
        $extSw.Stop()

        if ($exitCode -ne 0) {
            throw "Cold benchmark run $i exited with code $exitCode"
        }

        $jsonLine = ($rawOut | Where-Object { $_ -like "{*" } | Select-Object -Last 1)
        if (-not $jsonLine) {
            throw "Cold benchmark run $i emitted no JSON telemetry: $rawOut"
        }

        $parsed = $jsonLine | ConvertFrom-Json
        $runRecord = [ordered]@{
            iteration = $i
            cold_first_frame_ipc_ms = [double]$parsed.cold_first_frame_ipc_ms
            window_opened_ms = [double]$parsed.window_opened_ms
            first_ipc_received_ms = [double]$parsed.first_ipc_received_ms
            external_process_wall_ms = [Math]::Round($extSw.Elapsed.TotalMilliseconds, 3)
            ipc_server_mode = $parsed.ipc_server_mode
            working_set_mib = [double]$parsed.working_set_mib
            peak_working_set_mib = [double]$parsed.peak_working_set_mib
            private_memory_mib = [double]$parsed.private_memory_mib
            working_set_bytes = [long]$parsed.working_set_bytes
            peak_working_set_bytes = [long]$parsed.peak_working_set_bytes
            private_memory_bytes = [long]$parsed.private_memory_bytes
        }
        $coldRuns += $runRecord
        Write-Host ("  Run {0,2}/{1}: internal_first_frame={2,6:F2} ms | external_wall={3,6:F2} ms | RSS={4,5:F2} MiB | mode={5}" -f $i, $ColdIterations, $runRecord.cold_first_frame_ipc_ms, $runRecord.external_process_wall_ms, $runRecord.working_set_mib, $runRecord.ipc_server_mode)
        Start-Sleep -Milliseconds 100
    }
}
finally {
    if ($serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[5/5] Running 60 FPS 5.0s live streaming benchmark (300 frames over \\.\pipe\$PipeName)..."
$streamServerProc = Start-Process -FilePath $ExePath -ArgumentList "--mock-server --pipe $PipeName --hz 60 --frames 350" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 250

try {
    $rawStreamOut = & $ExePath --bench-60fps --pipe $PipeName --frames 300
    if ($LASTEXITCODE -ne 0) {
        throw "60fps benchmark exited with code $LASTEXITCODE"
    }
    $streamJsonLine = ($rawStreamOut | Where-Object { $_ -like "{*" } | Select-Object -Last 1)
    if (-not $streamJsonLine) {
        throw "60fps benchmark emitted no JSON telemetry: $rawStreamOut"
    }
    $streamParsed = $streamJsonLine | ConvertFrom-Json
}
finally {
    if ($streamServerProc -and -not $streamServerProc.HasExited) {
        Stop-Process -Id $streamServerProc.Id -Force -ErrorAction SilentlyContinue
    }
}

function Get-Percentile([double[]]$arr, [double]$p) {
    $sorted = $arr | Sort-Object
    if ($sorted.Count -eq 0) { return 0.0 }
    if ($sorted.Count -eq 1) { return $sorted[0] }
    $rank = $p * ($sorted.Count - 1)
    $lo = [Math]::Floor($rank)
    $hi = [Math]::Ceiling($rank)
    if ($lo -eq $hi) { return [Math]::Round($sorted[$lo], 3) }
    return [Math]::Round($sorted[$lo] + ($sorted[$hi] - $sorted[$lo]) * ($rank - $lo), 3)
}

$internalColdVals = [double[]]($coldRuns | ForEach-Object { $_.cold_first_frame_ipc_ms })
$externalColdVals = [double[]]($coldRuns | ForEach-Object { $_.external_process_wall_ms })
$coldRssVals = [double[]]($coldRuns | ForEach-Object { $_.working_set_mib })
$coldPrivateVals = [double[]]($coldRuns | ForEach-Object { $_.private_memory_mib })

$summary = [ordered]@{
    candidate = "Candidate A: .NET 9 NativeAOT + Avalonia 12.1.6"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    host = [ordered]@{
        os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
        gpu = "NVIDIA GeForce RTX 4080 SUPER (2560x1440 @ 540Hz)"
        dotnet_sdk = (dotnet --version).Trim()
        runtime_framework = $streamParsed.runtime_framework
        avalonia_nuget_version = $streamParsed.avalonia_version
        is_native_aot = [bool]$streamParsed.is_native_aot
        msvc_linker = "14.44.35207"
    }
    binary_footprint = [ordered]@{
        exe_name = $exeItem.Name
        exe_bytes = $exeItem.Length
        exe_mib = [Math]::Round($exeItem.Length / 1MB, 3)
        total_publish_bytes = $totalPublishBytes
        total_publish_mib = [Math]::Round($totalPublishBytes / 1MB, 3)
        webview_or_browser_dlls_present = [bool]$hasWebView
        publish_files = $fileManifest
        dumpbin_dependents = $dependentsRaw
    }
    cold_start_20_runs = [ordered]@{
        iterations = $ColdIterations
        internal_first_frame_ipc_ms = [ordered]@{
            min = [Math]::Round(($internalColdVals | Measure-Object -Minimum).Minimum, 3)
            p50 = Get-Percentile $internalColdVals 0.50
            p95 = Get-Percentile $internalColdVals 0.95
            max = [Math]::Round(($internalColdVals | Measure-Object -Maximum).Maximum, 3)
            mean = [Math]::Round(($internalColdVals | Measure-Object -Average).Average, 3)
        }
        external_process_wall_ms = [ordered]@{
            min = [Math]::Round(($externalColdVals | Measure-Object -Minimum).Minimum, 3)
            p50 = Get-Percentile $externalColdVals 0.50
            p95 = Get-Percentile $externalColdVals 0.95
            max = [Math]::Round(($externalColdVals | Measure-Object -Maximum).Maximum, 3)
            mean = [Math]::Round(($externalColdVals | Measure-Object -Average).Average, 3)
        }
        memory_at_first_frame = [ordered]@{
            working_set_p50_mib = Get-Percentile $coldRssVals 0.50
            working_set_max_mib = [Math]::Round(($coldRssVals | Measure-Object -Maximum).Maximum, 3)
            private_memory_p50_mib = Get-Percentile $coldPrivateVals 0.50
        }
        runs = $coldRuns
    }
    stream_60fps_5s = $streamParsed
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $ResultsJsonPath -Encoding UTF8
Write-Host ""
Write-Host "=== BENCHMARK COMPLETE ==="
Write-Host "Results written to: $ResultsJsonPath"
Write-Host ("Exe Size: {0} MiB | Total Publish Folder: {1} MiB | WebView2/Browser DLLs: {2}" -f $summary.binary_footprint.exe_mib, $summary.binary_footprint.total_publish_mib, $summary.binary_footprint.webview_or_browser_dlls_present)
Write-Host ("Cold First-Frame+IPC (20 runs): min={0}ms | p50={1}ms | p95={2}ms | max={3}ms" -f $summary.cold_start_20_runs.internal_first_frame_ipc_ms.min, $summary.cold_start_20_runs.internal_first_frame_ipc_ms.p50, $summary.cold_start_20_runs.internal_first_frame_ipc_ms.p95, $summary.cold_start_20_runs.internal_first_frame_ipc_ms.max)
Write-Host ("Cold External Wall  (20 runs): min={0}ms | p50={1}ms | p95={2}ms | max={3}ms" -f $summary.cold_start_20_runs.external_process_wall_ms.min, $summary.cold_start_20_runs.external_process_wall_ms.p50, $summary.cold_start_20_runs.external_process_wall_ms.p95, $summary.cold_start_20_runs.external_process_wall_ms.max)
Write-Host ("60FPS 300-Frame Stream: FPS={0} | Delta p50={1}ms p95={2}ms p99={3}ms | RenderLat p50={4}ms p99={5}ms | PeakRSS={6} MiB | ActiveRSS={7} MiB" -f $streamParsed.effective_fps, $streamParsed.frame_delta_p50_ms, $streamParsed.frame_delta_p95_ms, $streamParsed.frame_delta_p99_ms, $streamParsed.render_latency_p50_ms, $streamParsed.render_latency_p99_ms, $streamParsed.peak_working_set_mib, $streamParsed.working_set_mib)
