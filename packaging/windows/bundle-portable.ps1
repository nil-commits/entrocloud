<#
.SYNOPSIS
Builds Windows release binaries for Zerovault and stages a portable .zip archive.
#>
[CmdletBinding()]
param(
    [string]$TargetDir = "target",
    [string]$OutputDir = "dist\windows",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $RepoRoot
try {
    if (-not [System.IO.Path]::IsPathRooted($TargetDir)) {
        $TargetDir = Join-Path $RepoRoot $TargetDir
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
        $OutputDir = Join-Path $RepoRoot $OutputDir
    }

    if (-not $SkipBuild) {
        $env:CARGO_TARGET_DIR = $TargetDir
        & cargo build --release --locked -p zerovault-daemon -p zerovault-cli -p zerovault-ui
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed with exit code $LASTEXITCODE"
        }
    }

    $ReleaseDir = Join-Path $TargetDir "release"
    $StageDir = Join-Path $OutputDir "zerovault-portable"
    $ZipPath = Join-Path $OutputDir "zerovault-windows-x86_64-portable.zip"

    if (Test-Path $StageDir) {
        Remove-Item -Recurse -Force $StageDir
    }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $Binaries = @("zerovaultd.exe", "zv.exe", "zerovault-ui.exe")
    foreach ($Bin in $Binaries) {
        $Src = Join-Path $ReleaseDir $Bin
        if (-not (Test-Path $Src)) {
            throw "Expected release binary not found: $Src"
        }
        Copy-Item -Path $Src -Destination (Join-Path $StageDir $Bin) -Force
    }

    Copy-Item -Path (Join-Path $PSScriptRoot "install.ps1") `
        -Destination (Join-Path $StageDir "install.ps1") -Force

    $ReadmeContent = @"
Zerovault Portable Distribution (Windows x86_64)
================================================

Included binaries:
  - zerovaultd.exe    Background zero-knowledge sync & CfApi VFS daemon
  - zv.exe            Command-line client
  - zerovault-ui.exe  Full desktop GUI + system tray app (auto-starts local engine)

Quick start (Desktop GUI — no terminal required):
  1. Launch .\zerovault-ui.exe directly to open the onboarding wizard, add clouds,
     upload/browse encrypted files, or mount Windows Cloud Files (CfApi).

Quick start (Optional CLI / Background Daemon):
  1. Start the daemon in a terminal or background job:
       .\zerovaultd.exe
  2. Initialize or unlock your vault:
       .\zv.exe init
  3. Add one or more cloud backends:
       .\zv.exe remote add local-1 --kind fs --root C:\Path\To\EncryptedStore --policy pooled
  4. Mount your on-demand Windows Cloud Files sync root:
       .\zv.exe mount "$env:USERPROFILE\Zerovault"
  5. Launch the system tray popup:
       .\zerovault-ui.exe

Optional user-local install (adds %LOCALAPPDATA%\Zerovault\bin to PATH):
  powershell -ExecutionPolicy Bypass -File .\install.ps1
"@
    Set-Content -Path (Join-Path $StageDir "README-WINDOWS.txt") -Value $ReadmeContent -Encoding UTF8

    if (Test-Path $ZipPath) {
        Remove-Item -Force $ZipPath
    }
    Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -Force
    Write-Host "Staged portable bundle: $StageDir"
    Write-Host "Created archive:        $ZipPath"
}
finally {
    Pop-Location
}
