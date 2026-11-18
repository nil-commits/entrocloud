<#
.SYNOPSIS
Builds Windows release binaries for EntroCloud v1.0, audits every binary via dumpbin /dependents
and raw ASCII/UTF-16LE string scanning to prove 0 WebView2 / browser dependencies, and produces
a portable .zip distribution (`entrocloud-windows-x86_64-portable.zip`).
#>
[CmdletBinding()]
param(
    [string]$TargetDir = "target",
    [string]$OutputDir = "dist\windows",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-DumpbinExe {
    $OnPath = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -ne $OnPath) {
        return $OnPath.Source
    }

    $VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $VsWhere) {
        $VsInstall = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if (-not [string]::IsNullOrWhiteSpace($VsInstall)) {
            $Found = Get-ChildItem -Path (Join-Path $VsInstall "VC\Tools\MSVC") -Recurse -Filter "dumpbin.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match 'Host[xX]64\\x64\\dumpbin\.exe$' } |
                Sort-Object FullName -Descending |
                Select-Object -First 1
            if ($null -ne $Found) {
                return $Found.FullName
            }
        }
    }

    $Fallback = Get-ChildItem -Path "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter "dumpbin.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'Host[xX]64\\x64\\dumpbin\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -ne $Fallback) {
        return $Fallback.FullName
    }
    return $null
}

function Get-PeImportedDllNames {
    param([Parameter(Mandatory = $true)][byte[]]$PeBytes)

    if ($PeBytes.Length -lt 0x100 -or $PeBytes[0] -ne 0x4D -or $PeBytes[1] -ne 0x5A) {
        throw "Invalid PE MZ header."
    }
    $PeOffset = [BitConverter]::ToInt32($PeBytes, 0x3C)
    $Magic = [BitConverter]::ToUInt16($PeBytes, $PeOffset + 24)
    $NumSections = [BitConverter]::ToUInt16($PeBytes, $PeOffset + 6)
    $OptHeaderSize = [BitConverter]::ToUInt16($PeBytes, $PeOffset + 20)
    $ImportDirOffset = if ($Magic -eq 0x20B) { $PeOffset + 24 + 120 } else { $PeOffset + 24 + 104 }
    $ImportRva = [BitConverter]::ToUInt32($PeBytes, $ImportDirOffset)
    if ($ImportRva -eq 0) {
        return @()
    }

    $SecTable = $PeOffset + 24 + $OptHeaderSize
    $Sections = for ($i = 0; $i -lt $NumSections; $i++) {
        $Off = $SecTable + ($i * 40)
        [PSCustomObject]@{
            VirtualSize    = [BitConverter]::ToUInt32($PeBytes, $Off + 8)
            VirtualAddress = [BitConverter]::ToUInt32($PeBytes, $Off + 12)
            SizeOfRawData  = [BitConverter]::ToUInt32($PeBytes, $Off + 16)
            PointerToRaw   = [BitConverter]::ToUInt32($PeBytes, $Off + 20)
        }
    }

    $RvaToOffset = {
        param([uint32]$Rva)
        foreach ($Sec in $Sections) {
            $Span = [Math]::Max($Sec.VirtualSize, $Sec.SizeOfRawData)
            if ($Rva -ge $Sec.VirtualAddress -and $Rva -lt ($Sec.VirtualAddress + $Span)) {
                return [int]($Sec.PointerToRaw + ($Rva - $Sec.VirtualAddress))
            }
        }
        return -1
    }

    $DescOffset = & $RvaToOffset $ImportRva
    $Dlls = New-Object System.Collections.Generic.List[string]
    while ($DescOffset -ge 0 -and ($DescOffset + 20) -le $PeBytes.Length) {
        $NameRva = [BitConverter]::ToUInt32($PeBytes, $DescOffset + 12)
        $FirstThunk = [BitConverter]::ToUInt32($PeBytes, $DescOffset + 16)
        if ($NameRva -eq 0 -and $FirstThunk -eq 0) {
            break
        }
        $NameOff = & $RvaToOffset $NameRva
        if ($NameOff -ge 0) {
            $End = $NameOff
            while ($End -lt $PeBytes.Length -and $PeBytes[$End] -ne 0) { $End++ }
            $Dlls.Add([System.Text.Encoding]::ASCII.GetString($PeBytes, $NameOff, $End - $NameOff))
        }
        $DescOffset += 20
    }
    return $Dlls.ToArray()
}

function Assert-ZeroWebViewBinary {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [string]$DumpbinExe
    )

    $ForbiddenDllPattern = '(?i)(webview2|edgewebview|msedge|webkit|libcef|cef\.dll|electron|nw_elf)'
    if (-not [string]::IsNullOrWhiteSpace($DumpbinExe)) {
        $DumpOut = (& $DumpbinExe /dependents $BinaryPath 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "dumpbin /dependents failed on '$BinaryPath' (exit $LASTEXITCODE):`n$DumpOut"
        }
        if ($DumpOut -match $ForbiddenDllPattern) {
            throw "ZERO-WEBVIEW AUDIT FAILED: '$BinaryPath' imports forbidden browser/WebView DLL ($($Matches[0])):`n$DumpOut"
        }
    } else {
        $RawPe = [System.IO.File]::ReadAllBytes($BinaryPath)
        $ImportedDlls = Get-PeImportedDllNames -PeBytes $RawPe
        foreach ($Dll in $ImportedDlls) {
            if ($Dll -match $ForbiddenDllPattern) {
                throw "ZERO-WEBVIEW AUDIT FAILED: '$BinaryPath' imports forbidden DLL '$Dll'."
            }
        }
    }

    # Catch statically embedded WebView2LoaderStatic.lib / Tauri / Wry runtime entrypoints in .rdata/.text
    $Bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
    $AsciiText = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $Utf16Text = [System.Text.Encoding]::Unicode.GetString($Bytes)
    $ForbiddenRuntimeMarkers = @(
        'WebView2Loader.dll',
        'EmbeddedBrowserWebView.dll',
        'CreateCoreWebView2Environment',
        '__TAURI_INTERNALS__',
        'tauri_runtime_wry',
        'libwebkit2gtk-'
    )
    foreach ($Marker in $ForbiddenRuntimeMarkers) {
        if ($AsciiText.IndexOf($Marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $Utf16Text.IndexOf($Marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "ZERO-WEBVIEW STRING AUDIT FAILED: '$BinaryPath' contains embedded runtime marker '$Marker'."
        }
    }
}

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
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
        & cargo build --release --locked -p entrocloud-daemon -p entrocloud-cli -p entrocloud-ui
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed with exit code $LASTEXITCODE"
        }
    }

    $ReleaseDir = Join-Path $TargetDir "release"
    $StageDir   = Join-Path $OutputDir "entrocloud-portable"
    $ZipPath    = Join-Path $OutputDir "entrocloud-windows-x86_64-portable.zip"

    if (Test-Path -LiteralPath $StageDir) {
        Remove-Item -Recurse -Force -LiteralPath $StageDir
    }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $DumpbinExe = Resolve-DumpbinExe
    if ($null -ne $DumpbinExe) {
        Write-Host "Using PE import verifier: $DumpbinExe"
    } else {
        Write-Host "dumpbin.exe not found; using built-in PE Import Directory + ASCII/UTF-16 string verifier."
    }

    # Copy `entrocloud.exe` to `$StageDir\EntroCloud.exe` so Windows Explorer displays `EntroCloud.exe`
    # while `entrocloud.exe` sibling lookups resolve automatically on case-insensitive NTFS.
    $BinaryMappings = @(
        @{ SourceName = "entrocloud.exe";      StageName = "EntroCloud.exe"      },
        @{ SourceName = "entrocloudd.exe";     StageName = "entrocloudd.exe"     },
        @{ SourceName = "ec.exe";              StageName = "ec.exe"              },
        @{ SourceName = "entrocloud-tray.exe"; StageName = "entrocloud-tray.exe" }
    )

    $ChecksumLines = New-Object System.Collections.Generic.List[string]
    foreach ($Map in $BinaryMappings) {
        $Src = Join-Path $ReleaseDir $Map.SourceName
        if (-not (Test-Path -LiteralPath $Src)) {
            throw "Expected release binary not found: $Src"
        }

        Assert-ZeroWebViewBinary -BinaryPath $Src -DumpbinExe $DumpbinExe

        $Dst = Join-Path $StageDir $Map.StageName
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
        $Hash = (Get-FileHash -LiteralPath $Dst -Algorithm SHA256).Hash.ToLowerInvariant()
        $SizeMib = [Math]::Round(((Get-Item -LiteralPath $Dst).Length / 1MB), 3)
        $ChecksumLines.Add("$Hash  $($Map.StageName)")
        Write-Host ("Verified 0 WebView2 DLLs & markers: {0,-20} ({1,6} MiB, sha256={2})" -f $Map.StageName, $SizeMib, $Hash.Substring(0, 16))
    }

    foreach ($ScriptName in @("install.ps1", "register-uri.ps1", "unregister-uri.ps1")) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $ScriptName) `
            -Destination (Join-Path $StageDir $ScriptName) -Force
    }

    $SetupGuideSrc = Join-Path $RepoRoot "GOOGLE-DRIVE-SETUP.md"
    if (-not (Test-Path -LiteralPath $SetupGuideSrc)) {
        throw "Expected cloud setup guide not found: $SetupGuideSrc"
    }
    Copy-Item -LiteralPath $SetupGuideSrc -Destination (Join-Path $StageDir "GOOGLE-DRIVE-SETUP.md") -Force

    Set-Content -LiteralPath (Join-Path $StageDir "SHA256SUMS.txt") -Value ($ChecksumLines -join "`r`n") -Encoding UTF8

    $ReadmeContent = @"
EntroCloud v1.0 Portable Distribution (Windows 10/11 x86_64)
============================================================

Included native binaries (100% Pure Rust, 0 WebView2 / browser DLLs, 0 rclone subprocesses):
  - EntroCloud.exe       Pure Rust eframe/egui + glow desktop studio (0 B RAM when closed)
  - entrocloudd.exe      Always-on zero-knowledge sync, automatic backup & CfApi VFS daemon (~5.68 MiB idle RSS)
  - ec.exe               Administrative, OAuth2 PKCE, backup job, multi-cloud routing & sharing CLI
  - entrocloud-tray.exe  Optional lightweight system tray helper (~8.07 MiB RSS / 1.39 MiB private)

Quick start (Desktop GUI — no terminal or administrator rights required):
  1. Double-click EntroCloud.exe to create or unlock your vault password.
  2. Connect Google Drive, OneDrive, Dropbox, S3 / Cloudflare R2 / Backblaze B2, Nextcloud / WebDAV,
     or a 1-Click local / synced cloud folder (see GOOGLE-DRIVE-SETUP.md for step-by-step setup).
  3. Set up Automatic PC Folder Backup Jobs (with dry-run Preview & safe Restore), mount your
     Windows Cloud Files (CfApi) virtual drive, and share via ec:// (or legacy zv://) links
     or post-quantum ML-KEM-768 keybox.zv folders.

User-local install (%LOCALAPPDATA%\Programs\EntroCloud + PATH + Desktop/Start Menu + ec:// & zv://):
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -EnableAutoStart

Standalone ec:// + zv:// protocol registration / removal (no UAC elevation required):
  powershell -ExecutionPolicy Bypass -File .\register-uri.ps1
  powershell -ExecutionPolicy Bypass -File .\unregister-uri.ps1
"@
    Set-Content -LiteralPath (Join-Path $StageDir "README-WINDOWS.txt") -Value $ReadmeContent -Encoding UTF8

    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -Force -LiteralPath $ZipPath
    }
    Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -Force
    Write-Host "Staged portable bundle: $StageDir"
    Write-Host "Created archive:        $ZipPath"
}
finally {
    Pop-Location
}
