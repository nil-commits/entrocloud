<#
.SYNOPSIS
Installs EntroCloud v1.0 native binaries (EntroCloud.exe, entrocloudd.exe, ec.exe, entrocloud-tray.exe)
into %LOCALAPPDATA%\Programs\EntroCloud, updates User PATH, registers per-user ec:// and zv://
protocol handlers, creates Start Menu and Desktop shortcuts for EntroCloud.exe, and optionally enables
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run "EntroCloud". Requires ZERO UAC elevation.
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\EntroCloud"),
    [bool]$UpdateUserPath = $true,
    [bool]$RegisterUriProtocol = $true,
    [bool]$CreateStartMenuShortcut = $true,
    [bool]$CreateDesktopShortcut = $true,
    [Alias("InstallAutoStart", "RegisterLogonTasks")]
    [switch]$EnableAutoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "entrocloudd.exe")) {
        $SourceDir = $PSScriptRoot
    } else {
        $RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
        $SourceDir = Join-Path $RepoRoot "target\release"
    }
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Copy primary GUI binary with explicit PascalCase `EntroCloud.exe` directory casing on NTFS.
# On Windows NTFS, `EntroCloud.exe` and `entrocloud.exe` resolve to the same file, so removing any
# pre-existing lowercase entry before Copy-Item guarantees Windows Explorer displays `EntroCloud.exe`.
$UiSourceCandidate = Join-Path $SourceDir "EntroCloud.exe"
if (-not (Test-Path -LiteralPath $UiSourceCandidate)) {
    $UiSourceCandidate = Join-Path $SourceDir "entrocloud.exe"
}
if (-not (Test-Path -LiteralPath $UiSourceCandidate)) {
    throw "Missing required desktop binary '$UiSourceCandidate'. Build release binaries first or pass -SourceDir."
}

$UiExe = Join-Path $InstallDir "EntroCloud.exe"
if (Test-Path -LiteralPath $UiExe) {
    $ExistingUiItem = Get-Item -LiteralPath $UiExe
    if ($ExistingUiItem.Name -cne "EntroCloud.exe") {
        Remove-Item -Force -LiteralPath $UiExe
    }
}
Copy-Item -LiteralPath $UiSourceCandidate -Destination $UiExe -Force

foreach ($Bin in @("entrocloudd.exe", "ec.exe", "entrocloud-tray.exe")) {
    $Src = Join-Path $SourceDir $Bin
    if (-not (Test-Path -LiteralPath $Src)) {
        throw "Missing required release binary '$Src'. Build release binaries first or pass -SourceDir."
    }
    Copy-Item -LiteralPath $Src -Destination (Join-Path $InstallDir $Bin) -Force
}

$GuideCandidate = Join-Path $SourceDir "GOOGLE-DRIVE-SETUP.md"
if (-not (Test-Path -LiteralPath $GuideCandidate)) {
    $RepoGuide = Join-Path $PSScriptRoot "..\..\GOOGLE-DRIVE-SETUP.md"
    if (Test-Path -LiteralPath $RepoGuide) {
        $GuideCandidate = (Resolve-Path -LiteralPath $RepoGuide).Path
    }
}
if (Test-Path -LiteralPath $GuideCandidate) {
    Copy-Item -LiteralPath $GuideCandidate -Destination (Join-Path $InstallDir "GOOGLE-DRIVE-SETUP.md") -Force
}

if ($UpdateUserPath) {
    $CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $NormalizedInstall = $InstallDir.TrimEnd('\').ToLowerInvariant()
    $Entries = @()
    if (-not [string]::IsNullOrWhiteSpace($CurrentUserPath)) {
        $Entries = @($CurrentUserPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $AlreadyPresent = $false
    foreach ($Entry in $Entries) {
        if ($Entry.TrimEnd('\').ToLowerInvariant() -eq $NormalizedInstall) {
            $AlreadyPresent = $true
            break
        }
    }

    if (-not $AlreadyPresent) {
        $NewPath = (@($Entries) + @($InstallDir)) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added $InstallDir to User PATH."
    } else {
        Write-Host "$InstallDir is already present in User PATH."
    }
}

$TrayExe = Join-Path $InstallDir "entrocloud-tray.exe"

if ($RegisterUriProtocol) {
    $RegisterScript = Join-Path $PSScriptRoot "register-uri.ps1"
    if (Test-Path -LiteralPath $RegisterScript) {
        & $RegisterScript -UiExePath $UiExe
    } else {
        foreach ($Spec in @(
            @{ Scheme = "ec"; Description = "URL:EntroCloud Share Protocol" },
            @{ Scheme = "zv"; Description = "URL:EntroCloud Legacy Share Protocol" }
        )) {
            $BaseSubKey = "Software\Classes\$($Spec.Scheme)"
            $RootKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($BaseSubKey)
            try {
                $RootKey.SetValue("", $Spec.Description, [Microsoft.Win32.RegistryValueKind]::String)
                $RootKey.SetValue("URL Protocol", "", [Microsoft.Win32.RegistryValueKind]::String)
            }
            finally {
                $RootKey.Dispose()
            }

            $IconKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("$BaseSubKey\DefaultIcon")
            try {
                $IconKey.SetValue("", "`"$UiExe`",0", [Microsoft.Win32.RegistryValueKind]::String)
            }
            finally {
                $IconKey.Dispose()
            }

            $CmdKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("$BaseSubKey\shell\open\command")
            try {
                $CmdKey.SetValue("", "`"$UiExe`" --open-uri `"%1`"", [Microsoft.Win32.RegistryValueKind]::String)
            }
            finally {
                $CmdKey.Dispose()
            }
            Write-Host "Registered HKCU:\$BaseSubKey -> `"$UiExe`" --open-uri `"%1`""
        }
    }
}

if ($CreateStartMenuShortcut -or $CreateDesktopShortcut) {
    $Shell = New-Object -ComObject WScript.Shell

    if ($CreateStartMenuShortcut) {
        $StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\EntroCloud"
        New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null

        $UiShortcutPath = Join-Path $StartMenuDir "EntroCloud.lnk"
        $UiShortcut = $Shell.CreateShortcut($UiShortcutPath)
        $UiShortcut.TargetPath = $UiExe
        $UiShortcut.WorkingDirectory = $InstallDir
        $UiShortcut.Description = "EntroCloud Zero-Knowledge Multi-Cloud Drive & Automatic Folder Backup"
        $UiShortcut.Save()

        $TrayShortcutPath = Join-Path $StartMenuDir "EntroCloud Tray.lnk"
        $TrayShortcut = $Shell.CreateShortcut($TrayShortcutPath)
        $TrayShortcut.TargetPath = $TrayExe
        $TrayShortcut.WorkingDirectory = $InstallDir
        $TrayShortcut.Description = "EntroCloud Lightweight System Tray Helper"
        $TrayShortcut.Save()

        Write-Host "Created Start Menu shortcuts in: $StartMenuDir"
    }

    if ($CreateDesktopShortcut) {
        $DesktopDir = [Environment]::GetFolderPath("Desktop")
        if (-not [string]::IsNullOrWhiteSpace($DesktopDir) -and (Test-Path -LiteralPath $DesktopDir)) {
            $DesktopShortcutPath = Join-Path $DesktopDir "EntroCloud.lnk"
            $DesktopShortcut = $Shell.CreateShortcut($DesktopShortcutPath)
            $DesktopShortcut.TargetPath = $UiExe
            $DesktopShortcut.WorkingDirectory = $InstallDir
            $DesktopShortcut.Description = "EntroCloud Zero-Knowledge Multi-Cloud Drive & Automatic Folder Backup"
            $DesktopShortcut.Save()
            Write-Host "Created Desktop shortcut: $DesktopShortcutPath"
        }
    }
}

if ($EnableAutoStart) {
    $RunKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Software\Microsoft\Windows\CurrentVersion\Run")
    try {
        $RunKey.SetValue("EntroCloud", "`"$TrayExe`"", [Microsoft.Win32.RegistryValueKind]::String)
        Write-Host "Enabled Windows sign-in autostart: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run 'EntroCloud' -> `"$TrayExe`""
    }
    finally {
        $RunKey.Dispose()
    }
}

Write-Host "EntroCloud v1.0 installed to $InstallDir."
