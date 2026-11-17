<#
.SYNOPSIS
Installs Zerovault binaries into %LOCALAPPDATA%\Zerovault\bin, updates User PATH, and optionally
configures Start Menu shortcut and user logon Scheduled Task.
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Zerovault\bin"),
    [switch]$InstallAutoStart,
    [bool]$CreateStartMenuShortcut = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    if (Test-Path (Join-Path $PSScriptRoot "zerovaultd.exe")) {
        $SourceDir = $PSScriptRoot
    } else {
        $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        $SourceDir = Join-Path $RepoRoot "target\release"
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$Binaries = @("zerovaultd.exe", "zv.exe", "zerovault-ui.exe")
foreach ($Bin in $Binaries) {
    $Src = Join-Path $SourceDir $Bin
    if (-not (Test-Path $Src)) {
        throw "Missing binary '$Src'. Build release binaries first or pass -SourceDir."
    }
    Copy-Item -Path $Src -Destination (Join-Path $InstallDir $Bin) -Force
}

$CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$NormalizedInstall = $InstallDir.TrimEnd('\').ToLowerInvariant()
$Entries = @()
if (-not [string]::IsNullOrWhiteSpace($CurrentUserPath)) {
    $Entries = $CurrentUserPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
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
    Write-Host "Added $InstallDir to User PATH."
} else {
    Write-Host "$InstallDir is already present in User PATH."
}

if ($CreateStartMenuShortcut) {
    $StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
    $ShortcutPath = Join-Path $StartMenuDir "Zerovault.lnk"

    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = Join-Path $InstallDir "zerovault-ui.exe"
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.Description = "Zerovault Zero-Knowledge Multi-Cloud Tray Dashboard"
    $Shortcut.Save()
    Write-Host "Created Start Menu shortcut: $ShortcutPath"
}

if ($InstallAutoStart) {
    $TaskName = "ZerovaultDaemon"
    $DaemonExe = Join-Path $InstallDir "zerovaultd.exe"
    $Action = New-ScheduledTaskAction -Execute $DaemonExe
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
    Write-Host "Registered user logon Scheduled Task '$TaskName'."
}

Write-Host "Zerovault installed to $InstallDir."
