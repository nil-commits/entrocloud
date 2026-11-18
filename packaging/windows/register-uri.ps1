<#
.SYNOPSIS
Registers and empirically verifies the per-user ec:// (primary) and zv:// (legacy compatibility)
custom URI protocol handlers under HKCU:\Software\Classes\ec and HKCU:\Software\Classes\zv.
Requires ZERO UAC / Administrator elevation.
#>
[CmdletBinding()]
param(
    [string]$UiExePath,
    [switch]$SkipBinaryCheck,
    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($UiExePath)) {
    $LocalAdjacent = Join-Path $PSScriptRoot "EntroCloud.exe"
    if (Test-Path -LiteralPath $LocalAdjacent) {
        $UiExePath = $LocalAdjacent
    } else {
        $UiExePath = Join-Path $env:LOCALAPPDATA "Programs\EntroCloud\EntroCloud.exe"
    }
}

$NormalizedUiExe = [System.IO.Path]::GetFullPath($UiExePath)

if ((-not $VerifyOnly) -and (-not $SkipBinaryCheck) -and (-not (Test-Path -LiteralPath $NormalizedUiExe))) {
    throw "EntroCloud.exe not found at '$NormalizedUiExe'. Pass -UiExePath <path> or -SkipBinaryCheck."
}

$ExpectedIcon    = "`"$NormalizedUiExe`",0"
$ExpectedCommand = "`"$NormalizedUiExe`" --open-uri `"%1`""

$Schemes = @(
    @{
        Scheme      = "ec"
        Description = "URL:EntroCloud Share Protocol"
    },
    @{
        Scheme      = "zv"
        Description = "URL:EntroCloud Legacy Share Protocol"
    }
)

if (-not $VerifyOnly) {
    foreach ($Spec in $Schemes) {
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
            $IconKey.SetValue("", $ExpectedIcon, [Microsoft.Win32.RegistryValueKind]::String)
        }
        finally {
            $IconKey.Dispose()
        }

        $CmdKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("$BaseSubKey\shell\open\command")
        try {
            $CmdKey.SetValue("", $ExpectedCommand, [Microsoft.Win32.RegistryValueKind]::String)
        }
        finally {
            $CmdKey.Dispose()
        }
    }
}

# Empirical read-back verification against BOTH HKCU:\Software\Classes\ec and HKCU:\Software\Classes\zv
foreach ($Spec in $Schemes) {
    $Scheme = $Spec.Scheme
    $PsPath = "HKCU:\Software\Classes\$Scheme"
    $WinPath = "Software\Classes\$Scheme"

    if (-not (Test-Path -LiteralPath $PsPath)) {
        throw "Verification failed: $PsPath does not exist."
    }

    $VerifyRoot = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($WinPath, $false)
    if ($null -eq $VerifyRoot) {
        throw "Verification failed: Unable to open HKCU\$WinPath."
    }
    try {
        $ActualUrlProto = $VerifyRoot.GetValue("URL Protocol", $null)
        if ($null -eq $ActualUrlProto -or $ActualUrlProto -ne "") {
            throw "Verification failed: $PsPath 'URL Protocol' must equal empty string '', got '$ActualUrlProto'."
        }
    }
    finally {
        $VerifyRoot.Dispose()
    }

    $VerifyCmd = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$WinPath\shell\open\command", $false)
    if ($null -eq $VerifyCmd) {
        throw "Verification failed: $PsPath\shell\open\command does not exist."
    }
    try {
        $ActualCommand = [string]$VerifyCmd.GetValue("", "")
        if ($VerifyOnly -and -not $PSBoundParameters.ContainsKey("UiExePath")) {
            if ($ActualCommand -notmatch '--open-uri\s+"%1"$') {
                throw "Verification failed: $PsPath command '$ActualCommand' does not end with '--open-uri `"%1`"'."
            }
        } elseif ($ActualCommand -ne $ExpectedCommand) {
            throw "Verification failed: $PsPath expected command '$ExpectedCommand', got '$ActualCommand'."
        }
        Write-Host "Verified $PsPath -> $ActualCommand"
    }
    finally {
        $VerifyCmd.Dispose()
    }
}
