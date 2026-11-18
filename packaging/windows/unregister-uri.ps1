<#
.SYNOPSIS
Idempotently removes the per-user ec:// and zv:// custom URI protocol handlers from
HKCU:\Software\Classes\ec and HKCU:\Software\Classes\zv, then verifies removal.
Requires ZERO UAC / Administrator elevation.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($Scheme in @("ec", "zv")) {
    $SubKeyPath = "Software\Classes\$Scheme"
    $PsPath     = "HKCU:\Software\Classes\$Scheme"

    $Existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKeyPath, $false)
    if ($null -ne $Existing) {
        $Existing.Dispose()
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($SubKeyPath, $false)
        Write-Host "Removed $PsPath protocol registration."
    } else {
        Write-Host "$PsPath is already unregistered (no-op)."
    }

    if (Test-Path -LiteralPath $PsPath) {
        throw "Verification failed: $PsPath still exists after removal."
    }
}
