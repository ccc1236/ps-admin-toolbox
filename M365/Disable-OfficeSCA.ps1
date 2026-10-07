<#
.SYNOPSIS
    Switch Microsoft 365 Apps on a PC from Shared Computer Activation (SCA) to
    normal per-user activation, and clear cached Office licensing.

.DESCRIPTION
    Fixes the activation error:

        "The products we found in your account cannot be used to activate
         Office in shared computer scenarios."

    This appears when Office was deployed with SCA enabled (for example via an
    Intune Microsoft 365 Apps deployment with "Use shared computer activation"
    set to Yes) and the user signs in with a plan that does not support SCA.
    Among business plans only Microsoft 365 Business Premium supports SCA;
    Business Standard and Apps for business do not.

    The script:
      1. Closes running Office apps so licence files are not locked.
      2. Sets HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration
         SharedComputerLicensing = "0" (machine-wide).
      3. For EVERY user profile on the PC, deletes the SCA token folder
         (%LOCALAPPDATA%\Microsoft\Office\16.0\Licensing) and the
         HKCU\Software\Microsoft\Office\16.0\Common\Licensing key. Profiles
         that are not signed in have their registry hive loaded temporarily.

    Cleaning every profile (not just the current one) means the script works
    when run elevated under a separate admin account. It is safe: Office
    rebuilds both locations at each user's next sign-in. Documents, Outlook
    data and Windows sign-in are not touched.

    After the reboot the user opens Word > File > Account and signs in.
    Product Information should show "Product Activated" with a product ID
    instead of "Shared Computer Activation".

.PARAMETER Reboot
    Restart the computer when finished. Without it, reboot manually.

.EXAMPLE
    .\Disable-OfficeSCA.ps1
    .\Disable-OfficeSCA.ps1 -Reboot

.VERSION
    1.0

.AUTHOR
    ccc1236

.LASTUPDATED
    2026-10-07

.CHANGELOG
    v1.0 (2026-10-07):
      - Initial release

.NOTES
    Must run elevated (local administrator).
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    No external modules required. Click-to-Run Office only.

    If Office is deployed by Intune with SCA on, turn it off in the Intune
    app as well, or new installs will come back in shared mode.

    Reference:
      https://learn.microsoft.com/microsoft-365-apps/licensing-activation/overview-shared-computer-activation
      https://learn.microsoft.com/office/troubleshoot/activation/reset-office-365-proplus-activation-state
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Reboot
)

$ErrorActionPreference = 'Stop'

# --- Close Office apps -----------------------------------------------------
$officeProcesses = 'WINWORD','EXCEL','POWERPNT','OUTLOOK','ONENOTE','MSACCESS','MSPUB','VISIO','WINPROJ','lync'
Get-Process -Name $officeProcesses -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host ("Closing {0}" -f $_.Name) -ForegroundColor Yellow
    $_ | Stop-Process -Force
}

# --- Turn off SCA (machine-wide) -------------------------------------------
$c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
if (-not (Test-Path $c2rKey)) {
    Write-Host "Click-to-Run Office not found ($c2rKey)." -ForegroundColor Red
    exit 1
}
$before = (Get-ItemProperty $c2rKey -Name SharedComputerLicensing -ErrorAction SilentlyContinue).SharedComputerLicensing
Set-ItemProperty $c2rKey -Name SharedComputerLicensing -Value '0' -Type String
Write-Host ("SharedComputerLicensing: '{0}' -> '0'" -f $before) -ForegroundColor Green

# --- Clear cached licensing for every user profile --------------------------
$licensingSubKey = 'Software\Microsoft\Office\16.0\Common\Licensing'
$profiles = Get-CimInstance Win32_UserProfile |
    Where-Object { -not $_.Special -and $_.LocalPath -like '*\Users\*' }

foreach ($p in $profiles) {
    $who = Split-Path $p.LocalPath -Leaf

    # SCA licence tokens
    $tokenDir = Join-Path $p.LocalPath 'AppData\Local\Microsoft\Office\16.0\Licensing'
    if (Test-Path $tokenDir) {
        Remove-Item $tokenDir -Recurse -Force
        Write-Host ("[{0}] removed SCA token folder" -f $who)
    }

    # HKCU licensing key
    if ($p.Loaded) {
        # User is signed in: hive is already mounted under HKEY_USERS\<SID>
        $key = "Registry::HKEY_USERS\$($p.SID)\$licensingSubKey"
        if (Test-Path $key) {
            Remove-Item $key -Recurse -Force
            Write-Host ("[{0}] removed licensing key" -f $who)
        }
    }
    else {
        # User not signed in: load the hive temporarily
        $hive = Join-Path $p.LocalPath 'NTUSER.DAT'
        if (-not (Test-Path $hive)) { continue }
        $mount = "TempHive_$($p.SID)"
        reg.exe load "HKU\$mount" "$hive" | Out-Null
        try {
            $key = "Registry::HKEY_USERS\$mount\$licensingSubKey"
            if (Test-Path $key) {
                Remove-Item $key -Recurse -Force
                Write-Host ("[{0}] removed licensing key" -f $who)
            }
        }
        finally {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            reg.exe unload "HKU\$mount" | Out-Null
        }
    }
}

# --- Finish -----------------------------------------------------------------
Write-Host ""
Write-Host "Done. Reboot, then the user opens Word > File > Account and signs in." -ForegroundColor Cyan
if ($Reboot) { Restart-Computer -Force }
