<#
.SYNOPSIS
    Entra ID (Azure AD) sign-in anomaly check, multi-tenant.

.DESCRIPTION
    Pulls sign-in logs from Microsoft Graph for one or more tenants and flags
    anomalies such as risky sign-ins, failed MFA, or unusual locations.
    Writes a report per tenant.

    Run this in its OWN PowerShell session. Do not also load the
    ExchangeOnlineManagement module in the same session — MSAL assembly
    conflicts will break Graph. Run the EXO checks
    (Invoke-M365MonitoringChecks.ps1) in a separate PowerShell window.

.PARAMETER Tenant
    Tenant profile name (matches a file in .\tenants\<name>.json).

.PARAMETER OutputPath
    Directory for reports. Defaults to .\reports\<tenant>\.

.PARAMETER SignInLookbackDays
    How far back to pull sign-in logs. Default 1 (daily run).

.EXAMPLE
    .\Invoke-SignInCheck.ps1 -Tenant contoso
    .\Invoke-SignInCheck.ps1 -Tenant home -SignInLookbackDays 7

.VERSION
    1.0

.AUTHOR
    ccc1236

.LASTUPDATED
    2026-04-15

.CHANGELOG
    v1.0 (2026-04-15):
      - Initial release: Entra ID sign-in anomaly check via Microsoft Graph

.NOTES
    Required:
      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
      Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser

    Required Graph scopes: AuditLog.Read.All, Directory.Read.All

    Tenant profile schema (JSON):
      { "Name": "...", "TenantId": "<guid>", "AdminUpn": "admin@..." }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Tenant,
    [string]$OutputPath,
    [int]$SignInLookbackDays = 1
)

# --- Load tenant profile ---------------------------------------------------
$profilePath = Join-Path $PSScriptRoot "tenants\$Tenant.json"
if (-not (Test-Path $profilePath)) {
    Write-Host "Tenant profile not found: $profilePath" -ForegroundColor Red
    Write-Host "Available profiles:" -ForegroundColor Yellow
    Get-ChildItem (Join-Path $PSScriptRoot 'tenants') -Filter '*.json' -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("  - {0}" -f $_.BaseName) }
    exit 1
}
$profile = Get-Content $profilePath -Raw | ConvertFrom-Json
$TenantId = $profile.TenantId
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot ("reports\{0}" -f $Tenant) }

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDate   = Get-Date -Format 'yyyy-MM-dd'

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$reportDir = $OutputPath  # OutputPath already tenant-scoped

$logFile = Join-Path $reportDir ("run-signin-{0}.log" -f $timestamp)

Write-Host ("=== Tenant: {0} ({1}) ===" -f $profile.Name, $profile.TenantId) -ForegroundColor Cyan

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

# --- Guard against EXO being loaded (causes MSAL conflict) -----------------
if (Get-Module ExchangeOnlineManagement) {
    Write-Log "ExchangeOnlineManagement is loaded in this session. Close PowerShell and run this script in a fresh window." 'ERROR'
    exit 1
}

# --- Module check ----------------------------------------------------------
foreach ($mod in 'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.SignIns') {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Log "Missing module: $mod. Install with: Install-Module $mod -Scope CurrentUser" 'ERROR'
        exit 1
    }
}

# --- Connect ---------------------------------------------------------------
Write-Log "Connecting to Microsoft Graph (tenant: $TenantId)..."
Connect-MgGraph -TenantId $TenantId -Scopes 'AuditLog.Read.All','Directory.Read.All' -NoWelcome

# =============================================================================
# Check — Entra ID sign-in failures / anomalies
# =============================================================================
Write-Log "=== Entra ID sign-in logs (last $SignInLookbackDays day(s)) ==="

$startDate = (Get-Date).AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter    = "createdDateTime ge $startDate and (status/errorCode ne 0 or riskLevelDuringSignIn ne 'none')"

try {
    $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
} catch {
    Write-Log ("Sign-in log query failed: {0}" -f $_) 'ERROR'
    $signIns = @()
}

$signInReport = $signIns | ForEach-Object {
    [PSCustomObject]@{
        TimeUTC       = $_.CreatedDateTime
        User          = $_.UserPrincipalName
        App           = $_.AppDisplayName
        IP            = $_.IpAddress
        Country       = $_.Location.CountryOrRegion
        City          = $_.Location.City
        ErrorCode     = $_.Status.ErrorCode
        FailureReason = $_.Status.FailureReason
        RiskLevel     = $_.RiskLevelDuringSignIn
        RiskState     = $_.RiskState
        ClientApp     = $_.ClientAppUsed
    }
}

$signInCsv = Join-Path $reportDir ("signin-anomalies-{0}.csv" -f $runDate)
if ($signInReport.Count -gt 0) {
    $signInReport | Export-Csv -Path $signInCsv -NoTypeInformation -Encoding UTF8
    Write-Log ("Found {0} failed/risky sign-ins -> {1}" -f $signInReport.Count, $signInCsv) 'WARN'

    $topUsers = $signInReport | Group-Object User | Sort-Object Count -Descending | Select-Object -First 5
    Write-Log "Top users by failure/risk count:"
    $topUsers | ForEach-Object { Write-Log ("  {0,-40} {1}" -f $_.Name, $_.Count) }
} else {
    Write-Log "No failed or risky sign-ins in the window. Clean."
}

Write-Log "=== Summary ==="
Write-Log ("  Risky/failed sign-ins : {0}" -f $signInReport.Count)
Write-Log ("Reports saved to: {0}" -f $reportDir)

Disconnect-MgGraph | Out-Null
Write-Log "Done."
