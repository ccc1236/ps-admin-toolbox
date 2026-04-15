<#
.SYNOPSIS
    Exchange Online security monitoring checks (multi-tenant).
    Detects:
      - Mailboxes with auto-forwarding to external addresses
      - Newly created end-user inbox rules (delta detection against a baseline)

.DESCRIPTION
    Runs a set of Exchange Online security hygiene checks for one or more
    tenants and writes a report per tenant.

    Run this in its OWN PowerShell session. Do not also load Microsoft.Graph
    modules in the same session — MSAL assembly conflicts will break EXO.
    Run the Graph-based sign-in check (Invoke-SignInCheck.ps1) in a separate
    PowerShell window.

    The inbox rule check uses baseline-inboxrules.json. The first run
    establishes the baseline; subsequent runs flag new rules and refresh the
    baseline.

.PARAMETER Tenant
    Tenant profile name (matches a file in .\tenants\<name>.json).
    Example: -Tenant contoso loads .\tenants\contoso.json.

.PARAMETER OutputPath
    Directory for reports and baseline. Defaults to .\reports\<tenant>\.

.EXAMPLE
    .\Invoke-M365MonitoringChecks.ps1 -Tenant contoso
    .\Invoke-M365MonitoringChecks.ps1 -Tenant home

.VERSION
    1.0

.AUTHOR
    ccc1236

.LASTUPDATED
    2026-04-15

.CHANGELOG
    v1.0 (2026-04-15):
      - Initial release: external auto-forwarding detection and new inbox rule delta detection

.NOTES
    Required: Install-Module ExchangeOnlineManagement -Scope CurrentUser

    Tenant profile schema (JSON):
      { "Name": "...", "TenantId": "<guid>", "AdminUpn": "admin@..." }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Tenant,
    [string]$OutputPath
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
$AdminUpn = $profile.AdminUpn
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot ("reports\{0}" -f $Tenant) }

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDate   = Get-Date -Format 'yyyy-MM-dd'

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$reportDir = $OutputPath  # OutputPath already tenant-scoped

$baselineFile = Join-Path $OutputPath 'baseline-inboxrules.json'
$logFile      = Join-Path $reportDir ("run-exo-{0}.log" -f $timestamp)

Write-Host ("=== Tenant: {0} ({1}) ===" -f $profile.Name, $profile.TenantId) -ForegroundColor Cyan

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

# --- Guard against Graph being loaded (causes MSAL conflict) ---------------
if (Get-Module Microsoft.Graph.Authentication) {
    Write-Log "Microsoft.Graph.Authentication is loaded in this session. Close PowerShell and run this script in a fresh window." 'ERROR'
    exit 1
}

# --- Module check ----------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Log "Missing module: ExchangeOnlineManagement. Install with: Install-Module ExchangeOnlineManagement -Scope CurrentUser" 'ERROR'
    exit 1
}

# --- Connect ---------------------------------------------------------------
Write-Log "Connecting to Exchange Online as $AdminUpn..."
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false

# =============================================================================
# Check #14 — Mailbox auto-forwarding to external addresses
# =============================================================================
Write-Log "=== Check #14: Mailbox auto-forwarding rules ==="

$acceptedDomains = (Get-AcceptedDomain).DomainName
Write-Log ("Accepted domains: {0}" -f ($acceptedDomains -join ', '))

function Test-IsExternal {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $addr = $Address -replace '^smtp:', '' -replace '^SMTP:', ''
    $domain = ($addr -split '@')[-1].Trim().ToLower()
    if ([string]::IsNullOrWhiteSpace($domain)) { return $false }
    return ($acceptedDomains -notcontains $domain)
}

$forwardingHits = New-Object System.Collections.Generic.List[object]

Write-Log "Scanning mailbox-level forwarding settings..."
$mailboxes = Get-Mailbox -ResultSize Unlimited -Filter "RecipientTypeDetails -ne 'DiscoveryMailbox'"

foreach ($mbx in $mailboxes) {
    $fwdTarget = $null
    if ($mbx.ForwardingSmtpAddress) { $fwdTarget = $mbx.ForwardingSmtpAddress }
    elseif ($mbx.ForwardingAddress)  { $fwdTarget = $mbx.ForwardingAddress }

    if ($fwdTarget -and (Test-IsExternal $fwdTarget)) {
        $forwardingHits.Add([PSCustomObject]@{
            Source            = 'MailboxSetting'
            Mailbox           = $mbx.UserPrincipalName
            ForwardTo         = $fwdTarget
            DeliverAndForward = $mbx.DeliverToMailboxAndForward
            RuleName          = $null
            RuleEnabled       = $null
        })
    }
}

Write-Log "Scanning inbox rules for external forwarding/redirect..."
foreach ($mbx in $mailboxes) {
    try {
        $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue
    } catch { continue }

    foreach ($rule in $rules) {
        $targets = @()
        $targets += $rule.ForwardTo
        $targets += $rule.ForwardAsAttachmentTo
        $targets += $rule.RedirectTo
        $externalTargets = $targets | Where-Object { $_ } | Where-Object {
            $m = [regex]::Match($_, '\[SMTP:([^\]]+)\]|SMTP:([^\s;]+)|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)')
            if ($m.Success) {
                $addr = ($m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value | Where-Object { $_ })[0]
                Test-IsExternal $addr
            } else { $false }
        }

        if ($externalTargets.Count -gt 0) {
            $forwardingHits.Add([PSCustomObject]@{
                Source            = 'InboxRule'
                Mailbox           = $mbx.UserPrincipalName
                ForwardTo         = ($externalTargets -join '; ')
                DeliverAndForward = $null
                RuleName          = $rule.Name
                RuleEnabled       = $rule.Enabled
            })
        }
    }
}

$fwdCsv = Join-Path $reportDir ("external-forwarding-{0}.csv" -f $runDate)
if ($forwardingHits.Count -gt 0) {
    $forwardingHits | Export-Csv -Path $fwdCsv -NoTypeInformation -Encoding UTF8
    Write-Log ("Found {0} external forwarding configuration(s) -> {1}" -f $forwardingHits.Count, $fwdCsv) 'WARN'
    $forwardingHits | ForEach-Object {
        Write-Log ("  [{0}] {1} -> {2} (rule: {3})" -f $_.Source, $_.Mailbox, $_.ForwardTo, $_.RuleName)
    }
} else {
    Write-Log "No external forwarding detected. Clean."
}

# =============================================================================
# Check #15 — New inbox rules (delta vs baseline)
# =============================================================================
Write-Log "=== Check #15: New inbox rules (delta detection) ==="

$currentRules = New-Object System.Collections.Generic.List[object]
foreach ($mbx in $mailboxes) {
    try {
        $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue
    } catch { continue }

    foreach ($rule in $rules) {
        $currentRules.Add([PSCustomObject]@{
            Mailbox       = $mbx.UserPrincipalName
            RuleIdentity  = $rule.Identity.ToString()
            Name          = $rule.Name
            Enabled       = $rule.Enabled
            Description   = ($rule.Description -replace '\s+', ' ').Trim()
            ForwardTo     = ($rule.ForwardTo -join '; ')
            RedirectTo    = ($rule.RedirectTo -join '; ')
            DeleteMessage = $rule.DeleteMessage
            MoveToFolder  = $rule.MoveToFolder
        })
    }
}

if (-not (Test-Path $baselineFile)) {
    Write-Log ("No baseline found - writing initial baseline of {0} rule(s) to {1}" -f $currentRules.Count, $baselineFile)
    $currentRules | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineFile -Encoding UTF8
    Write-Log "Baseline established. Run again later to detect new rules."
    $newRules = @()
} else {
    $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
    $baselineKeys = $baseline | ForEach-Object { '{0}|{1}' -f $_.Mailbox, $_.RuleIdentity }
    $baselineSet  = [System.Collections.Generic.HashSet[string]]::new([string[]]$baselineKeys)

    $newRules = $currentRules | Where-Object {
        $key = '{0}|{1}' -f $_.Mailbox, $_.RuleIdentity
        -not $baselineSet.Contains($key)
    }

    $newRulesCsv = Join-Path $reportDir ("new-inbox-rules-{0}.csv" -f $runDate)
    if ($newRules.Count -gt 0) {
        $newRules | Export-Csv -Path $newRulesCsv -NoTypeInformation -Encoding UTF8
        Write-Log ("Found {0} NEW inbox rule(s) since last baseline -> {1}" -f $newRules.Count, $newRulesCsv) 'WARN'
        $newRules | ForEach-Object {
            Write-Log ("  NEW: {0} | rule '{1}' | fwd='{2}' | redirect='{3}'" -f $_.Mailbox, $_.Name, $_.ForwardTo, $_.RedirectTo)
        }
    } else {
        Write-Log "No new inbox rules since last baseline. Clean."
    }

    $currentRules | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineFile -Encoding UTF8
    Write-Log ("Baseline refreshed ({0} rules)." -f $currentRules.Count)
}

# --- Summary & disconnect --------------------------------------------------
Write-Log "=== Summary ==="
Write-Log ("  External forwarding : {0}" -f $forwardingHits.Count)
Write-Log ("  New inbox rules     : {0}" -f $newRules.Count)
Write-Log ("Reports saved to: {0}" -f $reportDir)

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Write-Log "Done."
