# M365 / Entra ID Monitoring Scripts

Multi-tenant PowerShell scripts for routine Microsoft 365 and Entra ID (Azure AD) security hygiene checks. Each script targets a single tenant per run, reads its connection details from a JSON profile in `tenants/`, and writes reports to `reports/<tenant>/`.

## Scripts

| Script | Purpose |
| ------ | ------- |
| `Invoke-M365MonitoringChecks.ps1` | Exchange Online checks: external auto-forwarding detection and new inbox rule delta detection (against a baseline). |
| `Invoke-SignInCheck.ps1` | Entra ID sign-in log anomaly check via Microsoft Graph — flags risky sign-ins, failed MFA, unusual locations. |

Both scripts share the same `tenants/` profile schema but must be run in **separate PowerShell sessions** — the ExchangeOnlineManagement and Microsoft.Graph modules share MSAL assemblies that conflict when loaded together.

## Requirements

**For `Invoke-M365MonitoringChecks.ps1`:**

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

**For `Invoke-SignInCheck.ps1`:**

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

Required Graph scopes for the sign-in check: `AuditLog.Read.All`, `Directory.Read.All`.

You'll also need an account with appropriate admin rights in each target tenant (Exchange admin / Global Reader at minimum, depending on what you're querying).

## Tenant profiles

Each tenant you want to monitor needs a JSON profile in `tenants/`:

```json
{
  "Name": "Contoso",
  "TenantId": "00000000-0000-0000-0000-000000000000",
  "AdminUpn": "admin@contoso.onmicrosoft.com"
}
```

See `tenants/example.json` for a template. The filename (minus `.json`) is what you pass to `-Tenant`.

**Don't commit real tenant profiles** — the repo's `.gitignore` already excludes `tenants/*.json` except `example.json`.

## Usage

### Exchange Online checks

```powershell
# Run with a tenant profile named contoso (loads tenants/contoso.json)
.\Invoke-M365MonitoringChecks.ps1 -Tenant contoso

# Custom output location
.\Invoke-M365MonitoringChecks.ps1 -Tenant contoso -OutputPath C:\Reports\M365

# Insider-threat mode: flag ALL forwarding (internal + external), not just external
.\Invoke-M365MonitoringChecks.ps1 -Tenant contoso -IncludeInternal
```

The inbox rule check uses a per-tenant baseline (`baseline-inboxrules.json`). The **first run** establishes the baseline; **subsequent runs** flag new rules added since the last run and refresh the baseline.

### Entra ID sign-in check

```powershell
# Default: last 24 hours
.\Invoke-SignInCheck.ps1 -Tenant contoso

# Look back further (free tier retains 7 days; P1/P2 retains 30)
.\Invoke-SignInCheck.ps1 -Tenant contoso -SignInLookbackDays 7
```

## Output

Both scripts write timestamped reports (CSV / HTML) to `reports/<tenant>/` by default. Adjust with `-OutputPath`.

## Typical workflow

Run both as a daily security hygiene check across all your tenants:

```powershell
# PowerShell session #1
.\Invoke-M365MonitoringChecks.ps1 -Tenant contoso
.\Invoke-M365MonitoringChecks.ps1 -Tenant fabrikam

# PowerShell session #2 (separate window!)
.\Invoke-SignInCheck.ps1 -Tenant contoso
.\Invoke-SignInCheck.ps1 -Tenant fabrikam
```

## Notes

- Sign-in log retention is **7 days on the Entra free tier** and **30 days on P1/P2**. Passing a larger `-SignInLookbackDays` won't retrieve data older than your license allows.
- Baseline files are gitignored — each machine/user maintains their own baseline per tenant.
