# ps-admin-toolbox

A curated collection of PowerShell scripts I use for day-to-day Windows / M365 / infrastructure administration. Each script is self-contained with its own help block (`Get-Help .\<script>.ps1 -Full`) and lives in a folder grouped by the system it targets.

## Contents

| Area | Script | Purpose |
| ---- | ------ | ------- |
| [ActiveDirectory](./ActiveDirectory) | `ADEnhancedHealthCheck.ps1` | Comprehensive AD domain controller health check with enhanced HTML report |
| [HyperV](./HyperV) | `Get-HyperVClusterInventory.ps1` | Inventory all VMs in a Hyper-V cluster (one row per VHD) and export to Excel |
| [M365](./M365) | `Invoke-M365MonitoringChecks.ps1` | Exchange Online monitoring — external auto-forwarding + new inbox rule delta detection (multi-tenant) |
| [M365](./M365) | `Invoke-SignInCheck.ps1` | Entra ID sign-in anomaly check via Microsoft Graph (multi-tenant) |
| [M365](./M365) | `Disable-OfficeSCA.ps1` | Switch Microsoft 365 Apps on a PC from shared computer activation to per-user activation and clear cached Office licensing (run on the PC, elevated) |
| [Utilities](./Utilities) | `Get-FolderTree.ps1` | Interactive folders-only tree map with custom depth |

## Requirements

Most scripts target **PowerShell 7+** and assume you're on a domain-joined or appropriately licensed management workstation. Per-script module requirements are documented in each script's header block.

Common modules you'll encounter:
- `ActiveDirectory`
- `Hyper-V`, `FailoverClusters`, `ImportExcel`
- `ExchangeOnlineManagement`
- `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`

## Usage

Each folder contains the script and (where useful) its own README with parameters and examples. General pattern:

```powershell
cd <Area>
.\<Script>.ps1 [-Param value]
```

Run `Get-Help .\<Script>.ps1 -Full` for detailed help on any script.

## Contributing / notes to self

- Bump the `Version`, `Last updated` and `Changelog` lines in the `.NOTES` section of a script's help block when making changes — don't rename the file.
- Don't add custom help keywords (e.g. `.VERSION`, `.AUTHOR`): PowerShell rejects them and silently drops the whole help block, breaking `Get-Help`. Keep script help separated from a following `function` by two blank lines.
- Keep secrets, tenant IDs, internal IPs, and hostnames out of committed code. Use parameters or a local `tenants\` / config file that's gitignored.
- Prefer parameterized scripts over hardcoded values so they're reusable across environments.

## Author

ccc1236
