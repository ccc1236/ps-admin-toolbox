# AD Enhanced Health Check

A PowerShell script that performs a comprehensive health check of Active Directory domain controllers and generates a visually enhanced HTML report for easy review and distribution.

## What it checks

- FSMO role holders
- Secure channel status
- SYSVOL / NETLOGON shares
- DFSR replication status
- DNS resolution
- Time synchronization
- Critical service status
- Replication summary (partner, attempts, success, delta, time offset)
- System uptime
- `dcdiag` and `repadmin` results (when run on a DC)
- Recent AD-related event logs (System, Directory Service, DNS Server, Security)
- Tombstone lifetime

## Requirements

- PowerShell **7.5+** recommended ([download](https://github.com/PowerShell/PowerShell/releases) or `winget install Microsoft.PowerShell`)
- ActiveDirectory PowerShell module
- Domain-joined machine (running on a domain controller is recommended for full `dcdiag` / `repadmin` output)
- Appropriate AD read permissions

## Usage

```powershell
.\ADEnhancedHealthCheck.ps1
```

### Parameters

| Parameter          | Default | Description                                                    |
| ------------------ | ------- | -------------------------------------------------------------- |
| `-OutputPath`      | `.`     | Directory where the HTML report will be saved                  |
| `-SkipRemoteTests` | `false` | Skip remote connectivity tests (faster, less coverage)         |
| `-TimeoutSeconds`  | `30`    | Timeout for remote operations                                  |
| `-EventLogDays`    | `7`     | How many days of event logs to pull                            |

### Examples

```powershell
# Run with defaults
.\ADEnhancedHealthCheck.ps1

# Save report to a specific folder, pull 14 days of events
.\ADEnhancedHealthCheck.ps1 -OutputPath "C:\Reports" -EventLogDays 14

# Skip remote tests for a quicker run
.\ADEnhancedHealthCheck.ps1 -SkipRemoteTests
```

## Output

An HTML file named with a timestamp (e.g. `ADHealthCheck_2026-04-15_093045.html`) is written to the `-OutputPath` directory.

## Changelog

See the `.CHANGELOG` block at the top of the script for version history.

## Author

ccc1236
