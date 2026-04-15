<#
.SYNOPSIS
  Inventory all VMs in a Hyper-V cluster (one row per VHD) and export to Excel.

.DESCRIPTION
  Queries each cluster node for its VMs and for each attached VHD outputs:
    - VM name
    - Host (cluster node)
    - State
    - Generation
    - Guest FQDN
    - Guest OS
    - vCPU count
    - Assigned RAM
    - Disk Path
    - Disk Size (GB)
    - Disk Used (GB)
    - Controller Type (IDE/SCSI)
    - VHD Format (VHD/VHDX)
    - NIC count
    - IP address(es)

  VMs with no disks attached are included with empty disk fields.
  Outputs to "VM-Inventory.xlsx" in the current directory.

.PARAMETER ClusterName
  Optional cluster name to target. Defaults to the local cluster.

.PARAMETER OutputPath
  Directory where the Excel file will be saved. Defaults to the current directory.

.PARAMETER OutputFile
  File name for the Excel export. Defaults to "VM-Inventory.xlsx".

.PARAMETER InstallMissingModules
  If specified, automatically installs the ImportExcel module if missing.
  Otherwise the script throws and exits.

.EXAMPLE
  .\Get-HyperVClusterInventory.ps1

.EXAMPLE
  .\Get-HyperVClusterInventory.ps1 -ClusterName HV-CL01 -OutputPath C:\Reports -OutputFile HV-CL01.xlsx

.VERSION
  1.1

.AUTHOR
  ccc1236

.LASTUPDATED
  2026-04-15

.CHANGELOG
  v1.1 (2026-04-15):
    - Added CmdletBinding and parameters (-ClusterName, -OutputPath, -OutputFile, -InstallMissingModules)
    - Added #Requires directive and Set-StrictMode
    - Module auto-install is now opt-in via -InstallMissingModules
    - Renamed output column "Type" -> "Controller Type" to match description
    - OutputPath is created if it doesn't exist

  v1.0:
    - Initial release: inventory cluster VMs + VHDs, export to Excel

.NOTES
  Requires the following modules:
    - Hyper-V
    - FailoverClusters
    - ImportExcel

  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

#Requires -Modules Hyper-V, FailoverClusters, ImportExcel

[CmdletBinding()]
param(
    [string]$ClusterName,
    [string]$OutputPath = (Get-Location).Path,
    [string]$OutputFile = 'VM-Inventory.xlsx',
    [switch]$InstallMissingModules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#-- Ensure ImportExcel is available (Hyper-V/FailoverClusters are enforced by #Requires) --
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    if ($InstallMissingModules) {
        Write-Host "Installing ImportExcel module..." -ForegroundColor Yellow
        Install-Module ImportExcel -Scope CurrentUser -Force
    }
    else {
        throw "ImportExcel module is not installed. Re-run with -InstallMissingModules or run: Install-Module ImportExcel -Scope CurrentUser"
    }
}

#-- Get all cluster nodes --
$clusterArgs = @{}
if ($PSBoundParameters.ContainsKey('ClusterName')) { $clusterArgs['Cluster'] = $ClusterName }
$nodes = (Get-ClusterNode @clusterArgs).Name

#-- Collect inventory --
$report = foreach ($node in $nodes) {
    Write-Host "Querying node $node..." -ForegroundColor Cyan

    try {
        $vms = Get-VM -ComputerName $node -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to query node '$node': $_"
        continue
    }

    foreach ($vm in $vms) {
        # Guest info from the VM object's integration services
        $guestFqdn = ''
        $guestOS   = ''
        try {
            $kvp = $vm | Get-VMIntegrationService -Name 'Key-Value Pair Exchange' -ErrorAction Stop
            if ($kvp.Enabled) {
                $guestFqdn = $vm.GuestComputerName
                $guestOS   = $vm.GuestOperatingSystem
            }
        }
        catch {
            # Integration services unavailable
        }

        # RAM: use MemoryAssigned when running, fall back to MemoryStartup
        $ramBytes = $(if ($vm.MemoryAssigned -gt 0) { $vm.MemoryAssigned } else { $vm.MemoryStartup })

        # Network info
        $nics   = Get-VMNetworkAdapter -VMName $vm.Name -ComputerName $node
        $ipList = $nics |
                  ForEach-Object { $_.IPAddresses } |
                  Where-Object { $_ } |
                  Select-Object -Unique

        # Collect VHDs
        $disks = Get-VMHardDiskDrive -VMName $vm.Name -ComputerName $node

        if ($disks) {
            # One row per attached VHD
            foreach ($hd in $disks) {
                $vhdInfo = $null
                try {
                    $vhdInfo = Get-VHD -Path $hd.Path -ComputerName $node -ErrorAction Stop
                }
                catch {
                    Write-Warning "Failed to query VHD '$($hd.Path)' on '$node': $_"
                }

                [PSCustomObject]@{
                    'VM Name'        = $vm.Name
                    'Host'           = $node
                    'State'          = $vm.State
                    'Generation'     = $vm.Generation
                    'Guest FQDN'    = $guestFqdn
                    'Guest OS'      = $guestOS
                    'vCPU'           = $vm.ProcessorCount
                    'RAM (GB)'       = [math]::Round($ramBytes / 1GB, 2)
                    'Disk Path'      = $hd.Path
                    'Disk Size (GB)' = $(if ($vhdInfo) { [math]::Round($vhdInfo.Size / 1GB, 2) } else { '' })
                    'Disk Used (GB)' = $(if ($vhdInfo) { [math]::Round($vhdInfo.FileSize / 1GB, 2) } else { '' })
                    'Controller Type' = $hd.ControllerType
                    'VHD Format'     = $(if ($vhdInfo) { $vhdInfo.VhdFormat } else { '' })
                    'NICs'           = $nics.Count
                    'IP Address'     = ($ipList -join ', ')
                }
            }
        }
        else {
            # VM has no disks — still include it in the report
            [PSCustomObject]@{
                'VM Name'        = $vm.Name
                'Host'           = $node
                'State'          = $vm.State
                'Generation'     = $vm.Generation
                'Guest FQDN'    = $guestFqdn
                'Guest OS'      = $guestOS
                'vCPU'           = $vm.ProcessorCount
                'RAM (GB)'       = [math]::Round($ramBytes / 1GB, 2)
                'Disk Path'      = ''
                'Disk Size (GB)' = ''
                'Disk Used (GB)' = ''
                'Controller Type' = ''
                'VHD Format'     = ''
                'NICs'           = $nics.Count
                'IP Address'     = ($ipList -join ', ')
            }
        }
    }
}

#-- Export to Excel --
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}
$excelPath = Join-Path $OutputPath $OutputFile
$report | Export-Excel -Path $excelPath -AutoSize -Title 'Hyper-V Cluster VM Inventory'

Write-Host "Inventory complete! Excel file saved to:`n$excelPath" -ForegroundColor Green
