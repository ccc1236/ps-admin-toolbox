<#
.SYNOPSIS
  Pester tests for Get-HyperVClusterInventory.ps1
  Mocks all Hyper-V and FailoverClusters cmdlets so no infrastructure is needed.

.NOTES
  Run with:
    Import-Module Pester -MinimumVersion 5.0 -Force
    Invoke-Pester .\Get-HyperVClusterInventory.Tests.ps1 -Output Detailed
  Requires: Pester v5+
#>

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Get-HyperVClusterInventory.ps1'

    # Define stub functions with the parameters the script actually uses.
    # Pester needs these to exist before it can mock them, and needs the
    # parameter names so mock bodies can reference them (e.g. $ComputerName).
    function global:Get-ClusterNode { }
    function global:Get-VM {
        param($ComputerName, $ErrorAction)
    }
    function global:Get-VMIntegrationService {
        param($Name, $ErrorAction, [Parameter(ValueFromPipeline)]$InputObject)
    }
    function global:Get-VMNetworkAdapter {
        param($VMName, $ComputerName)
    }
    function global:Get-VMHardDiskDrive {
        param($VMName, $ComputerName)
    }
    function global:Get-VHD {
        param($Path, $ComputerName, $ErrorAction)
    }
    function global:Export-Excel {
        param($Path, [switch]$AutoSize, $Title, [Parameter(ValueFromPipeline)]$InputObject)
    }
}

AfterAll {
    # Clean up global stubs
    $stubs = @('Get-ClusterNode','Get-VM','Get-VMIntegrationService',
               'Get-VMNetworkAdapter','Get-VMHardDiskDrive','Get-VHD','Export-Excel')
    foreach ($fn in $stubs) {
        Remove-Item -Path "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'Get-HyperVClusterInventory' {

    BeforeAll {
        #-- Mock: Module availability check (scoped to the modules the script checks) --
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name }
        } -ParameterFilter { $ListAvailable -and $Name -in @('Hyper-V','FailoverClusters','ImportExcel') }

        #-- Mock: Cluster nodes --
        Mock Get-ClusterNode {
            @(
                [PSCustomObject]@{ Name = 'NODE01' }
                [PSCustomObject]@{ Name = 'NODE02' }
            )
        }

        #-- Mock: VMs per node --
        Mock Get-VM {
            switch ($ComputerName) {
                'NODE01' {
                    @(
                        [PSCustomObject]@{
                            Name                 = 'VM-Web01'
                            State                = 'Running'
                            Generation           = 2
                            ProcessorCount       = 4
                            MemoryAssigned       = 8GB
                            MemoryStartup        = 8GB
                            GuestComputerName    = 'web01.contoso.com'
                            GuestOperatingSystem = 'Windows Server 2022'
                        }
                    )
                }
                'NODE02' {
                    @(
                        [PSCustomObject]@{
                            Name                 = 'VM-DB01'
                            State                = 'Off'
                            Generation           = 2
                            ProcessorCount       = 8
                            MemoryAssigned       = 0
                            MemoryStartup        = 16GB
                            GuestComputerName    = ''
                            GuestOperatingSystem = ''
                        },
                        [PSCustomObject]@{
                            Name                 = 'VM-NoDisk'
                            State                = 'Running'
                            Generation           = 1
                            ProcessorCount       = 2
                            MemoryAssigned       = 4GB
                            MemoryStartup        = 4GB
                            GuestComputerName    = 'nodisk.contoso.com'
                            GuestOperatingSystem = 'Windows Server 2019'
                        }
                    )
                }
            }
        }

        #-- Mock: Integration services --
        Mock Get-VMIntegrationService {
            [PSCustomObject]@{ Enabled = $true }
        }

        #-- Mock: Network adapters --
        Mock Get-VMNetworkAdapter {
            @(
                [PSCustomObject]@{ IPAddresses = @('10.0.0.10', 'fe80::1') }
            )
        }

        #-- Mock: Hard disk drives --
        Mock Get-VMHardDiskDrive {
            switch ($VMName) {
                'VM-Web01' {
                    @(
                        [PSCustomObject]@{
                            Path           = 'C:\ClusterStorage\Volume1\VM-Web01\disk0.vhdx'
                            ControllerType = 'SCSI'
                        }
                    )
                }
                'VM-DB01' {
                    @(
                        [PSCustomObject]@{
                            Path           = 'C:\ClusterStorage\Volume2\VM-DB01\disk0.vhdx'
                            ControllerType = 'SCSI'
                        },
                        [PSCustomObject]@{
                            Path           = 'C:\ClusterStorage\Volume2\VM-DB01\data.vhdx'
                            ControllerType = 'SCSI'
                        }
                    )
                }
                'VM-NoDisk' {
                    $null
                }
            }
        }

        #-- Mock: VHD info --
        Mock Get-VHD {
            switch ($Path) {
                'C:\ClusterStorage\Volume1\VM-Web01\disk0.vhdx' {
                    [PSCustomObject]@{
                        Size      = 100GB
                        FileSize  = 45GB
                        VhdFormat = 'VHDX'
                    }
                }
                'C:\ClusterStorage\Volume2\VM-DB01\disk0.vhdx' {
                    [PSCustomObject]@{
                        Size      = 200GB
                        FileSize  = 120GB
                        VhdFormat = 'VHDX'
                    }
                }
                'C:\ClusterStorage\Volume2\VM-DB01\data.vhdx' {
                    [PSCustomObject]@{
                        Size      = 500GB
                        FileSize  = 300GB
                        VhdFormat = 'VHDX'
                    }
                }
            }
        }

        #-- Mock: Export-Excel (no-op, don't write files) --
        Mock Export-Excel {}

        #-- Mock: Write-Host (suppress console output) --
        Mock Write-Host {}

        #-- Run the script --
        . $scriptPath
    }

    It 'Should query all cluster nodes' {
        # Verified by data: we get VMs from both NODE01 and NODE02
        $hosts = $report | Select-Object -ExpandProperty Host -Unique
        $hosts | Should -Contain 'NODE01'
        $hosts | Should -Contain 'NODE02'
    }

    It 'Should produce one row per VHD (3 disks + 1 diskless VM = 4 rows)' {
        $report | Should -HaveCount 4
    }

    It 'Should include correct VM names' {
        $names = $report | Select-Object -ExpandProperty 'VM Name' -Unique
        $names | Should -Contain 'VM-Web01'
        $names | Should -Contain 'VM-DB01'
        $names | Should -Contain 'VM-NoDisk'
    }

    It 'Should assign correct host per VM' {
        ($report | Where-Object { $_.'VM Name' -eq 'VM-Web01' })[0].Host | Should -Be 'NODE01'
        ($report | Where-Object { $_.'VM Name' -eq 'VM-DB01' })[0].Host | Should -Be 'NODE02'
    }

    It 'Should use MemoryStartup when VM is off (MemoryAssigned = 0)' {
        ($report | Where-Object { $_.'VM Name' -eq 'VM-DB01' })[0].'RAM (GB)' | Should -Be 16
    }

    It 'Should use MemoryAssigned when VM is running' {
        ($report | Where-Object { $_.'VM Name' -eq 'VM-Web01' })[0].'RAM (GB)' | Should -Be 8
    }

    It 'Should include diskless VMs with empty disk fields' {
        $noDisk = ($report | Where-Object { $_.'VM Name' -eq 'VM-NoDisk' })[0]
        $noDisk.'Disk Path'       | Should -Be ''
        $noDisk.'Disk Size (GB)'  | Should -Be ''
        $noDisk.'Disk Used (GB)'  | Should -Be ''
        $noDisk.'Controller Type' | Should -Be ''
        $noDisk.'VHD Format'      | Should -Be ''
    }

    It 'Should produce correct disk sizes for each VHD' {
        $web = ($report | Where-Object { $_.'VM Name' -eq 'VM-Web01' })[0]
        $web.'Disk Size (GB)' | Should -Be 100
        $web.'Disk Used (GB)' | Should -Be 45

        $dbDisks = $report | Where-Object { $_.'VM Name' -eq 'VM-DB01' }
        ($dbDisks | Select-Object -ExpandProperty 'Disk Size (GB)') | Should -Contain 200
        ($dbDisks | Select-Object -ExpandProperty 'Disk Size (GB)') | Should -Contain 500
    }

    It 'Should report IP addresses' {
        ($report | Where-Object { $_.'VM Name' -eq 'VM-Web01' })[0].'IP Address' | Should -Match '10\.0\.0\.10'
    }

    It 'Should call Export-Excel once' {
        Should -Invoke Export-Excel -Times 1 -Exactly
    }

    It 'Should have report data ready for export' {
        $report | Should -Not -BeNullOrEmpty
        $report | Should -HaveCount 4
    }
}

Describe 'Get-HyperVClusterInventory - Node failure handling' {

    BeforeAll {
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name }
        } -ParameterFilter { $ListAvailable -and $Name -in @('Hyper-V','FailoverClusters','ImportExcel') }

        Mock Get-ClusterNode {
            @(
                [PSCustomObject]@{ Name = 'BADNODE' }
                [PSCustomObject]@{ Name = 'GOODNODE' }
            )
        }

        # BADNODE throws, GOODNODE returns a VM
        Mock Get-VM {
            if ($ComputerName -eq 'BADNODE') {
                throw 'RPC server is unavailable'
            }
            @(
                [PSCustomObject]@{
                    Name                 = 'VM-OK'
                    State                = 'Running'
                    Generation           = 2
                    ProcessorCount       = 2
                    MemoryAssigned       = 4GB
                    MemoryStartup        = 4GB
                    GuestComputerName    = 'ok.contoso.com'
                    GuestOperatingSystem = 'Windows Server 2022'
                }
            )
        }

        Mock Get-VMIntegrationService { [PSCustomObject]@{ Enabled = $true } }
        Mock Get-VMNetworkAdapter { @([PSCustomObject]@{ IPAddresses = @('10.0.0.5') }) }
        Mock Get-VMHardDiskDrive {
            @([PSCustomObject]@{ Path = 'C:\disk.vhdx'; ControllerType = 'SCSI' })
        }
        Mock Get-VHD {
            [PSCustomObject]@{ Size = 50GB; FileSize = 20GB; VhdFormat = 'VHDX' }
        }
        Mock Export-Excel {}
        Mock Write-Host {}
        Mock Write-Warning {}

        . $scriptPath
    }

    It 'Should skip the failed node and only return data from the healthy one' {
        $report | Should -HaveCount 1
        $report[0].Host | Should -Be 'GOODNODE'
    }

    It 'Should still collect data from the healthy node' {
        $report | Should -HaveCount 1
        $report[0].'VM Name' | Should -Be 'VM-OK'
    }

    It 'Should emit a warning for the failed node' {
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}
