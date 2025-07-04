<#
.SYNOPSIS
AD Health Check - Enhanced Version

Performs a comprehensive health check of Active Directory domain controllers and generates an enhanced HTML report.

.DESCRIPTION
This script runs a set of diagnostics across all domain controllers in the current AD forest. It collects data such as:
- FSMO role holders
- Secure channel status
- SYSVOL/NETLOGON shares
- DFSR replication status
- DNS resolution checks
- Time synchronization info
- Critical service status
- Replication summary (partner, attempts, success, delta, time offset)
- System uptime
- dcdiag and repadmin results (on DCs only)
- Recent AD-related event logs

Results are formatted into a visually enhanced HTML report for easy review and distribution.

.VERSION
1.4

.AUTHOR
HS

.LASTUPDATED
2025-06-25

.NOTES
Run this script on a domain-joined machine with the Active Directory PowerShell module available.
Running the script from a domain controller is recommended to get full results including `dcdiag` and `repadmin` output.

"This AD Health Check script requires PowerShell 7.5+ for optimal compatibility.
Download: https://github.com/PowerShell/PowerShell/releases
Or: winget install Microsoft.PowerShell"
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [switch]$SkipRemoteTests,
    [int]$TimeoutSeconds = 30,
    [int]$EventLogDays = 7
)

# Initialize variables
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$report = @()
$dnsTestResults = @()
$dnsDetailedResults = @()
$replicationResults = @()
$errorLog = @()
$tombstoneInfo = $null
$eventLogResults = @()

# Function to log errors
function Write-ErrorLog {
    param($Message, $Exception = $null)
    $errorEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Message = $Message
        Exception = if ($Exception) { $Exception.ToString() } else { "N/A" }
    }
    $script:errorLog += $errorEntry
    Write-Warning $Message
}

# Function to get AD-related event logs
function Get-ADRelevantEventLogs {
    param(
        [string]$ComputerName,
        [int]$Days = 7,
        [int]$MaxEvents = 5
    )
    
    $eventLogs = @()
    $startTime = (Get-Date).AddDays(-$Days)
    
    # Define AD-related event IDs and their descriptions
    $adEventIds = @{
        # System Log - Critical AD Events
        1000 = "Application Error"
        1001 = "Application Hang"
        1074 = "System Shutdown/Restart"
        6005 = "Event Log Service Started"
        6006 = "Event Log Service Stopped"
        6008 = "Unexpected System Shutdown"
        6009 = "System Start"
        
        # Directory Service Log - NTDS Events
        1173 = "Directory Service Startup"
        1394 = "Replication Error"
        1311 = "KCC Error"
        2042 = "Tombstone Lifetime Exceeded"
        1586 = "LDAP over SSL Error"
        1925 = "Replication Link Establishment Failed"
        1644 = "Directory Service Startup Complete"
        1216 = "Directory Service Database Recovery"
        
        # DNS Server Log
        4013 = "DNS Server Failed to Load Zone"
        4015 = "DNS Server Zone Transfer Failed"
        6702 = "DNS Server Zone Dynamic Update Failed"
        
        # Security Log - AD Authentication
        4625 = "Failed Logon"
        4740 = "Account Lockout"
        4771 = "Kerberos Pre-authentication Failed"
        4776 = "Credential Validation Failed"
    }
    
    # Event logs to check
    $logNames = @("System", "Directory Service", "DNS Server", "Security")
    
    foreach ($logName in $logNames) {
        try {
            Write-Host "  Checking $logName event log on $ComputerName..." -ForegroundColor Cyan
            
            $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName = $logName
                StartTime = $startTime
                Level = 1,2,3  # Critical, Error, Warning
            } -MaxEvents 20 -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.Id -in $adEventIds.Keys -or 
                $_.LevelDisplayName -eq "Critical" -or 
                ($_.LevelDisplayName -eq "Error" -and $_.Id -in @(1394, 1925, 2042, 4013, 4015, 6702))
            } | 
            Select-Object -First $MaxEvents
            
            foreach ($event in $events) {
                $eventDescription = if ($adEventIds.ContainsKey($event.Id)) { 
                    $adEventIds[$event.Id] 
                } else { 
                    "AD-Related Event" 
                }
                
                $eventLogs += [PSCustomObject]@{
                    ComputerName = $ComputerName
                    LogName = $logName
                    TimeCreated = $event.TimeCreated
                    Level = $event.LevelDisplayName
                    EventId = $event.Id
                    Source = $event.ProviderName
                    Description = $eventDescription
                    Message = ($event.Message -split "`n")[0] # First line only
                    FullMessage = $event.Message
                }
            }
        }
        catch {
            Write-ErrorLog "Failed to retrieve $logName event log from $ComputerName" $_
            $eventLogs += [PSCustomObject]@{
                ComputerName = $ComputerName
                LogName = $logName
                TimeCreated = (Get-Date)
                Level = "Error"
                EventId = "N/A"
                Source = "Health Check Script"
                Description = "Event Log Access Failed"
                Message = "Unable to access $logName event log: $($_.Exception.Message)"
                FullMessage = $_.Exception.ToString()
            }
        }
    }
    
    # Return the most recent events, sorted by time
    return $eventLogs | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents
}

# Function to test remote connectivity
function Test-RemoteConnectivity {
    param($ComputerName)
    try {
        $result = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Function to get DC uptime
Function Get-DCUpTime($computername) {
    try {
        $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem -ComputerName $computername).LastBootupTime
    }
    catch [exception] {
        $uptimeResult = "Failed"
        $uptimeReason = "Unable to retrieve system uptime"
        return $uptimeResult, $uptimeReason
    }
    
    if ($uptime.TotalHours -lt 100 ) {
        $uptimeResult = [Math]::Round(($uptime | Select -ExpandProperty TotalHours),0,[MidPointRounding]::AwayFromZero)
        $uptimeResult = [string]$uptimeResult + " hrs"

        if ($uptime.TotalHours -lt 24 ) {
            $uptimeReason = "Only running for $uptimeResult"
            $uptimeResult = "Warning"
        }
    }else{
        $uptimeResult = [Math]::Round(($uptime | Select -ExpandProperty TotalDays),0,[MidPointRounding]::AwayFromZero)
        $uptimeResult = [string]$uptimeResult + " days"
    }
    
    return $uptimeResult, $uptimeReason
}

# Function to get replication data (updated with realistic thresholds)
function Get-ReplicationData($computername) {
    $repPartnerData = Get-ADReplicationPartnerMetadata -Target $computername

    $replResult = @{}

    # Get the replication partner
    $replResult.repPartner = ($RepPartnerData.Partner -split ',')[1] -replace 'CN=', '';

    # Last attempt - Industry best practice thresholds
    try {
        $replResult.lastRepAttempt = @()
        $replLastRepAttempt = ($repPartnerData | Where-Object {$_.Partner -match ($replResult.repPartner)}).LastReplicationAttempt
        $minutesSinceAttempt = ((Get-Date) - $replLastRepAttempt).TotalMinutes
        
        if ($minutesSinceAttempt -ge 60) {
            $replResult.lastRepAttempt += "Failed"
            $replResult.lastRepAttempt += "More than 60 minutes ago: $($replLastRepAttempt.ToString('yyyy-MM-dd HH:mm'))"
        } elseif ($minutesSinceAttempt -ge 15) {
            $replResult.lastRepAttempt += "Warning"
            $replResult.lastRepAttempt += "More than 15 minutes ago: $($replLastRepAttempt.ToString('yyyy-MM-dd HH:mm'))"
        } else {
            $replResult.lastRepAttempt += "Success: $($replLastRepAttempt.ToString('yyyy-MM-dd HH:mm'))"
        }

        # Last successful replication - Industry best practice thresholds
        $replResult.lastRepSuccess = @()
        $replLastRepSuccess = ($repPartnerData | Where-Object {$_.Partner -match ($replResult.repPartner)}).LastReplicationSuccess
        $minutesSinceSuccess = ((Get-Date) - $replLastRepSuccess).TotalMinutes
        
        if ($minutesSinceSuccess -ge 60) {
            $replResult.lastRepSuccess += "Failed"
            $replResult.lastRepSuccess += "More than 60 minutes ago: $($replLastRepSuccess.ToString('yyyy-MM-dd HH:mm'))"
        } elseif ($minutesSinceSuccess -ge 15) {
            $replResult.lastRepSuccess += "Warning"
            $replResult.lastRepSuccess += "More than 15 minutes ago: $($replLastRepSuccess.ToString('yyyy-MM-dd HH:mm'))"
        } else {
            $replResult.lastRepSuccess += "Success: $($replLastRepSuccess.ToString('yyyy-MM-dd HH:mm'))"
        }

        # Get failure count
        $replResult.failureCount = @()
        $replFailureCount = (Get-ADReplicationFailure -Target $computername).FailureCount
        if ($null -eq $replFailureCount) { 
            $replResult.failureCount += "Success"
        }else{
            $replResult.failureCount += "Failed"
            $replResult.failureCount += "$replFailureCount failed attempts"
        }

        # Get replication delta - Industry best practice thresholds
        $replResult.delta = @()
        $replDelta = (Get-Date) - $replLastRepAttempt
        $deltaMinutes = $replDelta.TotalMinutes

        # Check delta with realistic thresholds
        if ($deltaMinutes -ge 60) {
            $replResult.delta += "Failed"
            $replResult.delta += "Delta is more than 60 minutes: $([Math]::Round($deltaMinutes, 0)) minutes"
        } elseif ($deltaMinutes -ge 15) {
            $replResult.delta += "Warning"
            $replResult.delta += "Delta is more than 15 minutes: $([Math]::Round($deltaMinutes, 0)) minutes"
        } else {
            $replResult.delta += "Success: Less than 15 minutes"
        }
    }
    catch [exception]{
        $replResult.lastRepAttempt += "Failed"
        $replResult.lastRepAttempt += "Unable to retrieve replication data"
        $replResult.lastRepSuccess += "Failed"
        $replResult.lastRepSuccess += "Unable to retrieve replication data"
        $replResult.failureCount += "Failed"
        $replResult.failureCount += "Unable to retrieve replication data"
        $replResult.delta += "Failed"
        $replResult.delta += "Unable to retrieve replication data"
    }

    return $replResult
}

# Function to check tombstone lifetime
function Get-TombstoneLifetime {
    try {
        # Get the tombstone lifetime from AD configuration
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $tombstoneLifetime = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime
        
        # Default is 60 days if not set (Windows 2003 SP1 and later)
        if ($null -eq $tombstoneLifetime -or $tombstoneLifetime -eq 0) {
            $tombstoneLifetime = 60
            $isDefault = $true
        } else {
            $isDefault = $false
        }
        
        # Calculate recommended backup frequency (tombstoneLifetime - 1/3)
        $maxBackupAge = [Math]::Floor($tombstoneLifetime * 2/3)
        
        # Warning if tombstone lifetime is too low
        if ($tombstoneLifetime -lt 30) {
            $status = "Warning"
            $message = "Tombstone lifetime is $tombstoneLifetime days (recommended: 60+ days)"
        } elseif ($tombstoneLifetime -lt 60) {
            $status = "Warning"
            $message = "Tombstone lifetime is $tombstoneLifetime days (consider increasing to 60+ days)"
        } else {
            $status = "Success"
            $message = "Tombstone lifetime is $tombstoneLifetime days"
        }
        
        return @{
            Status = $status
            TombstoneLifetime = $tombstoneLifetime
            MaxBackupAge = $maxBackupAge
            Message = $message
            IsDefault = $isDefault
        }
    } catch {
        return @{
            Status = "Failed"
            Message = "Unable to retrieve tombstone lifetime: $($_.Exception.Message)"
            TombstoneLifetime = "Unknown"
            MaxBackupAge = "Unknown"
            IsDefault = $false
        }
    }
}

# Function for enhanced DNS health checks
function Get-DNSHealthDetails($domainController) {
    $dnsResults = @{
        ForwardLookup = @{ Status = "Unknown"; Message = "" }
        ReverseLookup = @{ Status = "Unknown"; Message = "" }
        ZoneHealth = @{ Status = "Unknown"; Message = "" }
        Forwarders = @{ Status = "Unknown"; Message = "" }
    }
    
    try {
        # Test forward DNS lookup for the domain
        $domainName = (Get-ADDomain).DNSRoot
        $forwardLookup = Resolve-DnsName -Name $domainName -Server $domainController -ErrorAction Stop
        if ($forwardLookup) {
            $dnsResults.ForwardLookup.Status = "Success"
            $dnsResults.ForwardLookup.Message = "Forward lookup successful"
        }
    } catch {
        $dnsResults.ForwardLookup.Status = "Failed"
        $dnsResults.ForwardLookup.Message = "Forward lookup failed: $($_.Exception.Message)"
    }
    
    try {
        # Test reverse DNS lookup
        $dcIP = (Get-ADDomainController -Identity $domainController).IPv4Address
        $reverseLookup = Resolve-DnsName -Name $dcIP -Server $domainController -ErrorAction Stop
        if ($reverseLookup) {
            $dnsResults.ReverseLookup.Status = "Success"  
            $dnsResults.ReverseLookup.Message = "Reverse lookup successful"
        }
    } catch {
        $dnsResults.ReverseLookup.Status = "Failed"
        $dnsResults.ReverseLookup.Message = "Reverse lookup failed: $($_.Exception.Message)"
    }
    
    # Check DNS zones and forwarders (requires remote PowerShell)
    try {
        $dnsInfo = Invoke-Command -ComputerName $domainController -ScriptBlock {
            $zones = Get-DnsServerZone -ErrorAction SilentlyContinue
            $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
            
            return @{
                Zones = $zones
                Forwarders = $forwarders
            }
        } -ErrorAction Stop
        
        # Analyze zones
        if ($dnsInfo.Zones) {
            $adZones = $dnsInfo.Zones | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsAutoCreated -eq $false }
            if ($adZones.Count -gt 0) {
                $dnsResults.ZoneHealth.Status = "Success"
                $dnsResults.ZoneHealth.Message = "$($adZones.Count) primary zones found"
            } else {
                $dnsResults.ZoneHealth.Status = "Warning"
                $dnsResults.ZoneHealth.Message = "No primary zones found"
            }
        }
        
        # Analyze forwarders
        if ($dnsInfo.Forwarders -and $dnsInfo.Forwarders.IPAddress.Count -gt 0) {
            $dnsResults.Forwarders.Status = "Success"
            $dnsResults.Forwarders.Message = "Forwarders configured: $($dnsInfo.Forwarders.IPAddress -join ', ')"
        } else {
            $dnsResults.Forwarders.Status = "Warning"
            $dnsResults.Forwarders.Message = "No DNS forwarders configured"
        }
        
    } catch {
        $dnsResults.ZoneHealth.Status = "Failed"
        $dnsResults.ZoneHealth.Message = "Unable to check DNS zones remotely"
        $dnsResults.Forwarders.Status = "Failed"
        $dnsResults.Forwarders.Message = "Unable to check forwarders remotely"
    }
    
    return $dnsResults
}

# Function to get time difference with proper formatting
function Get-TimeDifference($computername) {
    # credits: https://stackoverflow.com/a/63050189
    try {
        $currentTime, $timeDifference = (& w32tm /stripchart /computer:$computername /samples:1 /dataonly)[-1].Trim("s") -split ',\s*'
        $diff = [double]$timeDifference

        # Convert to seconds and round to 4 decimal places
        $diffSeconds = [Math]::Round($diff, 4, [MidPointRounding]::AwayFromZero)

        if ([Math]::Abs($diffSeconds) -ge 1) {
            $timeResult = "Failed"
            $timeReason = "Offset greater than 1 second: ${diffSeconds}s"
        } else {
            $timeResult = "Success: ${diffSeconds}s"
            $timeReason = ""
        }
        return $timeResult, $timeReason
    } catch {
        return "Failed", "Unable to retrieve time offset"
    }
}

# Verify we're running on a domain-joined machine and check if we're on a DC
try {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
    
    # Check if we're running on a domain controller
    $isDomainController = $false
    try {
        $localDC = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue
        if ($localDC) {
            $isDomainController = $true
            Write-Host "Running on Domain Controller: $env:COMPUTERNAME" -ForegroundColor Green
        } else {
            Write-Host "Running on Domain Member: $env:COMPUTERNAME" -ForegroundColor Yellow
            Write-Host "Note: Some advanced diagnostics may not be available from non-DC machines" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Running on Domain Member: $env:COMPUTERNAME" -ForegroundColor Yellow
    }
} catch {
    Write-Error "This script must be run on a domain-joined machine with AD PowerShell module."
    exit 1
}

# Test secure channel with nltest
Write-Host "Testing secure channel on LOCAL machine with nltest..." -ForegroundColor Cyan
try {
    $nltestResult = nltest /sc_query:$env:COMPUTERNAME 2>&1
    if ($nltestResult -match "The secure channel is not working") {
        $localSecureChannel = $false
        Write-ErrorLog "Failed to test secure channel with nltest" $nltestResult
        Write-Host "Local secure channel test failed!" -ForegroundColor Red
    } else {
        $localSecureChannel = $true
        Write-Host "Local secure channel status: $localSecureChannel" -ForegroundColor Green
    }
} catch {
    $localSecureChannel = $false
    Write-ErrorLog "Failed to test secure channel with nltest" $_
    Write-Host "Local secure channel test failed!" -ForegroundColor Red
}

# Get FSMO roles with error handling
Write-Host "Querying FSMO role holders..." -ForegroundColor Cyan
try {
    $fsmo = netdom query fsmo 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "netdom query fsmo failed with exit code $LASTEXITCODE"
    }
    # Filter out the "The command completed successfully." line and join
    $fsmo = ($fsmo | Where-Object { $_ -notmatch "The command completed successfully" }) -join "`n"
} catch {
    Write-ErrorLog "Failed to query FSMO roles" $_
    $fsmo = "Error retrieving FSMO roles: $($_.Exception.Message)"
}

# Get Domain Controllers with error handling
try {
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    Write-Host "Found $($dcs.Count) domain controllers" -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve domain controllers: $($_.Exception.Message)"
    exit 1
}

# Get tombstone lifetime information (only needs to be done once)
Write-Host "Checking tombstone lifetime..." -ForegroundColor Cyan
$tombstoneInfo = Get-TombstoneLifetime

foreach ($dc in $dcs) {
    Write-Host "`nChecking $($dc.HostName)..." -ForegroundColor Cyan
    
    # Initialize DC report object
    $dcReport = [PSCustomObject]@{
        Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        DomainController = $dc.HostName
        IPAddress        = $dc.IPv4Address
        Uptime           = "Unknown"
        Site             = $dc.Site
        IsGlobalCatalog  = $dc.IsGlobalCatalog
        IsReadOnly       = $dc.IsReadOnly
        OperatingSystem  = $dc.OperatingSystem
        Ping             = $false
        SecureChannel    = "N/A"
        SYSVOL           = $false
        NETLOGON         = $false
        TimeSource       = "Unknown"
        TimeOffset       = "Unknown"
        DFSR_Status      = "Unknown"
        RemoteAccessible = $false
        Services         = "Unknown"
        EventLogErrors   = 0
    }

    # Ping test with compatibility for different PowerShell versions
    try {
        # Try modern PowerShell first (6.0+)
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $dcReport.Ping = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -TimeoutSeconds 5
        } else {
            # For Windows PowerShell 5.1 and earlier
            $dcReport.Ping = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet
        }
    } catch {
        Write-ErrorLog "Ping failed for $($dc.HostName)" $_
        # Fallback to basic ping command if Test-Connection fails
        try {
            $pingResult = ping $dc.HostName -n 1 -w 3000
            $dcReport.Ping = $pingResult -match "Reply from" -and $pingResult -notmatch "Request timed out"
        } catch {
            $dcReport.Ping = $false
        }
    }

    # Get uptime
    try {
        $uptimeData = Get-DCUpTime -computername $dc.HostName
        $dcReport.Uptime = if ($uptimeData -is [array] -and $uptimeData[0] -eq "Warning") {
            $uptimeData[1]  # Show the reason for warning
        } elseif ($uptimeData -is [array] -and $uptimeData[0] -eq "Failed") {
            "Failed"
        } else {
            $uptimeData[0]  # Show the uptime value
        }
    } catch {
        Write-ErrorLog "Failed to get uptime for $($dc.HostName)" $_
        $dcReport.Uptime = "Failed"
    }

    # Test remote connectivity if not skipping remote tests
    if (-not $SkipRemoteTests) {
        $dcReport.RemoteAccessible = Test-RemoteConnectivity $dc.HostName
    }

    # Only test secure channel on local machine
    if ($dc.HostName -ieq $env:COMPUTERNAME -or $dc.HostName -ieq "$env:COMPUTERNAME.$($domain.DNSRoot)") {
        $dcReport.SecureChannel = $localSecureChannel
    }

    # SYSVOL & NETLOGON shares test
    if ($dcReport.Ping -and (-not $SkipRemoteTests -or $dcReport.SecureChannel -ne "N/A")) {
        try {
            $job = Start-Job -ScriptBlock {
                param($ComputerName)
                try {
                    $shares = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        (net share 2>$null) -match '^(SYSVOL|NETLOGON)'
                    } -ErrorAction Stop
                    return $shares
                } catch {
                    return $null
                }
            } -ArgumentList $dc.HostName
            
            $shares = Wait-Job $job -Timeout $TimeoutSeconds | Receive-Job
            Remove-Job $job -Force
            
            if ($shares) {
                $dcReport.SYSVOL = ($shares -match "SYSVOL").Count -gt 0
                $dcReport.NETLOGON = ($shares -match "NETLOGON").Count -gt 0
            }
        } catch {
            Write-ErrorLog "Failed to check shares on $($dc.HostName)" $_
        }
    }

    # Time sync check
    if ($dcReport.Ping -and $dcReport.RemoteAccessible) {
        try {
            $job = Start-Job -ScriptBlock {
                param($ComputerName)
                try {
                    $timeStatus = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        w32tm /query /status 2>&1
                    } -ErrorAction Stop
                    return $timeStatus
                } catch {
                    return $null
                }
            } -ArgumentList $dc.HostName
            
            $timeStatus = Wait-Job $job -Timeout $TimeoutSeconds | Receive-Job
            Remove-Job $job -Force
            
            if ($timeStatus) {
                $sourceMatch = $timeStatus | Select-String "Source"
                if ($sourceMatch) {
                    $dcReport.TimeSource = ($sourceMatch.Line -split ":")[-1].Trim()  # Accessing the Line property
                }
                $offsetMatch = $timeStatus | Select-String "Last Successful Sync Time|Poll Interval"
                if ($offsetMatch) {
                    $dcReport.TimeOffset = ($offsetMatch[0].Line -split ":")[-1].Trim()  # Accessing the Line property
                }
            }
        } catch {
            Write-ErrorLog "Failed to check time sync on $($dc.HostName)" $_
        }
    }

    # DFSR status check
    if ($dcReport.Ping -and $dcReport.RemoteAccessible) {
        try {
            $job = Start-Job -ScriptBlock {
                param($ComputerName)
                try {
                    $dfsrState = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        try {
                            # Check DFSR service first
                            $service = Get-Service -Name "DFSR" -ErrorAction SilentlyContinue
                            if (-not $service -or $service.Status -ne "Running") {
                                return "DFSR Service Not Running"
                            }
                            
                            # Check DFSR replication state
                            $dfsr = Get-WmiObject -Namespace "root\MicrosoftDFS" -Class DfsrReplicatedFolderInfo -ErrorAction SilentlyContinue
                            if ($dfsr) {
                                $healthyCount = ($dfsr | Where-Object {$_.State -eq 4}).Count
                                $totalCount = $dfsr.Count
                                return "DFSR: $healthyCount/$totalCount folders healthy"
                            } else {
                                return "No DFSR Data Found"
                            }
                        } catch {
                            return "DFSR Check Failed: $($_.Exception.Message)"
                        }
                    } -ErrorAction Stop
                    return $dfsrState
                } catch {
                    return "Remote DFSR Check Failed"
                }
            } -ArgumentList $dc.HostName
            
            $dcReport.DFSR_Status = Wait-Job $job -Timeout $TimeoutSeconds | Receive-Job
            Remove-Job $job -Force
        } catch {
            Write-ErrorLog "Failed to check DFSR on $($dc.HostName)" $_
        }
    }

    # Check critical services
    if ($dcReport.Ping -and $dcReport.RemoteAccessible) {
        try {
            $job = Start-Job -ScriptBlock {
                param($ComputerName)
                try {
                    $services = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        $criticalServices = @("NTDS", "DNS", "KDC", "W32Time", "Netlogon")
                        $serviceStatus = @()
                        foreach ($svc in $criticalServices) {
                            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                            if ($service) {
                                $serviceStatus += "${svc}: $($service.Status)"  # Add each service status to a new line
                            } else {
                                $serviceStatus += "${svc}: Service not found"  # If the service is not found
                            }
                        }
                        return $serviceStatus -join "`n"  # Join services with newlines
                    } -ErrorAction Stop
                    return $services
                } catch {
                    return "Service check failed"
                }
            } -ArgumentList $dc.HostName
            
            $dcReport.Services = Wait-Job $job -Timeout $TimeoutSeconds | Receive-Job
            Remove-Job $job -Force
        } catch {
            Write-ErrorLog "Failed to check services on $($dc.HostName)" $_
        }
    }

    # Get AD-related event logs (only from local DC to avoid RPC issues)
    if ($dc.HostName -ieq $env:COMPUTERNAME -or $dc.HostName -ieq "$env:COMPUTERNAME.$($domain.DNSRoot)") {
        Write-Host "  Collecting AD-related event logs for LOCAL DC: $($dc.HostName)..." -ForegroundColor Cyan
        $dcEventLogs = Get-ADRelevantEventLogs -ComputerName "localhost" -Days $EventLogDays -MaxEvents 5
        $eventLogResults += $dcEventLogs
        
        # Count critical/error events for summary
        $dcReport.EventLogErrors = ($dcEventLogs | Where-Object { $_.Level -in @("Critical", "Error") }).Count
    } else {
        # Skip event log collection for remote DCs to avoid RPC errors
        Write-Host "  Skipping event log collection for remote DC: $($dc.HostName) (run script locally on each DC for event logs)" -ForegroundColor Yellow
        $dcReport.EventLogErrors = 0
    }

    # DNS resolution test from this DC to others
    if ($dcReport.Ping) {
        foreach ($targetDC in $dcs) {
            if ($dc.Name -ne $targetDC.Name) {
                try {
                    $resolved = Resolve-DnsName -Name $targetDC.HostName -Server $dc.HostName -ErrorAction Stop -Type A
                    $dnsTestResults += [PSCustomObject]@{
                        SourceDC = $dc.HostName
                        TargetDC = $targetDC.HostName
                        Resolved = $true
                        IP       = ($resolved | Where-Object {$_.Type -eq "A"}).IPAddress -join ", "
                        RecordType = "A"
                    }
                } catch {
                    Write-ErrorLog "DNS resolution failed from $($dc.HostName) to $($targetDC.HostName)" $_
                    $dnsTestResults += [PSCustomObject]@{
                        SourceDC = $dc.HostName
                        TargetDC = $targetDC.HostName
                        Resolved = $false
                        IP       = "Resolution failed: $($_.Exception.Message)"
                        RecordType = "A"
                    }
                }
            }
        }
        
        # Get detailed DNS health information
        Write-Host "Getting detailed DNS health for $($dc.HostName)..." -ForegroundColor Cyan
        $dnsDetails = Get-DNSHealthDetails -domainController $dc.HostName
        $dnsDetailedResults += [PSCustomObject]@{
            DomainController = $dc.HostName
            ForwardLookup = "$($dnsDetails.ForwardLookup.Status): $($dnsDetails.ForwardLookup.Message)"
            ReverseLookup = "$($dnsDetails.ReverseLookup.Status): $($dnsDetails.ReverseLookup.Message)"
            ZoneHealth = "$($dnsDetails.ZoneHealth.Status): $($dnsDetails.ZoneHealth.Message)"
            Forwarders = "$($dnsDetails.Forwarders.Status): $($dnsDetails.Forwarders.Message)"
        }
    }

    # Get replication data
    if ($dcReport.Ping) {
        try {
            Write-Host "Getting replication data for $($dc.HostName)..." -ForegroundColor Cyan
            $repData = Get-ReplicationData -computername $dc.HostName
            $timeOffset = Get-TimeDifference -computername $dc.HostName
            
            $replicationResults += [PSCustomObject]@{
                DomainController = $dc.HostName
                ReplicationPartner = $repData.repPartner
                LastAttempt = if ($repData.lastRepAttempt -is [array]) { $repData.lastRepAttempt -join " - " } else { $repData.lastRepAttempt }
                LastSuccess = if ($repData.lastRepSuccess -is [array]) { $repData.lastRepSuccess -join " - " } else { $repData.lastRepSuccess }
                ReplicationDelta = if ($repData.delta -is [array]) { $repData.delta -join " - " } else { $repData.delta }
                TimeOffset = if ($timeOffset -is [array]) { $timeOffset[0] } else { $timeOffset }
            }
        } catch {
            Write-ErrorLog "Failed to get replication data for $($dc.HostName)" $_
            $replicationResults += [PSCustomObject]@{
                DomainController = $dc.HostName
                ReplicationPartner = "Failed to retrieve"
                LastAttempt = "Failed to retrieve"
                LastSuccess = "Failed to retrieve"
                ReplicationDelta = "Failed to retrieve"
                TimeOffset = "Failed to retrieve"
            }
        }
    }

    # Add results to report
    $report += $dcReport
}

# Run diagnostic commands locally with error handling (only on DCs)
if ($isDomainController) {
    Write-Host "`nRunning local diagnostics (Domain Controller detected)..." -ForegroundColor Yellow

    # dcdiag
    try {
        Write-Host "Running dcdiag..." -ForegroundColor Cyan
        $dcdiag = dcdiag /v 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "dcdiag completed with warnings or errors (exit code: $LASTEXITCODE)"
        }
    } catch {
        Write-ErrorLog "Failed to run dcdiag" $_
        $dcdiag = "Error running dcdiag: $($_.Exception.Message)"
    }

    # repadmin
    try {
        Write-Host "Running repadmin /replsummary..." -ForegroundColor Cyan
        $replSummary = repadmin /replsummary 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "repadmin completed with warnings or errors (exit code: $LASTEXITCODE)"
        }
    } catch {
        Write-ErrorLog "Failed to run repadmin" $_
        $replSummary = "Error running repadmin: $($_.Exception.Message)"
    }

    # Additional repadmin checks
    try {
        Write-Host "Running repadmin /showrepl..." -ForegroundColor Cyan
        $replStatus = repadmin /showrepl 2>&1 | Out-String
    } catch {
        Write-ErrorLog "Failed to run repadmin /showrepl" $_
        $replStatus = "Error running repadmin /showrepl: $($_.Exception.Message)"
    }
} else {
    Write-Host "`nSkipping dcdiag/repadmin (not running on a Domain Controller)..." -ForegroundColor Yellow
    $dcdiag = "dcdiag output not available - script not run from a Domain Controller"
    $replSummary = "repadmin /replsummary output not available - script not run from a Domain Controller"
    $replStatus = "repadmin /showrepl output not available - script not run from a Domain Controller"
}

# Build enhanced HTML report
$html = @"
<!DOCTYPE html>
<html><head>
    <title>Active Directory Health Report - $timestamp</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 20px; 
            background: #f5f5f5; 
            color: #333; 
            line-height: 1.6;
        }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2E5D9F; border-bottom: 3px solid #2E5D9F; padding-bottom: 10px; }
        h2 { color: #4A90A4; margin-top: 30px; }
        h3 { color: #666; }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px 8px; 
            text-align: left; 
            font-size: 0.9em;
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
            text-align: center;
        }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f0f8ff; }
        .ok { background-color: #d4edda !important; color: #155724; }
        .fail { background-color: #f8d7da !important; color: #721c24; }
        .warning { background-color: #fff3cd !important; color: #856404; }
        .na { background-color: #e2e3e5 !important; color: #6c757d; }
        .info-box { 
            background: #e3f2fd; 
            border-left: 4px solid #2196f3; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 4px;
        }
        .error-box { 
            background: #ffebee; 
            border-left: 4px solid #f44336; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 4px;
        }
        details { 
            margin-bottom: 20px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            overflow: hidden;
        }
        summary { 
            font-weight: bold; 
            font-size: 1.1em; 
            cursor: pointer; 
            padding: 15px; 
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
        }
        summary:hover { background: #e9ecef; }
        pre { 
            background: #f8f9fa; 
            padding: 15px; 
            border: 1px solid #e9ecef; 
            overflow: auto; 
            max-height: 500px; 
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85em;
            line-height: 1.4;
        }
        .stats { 
            display: flex; 
            justify-content: space-around; 
            margin: 20px 0; 
            flex-wrap: wrap;
        }
        .stat-item { 
            text-align: center; 
            padding: 15px; 
            background: white; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 5px;
            min-width: 120px;
        }
        .stat-number { font-size: 2em; font-weight: bold; color: #2E5D9F; }
        .stat-label { color: #666; font-size: 0.9em; }
        .status-indicator { 
            display: inline-block; 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            margin-right: 8px; 
        }
        .status-healthy { background-color: #28a745; }
        .status-warning { background-color: #ffc107; }
        .status-critical { background-color: #dc3545; }
        .status-unknown { background-color: #6c757d; }
        .event-critical { background-color: #f8d7da !important; color: #721c24; font-weight: bold; }
        .event-error { background-color: #f8d7da !important; color: #721c24; }
        .event-warning { background-color: #fff3cd !important; color: #856404; }
        .event-info { background-color: #d1ecf1 !important; color: #0c5460; }
        .event-message { font-size: 0.85em; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        
        /* Ensure details/summary works in all browsers */
        details > summary {
            list-style: none;
            cursor: pointer;
            user-select: none;
        }
        
        details > summary::-webkit-details-marker {
            display: none;
        }
        
        details > summary::before {
            content: '▶ ';
            font-size: 0.8em;
            margin-right: 5px;
            transition: transform 0.2s;
        }
        
        details[open] > summary::before {
            content: '▼ ';
        }
        
        details > summary:hover {
            background: #e9ecef !important;
        }
        
        details[open] > summary {
            border-bottom: 1px solid #ddd;
        }
        
        /* Content inside details */
        details > *:not(summary) {
            padding: 0;
            margin: 0;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            details[open] summary ~ * { display: block !important; }
        }
    </style>
</head><body>
<div class="container">
<h1>🏢 Active Directory Health Report</h1>
<div class="info-box">
    <strong>Generated:</strong> $timestamp<br>
    <strong>Domain:</strong> $($domain.DNSRoot)<br>
    <strong>Forest Level:</strong> $($domain.ForestMode)<br>
    <strong>Domain Level:</strong> $($domain.DomainMode)<br>
    <strong>Event Log Period:</strong> Last $EventLogDays days
</div>
"@

# Add statistics
$totalDCs = $report.Count
$healthyDCs = ($report | Where-Object {$_.Ping -and ($_.SecureChannel -eq $true -or $_.SecureChannel -eq "N/A") -and $_.SYSVOL -and $_.NETLOGON}).Count
$failedDCs = $totalDCs - $healthyDCs
$dnsIssues = ($dnsTestResults | Where-Object {-not $_.Resolved}).Count
$criticalEvents = ($eventLogResults | Where-Object { $_.Level -eq "Critical" }).Count
$errorEvents = ($eventLogResults | Where-Object { $_.Level -eq "Error" }).Count

$html += @"
<div class="stats">
    <div class="stat-item">
        <div class="stat-number">$totalDCs</div>
        <div class="stat-label">Total DCs</div>
    </div>
    <div class="stat-item">
        <div class="stat-number" style="color: #28a745;">$healthyDCs</div>
        <div class="stat-label">Healthy DCs</div>
    </div>
    <div class="stat-item">
        <div class="stat-number" style="color: #dc3545;">$failedDCs</div>
        <div class="stat-label">Issues Found</div>
    </div>
    <div class="stat-item">
        <div class="stat-number" style="color: #ffc107;">$dnsIssues</div>
        <div class="stat-label">DNS Issues</div>
    </div>
    <div class="stat-item">
        <div class="stat-number" style="color: #dc3545;">$criticalEvents</div>
        <div class="stat-label">Critical Events</div>
    </div>
    <div class="stat-item">
        <div class="stat-number" style="color: #ffc107;">$errorEvents</div>
        <div class="stat-label">Error Events</div>
    </div>
</div>
"@

# Add error summary if there are errors
if ($errorLog.Count -gt 0) {
    $html += @"
<div class="error-box">
    <h3>⚠️ Errors Encountered During Health Check</h3>
    <p>$($errorLog.Count) errors were logged during the health check. See details section below.</p>
</div>
"@
}

$html += @"
<h2>🏛️ FSMO Role Holders</h2>
<pre>$([System.Web.HttpUtility]::HtmlEncode($fsmo))</pre>

<h2>🖥️ Domain Controllers Summary</h2>
<table>
<tr>
    <th>Domain Controller</th>
    <th>IP Address</th>
    <th>Uptime</th>
    <th>Site</th>
    <th>GC</th>
    <th>RODC</th>
    <th>OS</th>
    <th>Ping</th>
    <th>Secure Channel</th>
    <th>SYSVOL</th>
    <th>NETLOGON</th>
    <th>Time Source</th>
    <th>DFSR Status</th>
    <th>Services</th>
    <th>Event Errors</th>
</tr>
"@

foreach ($entry in $report) {
    $pingClass = if ($entry.Ping) { "ok" } else { "fail" }
    $pingIcon = if ($entry.Ping) { "✅" } else { "❌" }
    
    $secureClass = switch ($entry.SecureChannel.ToString()) {
        "True" { "ok" }
        "N/A" { "na" }
        default { "fail" }
    }
    $secureIcon = switch ($entry.SecureChannel.ToString()) {
        "True" { "✅" }
        "N/A" { "ℹ️" }
        default { "❌" }
    }
    
    $sysvolClass = if ($entry.SYSVOL) { "ok" } else { "fail" }
    $sysvolIcon = if ($entry.SYSVOL) { "✅" } else { "❌" }
    
    $netlogonClass = if ($entry.NETLOGON) { "ok" } else { "fail" }
    $netlogonIcon = if ($entry.NETLOGON) { "✅" } else { "❌" }
    
    $dfsrClass = if ($entry.DFSR_Status -like "*healthy*" -or $entry.DFSR_Status -like "*Healthy*") { 
        "ok" 
    } elseif ($entry.DFSR_Status -eq "Unknown") { 
        "na" 
    } else { 
        "warning" 
    }

    # Uptime class based on content
    $uptimeClass = if ($entry.Uptime -like "*Failed*") {
        "fail"
    } elseif ($entry.Uptime -like "*Only running*") {
        "warning"
    } else {
        "ok"
    }

    # Event log errors class
    $eventErrorClass = if ($entry.EventLogErrors -eq 0) {
        "ok"
    } elseif ($entry.EventLogErrors -le 2) {
        "warning"
    } else {
        "fail"
    }

    $html += "<tr>"
    $html += "<td><strong>$($entry.DomainController)</strong></td>"
    $html += "<td>$($entry.IPAddress)</td>"
    $html += "<td class='$uptimeClass'>$($entry.Uptime)</td>"
    $html += "<td>$($entry.Site)</td>"
    $html += "<td>$($entry.IsGlobalCatalog)</td>"
    $html += "<td>$($entry.IsReadOnly)</td>"
    $html += "<td>$($entry.OperatingSystem)</td>"
    $html += "<td class='$pingClass'>$pingIcon $($entry.Ping)</td>"
    $html += "<td class='$secureClass'>$secureIcon $($entry.SecureChannel)</td>"
    $html += "<td class='$sysvolClass'>$sysvolIcon $($entry.SYSVOL)</td>"
    $html += "<td class='$netlogonClass'>$netlogonIcon $($entry.NETLOGON)</td>"
    $html += "<td>$($entry.TimeSource)</td>"
    $html += "<td class='$dfsrClass'>$($entry.DFSR_Status)</td>"
    $html += "<td><pre>$($entry.Services)</pre></td>"
    $html += "<td class='$eventErrorClass'>$($entry.EventLogErrors)</td>"
    $html += "</tr>"
}

$html += "</table>"

# Tombstone Lifetime section
$tombstoneClass = if ($tombstoneInfo.Status -eq "Success") { "ok" } elseif ($tombstoneInfo.Status -eq "Warning") { "warning" } else { "fail" }
$html += @"
<h2>⚰️ Tombstone Lifetime Status</h2>
<table>
<tr><th>Setting</th><th>Value</th><th>Status</th></tr>
<tr>
    <td><strong>Tombstone Lifetime</strong></td>
    <td>$($tombstoneInfo.TombstoneLifetime) days</td>
    <td class='$tombstoneClass'>$($tombstoneInfo.Message)</td>
</tr>
<tr>
    <td><strong>Max Backup Age</strong></td>
    <td>$($tombstoneInfo.MaxBackupAge) days</td>
    <td class='na'>Backups must be newer than this</td>
</tr>
<tr>
    <td><strong>Configuration</strong></td>
    <td>$(if ($tombstoneInfo.IsDefault) { "Default (60 days)" } else { "Custom ($($tombstoneInfo.TombstoneLifetime) days)" })</td>
    <td class='na'>Current setting</td>
</tr>
</table>

<h2>🌐 DNS Resolution Tests Between Domain Controllers</h2>
<table>
<tr><th>Source DC</th><th>Target DC</th><th>Status</th><th>Resolved IP(s)</th></tr>
"@

foreach ($dnsEntry in $dnsTestResults) {
    $dnsClass = if ($dnsEntry.Resolved) { "ok" } else { "fail" }
    $dnsIcon = if ($dnsEntry.Resolved) { "✅" } else { "❌" }
    $html += "<tr>"
    $html += "<td>$($dnsEntry.SourceDC)</td>"
    $html += "<td>$($dnsEntry.TargetDC)</td>"
    $html += "<td class='$dnsClass'>$dnsIcon $($dnsEntry.Resolved)</td>"
    $html += "<td>$($dnsEntry.IP)</td>"
    $html += "</tr>"
}

$html += "</table>"

# Enhanced DNS Health section
$html += @"
<h2>🔍 DNS Health Details</h2>
<table>
<tr><th>Domain Controller</th><th>Forward Lookup</th><th>Reverse Lookup</th><th>Zone Health</th><th>Forwarders</th></tr>
"@

foreach ($dnsDetail in $dnsDetailedResults) {
    # Determine classes based on status
    $forwardClass = if ($dnsDetail.ForwardLookup -like "Success:*") { "ok" } elseif ($dnsDetail.ForwardLookup -like "Warning:*") { "warning" } else { "fail" }
    $reverseClass = if ($dnsDetail.ReverseLookup -like "Success:*") { "ok" } elseif ($dnsDetail.ReverseLookup -like "Warning:*") { "warning" } else { "fail" }
    $zoneClass = if ($dnsDetail.ZoneHealth -like "Success:*") { "ok" } elseif ($dnsDetail.ZoneHealth -like "Warning:*") { "warning" } else { "fail" }
    $forwardersClass = if ($dnsDetail.Forwarders -like "Success:*") { "ok" } elseif ($dnsDetail.Forwarders -like "Warning:*") { "warning" } else { "fail" }

    $html += "<tr>"
    $html += "<td><strong>$($dnsDetail.DomainController)</strong></td>"
    $html += "<td class='$forwardClass'>$($dnsDetail.ForwardLookup)</td>"
    $html += "<td class='$reverseClass'>$($dnsDetail.ReverseLookup)</td>"
    $html += "<td class='$zoneClass'>$($dnsDetail.ZoneHealth)</td>"
    $html += "<td class='$forwardersClass'>$($dnsDetail.Forwarders)</td>"
    $html += "</tr>"
}

$html += "</table>"

# Replication Summary section
$html += @"
<h2>🔄 Replication Summary</h2>
<table>
<tr><th>Domain Controller</th><th>Replication Partner</th><th>Last Attempt</th><th>Last Success</th><th>Replication Delta</th><th>Time Offset</th></tr>
"@

foreach ($replEntry in $replicationResults) {
    # Determine classes based on content
    $attemptClass = if ($replEntry.LastAttempt -like "*Failed*") {
        "fail"
    } elseif ($replEntry.LastAttempt -like "*Warning*") {
        "warning"
    } else {
        "ok"
    }

    $successClass = if ($replEntry.LastSuccess -like "*Failed*") {
        "fail"
    } elseif ($replEntry.LastSuccess -like "*Warning*") {
        "warning"
    } else {
        "ok"
    }

    $deltaClass = if ($replEntry.ReplicationDelta -like "*Failed*") {
        "fail"
    } elseif ($replEntry.ReplicationDelta -like "*Warning*") {
        "warning"
    } else {
        "ok"
    }

    $offsetClass = if ($replEntry.TimeOffset -like "*Failed*") {
        "fail"
    } elseif ($replEntry.TimeOffset -like "*Warning*") {
        "warning"
    } else {
        "ok"
    }

    $html += "<tr>"
    $html += "<td><strong>$($replEntry.DomainController)</strong></td>"
    $html += "<td>$($replEntry.ReplicationPartner)</td>"
    $html += "<td class='$attemptClass'>$($replEntry.LastAttempt)</td>"
    $html += "<td class='$successClass'>$($replEntry.LastSuccess)</td>"
    $html += "<td class='$deltaClass'>$($replEntry.ReplicationDelta)</td>"
    $html += "<td class='$offsetClass'>$($replEntry.TimeOffset)</td>"
    $html += "</tr>"
}

$html += "</table>"

# Error log section
if ($errorLog.Count -gt 0) {
    $html += @"
<h2>⚠️ Error Log</h2>
<details><summary>Show Error Details ($($errorLog.Count) errors)</summary>
<table>
<tr><th>Timestamp</th><th>Error Message</th><th>Exception Details</th></tr>
"@
    foreach ($error in $errorLog) {
        $html += "<tr class='fail'>"
        $html += "<td>$($error.Timestamp)</td>"
        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($error.Message))</td>"
        $html += "<td><small>$([System.Web.HttpUtility]::HtmlEncode($error.Exception))</small></td>"
        $html += "</tr>"
    }
    $html += "</table></details>"
}

# Diagnostic sections
$html += @"
<h2>🔍 Detailed Diagnostics</h2>

<details><summary>📊 Show dcdiag Output</summary>
<pre>$([System.Web.HttpUtility]::HtmlEncode($dcdiag))</pre>
</details>

<details><summary>🔄 Show repadmin /replsummary Output</summary>
<pre>$([System.Web.HttpUtility]::HtmlEncode($replSummary))</pre>
</details>

<details><summary>🔄 Show repadmin /showrepl Output</summary>
<pre>$([System.Web.HttpUtility]::HtmlEncode($replStatus))</pre>
</details>
"@

# NEW EVENT LOG SECTION
if ($eventLogResults.Count -gt 0) {
    $html += @"
<h2>📋 Recent AD-Related Event Logs (Last $EventLogDays days)</h2>
<details><summary>Show Recent Event Logs ($($eventLogResults.Count) events found)</summary>
<table>
<tr><th>DC</th><th>Time</th><th>Log</th><th>Level</th><th>Event ID</th><th>Source</th><th>Description</th><th>Message</th><th>Details</th></tr>
"@
    
    foreach ($event in ($eventLogResults | Sort-Object TimeCreated -Descending)) {
        $eventClass = switch ($event.Level) {
            "Critical" { "event-critical" }
            "Error" { "event-error" }
            "Warning" { "event-warning" }
            default { "event-info" }
        }
        
        $levelIcon = switch ($event.Level) {
            "Critical" { "🔥" }
            "Error" { "❌" }
            "Warning" { "⚠️" }
            default { "ℹ️" }
        }
        
        $html += "<tr class='$eventClass'>"
        $html += "<td><strong>$($event.ComputerName)</strong></td>"
        $html += "<td>$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td>"
        $html += "<td>$($event.LogName)</td>"
        $html += "<td>$levelIcon $($event.Level)</td>"
        $html += "<td>$($event.EventId)</td>"
        $html += "<td>$($event.Source)</td>"
        $html += "<td>$($event.Description)</td>"
        $html += "<td class='event-message' title='$([System.Web.HttpUtility]::HtmlEncode($event.Message))'>$([System.Web.HttpUtility]::HtmlEncode($event.Message))</td>"
        $html += "<td><details><summary>Full Details</summary><pre>$([System.Web.HttpUtility]::HtmlEncode($event.FullMessage))</pre></details></td>"
        $html += "</tr>"
    }
    
    $html += "</table></details>"
} else {
    $html += @"
<h2>📋 Recent AD-Related Event Logs (Last $EventLogDays days)</h2>
<div class="info-box">
    <p>✅ No Critical or Error events found in AD-related event logs for the specified time period.</p>
</div>
"@
}

$html += @"

</div>
</body></html>
"@

# Save the report
$htmlFile = Join-Path $OutputPath "ADHealthCheck_$($env:COMPUTERNAME)_$timestamp.html"
try {
    $html | Out-File $htmlFile -Encoding UTF8 -ErrorAction Stop
    Write-Host "`n✅ AD Health check complete!" -ForegroundColor Green
    Write-Host "📄 Report saved to: $htmlFile" -ForegroundColor Cyan
    
    # Summary output
    Write-Host "`n📊 SUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total Domain Controllers: $totalDCs" -ForegroundColor White
    Write-Host "   Healthy Domain Controllers: $healthyDCs" -ForegroundColor Green
    Write-Host "   Domain Controllers with Issues: $failedDCs" -ForegroundColor Red
    Write-Host "   DNS Resolution Issues: $dnsIssues" -ForegroundColor Yellow
    Write-Host "   Critical Events Found: $criticalEvents" -ForegroundColor Red
    Write-Host "   Error Events Found: $errorEvents" -ForegroundColor Yellow
    Write-Host "   Errors Logged: $($errorLog.Count)" -ForegroundColor Red
    Write-Host "   Event Log Period: Last $EventLogDays days" -ForegroundColor Cyan
    
    if ($failedDCs -gt 0 -or $dnsIssues -gt 0 -or $criticalEvents -gt 0 -or $errorEvents -gt 0 -or $errorLog.Count -gt 0) {
        Write-Host "`n⚠️  Issues detected! Please review the HTML report for details." -ForegroundColor Red
    } else {
        Write-Host "`n✅ All domain controllers appear healthy with no critical events!" -ForegroundColor Green
    }
    
} catch {
    Write-Error "Failed to save report: $($_.Exception.Message)"
    exit 1
}

# Optional: Open the report
if ($env:OS -eq "Windows_NT") {
    $openReport = Read-Host "`nWould you like to open the report now? (Y/N)"
    if ([string]::IsNullOrWhiteSpace($openReport) -or $openReport -eq "Y" -or $openReport -eq "y") {
        try {
            Start-Process $htmlFile
        } catch {
            Write-Warning "Could not open report automatically. Please open: $htmlFile"
        }
    }
}
