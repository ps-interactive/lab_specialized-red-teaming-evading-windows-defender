# Test Windows Defender Status
# Check real-time protection and recent detections

Write-Host "`n=== Windows Defender Status Check ===" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator. Some checks may fail." -ForegroundColor Yellow
}

# Check Windows Defender service status
Write-Host "`n[*] Checking Windows Defender Service Status..." -ForegroundColor Green
try {
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defenderService) {
        Write-Host "    Service Name: $($defenderService.Name)"
        Write-Host "    Status: $($defenderService.Status)" -ForegroundColor $(if($defenderService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "    Start Type: $($defenderService.StartType)"
    } else {
        Write-Host "    [-] Windows Defender service not found" -ForegroundColor Red
    }
} catch {
    Write-Host "    [-] Error checking service: $_" -ForegroundColor Red
}

# Check Real-time Protection status
Write-Host "`n[*] Checking Real-time Protection Status..." -ForegroundColor Green
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($mpStatus) {
        Write-Host "    Real-time Protection: $($mpStatus.RealTimeProtectionEnabled)" -ForegroundColor $(if($mpStatus.RealTimeProtectionEnabled){"Yellow"}else{"Green"})
        Write-Host "    Behavior Monitoring: $($mpStatus.BehaviorMonitorEnabled)"
        Write-Host "    AntiSpyware Enabled: $($mpStatus.AntiSpywareEnabled)"
        Write-Host "    AntiVirus Enabled: $($mpStatus.AntivirusEnabled)"
        Write-Host "    Last Quick Scan: $($mpStatus.QuickScanEndTime)"
        Write-Host "    Last Full Scan: $($mpStatus.FullScanEndTime)"
    } else {
        Write-Host "    [-] Could not retrieve Defender status" -ForegroundColor Red
    }
} catch {
    Write-Host "    [-] Error getting MP status: $_" -ForegroundColor Red
}

# Check signature versions
Write-Host "`n[*] Checking Signature Versions..." -ForegroundColor Green
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        Write-Host "    AntiSpyware Signature Version: $($mpStatus.AntiSpywareSignatureVersion)"
        Write-Host "    AntiVirus Signature Version: $($mpStatus.AntivirusSignatureVersion)"
        Write-Host "    Last Updated: $($mpStatus.AntivirusSignatureLastUpdated)"
    }
} catch {
    Write-Host "    [-] Error checking signatures: $_" -ForegroundColor Red
}

# Check recent threats
Write-Host "`n[*] Checking Recent Threat Detections..." -ForegroundColor Green
try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 5
    
    if ($threats) {
        Write-Host "    [!] Recent threats detected:" -ForegroundColor Yellow
        foreach ($threat in $threats) {
            Write-Host "        Threat ID: $($threat.ThreatID)"
            Write-Host "        Detection Time: $($threat.InitialDetectionTime)"
            Write-Host "        Process: $($threat.ProcessName)"
            Write-Host "        ---"
        }
    } else {
        Write-Host "    [+] No recent threats detected" -ForegroundColor Green
    }
} catch {
    if ($_.Exception.Message -like "*No threats*") {
        Write-Host "    [+] No threats in detection history" -ForegroundColor Green
    } else {
        Write-Host "    [*] Could not retrieve threat history (may require admin)" -ForegroundColor Yellow
    }
}

# Check exclusions
Write-Host "`n[*] Checking Configured Exclusions..." -ForegroundColor Green
try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($preferences.ExclusionPath) {
        Write-Host "    Path Exclusions:" -ForegroundColor Yellow
        foreach ($path in $preferences.ExclusionPath) {
            Write-Host "        - $path"
        }
    } else {
        Write-Host "    [*] No path exclusions configured"
    }
    
    if ($preferences.ExclusionProcess) {
        Write-Host "    Process Exclusions:" -ForegroundColor Yellow
        foreach ($process in $preferences.ExclusionProcess) {
            Write-Host "        - $process"
        }
    } else {
        Write-Host "    [*] No process exclusions configured"
    }
} catch {
    Write-Host "    [*] Could not retrieve exclusions (may require admin)" -ForegroundColor Yellow
}

Write-Host "`n=== Status Check Complete ===" -ForegroundColor Cyan
Write-Host "[!] If evasion successful, no new threats should appear above" -ForegroundColor Magenta
