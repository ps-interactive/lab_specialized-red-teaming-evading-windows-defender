# Establish Windows Defender Baseline
# Capture current state before evasion testing

Write-Host "`n=== Establishing Windows Defender Baseline ===" -ForegroundColor Cyan
Write-Host "[*] Capturing current security state..." -ForegroundColor Green

$baseline = @{
    Timestamp = Get-Date
    DefenderStatus = @{}
    ThreatCount = 0
    EventCount = 0
}

# Capture current Defender status
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        $baseline.DefenderStatus = @{
            RealTimeProtection = $mpStatus.RealTimeProtectionEnabled
            BehaviorMonitoring = $mpStatus.BehaviorMonitorEnabled
            AntiSpyware = $mpStatus.AntiSpywareEnabled
            AntiVirus = $mpStatus.AntivirusEnabled
            SignatureVersion = $mpStatus.AntivirusSignatureVersion
            LastUpdated = $mpStatus.AntivirusSignatureLastUpdated
        }
        
        Write-Host "[+] Defender Status Captured:" -ForegroundColor Green
        Write-Host "    Real-time Protection: $($baseline.DefenderStatus.RealTimeProtection)"
        Write-Host "    Behavior Monitoring: $($baseline.DefenderStatus.BehaviorMonitoring)"
        Write-Host "    Signature Version: $($baseline.DefenderStatus.SignatureVersion)"
    }
} catch {
    Write-Host "[-] Could not capture Defender status" -ForegroundColor Red
}

# Count current threats
try {
    $threats = Get-MpThreat -ErrorAction SilentlyContinue
    if ($threats) {
        $baseline.ThreatCount = $threats.Count
        Write-Host "[!] Existing Threats: $($baseline.ThreatCount)" -ForegroundColor Yellow
    } else {
        Write-Host "[+] No existing threats" -ForegroundColor Green
    }
} catch {
    Write-Host "[+] No threat history" -ForegroundColor Green
}

# Count recent events
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        StartTime=(Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue
    
    if ($events) {
        $baseline.EventCount = $events.Count
        Write-Host "[*] Events in last 24 hours: $($baseline.EventCount)" -ForegroundColor Cyan
        
        # Count specific event types
        $threatEvents = $events | Where-Object { $_.Id -in @(1116, 1117) }
        $scanEvents = $events | Where-Object { $_.Id -in @(1000, 1001) }
        
        Write-Host "    Threat Events: $($threatEvents.Count)"
        Write-Host "    Scan Events: $($scanEvents.Count)"
    }
} catch {
    Write-Host "[*] Could not count events" -ForegroundColor Gray
}

# Check current exclusions
try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    $pathExclusions = if ($preferences.ExclusionPath) { $preferences.ExclusionPath.Count } else { 0 }
    $processExclusions = if ($preferences.ExclusionProcess) { $preferences.ExclusionProcess.Count } else { 0 }
    
    Write-Host "`n[*] Current Exclusions:" -ForegroundColor Cyan
    Write-Host "    Path Exclusions: $pathExclusions"
    Write-Host "    Process Exclusions: $processExclusions"
    
    if ($pathExclusions -gt 0 -or $processExclusions -gt 0) {
        Write-Host "    [!] Warning: Exclusions are configured" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[*] Could not check exclusions" -ForegroundColor Gray
}

# Save baseline to file
$baselineFile = "defender_baseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
try {
    $baseline | ConvertTo-Json -Depth 3 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-Host "`n[+] Baseline saved to: $baselineFile" -ForegroundColor Green
} catch {
    Write-Host "[-] Could not save baseline file" -ForegroundColor Red
}

# Recommendations
Write-Host "`n=== Baseline Established ===" -ForegroundColor Cyan
Write-Host "[*] Recommendations before testing:" -ForegroundColor Yellow
Write-Host "    1. Note the current threat count: $($baseline.ThreatCount)"
Write-Host "    2. Real-time protection is: $($baseline.DefenderStatus.RealTimeProtection)"
Write-Host "    3. Run verify_evasion.ps1 after payload execution"
Write-Host "    4. Compare results with this baseline"

Write-Host "`n[!] Ready for evasion testing!" -ForegroundColor Magenta
