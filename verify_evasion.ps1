# Verify Evasion Success
# Comprehensive check to confirm Windows Defender did not detect the payload

Write-Host "`n=== Evasion Verification Script ===" -ForegroundColor Cyan
Write-Host "[*] Performing comprehensive evasion checks..." -ForegroundColor Green

$evasionSuccess = $true
$issues = @()

# 1. Check for active threats
Write-Host "`n[1/5] Checking for active threats..." -ForegroundColor Yellow
try {
    $threats = Get-MpThreat -ErrorAction SilentlyContinue
    if ($threats) {
        Write-Host "    [-] ACTIVE THREATS DETECTED:" -ForegroundColor Red
        foreach ($threat in $threats) {
            Write-Host "        Threat: $($threat.ThreatName)"
            Write-Host "        Severity: $($threat.SeverityID)"
        }
        $evasionSuccess = $false
        $issues += "Active threats detected"
    } else {
        Write-Host "    [+] No active threats" -ForegroundColor Green
    }
} catch {
    Write-Host "    [*] Could not check threats (may indicate no threats)" -ForegroundColor Gray
}

# 2. Check threat history
Write-Host "`n[2/5] Checking threat detection history..." -ForegroundColor Yellow
try {
    $detectionHistory = Get-MpThreatDetection -ErrorAction SilentlyContinue | 
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-1) }
    
    if ($detectionHistory) {
        Write-Host "    [-] RECENT DETECTIONS FOUND:" -ForegroundColor Red
        foreach ($detection in $detectionHistory | Select-Object -First 3) {
            Write-Host "        Time: $($detection.InitialDetectionTime)"
            Write-Host "        Threat ID: $($detection.ThreatID)"
        }
        $evasionSuccess = $false
        $issues += "Recent threat detections in history"
    } else {
        Write-Host "    [+] No recent detections in history" -ForegroundColor Green
    }
} catch {
    Write-Host "    [+] No threat detection history (good sign)" -ForegroundColor Green
}

# 3. Check if real-time protection is still enabled
Write-Host "`n[3/5] Checking real-time protection status..." -ForegroundColor Yellow
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus.RealTimeProtectionEnabled) {
        Write-Host "    [+] Real-time protection still enabled (payload not caught)" -ForegroundColor Green
    } else {
        Write-Host "    [!] Real-time protection is disabled" -ForegroundColor Yellow
        $issues += "Real-time protection disabled"
    }
} catch {
    Write-Host "    [*] Could not check protection status" -ForegroundColor Gray
}

# 4. Check quarantine
Write-Host "`n[4/5] Checking quarantine for recent items..." -ForegroundColor Yellow
try {
    # Check event log for quarantine actions
    $quarantineEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        StartTime=(Get-Date).AddHours(-1)
        ID=1117
    } -ErrorAction SilentlyContinue
    
    if ($quarantineEvents) {
        Write-Host "    [-] ITEMS QUARANTINED:" -ForegroundColor Red
        foreach ($event in $quarantineEvents | Select-Object -First 3) {
            Write-Host "        Time: $($event.TimeCreated)"
            Write-Host "        Action: Quarantine"
        }
        $evasionSuccess = $false
        $issues += "Files quarantined"
    } else {
        Write-Host "    [+] No recent quarantine actions" -ForegroundColor Green
    }
} catch {
    Write-Host "    [+] No quarantine events found" -ForegroundColor Green
}

# 5. Check Windows Defender event log for blocks
Write-Host "`n[5/5] Checking for blocked execution events..." -ForegroundColor Yellow
try {
    $blockEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        StartTime=(Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue | Where-Object { $_.Id -in @(1121, 1122, 1123, 1125, 1126) }
    
    if ($blockEvents) {
        Write-Host "    [-] EXECUTION BLOCKS DETECTED:" -ForegroundColor Red
        foreach ($event in $blockEvents | Select-Object -First 3) {
            Write-Host "        Time: $($event.TimeCreated)"
            Write-Host "        Event: $($event.Id)"
        }
        $evasionSuccess = $false
        $issues += "Execution blocked by Defender"
    } else {
        Write-Host "    [+] No execution blocks detected" -ForegroundColor Green
    }
} catch {
    Write-Host "    [+] No block events found" -ForegroundColor Green
}

# Check for running suspicious processes (our payloads)
Write-Host "`n[*] Checking for payload processes..." -ForegroundColor Yellow
$suspiciousProcesses = Get-Process | Where-Object { 
    $_.ProcessName -match "powershell" -and 
    $_.StartTime -gt (Get-Date).AddMinutes(-10) 
} -ErrorAction SilentlyContinue

if ($suspiciousProcesses) {
    Write-Host "    [+] Found PowerShell processes (payload may be running):" -ForegroundColor Green
    foreach ($proc in $suspiciousProcesses) {
        Write-Host "        PID: $($proc.Id) - Started: $($proc.StartTime)"
    }
}

# Final verdict
Write-Host "`n=== Verification Results ===" -ForegroundColor Cyan

if ($evasionSuccess) {
    Write-Host "[+] EVASION SUCCESSFUL!" -ForegroundColor Green
    Write-Host "[+] Windows Defender did not detect or block the payload" -ForegroundColor Green
    Write-Host "[+] All checks passed - no detections, blocks, or quarantine actions" -ForegroundColor Green
    
    Write-Host "`n[*] Success Indicators:" -ForegroundColor Cyan
    Write-Host "    - No active threats"
    Write-Host "    - No detection history"
    Write-Host "    - No quarantine actions"
    Write-Host "    - No execution blocks"
    Write-Host "    - Real-time protection still active"
    
} else {
    Write-Host "[-] EVASION FAILED!" -ForegroundColor Red
    Write-Host "[-] Windows Defender detected the payload" -ForegroundColor Red
    
    Write-Host "`n[*] Issues Found:" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "    - $issue"
    }
    
    Write-Host "`n[!] Troubleshooting Tips:" -ForegroundColor Yellow
    Write-Host "    1. Verify obfuscation was properly applied"
    Write-Host "    2. Check if payload was executed too quickly"
    Write-Host "    3. Try different process injection targets"
    Write-Host "    4. Ensure latest evasion techniques are used"
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan
