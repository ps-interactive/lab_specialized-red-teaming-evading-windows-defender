# Check Windows Defender Event Logs
# Analyze recent detection and protection events

param(
    [int]$HoursBack = 1
)

Write-Host "`n=== Windows Defender Event Log Analysis ===" -ForegroundColor Cyan
Write-Host "[*] Checking events from last $HoursBack hour(s)..." -ForegroundColor Green

$startTime = (Get-Date).AddHours(-$HoursBack)

# Function to format event data
function Format-EventData {
    param($Event)
    
    $output = @{
        TimeCreated = $Event.TimeCreated
        EventID = $Event.Id
        Level = $Event.LevelDisplayName
        Message = ""
    }
    
    if ($Event.Message) {
        $output.Message = $Event.Message.Substring(0, [Math]::Min($Event.Message.Length, 200))
    }
    
    return $output
}

# Check Windows Defender Operational Log
Write-Host "`n[*] Checking Windows Defender Operational Log..." -ForegroundColor Green
try {
    $operationalEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Select-Object -First 20
    
    if ($operationalEvents) {
        $threats = $operationalEvents | Where-Object { $_.Id -in @(1116, 1117, 1118, 1119) }
        $realtime = $operationalEvents | Where-Object { $_.Id -in @(5001, 5004, 5007) }
        $behavior = $operationalEvents | Where-Object { $_.Id -in @(1015, 1016) }
        
        if ($threats) {
            Write-Host "    [!] THREAT DETECTION EVENTS:" -ForegroundColor Red
            foreach ($event in $threats) {
                $formatted = Format-EventData -Event $event
                Write-Host "        Time: $($formatted.TimeCreated)"
                Write-Host "        Event ID: $($formatted.EventID) - $(switch($event.Id){
                    1116 {'Malware detected'}
                    1117 {'Action taken on malware'}
                    1118 {'Action failed'}
                    1119 {'Critical action failed'}
                })" -ForegroundColor Yellow
                Write-Host "        Message: $($formatted.Message)"
                Write-Host "        ---"
            }
        } else {
            Write-Host "    [+] No threat detection events found" -ForegroundColor Green
        }
        
        if ($realtime) {
            Write-Host "`n    Real-time Protection Events:" -ForegroundColor Yellow
            foreach ($event in $realtime) {
                Write-Host "        Event $($event.Id): $(switch($event.Id){
                    5001 {'Real-time protection disabled'}
                    5004 {'Real-time protection configuration changed'}
                    5007 {'Platform configuration changed'}
                })"
            }
        }
        
        if ($behavior) {
            Write-Host "`n    Behavior Monitoring Events:" -ForegroundColor Yellow
            foreach ($event in $behavior) {
                Write-Host "        Event $($event.Id): Behavior detection at $($event.TimeCreated)"
            }
        }
        
        # Count event types
        $eventCounts = $operationalEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
        Write-Host "`n    Top Event Types (Last $HoursBack hour(s)):" -ForegroundColor Cyan
        foreach ($group in $eventCounts) {
            Write-Host "        Event ID $($group.Name): $($group.Count) occurrences"
        }
        
    } else {
        Write-Host "    [*] No events in specified timeframe" -ForegroundColor Gray
    }
} catch {
    Write-Host "    [-] Could not access Defender operational logs: $_" -ForegroundColor Red
    Write-Host "    [!] Try running as Administrator" -ForegroundColor Yellow
}

# Check WHC (Windows Health) Log
Write-Host "`n[*] Checking Windows Defender WHC Log..." -ForegroundColor Green
try {
    $whcEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/WHC'
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Select-Object -First 10
    
    if ($whcEvents) {
        Write-Host "    Health events found: $($whcEvents.Count)"
        foreach ($event in $whcEvents | Select-Object -First 3) {
            Write-Host "        Event $($event.Id): $($event.Message.Substring(0, [Math]::Min($event.Message.Length, 100)))"
        }
    } else {
        Write-Host "    [*] No WHC events in specified timeframe" -ForegroundColor Gray
    }
} catch {
    Write-Host "    [*] WHC log not accessible or empty" -ForegroundColor Gray
}

# Summary
Write-Host "`n=== Analysis Summary ===" -ForegroundColor Cyan

try {
    $allEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        StartTime=$startTime
    } -ErrorAction SilentlyContinue
    
    $threatCount = ($allEvents | Where-Object { $_.Id -in @(1116, 1117) }).Count
    $scanCount = ($allEvents | Where-Object { $_.Id -in @(1000, 1001, 1002) }).Count
    $configCount = ($allEvents | Where-Object { $_.Id -in @(5004, 5007) }).Count
    
    Write-Host "[*] Statistics for last $HoursBack hour(s):"
    Write-Host "    Total Defender Events: $($allEvents.Count)"
    Write-Host "    Threat Detections: $threatCount" -ForegroundColor $(if($threatCount -eq 0){"Green"}else{"Red"})
    Write-Host "    Scan Events: $scanCount"
    Write-Host "    Configuration Changes: $configCount"
    
    if ($threatCount -eq 0) {
        Write-Host "`n[+] SUCCESS: No threats detected in the specified timeframe!" -ForegroundColor Green
        Write-Host "[+] Evasion techniques appear to be working!" -ForegroundColor Green
    } else {
        Write-Host "`n[!] WARNING: Threats were detected!" -ForegroundColor Red
        Write-Host "[!] Review the events above for details" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[*] Could not generate summary statistics" -ForegroundColor Yellow
}

Write-Host "`n=== Log Analysis Complete ===" -ForegroundColor Cyan
