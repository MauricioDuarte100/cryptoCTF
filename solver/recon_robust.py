"""Robust recon: retry connection and carefully probe the server protocol."""
from pwn import *
import time
import sys

context.log_level = 'info'

MAX_RETRIES = 10
RETRY_DELAY = 5

def try_connect():
    for i in range(MAX_RETRIES):
        try:
            r = remote("20.244.7.184", 7331, timeout=30)
            return r
        except:
            print(f"[-] Attempt {i+1}/{MAX_RETRIES} failed. Waiting {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)
    return None

print("[*] Connecting to Killer Queen...")
r = try_connect()
if not r:
    print("[!] Could not connect after all retries")
    sys.exit(1)

print("[+] Connected!")

# Phase 1: Wait for server to send something (up to 15 seconds)
print("[*] Phase 1: Listening for initial data...")
try:
    data = r.recv(8192, timeout=15)
    print(f"[+] Initial data ({len(data)} bytes):")
    print(data.decode(errors='replace'))
    print(repr(data))
except EOFError:
    print("[-] Connection closed immediately")
    sys.exit(1)
except:
    print("[-] No initial data received (timeout)")

# Phase 2: Send a single number and see response line-by-line
print("[*] Phase 2: Sending test number '42'...")
r.sendline(b"42")
time.sleep(2)
try:
    data = r.recv(8192, timeout=5)
    print(f"[+] Response to '42': {repr(data)}")
except:
    print("[-] No response to '42'")

# Phase 3: Send larger number
print("[*] Phase 3: Sending '999999999'...")
r.sendline(b"999999999")
time.sleep(2)
try:
    data = r.recv(8192, timeout=5)
    print(f"[+] Response to '999999999': {repr(data)}")
except:
    print("[-] No response")

# Phase 4: Send more queries  
for x in [2, 3, 5, 7, 100, 12345]:
    r.sendline(str(x).encode())
    time.sleep(1)

time.sleep(3)
try:
    data = r.recv(16384, timeout=5)
    print(f"[+] Batch responses: {repr(data)}")
    lines = data.decode(errors='replace').strip().split('\n')
    for line in lines:
        print(f"  -> {line.strip()}")
except:
    print("[-] No batch response")

# Phase 5: Try to trigger something else 
print("[*] Phase 5: Trying 'flag', 'encrypt', 'key'...")
for cmd in [b"flag", b"encrypt", b"key"]:
    r.sendline(cmd)
    time.sleep(1)

time.sleep(3)
try:
    data = r.recv(16384, timeout=5)
    print(f"[+] Command responses: {repr(data)}")
except:
    print("[-] No command response")

r.close()
print("[*] Done")
