"""Minimal single-input test with raw socket for clarity."""
import socket
import time

HOST = "20.244.7.184"
PORT = 7331

for attempt in range(10):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((HOST, PORT))
        print(f"[+] Connected on attempt {attempt+1}")
        break
    except Exception as e:
        print(f"[-] Attempt {attempt+1}: {e}")
        time.sleep(3)
else:
    print("[!] All connection attempts failed")
    exit(1)

# Phase 1: Wait for initial data
print("[*] Waiting for initial data...")
sock.settimeout(10)
try:
    init = sock.recv(4096)
    print(f"[+] Initial recv: {repr(init)}")
except socket.timeout:
    print("[-] No initial data (timeout)")
except Exception as e:
    print(f"[-] Error: {e}")

# Phase 2: Send just "2\n"
print("[*] Sending: 2")
sock.sendall(b"2\n")

# Read response
print("[*] Waiting for response...")
sock.settimeout(15)
try:
    resp = sock.recv(4096)
    print(f"[+] Response: {repr(resp)}")
    # Try to get more
    while True:
        sock.settimeout(5)
        more = sock.recv(4096)
        if not more:
            break
        print(f"[+] More: {repr(more)}")
except socket.timeout:
    print("[-] No more data")
except Exception as e:
    print(f"[-] Error: {e}")

sock.close()
