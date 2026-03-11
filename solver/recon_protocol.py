"""
Full protocol test: try various input formats and commands.
The server might have a menu or expect JSON/hex/specific keywords.
"""
import socket
import time

HOST = "20.244.7.184"
PORT = 7331

def connect():
    for attempt in range(15):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((HOST, PORT))
            return sock
        except:
            time.sleep(3)
    return None

# Test various input types
tests = [
    b"QUERY 42\n",
    b"GET_PARAMS\n",
    b"HELLO\n", 
    b"START\n",
    b"CHALLENGE\n",
    b'{"x": 42}\n',
    b"T 42\n",
    b"CHEBYSHEV 42\n",
    b"ORACLE 42\n",
    b"Killer Queen\n",
    b"FLAG\n",
    b"SUBMIT flag{test}\n",
    b"1\n2\n3\n",
    b"0x2a\n",
]

print("[*] Connecting...")
sock = connect()
if not sock:
    print("[!] Failed")
    exit(1)
print("[+] Connected")

for test in tests:
    try:
        sock.sendall(test)
        time.sleep(0.1)
    except:
        print(f"[-] Send failed at {repr(test)}")
        break

# Wait and collect
time.sleep(5)
sock.settimeout(10)
full = b""
while True:
    try:
        d = sock.recv(65536)
        if not d: break
        full += d
    except: break

print(f"\nAll responses ({len(full)} bytes):")
lines = full.decode(errors='replace').split('\r\n')
i = 0
for line in lines:
    if line.strip():
        print(f"  [{i}] {line.strip()}")
        i += 1

sock.close()
