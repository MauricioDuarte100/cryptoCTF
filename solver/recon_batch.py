"""Test various protocol formats to find how the server communicates."""
import socket
import time

HOST = "20.244.7.184"
PORT = 7331

def connect():
    for attempt in range(10):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((HOST, PORT))
            return sock
        except Exception as e:
            print(f"[-] Attempt {attempt+1}: {e}")
            time.sleep(3)
    return None

print("[*] Connecting...")
sock = connect()
if not sock:
    exit(1)
print("[+] Connected")

# Strategy: Send 20 numbers rapidly and see if server responds after all 20
print("[*] Sending 20 numbers rapidfire...")
sock.settimeout(3)
for i in range(20):
    msg = f"{i+1}\n".encode()
    try:
        sock.sendall(msg)
    except Exception as e:
        print(f"[-] Send failed at i={i}: {e}")
        break
    time.sleep(0.1)

# Now wait for response
print("[*] Waiting for response after 20 sends...")
sock.settimeout(30)
full_resp = b""
while True:
    try:
        chunk = sock.recv(8192)
        if not chunk:
            break
        full_resp += chunk
        print(f"[+] chunk: {repr(chunk[:200])}")
    except socket.timeout:
        break
    except Exception as e:
        print(f"[-] Recv error: {e}")
        break

print(f"\n=== FULL RESPONSE ({len(full_resp)} bytes) ===")
print(repr(full_resp))
print()
print(full_resp.decode(errors='replace'))

sock.close()
