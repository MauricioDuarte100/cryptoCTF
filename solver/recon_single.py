"""
Ultra-careful single-request test. 
Send ONE request, wait a very long time for response.
Try sending: just a newline, a large prime, etc.
"""
import socket
import time
import sys

HOST = "20.244.7.184"
PORT = 7331

def connect():
    for attempt in range(20):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((HOST, PORT))
            print(f"[+] Connected on attempt {attempt+1}")
            return sock
        except Exception as e:
            print(f"[-] Attempt {attempt+1}: {type(e).__name__}")
            time.sleep(5)
    return None

sock = connect()
if not sock:
    sys.exit(1)

# Wait 30 seconds for any initial banner
print("[*] Waiting 30 seconds for initial data...")
sock.settimeout(30)
try:
    init = sock.recv(4096)
    print(f"[+] Initial: {repr(init)}")
except socket.timeout:
    print("[-] No initial data after 30s")

# Send a single large number
val = 12345678901234567890
print(f"[*] Sending: {val}")
sock.sendall(f"{val}\n".encode())

# Wait 30 seconds for response
print("[*] Waiting 30 seconds for response...")
sock.settimeout(30)
try:
    resp = sock.recv(4096)
    print(f"[+] Response: {repr(resp)}")
    try:
        r = int(resp.strip())
        if r == val:
            print("[!] ECHOED EXACTLY")
        else:
            print(f"[!] TRANSFORMED! Input={val}, Output={r}")
            print(f"    Difference: {val - r}")
            print(f"    Output bits: {r.bit_length()}")
    except:
        print("[?] Non-integer response")
except socket.timeout:
    print("[-] No response after 30s")
except Exception as e:
    print(f"[-] Error: {e}")

sock.close()
