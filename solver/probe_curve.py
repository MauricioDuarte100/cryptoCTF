import sys
import socket
import re
import time

HOST = 'challenges3.ctf.sd'
PORT = 33642

# P-256 Generator
P256_Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
P256_Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109

# secp256k1 Generator
SECP_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
SECP_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

def connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        return s
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return None

def recv_until(s, markers):
    buf = ""
    while True:
        try:
            data = s.recv(4096).decode(errors='ignore')
            if not data: break
            buf += data
            print(data, end='')
            for m in markers:
                if m in buf: return buf
        except socket.timeout:
            break
    return buf

def probe():
    # Test 1: P-256
    print("\n--- TEST 1: P-256 Point ---")
    s = connect()
    if not s: return
    
    recv_until(s, ["Input C1 >"])
    
    # Send P-256 G as C1
    msg = f"Point({P256_Gx}, {P256_Gy})"
    print(f"Sending: {msg}")
    s.sendall((msg + "\n").encode())
    
    # Send P-256 G as C2
    recv_until(s, ["Input C2 >"])
    print(f"Sending: {msg}")
    s.sendall((msg + "\n").encode())
    
    # Check response
    res = recv_until(s, ["Query", "Error", "Format"])
    if "Error" in res or "Format" in res:
        print("[-] P-256 Rejected")
    else:
        print("[+] P-256 Accepted (likely)")
        print(f"Result: {res}")
        
    s.close()
    
    # Test 2: secp256k1
    print("\n--- TEST 2: secp256k1 Point ---")
    s = connect()
    if not s: return
    
    recv_until(s, ["Input C1 >"])
    
    # Send SECP G as C1
    msg = f"Point({SECP_Gx}, {SECP_Gy})"
    print(f"Sending: {msg}")
    s.sendall((msg + "\n").encode())
    
    recv_until(s, ["Input C2 >"])
    s.sendall((msg + "\n").encode())
    
    res = recv_until(s, ["Query", "Error", "Format"])
    if "Error" in res or "Format" in res:
        print("[-] secp256k1 Rejected")
    else:
        print("[+] secp256k1 Accepted (likely)")
        print(f"Result: {res}")
    
    s.close()

if __name__ == "__main__":
    probe()
