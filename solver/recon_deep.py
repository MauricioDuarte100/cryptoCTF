"""
Test: what does the server do if we send numbers AND then try to receive more?
Also test: is the 'echo' actually T_n(x) mod p where n happens to be 1?
Let's send known values and see if the response matches T_n(x) for n>1.

Theory: Maybe server sends back T_n(x) where n is its secret key.
For n=1: T_1(x) = x (identity - matches echo behavior)
If the n changes per session, maybe we were unlucky and got n=1?

Let's try multiple sessions and compare.
Also: try sending non-integer inputs.
"""
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
            if attempt < 9:
                time.sleep(3)
    return None

# Test 1: Send 20 numbers, then try to send 21st to see error message
print("=== TEST 1: Send 21 numbers ===")
sock = connect()
if sock:
    for i in range(21):
        try:
            sock.sendall(f"{i*100 + 1}\n".encode())
            time.sleep(0.05)
        except Exception as e:
            print(f"[-] Send #{i+1} failed: {e}")
            break
    
    # Collect all
    time.sleep(3)
    sock.settimeout(10)
    full = b""
    while True:
        try:
            d = sock.recv(8192)
            if not d: break
            full += d
        except: break
    
    print(f"Response ({len(full)} bytes): {repr(full)}")
    lines = full.decode(errors='replace').strip().split('\r\n')
    print(f"Response lines ({len(lines)}):")
    for i, line in enumerate(lines):
        expected = i*100 + 1
        actual = line.strip()
        match = "MATCH" if actual == str(expected) else "DIFF"
        print(f"  [{i+1}] Sent: {expected}, Got: {actual} [{match}]")
    sock.close()
    time.sleep(5)
else:
    print("Could not connect for test 1")

# Test 2: Send specific values to check if T_n(x) != x for n > 1
# If p exists, T_2(x) = 2x^2 - 1 mod p
print("\n=== TEST 2: New session, send same values ===")
sock = connect()
if sock:
    values = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
    for v in values:
        sock.sendall(f"{v}\n".encode())
        time.sleep(0.05)
    
    time.sleep(3)
    sock.settimeout(10)
    full = b""
    while True:
        try:
            d = sock.recv(8192)
            if not d: break
            full += d
        except: break
    
    print(f"Response ({len(full)} bytes):")
    lines = full.decode(errors='replace').strip().split('\r\n')
    for i, line in enumerate(lines):
        v = values[i] if i < len(values) else '?'
        match = "MATCH" if line.strip() == str(v) else "DIFF"
        print(f"  Sent: {v}, Got: {line.strip()} [{match}]") 
    
    # After 20, try to receive extra data
    print("\n[*] Checking for post-exchange data...")
    sock.settimeout(15)
    try:
        extra = sock.recv(8192)
        print(f"[+] Extra data: {repr(extra)}")
    except Exception as e:
        print(f"[-] No extra data: {e}")
    
    sock.close()
else:
    print("Could not connect for test 2")
