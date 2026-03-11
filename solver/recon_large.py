"""
Test if server does Chebyshev computation by sending very large numbers.
If T_n(x) mod p != x, we'll see it with large x values that exceed p.
Also try to probe: does the server send parameters FIRST if we wait longer?
Or does it send the challenge AFTER our queries?
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

print("[*] Connecting...")
sock = connect()
if not sock:
    print("[!] Failed to connect")
    exit(1)
print("[+] Connected")

# Send very large numbers: if there's a modular prime p, result will be reduced
large_values = [
    10**100 + 7,   # 100-digit number
    10**50 + 3,     # 50-digit number
    10**20 + 11,    # 20-digit number
    2**256 + 1,     # 256-bit number
    2**128 - 159,   # 128-bit prime-ish
]

results = []
for v in large_values:
    msg = f"{v}\n".encode()
    sock.sendall(msg)
    time.sleep(0.2)

# Wait for responses
time.sleep(5)
sock.settimeout(10)
full = b""
while True:
    try:
        d = sock.recv(65536)
        if not d: break
        full += d
    except: break

print(f"\nResponse ({len(full)} bytes):")
resp_lines = full.decode(errors='replace').strip().split('\r\n')
for i, line in enumerate(resp_lines):
    line = line.strip()
    if i < len(large_values):
        sent = large_values[i]
        try:
            received = int(line)
            if received == sent:
                print(f"  Input[{i}]: {str(sent)[:30]}... -> ECHOED (identical)")
            else:
                print(f"  Input[{i}]: {str(sent)[:50]}...")
                print(f"  Output:    {str(received)[:50]}...")
                print(f"  *** TRANSFORMED! Difference: {sent - received} ***")
                # If transformed, it might be T_n(x) mod p
                # Check if received < sent (reduction happened)
                if received < sent:
                    print(f"  -> Output is smaller, possible modular reduction")
                    print(f"  -> Output bit length: {received.bit_length()}")
        except ValueError:
            print(f"  Input[{i}]: {str(sent)[:30]}...")
            print(f"  Output (non-numeric): {line[:100]}")
    else:
        print(f"  Extra line [{i}]: {line[:100]}")

# Now send a few more and also try to get post-query data
print("\n[*] Sending 15 more queries to reach 20 total...")
for i in range(15):
    sock.sendall(f"{i+100}\n".encode())
    time.sleep(0.1)

time.sleep(3)
sock.settimeout(10)
post = b""
while True:
    try:
        d = sock.recv(65536) 
        if not d: break
        post += d
    except: break

print(f"\nPost-query data ({len(post)} bytes):")
post_lines = post.decode(errors='replace').strip().split('\r\n')
for line in post_lines:
    print(f"  -> {line.strip()[:100]}")

# Check if connection is still alive
print("\n[*] Checking if connection still alive after 20 queries...")
try:
    sock.sendall(b"test_alive\n")
    time.sleep(2)
    alive = sock.recv(4096)
    print(f"[+] Still alive: {repr(alive)}")
except Exception as e:
    print(f"[-] Connection status: {e}")

sock.close()
