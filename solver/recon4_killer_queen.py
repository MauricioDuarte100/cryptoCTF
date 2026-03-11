"""
Killer Queen CTF Solver - Chebyshev Polynomial Key Exchange Attack

Challenge analysis from hints:
- fibonacci.txt: Chebyshev polynomials T_n(x), composition identity T_m(T_n(x)) = T_{mn}(x)
- biography.md: Chebyshev-based key exchange, DLP reduces to standard DLP in (Z/pZ)*
- ciggarettes.txt: Deterministic function, two voices composing, function composition
- dynamite.txt: 20 query limit
- laserbeam.txt: Group order not entirely smooth, one large factor ~70 bits, needs Pollard's rho / baby-step giant-step
- antoinette.md: Not RSA, polynomial exponentiation, Euler's totient
- curves.md: No y-coordinate, sequence with recurrence, composition
- sheet_music.md: SHA-256 for second key, AES for encryption, two-stage decryption

Attack strategy:
The Chebyshev polynomial DLP T_n(x) = y mod p reduces to the standard DLP via:
  If x = (g + g^{-1})/2 mod p for some g in (Z/pZ)*
  Then T_n(x) = (g^n + g^{-n})/2 mod p
  So finding n from T_n(x) reduces to DLP on g.

Protocol likely:
1. Server sends p, x (generator), and T_n(x) (public key for some secret n)
2. We can query T_k(x) for chosen k (up to 20 queries)
3. We need to find n (the secret key)
4. Use n to derive AES key (SHA-256 of secret) and decrypt flag
"""

from pwn import *
import time

context.log_level = 'info'

def connect():
    for attempt in range(5):
        try:
            r = remote("20.244.7.184", 7331, timeout=20)
            print(f"[+] Connected on attempt {attempt+1}")
            return r
        except:
            print(f"[-] Attempt {attempt+1} failed, retrying in 3s...")
            time.sleep(3)
    return None

r = connect()
if not r:
    print("Could not connect after 5 attempts")
    exit(1)

# Try to receive initial data 
print("[*] Waiting for server data...")
all_data = b""
try:
    all_data = r.recvrepeat(timeout=8)
    print(f"[+] Received {len(all_data)} bytes initially")
    print(all_data.decode(errors='replace'))
except:
    print("[-] No initial data")

# If nothing received, try to receive line by line
if not all_data:
    print("[*] Trying recvline...")
    try:
        line = r.recvline(timeout=10)
        print(f"[+] First line: {line}")
    except:
        print("[-] No line either")

# Try sending different probes
probes = [b"", b"\n", b"GET / HTTP/1.1\r\n\r\n", b"help", b"0", b"menu"]
for probe in probes:
    try:
        r.send(probe + b"\n" if not probe.endswith(b"\n") else probe)
        resp = r.recv(4096, timeout=3)
        print(f"[+] Probe {repr(probe)} -> {repr(resp)}")
        all_data += resp
    except:
        pass

print("\n=== ALL COLLECTED DATA ===")
print(all_data.decode(errors='replace'))

r.close()
