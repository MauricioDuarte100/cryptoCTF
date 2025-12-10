"""
Solver for Convergent Cipher Challenge - CORRECTED ANALYSIS
tcp.flagyard.com:31850

Cipher analysis:
- key = 6 bytes
- k0 = key[:3], k1 = key[3:], k2 = sha256(key)[:6]
- encrypt(pt):
    u1 = pt[:3] ^ k0
    u2 = pt[3:] ^ k1
    v1 = u1^(-1) mod (2^24 + 43)  -- MODULAR INVERSE!
    v2 = u2^(-1) mod (2^24 + 43)
    ct = (v1 || v2) ^ k2

Key insight: Since k0 and k1 are only 3 bytes each (2^24 possibilities),
and we can get 2 encryptions, we can:
1. Send pt1 = 0x000000000000 -> get ct1 = (k0^-1 || k1^-1) ^ k2
2. Send pt2 = 0x000001000001 -> get ct2 = ((k0^1)^-1 || (k1^1)^-1) ^ k2

XOR ct1 ^ ct2 = (k0^-1 ^ (k0^1)^-1) || (k1^-1 ^ (k1^1)^-1)
This DIRECTLY gives us the XOR difference pattern.

BUT WAIT: pt XOR k -> then modular inverse.
So for pt=0, we get sub(k) 
For pt=1, we get sub(k^1) = sub(k XOR 1) where XOR changes bit 0 of the 24-bit number

The differential pattern I'm looking for is correct.
Maybe there's just no match within the range - need to check both k and k^1.

Actually let me try a different approach: offset the plaintext differently.
"""

from pwn import *
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

MODULUS = 2**24 + 43

def sub_int(x):
    if x == 0:
        return 0
    return pow(x, -1, MODULUS)

def xor_bytes(A, B):
    return bytes([a ^ b for a, b in zip(A, B)])

def key_schedule(key):
    h = hashlib.sha256(key).digest()
    return [key[:3], key[3:], h[:6]]

def encrypt(pt, key):
    k0, k1, k2 = key_schedule(key)
    u1 = xor_bytes(pt[:3], k0)
    u2 = xor_bytes(pt[3:], k1)
    v1_int = sub_int(int.from_bytes(u1, 'big'))
    v2_int = sub_int(int.from_bytes(u2, 'big'))
    v1 = v1_int.to_bytes(3, 'big')
    v2 = v2_int.to_bytes(3, 'big')
    ct = xor_bytes(v1 + v2, k2)
    return ct

def search_key(target_diff, start, end):
    """Search for k such that sub(k) ^ sub(k^1) = target_diff"""
    for k in range(start, end):
        s0 = sub_int(k)
        s1 = sub_int(k ^ 1)
        if (s0 ^ s1) == target_diff:
            return k
    return None

# Connect to server
HOST = "tcp.flagyard.com"
PORT = 31850

print(f"🔌 Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT)

# Use zeros as first plaintext to get sub(k0)||sub(k1) ^ k2
pt1 = bytes(6)
io.recvuntil(b"Plaintext (hex): ")
io.sendline(pt1.hex().encode())
io.recvuntil(b"Ciphertext: ")
ct1 = bytes.fromhex(io.recvline().strip().decode())
print(f"📤 PT1: {pt1.hex()} -> CT1: {ct1.hex()}")

# Second: XOR with 0x000001 on each half
# This changes the LSB of the 24-bit number that goes into sub()
pt2 = bytes([0, 0, 1, 0, 0, 1])  # Changed to flip LSB
io.recvuntil(b"Plaintext (hex): ")
io.sendline(pt2.hex().encode())
io.recvuntil(b"Ciphertext: ")
ct2 = bytes.fromhex(io.recvline().strip().decode())
print(f"📤 PT2: {pt2.hex()} -> CT2: {ct2.hex()}")

# Wait before we need to enter key - keep connection alive
# The XOR gives: sub(k0) ^ sub(k0 ^ 1) || sub(k1) ^ sub(k1 ^ 1)
ct_xor = xor_bytes(ct1, ct2)
target_left = int.from_bytes(ct_xor[:3], 'big')
target_right = int.from_bytes(ct_xor[3:], 'big')

print(f"🔑 Target diffs: left={target_left:06x}, right={target_right:06x}")

# Parallel search using multiple processes
print(f"\n🔍 Parallel search for k0 and k1 (using {multiprocessing.cpu_count()} cores)...")

num_workers = multiprocessing.cpu_count()
chunk_size = 2**24 // num_workers

found_k0 = None
found_k1 = None

# Sequential but with progress
print("   Searching...")
for k in range(2**24):
    if found_k0 is None:
        s0 = sub_int(k)
        s1 = sub_int(k ^ 1)
        if (s0 ^ s1) == target_left:
            found_k0 = k
            print(f"✅ Found k0 = {k:06x}")
    
    if found_k1 is None:  
        s0 = sub_int(k)
        s1 = sub_int(k ^ 1)
        if (s0 ^ s1) == target_right:
            found_k1 = k
            print(f"✅ Found k1 = {k:06x}")
    
    if found_k0 is not None and found_k1 is not None:
        break
        
    if k % 1000000 == 0:
        print(f"   {k/2**24*100:.0f}%", end=" ", flush=True)

print()

if found_k0 is None or found_k1 is None:
    print(f"❌ Search failed! k0={found_k0}, k1={found_k1}")
    print("   The differential equation might have no solution for some key values.")
    print("   Trying brute force on shorter candidates...")
    
    # Try finding by verification instead
    # k0 candidates: all k where sub(k)^sub(k^1) matches (we check both directions)
    io.close()
    exit(1)

# Construct key candidates
print(f"\n🔐 Testing key candidates...")
candidates = []
for k0_test in [found_k0, found_k0 ^ 1]:
    for k1_test in [found_k1, found_k1 ^ 1]:
        key = k0_test.to_bytes(3, 'big') + k1_test.to_bytes(3, 'big')
        test_ct = encrypt(pt1, key)
        if test_ct == ct1:
            candidates.append(key)
            print(f"   ✓ Valid: {key.hex()}")

if not candidates:
    print("❌ No valid candidates!")
    io.close()
    exit(1)

# Send first valid key
key = candidates[0]
print(f"\n🔐 Sending key: {key.hex()}")

io.recvuntil(b"Key (hex): ")
io.sendline(key.hex().encode())

response = io.recvline()
print(f"\n🚩 {response.decode()}")

io.close()
