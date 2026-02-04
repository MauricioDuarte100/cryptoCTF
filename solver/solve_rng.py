#!/usr/bin/env python3
"""
Real Number Generator Challenge Solver
========================================

Vulnerability: 48-bit seed is brute-forceable with known plaintext attack.

The message starts with "The flag is: " (13 bytes known).
We can XOR ciphertext with known plaintext to get RNG output + SHAKE hash.
Then brute force the 48-bit seed.
"""

import math
import struct
import hashlib
from decimal import getcontext, Decimal as D
from multiprocessing import Pool, cpu_count
import time

getcontext().prec = 28

xor = lambda A, B: bytes([a ^ b for a, b in zip(A, B)])


class RealNumberGenerator:
    def __init__(self, seed):
        self.state = seed

    def random(self):
        self.state = D(math.e) * D(self.state) % D(math.pi)
        return math.sqrt(math.fabs(math.sin(float(self.state)) + math.cos(float(self.state))))

    def next_bytes(self):
        while True:
            r = self.random()
            B = struct.pack('d', r)
            for b in B:
                yield b


def get_rng_stream(seed, length):
    """Get first 'length' bytes from RNG with given seed."""
    rng = RealNumberGenerator(seed)
    gen = rng.next_bytes()
    return bytes([next(gen) for _ in range(length)])


def check_seed(seed):
    """Check if this seed produces the correct first bytes."""
    # Get RNG stream
    rng_stream = get_rng_stream(seed, len(enc))
    
    # Decrypt: msg = enc XOR rng_stream
    msg = xor(enc, rng_stream)
    
    # The flag portion is XORed with SHAKE-256(seed)
    # msg = b'The flag is: ' + xor(flag, shake)
    # So msg should start with 'The flag is: '
    
    if msg[:13] == b'The flag is: ':
        return seed, msg
    return None


def check_seed_batch(seed_range):
    """Check a batch of seeds."""
    start, end = seed_range
    for seed in range(start, end):
        result = check_seed(seed)
        if result:
            return result
        if seed % 10000000 == 0 and seed > 0:
            print(f"  Checked {seed:,}...")
    return None


# Challenge data
enc = bytes.fromhex("1040d2bac7d79358f28394ea658ed37a4aa13f3c1921415429c232034aa73c5431051d0e36d1dbf0ae5dbdf920eb1755f48a")

print("[*] Real Number Generator Solver")
print(f"[*] Ciphertext length: {len(enc)} bytes")
print(f"[*] Known plaintext: 'The flag is: ' (13 bytes)")
print()

# First, let's try a small search
print("[*] Quick test with small seed values...")
for seed in range(0, 100000):
    result = check_seed(seed)
    if result:
        seed, msg = result
        print(f"\n[+] FOUND SEED: {seed}")
        print(f"[+] Message: {msg}")
        
        # Now decrypt the flag portion
        flag_enc = msg[13:]  # After "The flag is: "
        shake_hash = hashlib.shake_256(str(seed).encode()).digest(len(flag_enc))
        flag = xor(flag_enc, shake_hash)
        print(f"\n[+] FLAG: {flag.decode()}")
        exit(0)

print("[*] Not found in quick search, trying parallel brute force...")
print(f"[*] Search space: 2^48 = {2**48:,} (this will take a while)")

# For full search, we'd need to parallelize
# But 2^48 is very large - let's try some optimizations first

# Maybe the seed is smaller than expected?
print("\n[*] Trying extended range (0 to 2^32)...")

batch_size = 1000000
num_workers = cpu_count()
print(f"[*] Using {num_workers} CPU cores")

start_time = time.time()

for batch_start in range(0, 2**32, batch_size * num_workers):
    ranges = [(batch_start + i * batch_size, batch_start + (i + 1) * batch_size) 
              for i in range(num_workers)]
    
    with Pool(num_workers) as pool:
        results = pool.map(check_seed_batch, ranges)
    
    for result in results:
        if result:
            seed, msg = result
            print(f"\n[+] FOUND SEED: {seed}")
            print(f"[+] Message: {msg}")
            
            flag_enc = msg[13:]
            shake_hash = hashlib.shake_256(str(seed).encode()).digest(len(flag_enc))
            flag = xor(flag_enc, shake_hash)
            print(f"\n[+] FLAG: {flag.decode()}")
            exit(0)
    
    elapsed = time.time() - start_time
    checked = batch_start + batch_size * num_workers
    rate = checked / elapsed if elapsed > 0 else 0
    eta = (2**48 - checked) / rate if rate > 0 else float('inf')
    print(f"[*] Checked {checked:,} seeds in {elapsed:.1f}s ({rate:.0f} seeds/s)")

print("[-] Seed not found in 2^32 range")
