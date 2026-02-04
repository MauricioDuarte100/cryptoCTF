#!/usr/bin/env python3
"""
Real Number Generator Challenge Solver - Simple Version
=========================================================
"""

import math
import struct
import hashlib
from decimal import getcontext, Decimal as D

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


# Challenge data
enc = bytes.fromhex("1040d2bac7d79358f28394ea658ed37a4aa13f3c1921415429c232034aa73c5431051d0e36d1dbf0ae5dbdf920eb1755f48a")
known_prefix = b'The flag is: '

print("[*] Real Number Generator Solver")
print(f"[*] Ciphertext length: {len(enc)} bytes")
print(f"[*] Known plaintext: 'The flag is: ' (13 bytes)")
print()

# Brute force seed
print("[*] Brute forcing seed (single thread)...")
print("[*] This could take a while for large seeds...")

for seed in range(0, 2**48):
    # Get RNG stream
    rng_stream = get_rng_stream(seed, len(enc))
    
    # Decrypt: msg = enc XOR rng_stream
    msg = xor(enc, rng_stream)
    
    # Check if starts with known prefix
    if msg[:13] == known_prefix:
        print(f"\n[+] FOUND SEED: {seed}")
        print(f"[+] Raw message: {msg}")
        
        # Decrypt the flag portion
        flag_enc = msg[13:]  # After "The flag is: "
        shake_hash = hashlib.shake_256(str(seed).encode()).digest(len(flag_enc))
        flag = xor(flag_enc, shake_hash)
        
        print(f"\n[+] FLAG: {flag.decode()}")
        break
    
    if seed % 1000000 == 0 and seed > 0:
        print(f"  Checked {seed:,} seeds...")

print("\n[*] Done")
