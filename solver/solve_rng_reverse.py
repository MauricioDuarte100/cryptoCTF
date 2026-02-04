#!/usr/bin/env python3
"""
Real Number Generator - State Recovery Attack
==============================================

Since we know the first 13 bytes of plaintext, we can recover
the first ~13 bytes of RNG output by XORing with ciphertext.

Then we try to reverse the PRNG to find the initial state/seed.
"""

import math
import struct
import hashlib
from decimal import getcontext, Decimal as D
import itertools

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


# Challenge data
enc = bytes.fromhex("1040d2bac7d79358f28394ea658ed37a4aa13f3c1921415429c232034aa73c5431051d0e36d1dbf0ae5dbdf920eb1755f48a")
known_prefix = b'The flag is: '

print("[*] Real Number Generator - State Recovery")
print(f"[*] Ciphertext length: {len(enc)} bytes")
print(f"[*] Known plaintext: {known_prefix!r}")
print()

# Recover first bytes of RNG stream
rng_output_partial = xor(enc[:len(known_prefix)], known_prefix)
print(f"[*] Partial RNG output (first 13 bytes): {rng_output_partial.hex()}")

# The RNG produces 8 bytes per call (one double)
# 13 bytes = 1 full double (8 bytes) + 5 bytes of second double

# Let's extract the first double
first_double_bytes = rng_output_partial[:8]
first_double = struct.unpack('d', first_double_bytes)[0]
print(f"[*] First RNG output value: {first_double}")

# The RNG output is: sqrt(|sin(state) + cos(state)|)
# We know this value, can we recover state?

# Let y = sqrt(|sin(s) + cos(s)|)
# y^2 = |sin(s) + cos(s)|
# sin(s) + cos(s) = ±y^2

# sin(s) + cos(s) = sqrt(2) * sin(s + pi/4)
# So: sqrt(2) * sin(s + pi/4) = ±y^2
# sin(s + pi/4) = ±y^2 / sqrt(2)

# This gives us s + pi/4 = arcsin(±y^2 / sqrt(2)) + 2*pi*k

y = first_double
y2 = y * y
print(f"[*] y^2 = {y2}")

# The argument to arcsin must be in [-1, 1]
arg = y2 / math.sqrt(2)
print(f"[*] arcsin argument: {arg}")

if abs(arg) <= 1:
    # Possible states after first random() call
    base_angle = math.asin(arg)
    possible_states_after = []
    
    # sin(s + pi/4) = arg
    # s + pi/4 = base_angle + 2*pi*k  OR  s + pi/4 = pi - base_angle + 2*pi*k
    
    for k in range(-10, 11):
        s1 = base_angle - math.pi/4 + 2*math.pi*k
        s2 = math.pi - base_angle - math.pi/4 + 2*math.pi*k
        
        # State must be in [0, pi) due to mod pi
        for s in [s1, s2]:
            s_mod = s % math.pi
            if 0 <= s_mod < math.pi:
                possible_states_after.append(s_mod)
    
    possible_states_after = list(set([round(s, 10) for s in possible_states_after]))
    print(f"[*] Found {len(possible_states_after)} possible states after first random() call")
    
    # Now reverse: state_after = e * seed % pi
    # seed = state_after / e  (mod pi somehow)
    # This is trickier because of the modulo
    
    print("\n[*] Trying to find seed from each possible state...")
    
    for state_after in possible_states_after:
        # state_after = (e * seed) mod pi
        # seed = (state_after + k*pi) / e for various k
        
        for k in range(1000):  # Try different multiples
            seed_candidate = (state_after + k * math.pi) / math.e
            
            if seed_candidate < 0:
                continue
            if seed_candidate > 2**48:
                break
            
            # Check if this seed is an integer (or close to it)
            seed_int = round(seed_candidate)
            
            # Verify by forward computation
            rng = RealNumberGenerator(seed_int)
            gen = rng.next_bytes()
            rng_bytes = bytes([next(gen) for _ in range(len(enc))])
            
            msg = xor(enc, rng_bytes)
            if msg.startswith(known_prefix):
                print(f"\n[+] FOUND SEED: {seed_int}")
                print(f"[+] Message: {msg}")
                
                flag_enc = msg[len(known_prefix):]
                shake_hash = hashlib.shake_256(str(seed_int).encode()).digest(len(flag_enc))
                flag = xor(flag_enc, shake_hash)
                
                print(f"\n[+] FLAG: {flag.decode()}")
                exit(0)

else:
    print(f"[!] arcsin argument out of range: {arg}")
    print("[*] The first double might be corrupted or incorrectly recovered")

print("\n[-] State recovery failed. Trying alternative approach...")

# Alternative: the known plaintext attack with optimizations
# Since Decimal precision is 28, the state space is limited

print("\n[*] Alternative: Testing if RNG output has patterns...")

# Let's check what the first double looks like for small seeds
print("[*] Sample RNG outputs for small seeds:")
for seed in [1, 100, 1000, 10000]:
    rng = RealNumberGenerator(seed)
    val = rng.random()
    print(f"    seed={seed}: random() = {val}")

# Check against our recovered value
print(f"\n[*] Target first double: {first_double}")
print("[*] This should help narrow down the search...")
