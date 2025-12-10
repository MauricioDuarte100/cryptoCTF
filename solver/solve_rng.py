"""
Solver for Real Number Generator - BRUTE FORCE WITH NUMBA

Uses Numba JIT for maximum speed on direct brute force.
"""

import math
import struct
import hashlib
from decimal import getcontext, Decimal as D

xor = lambda A, B: bytes([a ^ b for a, b in zip(A, B)])

# Target data 
ENC_HEX = "1040d2bac7d79358f28394ea658ed37a4aa13f3c1921415429c232034aa73c5431051d0e36d1dbf0ae5dbdf920eb1755f48a"
ENC = bytes.fromhex(ENC_HEX)
KNOWN_PT = b"The flag is: "
KNOWN_KS = xor(ENC[:len(KNOWN_PT)], KNOWN_PT)
TARGET_BYTES = KNOWN_KS[:8]

print(f"🔒 Target: {TARGET_BYTES.hex()}")

target_r1 = struct.unpack('d', TARGET_BYTES)[0]
print(f"📊 Target r1 = {target_r1}")

E = math.e
PI = math.pi

def check_seed_fast(seed):
    """Fast check using float math"""
    state = E * seed
    state = state - PI * int(state / PI)  # mod PI
    val = math.sin(state) + math.cos(state)
    r = math.sqrt(abs(val))
    return struct.pack('d', r) == TARGET_BYTES

print("\n🔍 Brute forcing from seed=0...")

found = False
# Try small seeds first
for seed in range(2**32):  # Start with 32-bit range
    if check_seed_fast(seed):
        print(f"✅ Found seed: {seed}")
        
        # Verify with Decimal math
        getcontext().prec = 50
        state = D(seed)
        keystream = []
        for _ in range((len(ENC) + 7) // 8):
            state = D(E) * state % D(PI)
            r = math.sqrt(abs(math.sin(float(state)) + math.cos(float(state))))
            keystream.extend(struct.pack('d', r))
        
        full_ks = bytes(keystream[:len(ENC)])
        msg = xor(ENC, full_ks)
        print(f"📝 Message: {msg}")
        
        flag_enc = msg[13:]
        flag_key = hashlib.shake_256(str(seed).encode()).digest(len(flag_enc))
        flag = xor(flag_enc, flag_key)
        print(f"\n🚩 FLAG: {flag.decode()}")
        found = True
        break
    
    if seed % 10000000 == 0:
        print(f"   {seed/2**32*100:.1f}% of 32-bit space...")

if not found:
    print("❌ Not found in 32-bit range")
