"""
Solver for Fatboy - Håstad Broadcast Attack

Since e=5 and we have 11 encryptions of the same message m,
we can use CRT across all moduli to find m^5, then take 5th root.

But there's quadratic padding: padded_m = a*m^2 + b*m + c
So we have: (a*m^2 + b*m + c)^5 ≡ ct (mod n)

This is a polynomial of degree 10 in m.
With 11 equations (11 > 10), we can use CRT + integer root.
"""

import json
import base64
from math import isqrt, gcd
from functools import reduce

with open('challenges/fatboy/server_logs.json', 'r') as f:
    logs = json.load(f)

print("🔓 Fatboy Solver - Håstad Broadcast")
print("=" * 60)

# Parse keys
from Crypto.PublicKey import RSA

keys_data = []
for idx, log in enumerate(logs):
    key_der = base64.b64decode(log['key'])
    key = RSA.import_key(key_der)
    keys_data.append({
        'idx': idx,
        'n': key.n,
        'e': key.e,
        'c': int(log['c'], 16)
    })

# All e should be 5
assert all(kd['e'] == 5 for kd in keys_data)
e = 5

print(f"   e = {e}")
print(f"   Number of keys: {len(keys_data)}")

# For Håstad: if the same message m is encrypted to e different moduli,
# we can recover m^e using CRT, then take the e-th root.

# But here we have padded messages. Let's see if without padding the attack works.
# Actually, the padding uses idx which is different for each, so the padded messages
# are different!

# Let's check: for each idx, the padded_m is:
# padded_m = (3+idx)*2^1024 * m^2 + (5*2^1024 + idx*4^1024) * m + (8*2^1024 + idx*6^1024)

# Each padded_m is different! So simple CRT won't work directly.

# HOWEVER, look at the structure:
# Let's define: P_idx(m) = a_idx * m^2 + b_idx * m + c_idx
# Then: P_idx(m)^5 ≡ ct_idx (mod n_idx)

# This is a polynomial congruence. We can use resultants or lattice methods.

# For now, let's try a simpler approach: guess that m is small (flag ~40 chars)

# Since the ciphertexts are different due to different idx, we can set up a
# system of polynomial equations and solve using Gröbner bases or similar.

# Actually, let's try: if the coefficients a, b, c are HUGE compared to m,
# then P_idx(m) ≈ a_idx * m^2 for large coefficients.

# Let's check the magnitude:
# a = (3+idx) * 2^1024, which is ~2^1026
# If m is ~2^256 (32 bytes flag), then a*m^2 ≈ 2^1026 * 2^512 ≈ 2^1538

# The n is 1024 bits = 2^1024
# So a*m^2 >> n, meaning padded_m mod n is complicated.

# Let's think differently. The flag is short, so m is small.
# The coefficients are structured: a_idx = k_a + idx * something

# Actually, let me re-read the code:
# a = 3*2^1024 + idx*2^1024 = (3+idx)*2^1024
# b = 5*2^1024 + idx*4^1024 = 5*2^1024 + idx*2^2048  (wait, 4^1024 = (2^2)^1024 = 2^2048)
# c = 8*2^1024 + idx*6^1024 = 8*2^1024 + idx*6^1024

# So for idx=0:
# a = 3*2^1024
# b = 5*2^1024
# c = 8*2^1024

# These are all around 2^1026, while n is 2^1024.
# So all coefficients are larger than n!

# Hmm, let's compute padded_m mod n for small m.

# Actually wait - the encryption is done in Python (arbitrary precision):
# padded_m = a*m*m + b*m + c_coef  (computed as a big integer)
# c = pow(padded_m, key.e, key.n)  (modular exponentiation)

# So padded_m can be MUCH larger than n before taking the power mod n.

# Let's try a different approach: since we have multiple encryptions,
# can we find a linear relationship?

# For idx=0: P_0(m) = 3*2^1024 * m^2 + 5*2^1024 * m + 8*2^1024
# For idx=1: P_1(m) = 4*2^1024 * m^2 + (5*2^1024 + 2^2048) * m + (8*2^1024 + 6^1024)

# Let's solve using the Franklin-Reiter related message attack idea.

# Actually, the simplest approach: since e=5 is small, and if m is very small,
# we might be able to just brute force m.

# Flag length is typically < 50 bytes = 400 bits

print("\n🔍 Trying small message brute force...")

# For idx=0:
n0 = keys_data[0]['n']
ct0 = keys_data[0]['c']
a0 = 3 * (2**1024)
b0 = 5 * (2**1024)
c0 = 8 * (2**1024)

# If m is a flag like "FlagY{...}" of length ~40, m is around 2^320
# padded_m ≈ 3*2^1024 * m^2 ≈ 3*2^1024 * 2^640 ≈ 2^1666
# pow(padded_m, 5, n0) with n0 = 2^1024

# This is getting complex. Let me try direct n-th root attack:
# If padded_m < n^(1/e) for all encryptions, then padded_m^e < product(n_i),
# and CRT gives us padded_m^e exactly, then we take e-th root.

N_product = 1
for kd in keys_data:
    N_product *= kd['n']

print(f"   Product of all n: {N_product.bit_length()} bits")

# Use CRT to combine: ct ≡ padded_m^e (mod n_i) for each i
# We get: combined_ct ≡ padded_m^e (mod N_product)
# If padded_m^e < N_product, this is exact.

# But padded_m depends on idx, so they're different!
# CRT doesn't apply directly.

# Let's try something else: directly check if the flag is something simple

print("\n🔍 Trying known flag formats...")

common_flags = [
    b"FlagY{hastad_attack}",
    b"FlagY{rsa_broadcast}",
    b"FlagY{fat_rsa}",
    b"FlagY{padded_rsa}",
    b"flag{test}",
]

for m_bytes in common_flags:
    m = int.from_bytes(m_bytes, 'big')
    
    # Check idx=0
    padded_m = a0 * m * m + b0 * m + c0
    computed_ct = pow(padded_m, 5, n0)
    
    if computed_ct == ct0:
        print(f"   ✅ Found flag: {m_bytes.decode()}")
        break
else:
    print("   Known flag formats didn't work")
    
# Since brute force won't work for arbitrary flags, we need the proper
# Coppersmith attack. Let's try a basic implementation.

print("\n🔍 Coppersmith-style attack for small roots...")

# The polynomial is: P(x) = (a*x^2 + b*x + c)^5 - ct (mod n)
# If x (the message m) is small enough, Coppersmith can find it.

# However, implementing Coppersmith from scratch is complex.
# Let's try SageMath if available, or use a simplified approach.

try:
    # Check if sage is available (it usually isn't on Windows)
    from sage.all import *
    print("   SageMath available, using Coppersmith...")
except ImportError:
    print("   SageMath not available")
    print("   Trying simplified Coppersmith via lattice...")
    
    # Simplified approach: if m < n^(1/(2e)) for some modulus, 
    # we can find m using lattice reduction.
    
    # For a 1024-bit n and e=5, n^(1/10) ≈ 2^102
    # This is only ~12 bytes, much smaller than a typical flag (40 bytes).
    
    # So the standard Coppersmith bound doesn't help directly.
    # We need to use multi-variate Coppersmith or other techniques.
    
    print("\n   The message is likely too large for simple Coppersmith.")
    print("   Need more advanced attack or additional information.")
    
    # Let me check if maybe the problem has a simpler solution
    # by looking at the structure more carefully.
    
    # Note: idx values go from 0 to 10
    # The coefficients change with idx
    # Maybe we can eliminate m somehow?
    
    # P_0(m) = 3*2^1024 * m^2 + 5*2^1024 * m + 8*2^1024
    # P_1(m) = 4*2^1024 * m^2 + (5*2^1024 + 2^2048) * m + (8*2^1024 + 6^1024)
    
    # These are related by: P_1(m) = P_0(m) + Δ(m)
    # where Δ(m) = 2^1024 * m^2 + 2^2048 * m + 6^1024
    
    # This might allow a resultant-based attack.
    
    print("\n   Trying polynomial GCD approach...")
