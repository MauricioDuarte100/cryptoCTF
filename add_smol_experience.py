#!/usr/bin/env python3
"""
Add smol challenge experience to training data
"""
import json

data = {
    "id": "smol_nitectf25_ecdsa_hnp",
    "team": "nitectf25",
    "event": "nitectf25",
    "challenge_name": "smol",
    "challenge_description": "ECDSA on SECP256k1 with 200-bit nonces (56-bit bias). Server provides m=r*s, a=(10+r)^11 mod m, b=(s^2+10)^r mod m. Must forge signature for gimme_flag to get flag. Connection via ncat --ssl smol.chals.nitectf25.live 1337. The hint 'FAN noises' refers to side-channel but the actual attack is algebraic.",
    "attack_type": "ECC/ECDSA",
    "tools_used": ["fpylll", "pwntools", "ecdsa", "sympy", "gmpy2"],
    "difficulty": "medium-hard",
    "writeup": """# Smol - ECDSA Biased Nonce Attack (nitectf25)

## Challenge Analysis
- ECDSA on SECP256k1 curve (256-bit order)
- Nonce k is limited to 200 bits: `k = secrets.randbelow(2**200 - 1) + 1`
- This creates a 56-bit bias exploitable via Hidden Number Problem (HNP)
- Server leaks r,s indirectly through: m=r*s, a=(10+r)^11 mod m, b=(s^2+10)^r mod m

## Key Insight
Since r and s are both prime (server enforces this), and m = r*s, we can recover r via:
- a ≡ 10^11 (mod r) due to CRT
- Therefore: r = GCD(a - 10^11, m)

## Attack Steps
1. **Extract r,s from m,a,b**: Use GCD(a - 10^11, m) since a ≡ 10^11 (mod r)
2. **Collect signatures**: Get multiple (r_i, s_i) pairs with same message hash z
3. **Build HNP system**: k_i = s_i^{-1} * (z + r_i * d) mod n where k_i < 2^200
4. **Construct lattice matrix**:
   - Top block: n * I (identity scaled by curve order)
   - Row for u_i = r_i * s_i^{-1} mod n (coefficients of d)
   - Row for t_i = z * s_i^{-1} mod n (constants)
5. **Apply LLL/BKZ reduction** to find short vector containing private key d
6. **Verify d** by checking recovered k values are within 2^200 bound
7. **Forge signature** for 'gimme_flag' using recovered d

## Mathematical Details
ECDSA equation: s = k^{-1} * (z + r*d) mod n
Rearranging: k = s^{-1} * (z + r*d) mod n = t + u*d mod n

With k < 2^200 (small), this is the Hidden Number Problem.

## Tools Required
- fpylll for LLL/BKZ lattice reduction
- ecdsa for curve operations
- pwntools or raw sockets for server connection
""",
    "solution_code": """from hashlib import sha256
from math import gcd
from fpylll import IntegerMatrix, LLL

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NONCE_BOUND = 2**200

def recover_r_s(m, a):
    '''Extract r,s from m=r*s using GCD trick'''
    diff = a - pow(10, 11)
    if diff <= 0:
        return None, None
    g = gcd(diff, m)
    if 1 < g < m:
        r, s = g, m // g
        if pow(10 + r, 11, m) == a:
            return r, s
        elif pow(10 + s, 11, m) == a:
            return s, r
    return None, None

def lattice_attack(sigs):
    '''HNP lattice attack to recover private key d'''
    num = len(sigs)
    t_vals = [(z * pow(s, -1, n)) % n for r, s, z in sigs]
    u_vals = [(r * pow(s, -1, n)) % n for r, s, z in sigs]
    
    dim = num + 2
    M = [[0]*dim for _ in range(dim)]
    
    for i in range(num):
        M[i][i] = n
    for i in range(num):
        M[num][i] = u_vals[i]
    M[num][num] = 1
    for i in range(num):
        M[num+1][i] = t_vals[i]
    M[num+1][num+1] = NONCE_BOUND
    
    mat = IntegerMatrix.from_matrix(M)
    LLL.reduction(mat)
    
    for i in range(mat.nrows):
        row = [mat[i,j] for j in range(mat.ncols)]
        for sign in [1, -1]:
            d = (sign * row[num]) % n
            if 1 < d < n-1:
                # Verify
                valid = all(
                    (pow(s,-1,n) * (z + r*d)) % n < NONCE_BOUND
                    for r, s, z in sigs
                )
                if valid:
                    return d
    return None

def forge_signature(d, msg=b"gimme_flag"):
    '''Forge ECDSA signature with recovered private key'''
    from ecdsa import SECP256k1
    import secrets
    
    z = int.from_bytes(sha256(msg).digest(), "big") % n
    G = SECP256k1.generator
    
    while True:
        k = secrets.randbelow(n - 1) + 1
        R = k * G
        r = int(R.x()) % n
        if r == 0: continue
        s = (pow(k, -1, n) * (z + r * d)) % n
        if s == 0: continue
        return r, s
""",
    "url": "",
    "year": 2025,
    "category": "crypto",
    "file_type": ".py",
    "scraped_at": "2025-12-15T01:00:00",
    "synthetic": False
}

with open('data/training_data.jsonl', 'a', encoding='utf-8') as f:
    f.write(json.dumps(data) + '\n')

print("✅ Added smol ECDSA HNP experience to training_data.jsonl")
