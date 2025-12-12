#!/usr/bin/env python3
"""
Generate a self-contained SageMath script that can be run at
https://sagecell.sagemath.org/ or any SageMath installation.

This script fetches ciphertexts and generates Sage code.
"""

import socket

HOST = "archive.cryptohack.org"
PORT = 21970

def get_ciphertexts():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    
    data = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    
    initial = data.decode()
    sock.close()
    
    lines = initial.split('\n')
    encrypted = []
    in_flag = False
    for line in lines:
        if "encrypted our secret flag" in line:
            in_flag = True
            continue
        if in_flag:
            stripped = line.strip()
            if stripped and not stripped.startswith("Now"):
                try:
                    encrypted.append(int(stripped))
                except:
                    pass
            if "Now you get to" in line:
                break
    
    return encrypted

print("[*] Fetching fresh ciphertexts from server...")
ciphertexts = get_ciphertexts()
print(f"[*] Got {len(ciphertexts)} ciphertexts")

# Generate Sage script
sage_code = '''# DGHV Approximate GCD Solver
# Paste this entire code into https://sagecell.sagemath.org/

# Ciphertexts from challenge
c = [
'''

for ct in ciphertexts:
    sage_code += f"    {ct},\n"

sage_code += ''']

print(f"Loaded {len(c)} ciphertexts")
print(f"First ciphertext: {c[0].nbits()} bits")

N = 128  # Modulus used for FLAG encryption
noise_bits = 126  # Approximate upper bound on noise

# Known prefix/suffix for crypto{...} format
known = [(0, 99), (1, 114), (2, 121), (3, 112), (4, 116), (5, 111), (6, 123), (-1, 125)]

# Method 1: Orthogonal Lattice
def orthogonal_lattice_attack(cts, num=6):
    """
    Build orthogonal lattice and run LLL
    """
    n = min(num, len(cts))
    c0 = cts[0]
    K = 2^noise_bits
    
    M = matrix(ZZ, n, n)
    M[0, 0] = K
    for i in range(1, n):
        M[0, i] = cts[i]
        M[i, i] = -c0
    
    print(f"Running LLL on {n}x{n} orthogonal lattice...")
    L = M.LLL()
    
    candidates = []
    for row in L:
        for entry in row:
            if entry != 0:
                g = gcd(c0, abs(entry))
                if g > 1 and 120 <= g.nbits() <= 140:
                    candidates.append(g)
    
    return candidates

# Method 2: Using known plaintext
def known_plaintext_attack(cts, known_pairs):
    """
    Use known plaintext positions to construct better lattice
    """
    # Adjust ciphertexts by subtracting known plaintext
    adjusted = []
    for pos, char in known_pairs:
        idx = pos if pos >= 0 else len(cts) + pos
        adjusted.append(cts[idx] - char)
    
    n = len(adjusted)
    K = 2^(noise_bits + 5)
    
    # Build lattice
    M = matrix(ZZ, n+1, n+1)
    M[0, 0] = K
    for i in range(n):
        M[i+1, 0] = adjusted[i]
        M[i+1, i+1] = 1
    
    print(f"Running LLL on {n+1}x{n+1} known-plaintext lattice...")
    L = M.LLL()
    
    candidates = []
    for row in L:
        val = row[0]
        if val != 0 and abs(val).nbits() < 200:
            g = gcd(cts[0], abs(val))
            if g > 1 and 100 <= g.nbits() <= 150:
                candidates.append(g)
    
    return candidates

# Method 3: Simultaneous Diophantine Approximation
def sda_attack(cts, num=7):
    """
    Use SDA-based lattice for approximate GCD
    """
    n = min(num, len(cts))
    
    # Reference: Chen-Nguyen's orthogonal lattice attack
    # We want short vector (1, x_1, ..., x_{n-1}) such that
    # c_0 + x_1*c_1 + ... + x_{n-1}*c_{n-1} is small (divisible by p)
    
    K = 2^(noise_bits + 10)
    
    M = matrix(ZZ, n, n)
    for i in range(n):
        M[i, 0] = cts[i]
        if i > 0:
            M[i, i] = K
    M[0, 0] = cts[0] * K
    
    print(f"Running BKZ on {n}x{n} SDA lattice...")
    # Try BKZ for better reduction
    try:
        L = M.BKZ(block_size=min(20, n))
    except:
        L = M.LLL()
    
    candidates = []
    for row in L:
        val = row[0]
        if val != 0:
            g = gcd(cts[0], abs(val))
            if g > 1 and 100 <= g.nbits() <= 150:
                candidates.append(g)
    
    return candidates

# Method 4: Difference-based lattice
def diff_lattice_attack(cts, num=8):
    """
    Use differences between ciphertexts
    """
    n = min(num, len(cts))
    c0 = cts[0]
    
    # d_i = c_0 - c_i = p*(q_0 - q_i) + (e_0 - e_i)
    diffs = [c0 - cts[i] for i in range(1, n)]
    
    m = len(diffs)
    K = 2^(noise_bits + 3)
    
    M = matrix(ZZ, m+1, m+1)
    M[0, 0] = K
    for i in range(m):
        M[i+1, 0] = diffs[i]
        M[i+1, i+1] = 1
    
    print(f"Running LLL on {m+1}x{m+1} difference lattice...")
    L = M.LLL()
    
    candidates = []
    for row in L:
        val = row[0]
        if val != 0:
            g = gcd(c0, abs(val))
            if g > 1 and 100 <= g.nbits() <= 150:
                candidates.append(g)
    
    return candidates

# Run all attacks
print("\\n=== Running Lattice Attacks ===\\n")

all_candidates = set()

print("Attack 1: Orthogonal Lattice")
cands1 = orthogonal_lattice_attack(c, num=6)
for x in cands1:
    if is_prime(x):
        all_candidates.add(x)
        print(f"  Found prime: {x.nbits()} bits")

print("\\nAttack 2: Known Plaintext")
cands2 = known_plaintext_attack(c, known)
for x in cands2:
    if is_prime(x):
        all_candidates.add(x)
        print(f"  Found prime: {x.nbits()} bits")

print("\\nAttack 3: SDA")
cands3 = sda_attack(c, num=7)
for x in cands3:
    if is_prime(x):
        all_candidates.add(x)
        print(f"  Found prime: {x.nbits()} bits")

print("\\nAttack 4: Difference Lattice")
cands4 = diff_lattice_attack(c, num=8)
for x in cands4:
    if is_prime(x):
        all_candidates.add(x)
        print(f"  Found prime: {x.nbits()} bits")

print(f"\\n=== Total unique prime candidates: {len(all_candidates)} ===\\n")

# Try decryption
def verify_and_decrypt(p, cts, mod=128):
    # Verify noise is reasonable
    for ct in cts[:5]:
        if ct % p > 2^127:
            return None
    
    # Decrypt
    flag = ""
    for ct in cts:
        m = (ct % p) % mod
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    
    return flag

for p in all_candidates:
    print(f"Testing p = {p} ({p.nbits()} bits)")
    flag = verify_and_decrypt(p, c)
    if flag:
        print(f"Decrypted: {flag}")
        if flag.startswith("crypto{"):
            print(f"\\n*** FLAG FOUND: {flag} ***")
            break
    else:
        print("  Failed verification")

print("\\nDone!")
'''

# Save to file
output_file = "sage_solver.sage"
with open(output_file, "w") as f:
    f.write(sage_code)

print(f"\n[*] Generated {output_file}")
print(f"[*] Copy the contents to https://sagecell.sagemath.org/ to run")
print(f"\n[*] Or run locally with: sage {output_file}")

# Also print the Sage code
print("\n" + "=" * 60)
print("SAGE CODE (copy this to SageMathCell):")
print("=" * 60)
print(sage_code[:2000] + "\n... (truncated, see file for full code)")
