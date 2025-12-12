#!/usr/bin/env python3
"""
DGHV Approximate GCD Attack - Pure Python Implementation

Attack Strategy:
c_i = p * q_i + e_i where e_i = N*r + m (small noise)

For two ciphertexts c_0, c_1:
- c_0 = p*q_0 + e_0
- c_1 = p*q_1 + e_1

Key insight: if we can find integers a, b such that a*c_0 - b*c_1 is small,
then we might recover p.

Using continued fractions on c_0/c_1 gives rational approximations q_0/q_1.

Alternative: Approximate GCD using the structure
gcd(c_0, c_1 mod c_0, ...) iteratively

This is similar to the extended Euclidean algorithm but for approximate values.
"""

import socket
from math import gcd
from fractions import Fraction

HOST = "archive.cryptohack.org"
PORT = 21970

def get_ciphertexts():
    """Get fresh ciphertexts from the server"""
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
    
    # Parse ciphertexts
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
                    val = int(stripped)
                    encrypted.append(val)
                except:
                    pass
            if "Now you get to" in line or "do you want" in line.lower():
                break
    
    return encrypted


def continued_fraction_convergents(n, d, max_depth=200):
    """
    Generate convergents of n/d using continued fraction expansion
    """
    convergents = []
    
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    while d != 0 and len(convergents) < max_depth:
        a = n // d
        n, d = d, n % d
        
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        
        convergents.append((h_curr, k_curr))
    
    return convergents


def isqrt(n):
    """Integer square root"""
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def approximate_gcd_attack(ciphertexts):
    """
    Use continued fractions on ratio c_0/c_1 to find candidates for p
    
    If c_0/c_1 ≈ q_0/q_1, then:
    c_0 * k_1 - c_1 * h_1 = error term involving p
    """
    c0, c1 = ciphertexts[0], ciphertexts[1]
    
    print(f"[*] c0 has {c0.bit_length()} bits")
    print(f"[*] c1 has {c1.bit_length()} bits")
    
    # Get continued fraction convergents
    convs = continued_fraction_convergents(c0, c1)
    print(f"[*] Generated {len(convs)} convergents")
    
    candidates = []
    
    for i, (h, k) in enumerate(convs):
        if k == 0:
            continue
        
        # diff = c0 * k - c1 * h
        # If h/k ≈ q0/q1, then:
        # diff = (p*q0 + e0)*k - (p*q1 + e1)*h
        #      = p*(q0*k - q1*h) + e0*k - e1*h
        # 
        # If h/k = q0/q1 exactly (i.e., g = gcd(q0,q1), h = q0/g, k = q1/g):
        # diff = e0*k - e1*h (which is small!)
        
        diff = c0 * k - c1 * h
        
        if diff == 0:
            continue
        
        # gcd(c0, diff) or gcd(c1, diff) might give us p
        g0 = gcd(c0, abs(diff))
        g1 = gcd(c1, abs(diff))
        
        for g in [g0, g1]:
            if g > 1:
                bits = g.bit_length()
                if 120 <= bits <= 140:
                    candidates.append((i, g, bits))
                    print(f"  Convergent {i}: Found candidate with {bits} bits")
    
    return candidates


def small_factors_attack(ciphertexts):
    """
    The error term e_i = 128*r_i + m_i where m_i < 128
    
    Try to find common factors by looking at linear combinations
    """
    print("\n[*] Trying linear combinations attack...")
    
    # Use differences: c_i - c_j = p*(q_i - q_j) + (e_i - e_j)
    # gcd of several differences might reveal p or factors of p
    
    from functools import reduce
    
    n = len(ciphertexts)
    diffs = []
    for i in range(min(n, 10)):
        for j in range(i+1, min(n, 10)):
            diffs.append(abs(ciphertexts[i] - ciphertexts[j]))
    
    g = reduce(gcd, diffs)
    print(f"[*] GCD of differences: {g} ({g.bit_length()} bits)")
    
    # The differences c_i - c_j contain p*(q_i - q_j)
    # But q's are random 1024-bit numbers, so q_i - q_j is also ~1024 bits
    # and random, so gcd is likely 1
    
    # Try something else: look for small quotient in ratios
    # If c_i / c_j = (p*q_i + e_i) / (p*q_j + e_j) ≈ q_i / q_j
    # Then p ≈ c_i / q_i
    
    return g


def modular_gcd_attack(ciphertexts):
    """
    Try to find p using the fact that:
    c_i ≡ e_i (mod p)
    
    So c_i - c_j ≡ e_i - e_j (mod p)
    
    If we could find p, then c_i mod p < 2^126 (noise bound)
    """
    print("\n[*] Trying modular structure attack...")
    
    c0, c1 = ciphertexts[0], ciphertexts[1]
    
    # c_0 mod p = e_0 (small)
    # c_1 mod p = e_1 (small)
    # 
    # So: c_0 = p * (c_0 // p) + e_0
    # And: p = (c_0 - e_0) / q_0
    #
    # The challenge: we don't know e_0 or q_0!
    #
    # But we can use approximate factoring:
    # c_0 ≈ p * q_0, and p is ~128 bits, q is ~1024 bits
    # So c_0 is ~1152 bits
    
    # Try extracting 128-bit factor
    # c_0 / 2^1024 should be close to p
    
    # Actually, let's just try modular square root
    # If c_0 ≡ e_0 (mod p), and we know bounds on e_0
    # We can't directly find p this way without more info
    
    return None


def lattice_free_attack(ciphertexts):
    """
    Improved approximate GCD without full lattice reduction.
    
    Uses the algorithm from "Algorithms for the Approximate Common Divisor Problem"
    by Galbraith, Gebregiyorgis, Murphy
    
    For c_0 = p*q_0, c_1 = p*q_1 + small errors,
    use the Euclidean algorithm with early termination.
    """
    print("\n[*] Trying Euclidean-based approximate GCD...")
    
    c0, c1 = ciphertexts[0], ciphertexts[1]
    noise_bound = 2**126  # Upper bound on noise
    
    # Sort so c0 > c1
    if c0 < c1:
        c0, c1 = c1, c0
    
    # Run Euclidean algorithm but track all remainders
    remainders = []
    a, b = c0, c1
    
    while b > 0 and len(remainders) < 2000:
        q = a // b
        r = a % b
        remainders.append((a, b, q, r))
        
        # Check if we've found something interesting
        if 120 <= b.bit_length() <= 140:
            if is_prime(b):
                print(f"  Found prime in remainders: {b.bit_length()} bits")
                return b
        
        a, b = b, r
    
    print(f"[*] Generated {len(remainders)} remainders")
    
    # Check GCDs of original ciphertexts with remainders
    candidates = []
    for a, b, q, r in remainders:
        for val in [a, b, r]:
            if val != 0:
                g = gcd(ciphertexts[0], val)
                if g > 1 and 120 <= g.bit_length() <= 140:
                    candidates.append(g)
                    print(f"  Candidate: {g.bit_length()} bits, prime={is_prime(g)}")
    
    return candidates


def decrypt_with_key(p, ciphertexts, N=128):
    """Decrypt the flag using recovered p"""
    flag = ""
    for c in ciphertexts:
        m = (c % p) % N
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    return flag


def verify_key(p, ciphertexts, noise_bound=2**126):
    """Verify if p is the correct key by checking noise bounds"""
    for c in ciphertexts:
        noise = c % p
        if noise > noise_bound:
            return False
    return True


def main():
    print("=" * 60)
    print("DGHV Homomorphic Encryption Solver")
    print("=" * 60)
    
    # Get ciphertexts
    print("\n[*] Fetching ciphertexts from server...")
    ciphertexts = get_ciphertexts()
    print(f"[*] Got {len(ciphertexts)} ciphertexts")
    
    if len(ciphertexts) < 2:
        print("[!] Not enough ciphertexts")
        return
    
    # Try various attacks
    print("\n[*] Attempting continued fraction attack...")
    cf_candidates = approximate_gcd_attack(ciphertexts)
    
    # Try lattice-free attack
    lf_result = lattice_free_attack(ciphertexts)
    
    # Try small factors
    sf_result = small_factors_attack(ciphertexts)
    
    # Collect all candidates
    all_candidates = set()
    
    for _, cand, _ in cf_candidates:
        all_candidates.add(cand)
    
    if isinstance(lf_result, int):
        all_candidates.add(lf_result)
    elif isinstance(lf_result, list):
        all_candidates.update(lf_result)
    
    print(f"\n[*] Total candidates: {len(all_candidates)}")
    
    # Try decryption with each candidate
    for p in all_candidates:
        if not is_prime(p):
            continue
        
        print(f"\n[*] Trying p = {p} ({p.bit_length()} bits)")
        
        if verify_key(p, ciphertexts):
            flag = decrypt_with_key(p, ciphertexts)
            print(f"[!] Decrypted: {flag}")
            
            if "crypto{" in flag or flag.startswith("flag{"):
                print(f"\n[!!!] FLAG FOUND: {flag}")
                return flag
        else:
            print(f"  Key failed noise verification")
    
    print("\n[!] No valid key found with current attacks")
    print("[!] Need lattice-based attack (SageMath) for more power")
    
    # Save ciphertexts for external analysis
    with open("cts_for_sage.txt", "w") as f:
        f.write("ciphertexts = [\n")
        for c in ciphertexts:
            f.write(f"    {c},\n")
        f.write("]\n")
    print("\n[*] Saved ciphertexts to cts_for_sage.txt")


if __name__ == "__main__":
    main()
