#!/usr/bin/env python3
"""
DGHV Challenge - Alternative Attack Strategies

After analyzing the challenge more carefully:

1. The FLAG is encrypted with p*q + 128*r + m where:
   - p is a 128-bit prime (same for all chars in one session)
   - q is random 1024-bit
   - r is bounded by 2^119
   - m is the ASCII char (0-127)

2. We get 36 ciphertexts (flag length)

3. We have an encrypt/decrypt oracle with the SAME p

KEY INSIGHT: The oracle uses the SAME p!

So if we can somehow learn p through the oracle, we can decrypt the flag.

ATTACK IDEA 1: Noise Cancellation
If we encrypt 0 with N=128, we get c_0 = p*q + 128*r + 0
If we could get c_0 mod p, we'd have 128*r (small)

But to get c_0 mod p, we need p...

ATTACK IDEA 2: Known Plaintext Attack
We encrypt known values and analyze the ciphertexts.

Let's encrypt the same byte multiple times and look for patterns.

ATTACK IDEA 3: GCD of (c - m) for correct m
For each FLAG ciphertext c_i = p*q_i + 128*r_i + m_i
If we guess m_i correctly: c_i - m_i = p*q_i + 128*r_i

Taking GCD of (c_i - m_i) for correct guesses might reveal p.

ATTACK IDEA 4: Using the homomorphic property
c_sum = encrypt(a) + encrypt(b) decrypts to (a+b) mod N
This doesn't directly help with FLAG unless we can manipulate it.

ATTACK IDEA 5: Lattice with correct parameters
The standard DGHV attack requires:
- Using the approximate GCD problem
- Proper lattice construction
- Efficient LLL/BKZ

Let me try a different lattice formulation.
"""

import socket
from math import gcd
from functools import reduce
import itertools

HOST = "archive.cryptohack.org"
PORT = 21970


def get_ciphertexts():
    """Get fresh ciphertexts from server"""
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


def is_prime(n, k=10):
    """Miller-Rabin"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
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


def try_gcd_with_guess(ciphertexts, char_guesses):
    """
    Try to find p by guessing characters and taking GCD of (c - m)
    
    If m_i is correct: c_i - m_i = p*q_i + 128*r_i = p*q_i + noise
    
    GCD of multiple (c_i - m_i) with correct guesses should reveal p
    or a multiple of p.
    """
    adjusted = [c - m for c, m in zip(ciphertexts, char_guesses)]
    g = reduce(gcd, adjusted)
    return g


def try_known_prefix_attack(ciphertexts):
    """
    CryptoHack flags have format: crypto{...}
    
    We know first 7 characters: c, r, y, p, t, o, {
    ASCII: 99, 114, 121, 112, 116, 111, 123
    
    Let's verify this and try to extract p.
    """
    prefix = "crypto{"
    prefix_bytes = [ord(c) for c in prefix]
    
    print(f"[*] Trying known prefix: {prefix}")
    print(f"[*] ASCII values: {prefix_bytes}")
    
    # Adjust ciphertexts by subtracting known plaintext
    adjusted = []
    for i, m in enumerate(prefix_bytes):
        if i < len(ciphertexts):
            adjusted.append(ciphertexts[i] - m)
    
    print(f"[*] Got {len(adjusted)} adjusted ciphertexts")
    
    # Now each adjusted[i] = c_i - m_i = p*q_i + 128*r_i
    # 
    # At this point, if we take GCD, we get gcd(p*q_i + noise, p*q_j + noise)
    # which is likely 1 since q's are random.
    #
    # But we can try pairwise combinations and linear combinations.
    
    g = reduce(gcd, adjusted)
    print(f"[*] GCD of adjusted: {g} ({g.bit_length()} bits)")
    
    # Try continued fraction on ratio of first two
    if len(adjusted) >= 2:
        a, b = adjusted[0], adjusted[1]
        # a/b ≈ (p*q_0 + e_0) / (p*q_1 + e_1) ≈ q_0/q_1
        # 
        # Using continued fractions to find q_0/q_1
        # Then a*k - b*h might reveal something about p
        
        convergents = []
        n, d = a, b
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        
        while d != 0 and len(convergents) < 300:
            q_cf = n // d
            n, d = d, n % d
            h_prev, h_curr = h_curr, q_cf * h_curr + h_prev
            k_prev, k_curr = k_curr, q_cf * k_curr + k_prev
            convergents.append((h_curr, k_curr))
        
        print(f"[*] Generated {len(convergents)} convergents")
        
        candidates = []
        for h, k in convergents:
            if k == 0:
                continue
            diff = a * k - b * h
            if diff != 0:
                g = gcd(ciphertexts[0], abs(diff))
                if 100 < g.bit_length() < 150:
                    candidates.append((g, h, k))
                    if len(candidates) <= 5:
                        print(f"  Candidate: {g.bit_length()} bits")
        
        return candidates
    
    return []


def extended_euclidean_attack(ciphertexts, prefix="crypto{"):
    """
    More sophisticated attack using extended Euclidean algorithm
    on adjusted ciphertexts.
    """
    prefix_bytes = [ord(c) for c in prefix]
    n_known = len(prefix_bytes)
    
    # Adjusted values: c_i - m_i = p*q_i + 128*r_i
    adjusted = [ciphertexts[i] - prefix_bytes[i] for i in range(n_known)]
    
    # For the difference of two adjusted values:
    # (c_i - m_i) - (c_j - m_j) = p*(q_i - q_j) + 128*(r_i - r_j)
    # 
    # Since q's are 1024-bit random, q_i - q_j is also ~1024 bits
    # and 128*(r_i - r_j) is bounded by roughly 2*128*2^119 = 2^128
    
    # Let's try a specific trick:
    # Consider d_ij = adjusted[i] - adjusted[j]
    # d_ij = p * (q_i - q_j) + small_noise
    #
    # If we can find two d's that share a common factor near 128 bits...
    
    diffs = []
    for i in range(n_known):
        for j in range(i+1, n_known):
            diffs.append(adjusted[i] - adjusted[j])
    
    # Try GCD of differences
    if len(diffs) > 1:
        g_diffs = reduce(gcd, diffs)
        print(f"[*] GCD of differences: {g_diffs} ({g_diffs.bit_length()} bits)")
    
    return adjusted


def brute_force_small_noise_attack(ciphertexts):
    """
    The noise is bounded: 128*r + m < 2^126 + 127
    
    If we knew the exact noise, we could recover p*q exactly.
    
    Let's try: is the flag perhaps just ASCII printable?
    All chars in [32, 126]?
    
    For known prefix "crypto{", the last char is '}' = 125.
    
    Actually, let me try something simpler:
    The ratio of ciphertexts should be close to ratio of q's.
    """
    c0, c1 = ciphertexts[0], ciphertexts[1]
    
    # c0 / c1 ≈ (p*q0 + e0) / (p*q1 + e1) ≈ q0 / q1 (since e << p*q)
    # More precisely: c0/c1 = q0/q1 * (1 + O(e/(p*q)))
    
    # The error is tiny, so continued fractions should find the exact ratio
    # once we get past a certain depth.
    
    # Then: c0 * q1 - c1 * q0 = (p*q0 + e0)*q1 - (p*q1 + e1)*q0
    #                        = e0*q1 - e1*q0
    # 
    # This is actually NOT small because q's are 1024-bit!
    # So this approach won't directly work.
    
    # Alternative: look at c0 % c1 in the Euclidean sequence
    # and check for values around 128 bits.
    
    print("\n[*] Euclidean algorithm on ciphertexts...")
    a, b = c0, c1
    remainders = []
    
    while b > 0:
        q = a // b
        r = a % b
        remainders.append((a, b, q, r))
        a, b = b, r
    
    print(f"[*] Found {len(remainders)} remainders")
    
    # Check if any remainder is close to 128 bits
    candidates = []
    for a, b, q, r in remainders:
        for val in [b, r]:
            if val > 0 and 120 <= val.bit_length() <= 140:
                if is_prime(val):
                    candidates.append(val)
                    print(f"  Found prime in remainders: {val.bit_length()} bits")
    
    return candidates


def main():
    print("=" * 60)
    print("DGHV Alternative Attack Strategies")
    print("=" * 60)
    
    print("\n[*] Fetching ciphertexts...")
    ciphertexts = get_ciphertexts()
    print(f"[*] Got {len(ciphertexts)} ciphertexts")
    print(f"[*] First ciphertext: {ciphertexts[0].bit_length()} bits")
    
    # Try known prefix attack
    print("\n" + "=" * 40)
    print("[*] Attack 1: Known Prefix (crypto{)")
    candidates = try_known_prefix_attack(ciphertexts)
    
    # Try extended Euclidean
    print("\n" + "=" * 40)
    print("[*] Attack 2: Extended Euclidean")
    adjusted = extended_euclidean_attack(ciphertexts)
    
    # Try brute force small noise
    print("\n" + "=" * 40)
    print("[*] Attack 3: Euclidean Remainders")
    remainder_candidates = brute_force_small_noise_attack(ciphertexts)
    
    # Collect all candidates
    all_candidates = set()
    for item in candidates:
        if isinstance(item, tuple):
            all_candidates.add(item[0])
        else:
            all_candidates.add(item)
    all_candidates.update(remainder_candidates)
    
    print(f"\n[*] Total candidates: {len(all_candidates)}")
    
    # Try decryption
    N = 128
    for p in all_candidates:
        if not is_prime(p):
            continue
        
        print(f"\n[*] Trying p = {p.bit_length()} bits")
        
        # Verify: (c mod p) should be small (< 2^127)
        valid = True
        for c in ciphertexts[:5]:
            noise = c % p
            if noise > 2**127:
                valid = False
                break
        
        if valid:
            flag = ""
            for c in ciphertexts:
                m = (c % p) % N
                if 0 <= m < 128:
                    flag += chr(m)
                else:
                    flag += "?"
            
            print(f"[!] Decrypted: {flag}")
            
            if flag.startswith("crypto{"):
                print(f"\n[!!!] FLAG: {flag}")
                return
    
    print("\n[!] No valid key found with these attacks")
    print("[*] Need SageMath for proper lattice reduction")


if __name__ == "__main__":
    main()
