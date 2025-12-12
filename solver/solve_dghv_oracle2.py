#!/usr/bin/env python3
"""
DGHV Challenge - Oracle-Based Attack

New strategy: Use the oracle to recover bits of p

The oracle:
- Encrypts: c = p*q + N*r + m (where q is random 1024-bit, r < 2^119)  
- Decrypts: (c mod p) mod N

Key insight: We control N and m in our encryptions.
The decryption gives us (c mod p) mod N.

Since c = p*q + N*r + m:
c mod p = (N*r + m) mod p

If N*r + m < p (which is likely since p is 128-bit and N*r+m ~ 2^126):
c mod p = N*r + m (exact value!)

Then: (c mod p) mod N = (N*r + m) mod N = m

So decryption always returns m correctly for our inputs.

But what if we could cause (c mod p) to wrap around?

Idea: If we know c exactly and we know the decrypted value d:
d = (c mod p) mod N
c mod p = d + k*N for some k >= 0

If we could find k, we'd have c mod p = d + k*N
And then p divides (c - d - k*N) for some k, q

Actually, let me think differently...

NEW APPROACH: Factor the difference of ciphertexts

For FLAG: c_i = p*q_i + 128*r_i + m_i

If we knew two flag chars m_i, m_j:
c_i - m_i = p*q_i + 128*r_i  (call this a_i)
c_j - m_j = p*q_j + 128*r_j  (call this a_j)

a_i*a_j = (p*q_i + 128*r_i)(p*q_j + 128*r_j)
        = p^2*q_i*q_j + 128*p*r_j*q_i + 128*p*r_i*q_j + 128^2*r_i*r_j

This is complicated...

SIMPLER: GCD with known plaintext

We know the flag format: crypto{...}
So we know first 7 characters: c,r,y,p,t,o,{

For each known char m:
c - m = p*q + 128*r

GCD of all (c_i - m_i) for known positions should be... still 1 because q's are random.

FINAL TRY: CryptoHack flags also end with }

So last char is } (ASCII 125)

Let me look at the whole problem again...

The FLAG encrypted ciphertexts are GIVEN to us. We can't interact with them.
We CAN use the oracle for our own encrypt/decrypt.

Wait! The oracle uses the SAME p!

So if I encrypt a known message and get the ciphertext, I can try to factor c - m.
But c = p*q + N*r + m, so c - m = p*q + N*r, and gcd with other (c-m) is still 1.

Unless... I can make the oracle reveal information about p!

ATTACK: Encrypt a specially crafted message and analyze the ciphertext!

Actually, we can't see our encryption's ciphertext value directly.
The oracle encrypts internally and only returns decrypted values.

Hmm, let me re-read the challenge...

OH WAIT! Looking at the challenge code again:

The FLAG ciphertexts ARE the ciphertext integers, printed in the initial message!
We know c_i for each flag character.

And for our own encryptions:
- We don't see the ciphertext c
- We only see the decrypted message

So we can't get fresh ciphertexts with known plaintexts to analyze.

The only attack is on the FLAG ciphertexts we're given!

Let me try a more targeted attack: assume flag format and look for p.
"""

import socket
from math import gcd
from functools import reduce

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


def is_prime(n, k=15):
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


def factor_search(ciphertexts, known_prefix="crypto{", known_suffix="}"):
    """
    Given known prefix and suffix, try to find p.
    
    For prefix: c_i - m_i = p*q_i + 128*r_i
    For suffix (last char): c_n - 125 = p*q_n + 128*r_n
    """
    prefix_bytes = [ord(c) for c in known_prefix]
    suffix_byte = ord(known_suffix)
    
    n = len(ciphertexts)
    
    # Adjusted ciphertexts for known positions
    adjusted = []
    for i, m in enumerate(prefix_bytes):
        adjusted.append(ciphertexts[i] - m)
    adjusted.append(ciphertexts[-1] - suffix_byte)  # Last char is }
    
    print(f"[*] Got {len(adjusted)} adjusted ciphertexts")
    
    # Each adjusted[j] = p*q_j + 128*r_j
    #
    # If we could find the GCD of all adjusted values divided by p...
    # That doesn't work because q's are coprime.
    #
    # Let's try: for two adjusted values a and b:
    # a = p*q_a + e_a
    # b = p*q_b + e_b
    # 
    # a*b = p^2*q_a*q_b + p*(q_a*e_b + q_b*e_a) + e_a*e_b
    #
    # This doesn't factor nicely either.
    
    # Different approach: The error e = 128*r is bounded by ~2^126
    # Since p ~ 2^128, we have e < p for most cases
    # So a mod p = e_a (small!)
    # And b mod p = e_b (small!)
    # 
    # If we could find a number that both a and b are near-multiples of...
    # That's the approximate GCD problem!
    
    # Let's try: compute a - k*b for small k and check for good GCDs
    a, b = adjusted[0], adjusted[1]
    
    print(f"[*] Searching for good k in a - k*b...")
    
    candidates = []
    for k in range(-1000, 1000):
        diff = a - k * b
        if diff == 0:
            continue
        
        # Check gcd with original ciphertexts
        g = gcd(ciphertexts[0], abs(diff))
        if 120 <= g.bit_length() <= 140:
            candidates.append(g)
            print(f"  k={k}: GCD has {g.bit_length()} bits")
    
    return candidates


def ratio_continued_fraction_attack(ciphertexts, known_prefix="crypto{"):
    """
    Use continued fractions on ratio of adjusted ciphertexts.
    
    a_0/a_1 ≈ (p*q_0 + e_0)/(p*q_1 + e_1) ≈ q_0/q_1 (for large p*q >> e)
    
    From continued fraction, get approximation h/k ≈ q_0/q_1
    Then a_0*k - a_1*h ≈ e_0*k - e_1*h (small-ish)
    
    GCD of this with ciphertext might reveal p.
    """
    prefix_bytes = [ord(c) for c in known_prefix]
    
    a0 = ciphertexts[0] - prefix_bytes[0]
    a1 = ciphertexts[1] - prefix_bytes[1]
    
    # Continued fraction of a0/a1
    n, d = abs(a0), abs(a1)
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    candidates = []
    depth = 0
    
    while d != 0 and depth < 500:
        q = n // d
        n, d = d, n % d
        
        h_prev, h_curr = h_curr, q * h_curr + h_prev
        k_prev, k_curr = k_curr, q * k_curr + k_prev
        depth += 1
        
        # Try this convergent
        if k_curr != 0:
            diff = a0 * k_curr - a1 * h_curr
            if diff != 0:
                g = gcd(ciphertexts[0], abs(diff))
                if 120 <= g.bit_length() <= 140:
                    if is_prime(g):
                        candidates.append(g)
                        print(f"  CF depth {depth}: Found prime candidate, {g.bit_length()} bits")
    
    print(f"[*] Explored {depth} CF depths")
    return candidates


def small_prime_factor_search(ciphertexts, known_prefix="crypto{"):
    """
    Check if any adjusted ciphertext has small prime factors that could help.
    """
    prefix_bytes = [ord(c) for c in known_prefix]
    
    print("[*] Checking for small factors...")
    
    for i, m in enumerate(prefix_bytes):
        a = ciphertexts[i] - m
        
        # Check small primes
        for p_small in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            power = 0
            temp = a
            while temp % p_small == 0:
                temp //= p_small
                power += 1
            if power > 0:
                print(f"  c[{i}]-{m}: divisible by {p_small}^{power}")


def solve_directly(ciphertexts):
    """
    Given c_i = p*q_i + 128*r_i + m_i
    where m_i is ASCII (most likely 32-126)
    
    For 'crypto{...}':
    m_0 = 99, m_1 = 114, m_2 = 121, m_3 = 112, m_4 = 116, m_5 = 111, m_6 = 123
    m_last = 125
    
    We have 8 known plaintext-ciphertext pairs.
    """
    known = {
        0: 99,   # c
        1: 114,  # r
        2: 121,  # y
        3: 112,  # p
        4: 116,  # t
        5: 111,  # o
        6: 123,  # {
        -1: 125  # }
    }
    
    print("[*] Using known prefix 'crypto{' and suffix '}'")
    
    # Create adjusted values
    adjusted = []
    for pos, char in known.items():
        if pos == -1:
            adjusted.append((len(ciphertexts)-1, ciphertexts[-1] - char))
        else:
            adjusted.append((pos, ciphertexts[pos] - char))
    
    print(f"[*] Got {len(adjusted)} adjusted values")
    
    # Try all pairs for continued fraction attack
    candidates = set()
    
    for i in range(len(adjusted)):
        for j in range(i+1, len(adjusted)):
            pos_i, a_i = adjusted[i]
            pos_j, a_j = adjusted[j]
            
            if a_i == 0 or a_j == 0:
                continue
            
            # CF on a_i / a_j
            n, d = abs(a_i), abs(a_j)
            h_prev, h_curr = 0, 1
            k_prev, k_curr = 1, 0
            
            depth = 0
            while d != 0 and depth < 200:
                q = n // d
                n, d = d, n % d
                h_prev, h_curr = h_curr, q * h_curr + h_prev
                k_prev, k_curr = k_curr, q * k_curr + k_prev
                depth += 1
                
                if k_curr != 0:
                    diff = a_i * k_curr - a_j * h_curr
                    if diff != 0:
                        g = gcd(ciphertexts[0], abs(diff))
                        if 120 <= g.bit_length() <= 140 and is_prime(g):
                            candidates.add(g)
    
    return list(candidates)


def decrypt_flag(p, ciphertexts, N=128):
    flag = ""
    for c in ciphertexts:
        m = (c % p) % N
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    return flag


def verify_key(p, ciphertexts):
    for c in ciphertexts[:10]:
        noise = c % p
        if noise > 2**127:
            return False
    return True


def main():
    print("=" * 60)
    print("DGHV Oracle-Based Attack")
    print("=" * 60)
    
    print("\n[*] Fetching ciphertexts...")
    ciphertexts = get_ciphertexts()
    print(f"[*] Got {len(ciphertexts)} ciphertexts")
    
    # Try multiple attacks
    all_candidates = set()
    
    print("\n" + "=" * 40)
    print("[*] Attack 1: Factor search")
    c1 = factor_search(ciphertexts)
    all_candidates.update(c1)
    
    print("\n" + "=" * 40)
    print("[*] Attack 2: CF on adjusted ciphertexts")
    c2 = ratio_continued_fraction_attack(ciphertexts)
    all_candidates.update(c2)
    
    print("\n" + "=" * 40)
    print("[*] Attack 3: Small prime factors")
    small_prime_factor_search(ciphertexts)
    
    print("\n" + "=" * 40)
    print("[*] Attack 4: Direct solve with known pairs")
    c4 = solve_directly(ciphertexts)
    all_candidates.update(c4)
    
    print(f"\n[*] Total prime candidates: {len(all_candidates)}")
    
    for p in all_candidates:
        print(f"\n[*] Testing p = {p.bit_length()} bits")
        
        if verify_key(p, ciphertexts):
            flag = decrypt_flag(p, ciphertexts)
            print(f"[!] Decrypted: {flag}")
            
            if flag.startswith("crypto{"):
                print(f"\n{'='*60}")
                print(f"[!!!] FLAG: {flag}")
                print(f"{'='*60}")
                return flag
    
    print("\n[!] No valid key found")


if __name__ == "__main__":
    main()
