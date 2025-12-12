#!/usr/bin/env python3
"""
DGHV Solver using olll library for LLL reduction
"""

import socket
from math import gcd
from functools import reduce
from fractions import Fraction
import olll

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


def is_prime(n, k=15):
    """Miller-Rabin primality test"""
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


def approximate_gcd_lattice(ciphertexts, num_cts=5, noise_bits=126):
    """
    Use LLL to solve approximate GCD
    
    Lattice construction:
    [ 2^noise_bits   0       0     ...   0    ]
    [ c_1           c_0      0     ...   0    ]
    [ c_2            0      c_0    ...   0    ]
    ...
    [ c_{n-1}        0       0     ...  c_0   ]
    
    Short vector reveals information about p
    """
    n = min(num_cts, len(ciphertexts))
    c0 = ciphertexts[0]
    
    K = 2 ** noise_bits
    
    # Build matrix
    matrix = []
    
    # First row
    row0 = [K] + [ciphertexts[i] for i in range(1, n)]
    matrix.append(row0)
    
    # Remaining rows  
    for i in range(1, n):
        row = [0] * n
        row[i] = c0
        matrix.append(row)
    
    print(f"[*] Built {n}x{n} matrix")
    print(f"[*] Running olll.reduction()...")
    
    try:
        reduced = olll.reduction(matrix, delta=Fraction(99, 100))
        print(f"[*] LLL completed")
        
        candidates = []
        for row in reduced:
            for entry in row:
                if entry != 0:
                    g = gcd(c0, abs(entry))
                    bits = g.bit_length()
                    if 120 <= bits <= 140:
                        candidates.append(g)
                        print(f"  Candidate: {g.bit_length()} bits, prime={is_prime(g)}")
        
        return candidates
    except Exception as e:
        print(f"[!] LLL failed: {e}")
        return []


def alternative_lattice(ciphertexts, num_cts=6, noise_bits=126):
    """
    Alternative lattice using differences
    """
    n = min(num_cts, len(ciphertexts))
    c0 = ciphertexts[0]
    
    # Use differences: d_i = c_0 - c_i = p*(q_0 - q_i) + (e_0 - e_i)
    diffs = [c0 - ciphertexts[i] for i in range(1, n)]
    
    # Create lattice to find small linear combinations
    K = 2 ** (noise_bits + 8)
    
    matrix = []
    
    # First row: scaling
    row0 = [K] + [0] * (n-1)
    matrix.append(row0)
    
    # Other rows: differences
    for i, d in enumerate(diffs):
        row = [d] + [0] * (n-1)
        row[i+1] = 1
        matrix.append(row)
    
    print(f"[*] Built alternative {n}x{n} matrix")
    
    try:
        reduced = olll.reduction(matrix, delta=Fraction(99, 100))
        
        candidates = []
        for row in reduced:
            val = row[0]
            if val != 0:
                g = gcd(c0, abs(val))
                bits = g.bit_length()
                if 100 <= bits <= 150:
                    candidates.append(g)
                    print(f"  Alt candidate: {g.bit_length()} bits")
        
        return candidates
    except Exception as e:
        print(f"[!] Alt LLL failed: {e}")
        return []


def crt_style_lattice(ciphertexts, num_cts=7, noise_bits=126):
    """
    Lattice based on the Coppersmith-style approach
    
    We want to find linear combination of c_i that is divisible by p
    """
    n = min(num_cts, len(ciphertexts))
    
    # Lattice: 
    # [ c_0  1  0  0  ...  0 ]
    # [ c_1  0  1  0  ...  0 ]
    # ...
    # [ c_n  0  0  0  ...  1 ]
    # [ K    0  0  0  ...  0 ]
    
    K = 2 ** (noise_bits + 5)
    
    matrix = []
    for i in range(n):
        row = [ciphertexts[i]] + [0] * n
        row[i+1] = 1
        matrix.append(row)
    
    # Add scaling row
    last_row = [K] + [0] * n
    matrix.append(last_row)
    
    print(f"[*] Built CRT-style {n+1}x{n+1} matrix")
    
    try:
        reduced = olll.reduction(matrix, delta=Fraction(99, 100))
        
        candidates = []
        for row in reduced:
            val = row[0]
            if val != 0 and abs(val).bit_length() < 200:
                g = gcd(ciphertexts[0], abs(val))
                if 100 <= g.bit_length() <= 150:
                    candidates.append(g)
                    print(f"  CRT candidate: {g.bit_length()} bits")
        
        return candidates
    except Exception as e:
        print(f"[!] CRT LLL failed: {e}")
        return []


def decrypt_flag(p, ciphertexts, N=128):
    """Decrypt using recovered p"""
    flag = ""
    for c in ciphertexts:
        m = (c % p) % N
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    return flag


def verify_key(p, ciphertexts):
    """Verify that p gives reasonable noise values"""
    noise_bound = 2**127
    for c in ciphertexts[:10]:
        noise = c % p
        if noise > noise_bound:
            return False
    return True


def main():
    print("=" * 60)
    print("DGHV Solver with olll Library")
    print("=" * 60)
    
    print("\n[*] Fetching ciphertexts...")
    ciphertexts = get_ciphertexts()
    print(f"[*] Got {len(ciphertexts)} ciphertexts")
    print(f"[*] First ciphertext: {ciphertexts[0].bit_length()} bits")
    
    # Try multiple lattice constructions
    all_candidates = set()
    
    print("\n" + "=" * 40)
    print("[*] Lattice Attack 1: Orthogonal")
    cands1 = approximate_gcd_lattice(ciphertexts, num_cts=5, noise_bits=126)
    all_candidates.update(cands1)
    
    print("\n" + "=" * 40)
    print("[*] Lattice Attack 2: Differences")
    cands2 = alternative_lattice(ciphertexts, num_cts=6, noise_bits=126)
    all_candidates.update(cands2)
    
    print("\n" + "=" * 40)
    print("[*] Lattice Attack 3: CRT-style")
    cands3 = crt_style_lattice(ciphertexts, num_cts=6, noise_bits=126)
    all_candidates.update(cands3)
    
    print(f"\n[*] Total unique candidates: {len(all_candidates)}")
    
    # Try decryption with each valid candidate
    for p in all_candidates:
        if not is_prime(p):
            continue
        
        bits = p.bit_length()
        print(f"\n[*] Testing prime p ({bits} bits)")
        
        if verify_key(p, ciphertexts):
            flag = decrypt_flag(p, ciphertexts)
            print(f"[!] Decrypted: {flag}")
            
            if flag.startswith("crypto{") or "flag{" in flag.lower():
                print(f"\n{'='*60}")
                print(f"[!!!] FLAG FOUND: {flag}")
                print(f"{'='*60}")
                return flag
        else:
            print(f"  Failed noise verification")
    
    print("\n[!] Could not find valid key")
    print("[*] May need more sophisticated lattice parameters")


if __name__ == "__main__":
    main()
