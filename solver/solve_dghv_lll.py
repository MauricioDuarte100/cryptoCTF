#!/usr/bin/env python3
"""
LLL-based Approximate GCD Attack for DGHV Challenge
Using gmpy2 for big integer arithmetic
"""

import socket
from math import gcd
from fractions import Fraction
import gmpy2
from gmpy2 import mpz, mpq

HOST = "archive.cryptohack.org"
PORT = 21970


def get_ciphertexts():
    """Fetch fresh ciphertexts from server"""
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
                    encrypted.append(mpz(stripped))
                except:
                    pass
            if "Now you get to" in line:
                break
    
    return encrypted


def dot_product(v1, v2):
    """Dot product of two vectors of mpz"""
    return sum(x * y for x, y in zip(v1, v2))


def vector_subtract(v1, v2):
    """Vector subtraction"""
    return [x - y for x, y in zip(v1, v2)]


def scalar_multiply(scalar, v):
    """Scalar multiplication"""
    return [scalar * x for x in v]


def gram_schmidt_coefficient(v, u, u_dot_u):
    """μ = <v, u> / <u, u>"""
    if u_dot_u == 0:
        return mpq(0)
    return mpq(dot_product(v, u), u_dot_u)


def lll_reduce(basis, delta=0.75):
    """
    LLL lattice reduction algorithm for big integers
    
    Input: List of basis vectors (each vector is a list of mpz)
    Output: LLL-reduced basis
    """
    n = len(basis)
    if n == 0:
        return basis
    
    m = len(basis[0])
    
    # Make a copy
    B = [list(v) for v in basis]
    
    # Gram-Schmidt orthogonalization (on the fly)
    def compute_gs():
        """Compute Gram-Schmidt orthogonalized basis and coefficients"""
        B_star = []
        mu = [[mpq(0)] * n for _ in range(n)]
        
        for i in range(n):
            v = list(B[i])
            for j in range(i):
                mu[i][j] = mpq(dot_product(B[i], B_star[j]), dot_product(B_star[j], B_star[j])) if dot_product(B_star[j], B_star[j]) != 0 else mpq(0)
                v = vector_subtract(v, scalar_multiply(mu[i][j], B_star[j]))
            B_star.append(v)
        
        return B_star, mu
    
    k = 1
    iterations = 0
    max_iterations = 500  # Prevent infinite loops
    
    while k < n and iterations < max_iterations:
        iterations += 1
        B_star, mu = compute_gs()
        
        # Size reduction step
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > mpq(1, 2):
                q = int(round(float(mu[k][j])))
                B[k] = vector_subtract(B[k], scalar_multiply(mpz(q), B[j]))
                B_star, mu = compute_gs()
        
        # Lovász condition
        Bk_star_norm = dot_product(B_star[k], B_star[k])
        Bk1_star_norm = dot_product(B_star[k-1], B_star[k-1])
        
        lhs = Bk_star_norm
        rhs = (mpq(delta) - mu[k][k-1] * mu[k][k-1]) * Bk1_star_norm
        
        if lhs >= rhs:
            k += 1
        else:
            # Swap B[k] and B[k-1]
            B[k], B[k-1] = B[k-1], B[k]
            k = max(k - 1, 1)
    
    print(f"[*] LLL completed in {iterations} iterations")
    return B


def approximate_gcd_lattice(ciphertexts, num_cts=5, noise_bits=126):
    """
    Solve approximate GCD using lattice reduction
    """
    n = min(num_cts, len(ciphertexts))
    c0 = ciphertexts[0]
    
    # Construct the lattice
    # Using Howgrave-Graham's orthogonal lattice approach
    # 
    # Matrix:
    # [ K   c_1   c_2   ...  c_{n-1} ]
    # [ 0   -c_0   0    ...    0     ]
    # [ 0    0   -c_0   ...    0     ]
    # ...
    # [ 0    0     0    ...  -c_0    ]
    #
    # Where K = 2^noise_bits (scaling factor)
    
    K = mpz(2) ** noise_bits
    
    # Build basis vectors
    basis = []
    
    # First vector
    v0 = [K] + [ciphertexts[i] for i in range(1, n)]
    basis.append(v0)
    
    # Remaining vectors
    for i in range(1, n):
        v = [mpz(0)] * n
        v[i] = -c0
        basis.append(v)
    
    print(f"[*] Constructed {n}x{n} lattice")
    print(f"[*] Running LLL...")
    
    reduced = lll_reduce(basis)
    
    print(f"[*] Analyzing reduced basis...")
    
    candidates = []
    for row in reduced:
        for entry in row:
            if entry != 0:
                g = gcd(int(c0), abs(int(entry)))
                bits = g.bit_length()
                if 100 <= bits <= 150:
                    candidates.append(g)
                    print(f"  Candidate: {bits} bits")
    
    return candidates


def alternative_lattice(ciphertexts, num_cts=6, noise_bits=126):
    """
    Alternative lattice construction
    
    Consider c_i = p * q_i + e_i
    
    We want to find a short vector in the lattice generated by columns of:
    [ c_0  c_1  c_2  ...  c_n ]
    [  1    0    0  ...   0   ]
    [  0    1    0  ...   0   ]
    ...
    [  0    0    0  ...   1   ]
    
    Scaled appropriately
    """
    n = min(num_cts, len(ciphertexts))
    K = mpz(2) ** (noise_bits + 5)  # Noise scaling
    
    # Build row-based lattice
    basis = []
    
    # First row: scaled ciphertexts
    v0 = [K] + [mpz(0)] * n
    basis.append(v0)
    
    # Remaining rows: ciphertexts and identity
    for i in range(n):
        v = [ciphertexts[i]] + [mpz(0)] * n
        v[i + 1] = mpz(1)
        basis.append(v)
    
    print(f"[*] Built {len(basis)}x{len(basis[0])} alternative lattice")
    print(f"[*] Running LLL...")
    
    reduced = lll_reduce(basis)
    
    candidates = []
    for row in reduced:
        val = row[0]
        if val != 0 and abs(int(val)).bit_length() < 200:
            g = gcd(int(ciphertexts[0]), abs(int(val)))
            if 100 <= g.bit_length() <= 150:
                candidates.append(g)
                print(f"  Candidate from row[0]: {g.bit_length()} bits")
    
    return candidates


def is_prime(n, k=15):
    """Miller-Rabin primality test using gmpy2"""
    return gmpy2.is_prime(n)


def decrypt_flag(p, ciphertexts, N=128):
    """Decrypt using recovered p"""
    flag = ""
    for c in ciphertexts:
        m = int(c) % p % N
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    return flag


def verify_key(p, ciphertexts, noise_bound=2**127):
    """Check if p gives reasonable noise values"""
    for c in ciphertexts:
        noise = int(c) % p
        if noise > noise_bound:
            return False
    return True


def main():
    print("=" * 60)
    print("DGHV Approximate GCD Solver (Pure Python + gmpy2)")
    print("=" * 60)
    
    print("\n[*] Fetching ciphertexts...")
    ciphertexts = get_ciphertexts()
    print(f"[*] Got {len(ciphertexts)} ciphertexts")
    
    if len(ciphertexts) < 3:
        print("[!] Not enough ciphertexts")
        return
    
    # Try lattice attacks
    print("\n[*] Attempting orthogonal lattice attack...")
    candidates1 = approximate_gcd_lattice(ciphertexts, num_cts=5)
    
    print("\n[*] Attempting alternative lattice attack...")
    candidates2 = alternative_lattice(ciphertexts, num_cts=5)
    
    all_candidates = set(candidates1 + candidates2)
    print(f"\n[*] Total unique candidates: {len(all_candidates)}")
    
    # Try each candidate
    for p in all_candidates:
        if not is_prime(p):
            continue
        
        print(f"\n[*] Testing p = {p} ({p.bit_length()} bits)")
        
        if verify_key(p, ciphertexts):
            flag = decrypt_flag(p, ciphertexts)
            print(f"[!] Decrypted: {flag}")
            
            if "crypto{" in flag or flag.startswith("flag{") or "CTF{" in flag:
                print(f"\n[!!!] FLAG FOUND: {flag}")
                return
        else:
            print("  Failed noise verification")
    
    print("\n[!] No valid key found")
    print("[*] The lattice might need more iterations or different parameters")
    
    # Save for external tools
    with open("ciphertexts_mpz.txt", "w") as f:
        for c in ciphertexts:
            f.write(f"{c}\n")
    print("[*] Saved ciphertexts to ciphertexts_mpz.txt")


if __name__ == "__main__":
    main()
