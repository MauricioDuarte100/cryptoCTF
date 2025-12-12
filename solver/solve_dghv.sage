#!/usr/bin/env sage
"""
DGHV Approximate GCD Attack using Lattice Reduction

The challenge uses DGHV homomorphic encryption:
c = p*q + N*r + m

Where:
- p is a 128-bit prime (secret key)
- q is a random 1024-bit number
- N = 128 (for flag encryption)
- r is noise bounded by 2^119
- m is the message byte (ASCII char, 0-127)

The noise term is: N*r + m < 128 * 2^119 + 127 ≈ 2^126

Attack Strategy:
We use the Simultaneous Diophantine Approximation attack.
Given ciphertexts c_0, c_1, ..., c_n all encrypted with same p,
we can recover p using lattice reduction.

Reference: 
- "Fully Homomorphic Encryption over the Integers" (DGHV)
- Approximate GCD problem and its lattice formulation
"""

import sys

# Read ciphertexts
ciphertexts = []
with open("dghv_ciphertexts.txt", "r") as f:
    for line in f:
        line = line.strip()
        if line:
            ciphertexts.append(Integer(line))

print(f"[*] Loaded {len(ciphertexts)} ciphertexts")
c = ciphertexts

# Parameters from the challenge
N = 128  # Modulus used for flag encryption
noise_bits = 126  # Upper bound on noise (N*r + m < 2^126)
p_bits = 128  # p is a 128-bit prime
q_bits = 1024  # q is 1024 bits

# For the approximate GCD attack, we use the lattice:
# Given c_0, c_1, ..., c_n where c_i = p * q_i + e_i (error/noise)
# 
# We construct a lattice where solving SVP/CVP gives us p
#
# Method 1: Orthogonal Lattice Attack
# For two ciphertexts c_0 and c_1:
# c_0 = p*q_0 + e_0
# c_1 = p*q_1 + e_1
#
# Consider: c_0 * c_1' - c_1 * c_0' where we seek (c_0', c_1') small
# If we could find q's: q_1*c_0 - q_0*c_1 = q_1*e_0 - q_0*e_1 (small)
#
# Method 2: Scaling trick
# We know c_0/p ≈ q_0, c_1/p ≈ q_1
# So c_1/c_0 ≈ q_1/q_0
# We can use continued fractions to find this ratio!

print("\n[*] Attempting continued fraction attack...")

# For the approximate GCD, we look at ratios
# c_i / c_j ≈ q_i / q_j (when noise is small)
# Using continued fractions on this ratio might give us the exact q_i / q_j

def cf_attack_on_pair(c0, c1, noise_bound):
    """
    Use continued fractions to find the approximate ratio c0/c1 ≈ q0/q1
    Then p ≈ gcd-like structure
    """
    ratio = c0 / c1
    cf = continued_fraction(ratio)
    convergents = cf.convergents()
    
    for conv in convergents[:100]:  # Check first 100 convergents
        q0_guess = conv.numerator()
        q1_guess = conv.denominator()
        
        if q0_guess == 0 or q1_guess == 0:
            continue
            
        # Check if this gives us p
        # c0 * q1_guess - c1 * q0_guess should be small (error related)
        diff = c0 * q1_guess - c1 * q0_guess
        
        # If the guesses are correct ratios:
        # diff = (p*q0 + e0)*q1_guess - (p*q1 + e1)*q0_guess
        #      = p*(q0*q1_guess - q1*q0_guess) + e0*q1_guess - e1*q0_guess
        # If q0_guess/q1_guess = q0/q1, then q0*q1_guess = q1*q0_guess
        # So diff = e0*q1_guess - e1*q0_guess
        
        # For recovering p, try gcd approach
        if diff != 0:
            g = gcd(c0, abs(diff))
            if g > 1 and g.nbits() >= 120 and g.nbits() <= 140:
                print(f"  Found candidate g = {g} ({g.nbits()} bits)")
                if is_prime(g):
                    print(f"  [!] Found prime p = {g}")
                    return g
    return None

# Try continued fraction on several pairs
for i in range(min(5, len(c))):
    for j in range(i+1, min(6, len(c))):
        print(f"[*] Trying CF attack on c[{i}] / c[{j}]...")
        result = cf_attack_on_pair(c[i], c[j], 2^noise_bits)
        if result:
            print(f"[!!!] SUCCESS! Found p = {result}")
            break
    if result:
        break

# Method 3: Direct lattice approach
# Construct matrix M:
# | 2^(noise_bits)  0        0    ...  0   |
# | c_1            -c_0      0    ...  0   |
# | c_2             0       -c_0  ...  0   |
# | ...                                     |
# | c_n             0        0    ... -c_0 |
#
# Short vector in this lattice reveals p

print("\n[*] Attempting lattice-based approximate GCD...")

def lattice_attack(ciphertexts, num_cts=5, noise_bound=2^126):
    """
    Construct a lattice to solve the approximate GCD problem
    """
    n = min(num_cts, len(ciphertexts))
    c0 = ciphertexts[0]
    
    # Use Howgrave-Graham's orthogonal lattice
    # Lattice basis:
    # [ K  c_1  c_2  ...  c_n ]
    # [ 0  -c_0  0   ...  0   ]
    # [ 0   0   -c_0 ...  0   ]
    # ...
    # [ 0   0    0   ... -c_0 ]
    #
    # K is a scaling factor to balance dimensions
    
    K = 2^(noise_bits)  # Noise bound
    
    M = matrix(ZZ, n, n)
    M[0, 0] = K
    for i in range(1, n):
        M[0, i] = ciphertexts[i]
        M[i, i] = -c0
    
    print(f"[*] Lattice dimension: {n}x{n}")
    print(f"[*] Running LLL...")
    
    L = M.LLL()
    
    print(f"[*] LLL completed. Analyzing short vectors...")
    
    # The short vector should be (K, e_1*q_0 - e_0*q_1, ...)
    # or multiples thereof that reveal p
    
    candidates = []
    for row in L:
        # Check each entry
        for entry in row:
            if entry != 0:
                # Try to extract p
                g = gcd(c0, abs(entry))
                if g > 1 and 120 <= g.nbits() <= 140:
                    candidates.append(g)
    
    return candidates

candidates = lattice_attack(c)
print(f"[*] Candidates found: {len(candidates)}")
for cand in set(candidates):
    print(f"  - {cand} ({cand.nbits()} bits, prime={is_prime(cand)})")

# Method 4: Different lattice formulation
print("\n[*] Trying alternative lattice construction...")

def alt_lattice_attack(ciphertexts, num_cts=6):
    """
    Alternative approach: use the structure more directly
    
    c_i = p*q_i + e_i
    
    Consider: c_1*x_1 + c_2*x_2 + ... + c_n*x_n ≡ 0 (mod p)
    
    We want to find small x_i such that the above holds
    This is an SVP problem in the lattice generated by c_i's
    """
    n = min(num_cts, len(ciphertexts))
    
    # Scaling factor
    B = 2^(noise_bits)
    
    # Create lattice [identity | scaled c]
    # We're looking for short vectors (x_1, ..., x_n) such that 
    # sum(c_i * x_i) is small (divisible by p)
    
    M = matrix(ZZ, n+1, n+1)
    
    # First row: [B, c_0, c_1, ..., c_{n-1}]
    M[0, 0] = B
    for i in range(n):
        M[0, i+1] = 0
    
    # Remaining rows: identity with ciphertexts
    for i in range(n):
        for j in range(n):
            if i == j:
                M[i+1, j+1] = 1
            else:
                M[i+1, j+1] = 0
        M[i+1, 0] = ciphertexts[i]
    
    print(f"[*] Running LLL on {n+1}x{n+1} matrix...")
    L = M.LLL()
    
    # Check short vectors
    for row in L[:5]:
        val = row[0]
        if val != 0:
            # This should be related to a linear combination
            # that equals something divisible by p
            print(f"  Short vector first entry: {val} ({val.nbits()} bits)")
    
    return L

L = alt_lattice_attack(c)

# Method 5: Sigma-based attack
print("\n[*] Trying sigma-based multivariate attack...")

def sigma_attack(ciphertexts, num_cts=7):
    """
    Use the fact that c_i - c_j = p*(q_i - q_j) + (e_i - e_j)
    
    The differences have smaller "q" components when q_i, q_j are close
    Create a lattice from pairwise differences
    """
    n = min(num_cts, len(ciphertexts))
    diffs = []
    
    for i in range(n):
        for j in range(i+1, n):
            diffs.append(ciphertexts[i] - ciphertexts[j])
    
    print(f"[*] Computing GCD of differences...")
    g = diffs[0]
    for d in diffs[1:]:
        g = gcd(g, d)
    
    print(f"[*] GCD of differences: {g} ({g.nbits()} bits)")
    
    # Factor g to find potential p
    if g > 1 and g.nbits() < 200:
        print(f"[*] Attempting factorization...")
        try:
            factors = factor(g)
            print(f"[*] Factors: {factors}")
            for f, e in factors:
                if 120 <= f.nbits() <= 140 and is_prime(f):
                    print(f"[!!!] Found candidate p = {f}")
                    return f
        except:
            pass
    
    return None

p_candidate = sigma_attack(c)

# If we found p, decrypt the flag!
def decrypt_flag(p, ciphertexts, N=128):
    """Decrypt using (c mod p) mod N"""
    flag = ""
    for c_i in ciphertexts:
        m = (c_i % p) % N
        flag += chr(m)
    return flag

# Try with any candidates we found
print("\n[*] Attempting decryption with candidates...")
for cand in set(candidates):
    if is_prime(cand):
        try:
            flag = decrypt_flag(cand, c)
            if flag.startswith("crypto{") or all(32 <= ord(ch) <= 126 for ch in flag):
                print(f"\n[!!!] FLAG: {flag}")
                break
            else:
                print(f"  Candidate {cand}: {repr(flag[:20])}...")
        except:
            pass

print("\n[*] Done!")
