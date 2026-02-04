#!/usr/bin/env python3
"""
CU29 Challenge Solver
=====================

Vulnerabilities:
1. d is small: d < n^0.34
2. We have pq = (p+q) >> 200 (high bits of p+q)
3. e = 23 with (p-1) % e == 0 or (q-1) % e == 0

Attack Strategy:
- We know p + q ≈ pq << 200 (approximately)
- We know p * q = n
- From these, we can solve for p, q using quadratic formula:
  p, q are roots of: x^2 - (p+q)*x + n = 0
  
The challenge is that we only know the high bits of (p+q).
We need to brute force the unknown low bits.

Alternative: Use Boneh-Durfee if d is truly small enough.
"""

import gmpy2
from Crypto.Util.number import long_to_bytes

# Challenge data
n = 74400198359942513862730376031146135802606791991588575465056163121555925617314946580878695576381159966669035646513358312316295727962048929334491638793366454990554957760082895721209907599102882541383389817613899931138405942694622063421798336056156478661669460226638891433547765658851966477956365621503055329677
e = 23
c = 67093879684168042482911544476248580360412038370701084199780323275036434279521774982225923057805337317989111708384627608827582845935869416467560399759225810925388294903783674263633367996837459206550597542374370661621276546154790021615738055122556152562693170717804941676044793478893041430142032267013836633841
pq_high = 10742021914074381086319674056236928469987565979831767505178443989041183736389136816846636592297
ee = 51932890691025605005017310915612916271600777979505331615727718159287280323849710338181794701070147316145187464745426238779347565715981026060820382009264707825630065910448457401066737999090581631520459289158388406640542880406872203650158510808041068826069081102690337835303900100550250976587109590929801721407

print("[*] CU29 Challenge Solver")
print(f"[*] n bit length: {n.bit_length()}")
print(f"[*] e = {e}")
print(f"[*] pq_high = (p+q) >> 200")
print()

# Approach 1: Reconstruct p+q from high bits and solve quadratic
# pq_high = (p+q) >> 200
# So: p+q ≈ pq_high << 200

# The unknown low 200 bits mean we have:
# p + q = (pq_high << 200) + x  where 0 <= x < 2^200

print("[*] Method 1: Quadratic solving with brute force on low bits")
print("[*] This requires brute forcing up to 2^200 values - too many!")
print()

# Approach 2: Use the relationship between e and ee
# We have: e = 23, ee = d^(-1) mod phi
# And: d is small (< n^0.34)
# 
# From ee * d ≡ 1 (mod phi), if we can find d, we can factor n

print("[*] Method 2: Using ee to find d (Boneh-Durfee style)")
print(f"[*] ee bit length: {ee.bit_length()}")
print()

# Since d < n^0.34, and ee * d ≡ 1 (mod phi)
# We have: ee * d = k * phi + 1 for some k
# And: phi ≈ n (since phi = n - p - q + 1)
# 
# ee * d ≈ k * n
# k ≈ ee * d / n
# Since d < n^0.34, k < ee * n^0.34 / n = ee / n^0.66
# 
# k is relatively small!

# Actually, let's try Wiener on ee since d is small
print("[*] Method 3: Wiener's attack on (n, ee) to find d")

from fractions import Fraction

def continued_fractions(a, b):
    fractions = []
    while b != 0:
        fractions.append(a // b)
        a, b = b, a % b
    return fractions

def convergents(cf):
    convs = []
    for i in range(len(cf)):
        if i == 0: 
            convs.append(Fraction(cf[0]))
        elif i == 1: 
            convs.append(Fraction(cf[1] * cf[0] + 1, cf[1]))
        else:
            convs.append(Fraction(
                cf[i] * convs[i-1].numerator + convs[i-2].numerator,
                cf[i] * convs[i-1].denominator + convs[i-2].denominator
            ))
    return convs

# Wiener on ee
cf = continued_fractions(ee, n)
convs = convergents(cf)

print(f"[*] Testing {len(convs)} convergents...")

for i, frac in enumerate(convs):
    k, d = frac.numerator, frac.denominator
    if k == 0: 
        continue
    if d <= 0:
        continue
    
    # Check if this d works: ee * d ≡ 1 (mod phi)
    # We need to find phi such that (ee * d - 1) / k = phi
    if (ee * d - 1) % k != 0:
        continue
    
    phi = (ee * d - 1) // k
    
    # phi = (p-1)(q-1) = n - p - q + 1
    # So: p + q = n - phi + 1
    s = n - phi + 1
    
    # p, q are roots of x^2 - s*x + n = 0
    # Discriminant = s^2 - 4n
    disc = s*s - 4*n
    
    if disc < 0:
        continue
    
    sqrt_disc = gmpy2.isqrt(disc)
    if sqrt_disc * sqrt_disc != disc:
        continue
    
    p = (s + sqrt_disc) // 2
    q = (s - sqrt_disc) // 2
    
    if p * q == n:
        print(f"\n[+] Wiener SUCCESS at convergent {i}!")
        print(f"[+] d = {d}")
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        
        # Verify
        phi_real = (p - 1) * (q - 1)
        
        # Decrypt with the ORIGINAL e=23 (not ee!)
        # c = m^e mod n
        # m = c^d_original mod n where d_original = e^(-1) mod phi
        d_original = pow(e, -1, phi_real)
        m = pow(c, d_original, n)
        
        flag = long_to_bytes(m)
        print(f"\n[+] FLAG: {flag}")
        break
    print("[-] Wiener attack failed")
    
    # Since Wiener failed, let's try a different approach
    # d < n^0.34 is in the Boneh-Durfee range
    
    print("\n[*] Method 4: Using pq_high leak directly")
    
    # p + q = (pq_high << 200) + x where x is the unknown lower 200 bits
    # Actually pq_high = (p+q) >> 200, so x could be up to 2^200
    # But we can narrow it down...
    
    # Let s = p + q, then p and q are roots of t^2 - s*t + n = 0
    # For real roots: s^2 >= 4n, so s >= 2*sqrt(n)
    
    import math
    sqrt_n = gmpy2.isqrt(n)
    min_sum = 2 * sqrt_n
    
    print(f"[*] sqrt(n) ≈ {sqrt_n}")
    print(f"[*] Minimum p+q = 2*sqrt(n) ≈ {min_sum}")
    
    # pq_high << 200 should be close to p+q
    base_sum = pq_high << 200
    print(f"[*] Base p+q from leak: {base_sum}")
    
    # The issue: pq_high is the HIGH bits, so:
    # p + q = pq_high * 2^200 + remainder (0 to 2^200 - 1)
    # 
    # We need to search the remainder space, but 2^200 is too large!
    # 
    # Alternative: Note that for RSA with 512-bit primes:
    # p + q ≈ 2^513 (roughly)
    # The leak gives us the high bits with good precision
    
    # Let's compute what the expected sum should be:
    # n = p*q ≈ 2^1024
    # If p ≈ q ≈ 2^512, then p+q ≈ 2^513
    
    expected_sum_bits = (n.bit_length() + 1) // 2 + 1  # roughly
    print(f"[*] Expected p+q bit length: ~{expected_sum_bits}")
    print(f"[*] base_sum bit length: {base_sum.bit_length()}")
    
    # The remainder is the low 200 bits of (p+q)
    # Since p,q are 512-bit, p+q is ~513 bits
    # pq_high has ~313 bits of the sum
    
    # Strategy: Use a meet-in-the-middle or lattice approach
    # 
    # Actually, let me check if the base_sum already works!
    # The >> 200 truncates, it doesn't round
    
    # Try values where low bits are set to reasonable guesses
    print("\n[*] Trying common low-bit patterns...")
    
    test_offsets = [0]
    
    # Add powers of 2 minus small values
    for shift in range(0, 200, 10):
        test_offsets.append(1 << shift)
        test_offsets.append((1 << shift) - 1)
    
    for offset in test_offsets:
        s = base_sum + offset
        disc = s*s - 4*n
        
        if disc < 0:
            continue
        
        sqrt_disc, exact = gmpy2.iroot(disc, 2)
        if not exact:
            continue
        
        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        
        if p * q == n:
            print(f"\n[+] Found factors with offset {offset}!")
            print(f"[+] p = {p}")
            print(f"[+] q = {q}")
            
            phi = (p - 1) * (q - 1)
            d_dec = pow(e, -1, phi)
            m = pow(c, d_dec, n)
            
            flag = long_to_bytes(m)
            print(f"\n[+] FLAG: {flag}")
            exit(0)
    
    print("[-] Pattern search failed")
    
    # Final attempt: Maybe the problem is simpler than expected
    # Check if ee works directly as the decryption exponent
    print("\n[*] Method 5: Trying ee directly as decryption exponent")
    
    # In the challenge, d was chosen, then ee = d^(-1) mod phi
    # So ee could be used directly to encrypt, and d to decrypt...
    # Wait, the original encryption uses e=23, not ee
    # c = m^23 mod n
    
    # Hmm, let me try a different approach:
    # ee and 23 are related through phi
    # ee * d ≡ 1 (mod phi) where d is the secret
    # 23 * d_23 ≡ 1 (mod phi)
    
    # We could try: c^d mod n where d relates to 23
    # But we don't have d_23 directly...
    
    # Let's try if the challenge is using ee for encryption by mistake
    print("[*] Trying ee as encryption exponent (maybe challenge error)...")
    
    # If c = m^ee mod n, then m = c^d mod n where d*ee ≡ 1 (mod phi)
    # We don't know phi, but we can try...
    
    # Actually, a key insight: if we compute m = c^d mod n using Wiener's d,
    # that might give us something
    
    # Let's check what d-values Wiener found (even if they didn't factor n)
    print("\n[*] Method 6: Testing all Wiener d candidates for direct decryption")
    
    for i, frac in enumerate(convs[:100]):  # First 100 convergents
        k, d_test = frac.numerator, frac.denominator
        if d_test <= 1:
            continue
        
        # Try decrypting with this d
        # But we encrypted with e=23, not ee...
        # This won't directly work
        pass
    
    print("[-] Need to use SageMath for Coppersmith/Boneh-Durfee")
    print("[*] Generating Sage script...")
    
    sage_script = f'''
# SageMath script for CU29
# Run with: sage solve_cu29.sage

n = {n}
e = 23
c = {c}
ee = {ee}
pq_high = {pq_high}

# Method 1: Partial p+q with Coppersmith
# p + q = pq_high * 2^200 + x, find small x

P.<x> = PolynomialRing(Zmod(n))

# s = p + q = pq_high << 200 + x
# p, q roots of t^2 - s*t + n = 0
# p = (s + sqrt(s^2 - 4n)) / 2
# 
# We want to find x such that s^2 - 4n is a perfect square

base = pq_high * 2^200

# f(x) = (base + x)^2 - 4*n = 0 has a root modulo some factor of n
# Actually, we need: base + x = p + q exactly

# Try small_roots
f = (base + x)^2 - 4*n
roots = f.small_roots(X=2^200, beta=0.5)
print("Roots:", roots)

for r in roots:
    s = base + int(r)
    disc = s^2 - 4*n
    if disc >= 0:
        sqrt_disc = isqrt(disc)
        if sqrt_disc^2 == disc:
            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2
            if p*q == n:
                print(f"p = {{p}}")
                print(f"q = {{q}}")
                phi = (p-1)*(q-1)
                d = inverse_mod(e, phi)
                m = power_mod(c, d, n)
                print(f"Flag: {{bytes.fromhex(hex(m)[2:])}}")
'''
    
    print(sage_script)

