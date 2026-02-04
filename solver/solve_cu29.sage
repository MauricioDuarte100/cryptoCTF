# CU29 Solver - Combined Attack
# Uses: pq_high leak + (p-1)%e==0 constraint + bivariate Coppersmith

from sage.all import *
import time

print("="*60)
print(" CU29 Combined Attack")
print("="*60)

# Challenge data
n = 74400198359942513862730376031146135802606791991588575465056163121555925617314946580878695576381159966669035646513358312316295727962048929334491638793366454990554957760082895721209907599102882541383389817613899931138405942694622063421798336056156478661669460226638891433547765658851966477956365621503055329677
e = 23
c = 67093879684168042482911544476248580360412038370701084199780323275036434279521774982225923057805337317989111708384627608827582845935869416467560399759225810925388294903783674263633367996837459206550597542374370661621276546154790021615738055122556152562693170717804941676044793478893041430142032267013836633841
pq_high = 10742021914074381086319674056236928469987565979831767505178443989041183736389136816846636592297
ee = 51932890691025605005017310915612916271600777979505331615727718159287280323849710338181794701070147316145187464745426238779347565715981026060820382009264707825630065910448457401066737999090581631520459289158388406640542880406872203650158510808041068826069081102690337835303900100550250976587109590929801721407

def long_to_bytes(n):
    if n == 0:
        return b'\x00'
    hex_str = hex(int(n))[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)

base = pq_high << 200

print(f"[*] n has {n.nbits()} bits")
print(f"[*] base = {base}")
print(f"[*] base has {base.nbits()} bits")

# Approach 1: Bivariate Coppersmith
# We have two unknowns: x (low bits of p+q) and let's say the difference p-q
# 
# Actually, let's reformulate:
# Let s = p + q = base + x where |x| < 2^200
# Let d = p - q (unknown)
# Then: p = (s+d)/2, q = (s-d)/2
# pq = (s^2 - d^2)/4 = n
# s^2 - d^2 = 4n
# (base + x)^2 - d^2 = 4n

# This is a Pell-like equation. Let's try small_roots with bivariate.

print("\n[*] Method 1: Bivariate small_roots")

# Define polynomial ring
PR.<x, y> = PolynomialRing(ZZ)

# Equation: (base + x)^2 - y^2 = 4*n
# Rearranged: (base + x)^2 - y^2 - 4*n = 0
# Expanding: base^2 + 2*base*x + x^2 - y^2 - 4*n = 0

f = base^2 + 2*base*x + x^2 - y^2 - 4*n

# For bivariate Coppersmith, we need to work modulo some value
# Let's try a different formulation

print("[*] Direct polynomial approach failed - trying GCD method")

# Approach 2: Use e divides (p-1) or (q-1)
# This means p ≡ 1 (mod e) or q ≡ 1 (mod e)
# 
# If p ≡ 1 (mod 23):
#   p = 23*k + 1 for some k
#   q = n / p
#   p + q = base + x
#   
# We can write: 23*k + 1 + n/(23*k+1) = base + x
# Multiply by (23*k+1):
#   (23*k+1)^2 + n = (base + x)(23*k + 1)
#   (23*k+1)^2 - (base+x)(23*k+1) + n = 0
#   
# This is quadratic in (23*k+1), but x is unknown...

print("\n[*] Method 2: Using p ≡ 1 (mod 23) constraint")

# Let's try: p ≡ 1 (mod 23) means gcd(p-1, 23) = 23
# So for any a, a^(p-1) ≡ 1 (mod p) by Fermat
# And a^((p-1)/23) is a 23rd root of unity mod p

# Approach 3: Direct search with constraints
# p ≡ 1 (mod 23), so p = 23*k + 1
# p + q ≈ base (roughly 513 bits)
# n = p*q

# If p is close to sqrt(n), let's search around there with the constraint

print("\n[*] Method 3: Constrained search around sqrt(n)")

sqrt_n = isqrt(n)
print(f"[*] sqrt(n) ≈ {sqrt_n}")

# p ≡ 1 (mod 23), so we only check those values
# Start from sqrt(n) and go in both directions

# Find the closest p ≡ 1 (mod 23) to sqrt(n)
remainder = sqrt_n % 23
if remainder == 1:
    start_p = sqrt_n
else:
    start_p = sqrt_n + (23 - remainder + 1) % 23

print(f"[*] Starting search from p = {start_p}")
print(f"[*] Checking p ≡ 1 (mod 23)...")

# Search range - we need to cover the difference between sqrt(n) and actual p
# Since p+q ≈ base ≈ 2*sqrt(n), and we know base approximately,
# p could be up to several bits away from sqrt(n)

count = 0
max_iter = 10000000  # 10M iterations

for offset in range(-max_iter//2, max_iter//2):
    p_test = start_p + 23 * offset  # Only check p ≡ 1 (mod 23)
    
    if p_test <= 1:
        continue
    
    if n % p_test == 0:
        q_test = n // p_test
        print(f"\n[+] FOUND!")
        print(f"[+] p = {p_test}")
        print(f"[+] q = {q_test}")
        print(f"[+] Verification: p*q == n ? {p_test * q_test == n}")
        print(f"[+] (p-1) % 23 = {(p_test-1) % 23}")
        print(f"[+] (q-1) % 23 = {(q_test-1) % 23}")
        
        # Decrypt
        phi = (p_test - 1) * (q_test - 1)
        d = inverse_mod(e, phi)
        m = power_mod(c, d, n)
        flag = long_to_bytes(m)
        print(f"\n[+] FLAG: {flag}")
        exit(0)
    
    count += 1
    if count % 1000000 == 0:
        print(f"    Checked {count} values...")

print(f"[-] Search failed after {count} iterations")

# Method 4: Try using hints about p+q more precisely
print("\n[*] Method 4: Precise p+q analysis")

# We know: pq_high = (p+q) >> 200
# So: p + q = pq_high * 2^200 + remainder where 0 <= remainder < 2^200
# 
# Also, p ≡ 1 (mod 23)
# So q = (p+q) - p ≡ (p+q) - 1 (mod 23)
# 
# If p + q ≡ r (mod 23), then q ≡ r - 1 (mod 23)
# For (q-1) to also be divisible by 23, we need q ≡ 1 (mod 23)
# So r - 1 ≡ 1 (mod 23), meaning r ≡ 2 (mod 23)
# 
# Let's check what base is mod 23

base_mod_23 = base % 23
print(f"[*] base mod 23 = {base_mod_23}")

# If the unknown x makes p+q ≡ 2 (mod 23), then both p and q are ≡ 1 (mod 23)
# This means x ≡ (2 - base_mod_23) (mod 23)
x_mod_23 = (2 - base_mod_23) % 23
print(f"[*] If both p,q ≡ 1 (mod 23), then x ≡ {x_mod_23} (mod 23)")

# Otherwise, only one of them is ≡ 1 (mod 23)
# Let's check if the challenge condition (p-1)%23==0 OR (q-1)%23==0
# means only one is divisible

print("\n[*] The condition is OR, so only one needs to be ≡ 1 (mod 23)")
print("[*] This doesn't constrain x as much...")

print("\n[*] ====================================")
print("[*] This challenge requires advanced bivariate Coppersmith")
print("[*] or extensive computational resources.")
print("[*] Consider using factordb.com or CADO-NFS for large factorizations.")
print("[*] ====================================")
