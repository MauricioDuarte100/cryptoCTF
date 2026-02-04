#!/usr/bin/env python3
"""
quik maff Solver
=================

We have:
- N = p*q
- e = random prime < 2^10
- cts = [m1^e, m2^e, m3^e] mod N  
- hint = m1 + m2 + m3

Attack: Brute force e (small), then use lattice/Grobner to solve system.

Since e is small (< 1024), we can try all primes < 1024.
For each e, we try to find m1, m2, m3 such that:
- m1^e = c1 mod N
- m2^e = c2 mod N  
- m3^e = c3 mod N
- m1 + m2 + m3 = hint

This is a polynomial system that can be solved with Grobner bases or lattices.
"""

from Crypto.Util.number import long_to_bytes, bytes_to_long
import sympy
from sympy import symbols, Poly
from itertools import product

# Parse the output - directly define values
N = 5981664384988507891478572449251897296717727847212579781448791472718547112403550208352320926002397616312181279859738938646168022481824206589739320298482728968548378237391009138243024910596491172979923991673446034011260330224409794208875199561844435663744993504673450898288161482849187018770655419007178851937895764901674192425054643548670616348302447202491340266057221307744866082461604674766259695903766772980842036324667567850124019171425634526227426965833985082234968255176231124754301435374519312001547854794352023852342682220352109083558778402466358598254431167382653831478713628185748237886560605604945010671417

cts = [
    4064195644006411160585797813860027634920635349984344191047587061586620848352019080467087592184982883284356841385019453458842500930190512793665886381102812026066865666098391973664302897278510995945377153937248437062600080527317980210967973971371047319247120004523147629534186514628527555180736833194525516718549330721987873868571634294877416190209288629499265010822332662061001208360467692613959936438519512705706688327846470352610192922218603268096313278741647626899523312431823527174576009143724850631439559205050395629961996905961682800070679793831568617438035643749072976096500278297683944583609092132808342160168,
    3972397619896893471633226994966440180689669532336298201562465946694941720775869427764056001983618377003841446300122954561092878433908258359050016399257266833626893700179430172867058140215023211349613449750819959868861260714924524414967854467488908710563470522800186889553825417008118394349306170727982570843758792622898850338954039322560740348595654863475541846505121081201633770673996898756298398831948133434844321091554344145679504115839940880338238034227536355386474785852916335583794757849746186832609785626770517073108801492522816245458992502698143396049695921044554959802743742110180934416272358039695942552488,
    956566266150449406104687131427865505474798294715598448065695308619216559681163085440476088324404921175885831054464222377255942505087330963629877648302727892001779224319839877897857215091085980519442914974498275528112936281916338633178398286676523416008365096599844169979821513770606168325175652094633129536643417367820830724397070621662683223203491074814734747601002376621653739871373924630026694962642922871008486127796621355314581093953946913681152270251669050414866366693593651789709229310574005739535880988490183275291507128529820194381392682870291338920077175831052974790596134745552552808640002791037755434586
]

hint = 2674558878275613295915981392537201653631411909654166620884912623530781


print("[*] quik maff Solver")
print(f"[*] N = {N}")
print(f"[*] N bits = {N.bit_length()}")
print(f"[*] hint = {hint}")
print(f"[*] hint bits = {hint.bit_length()}")
print(f"[*] Number of ciphertexts: {len(cts)}")
print()

# Generate primes < 2^10
def is_prime(n):
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0: return False
    return True

primes = [p for p in range(2, 1024) if is_prime(p)]
print(f"[*] Testing {len(primes)} primes for e...")

# For small e, we can try:
# If m1 + m2 + m3 = S (known), and we have c1, c2, c3
# Let m3 = S - m1 - m2
# Then: (S - m1 - m2)^e = c3 mod N
#
# Combined with m1^e = c1, m2^e = c2
# This is still hard without more structure

# Alternative: Hastad's Broadcast Attack variant
# But we have same N, not different N's

# Let's try a simple check: maybe e is small enough that we can
# factor the sums somehow

# First, let's try small e values and see if we can find something
# that works with the cube root trick or similar

import gmpy2

for e in primes[:50]:  # Try small primes first
    print(f"\r  Trying e = {e}...", end="", flush=True)
    
    # Check if any ciphertext has an exact e-th root
    for i, c in enumerate(cts):
        root, exact = gmpy2.iroot(c, e)
        if exact:
            msg = long_to_bytes(int(root))
            if msg.isascii() and b'{' in msg:
                print(f"\n[+] Found with e={e}, message {i}: {msg}")
    
    # Check if c = m^e without modular reduction
    # (i.e., m^e < N)

print("\n")

# If simple root doesn't work, try lattice approach
# We need to find m1, m2, m3 such that sum = hint

# Actually, let's try a different approach:
# For each e, compute all roots mod N (if possible)
# Then check which combination sums to hint

# Method: Use Z3 SAT solver for small e
print("[*] Trying Z3 constraint solver...")

try:
    from z3 import *
    
    for e in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        print(f"  Trying e = {e}...")
        
        # Create symbolic variables
        m1, m2, m3 = Ints('m1 m2 m3')
        
        s = Solver()
        s.set("timeout", 10000)  # 10 second timeout
        
        # Constraints
        s.add(m1 >= 0, m2 >= 0, m3 >= 0)
        s.add(m1 < N, m2 < N, m3 < N)
        s.add(m1 + m2 + m3 == hint)
        
        # These constraints are hard to express in Z3 for large numbers
        # Let's skip Z3 for now
        
except ImportError:
    print("[*] Z3 not available")

# Final approach: assume messages are small and try direct computation
print("\n[*] Trying direct approach assuming small messages...")

# The hint is about 273 bits, so each message is roughly 90-100 bits
# This is still a lot to brute force

# Let's check if the flag format gives us hints
# Flags usually start with a known prefix

# Try assuming m1 starts with "flag{" or similar
# flag{ = 0x666c61677b = 439898260347

flag_prefix = bytes_to_long(b"flag{")
print(f"[*] Assuming first message starts with 'flag{{': {flag_prefix}")

# For now, let's try a simpler approach:
# Check if N is factorizable
print("\n[*] Checking if N is factorable...")

# Quick trial division
for small_p in range(2, 100000):
    if N % small_p == 0:
        p = small_p
        q = N // p
        print(f"\n[+] N factored!")
        print(f"[+] p = {p}")  
        print(f"[+] q = {q}")
        
        phi = (p - 1) * (q - 1)
        
        # Now we can find d for any e
        for e in primes:
            if gmpy2.gcd(e, phi) != 1:
                continue
            d = pow(e, -1, phi)
            
            # Decrypt
            pts_recovered = [pow(c, d, N) for c in cts]
            
            # Check if sum matches
            if sum(pts_recovered) == hint:
                print(f"\n[+] FOUND e = {e}")
                for i, pt in enumerate(pts_recovered):
                    msg = long_to_bytes(pt)
                    print(f"[+] Message {i+1}: {msg}")
                exit(0)
        break

print("\n[-] Could not solve with simple approaches")
print("[*] This challenge likely requires SageMath with Grobner bases")
