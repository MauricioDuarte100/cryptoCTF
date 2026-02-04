#!/usr/bin/env sage
"""
Solver for quik maff challenge

Vulnerability Analysis:
-----------------------
We have:
- N = p*q (RSA modulus)
- e = secret prime exponent, e < 2^10 (so at most 168 primes to try)
- pts = [m1, m2, m3] (unknown plaintexts)
- cts = [c1, c2, c3] (ciphertexts where ci = mi^e mod N)
- hint = m1 + m2 + m3

Attack Strategy:
1. Brute-force e from all primes < 2^10
2. For each e, try to find the plaintexts using:
   - If we can factor N, we can decrypt directly
   - Otherwise, use lattice-based methods or Gröbner basis

Since we have 3 equations and 3 unknowns with the sum constraint,
we can use resultants or lattice methods.
"""

from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools

# Challenge data
N = 5981664384988507891478572449251897296717727847212579781448791472718547112403550208352320926002397616312181279859738938646168022481824206589739320298482728968548378237391009138243024910596491172979923991673446034011260330224409794208875199561844435663744993504673450898288161482849187018770655419007178851937895764901674192425054643548670616348302447202491340266057221307744866082461604674766259695903766772980842036324667567850124019171425634526227426965833985082234968255176231124754301435374519312001547854794352023852342682220352109083558778402466358598254431167382653831478713628185748237886560605604945010671417
cts = [4064195644006411160585797813860027634920635349984344191047587061586620848352019080467087592184982883284356841385019453458842500930190512793665886381102812026066865666098391973664302897278510995945377153937248437062600080527317980210967973971371047319247120004523147629534186514628527555180736833194525516718549330721987873868571634294877416190209288629499265010822332662061001208360467692613959936438519512705706688327846470352610192922218603268096313278741647626899523312431823527174576009143724850631439559205050395629961996905961682800070679793831568617438035643749072976096500278297683944583609092132808342160168, 3972397619896893471633226994966440180689669532336298201562465946694941720775869427764056001983618377003841446300122954561092878433908258359050016399257266833626893700179430172867058140215023211349613449750819959868861260714924524414967854467488908710563470522800186889553825417008118394349306170727982570843758792622898850338954039322560740348595654863475541846505121081201633770673996898756298398831948133434844321091554344145679504115839940880338238034227536355386474785852916335583794757849746186832609785626770517073108801492522816245458992502698143396049695921044554959802743742110180934416272358039695942552488, 956566266150449406104687131427865505474798294715598448065695308619216559681163085440476088324404921175885831054464222377255942505087330963629877648302727892001779224319839877897857215091085980519442914974498275528112936281916338633178398286676523416008365096599844169979821513770606168325175652094633129536643417367820830724397070621662683223203491074814734747601002376621653739871373924630026694962642922871008486127796621355314581093953946913681152270251669050414866366693593651789709229310574005739535880988490183275291507128529820194381392682870291338920077175831052974790596134745552552808640002791037755434586]
hint = 2674558878275613295915981392537201653631411909654166620884912623530781


def get_primes_up_to(n):
    """Return all primes less than n"""
    return list(primes(2, n))


def try_factor_n():
    """Attempt to factor N"""
    print("[*] Attempting to factor N...")
    # Try small factor test
    for p in primes(2, 10**6):
        if N % p == 0:
            return p, N // p
    
    # Check if N is a perfect power
    # ECM would be too slow for this size
    return None


def solve_with_grob(e):
    """
    Try to solve using Gröbner basis
    We have:
    - m1^e = c1 mod N
    - m2^e = c2 mod N  
    - m3^e = c3 mod N
    - m1 + m2 + m3 = hint

    This is tricky over Z/NZ, so we work symbolically first
    """
    pass


def solve_with_lattice(e):
    """
    Use lattice-based approach:
    We know m1 + m2 + m3 = hint
    If the mi are small enough, we might be able to use Coppersmith
    """
    pass


def brute_force_small_flags(e):
    """
    For small exponent e, if messages are small enough,
    we can try to find them by taking e-th roots
    """
    print(f"[*] Trying e = {e}...")
    
    # Check if any ciphertext has small e-th root (no modular reduction happened)
    for i, c in enumerate(cts):
        # Check if c^(1/e) is an integer (no mod happened)
        root = Integer(c).nth_root(e, truncate_mode=True)
        if root[1]:  # exact root found
            print(f"[+] ct[{i}] has exact {e}-th root: {root[0]}")
            try:
                msg = long_to_bytes(int(root[0]))
                print(f"[+] Possible message: {msg}")
            except:
                pass
    
    return None


def solve_resultant(e):
    """
    Use resultants to eliminate variables.
    We have:
    - m1^e - c1 = 0 mod N
    - m2^e - c2 = 0 mod N
    - m3 = hint - m1 - m2
    
    So (hint - m1 - m2)^e - c3 = 0 mod N
    
    We can compute resultant(m1^e - c1, (hint - m1 - m2)^e - c3, m1) to get poly in m2
    Then solve resultant(m2^e - c2, that_poly, m2) to get constant or contradiction
    """
    print(f"[*] Trying resultant method with e = {e}...")
    
    R.<m1, m2> = PolynomialRing(Zmod(N), 2)
    
    # Equations
    f1 = m1^e - cts[0]
    f2 = m2^e - cts[1]
    f3 = (hint - m1 - m2)^e - cts[2]
    
    # Try Gröbner basis (might be slow or infeasible)
    try:
        I = ideal([f1, f2, f3])
        # This might not work well over Z/NZ
    except:
        pass
    
    return None


def solve_coppersmith(e):
    """
    Coppersmith's method for small roots.
    We have m1 + m2 + m3 = hint where mi^e = ci mod N.
    
    Try: assume messages are roughly equal in size, each about hint/3.
    Let m1 = hint/3 + x1, m2 = hint/3 + x2, m3 = hint/3 + x3
    where x1 + x2 + x3 = 0 and each xi is small.
    """
    print(f"[*] Trying Coppersmith with e = {e}...")
    
    avg = hint // 3
    
    # Check if avg^e is close to any ct
    for i, c in enumerate(cts):
        check = pow(avg, e, N)
        if check == c:
            print(f"[+] Found m{i+1} = {avg}")
    
    return None


def hastad_attack(e):
    """
    Håstad's broadcast attack if same message encrypted multiple times.
    But here we have different messages, so not directly applicable.
    """
    pass


def franklin_reiter(e):
    """
    Franklin-Reiter attack when messages are related by a linear function.
    m1 + m2 + m3 = hint is a linear relation!
    
    If e is small (e.g., 3), we can use polynomial GCD.
    """
    print(f"[*] Trying Franklin-Reiter with e = {e}...")
    
    if e > 7:
        return None  # Only practical for small e
    
    # We have:
    # m1^e = c1, m2^e = c2, (hint - m1 - m2)^e = c3
    # 
    # Let's try special case: if any two messages are especially related
    
    return None


def solve():
    print(f"[*] Starting solver for quik maff")
    print(f"[*] N has {N.bit_length()} bits")
    print(f"[*] hint = {hint}")
    print(f"[*] hint has {hint.bit_length()} bits")
    
    # Get all primes less than 2^10
    possible_e = get_primes_up_to(2**10)
    print(f"[*] Testing {len(possible_e)} possible values for e")
    
    # First, check for small e-th roots (Håstad's insight)
    for e in possible_e:
        # For each e, check if c^(1/e) < N^(1/e) for any ct
        # This would mean no modular reduction happened
        
        for i, c in enumerate(cts):
            # Check e-th root
            try:
                root = Integer(c).nth_root(e, truncate_mode=True)
                if root[1]:  # exact integer root
                    m = int(root[0])
                    # Verify it's a valid message
                    if pow(m, e, N) == c:
                        print(f"[+] Found exact root for ct[{i}] with e = {e}")
                        print(f"[+] m = {m}")
                        try:
                            print(f"[+] As bytes: {long_to_bytes(m)}")
                        except:
                            pass
            except:
                pass
    
    # Try to factor N first
    factors = try_factor_n()
    if factors:
        p, q = factors
        print(f"[+] Factored N: p = {p}, q = {q}")
        
        phi = (p - 1) * (q - 1)
        
        for e in possible_e:
            if gcd(e, phi) == 1:
                d = inverse_mod(e, phi)
                m1 = pow(cts[0], d, N)
                m2 = pow(cts[1], d, N)
                m3 = pow(cts[2], d, N)
                
                if m1 + m2 + m3 == hint:
                    print(f"[+] Found correct e = {e}")
                    print(f"[+] m1 = {long_to_bytes(m1)}")
                    print(f"[+] m2 = {long_to_bytes(m2)}")
                    print(f"[+] m3 = {long_to_bytes(m3)}")
                    return (m1, m2, m3)
    
    # If we can't factor N, try other approaches
    print("[*] Could not factor N easily, trying algebraic methods...")
    
    # The hint is much smaller than N - about 237 bits vs 2048 bits
    # This means the messages themselves must be small!
    # Each message is approximately hint/3 ≈ 79 bits
    
    print(f"[*] Average message size estimate: {(hint // 3).bit_length()} bits")
    
    # For small messages with small e, we might be able to just take roots!
    for e in possible_e:
        for i, c in enumerate(cts):
            # If m < N^(1/e), then m^e < N, so c = m^e without modular reduction
            bound = int(N ** (1/e))
            
            root_result = Integer(c).nth_root(e, truncate_mode=True)
            if root_result[1]:
                m = int(root_result[0])
                if pow(m, e, N) == c and 0 < m < N:
                    print(f"[+] ct[{i}] decrypts directly with e={e}")
                    print(f"[+] m = {m}")
    
    # Try small e values more carefully
    for e in [3, 5, 7]:
        if e in possible_e:
            print(f"\n[*] Detailed analysis for e = {e}...")
            
            # Use Coppersmith's small roots
            # We know m1 + m2 + m3 = hint, and each mi^e = ci mod N
            # Since hint << N, messages are small
            
            # Check if messages are small enough that mi^e < N
            max_msg = hint  # Upper bound
            if max_msg ** e < N:
                print(f"[+] Messages small enough: {max_msg}^{e} < N")
                print(f"[+] Direct e-th roots should work!")
                
                m1 = Integer(cts[0]).nth_root(e, truncate_mode=True)
                m2 = Integer(cts[1]).nth_root(e, truncate_mode=True)
                m3 = Integer(cts[2]).nth_root(e, truncate_mode=True)
                
                if m1[1] and m2[1] and m3[1]:
                    m1, m2, m3 = int(m1[0]), int(m2[0]), int(m3[0])
                    print(f"[+] m1 = {m1}, m2 = {m2}, m3 = {m3}")
                    print(f"[+] Sum = {m1 + m2 + m3}")
                    print(f"[+] Hint = {hint}")
                    if m1 + m2 + m3 == hint:
                        print(f"[!] FOUND THE MESSAGES!")
                        flag1 = long_to_bytes(m1)
                        flag2 = long_to_bytes(m2)
                        flag3 = long_to_bytes(m3)
                        print(f"[+] Part 1: {flag1}")
                        print(f"[+] Part 2: {flag2}")
                        print(f"[+] Part 3: {flag3}")
                        print(f"[+] Flag: {flag1 + flag2 + flag3}")
                        return (flag1, flag2, flag3)
    
    print("[-] Could not solve with basic methods")
    return None


if __name__ == "__main__":
    result = solve()
    if result:
        print(f"\n[SUCCESS] Challenge solved!")
    else:
        print(f"\n[FAILED] Could not solve challenge")
