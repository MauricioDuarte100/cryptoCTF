#!/usr/bin/env python3
"""
Solver for quik maff - Using factordb or online factorization

The key insight: if we can factor N, we can solve this easily.
Let's try to factor N using known factorization services or methods.
"""

import requests
from Crypto.Util.number import long_to_bytes
from sympy import primerange, gcd

# Challenge data
N = 5981664384988507891478572449251897296717727847212579781448791472718547112403550208352320926002397616312181279859738938646168022481824206589739320298482728968548378237391009138243024910596491172979923991673446034011260330224409794208875199561844435663744993504673450898288161482849187018770655419007178851937895764901674192425054643548670616348302447202491340266057221307744866082461604674766259695903766772980842036324667567850124019171425634526227426965833985082234968255176231124754301435374519312001547854794352023852342682220352109083558778402466358598254431167382653831478713628185748237886560605604945010671417
cts = [4064195644006411160585797813860027634920635349984344191047587061586620848352019080467087592184982883284356841385019453458842500930190512793665886381102812026066865666098391973664302897278510995945377153937248437062600080527317980210967973971371047319247120004523147629534186514628527555180736833194525516718549330721987873868571634294877416190209288629499265010822332662061001208360467692613959936438519512705706688327846470352610192922218603268096313278741647626899523312431823527174576009143724850631439559205050395629961996905961682800070679793831568617438035643749072976096500278297683944583609092132808342160168, 3972397619896893471633226994966440180689669532336298201562465946694941720775869427764056001983618377003841446300122954561092878433908258359050016399257266833626893700179430172867058140215023211349613449750819959868861260714924524414967854467488908710563470522800186889553825417008118394349306170727982570843758792622898850338954039322560740348595654863475541846505121081201633770673996898756298398831948133434844321091554344145679504115839940880338238034227536355386474785852916335583794757849746186832609785626770517073108801492522816245458992502698143396049695921044554959802743742110180934416272358039695942552488, 956566266150449406104687131427865505474798294715598448065695308619216559681163085440476088324404921175885831054464222377255942505087330963629877648302727892001779224319839877897857215091085980519442914974498275528112936281916338633178398286676523416008365096599844169979821513770606168325175652094633129536643417367820830724397070621662683223203491074814734747601002376621653739871373924630026694962642922871008486127796621355314581093953946913681152270251669050414866366693593651789709229310574005739535880988490183275291507128529820194381392682870291338920077175831052974790596134745552552808640002791037755434586]
hint = 2674558878275613295915981392537201653631411909654166620884912623530781


def try_factordb():
    """Query factordb.com for known factorization"""
    print("[*] Checking factordb.com...")
    
    try:
        url = f"http://factordb.com/api?query={N}"
        resp = requests.get(url, timeout=30)
        data = resp.json()
        
        if data.get('status') == 'FF':  # Fully factored
            factors = data.get('factors', [])
            print(f"[+] Found factors in factordb!")
            print(f"[+] Factors: {factors}")
            return factors
        else:
            print(f"[-] N not fully factored in factordb. Status: {data.get('status')}")
    except Exception as e:
        print(f"[-] Error querying factordb: {e}")
    
    return None


def solve_with_factors(p, q):
    """Given factors p and q, solve for the flag"""
    print(f"\n[*] Solving with p, q...")
    print(f"[*] p = {p}")
    print(f"[*] q = {q}")
    
    phi = (p - 1) * (q - 1)
    
    # Try all primes less than 2^10 as e
    possible_e = list(primerange(2, 2**10))
    
    for e in possible_e:
        if gcd(e, phi) != 1:
            continue
        
        d = pow(e, -1, phi)
        
        m1 = pow(cts[0], d, N)
        m2 = pow(cts[1], d, N)
        m3 = pow(cts[2], d, N)
        
        if m1 + m2 + m3 == hint:
            print(f"\n[+] FOUND e = {e}!")
            
            f1 = long_to_bytes(m1)
            f2 = long_to_bytes(m2)
            f3 = long_to_bytes(m3)
            
            print(f"[+] Part 1: {f1}")
            print(f"[+] Part 2: {f2}")
            print(f"[+] Part 3: {f3}")
            
            flag = f1 + f2 + f3
            print(f"\n[+] FLAG: {flag}")
            return flag
    
    print("[-] Could not find valid e")
    return None


def check_n_structure():
    """Check if N has special structure"""
    print("[*] Analyzing N structure...")
    
    # Check if N is a square
    import gmpy2
    sqrt_n = gmpy2.isqrt(N)
    if sqrt_n * sqrt_n == N:
        print(f"[+] N is a perfect square! p = q = {sqrt_n}")
        return int(sqrt_n), int(sqrt_n)
    
    # Check if N = p * (p+1) or similar close primes
    for delta in range(-1000, 1001):
        if delta == 0:
            continue
        # N = p * (p + delta)
        # p^2 + delta*p - N = 0
        # p = (-delta + sqrt(delta^2 + 4N)) / 2
        disc = delta * delta + 4 * N
        sqrt_disc = gmpy2.isqrt(disc)
        if sqrt_disc * sqrt_disc == disc:
            p = (-delta + sqrt_disc) // 2
            if p > 0 and N % p == 0:
                q = N // p
                print(f"[+] Found close primes! p = {p}, q = {q}")
                return int(p), int(q)
    
    print("[-] No obvious structure found")
    return None


def main():
    print("[*] Quik Maff Advanced Solver")
    print(f"[*] N = {N}")
    print(f"[*] N has {N.bit_length()} bits")
    print()
    
    # First check local structure
    result = check_n_structure()
    if result:
        p, q = result
        return solve_with_factors(p, q)
    
    print()
    
    # Try factordb
    factors = try_factordb()
    if factors and len(factors) >= 2:
        # Parse factors
        p = int(factors[0][0])
        q = int(factors[1][0])
        return solve_with_factors(p, q)
    
    print()
    print("[-] Could not find factorization")
    print("[*] Try using yafu, msieve, or cado-nfs for factorization")
    
    return None


if __name__ == "__main__":
    result = main()
    if result:
        print(f"\n[SUCCESS]")
    else:
        print(f"\n[FAILED]")
