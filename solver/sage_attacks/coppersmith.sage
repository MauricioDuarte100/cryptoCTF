from __future__ import print_function
import time

############################################
# Coppersmith's Attack - Univariate Version
# Source: https://github.com/mimoo/RSA-and-LLL-attacks
#
# Two main use cases:
# 1. Stereotyped Messages: Find m when m = prefix + unknown
# 2. Factoring with High Bits Known: Factor n when we know partial p
############################################

debug = False  # Set to True for verbose output

def matrix_overview(BB, bound):
    """Display matrix picture with 0 and X."""
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)


def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham

    Finds a solution if:
    * b|modulus, b >= modulus^beta, 0 < beta <= 1
    * |x| < XX
    
    Args:
        pol: Monic polynomial to solve
        modulus: N (the RSA modulus)
        beta: b >= N^beta where b is the unknown factor
        mm: Lattice parameter m
        tt: Lattice parameter t
        XX: Upper bound on the root
        
    Returns:
        List of roots found
    """
    dd = pol.degree()
    nn = dd * mm + tt

    if not 0 < beta <= 1:
        raise ValueError("beta should belongs in (0, 1]")

    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    # Change ring of pol and x
    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()

    # Compute polynomials
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x * XX)**jj * modulus**(mm - ii) * polZ(x * XX)**ii)
    for ii in range(tt):
        gg.append((x * XX)**ii * polZ(x * XX)**mm)

    # Construct lattice B
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        for jj in range(ii+1):
            BB[ii, jj] = gg[ii][jj]

    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    BB = BB.LLL()

    # Transform shortest vector into polynomial    
    new_pol = 0
    for ii in range(nn):
        new_pol += x**ii * BB[0, ii] / XX**ii

    # Factor polynomial
    potential_roots = new_pol.roots()
    if debug:
        print("potential roots:", potential_roots)

    # Test roots
    roots = []
    for root in potential_roots:
        if root[0].is_integer():
            result = polZ(ZZ(root[0]))
            if gcd(modulus, result) >= modulus^beta:
                roots.append(ZZ(root[0]))

    return roots


def attack_stereotyped_message(N, e, c, prefix, unknown_bits, suffix=0):
    """
    Recover message when part of it is known.
    
    m = prefix || unknown || suffix
    c = m^e mod N
    
    Args:
        N: RSA modulus
        e: Public exponent (should be small, e.g., 3)
        c: Ciphertext
        prefix: Known high bits of message
        unknown_bits: Number of unknown bits
        suffix: Known low bits (default 0)
    
    Returns:
        Recovered message, or None
    """
    print(f"[*] Stereotyped Message Attack")
    print(f"[*] unknown_bits = {unknown_bits}")
    print(f"[*] e = {e}")
    
    ZmodN = Zmod(N)
    P.<x> = PolynomialRing(ZmodN)
    
    # m = prefix * 2^unknown_bits + x + suffix
    # We're looking for x < 2^unknown_bits
    pol = (prefix * 2^unknown_bits + x + suffix)^e - c
    pol = pol.monic()
    
    dd = pol.degree()
    
    # Parameters (tweak if needed)
    beta = 1
    epsilon = beta / 7
    mm = ceil(beta**2 / (dd * epsilon))
    tt = floor(dd * mm * ((1/beta) - 1))
    XX = ceil(N**((beta**2/dd) - epsilon))
    
    # Make sure XX is at least 2^unknown_bits
    XX = max(XX, 2^unknown_bits)
    
    print(f"[*] m = {mm}, t = {tt}, X = {XX}")
    
    start_time = time.time()
    roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)
    
    print(f"[*] Time: {time.time() - start_time:.2f}s")
    
    if roots:
        x0 = roots[0]
        m = prefix * 2^unknown_bits + x0 + suffix
        print(f"[+] Found x = {x0}")
        print(f"[+] Message m = {m}")
        
        # Verify
        if pow(m, e, N) == c:
            print("[+] Verified!")
            return int(m)
    
    print("[-] No solution found")
    return None


def attack_partial_p(N, p_high, unknown_bits):
    """
    Factor N when we know high bits of p.
    
    p = p_high * 2^unknown_bits + x where x < 2^unknown_bits
    
    Args:
        N: RSA modulus
        p_high: Known high bits of p
        unknown_bits: Number of unknown low bits
    
    Returns:
        (p, q) or None
    """
    print(f"[*] Partial p Factorization")
    print(f"[*] unknown_bits = {unknown_bits}")
    
    ZmodN = Zmod(N)
    P.<x> = PolynomialRing(ZmodN)
    
    # p = p_high * 2^unknown_bits + x
    # We want gcd(p, N) = p, so we solve p ≡ 0 (mod p)
    p_approx = p_high * 2^unknown_bits
    pol = x + p_approx
    pol = pol.monic()
    
    dd = pol.degree()
    
    # Parameters
    beta = 0.5  # p >= N^0.5
    epsilon = beta / 7
    mm = ceil(beta**2 / (dd * epsilon))
    tt = floor(dd * mm * ((1/beta) - 1))
    XX = ceil(N**((beta**2/dd) - epsilon))
    
    XX = max(XX, 2^unknown_bits)
    
    print(f"[*] m = {mm}, t = {tt}, X = {XX}")
    
    start_time = time.time()
    roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)
    
    print(f"[*] Time: {time.time() - start_time:.2f}s")
    
    if roots:
        x0 = roots[0]
        p = p_approx + x0
        if N % p == 0:
            q = N // p
            print(f"[+] p = {p}")
            print(f"[+] q = {q}")
            return (int(p), int(q))
    
    print("[-] No solution found")
    return None


def attack_partial_sum(N, sum_high, unknown_bits):
    """
    Factor N when we know high bits of p+q.
    
    p + q = sum_high * 2^unknown_bits + x where x < 2^unknown_bits
    
    This is for challenges like CU29!
    
    Args:
        N: RSA modulus
        sum_high: Known high bits of (p+q)
        unknown_bits: Number of unknown low bits
    
    Returns:
        (p, q) or None
    """
    print(f"[*] Partial Sum (p+q) Factorization")
    print(f"[*] unknown_bits = {unknown_bits}")
    print(f"[*] sum_high << unknown_bits = {sum_high << unknown_bits}")
    
    base = sum_high * 2^unknown_bits
    
    # p + q = base + x, p * q = n
    # From quadratic: p, q are roots of t^2 - (base+x)*t + n = 0
    # Discriminant D = (base+x)^2 - 4n must be a perfect square
    
    # We need to find x such that D is a square
    # This is not directly solvable with standard Coppersmith...
    
    # Alternative: enumerate x and check
    print("[*] Trying brute force search on unknown bits...")
    
    from sage.all import isqrt
    
    for x in range(0, min(2^20, 2^unknown_bits)):
        s = base + x
        D = s^2 - 4*N
        if D >= 0:
            sqrt_D = isqrt(D)
            if sqrt_D^2 == D:
                p = (s + sqrt_D) // 2
                q = (s - sqrt_D) // 2
                if p * q == N:
                    print(f"[+] Found at x = {x}!")
                    print(f"[+] p = {p}")
                    print(f"[+] q = {q}")
                    return (int(p), int(q))
        if x % 100000 == 0 and x > 0:
            print(f"    Checked {x}...")
    
    print("[-] Brute force failed, need lattice approach")
    return None


# CU29 Challenge Solver
if __name__ == "__main__":
    print("="*60)
    print(" Coppersmith Attack - CU29 Challenge")
    print("="*60)
    
    n = 74400198359942513862730376031146135802606791991588575465056163121555925617314946580878695576381159966669035646513358312316295727962048929334491638793366454990554957760082895721209907599102882541383389817613899931138405942694622063421798336056156478661669460226638891433547765658851966477956365621503055329677
    e = 23
    c = 67093879684168042482911544476248580360412038370701084199780323275036434279521774982225923057805337317989111708384627608827582845935869416467560399759225810925388294903783674263633367996837459206550597542374370661621276546154790021615738055122556152562693170717804941676044793478893041430142032267013836633841
    pq_high = 10742021914074381086319674056236928469987565979831767505178443989041183736389136816846636592297
    
    # pq_high = (p+q) >> 200
    # So we know 313 bits of p+q, missing 200 bits
    
    result = attack_partial_sum(n, pq_high, 200)
    
    if result:
        p, q = result
        phi = (p-1)*(q-1)
        d = inverse_mod(e, phi)
        m = power_mod(c, d, n)
        
        # Convert to bytes
        hex_str = hex(int(m))[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        flag = bytes.fromhex(hex_str)
        print(f"\n[+] FLAG: {flag}")
