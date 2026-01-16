from __future__ import print_function
import time

############################################
# Boneh-Durfee Attack on RSA
# Source: https://github.com/mimoo/RSA-and-LLL-attacks
# 
# Finds d when d < N^0.292
############################################

# Config
debug = True
strict = False
helpful_only = True
dimension_min = 7

# Functions
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1
    print(nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")

def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

def remove_unhelpful(BB, monomials, bound, current):
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    for ii in range(current, -1, -1):
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            for jj in range(ii + 1, BB.dimensions()[0]):
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            if affected_vectors == 0:
                print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB

            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    return BB

def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May

    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """

    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u)
    polZ = Q(pol).lift()

    UU = XX*YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()

    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()

    # y-shifts
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift)

    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)

    # construct lattice
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    if helpful_only:
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0,0

    if debug:
        helpful_vectors(BB, modulus^mm)

    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Solutions might not be found.")
        print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")

    if debug:
        matrix_overview(BB, modulus^mm)

    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")

    BB = BB.LLL()

    if debug:
        print("LLL is done!")
        print("looking for independent vectors in the lattice")

    found_polynomials = False

    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)

            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0

    rr = rr(q, q)

    soly = rr.roots()

    if len(soly) == 0:
        print("Your prediction (delta) is too small")
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    return solx, soly


def attack(N, e, delta=0.28, m=5):
    """
    Main attack function.
    
    Args:
        N: RSA modulus
        e: Public exponent (or ee from the challenge)
        delta: Hypothesis on d (d < N^delta), max 0.292
        m: Lattice size (bigger = slower but more likely to work)
    
    Returns:
        d: Private exponent, or None if failed
    """
    print(f"[*] Boneh-Durfee Attack")
    print(f"[*] N has {int(log(N)/log(2))} bits")
    print(f"[*] e has {int(log(e)/log(2))} bits")
    print(f"[*] delta = {delta}")
    print(f"[*] m = {m}")
    
    t = int((1-2*delta) * m)
    X = 2*floor(N^delta)
    Y = floor(N^(1/2))
    
    P.<x,y> = PolynomialRing(ZZ)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)
    
    print("=== running algorithm ===")
    start_time = time.time()
    
    solx, soly = boneh_durfee(pol, e, m, t, X, Y)
    
    print(f"=== {time.time() - start_time:.2f} seconds ===")
    
    if solx > 0:
        print("=== solution found ===")
        d = int(pol(solx, soly) / e)
        print(f"private key found: d = {d}")
        return d
    else:
        print("=== no solution was found ===")
        return None


# Example for CU29 challenge
if __name__ == "__main__":
    print("="*60)
    print(" Boneh-Durfee Attack - CU29 Challenge")
    print("="*60)
    
    # Challenge parameters
    n = 74400198359942513862730376031146135802606791991588575465056163121555925617314946580878695576381159966669035646513358312316295727962048929334491638793366454990554957760082895721209907599102882541383389817613899931138405942694622063421798336056156478661669460226638891433547765658851966477956365621503055329677
    e = 23
    c = 67093879684168042482911544476248580360412038370701084199780323275036434279521774982225923057805337317989111708384627608827582845935869416467560399759225810925388294903783674263633367996837459206550597542374370661621276546154790021615738055122556152562693170717804941676044793478893041430142032267013836633841
    ee = 51932890691025605005017310915612916271600777979505331615727718159287280323849710338181794701070147316145187464745426238779347565715981026060820382009264707825630065910448457401066737999090581631520459289158388406640542880406872203650158510808041068826069081102690337835303900100550250976587109590929801721407
    
    # In the challenge: d < n^0.34, so we use delta slightly below
    # But Boneh-Durfee only works for d < n^0.292
    # The challenge says d < n^0.34, which is beyond Boneh-Durfee's limit!
    
    # However, we have ee = d^(-1) mod phi
    # So we can try to find d using ee
    
    # First, let's try with ee as the modulus
    print("\n[*] Using ee as the exponent to find d")
    
    # Note: In this challenge, d was chosen small, then ee computed as inverse
    # So ee * d ≡ 1 (mod phi)
    # This means ee plays the role of e in standard RSA
    # We want to find d such that ee * d ≡ 1 (mod phi)
    
    # Try various delta values
    for delta in [0.28, 0.29, 0.292]:
        for m in [4, 5, 6]:
            print(f"\n{'='*40}")
            print(f"Trying delta={delta}, m={m}")
            print(f"{'='*40}")
            d = attack(n, ee, delta=delta, m=m)
            if d:
                # Decrypt!
                phi_approx = (ee * d - 1) 
                # Find actual phi
                for k in range(1, 100):
                    if (ee * d - 1) % k == 0:
                        phi = (ee * d - 1) // k
                        # Check if phi is valid
                        # phi = (p-1)(q-1) = n - p - q + 1
                        # p + q = n - phi + 1
                        s = n - phi + 1
                        disc = s*s - 4*n
                        if disc >= 0:
                            sqrt_disc = isqrt(disc)
                            if sqrt_disc * sqrt_disc == disc:
                                p = (s + sqrt_disc) // 2
                                q = (s - sqrt_disc) // 2
                                if p * q == n:
                                    print(f"\n[+] SUCCESS!")
                                    print(f"[+] k = {k}")
                                    print(f"[+] p = {p}")
                                    print(f"[+] q = {q}")
                                    
                                    # Now decrypt with e=23
                                    phi_real = (p-1)*(q-1)
                                    d_decrypt = inverse_mod(e, phi_real)
                                    m = power_mod(c, d_decrypt, n)
                                    
                                    # Convert to bytes
                                    hex_str = hex(int(m))[2:]
                                    if len(hex_str) % 2:
                                        hex_str = '0' + hex_str
                                    flag = bytes.fromhex(hex_str)
                                    print(f"[+] FLAG: {flag}")
                                    exit(0)
                break
