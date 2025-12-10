import gmpy2
import math
from fractions import Fraction
from Crypto.Util.number import long_to_bytes
from ..utils.helpers import safe_long_to_bytes

class RSASolver:
    """
    Solver for RSA challenges.
    """
    def __init__(self):
        pass

    def solve(self, n, e, c, **kwargs):
        """
        Attempts to solve RSA given n, e, c.
        kwargs can contain 'n_list', 'c_list' for broadcast attacks,
        or 'e1', 'e2', 'c1', 'c2' for common modulus.
        """
        print(f"[*] Attempting RSA solve with n={n}, e={e}, c={c}")
        
        # 1. Small Exponent Attack (e=3)
        if e == 3:
            print("[*] Trying Cube Root Attack (e=3)...")
            m, exact = gmpy2.iroot(c, 3)
            if exact:
                res = safe_long_to_bytes(m)
                if res:
                    print(f"[+] Solved with Cube Root: {res}")
                    return res.decode(errors='ignore')

        # 2. Wiener's Attack (Small d)
        print("[*] Trying Wiener's Attack...")
        res = self._wiener_attack(n, e, c)
        if res: return res

        # 3. Fermat Factorization (p close to q)
        print("[*] Trying Fermat Factorization...")
        res = self._fermat_factorization(n, e, c)
        if res: return res

        # 4. Small N Factorization
        if n < 2**100:
            print("[*] Trying Small N Factorization...")
            for i in range(2, 100000):
                if n % i == 0:
                    p = i
                    q = n // i
                    return self._decrypt_with_factors(n, e, c, p, q)
                    
        return None

    def _decrypt_with_factors(self, n, e, c, p, q):
        try:
            phi = (p - 1) * (q - 1)
            d = gmpy2.invert(e, phi)
            m = pow(c, d, n)
            res = safe_long_to_bytes(m)
            if res:
                print(f"[+] Solved with factors p={p}, q={q}")
                return res.decode(errors='ignore')
        except Exception as err:
            print(f"[-] Decryption failed: {err}")
        return None

    def _fermat_factorization(self, n, e, c):
        try:
            if n % 2 == 0: return self._decrypt_with_factors(n, e, c, 2, n//2)
            a = gmpy2.isqrt(n) + 1
            count = 0
            while count < 1000000:
                b2 = a*a - n
                if b2 >= 0:
                    b = gmpy2.isqrt(b2)
                    if b*b == b2:
                        p = a + b
                        q = a - b
                        return self._decrypt_with_factors(n, e, c, p, q)
                a += 1
                count += 1
        except:
            pass
        return None

    def _wiener_attack(self, n, e, c):
        # Based on continued fractions
        def continued_fractions(a, b):
            fractions = []
            while b != 0:
                fractions.append(a // b)
                a, b = b, a % b
            return fractions
        
        def convergents(cf):
            convs = []
            for i in range(len(cf)):
                if i == 0: convs.append(Fraction(cf[0]))
                elif i == 1: convs.append(Fraction(cf[1] * cf[0] + 1, cf[1]))
                else:
                    convs.append(Fraction(
                        cf[i] * convs[i-1].numerator + convs[i-2].numerator,
                        cf[i] * convs[i-1].denominator + convs[i-2].denominator
                    ))
            return convs

        try:
            cf = continued_fractions(e, n)
            convs = convergents(cf)
            for frac in convs:
                k, d = frac.numerator, frac.denominator
                if k == 0: continue
                if (e * d - 1) % k != 0: continue
                
                phi = (e * d - 1) // k
                s = n - phi + 1
                disc = s*s - 4*n
                if disc >= 0:
                    root = gmpy2.isqrt(disc)
                    if root*root == disc:
                        p = (s + root) // 2
                        q = (s - root) // 2
                        if p*q == n:
                            print(f"[+] Wiener Success: d={d}")
                            return self._decrypt_with_factors(n, e, c, p, q)
        except Exception as err:
            print(f"[-] Wiener failed: {err}")
        return None
