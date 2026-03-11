import gmpy2
import math
from fractions import Fraction
from Crypto.Util.number import long_to_bytes
from ..utils.helpers import safe_long_to_bytes
from typing import List, Tuple, Optional

class RSASolver:
    """
    Solver for RSA challenges.
    Implements multiple attack vectors.
    """
    def __init__(self):
        pass

    def solve(self, n, e, c, attack_order=None, **kwargs):
        """
        Attempts to solve RSA given n, e, c.
        
        Args:
            n, e, c: RSA parameters
            attack_order: Optional list of attack names to try in order
                          (from EarlyExitChecker). Skips attacks not in list.
            kwargs: extra params (n_list, c_list for broadcast, etc.)
        """
        print(f"[*] Attempting RSA solve with n ({n.bit_length()} bits), e={e}")
        
        # Map attack names to methods
        attack_methods = {
            "small_e_root": self._try_small_e,
            "wiener": self._try_wiener,
            "fermat": self._try_fermat,
            "trial_division": self._try_trial_div,
            "pollard_p1": self._try_pollard_p1,
            "pollard_rho": self._try_pollard_rho,
            "hastad_broadcast": lambda n, e, c: None,  # needs extra params
            "common_modulus": lambda n, e, c: None,     # needs extra params
            "crt_leak": lambda n, e, c: None,           # needs dp/dq
        }
        
        if attack_order:
            # Use the optimized order from EarlyExitChecker
            for attack_name in attack_order:
                method = attack_methods.get(attack_name)
                if method:
                    print(f"[*] Trying {attack_name}...")
                    result = method(n, e, c)
                    if result:
                        return result
        else:
            # Fallback: original sequential order
            if e <= 5 and e > 1:
                print("[*] Trying Small E Root Attack...")
                res = self._try_small_e(n, e, c)
                if res: return res

            print("[*] Trying Wiener's Attack...")
            res = self._try_wiener(n, e, c)
            if res: return res

            if n.bit_length() <= 512:
                print("[*] Trying Fermat Factorization...")
                res = self._try_fermat(n, e, c)
                if res: return res

            if n < 2**256:
                print("[*] Trying Trial Division...")
                res = self._try_trial_div(n, e, c)
                if res: return res

            print("[*] Trying Pollard p-1...")
            res = self._try_pollard_p1(n, e, c)
            if res: return res
                    
        return None
    
    def _try_small_e(self, n, e, c):
        """Small exponent attack: direct e-th root of c."""
        if e > 17:
            return None
        m, exact = gmpy2.iroot(c, e)
        if exact:
            res = safe_long_to_bytes(m)
            if res:
                print(f"[+] Solved with e-th root (e={e})")
                return res.decode(errors='ignore')
        return None
    
    def _try_wiener(self, n, e, c):
        return self._wiener_attack(n, e, c)
    
    def _try_fermat(self, n, e, c):
        return self._fermat_factorization(n, e, c)
    
    def _try_trial_div(self, n, e, c):
        for i in range(2, 100000):
            if n % i == 0:
                p = i
                q = n // i
                return self._decrypt_with_factors(n, e, c, p, q)
        return None
    
    def _try_pollard_p1(self, n, e, c):
        return self._pollard_p1(n, e, c)
    
    def _try_pollard_rho(self, n, e, c):
        return self.pollard_rho(n, e, c)

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

    # =========================================================================
    # NEW ATTACKS
    # =========================================================================
    
    def hastad_broadcast(self, ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
        """
        Hastad Broadcast Attack.
        
        When the same message M is encrypted with the same small e to multiple
        recipients (different N values), we can recover M using CRT.
        
        Args:
            ciphertexts: List of c values (c_i = m^e mod n_i)
            moduli: List of n values
            e: Common public exponent
        
        Returns:
            Recovered message M as integer
        """
        if len(ciphertexts) < e:
            print(f"[!] Need at least {e} ciphertexts for e={e}")
            return None
        
        # Use Chinese Remainder Theorem
        from functools import reduce
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        def crt(remainders, moduli):
            """Chinese Remainder Theorem for list of equations."""
            M = reduce(lambda x, y: x * y, moduli)
            result = 0
            for r, m in zip(remainders, moduli):
                Mi = M // m
                _, x, _ = extended_gcd(Mi, m)
                result += r * Mi * x
            return result % M
        
        # Apply CRT to get M^e
        M_product = reduce(lambda x, y: x * y, moduli[:e])
        m_pow_e = crt(ciphertexts[:e], moduli[:e])
        
        # Take e-th root
        m, exact = gmpy2.iroot(m_pow_e, e)
        if exact:
            print(f"[+] Hastad Broadcast: Recovered M = {m}")
            return int(m)
        
        return None
    
    def common_modulus(self, n: int, e1: int, e2: int, c1: int, c2: int) -> Optional[int]:
        """
        Common Modulus Attack.
        
        When the same message is encrypted with two different exponents
        (e1, e2) but the same N, and gcd(e1, e2) = 1, we can recover M.
        
        Uses Extended Euclidean Algorithm to find a, b such that:
        a*e1 + b*e2 = 1
        Then: M = c1^a * c2^b mod N
        
        Args:
            n: Common modulus
            e1, e2: Different public exponents
            c1, c2: Corresponding ciphertexts
        
        Returns:
            Recovered message M as integer
        """
        g = math.gcd(e1, e2)
        if g != 1:
            print(f"[!] gcd(e1, e2) = {g} != 1")
            return None
        
        # Extended GCD
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, a, b = extended_gcd(e1, e2)
        
        # Handle negative exponents
        if a < 0:
            c1 = gmpy2.invert(c1, n)
            a = -a
        if b < 0:
            c2 = gmpy2.invert(c2, n)
            b = -b
        
        m = (pow(c1, a, n) * pow(c2, b, n)) % n
        print(f"[+] Common Modulus: Recovered M = {m}")
        return int(m)
    
    def _pollard_p1(self, n: int, e: int, c: int, B: int = 100000) -> Optional[str]:
        """
        Pollard's p-1 Factorization.
        
        Works when p-1 (or q-1) is B-smooth (all prime factors < B).
        
        Args:
            n: Modulus to factor
            e, c: RSA parameters for decryption
            B: Smoothness bound
        
        Returns:
            Decrypted message if factorization succeeds
        """
        a = 2
        
        # Compute a^(B!) mod n
        for j in range(2, B + 1):
            a = pow(a, j, n)
            
            if j % 10000 == 0:
                g = math.gcd(a - 1, n)
                if 1 < g < n:
                    p = g
                    q = n // p
                    print(f"[+] Pollard p-1 found factor: p={p}")
                    return self._decrypt_with_factors(n, e, c, p, q)
        
        # Final check
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            p = g
            q = n // p
            print(f"[+] Pollard p-1 found factor: p={p}")
            return self._decrypt_with_factors(n, e, c, p, q)
        
        return None
    
    def pollard_rho(self, n: int, e: int, c: int, max_iter: int = 1000000) -> Optional[str]:
        """
        Pollard's Rho Factorization.
        
        General-purpose factorization algorithm.
        
        Args:
            n: Modulus to factor
            e, c: RSA parameters
            max_iter: Maximum iterations
        
        Returns:
            Decrypted message if factorization succeeds
        """
        if n % 2 == 0:
            return self._decrypt_with_factors(n, e, c, 2, n // 2)
        
        x = 2
        y = 2
        d = 1
        
        f = lambda x: (x * x + 1) % n
        
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
            max_iter -= 1
            if max_iter <= 0:
                break
        
        if 1 < d < n:
            p = d
            q = n // p
            print(f"[+] Pollard Rho found factor: p={p}")
            return self._decrypt_with_factors(n, e, c, p, q)
        
        return None
    
    def franklin_reiter(self, n: int, e: int, c1: int, c2: int, a: int, b: int) -> Optional[int]:
        """
        Franklin-Reiter Related Message Attack.
        
        When m2 = a*m1 + b (linear relation), we can recover m1.
        
        Works by computing GCD of two polynomials:
        f1(x) = x^e - c1
        f2(x) = (a*x + b)^e - c2
        
        Args:
            n: Modulus
            e: Public exponent (should be small, e.g., 3)
            c1, c2: Ciphertexts
            a, b: Linear relation coefficients (m2 = a*m1 + b)
        
        Returns:
            Recovered m1
        
        Note: Requires sympy for polynomial GCD
        """
        try:
            from sympy import symbols, Poly, GCD
            from sympy.polys.galoistools import gf_gcd
            from sympy import ZZ
            
            x = symbols('x')
            
            # Define polynomials in Z_n[x]
            f1 = Poly(x**e - c1, x, domain=ZZ)
            f2 = Poly((a*x + b)**e - c2, x, domain=ZZ)
            
            # This is simplified - proper implementation needs modular polynomial GCD
            # For now, use Sage if available or return None
            print("[!] Franklin-Reiter requires polynomial GCD in Z_n[x]")
            print("[*] Use Sage: gcd(f1, f2) over PolynomialRing(Zmod(n), 'x')")
            
        except ImportError:
            print("[!] sympy required for Franklin-Reiter")
        
        return None
