import math
from typing import Tuple, Optional, List

Point = Optional[Tuple[int, int]]

class ECCSolver:
    """
    Solver for Elliptic Curve Cryptography challenges.
    
    Supports:
    - BSGS (Baby-step Giant-step)
    - Pohlig-Hellman (smooth order)
    - Invalid Curve Attack (ECDH)
    - Smart's Attack (anomalous curves)
    """
    def __init__(self):
        pass

    def solve(self, p: int, a: int, b: int, G: Point, P: Point) -> Optional[str]:
        """
        Attempts to find n such that P = n * G over the curve y^2 = x^3 + ax + b (mod p).
        G and P are tuples (x, y).
        """
        print(f"[*] Attempting ECC solve on curve y^2 = x^3 + {a}x + {b} (mod {p})")
        
        # Check if points are on curve
        if not self._is_on_curve(G, p, a, b) or not self._is_on_curve(P, p, a, b):
            print("[-] Points not on curve!")
            return None

        # Try BSGS for discrete log
        if p < 2**40:
            print("[*] Trying Baby-step Giant-step (BSGS)...")
            n = self._bsgs(G, P, p, a, b)
            if n:
                print(f"[+] Found scalar n: {n}")
                return str(n)
        else:
            print("[-] Field too large for simple BSGS. Try Pohlig-Hellman or Smart's attack.")

        return None

    def _is_on_curve(self, point: Point, p: int, a: int, b: int) -> bool:
        if point is None: return True
        x, y = point
        return (y*y - (x*x*x + a*x + b)) % p == 0

    def _add(self, P: Point, Q: Point, p: int, a: int) -> Point:
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 != y2:
            return None
        
        if x1 == x2:
            m = (3*x1*x1 + a) * pow(2*y1, -1, p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, p)
            
        m = m % p
        x3 = (m*m - x1 - x2) % p
        y3 = (m*(x1 - x3) - y1) % p
        return (x3, y3)

    def _mul(self, n: int, P: Point, p: int, a: int) -> Point:
        R = None
        for i in range(n.bit_length()):
            if (n >> i) & 1:
                R = self._add(R, P, p, a)
            P = self._add(P, P, p, a)
        return R
    
    def _neg(self, P: Point, p: int) -> Point:
        """Negate a point: -(x, y) = (x, -y mod p)"""
        if P is None:
            return None
        return (P[0], (-P[1]) % p)

    def _bsgs(self, G: Point, P: Point, p: int, a: int, b: int) -> Optional[int]:
        """Baby-step Giant-step for discrete log."""
        m = int(math.sqrt(p)) + 1
        table = {}
        
        # Baby steps
        curr = None
        for j in range(m):
            table[curr] = j
            curr = self._add(curr, G, p, a)
            
        # Giant steps
        factor = self._mul(m, G, p, a)
        neg_factor = self._neg(factor, p)
        curr = P
        
        for i in range(m):
            if curr in table:
                return i*m + table[curr]
            curr = self._add(curr, neg_factor, p, a)
            
        return None

    # =========================================================================
    # NEW ATTACKS
    # =========================================================================
    
    def pohlig_hellman(self, G: Point, P: Point, p: int, a: int, b: int, 
                        order: int, factors: List[Tuple[int, int]]) -> Optional[int]:
        """
        Pohlig-Hellman attack for curves with smooth order.
        
        When the curve order factors into small primes, we can solve DLP
        in each small subgroup and combine with CRT.
        
        Args:
            G: Generator point
            P: Target point (P = n*G)
            p, a, b: Curve parameters
            order: Order of the curve (number of points)
            factors: List of (prime, exponent) tuples from factorization of order
        
        Returns:
            Scalar n such that P = n*G
        """
        print(f"[*] Pohlig-Hellman with factors: {factors}")
        
        remainders = []
        moduli = []
        
        for prime, exp in factors:
            # Subgroup order
            pi_power = prime ** exp
            
            # Lift to subgroup
            cofactor = order // pi_power
            Gi = self._mul(cofactor, G, p, a)
            Pi = self._mul(cofactor, P, p, a)
            
            if Gi is None:
                continue
            
            # Solve DLP in subgroup of order pi_power
            # For small primes, use brute force or BSGS
            ni = self._solve_small_dlog(Gi, Pi, p, a, pi_power)
            
            if ni is not None:
                remainders.append(ni)
                moduli.append(pi_power)
                print(f"    n ≡ {ni} (mod {pi_power})")
        
        # Combine with CRT
        if not remainders:
            return None
        
        n = self._crt(remainders, moduli)
        print(f"[+] Pohlig-Hellman: n = {n}")
        return n
    
    def _solve_small_dlog(self, G: Point, P: Point, p: int, a: int, order: int) -> Optional[int]:
        """Solve DLP for small order using brute force or BSGS."""
        if order < 10000:
            # Brute force
            curr = None
            for i in range(order):
                if curr == P:
                    return i
                curr = self._add(curr, G, p, a)
        else:
            # BSGS for larger
            m = int(math.sqrt(order)) + 1
            table = {}
            
            curr = None
            for j in range(m):
                table[curr] = j
                curr = self._add(curr, G, p, a)
            
            factor = self._mul(m, G, p, a)
            neg_factor = self._neg(factor, p)
            curr = P
            
            for i in range(m):
                if curr in table:
                    return i * m + table[curr]
                curr = self._add(curr, neg_factor, p, a)
        
        return None
    
    def _crt(self, remainders: List[int], moduli: List[int]) -> int:
        """Chinese Remainder Theorem."""
        from functools import reduce
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            return gcd, y1 - (b // a) * x1, x1
        
        M = reduce(lambda x, y: x * y, moduli)
        result = 0
        
        for r, m in zip(remainders, moduli):
            Mi = M // m
            _, x, _ = extended_gcd(Mi % m, m)
            result += r * Mi * x
        
        return result % M
    
    def invalid_curve_attack(self, victim_oracle, p: int, a: int, 
                             original_b: int, weak_curves: List[dict]) -> Optional[int]:
        """
        Invalid Curve Attack for ECDH.
        
        When the victim doesn't validate that received points are on the curve,
        we can send points from weak curves (with smooth order) and recover
        the private key using Pohlig-Hellman + CRT.
        
        Args:
            victim_oracle: Function that takes a point and returns victim's ECDH result
            p, a: Curve parameters (b is not used in point arithmetic!)
            original_b: Original curve's b parameter
            weak_curves: List of dicts with {'b': b_val, 'point': (x,y), 'order': order, 'factors': [...]}
        
        Returns:
            Victim's private key
        """
        print("[*] Invalid Curve Attack")
        print(f"    Note: Point arithmetic uses only 'a', not 'b'")
        
        remainders = []
        moduli = []
        
        for curve in weak_curves:
            b_weak = curve['b']
            point = curve['point']
            order = curve['order']
            
            print(f"    Trying curve b={b_weak}, point order={order}")
            
            # Send invalid point to victim
            try:
                shared_secret = victim_oracle(point)
                
                if shared_secret is None:
                    continue
                
                # Solve DLP in weak curve's subgroup
                # shared_secret = d * point (where d is victim's private key)
                d_mod = self._solve_small_dlog(point, shared_secret, p, a, order)
                
                if d_mod is not None:
                    remainders.append(d_mod)
                    moduli.append(order)
                    print(f"    d ≡ {d_mod} (mod {order})")
            except:
                continue
        
        if not remainders:
            return None
        
        d = self._crt(remainders, moduli)
        print(f"[+] Recovered private key: d = {d}")
        return d
    
    def smart_attack(self, G: Point, P: Point, p: int, a: int, b: int) -> Optional[int]:
        """
        Smart's Attack for anomalous curves.
        
        When #E(Fp) = p (curve has p points), the DLP can be solved in
        linear time using p-adic logarithms.
        
        Args:
            G: Generator point
            P: Target point
            p, a, b: Curve parameters
        
        Returns:
            Scalar n such that P = n*G (or None if not anomalous)
        
        Note: Full implementation requires p-adic arithmetic.
        For CTFs, use SageMath's built-in.
        """
        print("[*] Smart's Attack (Anomalous Curves)")
        print("    Checking if curve is anomalous (#E = p)...")
        
        # This requires computing curve order to verify #E = p
        # Full attack needs p-adic lifting (Hensel)
        print("[!] Smart's attack requires SageMath implementation")
        print("[*] Use in Sage:")
        print("    E = EllipticCurve(GF(p), [a, b])")
        print("    if E.order() == p:")
        print("        n = E.lift_x(P[0]).log(E.lift_x(G[0]))")
        
        return None
