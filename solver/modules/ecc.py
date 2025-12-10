import math

class ECCSolver:
    """
    Solver for Elliptic Curve Cryptography challenges.
    Currently supports:
    - Discrete Logarithm for small fields (BSGS)
    """
    def __init__(self):
        pass

    def solve(self, p, a, b, G, P):
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
        # Limit to reasonable size for pure python
        if p < 2**40:
            print("[*] Trying Baby-step Giant-step (BSGS)...")
            n = self._bsgs(G, P, p, a, b)
            if n:
                print(f"[+] Found scalar n: {n}")
                return str(n)
        else:
            print("[-] Field too large for simple BSGS. Smart's attack or Pollard's Rho needed (requires SageMath).")

        return None

    def _is_on_curve(self, point, p, a, b):
        if point is None: return True
        x, y = point
        return (y*y - (x*x*x + a*x + b)) % p == 0

    def _add(self, P, Q, p, a):
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

    def _mul(self, n, P, p, a):
        R = None
        for i in range(n.bit_length()):
            if (n >> i) & 1:
                R = self._add(R, P, p, a)
            P = self._add(P, P, p, a)
        return R

    def _bsgs(self, G, P, p, a, b):
        m = int(math.sqrt(p)) + 1
        table = {}
        
        # Baby steps
        curr = None
        for j in range(m):
            table[curr] = j
            curr = self._add(curr, G, p, a)
            
        # Giant steps
        factor = self._mul(m, G, p, a)
        # Inverse of factor? Actually we need P - i*m*G
        # Easier: P = j*G + i*m*G => P - j*G = i*m*G ? No.
        # Standard BSGS: P = i*m*G + j*G
        # We computed j*G. Now we compute P - i*m*G and check if in table.
        # Subtraction is adding negative point. -(x,y) = (x, -y)
        
        neg_factor = (factor[0], -factor[1] % p)
        curr = P
        
        for i in range(m):
            if curr in table:
                return i*m + table[curr]
            curr = self._add(curr, neg_factor, p, a)
            
        return None
