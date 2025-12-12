
import math
import random
from fractions import Fraction

# --- Helper Functions ---

def inverse_mod(a, m):
    """
    Compute the modular multiplicative inverse of a modulo m.
    Uses Python's pow(a, -1, m) which is efficient.
    """
    return pow(a, -1, m)
    
def getPrime(n):
    """
    Mimic Crypto.Util.number.getPrime if not available.
    """
    try:
        from Crypto.Util.number import getPrime as gp
        return gp(n)
    except ImportError:
        def is_prime(num):
             if num < 2: return False
             for i in range(2, int(num**0.5) + 1):
                 if num % i == 0: return False
             return True
        while True:
             num = random.getrandbits(n)
             if is_prime(num): return num

class GF:
    def __init__(self, p):
        self.p = p

# --- Matrix and LLL ---

class Matrix:
    def __init__(self, ring, rows, cols=None):
        if cols is None and isinstance(rows, list):
            self.mat = [r[:] for r in rows]
            self.rows = len(rows)
            self.cols = len(rows[0]) if self.rows > 0 else 0
        elif isinstance(rows, int) and isinstance(cols, int):
            self.rows = rows
            self.cols = cols
            self.mat = [[0]*cols for _ in range(rows)]
        else:
            raise ValueError("Invalid Matrix constructor arguments")
            
    def __getitem__(self, idx):
        if isinstance(idx, tuple):
            r, c = idx
            return self.mat[r][c]
        return self.mat[idx]

    def __setitem__(self, idx, val):
        if isinstance(idx, tuple):
            r, c = idx
            self.mat[r][c] = val
        else:
            self.mat[idx] = val

    def __repr__(self):
        return "Matrix([\n  " + ",\n  ".join(str(r) for r in self.mat) + "\n])"
    
    def __len__(self):
        return self.rows

    def LLL(self, delta=0.99):
        """
        Pure Python implementation of the Lenstra-Lenstra-Lovász (LLL) lattice reduction algorithm.
        Returns a NEW Matrix object with the reduced basis.
        Uses fractions.Fraction for exact Gram-Schmidt to handle large integers.
        """
        # Working with lists for speed
        B = [list(row) for row in self.mat]
        n = len(B)
        if n == 0: return Matrix(ZZ, [])
        k = 1
        
        def dot(v1, v2):
            return sum(x*y for x, y in zip(v1, v2))

        # Orthogonalized basis (Fraction)
        B_star = [[Fraction(x) for x in b] for b in B] 
        mu = [[Fraction(0)]*n for _ in range(n)]
        
        # Initial Gram-Schmidt
        for i in range(n):
            for j in range(i):
                d = dot(B_star[j], B_star[j])
                if d == 0: mu[i][j] = Fraction(0)
                else: mu[i][j] = dot(B[i], B_star[j]) / d
                for l in range(len(B[i])):
                    B_star[i][l] -= mu[i][j] * B_star[j][l]

        def update_gs_for_k(k):
            # Recompute B_star[k] and mu[k][0...k-1] using current B[k]
            B_star[k] = [Fraction(x) for x in B[k]]
            for j in range(k):
                d = dot(B_star[j], B_star[j])
                if d == 0: mu[k][j] = Fraction(0)
                else: mu[k][j] = dot(B[k], B_star[j]) / d
                for l in range(len(B[k])):
                    B_star[k][l] -= mu[k][j] * B_star[j][l]

        while k < n:
            # Size reduction
            for j in range(k - 1, -1, -1):
                if abs(mu[k][j]) > Fraction(1, 2):
                    q = round(float(mu[k][j]))
                    for l in range(len(B[k])):
                        B[k][l] -= q * B[j][l]
                    
                    # Update internal GS state for k
                    # Since B[k] changed, B_star[k] and mu[k][j] are invalid
                    update_gs_for_k(k)
                    
                    # NOTE: Updating B_star[k] does NOT affect previous B_star[0..k-1]
                    # Nor does it affect mu[k][0..j-1] because they depend on B[k] projection onto previous B_stars which didn't change?
                    # Actually, if we change B[k], we change its projection.
                    # Standard LLL size reduction step usually updates B[k] and then updates mu[k][j] = mu[k][j] - q.
                    # But full recompute is safer against bugs.

            # Lovasz condition check
            d_k = dot(B_star[k], B_star[k])
            d_k_1 = dot(B_star[k-1], B_star[k-1])
            f_delta = Fraction(int(delta*100), 100)
            
            if d_k >= (f_delta - mu[k][k-1]**2) * d_k_1:
                k += 1
            else:
                # Swap B[k] and B[k-1]
                B[k], B[k-1] = B[k-1], B[k]
                
                # We must update Gram-Schmidt not just for k-1 and k, but propagate changes to mu
                # The efficient way is updating mu, but let's do the "slow but sure" Re-GS
                # Recomputing GS for k-1, then k
                update_gs_for_k(k-1)
                update_gs_for_k(k)
                
                # CRITICAL MISSING STEP IN PREVIOUS VERSION:
                # We must update mu[i][k-1] and mu[i][k] for all i > k
                # because B_star[k-1] and B_star[k] have changed!
                for i in range(k + 1, n):
                    # Update mu[i][k-1]
                    d_prev = dot(B_star[k-1], B_star[k-1])
                    if d_prev == 0: mu[i][k-1] = Fraction(0)
                    else: mu[i][k-1] = dot(B[i], B_star[k-1]) / d_prev
                    
                    # Update mu[i][k]
                    d_curr = dot(B_star[k], B_star[k])
                    if d_curr == 0: mu[i][k] = Fraction(0)
                    else: mu[i][k] = dot(B[i], B_star[k]) / d_curr

                k = max(k - 1, 1)

        return Matrix(ZZ, B)

# Dummy object for ZZ ring
class RingZZ:
    pass
ZZ = RingZZ()

# --- Elliptic Curve ---

class EllipticCurve:
    def __init__(self, field, params):
        self.field = field
        self.a = params[0]
        self.b = params[1]
        self.p = field.p

    def __call__(self, x, y):
        return Point(self, x, y)

class Point:
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = curve.p
        if (x is not None) and (y is not None):
            # Check point on curve if desired
            pass

    def __eq__(self, other):
        if other is None: return False
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if other is None: return self
        P = self
        Q = other
        p = self.p
        
        if P.x == Q.x and P.y != Q.y:
            return Point(self.curve, None, None) 

        if P.x == Q.x:
            if P.y == 0: return Point(self.curve, None, None)
            lam = (3 * P.x * P.x + self.curve.a) * inverse_mod(2 * P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse_mod(Q.x - P.x, p)
            lam %= p

        x3 = (lam * lam - P.x - Q.x) % p
        y3 = (lam * (P.x - x3) - P.y) % p
        return Point(self.curve, x3, y3)

    def __rmul__(self, scalar):
        result = None
        addend = self
        scalar = int(scalar)
        while scalar > 0:
            if scalar & 1:
                if result is None: result = addend
                elif result.x is None: result = addend 
                elif addend.x is None: pass
                else: result = result + addend
            if addend.x is not None:
                addend = addend + addend
            scalar >>= 1
        return result

    def xy(self):
        return (self.x, self.y)
