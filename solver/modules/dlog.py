import math

class DLogSolver:
    """
    Solver for Discrete Logarithm Problem (DLP) in modular arithmetic.
    Target: g^x = h (mod p)
    """
    def __init__(self):
        pass

    def solve(self, g, h, p, order=None):
        """
        Solves g^x = h (mod p) using BSGS.
        If order is not provided, it assumes order is p-1 (safe prime) or tries to guess.
        For this challenge, we know the order is q (small).
        """
        print(f"[*] Attempting DLog solve: {g}^x = {h} (mod {p})")
        
        if order is None:
            # Fallback or error, BSGS needs a bound. 
            # If p is large, we can't iterate sqrt(p).
            # But if the actual exponent is small, we might find it.
            limit = 1 << 24 # 16 million iterations max (~seconds)
        else:
            limit = int(math.sqrt(order)) + 1

        print(f"[*] BSGS Limit: {limit}")
        
        # BSGS
        # x = i*m + j
        # g^(im+j) = h
        # g^j = h * (g^-m)^i
        
        m = limit
        table = {}
        
        # Baby steps: g^j
        print("[*] Building table (Baby steps)...")
        curr = 1
        for j in range(m):
            table[curr] = j
            curr = (curr * g) % p
            
        # Giant steps
        print("[*] Searching (Giant steps)...")
        factor = pow(g, -m, p)
        curr = h
        
        for i in range(m):
            if curr in table:
                x = i*m + table[curr]
                print(f"[+] Found x: {x}")
                return x
            curr = (curr * factor) % p
            
        print("[-] DLog failed.")
        return None
