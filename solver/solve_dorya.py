
import json
import sys
import os
from pathlib import Path

# Add project root/solver to path
current_dir = Path(os.getcwd())
sys.path.append(str(current_dir))
sys.path.append(str(current_dir / 'solver'))

from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import sympy
from sympy import symbols, Poly, LC
import time

try:
    # Add solver/modules to path to import lattice directly
    sys.path.append(str(current_dir / 'solver' / 'modules'))
    import lattice
    from lattice import LLL, Matrix
except ImportError as e:
    print(f"Error importing lattice: {e}")
    sys.exit(1)

OUT_FILE = "challenges/dorya/out.txt"

def solve():
    print("[-] Reading output file...")
    with open(OUT_FILE, 'r') as f:
        content = f.read().replace("'", '"')
        data = json.loads(content)
    
    # Reconstruct CRT polynomial
    coeffs = [1 * 2**1024, 3 * 2**1024, 3 * 2**1024, 7 * 2**1024]
    
    N_list = []
    # We will store polynomials as coefficient lists (low to high degree)
    Poly_list = []
    
    x = symbols('x')
    
    print("[-] Constructing polynomials...")
    for entry in data:
        n = entry['n']
        c = entry['c']
        a, b, k_term, d = coeffs
        
        # P_i(x) = (a*x + b)^7 - c*(k_term*x + d)^7 mod n
        # Expand using SymPy
        p_expr = ((a % n) * x + (b % n))**7 - (c % n) * ((k_term % n) * x + (d % n))**7
        poly = Poly(p_expr, x)
        
        # Get coefficients mod n (SymPy might keep large ints, we need mod n)
        # poly.all_coeffs() returns high to low
        raw_coeffs = [int(cf) % n for cf in poly.all_coeffs()]
        raw_coeffs.reverse() # low to high
        
        # Pad with zeros to degree 7
        while len(raw_coeffs) <= 7:
            raw_coeffs.append(0)
            
        Poly_list.append(raw_coeffs)
        N_list.append(n)
        
        # Update coeffs
        coeffs[0] += 2**1024
        coeffs[1] += 4**1024
        coeffs[2] += 6**1024
        coeffs[3] += 8**1024
        
    print("[-] Combining with CRT...")
    big_N = 1
    for n in N_list:
        big_N *= n
        
    final_coeffs = [0] * 8
    
    for i in range(len(data)):
        n_i = N_list[i]
        m_i = big_N // n_i
        y_i = inverse(m_i, n_i)
        term = m_i * y_i
        
        p_coeffs = Poly_list[i]
        for deg in range(8):
            final_coeffs[deg] = (final_coeffs[deg] + p_coeffs[deg] * term) % big_N
            
    # Normalize to monic
    # Leading coeff is at index 7
    lead = final_coeffs[7]
    inv_lead = inverse(lead, big_N)
    
    monic_coeffs = [(c * inv_lead) % big_N for c in final_coeffs]
    
    # Coppersmith params
    degree = 7
    m_param = 2 # Reduced to 2 for speed with pure python LLL. Dimension 7*3=21? No, 7*(m)??
    # Loop i from 0 to m-1 -> m iterations.
    # Inner loop j from 0 to degree-1 -> degree iterations.
    # Total dim = m * degree.
    # For m=2, dim = 2 * 7 = 14.
    # For m=3, dim = 3 * 7 = 21.
    
    # Bound X < N^(1/7).
    # With m=2, we usually get weaker bound but faster.

    
    # We want root bound X approx 480 bits.
    # N approx 7168 bits.
    # X < N^(1/degree) -> 480 < 1024. OK.
    
    X = 2**490 # Bound
    
    f_poly = Poly.from_list(list(reversed(monic_coeffs)), x) # sympy wants high to low
    print(f"[-] Running Lightweight Coppersmith (Dim 8)...")
    dim = 8
    mat_data = [[0] * dim for _ in range(dim)]
    
    # f(x) is monic_coeffs (low to high)
    # f_poly needs to be scaled by X^k in roots
    
    # Rows 0-6: N * (xX)^k
    # Row 7: f(xX)
    
    # Fill N rows
    for i in range(7):
        # N * X^i * x^i
        mat_data[i][i] = big_N * (X**i)

    # Fill f row
    # f(x) = sum a_i x^i
    # We want vector for f(xX) = sum a_i X^i x^i
    f_coeffs_low_high = list(reversed(f_poly.all_coeffs()))
    
    for i, cf in enumerate(f_coeffs_low_high):
        if i < dim:
             mat_data[7][i] = int(cf) * (X**i)

            
    # LLL
    M = Matrix(mat_data)
    print(f"[-] Lattice dimension: {dim}x{dim}")
    
    start_time = time.time()
    reduced_M = LLL(M)
    print(f"[-] LLL finished in {time.time() - start_time:.2f}s")
    
    # Process reduced vectors
    # vector v = (a0, a1 X, a2 X^2, ...)
    # poly Q(x) = sum (ai) x^i
    
    found = False
    for row in reduced_M.data:
        # Reconstruct polynomial
        # Div by X^i
        q_coeffs = []
        for i, val in enumerate(row):
            if val % (X**i) == 0:
                 q_coeffs.append(val // (X**i))
            else:
                # Should not happen if X is power of 2 and int arithmetic
                q_coeffs.append(val // (X**i)) # integer div
        
        # High to low for sympy roots
        q_poly = Poly.from_list(list(reversed(q_coeffs)), x)
        
        if q_poly.is_zero:
            continue
            
        # Find integer roots
        # For integer polynomial, rational roots are factors of a0/an
        # Sympy roots
        try:
             # Fast check: value at 0 is constant term
             # We assume root is positive
             
             # sympy all_roots might return floats or exact roots
             # ground_roots works for integers?
             
             # roots() returns dict {root: multiplicity}
             candidates = sympy.roots(q_poly)
             for r in candidates:
                 if r.is_Integer:
                     m_val = int(r)
                     try:
                         flag = long_to_bytes(m_val)
                         if b'0xL4ugh' in flag:
                             print(f"[!] FLAG FOUND: {flag.decode()}")
                             found = True
                             break
                     except:
                         pass
        except:
             pass
        
        if found:
            break
            
    if not found:
        print("[-] Flag not found in reduced basis rows.")

if __name__ == "__main__":
    solve()
