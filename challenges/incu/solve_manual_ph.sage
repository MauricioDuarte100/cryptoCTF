
from sage.all import *
import ast
import sys

def solve():
    with open('/home/sage/repo/challenges/incu/data.txt', 'r') as f:
        content = f.read().strip()
    parts = content.split('\n')
    params = ast.literal_eval(parts[0])
    ciphertexts = ast.literal_eval(parts[1])
    p = params['p']
    roots = params['roots']
    factors_list = [(2, 4), (5, 2), (433, 1), (3623, 1), (4507, 1), (1608913, 1), (62107033127, 1)]
    q = 1
    for b, e in factors_list: q *= b**e
    Fp = GF(p)
    g = Fp.multiplicative_generator()
    h = g**((p-1) // q)
    
    root_logs = []
    exponent_to_subgroup = (p-1) // q
    for i, r in enumerate(roots):
        print(f"Root {i}...")
        sys.stdout.flush()
        r_sub = Fp(r)**exponent_to_subgroup
        try:
            # Try manual PH step by step to find where it fails
            l_val = 0
            curr_mod = 1
            for pi, ei in factors_list:
                qi = pi**ei
                # Project back to subgroup of order qi
                hi = h**(q // qi)
                ri = r_sub**(q // qi)
                li = discrete_log(ri, hi, ord=qi)
                # CRT combination
                l_val = crt([l_val, li], [curr_mod, qi])
                curr_mod *= qi
            
            root_logs.append(l_val)
        except Exception as e:
            print(f"Error at root {i}: {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            return

    print("All logs done. Solving blocks...")
    # ... rest of solve logic ...
solve()
