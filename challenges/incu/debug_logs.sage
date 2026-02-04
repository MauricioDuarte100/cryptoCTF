
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
    
    print(f"h order: {h.order()}")
    print(f"expected q: {q}")
    
    root_logs = []
    exponent_to_subgroup = (p-1) // q
    for i, r in enumerate(roots):
        r_sub = Fp(r)**exponent_to_subgroup
        try:
            print(f"  Computing log for root {i}...", end="")
            sys.stdout.flush()
            l = discrete_log(r_sub, h, ord=q)
            root_logs.append(l)
            print(" Done")
        except Exception as e:
            print(f" FAILED: {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            break

solve()
