
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
    ciphertexts = ciphertexts
    
    # Fully factor p-1 carefully
    p_minus_1 = p - 1
    factors = p_minus_1.factor()
    print(f"Factors of p-1: {factors}")
    
    # We take all factors that are manageable
    # Let's take all except the last one (which is huge)
    manageable_factors = factors[:-1]
    q = ZZ(1)
    for b, e in manageable_factors:
        q *= b**e
    
    print(f"Subgroup order q: {q} (~{float(log(q, 2)):.2f} bits)")
    
    Fp = GF(p)
    g = Fp.multiplicative_generator()
    h = g**((p-1)//q)
    
    root_logs = []
    exponent = (p-1)//q
    for i, r in enumerate(roots):
        print(f"Root {i}...", end="")
        sys.stdout.flush()
        r_sub = Fp(r)**exponent
        # Use discrete_log with known factorization for stability
        try:
            l = r_sub.discrete_log(h)
            root_logs.append(l)
            print(" Done")
        except Exception as e:
            print(f" Failed: {e}")
            # Try modulo each factor
            l_val = ZZ(0)
            m_val = ZZ(1)
            for b, e in manageable_factors:
                mi = b**e
                hi = h**(q//mi)
                ri = r_sub**(q//mi)
                li = discrete_log(ri, hi, ord=mi)
                l_val = crt([l_val, li], [m_val, mi])
                m_val *= mi
            root_logs.append(l_val)
            print(" Fixed with manual PH")
        sys.stdout.flush()

    def solve_ct(ct):
        l_c = (Fp(ct)**exponent).discrete_log(h)
        n = 64
        M = Matrix(ZZ, n+2, n+2)
        K = 2**128
        for i in range(n):
            M[i, i] = 2
            M[i, n+1] = root_logs[i] * K
        M[n, n] = 1
        M[n, n+1] = l_c * K
        M[n+1, n+1] = q * K
        M[n+1, :n] = [1]*n
        
        B = M.LLL()
        for row in B:
            if abs(row[n]) == 1 and row[n+1] == 0:
                sgn = -row[n]
                bits = [int((sgn * row[j] + 1) // 2) for j in range(n)]
                if all(b in [0, 1] for b in bits):
                    return bits
        return None

    all_bits = []
    for ct in ciphertexts:
        res = solve_ct(ct)
        if res: all_bits.extend(res)
        else: all_bits.extend([0]*64)
    
    val = sum(int(b) << i for i, b in enumerate(all_bits))
    print(f"RESULT: {val.to_bytes((val.bit_length()+7)//8, 'big')}")

if __name__ == "__main__":
    solve()
