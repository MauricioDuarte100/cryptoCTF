
import sys

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
G1, G2 = E.gens()
n = E.order()
G = E.abelian_group()
inv = G.invariants()
d1, d2 = inv[0], inv[1]

# q are prime factors of d1
factors = [11, 10177, 859267, 52437899]

def solve_ab_mod_d1(P):
    res_a = []
    res_b = []
    for q in factors:
        # G1, G2 have order d2 (usually) or at least multiples of q
        # But we know d1 | d2, and E[q] is in E(K)
        # We need points of order q
        o1, o2 = G1.order(), G2.order()
        G1q = (o1 // q) * G1
        G2q = (o2 // q) * G2
        Pq = (o1 // q) * P # assumes P is in group of order o1? No, P is aG1 + bG2.
        # Actually P = aG1 + bG2 => (o1//q)P = a(o1//q)G1 + b(o1//q)G2 mod ...
        # (Assuming o1 = o2 = d2)
        Pq = (d2 // q) * P
        G1q = (d2 // q) * G1
        G2q = (d2 // q) * G2
        
        base = G1q.weil_pairing(G2q, q)
        if base == 1:
            # If G1q, G2q are dependent, we can't use Weil pairing this way.
            # But the challenge uses G1, G2 = E.gens(), which SHOULD be independent.
            # Let's hope for the best.
            pass
            
        target_a = Pq.weil_pairing(G2q, q)
        target_b = G1q.weil_pairing(Pq, q)
        
        a_q = discrete_log(target_a, base, ord=q)
        b_q = discrete_log(target_b, base, ord=q)
        
        res_a.append(a_q)
        res_b.append(b_q)
    
    return crt(res_a, factors), crt(res_b, factors)

def my_long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def solve():
    with open("/home/sage/repo/challenges/a-dance-of-add-and-mul/chall.txt", "r") as f:
        data = f.read().strip()
    
    import ast
    pts_data = ast.literal_eval(data)
    cs = [E(x, y) for x, y in pts_data]
    
    print(f"Loaded {len(cs)} points")
    
    abs_d1 = []
    for i, P in enumerate(cs):
        a, b = solve_ab_mod_d1(P)
        abs_d1.append((a, b))
        if i % 100 == 0:
            print(f"Solved {i}/{len(cs)}")
    
    # Try x0 possibilities
    for x0_possibility in [abs_d1[0][0], abs_d1[0][1]]:
        xi = x0_possibility
        bits = []
        fail = False
        current_xi = xi
        
        for i in range(len(abs_d1)):
            a, b = abs_d1[i]
            if a == current_xi:
                bits.append("0")
                current_xi = b
            elif b == current_xi:
                bits.append("1")
                current_xi = a
            else:
                fail = True
                break
        
        if not fail:
            m_bin = "".join(bits)
            m = int(m_bin, 2)
            try:
                flag = my_long_to_bytes(m)
                if b"Alpaca" in flag:
                    print(f"FLAG: {flag.decode()}")
                    return
            except:
                pass

solve()
