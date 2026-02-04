
from sage.all import *
import struct
import math
from decimal import getcontext, Decimal as D
import random

getcontext().prec = int(100)

class RealNumberGenerator():
    def __init__(self, seed):
        self.state = seed

    def random(self):
        self.state = D(math.e) * D(str(self.state)) % D(math.pi)
        return math.sqrt(math.fabs(math.sin(D(str(self.state))) + math.cos(D(str(self.state)))))

    def next_bytes(self):
        while True:
            r = self.random()
            B = struct.pack('d', r)
            for b in B:
                yield b

def verify_reduction():
    print("Verifying reduction logic...")
    seed = random.getrandbits(48)
    print(f"True seed: {seed}")
    
    rng = RealNumberGenerator(seed)
    gen = rng.next_bytes()
    # r0 (8 bytes) + r1 (3 bytes to create context)
    stream_prefix = bytes([next(gen) for _ in range(16)])
    bytes_r0 = stream_prefix[:8]
    r0 = struct.unpack('d', bytes_r0)[0]
    
    # Recover s1 (approx)
    y = r0**2
    target = y / math.sqrt(2)
    if target > 1.0: target = 1.0
    asin_t = math.asin(target)
    thetas = [asin_t, math.pi - asin_t, math.pi + asin_t, 2*math.pi - asin_t]
    
    candidates_s1 = []
    for th in thetas:
        s = th - math.pi/4
        s %= (2*math.pi)
        if 0 <= s < math.pi:
            candidates_s1.append(s)

    alpha = D(math.e) / D(math.pi)
    
    # CVP to find alias
    M_CVP = int(2**120)
    alpha_int = int(M_CVP * alpha)
    
    found_alias = False
    aliases = []
    
    for s1_val in candidates_s1:
        beta = D(s1_val) / D(math.pi)
        beta_int = int(M_CVP * beta)
        
        L_CVP = Matrix(ZZ, [[1, alpha_int], [0, -M_CVP]])
        target_vec = vector(ZZ, [0, beta_int])
        
        try:
            # Manual CVP
            B_red = L_CVP.LLL()
            t_vec = vector(QQ, target_vec)
            B_red_qq = B_red.change_ring(QQ)
            x = B_red_qq.solve_left(t_vec)
            from itertools import product
            c_base = [round(xi) for xi in x]
            
            # Check neighbors to find A valid alias (might not be the "closest" if noise is high)
            for delta in product(range(-2, 3), repeat=len(c_base)):
                c = [ci + di for ci, di in zip(c_base, delta)]
                closest_pt = vector(ZZ, c) * B_red
                coeffs = L_CVP.solve_left(closest_pt)
                extracted_s0 = coeffs[0]
                s0_cand = int(extracted_s0)
                
                # Check if this alias generates r0
                if 0 < abs(s0_cand) < 2**70: # Wide check
                     try:
                        trng = RealNumberGenerator(abs(s0_cand))
                        g = trng.next_bytes()
                        s_p = bytes([next(g) for _ in range(8)])
                        if s_p == bytes_r0:
                             print(f"Found alias: {abs(s0_cand)}")
                             aliases.append(abs(s0_cand))
                             found_alias = True
                     except: pass
        except Exception as e:
            print(e)
            
    if not aliases:
        print("No alias found! CVP failed.")
        return

    print(f"Aliases found: {len(aliases)}")
    
    # Try reduction on aliases
    from sage.rings.real_mpfr import RealField
    RR = RealField(2000)
    alpha_rr = RR(math.e)/RR(math.pi)
    cf = continued_fraction(alpha_rr)
    convs = cf.convergents()
    # Listify to check length
    convs_list = list(convs)
    print(f"Convergents count: {len(convs_list)}")
    
    for alias in aliases:
        print(f"Reducing alias {alias}")
        matched = False
        for conv in convs_list[:300]:
            q = int(conv.denominator())
            if q == 0: continue
            
            # Check simple reduction
            rem = alias % q
            
            checks = [rem, rem+q, rem-q, rem+2*q, rem-2*q]
            for cand in checks:
                if cand == seed:
                    print(f"SUCCESS! Found seed {cand} using q={q} from alias {alias}")
                    matched = True
                    return
        if not matched:
            print(f"Failed to reduce alias {alias}")

if __name__ == "__main__":
    verify_reduction()
