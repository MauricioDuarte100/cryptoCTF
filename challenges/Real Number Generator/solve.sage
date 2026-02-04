
from sage.all import *
import struct
import math
from decimal import getcontext, Decimal as D
import hashlib
import operator

# Configuration from challenge
getcontext().prec = int(28)

def xor(a, b):
    return bytes([operator.xor(x, y) for x, y in zip(a, b)])

class RealNumberGenerator():
    def __init__(self, seed):
        self.state = D(seed)

    def random(self):
        # We need to ensure we use prec=28 for the internal state update
        ctx = getcontext()
        orig_prec = int(ctx.prec)
        ctx.prec = int(28)
        self.state = D(math.e) * self.state % D(math.pi)
        res = math.sqrt(math.fabs(math.sin(float(self.state)) + math.cos(float(self.state))))
        ctx.prec = orig_prec
        return res

    def next_bytes(self):
        while True:
            r = self.random()
            B = struct.pack('d', r)
            for b in B:
                yield b

def recover_flag(seed, enc):
    rng = RealNumberGenerator(seed)
    rng_gen = rng.next_bytes()
    rng_stream = bytes([next(rng_gen) for _ in range(len(enc))])
    msg = xor(enc, rng_stream)
    print(f"Decrypted msg: {msg}")
    
    prefix = b'The flag is: '
    if msg.startswith(prefix):
        masked_flag = msg[len(prefix):]
        # Use str(seed).encode() as in chal.py
        mask = hashlib.shake_256(str(seed).encode()).digest(len(masked_flag))
        flag = xor(masked_flag, mask)
        print(f"FLAG-ALERT: {flag.decode(errors='ignore')}")
    else:
        print("Wait, prefix did not match exactly.")
        print(f"Raw decrypted: {msg[:20]}...")
    return

def solve():
    print("Reading output...")
    try:
        with open("/home/sage/repo/challenges/Real Number Generator/output.txt", "r") as f:
            enc_hex = f.read().strip()
    except:
        with open("output.txt", "r") as f:
            enc_hex = f.read().strip()
            
    enc = bytes.fromhex(enc_hex)
    known_prefix = b'The flag is: '
    n = len(known_prefix)
    rng_stream_prefix = xor(enc[:n], known_prefix)
    
    bytes_r0 = rng_stream_prefix[:8]
    r0 = struct.unpack('d', bytes_r0)[0]
    print(f"Recovered r0: {r0}")
    
    # partial r1 (bytes 8-12)
    bytes_r1_partial = rng_stream_prefix[8:]
    print(f"r1 partial: {bytes_r1_partial.hex()}")
    
    y = r0**2
    target = y / math.sqrt(2)
    if target > 1.0: target = 1.0
    asin_t = math.asin(target)
    
    candidate_s1_list = []
    thetas = [asin_t, math.pi - asin_t, math.pi + asin_t, 2*math.pi - asin_t]
    for th in thetas:
        s = (th - math.pi/4) % (2*math.pi)
        if 0 <= s < math.pi:
            # Check s1 vs partial r1 using EXACT challenge logic
            getcontext().prec = int(28)
            s2 = D(math.e) * D(s) % D(math.pi)
            r1_test = math.sqrt(math.fabs(math.sin(float(s2)) + math.cos(float(s2))))
            b_r1 = struct.pack('d', r1_test)
            if b_r1.startswith(bytes_r1_partial):
                print(f"Confirmed s1: {s}")
                candidate_s1_list.append(s)
    
    if not candidate_s1_list:
        print("Verification failed. Trying all base candidates.")
        for th in thetas:
            s = (th - math.pi/4) % (2*math.pi)
            if 0 <= s < math.pi:
                candidate_s1_list.append(s)

    # Lattice Attack
    # M should match precision. 10^-28 error -> M ~ 10^28
    M = int(10**32) 
    alpha = D(math.e) / D(math.pi)
    alpha_int = int(M * alpha)
    L = Matrix(ZZ, [[1, alpha_int], [0, -M]])
    B = L.LLL()
    
    for s1 in candidate_s1_list:
        beta = D(s1) / D(math.pi)
        # target vector (2^47, M * beta)
        target_vec = vector(ZZ, [2**47, int(M * beta)])
        
        # Manual CVP
        x = B.change_ring(QQ).solve_left(vector(QQ, target_vec))
        from itertools import product
        c_base = [round(xi) for xi in x]
        
        for delta in product(range(-5, 6), repeat=2):
            c = vector(ZZ, [cb + db for cb, db in zip(c_base, delta)])
            v = c * B
            s0_raw = int(L.solve_left(v)[0])
            
            for s0 in [s0_raw, -s0_raw]:
                if 0 < s0 < 2**60:
                    test_rng = RealNumberGenerator(s0)
                    gen = test_rng.next_bytes()
                    try:
                        p = bytes([next(gen) for _ in range(13)])
                        if p == rng_stream_prefix:
                            print(f"FOUND SEED: {s0}")
                            recover_flag(s0, enc)
                            return
                    except: pass

    print("CVP failed. Trying Reduction on aliases...")
    # Find alias with smaller M to be more flexible
    M_alias = int(10**25)
    L_alias = Matrix(ZZ, [[1, int(M_alias * alpha)], [0, -M_alias]])
    B_alias = L_alias.LLL()
    
    for s1 in candidate_s1_list:
        beta = D(s1) / D(math.pi)
        target_v = vector(ZZ, [0, int(M_alias * beta)])
        x = B_alias.change_ring(QQ).solve_left(vector(QQ, target_v))
        c_base = [round(xi) for xi in x]
        for delta in product(range(-3, 4), repeat=2):
            c = vector(ZZ, [cb + db for cb, db in zip(c_base, delta)])
            v = c * B_alias
            s0_alias = abs(int(L_alias.solve_left(v)[0]))
            if s0_alias == 0: continue
            
            # Verify alias
            tr = RealNumberGenerator(s0_alias)
            g = tr.next_bytes()
            try:
                p = bytes([next(g) for _ in range(8)])
                if p == bytes_r0:
                    print(f"Alias found: {s0_alias}. Reducing...")
                    from sage.rings.real_mpfr import RealField
                    RR = RealField(1000)
                    cf = continued_fraction(RR(math.e)/RR(math.pi))
                    convs = list(cf.convergents())
                    for conv in convs[10:300]:
                        q = int(conv.denominator())
                        rem = s0_alias % q
                        for k in range(-5, 6):
                            s0_test = rem + k*q
                            if 0 < s0_test < 2**55:
                                tr2 = RealNumberGenerator(s0_test)
                                g2 = tr2.next_bytes()
                                try:
                                    prefix = bytes([next(g2) for _ in range(13)])
                                    if prefix == rng_stream_prefix:
                                        print(f"FOUND SEED via reduction: {s0_test}")
                                        recover_flag(s0_test, enc)
                                        return
                                except: pass
            except: pass

if __name__ == "__main__":
    solve()
