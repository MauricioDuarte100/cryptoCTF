from sage.all import *
from Crypto.Util.number import getPrime
from hashlib import sha256
from secrets import randbelow

# Simulate without fastecdsa dependency
def simulate():
    # Curve secp256k1 parameters
    p_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a_curve = 0
    b_curve = 7
    q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    E = EllipticCurve(GF(p_curve), [a_curve, b_curve])
    G = E(Gx, Gy)
    
    d = randint(1, q-1)
    P = d * G
    
    p = getPrime(311) # 0x137
    a = randint(1, p-1)
    b = randint(1, p-1)
    x = randint(1, p-1)
    
    def lcg(a, b, p, x):
        while True:
            x = (a * x + b) % p
            yield x
            
    rng = lcg(a, b, p, x)
    
    data = []
    
    # Generate 17 signatures
    for i in range(17):
        k = next(rng)
        # Random message
        z = randint(1, q-1)
        
        k_inv = inverse_mod(k, q)
        r = int((k * G).xy()[0]) % q
        
        if r == 0: continue
        
        s = (k_inv * (z + r * d)) % q
        
        if s == 0: continue
            
        data.append({'r': r, 's': s, 'z': z})
        
    print(f"True d: {d}")
    
    # Lattice solve
    print("Attempting to solve...")
    m_len = len(data)
    M = Matrix(ZZ, m_len + 2, m_len + 2)
    for i in range(m_len):
        M[i, i] = q
    
    Ts = []
    Cs = []
    for i in range(m_len):
        dt = data[i]
        sinv = inverse_mod(dt['s'], q)
        ti = (sinv * dt['z']) % q
        ci = (sinv * dt['r']) % q
        Ts.append(ti)
        Cs.append(ci)
        M[m_len, i] = ci
        
    M[m_len, m_len] = 1 # Weight for d
    
    for i in range(m_len):
        M[m_len+1, i] = Ts[i]
    M[m_len+1, m_len+1] = 2**256
    
    print("Running LLL...")
    L = M.LLL()
    
    found = False
    for row in L:
        d_val = row[m_len]
        c_val = row[m_len+1]
        
        cands = []
        if c_val != 0: cands.append(abs(d_val // c_val))
        cands.append(abs(d_val))
        
        if d in cands:
            print(f"FOUND d: {d}")
            found = True
            break
            
    if not found:
        print("Failed on simulated data.")
    else:
        print("Success on simulated data.")

if __name__ == '__main__':
    simulate()
