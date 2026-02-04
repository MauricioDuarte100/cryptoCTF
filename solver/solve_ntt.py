import re
import os
from hashlib import sha256
from Crypto.Cipher import AES

# Kyber Parameters
K = 12
N = 256
Q = 3329
ZETA_GEN = 17
DELTAs = [240, 430, 600, 75, 70, 88, 99]

def gen_zetas():
    zetas = [0] * 128
    val = 1
    for i in range(128):
        zetas[i] = val
        val = (val * ZETA_GEN) % Q
    
    def bit_reverse(n, b):
        x = 0
        for i in range(b):
            x = (x << 1) | (n & 1)
            n >>= 1
        return x

    inv_zetas = [0] * 128
    for i in range(128):
        inv_zetas[bit_reverse(i, 7)] = zetas[i]
    return inv_zetas

ZETAS = gen_zetas()

def fqmul(a, b):
    return (a * b) % Q

def parse_output(filename):
    with open(filename, 'r') as f:
        content = f.read()
    
    pk_match = re.search(r"pk = ([0-9a-f]+)", content)
    leaks_match = re.search(r"leaks = (\[.*\])", content, re.DOTALL)
    ct_match = re.search(r"ct = ([0-9a-f]+)", content)
    iv_match = re.search(r"iv = ([0-9a-f]+)", content)
    
    pk = bytes.fromhex(pk_match.group(1))
    leaks = eval(leaks_match.group(1)) 
    ct = bytes.fromhex(ct_match.group(1))
    iv = bytes.fromhex(iv_match.group(1))
    
    return pk, leaks, ct, iv

def check_dist(calc, leak, delta):
    diff = (calc - leak + Q//2) % Q - Q//2
    return abs(diff) <= delta

def solve_poly_correct(raw_leak):
    layers = []
    for l in range(7):
        layers.append(raw_leak[l*256 : (l+1)*256])
        
    # Groups: dict j -> {indices, candidates}
    # Layer 0 indices: [i, i+128]
    # Candidates: (s[i], s[i+128])
    groups = {} 
    
    zeta0 = ZETAS[1]
    leak0 = layers[0]
    delta0 = DELTAs[0]
    
    for i in range(128):
        cands = []
        l_lo = leak0[i]
        l_hi = leak0[i+128]
        for v_lo in range(-2, 3):
            for v_hi in range(-2, 3):
                t = fqmul(zeta0, v_hi)
                r_lo = (v_lo + t) % Q
                r_hi = (v_lo - t) % Q
                if check_dist(r_lo, l_lo, delta0) and check_dist(r_hi, l_hi, delta0):
                    cands.append((v_lo, v_hi))
        groups[i] = {'indices': [i, i+128], 'cands': cands}
        
    # Layer 1
    # Merge groups j and j+64.
    # Indices: [j, j+128] + [j+64, j+192]
    # Constraints:
    # 1. r[j] & r[j+64] (ZETAS[2])
    # 2. r[j+128] & r[j+192] (ZETAS[3])
    
    leak1 = layers[1]
    delta1 = DELTAs[1]
    new_groups = {}
    
    z_constr1 = ZETAS[2]
    z_constr2 = ZETAS[3]
    z_prev = ZETAS[1]
    
    for j in range(64):
        g1 = groups[j]
        g2 = groups[j+64]
        merged = []
        
        l1_lo = leak1[j]
        l1_hi = leak1[j+64]
        l2_lo = leak1[j+128]
        l2_hi = leak1[j+192]
        
        for c1 in g1['cands']:
            # c1: (s[j], s[j+128])
            # Precompute r inputs from Layer 0
            t_prev1 = fqmul(z_prev, c1[1])
            r_j = (c1[0] + t_prev1) % Q
            r_j128 = (c1[0] - t_prev1) % Q
            
            for c2 in g2['cands']:
                # c2: (s[j+64], s[j+192])
                t_prev2 = fqmul(z_prev, c2[1])
                r_j64 = (c2[0] + t_prev2) % Q
                r_j192 = (c2[0] - t_prev2) % Q
                
                # Check Constraint 1: (r_j, r_j64) with ZETAS[2]
                t1 = fqmul(z_constr1, r_j64)
                out1_lo = (r_j + t1) % Q
                out1_hi = (r_j - t1) % Q
                
                if not (check_dist(out1_lo, l1_lo, delta1) and check_dist(out1_hi, l1_hi, delta1)):
                    continue
                    
                # Check Constraint 2: (r_j128, r_j192) with ZETAS[3]
                t2 = fqmul(z_constr2, r_j192)
                out2_lo = (r_j128 + t2) % Q
                out2_hi = (r_j128 - t2) % Q
                
                if check_dist(out2_lo, l2_lo, delta1) and check_dist(out2_hi, l2_hi, delta1):
                    # Valid
                    merged.append(c1 + c2)
        
        new_groups[j] = {'indices': g1['indices'] + g2['indices'], 'cands': merged}
        
    groups = new_groups
    
    # Layer 2
    # Merge groups j and j+32 (j in 0..31)
    # Indices: [j, j+128, j+64, j+192] + [j+32, j+160, j+96, j+224]
    # Constraints: 4 blocks.
    # 1. r[j], r[j+32] (Z4)
    # 2. r[j+64], r[j+96] (Z5)
    # 3. r[j+128], r[j+160] (Z6)
    # 4. r[j+192], r[j+224] (Z7)
    
    leak2 = layers[2]
    delta2 = DELTAs[2]
    new_groups = {}
    
    z_L0 = ZETAS[1]
    z_L1_1 = ZETAS[2] # for j, j+64
    z_L1_2 = ZETAS[3] # for j+128, j+192
    
    zs_L2 = [ZETAS[4], ZETAS[5], ZETAS[6], ZETAS[7]]
    
    # Offsets for Layer 2 constraints
    # Constraint k (0..3) corresponds to r[j + k*64] and r[j + k*64 + 32]
    
    for j in range(32):
        g1 = groups[j]
        g2 = groups[j+32]
        merged = []
        
        # Pre-fetch leaks for all 4 constraints
        leaks_L2 = []
        for k in range(4):
            idx_lo = j + k*64
            idx_hi = j + k*64 + 32
            leaks_L2.append((leak2[idx_lo], leak2[idx_hi]))
            
        for c1 in g1['cands']:
            # c1: s[j], s[j+128], s[j+64], s[j+192]
            # Need to compute r at Layer 1 output (Layer 2 input)
            # r1_j, r1_j64, r1_j128, r1_j192
            
            # Recalc Layer 0
            t0_a = fqmul(z_L0, c1[1]) # s[j+128]
            r0_j = (c1[0] + t0_a) % Q
            r0_j128 = (c1[0] - t0_a) % Q
            
            t0_b = fqmul(z_L0, c1[3]) # s[j+192]
            r0_j64 = (c1[2] + t0_b) % Q
            r0_j192 = (c1[2] - t0_b) % Q
            
            # Recalc Layer 1
            t1_a = fqmul(z_L1_1, r0_j64)
            r1_j = (r0_j + t1_a) % Q
            r1_j64 = (r0_j - t1_a) % Q 
            # In Layer 2, constraints are on:
            # 1. (r1[j], r1[j+32])
            # 2. (r1[j+64], r1[j+96])??
            # Wait.
            # Layer 2 logic:
            # Block 0: inputs r1[0..63]. pairs (x, x+32). -> outputs r2[x], r2[x+32].
            # r1[j] is checked vs r1[j+32].
            # r1[j+64] is NOT checking vs r1[j+96] in THIS block.
            # r1[j+64] belongs to Block 1 (inputs 64..127).
            # Yes. Block 1 pairs (x, x+32) where x in 64..95.
            # So j+64 corresponds to x=j+64. pair is j+64, j+96.
            # So indeed, we solve for 4 pairs.
            
            # We need r1_j, r1_j64, r1_j128, r1_j192 from c1?
            # From c1 we get:
            # r1_j = r0_j + t1_a
            # r1_j64 = r0_j - t1_a
            # r1_j128 = r0_j128 + t1_b
            # r1_j192 = r0_j128 - t1_b
            
            t1_b = fqmul(z_L1_2, r0_j192)
            r1_j128 = (r0_j128 + t1_b) % Q
            r1_j192 = (r0_j128 - t1_b) % Q
            
            # Note mapping:
            # c1 provides inputs at indices: j, j+64, j+128, j+192
            # These are exactly the 'lo' indices for the 4 constraints?
            # Constraint 0: lo=j. hi=j+32.
            # Constraint 1: lo=j+64. hi=j+96.
            # Constraint 2: lo=j+128. hi=j+160.
            # Constraint 3: lo=j+192. hi=j+224.
            # So c1 provides the 'lo' sides. c2 provides the 'hi' sides.
            
            r1_vals_c1 = [r1_j, r1_j64, r1_j128, r1_j192]
            
            for c2 in g2['cands']:
                # c2: s[j+32], s[j+160], s[j+96], s[j+224]
                # Order in c2 tuple:
                # Based on Layer 1 merge:
                # indices: [j+32, j+32+128, j+32+64, j+32+192]
                #        = [j+32, j+160, j+96, j+224]
                # c2[0]=s[j+32], c2[1]=s[j+160], c2[2]=s[j+96], c2[3]=s[j+224]
                
                # Recalc Layer 0 for c2
                t0_c = fqmul(z_L0, c2[1])
                r0_j32 = (c2[0] + t0_c) % Q
                r0_j160 = (c2[0] - t0_c) % Q
                
                t0_d = fqmul(z_L0, c2[3])
                r0_j96 = (c2[2] + t0_d) % Q
                r0_j224 = (c2[2] - t0_d) % Q
                
                # Recalc Layer 1 for c2
                t1_c = fqmul(z_L1_1, r0_j96)
                r1_j32 = (r0_j32 + t1_c) % Q
                r1_j96 = (r0_j32 - t1_c) % Q
                
                t1_d = fqmul(z_L1_2, r0_j224)
                r1_j160 = (r0_j160 + t1_d) % Q
                r1_j224 = (r0_j160 - t1_d) % Q
                
                # Values: r1_j32, r1_j96, r1_j160, r1_j224
                # We need to match:
                # Constr 0: r1_j vs r1_j32.
                # Constr 1: r1_j64 vs r1_j96.
                # Constr 2: r1_j128 vs r1_j160.
                # Constr 3: r1_j192 vs r1_j224.
                
                val_pairs = [
                    (r1_vals_c1[0], r1_j32),
                    (r1_vals_c1[1], r1_j96),
                    (r1_vals_c1[2], r1_j160),
                    (r1_vals_c1[3], r1_j224)
                ]
                
                valid = True
                for k_con in range(4):
                    z = zs_L2[k_con]
                    in_lo, in_hi = val_pairs[k_con]
                    t = fqmul(z, in_hi)
                    out_lo = (in_lo + t) % Q
                    out_hi = (in_lo - t) % Q
                    lk_lo, lk_hi = leaks_L2[k_con]
                    if not (check_dist(out_lo, lk_lo, delta2) and check_dist(out_hi, lk_hi, delta2)):
                        valid = False
                        break
                
                if valid:
                    merged.append(c1 + c2)
        
        new_groups[j] = {'indices': g1['indices'] + g2['indices'], 'cands': merged}
    
    groups = new_groups
    
    full_coeffs = [0] * 256
    for base, data in groups.items():
        if not data['cands']:
            return None 
        cand = data['cands'][0] 
        indices = data['indices']
        for idx, val in zip(indices, cand):
            full_coeffs[idx] = val
            
    return full_coeffs

def poly_tobytes(coeffs):
    r = bytearray(384)
    for i in range(128):
        t0 = coeffs[2*i] % Q
        t1 = coeffs[2*i+1] % Q
        r[3*i+0] = t0 & 0xff
        r[3*i+1] = ((t0 >> 8) & 0x0f) | ((t1 & 0x0f) << 4)
        r[3*i+2] = (t1 >> 4) & 0xff
    return r

def ntt(r):
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = fqmul(zeta, r[j + length])
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
            start += 2 * length
        length >>= 1
    return r

def verify_leaks(coeffs, actual_leaks):
    # Simulate partial NTT and compare
    r = list(coeffs)
    diffs = []
    
    # Layer 0
    # Capture state after layers
    # leak struct: 7 layers of 256 ints.
    
    layers_data = []
    
    k = 1
    length = 128
    
    # Layers count
    layer_idx = 0
    
    while length >= 2:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = fqmul(zeta, r[j + length])
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
            start += 2 * length
        
        # After layer, r is updated
        # Capture r
        # Calculate diff with actual_leaks
        # actual_leaks slice
        chunk = actual_leaks[layer_idx*256 : (layer_idx+1)*256]
        
        current_diffs = []
        for i in range(256):
            # check distance
            d = (r[i] - chunk[i] + Q//2) % Q - Q//2
            current_diffs.append(abs(d))
        
        diffs.extend(current_diffs)
        length >>= 1
        layer_idx += 1
        
    return diffs

def solve():
    pk, leaks, ct, iv = parse_output(r"challenges/Nightfall Tempest Trials/attachment/output.txt")
    sk_bytes = bytearray()
    
    for k in range(K):
        print(f"Solving Poly {k}...")
        coeffs = solve_poly_correct(leaks[k])
        if coeffs is None:
            print("Failed to recover poly")
            return
        
        # Transform to NTT domain
        coeffs_ntt = ntt(list(coeffs)) # Copy
        sk_bytes.extend(poly_tobytes(coeffs_ntt))
        
        # Verify
        print(f"Verifying Poly {k}...")
        diffs = verify_leaks(coeffs, leaks[k])
        print(f"Max diff: {max(diffs)}")
        
    key = sha256(sk_bytes).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    
    try:
        pad_len = pt[-1]
        if 0 < pad_len <= 16:
            pt = pt[:-pad_len]
    except:
        pass
        
    print(f"Decrypted: {pt}")
    try:
        print(f"Decrypted (str): {pt.decode('utf-8')}")
    except:
        pass

if __name__ == "__main__":
    solve()
