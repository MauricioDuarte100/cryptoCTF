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

    inv_zetas_br = [0] * 128
    inv_zetas_norm = [0] * 128
    for i in range(128):
        inv_zetas_br[bit_reverse(i, 7)] = zetas[i]
        inv_zetas_norm[i] = zetas[i] # Try normal order too
        
    return inv_zetas_br, inv_zetas_norm

ZETAS_BR, ZETAS_NORM = gen_zetas()
ZETAS = ZETAS_BR # Default

def fqmul(a, b):
    return (a * b) % Q

def parse_output(filename):
    with open(filename, 'r') as f:
        content = f.read()
    
    pk_match = re.search(r"pk = ([0-9a-f]+)", content)
    leaks_match = re.search(r"leaks = (\[.*\])", content, re.DOTALL)
    ct_match = re.search(r"ct = ([0-9a-f]+)", content)
    iv_match = re.search(r"iv = ([0-9a-f]+)", content)
    
    # Safely eval leaks
    # In some envs eval might be restricted, but standard python is fine.
    # The leaks structure is large, simpler to eval than regex parse 1792 ints.
    leaks = eval(leaks_match.group(1)) 
    
    return bytes.fromhex(pk_match.group(1)), leaks, bytes.fromhex(ct_match.group(1)), bytes.fromhex(iv_match.group(1))

def check_dist(calc, leak, delta):
    diff = (calc - leak + Q//2) % Q - Q//2
    # Relax delta slightly
    return abs(diff) <= (delta + 5)

def calc_err(calc, leak):
    return abs((calc - leak + Q//2) % Q - Q//2)

def solve_poly_general(raw_leak):
    layers = []
    for l in range(7):
        layers.append(raw_leak[l*256 : (l+1)*256])
        
    # Initialization
    # A list of groups.
    # group_map: maps index -> group (shared reference)
    # Group structure: { 'indices': [list of indices], 'cands': [ list of candidates ] }
    # Candidate structure: { 's': {idx: val}, 'r': {idx: val} }
    # Optimized Candidate: Tuple( Tuple(s values), Tuple(r values) )
    # But indices order in tuple must be stable.
    # Let's use dicts for `s` and `r` in candidates for clarity, optimization later if needed.
    
    group_map = {}
    for i in range(256):
        cands = []
        # Diagnostic showed s in [-3, 3]
        for v in range(-3, 4):
            cands.append( ({i: v}, {i: v}, 0) ) # s[i]=v, r[i]=v, err=0
        
        g = {'indices': [i], 'cands': cands}
        group_map[i] = g
        
    # Iterate Layers
    for l in range(7):
        length = 128 >> l
        delta = DELTAs[l]
        leak_layer = layers[l]
        
        # Determine Zetas range for this layer
        # k starts at 1. L0 uses k=1.
        # L1 uses k=2,3.
        # L_l uses k in [2^l, 2^(l+1) - 1]
        k_start = 1 << l
        
        # Loop structure mimicking ntt.c
        start = 0
        while start < 256:
            zeta = ZETAS[k_start]
            k_start += 1
            
            for j in range(start, start + length):
                idx1 = j
                idx2 = j + length
                
                g1 = group_map[idx1]
                g2 = group_map[idx2]
                
                # Check consistency
                if g1 is g2:
                    # Already merged group. Apply NEW constraint on existing candidates.
                    refined_cands = []
                    
                    lk1 = leak_layer[idx1]
                    lk2 = leak_layer[idx2]
                    
                    for c in g1['cands']:
                        # c is (s_dict, r_dict)
                        r1 = c[1][idx1]
                        r2 = c[1][idx2]
                        
                        t = fqmul(zeta, r2)
                        new_r1 = (r1 + t) % Q
                        new_r2 = (r1 - t) % Q
                        
                        if check_dist(new_r1, lk1, delta) and check_dist(new_r2, lk2, delta):
                            # Valid
                            new_r = c[1].copy() # Copy needed? Yes if we share refs.
                            new_r[idx1] = new_r1
                            new_r[idx2] = new_r2
                            new_r[idx1] = new_r1
                            new_r[idx2] = new_r2
                            
                            err1 = calc_err(new_r1, lk1)
                            err2 = calc_err(new_r2, lk2)
                            new_err = max(c[2], err1, err2)
                            
                            refined_cands.append((c[0], new_r, new_err))
                            
                    # Update group inplace
                    g1['cands'] = refined_cands
                    continue

                # Merge g1 and g2
                new_cands = []
                
                # Pruning heuristic: if we have too many candidates, we might OOM.
                # But typically it prunes down fast.
                
                # Pre-fetch leaks
                lk1 = leak_layer[idx1]
                lk2 = leak_layer[idx2]
                
                for c1 in g1['cands']:
                    # c1 is (s_dict, r_dict)
                    r1 = c1[1][idx1] # Needed input r at idx1
                    
                    for c2 in g2['cands']:
                        r2 = c2[1][idx2] # Needed input r at idx2
                        
                        # Butterfly
                        t = fqmul(zeta, r2)
                        new_r1 = (r1 + t) % Q
                        new_r2 = (r1 - t) % Q
                        
                        # Check
                        if check_dist(new_r1, lk1, delta) and check_dist(new_r2, lk2, delta):
                            # Valid merge
                            # Combine s dicts
                            new_s = c1[0].copy()
                            new_s.update(c2[0])
                            
                            # Combine r dicts and update current values
                            new_r = c1[1].copy()
                            new_r.update(c2[1])
                            new_r[idx1] = new_r1
                            new_r[idx2] = new_r2
                            
                            new_r[idx1] = new_r1
                            new_r[idx2] = new_r2
                            
                            err1 = calc_err(new_r1, lk1)
                            err2 = calc_err(new_r2, lk2)
                            new_err = max(c1[2], c2[2], err1, err2)
                            
                            new_cands.append( (new_s, new_r, new_err) )
                            new_cands.append( (new_s, new_r, new_err) )
                                
                if len(new_cands) > 20000:
                    new_cands.sort(key=lambda x: x[2])
                    new_cands = new_cands[:20000]
                
                # Create NEW group
                new_indices = g1['indices'] + g2['indices']
                new_group = {'indices': new_indices, 'cands': new_cands}
                
                # Update map
                for idx in new_indices:
                    group_map[idx] = new_group
                    
            start += 2 * length
            
        print(f"Layer {l} complete. Group 0 candidates: {len(group_map[0]['cands'])}")
        if len(group_map[0]['cands']) == 0:
            return None # Failed
            
    # Collect all valid coeffs candidates
    # We might have multiple groups, and each group might have multiple candidates.
    # But usually distinct groups are independent indices.
    # The ambiguity comes from 'cands' list being > 1 in a group.
    
    # We need to form combinatorial product of candidates across groups.
    # Collect lists of (indices, value_dict) for each unique group.
    
    unique_groups = []
    processed_groups = set()
    for i in range(256):
        g = group_map[i]
        gid = id(g)
        if gid in processed_groups:
            continue
        processed_groups.add(gid)
        unique_groups.append(g)
        
    # Cartesian product of candidates from each group
    # groups[k] has candidates list.
    import itertools
    
    all_coeffs_options = []
    
    # Prepare lists of candidates for product
    # For each group, sort candidates by error and take top N
    group_cands_lists = []
    for g in unique_groups:
        cands = g['cands'] # List of (s, r, err)
        # Sort by error
        cands.sort(key=lambda x: x[2])
        # Take top 3? Or top 1 if margin is large?
        # Let's take top 5 to be safe but allow reduction
        limit = 5
        best_cands = cands[:limit]
        group_cands_lists.append(best_cands)
        
    # Calculate size
    total = 1
    for gl in group_cands_lists:
        total *= len(gl)
    print(f"DEBUG: Poly candidates count (pruned): {total}")
       
    for combo in itertools.product(*group_cands_lists):
        # combo is tuple of candidates (one per group)
        # Construct full coeffs
        c = [0] * 256
        for group_idx, cand_tuple in enumerate(combo):
             # cand_tuple is (s_map, r_map, err)
             s_map = cand_tuple[0]
             for k, v in s_map.items():
                 c[k] = v
        all_coeffs_options.append(c)
            
    return all_coeffs_options

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

    return r

def attempt_solve(zeta_table):
    global ZETAS
    ZETAS = zeta_table
    print(f"DEBUG: ZETAS[0..5]: {ZETAS[:5]}")
    print(f"DEBUG: ZETAS[1] used for L0: {ZETAS[1]}")
    
    pk, leaks, ct, iv = parse_output(r"challenges/Nightfall Tempest Trials/attachment/output.txt")
    
    poly_candidates = []
    
    for k in range(K):
        #print(f"Solving Poly {k}...")
        coeffs_options = solve_poly_general(leaks[k])
        if not coeffs_options:
            print(f"Failed to recover poly {k}")
            return None
        
        # Transform all options to bytes
        poly_bytes_options = []
        for c in coeffs_options:
            c_ntt = ntt(list(c))
            poly_bytes_options.append(poly_tobytes(c_ntt))
        poly_candidates.append(poly_bytes_options)
        
    print("Brute-forcing candidate combinations...")
    import itertools
    
    total_combos = 1
    for p in poly_candidates:
        total_combos *= len(p)
    print(f"Total key combinations: {total_combos}")
    
    return poly_candidates, ct, iv

def solve():
    print("Trying Bit-Reversed Zetas...")
    res = attempt_solve(ZETAS_BR)
    if res:
        poly_candidates, ct, iv = res
        check_combinations(poly_candidates, ct, iv)
        
    print("Trying Normal Zetas...")
    res = attempt_solve(ZETAS_NORM)
    if res:
        poly_candidates, ct, iv = res
        check_combinations(poly_candidates, ct, iv)

def check_combinations(poly_candidates, ct, iv):
    import itertools
    count = 0
    total_combos = 1
    for p in poly_candidates:
        total_combos *= len(p)
        
    for key_parts in itertools.product(*poly_candidates):
        sk_bytes = bytearray()
        for p in key_parts:
            sk_bytes.extend(p)
            
        key = sha256(sk_bytes).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        
        count += 1
        if count % 10000 == 0:
            print(f"Checked {count}/{total_combos}")
            
        try:
            pad_len = pt[-1]
            if 0 < pad_len <= 16:
                unpadded = pt[:-pad_len]
                if b'flag{' in unpadded or b'CTF{' in unpadded or b'nightfall{' in unpadded:
                     print(f"FOUND FLAG: {unpadded.decode('utf-8')}")
                     return
        except:
            pass
    print("No flag found in this set.")

if __name__ == "__main__":
    solve()
