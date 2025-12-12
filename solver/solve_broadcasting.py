import re
import sys
from hashlib import sha256
from Crypto.Cipher import AES
import random

# Parametros
N = 509
q = 2048
p = 3

def process_sample(args):
    pk, ct = args
    h_coeffs = parse_poly_str(pk)
    c_coeffs = parse_poly_str(ct)
    
    h_inv = invertmodpowerof2(h_coeffs, q)
    if h_inv:
        b = poly_mul_balanced(h_inv, c_coeffs, q)
        return (h_inv, b)
    return None

# Fast polynomial arithmetic in Python using lists
# Coeffs are [c_0, c_1, ..., c_{N-1}] corresponding to c_0 + c_1 x + ...
# Arithmetic is modulo x^N - 1

def poly_add(f, g, mod):
    res = [(a + b) % mod for a, b in zip(f, g)]
    return res

def poly_sub(f, g, mod):
    res = [(a - b) % mod for a, b in zip(f, g)]
    return res

def poly_mul_balanced(f, g, q_mod):
    # Convolution mod x^N - 1
    # Naive multiplication O(N^2)
    # Since N=509 is small enough, N^2 = 250,000.
    # 250k ops is fine.
    res = [0] * N
    for i in range(N):
        fi = f[i]
        if fi == 0: continue
        for j in range(N):
            # (i+j) mod N
            # Since x^N = 1
            k = (i + j) 
            if k >= N: k -= N
            res[k] += fi * g[j]
    
    # Balanced mod
    return [((c + q_mod // 2) % q_mod) - q_mod // 2 for c in res]

def poly_mul_mod(f, g, mod):
    res = [0] * N
    for i in range(N):
        fi = f[i]
        if fi == 0: continue
        for j in range(N):
            k = (i + j) 
            if k >= N: k -= N
            res[k] += fi * g[j]
            
    return [x % mod for x in res]

def poly_inv_mod_2(f):
    # Invert f modulo 2 and x^N - 1
    # Use Sympy for this step as it's hard to implement from scratch (GCD)
    # Convert list to sympy poly
    from sympy import symbols, GF, Poly, gcdex
    x = symbols('x')
    
    # Construct poly from list
    # List is [c0, c1, ...] -> c0 + c1*x ...
    # Sympy Poly expects coeffs in decreasing order? No, depends.
    # Poly(coeffs, x) uses decreasing order by default?
    # Let's build expression
    expr = sum(c * x**i for i, c in enumerate(f))
    
    # Modulus poly
    mod_poly = x**N - 1
    
    # Invert over GF(2)
    try:
        s, t, g = gcdex(expr, mod_poly, modulus=2)
        if g != 1: # Not invertible or GCD!=1
             # In ring GF(2)[x]/(x^N-1), inverse exists iff gcd(f, x^N-1)=1
             # If g != 1 in GF(2), then not invertible.
             # Wait, gcdex returns g such that s*f + t*mod = g.
             # If g is a unit in GF(2) (i.e. 1), then s is inverse.
             # If g has degree > 0, failed.
             return None
        
        # Extract coeffs from s
        inv_poly = Poly(s, x, modulus=2)
        coeffs = inv_poly.all_coeffs() # High to low
        # We want low to high, length N
        coeffs = coeffs[::-1] # Low to high
        res = [int(c) for c in coeffs] + [0]*(N - len(coeffs))
        return res
    except Exception as e:
        return None

def invertmodpowerof2(f, q_val):
    # Hensel lifting
    # f is list
    # q is power of 2
    
    # Inverse mod 2
    h = poly_inv_mod_2(f)
    if h is None: return None
    
    # Lift
    # To reduce ops, we assume q=2048 = 2^11.
    # Steps: 2 -> 4 -> 8 -> 16 -> ... -> 2048
    curr_q = 2
    while curr_q < q_val:
        curr_q *= 2
        
        # h = h * (2 - f*h) mod curr_q
        # r = f*h
        r = poly_mul_mod(f, h, curr_q) # Result in [0, curr_q)
        
        # 2 - r
        # 2 is poly [2, 0...]
        # (2 - r)
        two_minus_r = [(0 - r[i]) % curr_q for i in range(N)]
        two_minus_r[0] = (2 - r[0]) % curr_q
        
        h = poly_mul_mod(h, two_minus_r, curr_q)
        
    # Check
    # Final modulation to balanced
    # The result h is in [0, q).
    # But function returns balanced?
    # chall.sage uses balancedmod in the loop. 
    # Actually standard hensel lifting works in Zq. 
    # Just return coefficients in [0, q) or balanced.
    # The solver expects balanced mod q?
    return [((c + q_val // 2) % q_val) - q_val // 2 for c in h]

def parse_poly_str(s):
    # Parse string like "-123*x^5 + 4*x^2 + 1"
    # Returns list of coeffs size N
    coeffs = [0] * N
    
    # Find all terms
    # Term: (coeff?) * x ^ (exp)
    # or const
    # Normalized: " ... + ... "
    # Regex for term: ([+-]?\s*\d+)?\s*\*?\s*(x(?:\^(\d+))?)?
    # Better: split by + or - (keeping delimiter)
    
    # Cleanup spaces
    s = s.replace(" ", "")
    # Add + before - if not at start
    s = s.replace("-", "+-")
    if s.startswith("+-"): s = s[1:] # Remove leading +
    elif s.startswith("+"): s = s[1:]
    
    terms = s.split("+")
    for term in terms:
        if not term: continue
        if term == "-": continue # glitch
        
        coeff = 1
        exp = 0
        
        if "*x" in term:
            parts = term.split("*x")
            val = parts[0]
            if val == "-": coeff = -1
            elif val == "": coeff = 1
            else: coeff = int(val)
            
            rest = parts[1] # "^5" or ""
            if "^" in rest:
                exp = int(rest.replace("^", ""))
            else:
                exp = 1
        elif "x" in term: # "x", "-x", "x^5"
            if "^" in term:
                parts = term.split("x^")
                val = parts[0]
                if val == "-": coeff = -1
                elif val == "": coeff = 1
                else: coeff = int(val) # Should be empty or -
                exp = int(parts[1])
            else:
                # "x", "-x"
                val = term.replace("x", "")
                if val == "-": coeff = -1
                elif val == "": coeff = 1
                else: coeff = int(val) # rare "2x" without *
                exp = 1
        else:
            # Constant
            coeff = int(term)
            exp = 0
            
        if exp < N:
            coeffs[exp] += coeff
            
    return coeffs

def solve():
    print("Reading output.txt...")
    with open(r'c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\challenges\broadcasting-ntru\broadcasting-ntru\output.txt', 'r') as f:
        data = f.read()
    
    # Extract keys and cts
    # public keys: [ ... ]
    # ciphertexts: [ ... ]
    
    try:
        pk_block = data.split("public keys:")[1].split("ciphertexts:")[0].strip()
        ct_block = data.split("ciphertexts:")[1].split("encrypted flag:")[0].strip()
        enc_flag = data.split("encrypted flag:")[1].strip()
    except:
        print("Error parsing blocks")
        return

    # Parse lists
    # Remove brackets
    pk_str = pk_block[1:-1]
    ct_str = ct_block[1:-1]
    
    # Split by ", "
    # Note: Regex parsing above handles coeffs. We can assume polynomials are separated by ", "
    # Note: Polynomials don't contain ", "? 
    # Yes, standard sage output uses ", " as separator.
    
    pks = pk_str.split(", ")
    cts = ct_str.split(", ")
    
    print(f"Parsing {len(pks)} samples...")
    
    samples = []
    
    # Invert
    # Can invert in parallel? No need.
    valid_count = 0
    
    samples_limit = 400
    print(f"Using limit of {samples_limit} samples with Multiprocessing.")
    
    # Prepare data for pool
    loop_limit = min(len(pks), samples_limit)
    pool_inputs = list(zip(pks[:loop_limit], cts[:loop_limit]))
    
    from multiprocessing import Pool
    
    with Pool() as pool:
        results = pool.map(process_sample, pool_inputs)
        
    for res in results:
        if res is not None:
            samples.append(res)
            
    print(f"Total valid samples: {len(samples)}")
    
    num_samples = len(samples)
    
    # Maintain current residuals
    # res = b - a*m = b (initially)
    # stored as list of coeffs in [0, q) for easy indexing
    residuals = []
    for a, b in samples:
        res = [(val % q) for val in b]
        residuals.append(res)
    
    # Precompute a in [0, q)
    a_list = []
    for a, b in samples:
        a_list.append([(val % q) for val in a])

    # Correlation Attack Initialization
    print("Computing correlations...")
    m = [0] * N
    
    # Precompute centered residuals and a
    def center(x):
        return x if x <= q//2 else x - q
        
    scores = [0] * N
    
    for i in range(len(samples)):
        b_coeffs = [center(x) for x in residuals[i]]
        a_coeffs = [center(x) for x in a_list[i]]
        
        for j in range(N):
            s = 0
            for k in range(N):
                idx = k - j
                if idx < 0: idx += N
                s += b_coeffs[k] * a_coeffs[idx]
            scores[j] += s
            
    avg_score = sum(scores) / N
    print(f"Avg Correlation: {avg_score}")
    
    cnt = 0
    for j in range(N):
        if scores[j] > avg_score: 
             m[j] = 1
             cnt += 1
    print(f"Initialized m with {cnt} ones based on correlation.")
    
    # Update residuals based on this initialization
    for i in range(len(residuals)):
        ai = a_list[i]
        curr = residuals[i]
        for j in range(N):
            if m[j] == 1:
                # subtract col j
                # col j is a shifted by j
                # so subtract a[(k-j)%N]
                for k in range(N):
                    idx = k - j
                    if idx < 0: idx += N
                    curr[k] = (curr[k] - ai[idx]) % q
        residuals[i] = curr

    
    for step in range(10):
        print(f"Pass {step+1}...")
        flipped = 0
        
        perm = list(range(N))
        random.shuffle(perm)
        
        for j in perm:
            # Current bit m[j]
            # Try flip
            delta = 1 if m[j] == 0 else -1
            
            # Change in total score?
            score_change = 0
            
            # Only iterate if we think it's useful
            # We must iterate all samples to be correct
            
            # Inner loop manually optimized
            for i in range(num_samples):
                res = residuals[i]
                ai = a_list[i]
                
                # Check all N coeffs of result
                # res_k' = res_k - delta * ai[k-j]
                
                for k in range(N):
                    # shift index
                    idx = k - j
                    if idx < 0: idx += N
                    
                    sub = (delta * ai[idx]) 
                    # If delta is 1 (0->1): sub = ai => res - ai
                    # If delta is -1 (1->0): sub = -ai => res + ai
                    
                    old_v = res[k]
                    # Calc old cost
                    # Distance to 0
                    d0 = old_v if old_v < 1024 else 2048 - old_v
                    # Distance to 1
                    dist1 = old_v - 1
                    d1 = dist1 if dist1 >= 0 else -dist1 # abs
                    # Correct for circle
                    if d1 > 1024: d1 = 2048 - d1 # approx logic correct for large q?
                    # Precise: min(|x-1|, q-|x-1|)
                    t1 = (old_v - 1) % q
                    d1 = t1 if t1 < 1024 else 2048 - t1
                    
                    cost_old = d0 if d0 < d1 else d1
                    
                    # New val
                    new_v = (old_v - sub) % q # change is SUBTRACTING delta*a
                    
                    d0 = new_v if new_v < 1024 else 2048 - new_v
                    t1 = (new_v - 1) % q
                    d1 = t1 if t1 < 1024 else 2048 - t1
                    
                    cost_new = d0 if d0 < d1 else d1
                    
                    score_change += (cost_new - cost_old)
            
            if score_change < 0:
                # Apply
                m[j] = 1 - m[j]
                flipped += 1
                
                # Update residuals
                for i in range(num_samples):
                    res = residuals[i]
                    ai = a_list[i]
                    for k in range(N):
                        idx = k - j
                        if idx < 0: idx += N
                        sub = (delta * ai[idx])
                        res[k] = (res[k] - sub) % q
                        
        print(f"Flipped {flipped} bits.")
        if flipped == 0: break
        
    # Calculate final cost
    final_cost = 0
    for res in residuals:
        for val in res:
            d0 = val if val < 1024 else 2048 - val
            t1 = (val - 1) % 2048
            d1 = t1 if t1 < 1024 else 2048 - t1
            final_cost += min(d0, d1)
    print(f"Final Total Cost: {final_cost} (Average per eqn: {final_cost / (len(residuals)*N)})")
    
    print("Recovered Message:", m)
    with open("recovered_m.txt", "w") as f:
        f.write(str(m))
    
    # Reconstruct m poly string for sha256
    # CHALLENGE format: str(msg)
    # Sage str(poly) format: "x^508 + x^2 + 1" etc.
    # coeffs are 0 or 1.
    # Terms decreasing degree.
    
    terms = []
    for i in range(N-1, -1, -1):
        if m[i] == 1:
            if i == 0: terms.append("1")
            elif i == 1: terms.append("x")
            else: terms.append(f"x^{i}")
            
    msg_str = " + ".join(terms)
    if not msg_str: msg_str = "0"
    
    print("Msg Str:", msg_str)
    
    key = sha256(msg_str.encode()).digest()[:16]
    
    # Decrypt
    ct_bytes = bytes.fromhex(enc_flag) # nonce(8) + ct
    nonce = ct_bytes[:8]
    ciphertext = ct_bytes[8:]
    
    cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce) # nonce for PyCryptodome CTR
    # Actually PyCryptodome AES CTR takes 'nonce' (usually 8 bytes for 64-bit counter)
    # The challenge uses AES.new(key=key, mode=AES.MODE_CTR) which defaults to generating a random nonce.
    # It prints (cipher.nonce + enc_flag).
    # So the first 8 bytes IS the nonce.
    
    try:
        flag = cipher.decrypt(ciphertext)
        print("Flag:", flag)
    except:
        print("Decryption error")

if __name__ == "__main__":
    solve()
