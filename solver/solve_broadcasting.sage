import re
from hashlib import sha256
from Crypto.Cipher import AES

# Parametros del reto
N = 509
q = 2048
p = 3
d = 253

# Definir el anillo
Zx.<x> = ZZ[]

def balancedmod(f, q):
    g = list(((f[i] + q // 2) % q) - q // 2 for i in range(N))
    return Zx(g)

def convolution(f, g):
    return (f * g) % (x ^ N - 1)

def invertmodprime(f, p):
    try:
        T = Zx.change_ring(Integers(p)).quotient(x ^ N - 1)
        return Zx(lift(1 / T(f)))
    except:
        return None

def invertmodpowerof2(f, q):
    # assert q.is_power_of(2)
    h = invertmodprime(f, 2)
    if h is None: return None
    while True:
        r = balancedmod(convolution(h, f), q)
        if r == 1:
            return h
        h = balancedmod(convolution(h, 2 - r), q)

def parse_polynomials(text):
    # Parsea una lista de polinomios en formato Sage string
    # Asume formato "[poly1, poly2, ...]"
    # Elimina corchetes
    content = text.strip()[1:-1]
    # Split by comma taking care of potential commas inside (though poly string usually doesn't have commas if coeff*x^n)
    # Actually sage poly string: is like "123*x^5 + 4"
    # Assuming commas only separate list items
    polys_str = content.split(', ')
    res = []
    print(f"Parsing {len(polys_str)} polynomials...")
    for s in polys_str:
        # Sage eval es lento para muchos, mejor parseo manual si se puede
        # Pero eval es seguro en este contexto local
        try:
            res.append(sage_eval(s, locals={'x': x}))
        except:
            pass
    return res

def solve():
    print("Loading output.txt...")
    with open(r'c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\challenges\broadcasting-ntru\broadcasting-ntru\output.txt', 'r') as f:
        data = f.read()
    
    # Extraer las partes
    pk_start = data.find("public keys: ") + len("public keys: ")
    pk_end = data.find("\nciphertexts: ")
    ct_start = data.find("ciphertexts: ") + len("ciphertexts: ")
    ct_end = data.find("\nencrypted flag: ")
    if ct_end == -1: ct_end = len(data) # Handle potential missing newline at end
    
    pk_str = data[pk_start:pk_end]
    ct_str = data[ct_start:ct_end]
    
    # Simple cleanup just in case
    pk_str = pk_str.strip()
    ct_str = ct_str.strip()

    public_keys = parse_polynomials(pk_str)
    ciphertexts = parse_polynomials(ct_str)
    
    print(f"Loaded {len(public_keys)} keys and {len(ciphertexts)} ciphertexts.")
    
    # Precompute a_i and b_i
    # Formato LWE: b + a*m = r (mod q)
    # c = h*r + m  => h^-1 * c = r + h^-1 * m
    # => b = h^-1 * c, a = h^-1
    # => b - a*m = r
    # Esperamos r in {0, 1} coeffs
    
    samples = []
    print("Inverting public keys...")
    for i in range(len(public_keys)):
        h = public_keys[i]
        c = ciphertexts[i]
        
        # Check invertibility
        # We need h invertible mod (x^N-1, q)
        # q=2048. Invertible if invertible mod 2.
        h_inv = invertmodpowerof2(h, q)
        if h_inv is not None:
            a = h_inv
            b = balancedmod(convolution(h_inv, c), q)
            samples.append((a, b))
        
    print(f"Used {len(samples)} samples out of {len(public_keys)}.")
    
    # Bit-Flipping Attack
    # Recover m. m is binary.
    # Initialize m = 0
    m_coeffs = [0] * N
    
    # Compute Initial Residuals
    # Res_i = b_i - a_i * m
    # Since m=0, Res_i = b_i
    residuals = [] # List of lists of coeffs
    for a, b in samples:
        # Convert b to list of coeffs in [0, q)
        res = [(b[j] % q) for j in range(N)]
        residuals.append(res)
    
    # Precompute rotated a_i for fast updates
    # A_cols[j] = list of vectors (a_i rotated by j)
    # Actually we loop over j, so we just need a_i coeffs
    # a_i_coeffs[i] = list of coeffs of a_i
    a_coeffs = []
    for a, b in samples:
        a_coeffs.append([(a[j] % q) for j in range(N)])
        
    def get_cost(val):
        # Distance to {0, 1} mod q
        # min dist to 0, 1, q, q+1, ...
        # Since val is in [0, q)
        d0 = min(val, q - val)
        # d1: val to 1.
        # if val=0, d1=1. if val=1, d1=0. if val=q-1, d1=|q-1 - 1|? No 1 is 1.
        # val is reduced mod q.
        # distance on circle to 1.
        d1 = min(abs(val - 1), q - abs(val - 1))
        return min(d0, d1)

    def calculate_total_cost():
        total = 0
        for res in residuals:
            for x_val in res:
                total += get_cost(x_val)
        return total

    print("Starting optimization...")
    current_cost = calculate_total_cost()
    print(f"Initial Cost: {current_cost}")
    
    # Loop
    consecutive_no_change = 0
    
    # Optimization: To speed up, we can pick just *one* sample to debug? No we need all.
    # With 700 samples, loop over 509 bits.
    
    changed = True
    while changed:
        changed = False
        print(f"Pass start. Cost: {current_cost}")
        for j in range(N):
            # Try flipping bit j of m (coeff j)
            # m_new[j] = 1 - m_old[j]
            # Delta m = m_new - m_old.
            # If 0 -> 1, Delta = 1. If 1 -> 0, Delta = -1.
            delta = 1 if m_coeffs[j] == 0 else -1
            
            # Predict cost change
            # New residual coeff k for sample i:
            # res'_{i,k} = res_{i,k} - (a_i * (delta * x^j))_k
            # (a_i * x^j)_k = a_{i, k-j}
            # So res'_{i,k} = res_{i,k} - delta * a_{i, k-j}
            
            cost_diff = 0
            
            # Estimate cost diff - optimize this loop?
            # It's pure Python, might be slow.
            # But let's try.
            
            for i in range(len(samples)):
                # a_poly = a_coeffs[i]
                # res_poly = residuals[i]
                # for k in range(N):
                #     old_val = res_poly[k]
                #     sub = (delta * a_coeffs[i][(k - j) % N]) % q
                #     new_val = (old_val - sub) % q
                #     cost_diff += (get_cost(new_val) - get_cost(old_val))
                
                # Vectorized update for one sample? no easy way in pure python list
                # Just iterate
                
                # To speed up: We can assume most residuals are independent?
                # Maybe just check a subset of samples? 
                # No, we need accuracy.
                
                # Let's run full check.
                # Optimization: We only care if sum(cost_diff) < 0.
                pass 
                
            # Actually, doing this loop 500 times is too slow in Python.
            # 500 * 700 * 500 = 175M ops.
            # We need to implement this efficiently.
            # We can use Sage vectors?
            
        # Refined efficient loop using vector logic
        # But updating residuals is the heavy part.
        break # Placeholder for Logic below
        
    # Python-based fast solver
    # Since we can't easily compile C, we rely on Sage's vector operations if possible.
    # Sage vectors over ZZ/qZZ are fast.
    
    # Convert to matrices
    print("Building matrices...")
    # Matrix A: rows are samples. But actually we want flattened?
    # No, let's keep list of sample vectors.
    # samples_A[i] = vector(a_i)
    # samples_B[i] = vector(b_i)
    
    # Zq = Integers(q)
    # V = VectorSpace(Zq, N)
    
    # We maintain residual vectors R_i = B_i - m * A_i (convolution)
    # Actually convolution corresponds to cyclic shift matrix.
    # Updating m_j changes R_i by -delta * (rot(A_i, j)).
    
    # Let's perform the greedy descent.
    
    Zq = Integers(q)
    
    # Store everything as lists of integers for speed in simple loop?
    # lists are faster than calling sage element methods repeatedly?
    # actually primitive int obs are fastest.
    
    # Let's execute the greedy pass
    # Just run it. 175M ops takes ~30s in PyPy or ~1-2 min in Python.
    # It's acceptable for a CTF solver.
    pass

    # ... Actual implementation in the file ...

def solve_fast():
    # Implementation of the solver
    import sys
    
    print("Loading output.txt...")
    with open(r'c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\challenges\broadcasting-ntru\broadcasting-ntru\output.txt', 'r') as f:
        txt = f.read()
    
    pk_block = txt.split('ciphertexts:')[0].split('public keys:')[1].strip()
    ct_block = txt.split('ciphertexts:')[1].split('encrypted flag:')[0].strip()
    enc_flag = txt.split('encrypted flag:')[1].strip()
    
    # Dangerous eval, but locally fine
    # Prepare x in locals
    R = Zx
    x = R.gen()
    
    # Use sage_eval with pre-prepared list string
    # Remove brackets if needed or just eval the whole list
    public_keys = sage_eval(pk_block, locals={'x': x})
    ciphertexts = sage_eval(ct_block, locals={'x': x})
    
    print(f"Loaded {len(public_keys)} samples.")
    
    samples = []
    
    for i in range(len(public_keys)):
        h = public_keys[i]
        c = ciphertexts[i]
        h_inv = invertmodpowerof2(h, q)
        if h_inv:
            # b - am = r
            # b = h^-1 c, a = h^-1
            # We use a = h^-1 directly. 
            # Residual = b - a*m = b - (h^-1 * m)
            # Actually we want b - a*m => b - a*m. Yes.
            # a = h^-1. b = h^-1 * c.
            # Wait, equation: h^-1 c = r + h^-1 m
            # -> h^-1 c - h^-1 m = r
            # Let b = h^-1 c, a = h^-1.
            # Then b - a*m = r.
            # So subtracting a*m.
            b = balancedmod(convolution(h_inv, c), q)
            a = h_inv
            samples.append((a, b))
    
    print(f"Using {len(samples)} valid samples.")
    
    # Current m (all zeros)
    m = [0]*N
    
    # Compute initial residuals (b) and store as lists
    # Flatten residuals? No, keep structure
    current_b = []
    current_a = [] # Store rotated versions? No, just store a coeffs
    
    for a, b in samples:
        current_b.append(b.list() + [0]*(N-len(b.list())))
        current_a.append(a.list() + [0]*(N-len(a.list())))
        
    # Calculate costs
    def score_vec(v):
        # v is list
        # We want to minimize dist to {0, 1} mod q
        # For q=2048, 0 and 1 are 0, 1.
        # cost = min(x, q-x) if close to 0??
        # We want sum of distances.
        # Distance metric:
        # dist(x, 0) = min(x, 2048-x)
        # dist(x, 1) = min(|x-1|, 2048-|x-1|)
        # cost = min(dist(x,0), dist(x,1))
        # Since we expect exact 0 or 1, maybe square?
        # L1 is fine.
        s = 0
        for x in v:
            x = x % q
            d0 = x if x < 1024 else 2048 - x
            d1 = abs(x-1)
            if d1 >= 1024: d1 = 2048 - d1
            s += min(d0, d1)
        return s

    current_residuals = [list(x) for x in current_b]
    
    # Descent
    for step in range(5): # Passes
        print(f"Pass {step+1}")
        improves = 0
        
        # Determine check order (random or sequential)
        indices = list(range(N))
        shuffle(indices)
        
        for j in indices:
            # Evaluate flipping m[j]
            # If m[j] = 0, we try setting to 1 -> add -a to residual
            # If m[j] = 1, we try setting to 0 -> add +a to residual
            delta = -1 if m[j] == 0 else 1
            
            # We want to check change in global score
            diff = 0
            
            # Optimization: compute diff sample by sample
            # and break if it looks bad? No, exact greedy.
            
            # To be fast, we just compute coeffs of a shifted by j
            # shift a by j: a[k] -> a[k-j]
            
            # We can select a subset of samples to estimate gradient?
            # 700 samples is a lot. Let's try 100 random samples for estimation?
            # Or just do all.
            
            # Fast implementation using sage vectors/matrices might be better?
            # Let's stick to list here but optimize.
            
            # Global score logic:
            net_gain = 0
            
            # Pre-calculate shifted indices to avoid mod inside loop
            # idxs[k] = (k - j) % N
            
            # Actually, calculate the gain.
            for i in range(len(current_residuals)):
                # residual vector r
                r = current_residuals[i]
                # a vector a
                a = current_a[i]
                
                # We update r[k] += delta * a[(k-j)%N]
                # Compute cost change
                
                # Vectorized Cost Change Check
                for k in range(N):
                    old_val = r[k]
                    # shift = - delta * a[(k-j)%N]
                    # actually: residual = b - a*m.
                    # if m_j increases by 1: m' = m + x^j
                    # residual' = b - a*(m+x^j) = b - a*m - a*x^j
                    # change is subtracting a shifted by j.
                    # so if m[j] 0->1, subtract a_shifted
                    # if m[j] 1->0, add a_shifted
                    
                    shift_val = a[(k-j) % N]
                    if m[j] == 0: change = -shift_val
                    else: change = shift_val
                    
                    new_val = (old_val + change) % q
                    
                    # Inlined score
                    d0_old = old_val if old_val < 1024 else 2048 - old_val
                    d1_old = abs(old_val-1) # rough
                    if old_val == 0: d1_old = 1
                    elif old_val == 1: d1_old = 0
                    else: 
                        t = old_val - 1
                        if t < 0: t += 2048 # (0-1)%2048 = 2047
                        d1_old = t if t < 1024 else 2048 - t
                    
                    cost_old = d0_old if d0_old < d1_old else d1_old
                    
                    d0_new = new_val if new_val < 1024 else 2048 - new_val
                    t = new_val - 1
                    if t < 0: t += 2048
                    d1_new = t if t < 1024 else 2048 - t
                    
                    cost_new = d0_new if d0_new < d1_new else d1_new
                    
                    net_gain += (cost_new - cost_old)
            
            if net_gain < 0:
                # Accept change
                m[j] = 1 - m[j]
                improves += 1
                # Update residuals
                for i in range(len(current_residuals)):
                    r = current_residuals[i]
                    a = current_a[i]
                    for k in range(N):
                        shift_val = a[(k-j)%N]
                        change = -shift_val if m[j] == 1 else shift_val # m just flipped
                        r[k] = (r[k] + change) % q
                        
        print(f"Pass {step+1}: {improves} bits flipped.")
        if improves == 0: break
        
    print("Recovered Message:", m)
    
    # Decrypt Flag
    # msg poly to msg bytes
    # msg is Zx poly.
    # Convert coeffs to what?
    # generate_message says: list(randrange(2)...)
    # The SHA256 takes str(msg).encode()
    # So we need to reconstruct the polynomial object and str() it.
    
    m_poly = Zx(m)
    print("Message Poly:", m_poly)
    
    key = sha256(str(m_poly).encode()).digest()[:16]
    nonce_iv = bytes.fromhex(enc_flag)[:8] # AES-CTR nonce is usually 8 bytes? 
    # challenge says: (cipher.nonce + enc_flag).hex()
    # AES.new(mode=CTR) generates a nonce (default 8 bytes for PyCrypto/PyCryptodome).
    
    ct_bytes = bytes.fromhex(enc_flag)[8:]
    cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce_iv)
    try:
        flag = cipher.decrypt(ct_bytes)
        print("Flag:", flag)
    except Exception as e:
        print("Decryption failed:", e)

if __name__ == "__main__":
    solve_fast()
