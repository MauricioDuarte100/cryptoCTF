
import socket
import base64
import gzip
import ast
import math
import sys

# -----------------
# Configuration
# -----------------
HOST = 'archive.cryptohack.org'
PORT = 43607
Q = 8380417
K = 8
L = 7

# -----------------
# Networking & IO
# -----------------
def recv_until(s, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    return data

def get_challenge_data(s):
    # Depending on the server output format, we might need to be more robust
    # The server prints: 
    # sanitize_mat(A) = '...'
    # sanitize_vec(t) = '...'
    # MLWE (1) or not (0) ?
    
    # We read until the prompt
    data = recv_until(s, b"> ")
    text = data.decode()
    
    # Extract A
    start_A = text.find("sanitize_mat(A) = '") + len("sanitize_mat(A) = '")
    end_A = text.find("'", start_A)
    A_b64 = text[start_A:end_A]
    
    # Extract t
    start_t = text.find("sanitize_vec(t) = '") + len("sanitize_vec(t) = '")
    end_t = text.find("'", start_t)
    t_b64 = text[start_t:end_t]
    
    return A_b64, t_b64, text

def send_answer(s, ans):
    s.sendall(str(ans).encode() + b"\n")

# -----------------
# Data Decoding
# -----------------
def decode_data(b64_str):
    # "b64encode(gzip.compress(A)).decode()"
    # Reverse it
    try:
        compressed = base64.b64decode(b64_str)
        decompressed = gzip.decompress(compressed)
        # It's a string representation of a list of lists (A) or list of lists (t coeffs)
        # However, the server code says:
        # A = str(A).replace(" ", "") -> A is a list of lists of lists (since matrix entries are polys = list of ints)
        # s = literal_eval(s.decode())
        obj = ast.literal_eval(decompressed.decode())
        return obj
    except Exception as e:
        print(f"Error decoding: {e}")
        return None

# -----------------
# Math & LLL
# -----------------
def create_matrix(rows, cols):
    return [[0] * cols for _ in range(rows)]

def dot_product(v1, v2):
    return sum(x*y for x, y in zip(v1, v2))

def vector_add(v1, v2):
    return [x+y for x, y in zip(v1, v2)]

def vector_sub(v1, v2):
    return [x-y for x, y in zip(v1, v2)]

def vector_scale(v, scalar):
    return [x*scalar for x in v]

def deep_copy_matrix(M):
    return [row[:] for row in M]

def lll_reduction(basis, delta=0.99):
    """
    Pure Python LLL reduction.
    basis: list of lists (row vectors)
    returns: reduced basis
    """
    n = len(basis)
    m = len(basis[0]) # dimension of vectors
    
    # We work with copies
    b = deep_copy_matrix(basis)
    
    # Gram-Schmidt
    # mu[i][j] = <b_i, b_j*> / <b_j*, b_j*>
    # B[i] = |b_i*|^2
    mu = create_matrix(n, n)
    B = [0.0] * n
    b_star = create_matrix(n, m) # Orthogonalized vectors
    
    def update_gsm(k):
        b_star[k] = b[k][:]
        for j in range(k):
            # mu_{k,j} = <b_k, b_j*> / B_j
            # But simpler to project: b_star[k] = b[k] - sum(mu_{k,j} * b_star[j])
             
            # Standard GS update
            # Using computed b_star[j]
            dot_val = dot_product(b[k], b_star[j])
            mu[k][j] = dot_val / B[j]
            b_star[k] = vector_sub(b_star[k], vector_scale(b_star[j], mu[k][j]))
            
        B[k] = dot_product(b_star[k], b_star[k])

    # Initial GS
    for i in range(n):
        update_gsm(i)
        
    k = 1
    while k < n:
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q_coeff = round(mu[k][j])
                b[k] = vector_sub(b[k], vector_scale(b[j], q_coeff))
                # Update GS for k
                # Optimization: only necessary to update mu[k][...] but here we are lazy/safe
                # Actually, full GS update is expensive.
                # In standard LLL, we only update specific mu values or recompute.
                # Let's recompute row k's GS to be safe and simple
                update_gsm(k)
        
        # Lovasz condition check
        # B[k] >= (delta - mu[k][k-1]^2) * B[k-1]
        
        if B[k] >= (delta - mu[k][k-1]**2) * B[k-1]:
            k += 1
        else:
            # Swap b[k] and b[k-1]
            b[k], b[k-1] = b[k-1], b[k]
            
            # Recompute GS for k-1 and k? 
            # If we swap k, k-1, we invalidate GS for k-1 and onwards.
            # But only k-1 and k change local relations. k+1... don't change b_star?
            # Actually b_star[k-1] changes so all future mu[i][k-1] change.
            # Simplest for this dimension: recompute GS from k-1
            
            # A bit optimized:
            update_gsm(k-1)
            update_gsm(k)
            # Actually we need to update everything after k?
            # No, standard LLL text says we need to update structure.
            # For n=16, recomputing from k-1 to end or just k-1, k is fine?
            # Swapping k, k-1 affects b_star[k-1] (new) and b_star[k] (new).
            # b_star[i] for i > k depends on b_star[k-1] and b_star[k]. So they change too.
            # So we strictly need to recompute GS from k-1 to n-1.
            # Given n=16, this is cheap.
            for i in range(k-1, n):
                update_gsm(i)
                
            k = max(k - 1, 1)
            
    return b

# -----------------
# Solver Logic
# -----------------
def eval_poly(poly_list):
    # Evaluate at x=1
    return sum(poly_list)

def solve_instance(A_raw, t_raw):
    # A_raw is list of list of polys (coeffs)
    # A_ij is a poly
    
    # Map to integers mod Q
    # We want to solve t = A*s + e (mod Q)
    # Dimensions: 
    # A is K x L matrix of polys
    # t is K vector of polys
    
    # Convert A to integer matrix A_int (K x L)
    A_int = []
    for row in A_raw:
        new_row = [eval_poly(poly) % Q for poly in row]
        A_int.append(new_row)
        
    # Convert t to integer vector t_int (length K)
    t_int = [eval_poly(poly) % Q for poly in t_raw]
    
    # Construct Embedding Lattice
    # We want to find small (s, e, 1) such that [A | -I] * (s, e)^T = t ?
    # Standard embedding for LWE:
    # Lattice basis B:
    # [ Q*I_K   0      0 ]
    # [ A_int^T I_L    0 ]  <-- Transpose?
    # Wait.
    # A * s = t - e  (mod Q)
    # (col 1)*s1 + ... + (col L)*sL + e = t (mod Q)
    # So t is a linear combo of cols of A plus a small error e.
    # Lattice generated by Columns of A mod Q?
    # Primal lattice: L = { y | y = A*s mod Q }
    # Since we have error, we use embedding.
    # Basis:
    # Rows are basis vectors.
    # We want specific target t.
    # Kannan's embedding:
    # [ Matrix for L    0 ]
    # [ target          1 ]
    
    # Primal Basis for LWE (A s + e = t):
    # We want to represent t as A*s mod Q + small error.
    # Lattice construction:
    # (A*s mod Q, s) -> vector of length K+L.
    # If we find close vector to (t, 0), the difference is (e, -s).
    # Small vector in lattice L' generated by:
    # [ Q*I_K     0 ]
    # [ A_int^T   I_L ]
    # Rows are ( col_j(A),  e_j )
    #
    # Wait, A_int is KxL. A_int^T is LxK.
    # Row 0..K-1: ( Q*e_i, 0 ) -> (0..Q..0, 0..0)
    # Row K..K+L-1: ( Col_j(A), e_j ) -> (A[0][j], A[1][j]... A[K-1][j], 0..1..0 )
    #
    # This lattice contains vectors (v, s) where v = A*s mod Q.
    # We are given t.
    # We want v roughly equal to t.
    # So (v, s) is close to (t, 0).
    # We add (t, 0, M) to the basis to reduce.
    #
    # Final Basis (rows):
    # [ Q*I_K      0     0 ]
    # [ A_int^T    I_L   0 ]
    # [ -t_int     0     M ]
    #
    # If MLWE: t = A s + e. 
    # row_last + sum(s_j * row_j_of_A) + appropriate Q rows
    # = ( -t + A*s, s, M )
    # = ( -e, s, M )
    # This vector is SHORT.
    #
    # If Uniform: t is random.
    # We likely won't find such a short vector.
    
    # Scaling factor M. usually 1 is fine since s, e are small?
    # e approx 16*3, s approx 16*3. M=1 is OK. 
    # Q is 8*10^6.
    M = 1
    
    dim = K + L + 1
    # Initialize zero matrix
    B = create_matrix(dim, dim)
    
    # Fill Q*I_K
    for i in range(K):
        B[i][i] = Q
        
    # Fill A^T and I_L
    for j in range(L):
        # Row K+j
        # First K cols are A column j
        for i in range(K):
            B[K+j][i] = A_int[i][j]
        # Next L cols are I_L
        B[K+j][K+j] = 1
        
    # Fill -t and M
    for i in range(K):
        B[K+L][i] = (Q - t_int[i]) % Q # -t mod Q
        # better to put -t_int directly if we use standard math? 
        # Modulo arithmetic handles it in the lattice via Q*I_K rows.
        # But for initial vector, we put -t.
        # Wait, if we put -t, we rely on Q rows to bring it to correct range? Yes.
        # Using (Q - t) % Q is effectively -t mod Q.
    
    B[K+L][K+L] = M
    
    # Reduce
    reduced_B = lll_reduction(B)
    
    # Check for short vectors
    # We look for a row with small norm.
    # Expected norm if MLWE:
    # ||(-e, s, M)||
    # e_coeff sum of ~256 terms uniform(-2, 2). Var = 256 * (16/12 * 4)? 
    # Uniform(-2,2) is {-2,-1,0,1,2}. Variance of discrete?
    # p=1/5 for each. E[X]=0. E[X^2] = (4+1+0+1+4)/5 = 2.
    # Sum of 256 such vars -> Var = 256*2 = 512. StdDev = 22.
    # So e_i(1) is roughly 22.
    # s_i(1) is roughly 22.
    # Norm squared = K * (22^2) + L * (22^2) + M^2
    # = (8+7) * 484 + 1 ~= 15 * 500 = 7500.
    # Length ~= 86.
    
    # If random:
    # Determinant of lattice (without M row) is Q^K.
    # Dimension 15.
    # Gaussian heuristic approx det^(1/dim) * sqrt(dim).
    # (Q^8)^(1/15) = Q^(8/15) ~= (2^23)^(0.53) ~= 2^12.
    # Random vector length ~ 4000.
    #
    # 86 vs 4000. VERY CLEAR distinction.
    
    min_norm_sq = float('inf')
    for row in reduced_B:
        # We only care about vectors that used the last row (M component is non-zero)
        # Or just generally any short vector?
        # If we successfully reduce, the shortest vector should be the one we want or close.
        # The M component helps us track if we included t.
        # If M component is +/- M, it's a candidate.
        # If M component is 0, it's a vector in the lattice of A (A*s - e = 0), i.e. small solution to homogeneous? Unlikely to be smaller than e.
        
        # ACTUALLY, checking any small vector is risky if there are short vectors in A's lattice.
        # But A is random, so shortest vector in A's lattice should be around Gaussian heuristic (large).
        # So generally, just check the norm of the shortest vector.
        
        n_sq = sum(x*x for x in row)
        if n_sq < min_norm_sq and n_sq > 0:
            min_norm_sq = n_sq
            
    # Threshold?
    # 86^2 = 7500.
    # 4000^2 = 16,000,000.
    # Threshold ~ 100,000 is extremely safe.
    
    if min_norm_sq < 200000:
        return 1
    return 0

# -----------------
# Main Loop
# -----------------
if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Initial greeting
    print(s.recv(1024).decode())
    
    rounds = 130
    try:
        for i in range(rounds):
            print(f"Round {i+1}/{rounds}")
            data_tup = get_challenge_data(s)
            if not data_tup:
                print("Failed to get data")
                break
                
            A_b64, t_b64, full_text = data_tup
            
            # Check for flag in text just in case
            if "BZHCTF" in full_text or "crypto{" in full_text:
                print("FLAG FOUND IN OUTPUT:", full_text)
                break
                
            A_raw = decode_data(A_b64)
            t_raw = decode_data(t_b64)
            
            if A_raw is None or t_raw is None:
                print("Decode error, guessing 0")
                send_answer(s, 0)
                continue
                
            ans = solve_instance(A_raw, t_raw)
            # print(f"Answer: {ans}")
            send_answer(s, ans)
            
            # Read immediate result "wp, x/128"
            padding = s.recv(1024).decode()
            if "flag" in padding or "BZHCTF" in padding:
                print(padding)
                break
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()
