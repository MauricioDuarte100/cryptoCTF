from sage.all import *
from egcl_data import data, ct, nonce
from Crypto.Cipher import AES
from hashlib import sha256

# Constants
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp(data):
    """
    Attempt to solve the specialized HNP problem using lattice reduction.
    We have k_i = T_i + C_i * d + N_i * q (unreduced k_i form)
    Wait, N_i is determined by how many q's fit in k_i.
    Actually, k_i can be written as:
    k_i = A_i + B_i * d + J_i * q where A_i, B_i are computed mod q.
    J_i is roughly k_i / q.
    Constraints: 0 <= k_i < 2^311.
    LCG constraints.
    
    BUT, we have a simpler method if we assume the standard LCG-HNP structure.
    Usually we construct a lattice for CVP.
    We want to find (d, J_0, ..., J_m) such that k_i satisfy LCG?
    Or maybe we can just find 'd' such that k_i < 2^311?
    
    Lets build a lattice where rows correspond to d and q multiples.
    Lattice basis M (dim m+2 x m+1 ? or m+1 x m+1):
    Columns: we want small values T_i + C_i d + J_i q
    Row 0: (C_0, C_1, ..., C_m) * WEIGHT? No.
    The values should be compared to 2^311.
    If we scale everything down by 2^311?
    
    Lets try standard approach:
    We know k_i = a k_{i-1} + b mod p.
    This implies k_i are "somewhat" random.
    The constraint k_i < 2^311 is the ONLY constraint we have on k.
    This means we have m inequalities:
    0 <= (T_i + C_i * d) mod q + J_i * q < 2^311
    
    There are m=17 samples.
    Let's use the lattice from "Bias in ECDSA Nonces" but adapted.
    Usually we have k_i - l_i q = hash + r d.
    We rewrite as k_i - hash - r d - l_i q = 0.
    Here k_i is unknown but "small" (311 bits).
    q is 256 bits.
    So k_i is roughly 2^55 * q.
    
    We construct lattice:
    Basis vectors:
    v_d = (C_0, C_1, ..., C_m, 1/S)  (for d)
    v_q0 = (q, 0, ..., 0, 0)
    v_q1 = (0, q, ..., 0, 0)
    ...
    v_qm = (0, 0, ..., q, 0)
    v_T = (T_0, T_1, ..., T_m, 0)  (target shift)
    
    We want to find combination:
    d * v_d + \sum N_i v_qi + 1 * v_T
    = (C_0 d + N_0 q + T_0, ..., C_m d + N_m q + T_m, d/S)
    = (k_0, k_1, ..., k_m, d/S)
    
    We want k_i approx 2^310.
    So the norm of the vector is approx sqrt(m * 2^620 + (2^256/S)^2).
    
    Lattice dimension m+2.
    Determinant is q^m * (1/S)? No.
    Basis is triangular?
    M = [
        [q, 0, ... 0, 0],
        [0, q, ... 0, 0],
        ...
        [C_0, C_1, ... C_m, 1] 
    ]
    We multiply C_i row by d. Add multiples of q rows.
    We also add T vector.
    M_cvp = [
        [q, 0, ... 0],
        ...
        [0, 0, ... q],
        [C_0, ... C_m]
    ]
    Target v = [-T_0, -T_1, ... -T_m].
    
    We find CVP close to v.
    The lattice vector u = d * [C...] + \sum N * [q...]
    u approx -v + k
    u + v = k
    k is the error vector.
    We want k_i < 2^311.
    Usually CVP finds the CLOSEST lattice point.
    So it minimizes |u - (-v)| = |u+v| = |k|.
    So it finds minimal |k|.
    
    Will this work?
    Expected shortest vector in random lattice?
    Volume = q^m.
    Dim = m.
    Lambda_1 approx sqrt(m) * q.
    We are looking for vector k of norm approx sqrt(m) * 2^311.
    q = 2^256. 2^311 = 2^55 * q.
    Wait. 2^311 is MUCH LARGER than q.
    We can trivially find vectors of length q/2 (by reducing mod q) which is 2^255.
    (Simply set d=0, choose N_i such that T_i + N_i q is small).
    So the lattice contains MUCH SHORT vectors than the one we are looking for.
    The "solution" k_i are actually HUGE compared to the shortest vectors in the lattice.
    So simply minimizing norm will find k_i in range [-q/2, q/2].
    This is NOT the correct k_i because k_i must allow LCG.
    
    So WITHOUT LCG constraints, we can find MANY d's that satisfy k_i < 2^311?
    Actually if we pick d=0, we have k_i < q.
    So d=0 is a valid solution to "k_i < 2^311".
    But d is not 0.
    We need the LCG structure.
    
    So we MUST use the LCG constraint.
    Or maybe p is close to q? No 2^311 vs 2^256.
    
    Wait.
    LCG output k_i is used.
    k_i = a k_{i-1} + b mod p.
    Maybe we can use the technique for HNP with LCG.
    We have 17 relations.
    
    Let's try to verify if p is actually 2^311 (approx).
    Or maybe we can guess p? No.
    
    Wait, LCG on elliptic curves?
    No, LCG generates scalars k.
    
    Let's try to find d using the "hidden number problem" solver in Sage if applicable?
    Or implement the specific lattice.
    
    Let's assume the LCG parameters a, b are small? No.
    Let's assume we can model the LCG as a lattice.
    k_i - a k_{i-1} - b = m_i p.
    This involves p.
    We don't know p.
    
    Is it possible the challenge is flawed?
    msgs are predictable? No.
    
    Maybe I can use the fact that k_i are generated sequentially.
    Is there an attack on LCG where we know LSBs of output?
    Yes, lattice reduction.
    But here we missed the MSBs (top 55 bits).
    This is "LCG with known LSBs".
    Actually we know k_i mod q.
    This is 256 bits out of 311.
    We know 256 LSBs (if p is power of 2).
    But modulo p, "LSB" is not well defined.
    However, if p is not too far from 2^311, and we know k_i mod q (256 bits).
    Assuming k_i are uniformly distributed in [0, p).
    
    Let's try a brute force on 55 bits? No.
    
    Wait. The "intended" solution for EGCL usually involves lattice reduction.
    Maybe I can use the "orthogonal lattice" approach.
    Since we don't know a, b, p.
    This is very strange.
    
    Is it possible I can recover d from just 2 signatures if I assume k_i share MSBs?
    No, k_i are uniform in p.
    
    Let's verify if p is printed in the challenge?
    In the main code: 
    p = getPrime(0x137)
    print(f"{sigs = }")
    NO p is printed.
    
    Maybe I can guess p?
    Just iterating primes around 2^311?
    Density of primes is 1/ln(x).
    2^311 is huge. Too many primes.
    
    Let's assume there is a side channel.
    "challenges/egcl".
    Maybe the file name is a hint? "chall_4bd2cb8f...". MD5.
    
    Let's look at the signatures again.
    Maybe k is repeaded?
    If k repeats, r repeats.
    Let's check for repeated r.
    
    Also check if s is related.
    
    I will write a script to check for repeated r.
    And run a basic lattice reduction just in case d is small?
    Or k_i is small?
    
    """
    
    # Check for repeated r
    rs = [d['r'] for d in data]
    if len(rs) != len(set(rs)):
        print("[!] Found repeated r!")
        # Find which indices
        seen = {}
        for i, r in enumerate(rs):
            if r in seen:
                print(f"Indices {seen[r]} and {i} share r.")
            seen[r] = i
    else:
        print("No repeated r found.")

    # Check for small d
    pass

    Ms = []
    # Build list of (t_i, c_i)
    # k_i = t_i + c_i * d mod q
    # s * k = z + r * d
    # k = s^-1 * z + s^-1 * r * d
    for d_entry in data:
        s_inv = inverse_mod(d_entry['s'], q)
        t = (s_inv * d_entry['z']) % q
        c = (s_inv * d_entry['r']) % q
        Ms.append((t, c))

    # Lattice attack attempt ignoring LCG (just bounds)
    # This is unlikely to work due to previous reasoning (k_i large), but let's try.
    # We construct lattice to find minimal vector (d, k_0-t_0, ...) ??
    # No, we'll try to find vector close to (-t_0, ..., -t_m).
    
    # Let's try to assume a,b,p allows some relation.
    # What if we assume p is roughly q * 2^55?
    # Unlikely to help.
    
    print("Checking correlations...")
    return

if __name__ == '__main__':
    solve_hnp(data)
