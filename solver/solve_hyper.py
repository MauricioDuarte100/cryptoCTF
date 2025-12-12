#!/usr/bin/env python3
"""
Solver for Hyper - Optimized with NumPy matrix operations.
"""

from hashlib import sha256
from itertools import product
import numpy as np

MASK1 = 0x6D6AC812F52A212D5A0B9F3117801FD5
MASK2 = 0xD736F40E0DED96B603F62CBE394FEF3D
MASK3 = 0xA55746EF3955B07595ABC13B9EBEED6B
MASK4 = 0xD670201BAC7515352A273372B2A95B23


class LFSR:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = key & ((1 << n) - 1)
        self.mask = mask

    def __call__(self):
        b = self.state & 1
        self.state = (self.state >> 1) | (
            ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
        )
        return b


class Cipher:
    def __init__(self, key: int):
        self.lfsr1 = LFSR(128, key, MASK1)
        key >>= 128
        self.lfsr2 = LFSR(128, key, MASK2)
        key >>= 128
        self.lfsr3 = LFSR(128, key, MASK3)
        key >>= 128
        self.lfsr4 = LFSR(128, key, MASK4)

    def bit(self):
        x = self.lfsr1() ^ self.lfsr1() ^ self.lfsr1()
        y = self.lfsr2()
        z = self.lfsr3() ^ self.lfsr3() ^ self.lfsr3() ^ self.lfsr3()
        w = self.lfsr4() ^ self.lfsr4()
        return sha256(str((3 * x + 1 * y + 4 * z + 2 * w + 3142)).encode()).digest()[0] & 1

    def stream(self):
        while True:
            b = 0
            for i in reversed(range(8)):
                b |= self.bit() << i
            yield b

    def encrypt(self, pt: bytes):
        return bytes([x ^ y for x, y in zip(pt, self.stream())])


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in reversed(range(8)):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i+8]):
            byte |= bit << (7 - j)
        result.append(byte)
    return bytes(result)


def load_challenge_data():
    with open("challenges/hyper/output_94884786534925b5e115c1141970bffc.txt", "r") as f:
        lines = f.read().strip().split('\n')
    gift = bytes.fromhex(lines[0])
    ct = bytes.fromhex(lines[1])
    return gift, ct


def mask_to_feedback_vector(mask, n):
    """Convert mask to feedback coefficient vector."""
    return np.array([(mask >> i) & 1 for i in range(n)], dtype=np.uint8)


def compute_lfsr_transition_matrix(mask, n):
    """
    Compute LFSR transition matrix T such that s(t+1) = T @ s(t) mod 2.
    
    For Fibonacci LFSR: 
    - New bits shift right
    - MSB is feedback (XOR of masked bits)
    """
    T = np.zeros((n, n), dtype=np.uint8)
    
    # Shift: s_i(t+1) = s_{i+1}(t) for i = 0..n-2
    for i in range(n - 1):
        T[i, i + 1] = 1
    
    # Feedback: s_{n-1}(t+1) = XOR of masked bits
    for i in range(n):
        if (mask >> i) & 1:
            T[n - 1, i] = 1
    
    return T


def compute_output_coeffs_fast(mask, n, num_outputs, stride=1):
    """
    Fast computation of LFSR output coefficients using matrix powers.
    
    Output at step t: o(t) = e_0 @ T^t @ s(0) = e_0 @ T^t
    where e_0 = [1, 0, 0, ..., 0] (select LSB).
    
    Returns matrix C where C[i] = coefficients for output at step i*stride.
    """
    T = compute_lfsr_transition_matrix(mask, n)
    
    # We need T^0, T^stride, T^{2*stride}, ...
    # Use binary exponentiation for efficiency
    
    coeffs = []
    e0 = np.zeros(n, dtype=np.uint8)
    e0[0] = 1
    
    # Current power of T
    T_pow = np.eye(n, dtype=np.uint8)  # T^0
    T_stride = np.linalg.matrix_power(T, stride).astype(np.uint8) % 2  # For modular mult
    
    # Actually, matrix power in GF(2) needs special handling
    def gf2_matrix_mult(A, B):
        return (A @ B) % 2
    
    def gf2_matrix_power(M, k):
        n = M.shape[0]
        result = np.eye(n, dtype=np.uint8)
        base = M.copy()
        while k > 0:
            if k & 1:
                result = gf2_matrix_mult(result, base)
            base = gf2_matrix_mult(base, base)
            k >>= 1
        return result
    
    T_stride = gf2_matrix_power(T, stride)
    T_pow = np.eye(n, dtype=np.uint8)
    
    for i in range(num_outputs):
        # Output coefficient = e_0 @ T_pow = first row of T_pow
        coeffs.append(T_pow[0].copy())
        # Update: T_pow = T_pow @ T_stride
        T_pow = gf2_matrix_mult(T_pow, T_stride)
    
    return np.array(coeffs, dtype=np.uint8)


def compute_y_coeffs(num_bits):
    """LFSR2 outputs, one per keystream bit."""
    print("  Computing y coefficients...")
    return compute_output_coeffs_fast(MASK2, 128, num_bits, stride=1)


def compute_z_coeffs(num_bits):
    """
    LFSR3 z values: z[i] = XOR of 4 consecutive outputs.
    
    z[i] = o[4i] XOR o[4i+1] XOR o[4i+2] XOR o[4i+3]
         = (e_0 @ T^{4i}) XOR (e_0 @ T^{4i+1}) XOR (e_0 @ T^{4i+2}) XOR (e_0 @ T^{4i+3})
         = e_0 @ T^{4i} @ (I + T + T^2 + T^3)
    
    Let S = I + T + T^2 + T^3 (in GF(2))
    Then z[i] = e_0 @ T^{4i} @ S = (T^{4i})^T @ e_0^T @ S = ...
    
    Actually easier: z_coef[i] = sum of o_coef[4i:4i+4]
    """
    print("  Computing z coefficients...")
    n = 128
    T = compute_lfsr_transition_matrix(MASK3, n)
    
    def gf2_matmul(A, B):
        return (A @ B) % 2
    
    def gf2_matpow(M, k):
        n = M.shape[0]
        result = np.eye(n, dtype=np.uint8)
        base = M.copy()
        while k > 0:
            if k & 1:
                result = gf2_matmul(result, base)
            base = gf2_matmul(base, base)
            k >>= 1
        return result
    
    # Compute S = I + T + T^2 + T^3
    I = np.eye(n, dtype=np.uint8)
    T2 = gf2_matmul(T, T)
    T3 = gf2_matmul(T2, T)
    S = (I + T + T2 + T3) % 2
    
    # For z[i], coefficient = e_0 @ T^{4i} @ S
    # But e_0 @ M = M[0] (first row)
    # So coef = (T^{4i} @ S)[0]
    
    T4 = gf2_matpow(T, 4)
    current = np.eye(n, dtype=np.uint8)  # T^0
    
    z_coeffs = []
    for i in range(num_bits):
        # (current @ S)[0] = coefficient vector
        temp = gf2_matmul(current, S)
        z_coeffs.append(temp[0].copy())
        # Update: current = current @ T4
        current = gf2_matmul(current, T4)
    
    return np.array(z_coeffs, dtype=np.uint8)


def attack_single_lfsr(ks, coefs):
    """
    Attack single LFSR using correlation with keystream.
    Uses Walsh-like correlation.
    """
    n = coefs.shape[1]
    
    # Convert to +1/-1
    ks_signed = 2 * ks.astype(np.float64) - 1
    coefs_signed = 2 * coefs.astype(np.float64) - 1
    
    # Correlations
    votes = coefs_signed.T @ ks_signed
    
    # Estimate
    s = (votes < 0).astype(np.uint8)
    
    # Verify
    output = (coefs @ s) % 2
    matches = np.sum(output == ks)
    
    return s, matches, votes


def iterative_decode(ks, y_coefs, z_coefs, num_iters=50):
    """
    Iteratively decode s2 and s3.
    
    1. Estimate s2, s3 using individual correlations
    2. Fix s2, refine s3 estimate
    3. Fix s3, refine s2 estimate
    4. Repeat
    """
    n = 128
    num_bits = len(ks)
    
    # Initial estimates
    print("Initial single-LFSR attacks...")
    s2, m2, v2 = attack_single_lfsr(ks, y_coefs)
    s3, m3, v3 = attack_single_lfsr(ks, z_coefs)
    
    print(f"  s2 estimate: {m2}/{num_bits} matches ({m2/num_bits*100:.1f}%)")
    print(f"  s3 estimate: {m3}/{num_bits} matches ({m3/num_bits*100:.1f}%)")
    
    y = (y_coefs @ s2) % 2
    z = (z_coefs @ s3) % 2
    yz = y ^ z
    yz_matches = np.sum(yz == ks)
    print(f"  Combined (y^z): {yz_matches}/{num_bits} matches ({yz_matches/num_bits*100:.1f}%)")
    
    best_match = yz_matches
    best_s2, best_s3 = s2.copy(), s3.copy()
    
    for it in range(num_iters):
        # Given s3 (fixed), estimate s2
        z = (z_coefs @ s3) % 2
        target_y = ks ^ z  # y should make y^z = ks
        
        # Use correlation to estimate s2
        target_signed = 2 * target_y.astype(np.float64) - 1
        y_coefs_signed = 2 * y_coefs.astype(np.float64) - 1
        votes2 = y_coefs_signed.T @ target_signed
        s2 = (votes2 < 0).astype(np.uint8)
        
        # Given s2 (fixed), estimate s3
        y = (y_coefs @ s2) % 2
        target_z = ks ^ y  # z should make y^z = ks
        
        target_signed = 2 * target_z.astype(np.float64) - 1
        z_coefs_signed = 2 * z_coefs.astype(np.float64) - 1
        votes3 = z_coefs_signed.T @ target_signed
        s3 = (votes3 < 0).astype(np.uint8)
        
        # Verify
        y = (y_coefs @ s2) % 2
        z = (z_coefs @ s3) % 2
        yz = y ^ z
        matches = np.sum(yz == ks)
        
        if matches > best_match:
            best_match = matches
            best_s2, best_s3 = s2.copy(), s3.copy()
            print(f"  Iteration {it+1}: {matches}/{num_bits} ({matches/num_bits*100:.1f}%)")
        
        if matches == num_bits:
            print(f"  Perfect solution found at iteration {it+1}!")
            break
    
    return best_s2, best_s3, best_match


def verify_and_decrypt(s2_int, s3_int, gift, ct):
    """
    Given s2 and s3, we still need s1 and s4.
    We can try to recover them from remaining constraints.
    """
    pass


def main():
    print("="*60)
    print("HYPER Challenge Solver - Optimized Approach")
    print("="*60)
    
    # Load data
    gift, ct = load_challenge_data()
    keystream_bits = bytes_to_bits(gift)
    
    # Use a reasonable number of bits
    num_bits = 8000
    print(f"\nUsing {num_bits} keystream bits")
    
    ks = np.array(keystream_bits[:num_bits], dtype=np.uint8)
    
    # Compute coefficient matrices
    print("\nComputing coefficient matrices...")
    y_coefs = compute_y_coeffs(num_bits)
    z_coefs = compute_z_coeffs(num_bits)
    print(f"y_coefs shape: {y_coefs.shape}")
    print(f"z_coefs shape: {z_coefs.shape}")
    
    # Iterative decoding
    print("\nIterative decoding...")
    s2, s3, matches = iterative_decode(ks, y_coefs, z_coefs, num_iters=100)
    
    print(f"\nFinal result: {matches}/{num_bits} matches ({matches/num_bits*100:.1f}%)")
    
    if matches > num_bits * 0.99:
        # Convert to integers
        s2_int = sum(int(b) << i for i, b in enumerate(s2))
        s3_int = sum(int(b) << i for i, b in enumerate(s3))
        
        print(f"\ns2 = 0x{s2_int:032x}")
        print(f"s3 = 0x{s3_int:032x}")
        
        # Now we need to recover s1 and s4
        # For each keystream bit, given y and z, we can narrow down (x, w)
        print("\n" + "="*60)
        print("Recovering s1 and s4...")
        
        # Compute actual y, z values
        y_vals = (y_coefs @ s2) % 2
        z_vals = (z_coefs @ s3) % 2
        
        # For each bit, find possible (x, w)
        # Build lookup table
        hash_lookup = {}
        for x, y, z, w in product([0, 1], repeat=4):
            val = 3 * x + 1 * y + 4 * z + 2 * w + 3142
            bit = sha256(str(val).encode()).digest()[0] & 1
            key = (y, z, bit)
            if key not in hash_lookup:
                hash_lookup[key] = []
            hash_lookup[key].append((x, w))
        
        # Count how many bits uniquely determine (x, w)
        unique_xw = 0
        x_determined = []
        w_determined = []
        
        for i in range(num_bits):
            key = (y_vals[i], z_vals[i], ks[i])
            if key in hash_lookup:
                opts = hash_lookup[key]
                if len(opts) == 1:
                    unique_xw += 1
                    x_determined.append((i, opts[0][0]))
                    w_determined.append((i, opts[0][1]))
        
        print(f"Bits with unique (x,w): {unique_xw}/{num_bits}")
        
        # Use determined x values to attack LFSR1
        # x[i] = lfsr1[3i] ^ lfsr1[3i+1] ^ lfsr1[3i+2]
        # Similar to z, we can compute coefficients
        
        if unique_xw > 200:
            print("\nSufficient unique x values to attack LFSR1!")


if __name__ == "__main__":
    main()
