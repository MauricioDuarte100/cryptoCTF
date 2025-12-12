#!/usr/bin/env python3
"""
Solver for u-turn challenge using sympy's LLL implementation.
"""

import ast
import os
from sympy import Matrix, Integer

# Challenge parameters
K, L = 48, 50
N = 256  # modulus

def load_matrix():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    a_path = os.path.join(script_dir, "..", "challenges", "uturn", "u-turn", "A.txt")
    with open(a_path, "r") as f:
        return ast.literal_eval(f.read())

TARGET_HEX = "fdac962720ab6e0c60ddbdf06d05112e315b86294e6bef26a695d851bb898b025dd3f6a65620cb4b509292cb64d0aa88"
TARGET = bytes.fromhex(TARGET_HEX)

def build_lattice(A, h):
    """Build the embedding lattice for LLL."""
    h_list = list(h)
    dim = K + L + 1
    M_weight = 1
    
    # Build lattice basis as a list of lists
    basis = []
    
    # First K rows: N*I_K
    for i in range(K):
        row = [0] * dim
        row[i] = N
        basis.append(row)
    
    # Next L rows: A^T in first K cols, I_L in next L cols
    for j in range(L):
        row = [0] * dim
        for i in range(K):
            row[i] = A[i][j]
        row[K + j] = 1
        basis.append(row)
    
    # Last row: -h and M_weight
    row = [0] * dim
    for i in range(K):
        row[i] = (N - h_list[i]) % N
    row[K + L] = M_weight
    basis.append(row)
    
    return basis

def verify_solution(A, x, h):
    """Check if A*x ≡ h (mod 256)."""
    result = [0] * K
    for i in range(K):
        for j in range(L):
            result[i] = (result[i] + A[i][j] * x[j]) % N
    return result == list(h)

def reverse_sanitize(x):
    """Reverse the sanitize operation."""
    # Quinary to integer
    a = sum((xi + 2) * (5 ** i) for i, xi in enumerate(x))
    
    # Integer to bytes (little-endian)
    xored_bytes = []
    for _ in range(16):
        xored_bytes.append(a % 256)
        a //= 256
    
    # XOR with padding
    flag_bytes = bytes([b ^ 0x10 for b in xored_bytes])
    return flag_bytes

def main():
    print("Loading matrix A...")
    A = load_matrix()
    
    print("Target hash:", TARGET_HEX[:40] + "...")
    
    print("\nBuilding lattice (dim 99x99)...")
    basis = build_lattice(A, TARGET)
    
    print("Converting to sympy Matrix...")
    B = Matrix(basis)
    
    print("Running LLL (this may take a few minutes)...")
    try:
        B_reduced = B.LLL()
        print("LLL completed!")
    except Exception as e:
        print(f"LLL failed: {e}")
        return
    
    print("\nSearching for valid solution in reduced basis...")
    M_weight = 1
    
    for row_idx in range(B_reduced.rows):
        row = [int(B_reduced[row_idx, col]) for col in range(B_reduced.cols)]
        
        if row[-1] in [M_weight, -M_weight]:
            x = row[K:K+L]
            if row[-1] == -M_weight:
                x = [-xi for xi in x]
            
            if all(-2 <= xi <= 2 for xi in x):
                if verify_solution(A, x, TARGET):
                    print(f"\nFound solution!")
                    print(f"x = {x}")
                    
                    flag_bytes = reverse_sanitize(x)
                    print(f"Flag bytes: {flag_bytes}")
                    print(f"Flag hex: {flag_bytes.hex()}")
                    
                    try:
                        flag_str = flag_bytes.decode('ascii')
                        if all(c in '0123456789abcdef' for c in flag_str):
                            print(f"\nFLAG: BZHCTF{{{flag_str}}}")
                        else:
                            print(f"Decoded: {repr(flag_str)}")
                    except:
                        print(f"Could not decode as ASCII")
                    return
    
    # Also check for short vectors without the M component condition
    print("\nChecking all short vectors...")
    for row_idx in range(min(20, B_reduced.rows)):  # Check first 20 rows
        row = [int(B_reduced[row_idx, col]) for col in range(B_reduced.cols)]
        x = row[K:K+L]
        
        if all(-2 <= xi <= 2 for xi in x) and any(xi != 0 for xi in x):
            if verify_solution(A, x, TARGET):
                print(f"\nFound solution in row {row_idx}!")
                print(f"x = {x}")
                
                flag_bytes = reverse_sanitize(x)
                print(f"Flag bytes: {flag_bytes}")
                
                try:
                    flag_str = flag_bytes.decode('ascii')
                    print(f"\nFLAG: BZHCTF{{{flag_str}}}")
                except:
                    print(f"Flag hex: {flag_bytes.hex()}")
                return
    
    print("\nNo valid solution found in reduced basis")

if __name__ == "__main__":
    main()
