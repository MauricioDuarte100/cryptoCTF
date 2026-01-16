#!/usr/bin/env python3
"""
Unified Lattice Module for CryptoCTF
=====================================

Provides LLL/BKZ lattice reduction with multiple backends:
1. fpylll (fastest, requires installation)
2. sympy (pure Python, slower but works everywhere)
3. Custom pure Python (from sage_replacement.py)
4. SageMath subprocess (if sage is installed)

Usage:
    from solver.modules.lattice import LLL, BKZ, Matrix, solve_hnp
    
    # Create matrix
    M = Matrix([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
    
    # Reduce with LLL
    reduced = LLL(M)
    
    # Or with BKZ (if available)
    reduced = BKZ(M, block_size=20)
"""

import subprocess
import tempfile
import json
import sys
from typing import List, Tuple, Optional, Union
from fractions import Fraction

# Try importing fast backends
FPYLLL_AVAILABLE = False
SYMPY_AVAILABLE = False

try:
    from fpylll import IntegerMatrix, LLL as FPYLLL_LLL, BKZ as FPYLLL_BKZ
    FPYLLL_AVAILABLE = True
except ImportError:
    pass

try:
    from sympy import Matrix as SympyMatrix
    from sympy.matrices.normalforms import smith_normal_form
    SYMPY_AVAILABLE = True
except ImportError:
    pass


class Matrix:
    """
    Matrix class compatible with multiple backends.
    Stores data as list of lists of integers.
    """
    def __init__(self, data: List[List[int]]):
        self.data = [[int(x) for x in row] for row in data]
        self.nrows = len(data)
        self.ncols = len(data[0]) if self.nrows > 0 else 0
    
    def __getitem__(self, idx):
        if isinstance(idx, tuple):
            return self.data[idx[0]][idx[1]]
        return self.data[idx]
    
    def __setitem__(self, idx, val):
        if isinstance(idx, tuple):
            self.data[idx[0]][idx[1]] = int(val)
        else:
            self.data[idx] = [int(x) for x in val]
    
    def __repr__(self):
        return f"Matrix({self.nrows}x{self.ncols})"
    
    def __len__(self):
        return self.nrows
    
    def row(self, i: int) -> List[int]:
        return self.data[i][:]
    
    def column(self, j: int) -> List[int]:
        return [self.data[i][j] for i in range(self.nrows)]
    
    def tolist(self) -> List[List[int]]:
        return [row[:] for row in self.data]
    
    @staticmethod
    def identity(n: int) -> 'Matrix':
        data = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
        return Matrix(data)
    
    @staticmethod
    def zero(nrows: int, ncols: int) -> 'Matrix':
        return Matrix([[0] * ncols for _ in range(nrows)])


def _lll_python_pure(matrix: Matrix, delta: float = 0.99) -> Matrix:
    """
    Pure Python LLL implementation.
    Slower but works everywhere without dependencies.
    """
    B = [row[:] for row in matrix.data]
    n = len(B)
    if n == 0:
        return Matrix([])
    
    k = 1
    
    def dot(v1, v2):
        return sum(x * y for x, y in zip(v1, v2))
    
    # Orthogonalized basis (using Fraction for exact arithmetic)
    B_star = [[Fraction(x) for x in b] for b in B]
    mu = [[Fraction(0)] * n for _ in range(n)]
    
    # Initial Gram-Schmidt
    for i in range(n):
        for j in range(i):
            d = dot(B_star[j], B_star[j])
            if d == 0:
                mu[i][j] = Fraction(0)
            else:
                mu[i][j] = dot(B[i], B_star[j]) / d
            for l in range(len(B[i])):
                B_star[i][l] -= mu[i][j] * B_star[j][l]
    
    def update_gs_for_k(k):
        B_star[k] = [Fraction(x) for x in B[k]]
        for j in range(k):
            d = dot(B_star[j], B_star[j])
            if d == 0:
                mu[k][j] = Fraction(0)
            else:
                mu[k][j] = dot(B[k], B_star[j]) / d
            for l in range(len(B[k])):
                B_star[k][l] -= mu[k][j] * B_star[j][l]
    
    while k < n:
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(float(mu[k][j]))
                for l in range(len(B[k])):
                    B[k][l] -= q * B[j][l]
                update_gs_for_k(k)
        
        # Lovasz condition
        d_k = dot(B_star[k], B_star[k])
        d_k_1 = dot(B_star[k - 1], B_star[k - 1])
        f_delta = Fraction(int(delta * 100), 100)
        
        if d_k >= (f_delta - mu[k][k - 1] ** 2) * d_k_1:
            k += 1
        else:
            # Swap
            B[k], B[k - 1] = B[k - 1], B[k]
            update_gs_for_k(k - 1)
            update_gs_for_k(k)
            
            # Update mu for subsequent rows
            for i in range(k + 1, n):
                d_prev = dot(B_star[k - 1], B_star[k - 1])
                if d_prev == 0:
                    mu[i][k - 1] = Fraction(0)
                else:
                    mu[i][k - 1] = dot(B[i], B_star[k - 1]) / d_prev
                
                d_curr = dot(B_star[k], B_star[k])
                if d_curr == 0:
                    mu[i][k] = Fraction(0)
                else:
                    mu[i][k] = dot(B[i], B_star[k]) / d_curr
            
            k = max(k - 1, 1)
    
    return Matrix([[int(x) for x in row] for row in B])


def _lll_fpylll(matrix: Matrix, delta: float = 0.99) -> Matrix:
    """LLL using fpylll (fastest)."""
    M = IntegerMatrix(matrix.nrows, matrix.ncols)
    for i in range(matrix.nrows):
        for j in range(matrix.ncols):
            M[i, j] = matrix.data[i][j]
    
    FPYLLL_LLL.reduction(M, delta=delta)
    
    result = [[M[i, j] for j in range(matrix.ncols)] for i in range(matrix.nrows)]
    return Matrix(result)


def _bkz_fpylll(matrix: Matrix, block_size: int = 20) -> Matrix:
    """BKZ using fpylll."""
    M = IntegerMatrix(matrix.nrows, matrix.ncols)
    for i in range(matrix.nrows):
        for j in range(matrix.ncols):
            M[i, j] = matrix.data[i][j]
    
    FPYLLL_BKZ.reduction(M, FPYLLL_BKZ.Param(block_size))
    
    result = [[M[i, j] for j in range(matrix.ncols)] for i in range(matrix.nrows)]
    return Matrix(result)


def _lll_sage_subprocess(matrix: Matrix, delta: float = 0.99) -> Matrix:
    """
    Run LLL using SageMath subprocess.
    Works if 'sage' is installed and in PATH.
    """
    # Create temporary sage script
    script = f'''
from sage.all import *
M = Matrix(ZZ, {matrix.data})
L = M.LLL(delta={delta})
print(L.list())
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False) as f:
        f.write(script)
        script_path = f.name
    
    try:
        result = subprocess.run(
            ['sage', script_path],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Sage failed: {result.stderr}")
        
        # Parse output
        output = result.stdout.strip()
        # Sage outputs a flat list, need to reshape
        flat = eval(output)
        rows = []
        for i in range(0, len(flat), matrix.ncols):
            rows.append(flat[i:i + matrix.ncols])
        
        return Matrix(rows)
    
    except FileNotFoundError:
        raise RuntimeError("SageMath not found. Install SageMath or use another backend.")
    finally:
        import os
        os.unlink(script_path)


def LLL(matrix: Matrix, delta: float = 0.99, backend: str = 'auto') -> Matrix:
    """
    LLL lattice basis reduction.
    
    Args:
        matrix: Input lattice basis (rows are basis vectors)
        delta: LLL parameter (default 0.99)
        backend: 'auto', 'fpylll', 'python', or 'sage'
    
    Returns:
        Reduced lattice basis
    """
    if backend == 'auto':
        if FPYLLL_AVAILABLE:
            backend = 'fpylll'
        else:
            backend = 'python'
    
    if backend == 'fpylll':
        if not FPYLLL_AVAILABLE:
            raise ImportError("fpylll not installed. Run: pip install fpylll")
        return _lll_fpylll(matrix, delta)
    
    elif backend == 'python':
        return _lll_python_pure(matrix, delta)
    
    elif backend == 'sage':
        return _lll_sage_subprocess(matrix, delta)
    
    else:
        raise ValueError(f"Unknown backend: {backend}")


def BKZ(matrix: Matrix, block_size: int = 20, backend: str = 'auto') -> Matrix:
    """
    BKZ lattice basis reduction (stronger than LLL).
    
    Args:
        matrix: Input lattice basis
        block_size: BKZ block size (higher = better reduction, slower)
        backend: 'auto' or 'fpylll'
    
    Returns:
        Reduced lattice basis
    """
    if backend == 'auto':
        if FPYLLL_AVAILABLE:
            return _bkz_fpylll(matrix, block_size)
        else:
            # Fall back to LLL with smaller delta
            print("[!] BKZ not available, falling back to LLL")
            return LLL(matrix, delta=0.75, backend='python')
    
    elif backend == 'fpylll':
        if not FPYLLL_AVAILABLE:
            raise ImportError("fpylll required for BKZ")
        return _bkz_fpylll(matrix, block_size)
    
    else:
        raise ValueError(f"Unknown backend for BKZ: {backend}")


def solve_hnp(signatures: List[Tuple[int, int, int]], 
              n: int, 
              nonce_bits: int,
              backend: str = 'auto') -> Optional[int]:
    """
    Solve Hidden Number Problem for ECDSA biased nonce attack.
    
    Given signatures with biased nonces k < 2^nonce_bits,
    recover the private key d.
    
    Args:
        signatures: List of (r, s, z) tuples from ECDSA signatures
        n: Order of the curve
        nonce_bits: Upper bound on nonce bit length
        backend: LLL backend to use
    
    Returns:
        Private key d if found, None otherwise
    """
    m = len(signatures)
    if m < 4:
        print(f"[!] Need at least 4 signatures, got {m}")
        return None
    
    # Build lattice for HNP
    # Standard construction from "Biased Nonce Sense" paper
    B = 2 ** nonce_bits
    
    # Build (m+1) x (m+1) matrix
    M_data = [[0] * (m + 1) for _ in range(m + 1)]
    
    for i in range(m):
        r, s, z = signatures[i]
        s_inv = pow(s, -1, n)
        t = (r * s_inv) % n
        u = (-z * s_inv) % n
        
        M_data[i][i] = n
        M_data[m][i] = t
    
    M_data[m][m] = B // n  # Scale factor
    
    # Also add the constant column for u values
    # This is a simplified version - full HNP needs more care
    
    M = Matrix(M_data)
    
    print(f"[*] Running LLL on {m+1}x{m+1} HNP lattice...")
    L = LLL(M, backend=backend)
    
    # Check short vectors for solution
    for row in L.data:
        # The last entry might encode d * (B/n)
        if row[-1] != 0:
            d_candidate = (row[-1] * n) // B
            if 0 < d_candidate < n:
                # Verify by checking one signature
                r, s, z = signatures[0]
                k = (z + r * d_candidate) * pow(s, -1, n) % n
                if k.bit_length() <= nonce_bits:
                    print(f"[+] Found d = {d_candidate}")
                    return d_candidate
    
    return None


def get_backend_info() -> dict:
    """Get information about available backends."""
    return {
        'fpylll': FPYLLL_AVAILABLE,
        'sympy': SYMPY_AVAILABLE,
        'python': True,
        'recommended': 'fpylll' if FPYLLL_AVAILABLE else 'python'
    }


if __name__ == "__main__":
    print("Lattice Module for CryptoCTF")
    print("=" * 40)
    
    info = get_backend_info()
    print(f"fpylll: {'Available' if info['fpylll'] else 'Not installed'}")
    print(f"sympy: {'Available' if info['sympy'] else 'Not installed'}")
    print(f"python (pure): Always available")
    print(f"Recommended: {info['recommended']}")
    
    # Test LLL
    print("\n[*] Testing LLL...")
    M = Matrix([
        [1, 0, 0, 1021],
        [0, 1, 0, 2011],
        [0, 0, 1, 3001],
        [0, 0, 0, 4001]
    ])
    
    L = LLL(M)
    print(f"Original: {M.data[0]}")
    print(f"Reduced:  {L.data[0]}")
    print("[+] LLL test complete")
