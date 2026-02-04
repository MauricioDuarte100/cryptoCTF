"""
Solver for Reduced Collisions - Learn A then find kernel

Strategy:
1. The server sends (y, h) pairs where h = A @ y mod q
2. By collecting multiple (y, h) pairs, we can solve for A
3. Once A is known, use LLL to find kernel vectors
4. Return y' = y + z where z is a short kernel vector
"""

from pwn import *
import numpy as np

HOST = "flagyard.com"
PORT = 32099

q = 67
n = 8
m = 20
d = 2

context.log_level = 'error'

def parse_vector(line):
    """Parse a vector from server output."""
    # Format: [a, b, c, ...]
    return list(map(int, line.strip().strip('[]').replace(',', ' ').split()))

print(f"🔌 Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT)

# Collect (y, h) pairs to reconstruct A
# With m = 20 unknowns per row and n = 8 rows, we need enough equations
# Each (y, h) pair gives us n equations: A[i] @ y = h[i] for i in 0..n-1

# We need at least m linearly independent y vectors to solve for A
# But we can also use the structure: A is random over [0, q)

# Collect pairs
pairs = []
print(f"\n📚 Collecting (y, h) pairs to learn A...")

for i in range(25):  # Collect enough pairs
    try:
        io.recvuntil(b"y: ")
        y_line = io.recvline().decode()
        io.recvuntil(b"h: ")
        h_line = io.recvline().decode()
        
        y = parse_vector(y_line)
        h = parse_vector(h_line)
        
        pairs.append((y, h))
        
        # Send dummy response to continue
        io.recvuntil(b"y': ")
        dummy = [0] * m
        io.sendline(' '.join(map(str, dummy)))
        response = io.recvline().decode()
        
        if i % 5 == 0:
            print(f"   Collected {i+1} pairs...")
            
    except Exception as e:
        print(f"   Error at pair {i}: {e}")
        break

print(f"   Total pairs collected: {len(pairs)}")

# Now try to reconstruct A
# For each row i of A: sum(A[i][j] * y[j]) = h[i] (mod q)
# This is a system of linear equations over Z_q

# Build the system for each row of A
Y = np.array([p[0] for p in pairs], dtype=np.int64)  # num_pairs x m
H = np.array([p[1] for p in pairs], dtype=np.int64)  # num_pairs x n

print(f"\n🔍 Reconstructing matrix A...")
print(f"   Y shape: {Y.shape}")
print(f"   H shape: {H.shape}")

# For each row i: Y @ A[i]^T = H[:, i] (mod q)
# We need to solve for A[i] given Y and H[:, i]

# Use least squares approximation or Gaussian elimination over Z_q

def solve_linear_mod(Y, h, q):
    """
    Solve Y @ x = h (mod q) for x.
    Y is (num_equations x num_vars), h is (num_equations,)
    Returns x if unique solution exists.
    """
    num_eq, num_var = Y.shape
    
    # Augmented matrix
    M = np.zeros((num_eq, num_var + 1), dtype=np.int64)
    M[:, :num_var] = Y % q
    M[:, num_var] = h % q
    
    # Gaussian elimination over Z_q
    pivot_row = 0
    for col in range(num_var):
        # Find pivot
        found = False
        for row in range(pivot_row, num_eq):
            if M[row, col] % q != 0:
                # Swap rows
                M[[pivot_row, row]] = M[[row, pivot_row]]
                found = True
                break
        
        if not found:
            continue
        
        # Make pivot = 1
        pivot = int(M[pivot_row, col]) % q
        pivot_inv = pow(pivot, -1, q)
        M[pivot_row] = (M[pivot_row] * pivot_inv) % q
        
        # Eliminate other rows
        for row in range(num_eq):
            if row != pivot_row and M[row, col] != 0:
                factor = M[row, col]
                M[row] = (M[row] - factor * M[pivot_row]) % q
        
        pivot_row += 1
    
    # Back-substitute
    x = np.zeros(num_var, dtype=np.int64)
    for row in range(min(pivot_row, num_var) - 1, -1, -1):
        # Find the pivot column
        for col in range(num_var):
            if M[row, col] == 1:
                x[col] = M[row, num_var]
                for other_col in range(col + 1, num_var):
                    x[col] = (x[col] - M[row, other_col] * x[other_col]) % q
                break
    
    return x % q

# Solve for each row of A
A = np.zeros((n, m), dtype=np.int64)
for i in range(n):
    h_i = H[:, i]
    A[i] = solve_linear_mod(Y, h_i, q)

print(f"   A reconstructed!")
print(f"   A shape: {A.shape}")

# Verify reconstruction
def H_func(A, y):
    return [(sum(a_ * y_ for a_, y_ in zip(row, y)) % q) for row in A]

# Test on a collected pair
y_test, h_test = pairs[-1]
h_computed = H_func(A.tolist(), y_test)
print(f"\n🔍 Verification:")
print(f"   Expected h: {h_test}")
print(f"   Computed h: {h_computed}")
print(f"   Match: {h_test == h_computed}")

if h_test != h_computed:
    print("   ⚠️ Reconstruction failed, trying alternative method...")
else:
    print("   ✅ A reconstructed correctly!")
    
    # Now find the kernel of A mod q using LLL
    print(f"\n🔍 Finding kernel of A using LLL...")
    
    try:
        from fpylll import IntegerMatrix, LLL
        
        # Build lattice for kernel
        # We want z such that A @ z ≡ 0 (mod q)
        # Lattice: rows represent z coordinates, use scaling trick
        
        # Standard approach: L = [A^T | q*I_m]
        # Short vectors in L give kernel vectors
        
        A_T = A.T  # m x n
        
        dim = m + n
        B = IntegerMatrix(m, dim)
        
        # Fill in A^T
        for i in range(m):
            for j in range(n):
                B[i, j] = int(A_T[i, j])
        
        # Fill in q*I
        for i in range(m):
            B[i, n + i] = q
        
        # Run LLL
        LLL.reduction(B)
        
        # Extract kernel vectors (the first m components of short rows)
        kernel_vectors = []
        for i in range(m):
            z = [B[i, n + j] for j in range(m)]  # Last m components
            
            # Verify it's a kernel vector
            Az = np.array(A) @ np.array(z)
            if np.all(Az % q == 0) and any(z):
                kernel_vectors.append(z)
        
        print(f"   Found {len(kernel_vectors)} kernel vectors")
        
        if kernel_vectors:
            # Now get the next (y, h) and find a collision
            print(f"\n🔓 Getting new (y, h) and finding collision...")
            
            io.recvuntil(b"y: ")
            y_new = parse_vector(io.recvline().decode())
            io.recvuntil(b"h: ")  
            h_new = parse_vector(io.recvline().decode())
            
            print(f"   y = {y_new}")
            print(f"   h = {h_new}")
            
            # Find y' = y + z such that |y'[i]| <= d
            y_np = np.array(y_new)
            found = False
            
            for z in kernel_vectors:
                z = np.array(z)
                
                # Try various multiples
                for scale in [1, -1, 2, -2]:
                    y_prime = y_np + scale * z
                    
                    # Check bounds and that it's different from y
                    if np.all(np.abs(y_prime) <= d) and not np.array_equal(y_prime, y_np):
                        # Verify collision
                        h_prime = H_func(A.tolist(), y_prime.tolist())
                        if h_prime == h_new:
                            print(f"   ✅ Found collision!")
                            print(f"   y' = {y_prime.tolist()}")
                            
                            io.recvuntil(b"y': ")
                            io.sendline(' '.join(map(str, y_prime.astype(int))))
                            
                            response = io.recvall(timeout=2).decode()
                            print(f"\n🚩 Server response:\n{response}")
                            found = True
                            break
                
                if found:
                    break
            
            if not found:
                print("   ❌ No valid collision found with kernel vectors")
                # Try more combinations
                print("   Trying linear combinations of kernel vectors...")
                
                if len(kernel_vectors) >= 2:
                    for i, z1 in enumerate(kernel_vectors[:5]):
                        for j, z2 in enumerate(kernel_vectors[:5]):
                            if i >= j:
                                continue
                            for a1 in range(-2, 3):
                                for a2 in range(-2, 3):
                                    if a1 == 0 and a2 == 0:
                                        continue
                                    z_comb = a1 * np.array(z1) + a2 * np.array(z2)
                                    y_prime = y_np + z_comb
                                    
                                    if np.all(np.abs(y_prime) <= d) and not np.array_equal(y_prime, y_np):
                                        h_prime = H_func(A.tolist(), y_prime.tolist())
                                        if h_prime == h_new:
                                            print(f"   ✅ Found collision with combination!")
                                            
                                            io.recvuntil(b"y': ")
                                            io.sendline(' '.join(map(str, y_prime.astype(int))))
                                            
                                            response = io.recvall(timeout=2).decode()
                                            print(f"\n🚩 Server response:\n{response}")
                                            found = True
                                            break
                                if found:
                                    break
                            if found:
                                break
                        if found:
                            break
        
    except ImportError:
        print("   fpylll not available. Install with: pip install fpylll")

io.close()
