# solver/modules/lattice_subset_sum.py
import operator

def solve_u_turn(target_hex, A):
    """
    Solves the LWE exact subset sum via Kannan's embedding over ZZ.
    Requires execution via SageMath environment.
    """
    import binascii
    h = list(binascii.unhexlify(target_hex))
    
    dim_x = 50
    dim_y = 48
    
    # Needs to be run inside SageMath
    # M = Matrix(ZZ, dim_x + dim_y + 1, dim_x + dim_y + 1)
    # This snippet is a skeleton to be passed to SageMath.
    sage_code = f'''
dim_x = {dim_x}
dim_y = {dim_y}
A = {A}
h = {h}

M = Matrix(ZZ, dim_x + dim_y + 1, dim_x + dim_y + 1)
K = 200

for i in range(dim_x):
    M[i, i] = 1

for i in range(dim_x):
    for j in range(dim_y):
        M[i, dim_x + j] = K * A[j][i]

for j in range(dim_y):
    M[dim_x + j, dim_x + j] = K * 256

for j in range(dim_y):
    M[dim_x + dim_y, dim_x + j] = -K * h[j]

M[dim_x + dim_y, dim_x + dim_y] = 15

M_red = M.LLL()

import operator
valid_xs = []
for row in M_red:
    if row[-1] == 15 or row[-1] == -15:
        if all(x == 0 for x in row[dim_x:dim_x+dim_y]):
            x = list(row[:dim_x])
            if row[-1] == -15:
                x = [-xi for xi in x]
            
            if all(-2 <= xi <= 2 for xi in x):
                valid_xs.append(x)

for x in valid_xs:
    D = [xi + 2 for xi in x]
    a_mod = sum(d * (5**i) for i, d in enumerate(D))
    
    for k in range(5000):
        a_cand = a_mod + k * (5**50)
        
        a_bytes = []
        temp = a_cand
        for _ in range(16):
            a_bytes.append(temp % 256)
            temp //= 256
        
        if temp != 0:
            continue
            
        flag = bytes([int(operator.xor(int(b), 16)) for b in a_bytes])
        if all(32 <= b <= 126 for b in flag):
            print("Found flag:", flag)
            
    '''
    return sage_code
