from sage.all import *

A = [[978223, 4103264, 2434930, 67809, 6689879, 8055109, 7358908], [704310, 752283, 1297100, 5467548, 2062034, 1748259, 393695], [2137404, 1207017, 4202172, 7586405, 8338363, 66015, 2477572], [2415274, 3971353, 4875079, 5152330, 5802762, 6727030, 3467171], [120474, 8076081, 4913437, 7056765, 4114904, 165323, 7714928], [57003, 259088, 6290590, 6813182, 7431019, 54935, 6547376], [5714777, 1965973, 3869597, 6806257, 3429400, 7138992, 2684187], [902807, 5735163, 4236221, 7359799, 7035051, 5481646, 3562173], [681907, 1263527, 4069317, 233811, 608502, 2907035, 625938], [2993255, 2217495, 6923674, 1947351, 3575140, 3447543, 5071692]]
b = [4564535, 3088331, 4021737, 2387590, 7844407, 3965605, 7334578, 356862, 1345100, 2445644]
p = 8380417

m = 10
n = 7

# LWE-like: b = As + e mod p
# Lattice:
# Rows corresponding to p * I_m
# Rows corresponding to Columns of A
# Row for -b | 1
M = Matrix(ZZ, m + n + 1, m + 1)
for i in range(m):
    M[i, i] = p

A_mat = Matrix(GF(p), A)
for i in range(n):
    for j in range(m):
        M[m + i, j] = int(A_mat[j, i])

for j in range(m):
    M[m + n, j] = -b[j]
M[m + n, m] = 1

L = M.LLL()
for row in L:
    if abs(row[m]) == 1:
        e = [abs(x) for x in row[:m]]
        if all(x in [0, 1] for x in e):
            # b - e = As
            target = vector(GF(p), b) - vector(GF(p), e)
            try:
                s = A_mat.solve_right(target)
                flag_bytes = b""
                for x in s:
                    flag_bytes += int(x).to_bytes(3, 'big')
                print(f"FLAG: Alpaca{{{flag_bytes.decode()}}}")
                break
            except:
                continue
