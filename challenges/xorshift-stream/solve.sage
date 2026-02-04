
from sage.all import *

def solve():
    print("Step 1")
    R = GF(2)
    M = identity_matrix(R, 64)
    M_L13 = identity_matrix(R, 64)
    for i in range(64 - 13):
        M_L13[i + 13, i] += 1
    M = M_L13 * M
    M_R7 = identity_matrix(R, 64)
    for i in range(64 - 7):
        M_R7[i, i + 7] += 1
    M = M_R7 * M
    M_L17 = identity_matrix(R, 64)
    for i in range(64 - 17):
        M_L17[i + 17, i] += 1
    M = M_L17 * M
    T = M
    print("Step 2")
    ct_hex = "142d35c86db4e4bb82ca5965ca1d6bd55c0ffeb35c8a5825f00819821cd775c4c091391f5eb5671b251f5722f1b47e539122f7e5eadc00eee8a6a631928a0c14c57c7e05b6575067c336090f85618c8e181eeddbb3c6e177ad0f9b16d23c777b313e62b877148f06014e8bf3bc156bf88eedd123ba513dfd6fcb32446e41a5b719412939f5b98ffd54c2b5e44f4f7a927ecaff337cddf19fa4e38cbe01162a1b54bb43b0678adf2801d893655a74c656779f9a807c3125b5a30f4800a8"
    ct = bytes.fromhex(ct_hex)
    A = []
    b = []
    for i in range(4):
        ct_block = int.from_bytes(ct[i*8 : i*8 + 8], "little")
        Ti = T**(i+1)
        for j in range(8):
            A.append(Ti.row(j*8 + 7))
            b.append(R((ct_block >> (j*8 + 7)) & 1))
            A.append(Ti.row(j*8 + 5))
            b.append(R(((ct_block >> (j*8 + 5)) & 1) ^ 1))
            A.append(Ti.row(j*8 + 6) + Ti.row(j*8 + 4))
            b.append(R(((ct_block >> (j*8 + 6)) ^ (ct_block >> (j*8 + 4)) ^ 1) & 1))
    print("Step 3")
    A_mat = matrix(R, A)
    b_vec = vector(R, b)
    S0_sol = A_mat.solve_right(b_vec)
    print("Step 4")
    S0_val = 0
    for idx, bit in enumerate(S0_sol):
        if bit: S0_val |= (1 << idx)
    def get_next(state):
        state = (state ^ (state << 13)) % 2**64
        state = (state ^ (state >> 7)) % 2**64
        state = (state ^ (state << 17)) % 2**64
        return state
    curr_state = S0_val
    dec = b""
    for i in range(0, len(ct), 8):
        curr_state = get_next(curr_state)
        block = ct[i : i + 8]
        pt_int = int.from_bytes(block, "little") ^ curr_state
        dec += pt_int.to_bytes(8, "little")[:len(block)]
    print(f"Decrypted: {dec}")
    key_len = 63
    key = bytes.fromhex(dec[:2*key_len].decode())
    tag = dec[2*key_len:]
    flag = bytes([k ^ t for k, t in zip(key, tag)])
    print(f"FLAG: {flag.decode()}")

solve()
