
from z3 import *
import binascii

def solve():
    ct_hex = "142d35c86db4e4bb82ca5965ca1d6bd55c0ffeb35c8a5825f00819821cd775c4c091391f5eb5671b251f5722f1b47e539122f7e5eadc00eee8a6a631928a0c14c57c7e05b6575067c336090f85618c8e181eeddbb3c6e177ad0f9b16d23c777b313e62b877148f06014e8bf3bc156bf88eedd123ba513dfd6fcb32446e41a5b719412939f5b98ffd54c2b5e44f4f7a927ecaff337cddf19fa4e38cbe01162a1b54bb43b0678adf2801d893655a74c656779f9a807c3125b5a30f4800a8"
    ct = bytes.fromhex(ct_hex)
    
    s = Solver()
    S0 = BitVec('s0', 64)
    
    def get_next(state):
        state ^= (state << 13)
        state ^= LShR(state, 7) # In Z3, >> on signed is Arithmetic, use LShR for Logical
        state ^= (state << 17)
        return state

    curr_state = S0
    # First 126 characters are hex chars of key. 126 / 8 = 15.75 blocks.
    # So the first 15 blocks are definitely hex chars.
    for i in range(15):
        curr_state = get_next(curr_state)
        ct_block = int.from_bytes(ct[i*8 : i*8 + 8], "little")
        pt_block = curr_state ^ ct_block
        
        # Each byte of pt_block must be in '0123456789abcdef'
        for j in range(8):
            byte = (pt_block >> (j*8)) & 0xFF
            
            # Constraints on hex chars:
            # '0'-'9': 0x30 to 0x39 (00110000 to 00111001)
            # 'a'-'f': 0x61 to 0x66 (01100001 to 01100110)
            
            # bit 7 is always 0
            s.add(Extract(7, 7, byte) == 0)
            # bit 5 is always 1
            s.add(Extract(5, 5, byte) == 1)
            # bit 6 ^ bit 4 is always 1
            s.add(Extract(6, 6, byte) ^ Extract(4, 4, byte) == 1)
            
    print("Checking constraints...")
    if s.check() == sat:
        print("Sat!")
        m = s.model()
        S0_val = m[S0].as_long()
        print(f"S0: {S0_val}")
        
        # Reconstruct and decrypt
        def next_py(state):
            state = (state ^ (state << 13)) % 2**64
            state = (state ^ (state >> 7)) % 2**64
            state = (state ^ (state << 17)) % 2**64
            return state

        curr = S0_val
        dec = b""
        for i in range(0, len(ct), 8):
            curr = next_py(curr)
            blk = ct[i : i + 8]
            pt_int = int.from_bytes(blk, "little") ^ curr
            dec += pt_int.to_bytes(8, "little")[:len(blk)]
            
        print(f"Decrypted: {dec}")
        key_len = 63
        key_hex = dec[:2*key_len]
        tag = dec[2*key_len:]
        key = bytes.fromhex(key_hex.decode())
        flag = bytes([k ^ t for k, t in zip(key, tag)])
        print(f"FLAG: {flag.decode()}")
    else:
        print("Unsat")

solve()
