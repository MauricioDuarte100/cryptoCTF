from pwn import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import os
import struct

# Set up the connection
HOST = 'remote.infoseciitr.in'
PORT = 4005

# --------------------------------------------------------------------------
# GF(2^128) Arithmetic
# --------------------------------------------------------------------------

class GF2_128:
    def __init__(self, val):
        self.val = val & ((1 << 128) - 1)

    def __add__(self, other):
        return GF2_128(self.val ^ other.val)

    def __mul__(self, other):
        # Standard GCM multiplication (reversed bits for POLYVAL)
        # Constant: 0xc2000000000000000000000000000001
        a = self.val
        b = other.val
        p = 0
        for i in range(128):
            if b & 1:
                p ^= a
            b >>= 1
            carry = a & (1 << 127)
            a <<= 1
            if carry:
                a ^= 0xc2000000000000000000000000000001
        return GF2_128(p)

    def inv(self):
        # Exponentiation: a^(2^128 - 2)
        res = GF2_128(1)
        base = self
        exp = (1 << 128) - 2
        while exp > 0:
            if exp & 1:
                res = res * base
            base = base * base
            exp >>= 1
        return res

def poly_mul(a, b):
    # a and b are integers
    p = 0
    for i in range(128):
        if b & 1:
            p ^= a
        b >>= 1
        carry = a & (1 << 127)
        a = (a << 1) & ((1 << 128) - 1)
        if carry:
            a ^= 0xc2000000000000000000000000000001
    return p

# --------------------------------------------------------------------------
# AES-GCM-SIV Helpers
# --------------------------------------------------------------------------

def to_int(b):
    return int.from_bytes(b, 'little')

def to_bytes(i):
    return i.to_bytes(16, 'little')

def aes_encrypt(key, block):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def derive_keys(key, nonce):
    # RFC 8452 Section 4
    z = b'\x00' * 16
    block = aes_encrypt(key, z)
    tag_key_input = block[:4] + nonce
    k_auth = aes_encrypt(key, tag_key_input)
    
    enc_key_input = bytearray(tag_key_input)
    enc_key_input[-1] ^= 0x01 # RFC 8452: XOR with 1 (LSB)
    k_enc = aes_encrypt(key, bytes(enc_key_input))
    
    return k_auth, k_enc

def polyval(h, blocks):
    # h is integer, blocks is list of integers
    s = 0
    for x in blocks:
        s = poly_mul(s ^ x, h)
    return s

def solve():
    # context.log_level = 'debug'
    r = remote(HOST, PORT)

    # 1. Leak Keys
    keys = []
    nonce = None
    
    r.recvuntil(b"Choose an option:")
    
    # Initial key
    r.sendline(b"2")
    r.recvuntil(b"KEYS=['")
    k0 = r.recvuntil(b"']", drop=True).decode()
    r.recvuntil(b"nonce=")
    nonce_hex = r.recvline().strip().decode()
    keys.append(binascii.unhexlify(k0))
    nonce = binascii.unhexlify(nonce_hex)
    
    # Rotate 3 times
    for _ in range(3):
        r.sendline(b"1")
        r.recvuntil(b"Key rotated.")
        r.sendline(b"2")
        r.recvuntil(b"KEYS=")
        line = r.recvline().strip().decode()
        # line is "['key1', 'key2', ...]"
        current_keys = eval(line)
        keys.append(binascii.unhexlify(current_keys[-1]))
        r.recvuntil(b"nonce=")
        r.recvline()

    print(f"[*] Keys: {[k.hex() for k in keys]}")
    print(f"[*] Nonce: {nonce.hex()}")

    # 2. Solve Linear System
    
    # Generate random Tag T (16 bytes) that satisfies MSB constraint for all keys
    print("[*] Searching for valid Tag T...")
    while True:
        T = os.urandom(16)
        valid_t = True
        for i in range(4):
            _, k_enc_bytes = derive_keys(keys[i], nonce)
            cipher_ecb = Cipher(algorithms.AES(k_enc_bytes), modes.ECB(), backend=default_backend())
            decryptor = cipher_ecb.decryptor()
            d_bytes = decryptor.update(T) + decryptor.finalize()
            if (d_bytes[-1] & 0x80) != 0:
                valid_t = False
                break
        if valid_t:
            break
    print(f"[*] Found valid Tag T: {T.hex()}")
    
    # Calculate KS_i for each key
    keystreams = []
    k_auths = []
    
    for key in keys:
        k_auth, k_enc = derive_keys(key, nonce)
        k_auths.append(to_int(k_auth))
        
        # AES-CTR with IV=T (masked)
        # RFC 8452: Increment first 32 bits (little-endian) modulo 2^32.
        t_masked = bytearray(T)
        t_masked[-1] &= 0x7f
        
        # Initial counter value (first 4 bytes as little-endian int)
        ctr_val = struct.unpack("<I", t_masked[:4])[0]
        suffix = t_masked[4:]
        
        ks = b""
        cipher_ecb = Cipher(algorithms.AES(k_enc), modes.ECB(), backend=default_backend())
        encryptor = cipher_ecb.encryptor()
        
        for _ in range(8): # 8 blocks
            # Construct current counter block
            curr_ctr_block = struct.pack("<I", ctr_val) + suffix
            ks += encryptor.update(curr_ctr_block)
            ctr_val = (ctr_val + 1) & 0xFFFFFFFF
            
        keystreams.append(ks)

    # Determine C1..C4
    p1 = b"gib m".ljust(16, b' ')
    p2 = b"e fl".ljust(16, b' ')
    p3 = b"ag p".ljust(16, b' ')
    p4 = b"lis".ljust(16, b' ')
    
    c1 = to_int(p1) ^ to_int(keystreams[0][0:16])
    c2 = to_int(p2) ^ to_int(keystreams[1][16:32])
    c3 = to_int(p3) ^ to_int(keystreams[2][32:48])
    c4 = to_int(p4) ^ to_int(keystreams[3][48:64])
    
    fixed_c = [c1, c2, c3, c4] # Integers
    
    # Length block
    len_block_int = 1024 << 64
    
    # Matrix M: 4x4
    matrix = []
    rhs = []
    
    for i in range(4):
        h = GF2_128(k_auths[i])
        ks_blocks = [to_int(keystreams[i][j:j+16]) for j in range(0, 128, 16)]
        
        # Calculate Constant Term (Target Tag check)
        # D = AES_Decrypt(K_enc, T)
        # We assume (POLYVAL XOR Nonce) & mask == D
        # We target POLYVAL = D XOR Nonce (ignoring mask for now)
        
        # Note: k_enc is bytes
        _, k_enc_bytes = derive_keys(keys[i], nonce)
        
        cipher_ecb = Cipher(algorithms.AES(k_enc_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher_ecb.decryptor()
        d_bytes = decryptor.update(T) + decryptor.finalize()
        d = to_int(d_bytes)
        
        target_polyval = d ^ to_int(nonce)
        
        # Equation: P(H, C) = Target_Polyval XOR P(H, KS) XOR P(H, Len)
        
        # Helper for powers of H
        h_pow = [GF2_128(1)] * 10
        curr = h
        for p in range(1, 10):
            h_pow[p] = curr
            curr = curr * h
            
        # P(H, KS)
        p_ks = GF2_128(0)
        for b_idx in range(8):
            term = GF2_128(to_int(keystreams[i][b_idx*16:(b_idx+1)*16])) * h_pow[9 - b_idx]
            p_ks = p_ks + term
            
        p_len = GF2_128(len_block_int) * h_pow[1]
        
        rhs_val = GF2_128(target_polyval) + p_ks + p_len
        
        # Subtract known C terms (C1..C4)
        for b_idx in range(4):
            term = GF2_128(fixed_c[b_idx]) * h_pow[9 - b_idx]
            rhs_val = rhs_val + term
            
        # Coefficients for C5..C8 are H^5..H^2
        row = [h_pow[5], h_pow[4], h_pow[3], h_pow[2]]
        matrix.append(row)
        rhs.append(rhs_val)

    # Solve Matrix (Gaussian Elimination)
    for i in range(4):
        # Pivot
        if matrix[i][i].val == 0:
            for j in range(i+1, 4):
                if matrix[j][i].val != 0:
                    matrix[i], matrix[j] = matrix[j], matrix[i]
                    rhs[i], rhs[j] = rhs[j], rhs[i]
                    break
        
        inv = matrix[i][i].inv()
        
        # Normalize row
        for j in range(i, 4):
            matrix[i][j] = matrix[i][j] * inv
        rhs[i] = rhs[i] * inv
        
        # Eliminate other rows
        for k in range(4):
            if k != i:
                factor = matrix[k][i]
                for j in range(i, 4):
                    matrix[k][j] = matrix[k][j] + (matrix[i][j] * factor)
                rhs[k] = rhs[k] + (rhs[i] * factor)

    # Result C5..C8
    c_solved = [r.val for r in rhs]
    print(f"DEBUG: c_solved = {[hex(c) for c in c_solved]}")
    
    # Construct Final Ciphertext
    final_ct = b""
    for c in fixed_c:
        final_ct += to_bytes(c)
    for c in c_solved:
        final_ct += to_bytes(c)
    final_ct += T
    
    print(f"[*] Final Ciphertext ({len(final_ct)} bytes): {final_ct.hex()}")
    
    # 3. Push Ciphertext
    r.sendline(b"3")
    r.sendline(final_ct.hex().encode())
    
    # 4. Request Flag
    r.sendline(b"4")
    
    try:
        while True:
            line = r.recvline().decode().strip()
            print(f"[SERVER] {line}")
            if "flag{" in line:
                print(f"\n[+] FLAG: {line}")
                break
    except EOFError:
        print("[-] Connection closed unexpectedly.")
    
    r.close()

if __name__ == "__main__":
    solve()
