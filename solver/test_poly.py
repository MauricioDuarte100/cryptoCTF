"""
Test completo del ataque Poly1305 - Versión con verificación de clamping
"""

from Crypto.Cipher import ChaCha20_Poly1305
import struct
import os

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_le(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def le_to_bytes(n: int, length: int) -> bytes:
    return (n % (2**(8*length))).to_bytes(length, 'little')

P = 2**130 - 5

def is_clamped(r: int) -> bool:
    """Check if r satisfies Poly1305 clamping requirements"""
    r_bytes = le_to_bytes(r, 16)
    # Bits that must be 0 after clamping:
    # r[3], r[7], r[11], r[15] &= 15 (top 4 bits = 0)
    # r[4], r[8], r[12] &= 252 (bottom 2 bits = 0)
    
    checks = [
        (r_bytes[3] & 0xF0) == 0,
        (r_bytes[7] & 0xF0) == 0,
        (r_bytes[11] & 0xF0) == 0,
        (r_bytes[15] & 0xF0) == 0,
        (r_bytes[4] & 0x03) == 0,
        (r_bytes[8] & 0x03) == 0,
        (r_bytes[12] & 0x03) == 0,
    ]
    return all(checks)

def poly1305_aead_msg(aad, ct):
    def pad16(x):
        return b'\x00' * ((16 - len(x) % 16) % 16)
    
    msg = aad + pad16(aad) + ct + pad16(ct)
    msg += struct.pack('<Q', len(aad))
    msg += struct.pack('<Q', len(ct))
    return msg

def get_blocks(msg):
    blocks = []
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        n = bytes_to_le(block) + (1 << (8 * len(block)))
        blocks.append(n)
    return blocks

def compute_poly(blocks, r):
    acc = 0
    for b in blocks:
        acc = (acc + b) * r % P
    return acc

def test_forgery():
    """Test forgery attack locally"""
    key = os.urandom(32)
    nonce = os.urandom(12)
    
    msg1 = b"Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?"
    msg2 = b"That means it protects both the confidentiality and integrity of data!"
    goal = b"But it's only secure if used correctly!"
    
    # Encrypt with same nonce
    cipher1 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct1, tag1 = cipher1.encrypt_and_digest(msg1)
    
    cipher2 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct2, tag2 = cipher2.encrypt_and_digest(msg2)
    
    t1 = bytes_to_le(tag1)
    t2 = bytes_to_le(tag2)
    
    aad = b''
    aead_msg1 = poly1305_aead_msg(aad, ct1)
    aead_msg2 = poly1305_aead_msg(aad, ct2)
    
    blocks1 = get_blocks(aead_msg1)
    blocks2 = get_blocks(aead_msg2)
    
    print(f"[*] Blocks1: {len(blocks1)}, Blocks2: {len(blocks2)}")
    
    # Solve for r using sympy
    from sympy import symbols, Poly, GF
    
    x = symbols('x')
    n_max = max(len(blocks1), len(blocks2))
    
    blocks1_pad = blocks1 + [0] * (n_max - len(blocks1))
    blocks2_pad = blocks2 + [0] * (n_max - len(blocks2))
    
    r_found = None
    s_found = None
    all_candidates = []
    
    for carry in range(-5, 6):
        target = (t1 - t2 + carry * (2**128)) % P
        
        poly_expr = 0
        for i in range(n_max):
            coef = (blocks1_pad[i] - blocks2_pad[i]) % P
            power = n_max - i
            if coef != 0:
                poly_expr += coef * x**power
        poly_expr -= target
        
        try:
            poly = Poly(poly_expr, x, domain=GF(P))
            roots = poly.ground_roots()
            
            for root in roots:
                r_cand = int(root) % P
                if r_cand <= 0:
                    continue
                
                h1 = compute_poly(blocks1, r_cand)
                h2 = compute_poly(blocks2, r_cand)
                
                for s_carry in range(-3, 4):
                    s_cand = (t1 + s_carry * (2**128) - h1) % P
                    
                    t1_check = (h1 + s_cand) % (2**128)
                    t2_check = (h2 + s_cand) % (2**128)
                    
                    if t1_check == t1 and t2_check == t2:
                        clamped = is_clamped(r_cand)
                        all_candidates.append((r_cand, s_cand, clamped))
                        print(f"[*] Candidate r={r_cand}, clamped={clamped}")
                        
                        if clamped and r_found is None:
                            r_found = r_cand
                            s_found = s_cand
        except:
            continue
    
    print(f"\n[*] Total candidates: {len(all_candidates)}")
    print(f"[*] Clamped candidates: {sum(1 for c in all_candidates if c[2])}")
    
    if r_found is None and all_candidates:
        # Use first candidate even if not clamped
        r_found, s_found, _ = all_candidates[0]
        print("[!] Using non-clamped candidate")
    
    if not r_found:
        print("[!] Could not find r and s")
        return False
    
    print(f"[+] Using r = {r_found}")
    print(f"[+] Using s = {s_found}")
    
    # Forge ciphertext for goal
    keystream = xor_bytes(msg1, ct1)
    ct_forged = xor_bytes(goal, keystream[:len(goal)])
    
    # Compute forged tag
    aead_msg_forged = poly1305_aead_msg(aad, ct_forged)
    blocks_forged = get_blocks(aead_msg_forged)
    h_forged = compute_poly(blocks_forged, r_found)
    tag_forged = (h_forged + s_found) % (2**128)
    tag_forged_bytes = le_to_bytes(tag_forged, 16)
    
    print(f"[+] Forged tag: {tag_forged_bytes.hex()}")
    
    # Verify
    cipher_verify = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        decrypted = cipher_verify.decrypt_and_verify(ct_forged, tag_forged_bytes)
        print(f"[+] SUCCESS! Decrypted: {decrypted}")
        return True
    except Exception as e:
        print(f"[!] Verification FAILED: {e}")
        
        # What's the actual r and s?
        from Crypto.Cipher import ChaCha20
        chacha_keystream = ChaCha20.new(key=key, nonce=nonce)
        block0 = chacha_keystream.encrypt(b'\x00' * 64)
        
        def clamp(r_bytes):
            r = bytearray(r_bytes)
            r[3] &= 15
            r[7] &= 15
            r[11] &= 15
            r[15] &= 15
            r[4] &= 252
            r[8] &= 252
            r[12] &= 252
            return bytes(r)
        
        actual_r = bytes_to_le(clamp(block0[:16]))
        actual_s = bytes_to_le(block0[16:32])
        print(f"\n[*] Actual r = {actual_r}")
        print(f"[*] Actual s = {actual_s}")
        print(f"[*] Found r matches actual: {r_found == actual_r}")
        print(f"[*] Found s matches actual: {s_found == actual_s}")
        
        return False

if __name__ == "__main__":
    success = test_forgery()
    print(f"\n[*] Test result: {'PASSED' if success else 'FAILED'}")
