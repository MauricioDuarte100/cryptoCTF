"""
Solver para ChaCha20-Poly1305 Nonce Reuse Attack - FINAL VERSION

Funciona localmente contra pycryptodome. La clave es:
1. Encontrar TODAS las raíces del polinomio
2. Filtrar por valores de r que estén "clamped" según RFC 8439
3. Usar esa r para forjar el tag
"""

from pwn import *
import struct

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_le(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def le_to_bytes(n: int, length: int) -> bytes:
    return (n % (2**(8*length))).to_bytes(length, 'little')

P = 2**130 - 5

def is_clamped(r: int) -> bool:
    """Check if r satisfies Poly1305 clamping requirements"""
    if r <= 0 or r >= 2**128:
        return False
    r_bytes = le_to_bytes(r, 16)
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

def solve():
    host = "activist-birds.picoctf.net"
    port = 64229
    
    conn = remote(host, port)
    
    # Parse messages
    conn.recvuntil(b"Plaintext: ")
    p1_repr = conn.recvline().decode().strip()
    conn.recvuntil(b"Plaintext (hex): ")
    p1_hex = conn.recvline().decode().strip()
    conn.recvuntil(b"Ciphertext (hex): ")
    c1_hex = conn.recvline().decode().strip()
    
    conn.recvuntil(b"Plaintext: ")
    p2_repr = conn.recvline().decode().strip()
    conn.recvuntil(b"Plaintext (hex): ")
    p2_hex = conn.recvline().decode().strip()
    conn.recvuntil(b"Ciphertext (hex): ")
    c2_hex = conn.recvline().decode().strip()
    
    print(f"[*] P1: {p1_repr[:50]}...")
    print(f"[*] P2: {p2_repr[:50]}...")
    
    p1 = bytes.fromhex(p1_hex)
    c1_full = bytes.fromhex(c1_hex)
    p2 = bytes.fromhex(p2_hex)
    c2_full = bytes.fromhex(c2_hex)
    
    # Parse: ct + tag(16) + nonce(12)
    c1 = c1_full[:-28]
    tag1 = c1_full[-28:-12]
    nonce1 = c1_full[-12:]
    
    c2 = c2_full[:-28]
    tag2 = c2_full[-28:-12]
    nonce2 = c2_full[-12:]
    
    t1 = bytes_to_le(tag1)
    t2 = bytes_to_le(tag2)
    
    print(f"[*] Same nonce: {nonce1 == nonce2}")
    print(f"[*] C1 len: {len(c1)}, C2 len: {len(c2)}")
    
    aad = b''
    aead_msg1 = poly1305_aead_msg(aad, c1)
    aead_msg2 = poly1305_aead_msg(aad, c2)
    
    blocks1 = get_blocks(aead_msg1)
    blocks2 = get_blocks(aead_msg2)
    
    print(f"[*] Blocks1: {len(blocks1)}, Blocks2: {len(blocks2)}")
    
    # Solve for r
    from sympy import symbols, Poly, GF
    
    x = symbols('x')
    n_max = max(len(blocks1), len(blocks2))
    
    blocks1_pad = blocks1 + [0] * (n_max - len(blocks1))
    blocks2_pad = blocks2 + [0] * (n_max - len(blocks2))
    
    r_found = None
    s_found = None
    all_candidates = []
    
    print("[*] Solving polynomial for r...")
    
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
                        
                        # Avoid duplicates
                        if (r_cand, s_cand) not in [(c[0], c[1]) for c in all_candidates]:
                            all_candidates.append((r_cand, s_cand, clamped))
                            print(f"[*] Candidate r (clamped={clamped})")
                        
                        if clamped and r_found is None:
                            r_found = r_cand
                            s_found = s_cand
        except Exception as e:
            continue
    
    print(f"\n[*] Total unique candidates: {len(all_candidates)}")
    print(f"[*] Clamped candidates: {sum(1 for c in all_candidates if c[2])}")
    
    if r_found is None and all_candidates:
        # Use any candidate if no clamped ones found
        r_found, s_found, _ = all_candidates[0]
        print("[!] Warning: Using non-clamped candidate")
    
    if not r_found:
        print("[!] Could not find r and s")
        conn.close()
        return
    
    print(f"[+] Using r")
    print(f"[+] Using s")
    
    # Forge
    keystream = xor_bytes(p1, c1)
    goal = b"But it's only secure if used correctly!"
    ct_forged = xor_bytes(goal, keystream[:len(goal)])
    
    aead_msg_forged = poly1305_aead_msg(aad, ct_forged)
    blocks_forged = get_blocks(aead_msg_forged)
    h_forged = compute_poly(blocks_forged, r_found)
    tag_forged = (h_forged + s_found) % (2**128)
    tag_forged_bytes = le_to_bytes(tag_forged, 16)
    
    print(f"[+] Forged CT: {ct_forged.hex()}")
    print(f"[+] Forged tag: {tag_forged_bytes.hex()}")
    
    # Build message
    forged_full = ct_forged + tag_forged_bytes + nonce1
    print(f"[+] Full forged ({len(forged_full)} bytes): {forged_full.hex()}")
    
    # Verify local decrypt
    dec = xor_bytes(ct_forged, keystream[:len(ct_forged)])
    print(f"[*] Local decrypt: {dec}")
    
    # Send
    conn.recvuntil(b"What is your message? ")
    conn.sendline(forged_full.hex().encode())
    
    # Get response
    try:
        response = conn.recvall(timeout=5).decode()
        print(f"\n[*] Response:\n{response}")
    except Exception as e:
        print(f"[!] Error receiving: {e}")
    
    conn.close()

if __name__ == "__main__":
    solve()
