
# Poly1305 forgery attack - Sage script
import sys
P = 2**130 - 5

def bytes_to_le_int(b):
    return int.from_bytes(bytes.fromhex(b), 'little')

def le_int_to_bytes(n, length):
    return n.to_bytes(length, 'little')

def poly1305_blocks(msg_hex):
    msg = bytes.fromhex(msg_hex)
    blocks = []
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        n = int.from_bytes(block, 'little') + (1 << (8 * len(block)))
        blocks.append(n)
    return blocks

# Ciphertexts (sin tag ni nonce)
c1_hex = "06cfd2fcc4b1e1003393dae76aa9b18ac2753c1d29958d6e2f190aa5f8234a3cb52b7a6a1d1d8311f363e162055d97707c29c7473c57f4729c6d2a045bd5ac658476a8009096158ba984a841f9"
c2_hex = "16ced7a89db3f141368e95f93efda999d9211a163ca5c56d725d4fd5e327562de574212c1d0ac61ee92ae17b18418b3e692ec006215ce4379e7120025b85b76acb7ce9159dd0"
tag1_hex = "a7527bb524af30b20bc21ed59c41e097"
tag2_hex = "9a05e982eae7656f0ed236ce337761e0"

blocks1 = poly1305_blocks(c1_hex)
blocks2 = poly1305_blocks(c2_hex)
t1 = bytes_to_le_int(tag1_hex)
t2 = bytes_to_le_int(tag2_hex)

# Ring de polinomios sobre ZZ
R.<x> = PolynomialRing(Zmod(P))

# Construir polinomios
def build_poly(blocks):
    p = 0
    for b in blocks:
        p = (p + b) * x
    return p

poly1 = build_poly(blocks1)
poly2 = build_poly(blocks2)
diff_poly = poly1 - poly2

# Probar diferentes carries para resolver
for carry in range(-3, 4):
    target = (t1 - t2 + carry * 2**128) % P
    f = diff_poly - target
    roots = f.roots()
    for root, _ in roots:
        r_cand = int(root)
        # Verificar que es un r válido (clamped)
        # Calcular s
        h1 = int(poly1(r_cand))
        s_cand = (t1 - h1) % (2**128)
        # Verificar con el segundo par
        h2 = int(poly2(r_cand))
        t2_check = (h2 + s_cand) % (2**128)
        if t2_check == t2:
            print(f"r = {r_cand}")
            print(f"s = {s_cand}")
            sys.exit(0)
