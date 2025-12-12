#!/usr/bin/env sage
# SageMath script to solve GF(2^128) polynomial and forge GCM tag
# Run with: sage C:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\solver\solve_auth2_sage.sage

from sage.all import *

# Define GF(2^128) with GCM's modulus
# GCM uses x^128 + x^7 + x^2 + x + 1
F = GF(2^128, name='a', modulus=x^128 + x^7 + x^2 + x + 1)

def int_to_gf(n):
    """Convert integer to GF(2^128) element."""
    # Need to handle bit ordering - GCM uses reflected bits
    bits = [(n >> i) & 1 for i in range(128)]
    return F(bits)

def gf_to_int(elem):
    """Convert GF(2^128) element to integer."""
    bits = elem._vector_()
    return sum(int(bits[i]) << i for i in range(128))

def bytes_to_gf(b):
    """Convert bytes to GF element."""
    return int_to_gf(int.from_bytes(b, 'big'))

def gf_to_bytes(elem):
    """Convert GF element to bytes."""
    n = gf_to_int(elem)
    return n.to_bytes(16, 'big')

# Polynomial coefficients (c0 + c1*H + c2*H^2 + c3*H^3 + c4*H^4 = 0)
coeffs = [
    int_to_gf(206055930957566183986197250669381693542),  # H^0\n    int_to_gf(320),  # H^1\n    int_to_gf(175719096212068257126917706839933059072),  # H^2\n    int_to_gf(112876232184848783522358161679867340247),  # H^3\n    int_to_gf(262499556430813872567402614343519506308),  # H^4\n]

# Create polynomial over GF(2^128)
R.<H> = F[]
P = sum(coeffs[i] * H^i for i in range(len(coeffs)))

print(f"Polynomial degree: {P.degree()}")
print(f"Finding roots...")

# Find roots
roots = P.roots(multiplicities=False)
print(f"Found {len(roots)} root(s)")

if not roots:
    print("No roots found - check polynomial construction")
    exit(1)

# GHASH buffers (in hex)
buf1 = bytes.fromhex("c57b935b4c4aac92df791e19cb710f8454eb2beb303cfe7e509b351bc1ee65d784324454d6eb06a3000000000000000000000000000000000000000000000140")
buf2 = bytes.fromhex("c57b935b4c4aac92df791e19cb710fe7398a48d81e72b77c48c97804d1bc3a85f934555cccf106a3000000000000000000000000000000000000000000000140")
K = bytes.fromhex("be59e6282938c2f3b21c3c23eb534ec515aa6aaa711ed25e72e95a77a4cc5ff7a6553131a59f24de")

def ghash(data, H_elem):
    """Compute GHASH(H, data) using SageMath GF arithmetic."""
    Y = F(0)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    for block in blocks:
        block = block + bytes(16 - len(block)) if len(block) < 16 else block
        Xi = bytes_to_gf(block)
        Y = (Y + Xi) * H_elem
    return Y

# Try each root
for root in roots:
    S2 = ghash(buf2, root)
    T2 = bytes(a ^^ b for a, b in zip(gf_to_bytes(S2), K[:16]))
    
    C2_hex = buf2[:40].hex()  # First 40 bytes are the ciphertext
    T2_hex = T2.hex()
    
    print(f"\nH = {gf_to_int(root):032x}")
    print(f"Forged token: {C2_hex};{T2_hex}")
