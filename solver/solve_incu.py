"""
Solver for Incunabula - Proper MITM with 32-bit split

For MITM:
- Split 64 bits into two 32-bit halves
- Precompute all 2^32 products for second half (bits 32-63)
- For each of 2^32 first-half products, check if c * inv(first) is in table

This is ~8GB of RAM for the table but should work.

Actually, 2^32 entries × 32 bytes each = 128 GB, too much.
Let's use a hash-based approach with collision handling.
"""

from pwn import *
import ast
import hashlib

HOST = "tcp.flagyard.com"
PORT = 29951

context.log_level = 'error'

print(f"🔌 Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT)

line1 = io.recvline().decode().strip()
line2 = io.recvline().decode().strip()

params = ast.literal_eval(line1)
ciphertexts = ast.literal_eval(line2)

p = params['p']
primes = params['primes']
roots = params['roots']

print(f"   p bits: {p.bit_length()}")
print(f"   {len(ciphertexts)} ciphertexts")

io.close()

def encrypt(plaintext, roots, p):
    ciphertext = 1
    for i in range(len(roots)):
        bit = plaintext & 1
        if bit:
            ciphertext = (ciphertext * roots[i]) % p
        plaintext >>= 1
    return ciphertext

def modinv(a, m):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        return None
    return x % m

# We know chunk 8 = "FlagY{aa"
known_8 = b"FlagY{aa"
known_8_int = int.from_bytes(known_8, 'big')

# Verify
ct8 = encrypt(known_8_int, roots, p)
print(f"\n📊 Verification:")
print(f"   Known chunk 8: {known_8}")
print(f"   encrypt({known_8}) matches ciphertexts[8]? {ct8 == ciphertexts[8]}")

# For remaining chunks, use optimized MITM
# Table size: 2^24 entries with lower 24 bits fixed

# Better approach: split into 24-bit halves for lower memory
# 2^24 = 16M entries, ~512 MB with 32-byte keys

print(f"\n🔍 MITM with 24-bit split...")

def mitm_24bit(target_ct, roots, p):
    """MITM attack splitting at bit 24 (lower for memory)."""
    
    # Precompute second half: product of roots[24:64] for all bit patterns
    # That's 40 bits = 1T entries, still too large!
    
    # Let's try 20-bit split: 2^20 = 1M entries for first half, search 2^44 for second
    # Still too slow.
    
    # Alternative: Use multiple smaller splits with intermediate hash tables
    
    # Try 16-bit split: 2^16 entries = 65K, very fast
    # Then search 2^48 for remaining = 281T, too slow
    
    # Let's try 24+24+16 split:
    # bits 0-23: precompute table (16M entries)
    # bits 24-47: precompute another table (16M entries) 
    # bits 48-63: iterate and combine
    
    # For each of 2^16 patterns in bits 48-63:
    #   partial_ct = target_ct * inv(product of roots[48:64]^bits)
    #   Now need to find a, b such that:
    #   product(roots[0:24]^a) * product(roots[24:48]^b) = partial_ct
    #   This is MITM on two 24-bit halves!
    
    pass

# Actually, let's just do a smarter brute force with multiprocessing
# and focus on printable ASCII only

import multiprocessing as mp
from itertools import product

def check_ascii_chunk(args):
    """Check if an ASCII chunk matches the target ciphertext."""
    chars, target_ct, roots, p = args
    candidate = bytes(chars)
    pt = int.from_bytes(candidate, 'big')
    
    # Compute encrypt
    ciphertext = 1
    for i in range(64):
        if pt & (1 << i):
            ciphertext = (ciphertext * roots[i]) % p
    
    if ciphertext == target_ct:
        return candidate
    return None

# Focus on alphanumeric + common symbols for CTF flags
flag_charset = b"abcdefghijklmnopqrstuvwxyz0123456789_"
print(f"   Using charset of {len(flag_charset)} characters")

# For chunk 0 (last 8 bytes), we expect it ends with "}"
# Try patterns like "xxxxxx?}" where ? is any printable
print(f"\n🔍 Searching for chunk 0 (should end with closing brace)...")

found_chunk0 = None
for suffix_len in range(1, 8):
    if found_chunk0:
        break
    prefix_len = 8 - suffix_len - 1  # -1 for the "}"
    
    print(f"   Trying {prefix_len} chars + '}}' + {suffix_len-1} nulls...")
    
    if prefix_len < 0:
        continue
    
    for prefix_chars in product(flag_charset, repeat=prefix_len):
        candidate = bytes(prefix_chars) + b"}" + b"\x00" * (suffix_len - 1)
        if len(candidate) != 8:
            continue
        pt = int.from_bytes(candidate, 'big')
        ct = encrypt(pt, roots, p)
        if ct == ciphertexts[0]:
            found_chunk0 = candidate
            print(f"   ✅ Found chunk 0: {candidate}")
            break

if not found_chunk0:
    # Try alternate patterns - maybe the flag is shorter
    print(f"   Trying with trailing padding...")
    for total_len in range(2, 8):
        if found_chunk0:
            break
        for chars in product(flag_charset, repeat=total_len - 1):
            candidate = bytes(chars) + b"}"
            candidate = candidate.ljust(8, b"\x00")
            pt = int.from_bytes(candidate, 'big')
            ct = encrypt(pt, roots, p)
            if ct == ciphertexts[0]:
                found_chunk0 = candidate
                print(f"   ✅ Found chunk 0: {candidate}")
                break

# Now try to find other chunks
chunks = {8: known_8}
if found_chunk0:
    chunks[0] = found_chunk0

print(f"\n📊 Found chunks so far:")
for idx, chunk in sorted(chunks.items()):
    print(f"   Chunk {idx}: {chunk}")

# For middle chunks, we need to be smarter
# Each chunk is 8 bytes of flag content
# If flag format is "FlagY{xxxx...xxxx}", middle chunks are flag content

print(f"\n🔍 Searching middle chunks with reduced charset...")

for chunk_idx in range(1, 8):
    if chunk_idx in chunks:
        continue
    
    print(f"\n   Searching chunk {chunk_idx}...")
    target_ct = ciphertexts[chunk_idx]
    
    # With 36^8 ≈ 2.8T, still too slow for single thread
    # Let's try common patterns first
    
    # Try all lowercase 6-char patterns (36^6 = 2.2B, still slow)
    # Focus on 4-char patterns repeated: "aaaabbbb" format
    
    found = False
    
    # Try simple patterns first
    for rep_len in [2, 4]:
        if found:
            break
        pattern_len = 8 // rep_len
        print(f"      Trying {pattern_len}-char pattern repeated {rep_len}x...")
        
        for pattern in product(flag_charset, repeat=pattern_len):
            candidate = bytes(pattern * rep_len)
            if len(candidate) != 8:
                continue
            pt = int.from_bytes(candidate, 'big')
            ct = encrypt(pt, roots, p)
            if ct == target_ct:
                chunks[chunk_idx] = candidate
                print(f"      ✅ Found: {candidate}")
                found = True
                break
    
    if not found:
        print(f"      Not a simple pattern...")

# Final output
print(f"\n📊 Final chunks:")
flag_bytes = b""
for i in range(8, -1, -1):
    if i in chunks:
        flag_bytes += chunks[i]
        print(f"   Chunk {i}: {chunks[i]}")
    else:
        flag_bytes += b"????????"
        print(f"   Chunk {i}: ???")

print(f"\n🚩 Partial flag: {flag_bytes}")
