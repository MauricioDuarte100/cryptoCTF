#!/usr/bin/env python3
"""
Deceptive Fairness - Alternative cipher analysis
Looking at Two-Square, Four-Square, and transposition ciphers
"""

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

def to_bigrams(s):
    return [s[i:i+2] for i in range(0, len(s), 2)]

bg1, bg2, bg3 = to_bigrams(ct1), to_bigrams(ct2), to_bigrams(ct3)

print("=" * 60)
print("ALTERNATIVE CIPHER ANALYSIS")
print("=" * 60)

# Maybe we should SORT bigrams and see what we get
print("\n--- Sorted Bigrams ---")
print(f"R1 sorted: {sorted(bg1)}")
print(f"R2 sorted: {sorted(bg2)}")
print(f"R3 sorted: {sorted(bg3)}")

# What if reading the first letter of each sorted bigram spells something?
r1_first = "".join(bg[0] for bg in sorted(bg1))
r1_second = "".join(bg[1] for bg in sorted(bg1))
print(f"\nR1 sorted first letters: {r1_first}")
print(f"R1 sorted second letters: {r1_second}")

# Try treating bigram as a PAIR of letters that go together
# What if each bigram encodes a single letter via some mapping?
print("\n--- Bigram to Letter Mapping ---")
# Common bigrams sorted: BA, EC, FD, HW, NQ, OT, PC, RP
# These could map to individual letters

# Let's see if it's Bifid cipher
print("\n--- Bifid/Trifid Analysis ---")
# In Bifid, we extract row and column numbers from a Polybius square

# What about Vigenere?
print("\n--- Vigenere Analysis ---")
def vigenere_decrypt(ciphertext, key):
    result = ""
    key = key.upper()
    key_idx = 0
    for c in ciphertext.upper():
        if c.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
            key_idx += 1
        else:
            result += c
    return result

keys = ["FAIR", "DECEPTION", "PAIRS", "SECRET", "KEY", "FLAG", 
        "DECEPTIVE", "UNFAIR", "CHEAT", "DECEIVE", "TRUTH"]
print("Testing Vigenere keys:")
for key in keys:
    dec1 = vigenere_decrypt(ct1, key)
    dec2 = vigenere_decrypt(ct2, key)
    dec3 = vigenere_decrypt(ct3, key)
    # Combined check
    combined = dec1.lower()
    if any(w in combined for w in ["the", "flag", "key", "and", "is"]):
        print(f"  Key '{key}': {dec1}")

# Let's look at ROT ciphers on the first ciphertext
print("\n--- ROT Decryption (Row 1) ---")
for shift in range(26):
    dec = ""
    for c in ct1:
        dec += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
    # Check if readable
    if 'FLAG' in dec or 'THE' in dec or 'PAIR' in dec:
        print(f"ROT-{shift}: {dec}")

# What about Atbash?
print("\n--- Atbash Cipher ---")
def atbash(text):
    result = ""
    for c in text.upper():
        if c.isalpha():
            result += chr(ord('Z') - (ord(c) - ord('A')))
        else:
            result += c
    return result

print(f"R1 Atbash: {atbash(ct1)}")
print(f"R2 Atbash: {atbash(ct2)}")
print(f"R3 Atbash: {atbash(ct3)}")

# What about reading down the matrix?
print("\n--- Matrix Transposition ---")
# Pad all to same length
max_len = max(len(ct1), len(ct2), len(ct3))
m1 = ct1.ljust(max_len, '?')
m2 = ct2.ljust(max_len, '?')
m3 = ct3.ljust(max_len, '?')

# Read columns
cols = ""
for i in range(max_len):
    cols += m1[i] + m2[i] + m3[i]
print(f"Column read (down each): {cols}")

# Read column pairs as bigrams
col_bigrams = []
for i in range(max_len):
    col = m1[i] + m2[i] + m3[i]
    col_bigrams.append(col)
print(f"Column triplets: {col_bigrams}")

# What if the key is to look at DIFFERENCES in positions?
print("\n--- Position Difference Analysis ---")
# Row 1 is the "baseline"
common = set(bg1) & set(bg2) & set(bg3)
for bg in sorted(common):
    p1 = bg1.index(bg)
    p2 = bg2.index(bg) if bg in bg2 else -99
    p3 = bg3.index(bg) if bg in bg3 else -99
    diff12 = p2 - p1 if p2 >= 0 else None
    diff13 = p3 - p1 if p3 >= 0 else None
    print(f"{bg}: pos=[{p1},{p2},{p3}] diff12={diff12} diff13={diff13}")

# Try Nihilist cipher
print("\n--- Nihilist Cipher Analysis ---")
# Nihilist uses a Polybius square + key addition

# What if we convert each letter to a number and look for patterns?
print("\n--- Numeric Analysis ---")
def to_nums(s):
    return [ord(c) - ord('A') for c in s]

n1 = to_nums(ct1)
n2 = to_nums(ct2)
n3 = to_nums(ct3)
print(f"R1 nums: {n1}")
print(f"R2 nums: {n2}")
print(f"R3 nums: {n3}")

# Sum of each position
print(f"\nColumn sums (mod 26):")
for i in range(min(len(n1), len(n2), len(n3))):
    s = (n1[i] + n2[i] + n3[i]) % 26
    c = chr(s + ord('A'))
    print(f"  Col {i}: {n1[i]}+{n2[i]}+{n3[i]} mod 26 = {s} = {c}", end="")
    if (i + 1) % 5 == 0:
        print()

# Maybe it's Beaufort cipher
print("\n\n--- Beaufort Cipher ---")
def beaufort_decrypt(ciphertext, key):
    result = ""
    key = key.upper()
    key_idx = 0
    for c in ciphertext.upper():
        if c.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result += chr((shift - (ord(c) - ord('A'))) % 26 + ord('A'))
            key_idx += 1
        else:
            result += c
    return result

for key in ["FAIR", "PAIR", "DECEPTION"]:
    print(f"Key '{key}': {beaufort_decrypt(ct1, key)}")

# What if the secret is literally written across the three rows?
print("\n--- Interleaved Reading ---")
# Read: R1[0], R2[0], R3[0], R1[1], R2[1], R3[1], ...
interleaved = ""
for i in range(max_len):
    if i < len(ct1): interleaved += ct1[i]
    if i < len(ct2): interleaved += ct2[i]
    if i < len(ct3): interleaved += ct3[i]
print(f"Interleaved: {interleaved}")

# And just reading row by row
print(f"Concatenated: {ct1 + ct2 + ct3}")

# Extract just the letters that are DIFFERENT between rows
print("\n--- Difference Extraction ---")
# Compare character positions
for i in range(min(len(ct1), len(ct2), len(ct3))):
    if ct1[i] != ct2[i] or ct1[i] != ct3[i]:
        print(f"Pos {i}: {ct1[i]} / {ct2[i]} / {ct3[i]}")

# IMPORTANT: Check if there's a Two-Square cipher structure
print("\n--- Two-Square Cipher (horizontal) ---")
# In Two-square, we use 2 grids. One encodes first letter, other encodes second
# Let's try with different keys

import string
def create_grid(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    grid = []
    for c in key + string.ascii_uppercase.replace('J', ''):
        if c not in seen and c.isalpha():
            grid.append(c)
            seen.add(c)
    return [grid[i:i+5] for i in range(0, 25, 5)]

def find_pos(grid, char):
    char = char.upper()
    if char == 'J': char = 'I'
    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell == char:
                return r, c
    return None, None

def two_square_decrypt(ciphertext, key1, key2):
    g1 = create_grid(key1)
    g2 = create_grid(key2)
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        if i+1 >= len(ciphertext): break
        a, b = ciphertext[i], ciphertext[i+1]
        r1, c1 = find_pos(g1, a)  # First letter from grid 1
        r2, c2 = find_pos(g2, b)  # Second letter from grid 2
        if r1 is None or r2 is None:
            plaintext += a + b
            continue
        # In horizontal two-square, decrypt by taking grid1[r2,c1] and grid2[r1,c2]
        plaintext += g1[r2][c1] + g2[r1][c2]
    return plaintext

# Try different key combinations
key_pairs = [
    ("DECEPTIVE", "FAIRNESS"),
    ("FAIRNESS", "DECEPTIVE"),
    ("FAIR", "DECEPTION"),
    ("DECEPTION", "FAIR"),
    ("PAIRS", "DECEIVING"),
]
print("Two-Square decryptions:")
for k1, k2 in key_pairs:
    dec = two_square_decrypt(ct1, k1, k2)
    print(f"  Keys ({k1}, {k2}): {dec}")

# Four-Square cipher
print("\n--- Four-Square Cipher ---")
def four_square_decrypt(ciphertext, key1, key2):
    plain_grid = create_grid("")  # Standard alphabet
    g1 = create_grid(key1)  # Top-right
    g2 = create_grid(key2)  # Bottom-left
    
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        if i+1 >= len(ciphertext): break
        a, b = ciphertext[i], ciphertext[i+1]
        # In four-square, ciphertext comes from keyed grids (top-right, bottom-left)
        r1, c1 = find_pos(g1, a)  # Cipher a from key grid 1 (top-right)
        r2, c2 = find_pos(g2, b)  # Cipher b from key grid 2 (bottom-left)
        if r1 is None or r2 is None:
            plaintext += a + b
            continue
        # Plaintext comes from plain grids at r1,c2 and r2,c1
        plaintext += plain_grid[r1][c2] + plain_grid[r2][c1]
    return plaintext

for k1, k2 in key_pairs:
    dec = four_square_decrypt(ct1, k1, k2)
    print(f"  Keys ({k1}, {k2}): {dec}")
