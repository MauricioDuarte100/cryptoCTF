#!/usr/bin/env python3
"""
Deceptive Fairness CTF Challenge - Re-analysis
"""

# Challenge data
ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

print("=" * 60)
print("DECEPTIVE FAIRNESS - DEEP ANALYSIS")
print("=" * 60)

# Parse as bigrams
def to_bigrams(s):
    return [s[i:i+2] for i in range(0, len(s), 2)]

bg1 = to_bigrams(ct1)
bg2 = to_bigrams(ct2)
bg3 = to_bigrams(ct3)

print(f"\nRow 1: {bg1}")
print(f"Row 2: {bg2}")
print(f"Row 3: {bg3}")

# Unique bigrams per row
unique1 = set(bg1)
unique2 = set(bg2)
unique3 = set(bg3)

# Common bigrams
common = unique1 & unique2 & unique3
print(f"\nCommon bigrams: {sorted(common)}")
print(f"Only in Row 1: {unique1 - unique2 - unique3}")
print(f"Only in Row 2: {unique2 - unique1 - unique3}")
print(f"Only in Row 3: {unique3 - unique1 - unique2}")

# Look at extra bigrams in rows 2 and 3
print("\n--- Extra Bigrams Analysis ---")
print(f"Row 2 extra (beyond row 1): {unique2 - unique1}")
print(f"Row 3 extra (beyond row 1): {unique3 - unique1}")

# What if the secret is in the EXTRA bigrams?
# Row 2 has: QK, UI  
# Row 3 has: SU
# These spell "QKUISU" - but let's check ordering

print("\n--- Position Analysis ---")
for bg in ['QK', 'UI', 'SU', 'AK', 'OA', 'PC']:
    pos = []
    for i, row in enumerate([bg1, bg2, bg3]):
        if bg in row:
            pos.append((i+1, row.index(bg)))
    print(f"{bg}: {pos}")

# Maybe it's a polybius square?
print("\n--- Polybius Square Analysis ---")
# Standard polybius 5x5 (I/J combined)
POLYBIUS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
def polybius_decode(pairs):
    result = ""
    for pair in pairs:
        if len(pair) == 2:
            # Convert letters to row/col numbers (A=1, B=2, etc)
            row = (ord(pair[0]) - ord('A')) 
            col = (ord(pair[1]) - ord('A'))
            if 0 <= row < 5 and 0 <= col < 5:
                idx = row * 5 + col
                if idx < len(POLYBIUS):
                    result += POLYBIUS[idx]
    return result

# Try treating bigrams as Polybius coordinates
print("If bigrams are coordinates (AA=A, AB=B, etc):")
for name, bgs in [("Row1", bg1), ("Row2", bg2), ("Row3", bg3)]:
    # This won't work for our bigrams since they use letters beyond E
    pass

# What if we look at first letter of each bigram?
print("\n--- First/Second Letter Extraction ---")
first_letters = [bg[0] for bg in bg1 + bg2 + bg3]
second_letters = [bg[1] for bg in bg1 + bg2 + bg3]
print(f"First letters: {''.join([bg[0] for bg in bg1])}")
print(f"Second letters: {''.join([bg[1] for bg in bg1])}")
print(f"First letters R2: {''.join([bg[0] for bg in bg2])}")
print(f"Second letters R2: {''.join([bg[1] for bg in bg2])}")
print(f"First letters R3: {''.join([bg[0] for bg in bg3])}")
print(f"Second letters R3: {''.join([bg[1] for bg in bg3])}")

# Four-Square or Two-Square cipher?
print("\n--- Four-Square Cipher Analysis ---")
# In four-square, you use 4 grids. The bigram output comes from opposite corners

# Let's try taking column reads
print("\n--- Column Reading ---")
max_len = max(len(ct1), len(ct2), len(ct3))
cols = []
for i in range(max_len):
    col = ""
    for ct in [ct1, ct2, ct3]:
        if i < len(ct):
            col += ct[i]
    cols.append(col)
print("Columns:", cols)
print("Joined:", "".join(cols))

# Diagonal reads
print("\n--- Diagonal Reading ---")
# Arrange as matrix
matrix = [list(ct1), list(ct2), list(ct3)]
# Pad to equal length
max_col = max(len(r) for r in matrix)
for r in matrix:
    while len(r) < max_col:
        r.append(' ')

diag1 = ""
for i in range(min(3, max_col)):
    diag1 += matrix[i][i]
print(f"Main diagonal start: {diag1}")

# What if we need to find the ORDER?
print("\n--- Bigram Order Analysis ---")
# Perhaps the secret is which ORDER gives valid words
import itertools
# Take common bigrams and try permutations
common_list = sorted(common)
print(f"8 common bigrams: {common_list}")

# Try Playfair with different keys
import string
def create_playfair_grid(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    grid = []
    for c in key + string.ascii_uppercase.replace('J', ''):
        if c not in seen and c.isalpha():
            grid.append(c)
            seen.add(c)
    return [grid[i:i+5] for i in range(0, 25, 5)]

def find_position(grid, char):
    char = char.upper()
    if char == 'J': char = 'I'
    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell == char:
                return r, c
    return None, None

def playfair_decrypt(ciphertext, key):
    grid = create_playfair_grid(key)
    plaintext = ""
    ct = ciphertext.upper().replace('J', 'I')
    for i in range(0, len(ct), 2):
        if i+1 >= len(ct):
            break
        a, b = ct[i], ct[i+1]
        r1, c1 = find_position(grid, a)
        r2, c2 = find_position(grid, b)
        if r1 is None or r2 is None:
            plaintext += a + b
            continue
        if r1 == r2:
            plaintext += grid[r1][(c1-1) % 5] + grid[r2][(c2-1) % 5]
        elif c1 == c2:
            plaintext += grid[(r1-1) % 5][c1] + grid[(r2-1) % 5][c2]
        else:
            plaintext += grid[r1][c2] + grid[r2][c1]
    return plaintext

# Try many more keys
print("\n--- Extended Key Search ---")
keys_to_try = [
    "FAIRNESS", "DECEPTIVE", "DECEPTION", "FAIR", "PLAYFAIR",
    "UNFAIR", "CHEAT", "SECRET", "HIDDEN", "CRYPTO", "FLAG",
    "DECEIVE", "DECEIVER", "TRUTH", "LIES", "FAIRPLAY",
    "BALANCE", "EQUAL", "JUSTICE", "HONEST"
]

for key in keys_to_try:
    pt1 = playfair_decrypt(ct1, key)
    pt2 = playfair_decrypt(ct2, key)
    pt3 = playfair_decrypt(ct3, key)
    # Look for readable patterns
    combined = pt1 + pt2 + pt3
    if any(word in combined.upper() for word in ['FLAG', 'THE', 'KEY', 'SECRET', 'ANSWER']):
        print(f"Key '{key}':")
        print(f"  {pt1}")
        print(f"  {pt2}")
        print(f"  {pt3}")

# Maybe it's NOT Playfair at all
# Look for XOR patterns
print("\n--- XOR Analysis ---")
# Check if there's a XOR relationship between rows
def xor_strings(s1, s2):
    result = []
    for i in range(min(len(s1), len(s2))):
        result.append(chr(ord(s1[i]) ^ ord(s2[i])))
    return "".join(result)

print(f"CT1 XOR CT2: {repr(xor_strings(ct1, ct2))}")
print(f"CT1 XOR CT3: {repr(xor_strings(ct1, ct3))}")
print(f"CT2 XOR CT3: {repr(xor_strings(ct2, ct3))}")

# Maybe simple substitution?
print("\n--- Frequency Analysis ---")
from collections import Counter
all_text = ct1 + ct2 + ct3
freq = Counter(all_text)
print(f"Frequency: {freq.most_common()}")

# Try Caesar on different parts
print("\n--- Caesar Shifts ---")
def caesar_decrypt(text, shift):
    result = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base - shift) % 26 + base)
        else:
            result += c
    return result

for shift in range(26):
    dec1 = caesar_decrypt(ct1, shift)
    if 'FLAG' in dec1 or 'THE' in dec1 or 'PAIR' in dec1:
        print(f"Shift {shift}: {dec1}")

# Maybe we need to extract based on position differences
print("\n--- Bigram Position Correlation ---")
# Create alignment showing where each bigram appears
all_bigrams_set = unique1 | unique2 | unique3
for bg in sorted(all_bigrams_set):
    p1 = bg1.index(bg) if bg in bg1 else -1
    p2 = bg2.index(bg) if bg in bg2 else -1
    p3 = bg3.index(bg) if bg in bg3 else -1
    print(f"{bg}: [{p1:2}, {p2:2}, {p3:2}]")

# Perhaps the key is in extracting unique elements
print("\n--- Unique Element Analysis ---")
only_r1 = unique1 - (unique2 | unique3)
only_r2 = unique2 - (unique1 | unique3)  
only_r3 = unique3 - (unique1 | unique2)
print(f"Only in R1: {only_r1}")
print(f"Only in R2: {only_r2}")
print(f"Only in R3: {only_r3}")

# Row 2 has QK, UI (FD appears twice so still just QK, UI)
# Row 3 has SU
# These: QK UI SU = QKUISU?

print("\n--- Secret from Unique Bigrams ---")  
# Order by appearance in their rows
r2_unique = [bg for bg in bg2 if bg in only_r2]
r3_unique = [bg for bg in bg3 if bg in only_r3]
print(f"R2 unique in order: {r2_unique}")
print(f"R3 unique in order: {r3_unique}")

# All unique bigrams combined
all_unique = list(only_r1) + r2_unique + r3_unique
print(f"All unique: {all_unique}")
print(f"Joined: {''.join(all_unique)}")
