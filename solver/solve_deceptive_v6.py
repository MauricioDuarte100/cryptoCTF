#!/usr/bin/env python3
"""
Deceptive Fairness - Trying simpler interpretations
Maybe it's not about decryption at all?
"""

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

print("=" * 60)
print("SIMPLER INTERPRETATIONS")
print("=" * 60)

# What if we just need to read something directly?
# The challenge says "Everything matters" and "recover the secrets"

# Let's look at what letters ONLY appear in certain positions
print("\n--- Letter Position Analysis ---")

# All letters in all 3 strings
all_letters = set(ct1) | set(ct2) | set(ct3)
print(f"All letters used: {sorted(all_letters)}")
print(f"Count: {len(all_letters)}")

# Missing letters from alphabet
alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
missing = alphabet - all_letters
print(f"Missing from alphabet: {sorted(missing)}")
# Missing: G, J, L, M, V, X, Y, Z

# Could the MISSING letters be the answer?
missing_sorted = sorted(missing)
print(f"Missing letters as string: {''.join(missing_sorted)}")

# Or the letters that ARE present in specific orders?
print("\n--- Letters in Order of Appearance ---")
seen = []
for c in ct1 + ct2 + ct3:
    if c not in seen:
        seen.append(c)
print(f"First appearance order: {''.join(seen)}")

# What if we read just certain positions?
print("\n--- Position-based extraction ---")
# Positions 0, 5, 10, 15... (every 5th)
for step in [3, 4, 5, 6, 7]:
    extracted = ct1[::step] + ct2[::step] + ct3[::step]
    print(f"Every {step}th: {extracted}")

# What if the answer is in the BIGRAM positions?
print("\n--- Bigram as coordinates (Polybius-like) ---")
# Standard Polybius:
# 1 2 3 4 5
# A B C D E  (row 1)
# F G H I K  (row 2)
# L M N O P  (row 3)
# Q R S T U  (row 4)
# V W X Y Z  (row 5)

def polybius_standard(row, col):
    """Convert 1-5 row and 1-5 col to letter"""
    letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    idx = (row - 1) * 5 + (col - 1)
    if 0 <= idx < 25:
        return letters[idx]
    return '?'

# But our bigrams use letters as coordinates
# Maybe A=1, B=2, ... E=5, F=1, G=2, etc? (mod 5)
def letter_to_coord(c):
    return (ord(c) - ord('A')) % 5 + 1

print("\nTrying letter-to-coordinate mapping:")
for ct in [ct1, ct2, ct3]:
    bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
    result = ""
    for bg in bigrams:
        row = letter_to_coord(bg[0])
        col = letter_to_coord(bg[1])
        result += polybius_standard(row, col)
    print(f"  {ct[:20]}... -> {result}")

# What if A=0, B=1, etc and we do (first * 26 + second) mod 26?
print("\n--- Numeric combination ---")
def letter_val(c):
    return ord(c) - ord('A')

for ct in [ct1, ct2, ct3]:
    bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
    result = ""
    for bg in bigrams:
        combined = (letter_val(bg[0]) + letter_val(bg[1])) % 26
        result += chr(combined + ord('A'))
    print(f"  Sum mod 26: {result}")
    
    result2 = ""
    for bg in bigrams:
        combined = (letter_val(bg[0]) - letter_val(bg[1])) % 26
        result2 += chr(combined + ord('A'))
    print(f"  Diff mod 26: {result2}")
    
    result3 = ""
    for bg in bigrams:
        combined = (letter_val(bg[0]) * letter_val(bg[1])) % 26
        result3 += chr(combined + ord('A'))
    print(f"  Product mod 26: {result3}")

# XOR each pair
print("\n--- XOR of pairs ---")
for ct in [ct1, ct2, ct3]:
    bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
    result = ""
    for bg in bigrams:
        xored = letter_val(bg[0]) ^ letter_val(bg[1])
        result += chr((xored % 26) + ord('A'))
    print(f"  XOR: {result}")

# What if the three lines are meant to be XORed together?
print("\n--- Three-way XOR ---")
result = ""
for i in range(min(len(ct1), len(ct2), len(ct3))):
    xored = letter_val(ct1[i]) ^ letter_val(ct2[i]) ^ letter_val(ct3[i])
    result += chr((xored % 26) + ord('A'))
print(f"XOR all three: {result}")

# Average of the three
print("\n--- Average (mod 26) ---")
result = ""
for i in range(min(len(ct1), len(ct2), len(ct3))):
    avg = (letter_val(ct1[i]) + letter_val(ct2[i]) + letter_val(ct3[i])) // 3
    result += chr(avg + ord('A'))
print(f"Average: {result}")

# Maybe it's about what's CONSISTENT?
print("\n--- Consistent Patterns ---")
# Look at which bigram pairs repeat
from collections import Counter

all_bigrams = []
for ct in [ct1, ct2, ct3]:
    for i in range(0, len(ct), 2):
        all_bigrams.append(ct[i:i+2])

freq = Counter(all_bigrams)
print("Bigram frequencies:")
for bg, count in freq.most_common():
    print(f"  {bg}: {count}")

# Those that appear exactly 3 times (once per row) might be "fair"
fair_bigrams = [bg for bg, count in freq.items() if count == 3]
print(f"\nFair bigrams (appear 3x): {fair_bigrams}")
fair_msg = "".join(fair_bigrams)
print(f"Fair message: {fair_msg}")

# What if we decode these with Playfair?
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
    if char == 'J': char = 'I'
    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell == char:
                return r, c
    return None, None

def playfair_decrypt(ciphertext, key):
    grid = create_grid(key)
    plaintext = ""
    ct = ciphertext.upper().replace('J', 'I')
    for i in range(0, len(ct), 2):
        if i+1 >= len(ct): break
        a, b = ct[i], ct[i+1]
        r1, c1 = find_pos(grid, a)
        r2, c2 = find_pos(grid, b)
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

print(f"\nFair bigrams decrypted (DECEPTION): {playfair_decrypt(fair_msg, 'DECEPTION')}")

# Maybe the flag is simpler - just the bigrams that are unique?
print("\n--- Unique bigrams only ---")
in_1 = set([ct1[i:i+2] for i in range(0, len(ct1), 2)])
in_2 = set([ct2[i:i+2] for i in range(0, len(ct2), 2)])
in_3 = set([ct3[i:i+2] for i in range(0, len(ct3), 2)])

only_1 = in_1 - in_2 - in_3
only_2 = in_2 - in_1 - in_3
only_3 = in_3 - in_1 - in_2

print(f"Only in 1: {only_1}")
print(f"Only in 2: {only_2}")
print(f"Only in 3: {only_3}")

# Combined unique: empty + QK,UI + SU
unique_combined = "".join(sorted(only_1)) + "".join(sorted(only_2)) + "".join(sorted(only_3))
print(f"Unique combined: {unique_combined}")
print(f"Unique decrypted: {playfair_decrypt(unique_combined, 'DECEPTION')}")

# What about just reading row by row ignoring the cipher?
# AK NQ RP BA OT EC PC FD OA HW
# QK PC FD RP NQ BA OT EC FD HW UI
# RP BA OT EC NQ AK FD OA HW PC SU

# The pattern looks like each row has a similar set of bigrams but in different positions
# Maybe we need to ALIGN them?

print("\n--- Alignment Analysis ---")
# If we sort each row's bigrams alphabetically
sorted_1 = sorted([ct1[i:i+2] for i in range(0, len(ct1), 2)])
sorted_2 = sorted([ct2[i:i+2] for i in range(0, len(ct2), 2)])
sorted_3 = sorted([ct3[i:i+2] for i in range(0, len(ct3), 2)])

print(f"Sorted R1: {sorted_1}")
print(f"Sorted R2: {sorted_2}")
print(f"Sorted R3: {sorted_3}")

# Decode sorted
sorted_msg_1 = "".join(sorted_1)
sorted_msg_2 = "".join(sorted_2)
sorted_msg_3 = "".join(sorted_3)

print(f"\nDecoded sorted R1: {playfair_decrypt(sorted_msg_1, 'DECEPTION')}")
print(f"Decoded sorted R2: {playfair_decrypt(sorted_msg_2, 'DECEPTION')}")
print(f"Decoded sorted R3: {playfair_decrypt(sorted_msg_3, 'DECEPTION')}")
