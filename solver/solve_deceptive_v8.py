#!/usr/bin/env python3
"""
Debug the discrepancy: encrypted PAIRSCANBEDECEIVING gives AKNMRP... but CT1 is AKNQRP...
Position 3 differs: M vs Q
"""

import string

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

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

def playfair_encrypt(plaintext, key):
    grid = create_grid(key)
    pt = plaintext.upper().replace('J', 'I')
    prepared = ""
    i = 0
    while i < len(pt):
        prepared += pt[i]
        if i + 1 < len(pt) and pt[i] == pt[i+1]:
            prepared += 'X'
        i += 1
    if len(prepared) % 2 == 1:
        prepared += 'X'
    
    ciphertext = ""
    for i in range(0, len(prepared), 2):
        a, b = prepared[i], prepared[i+1]
        r1, c1 = find_pos(grid, a)
        r2, c2 = find_pos(grid, b)
        if r1 == r2:
            ciphertext += grid[r1][(c1+1) % 5] + grid[r2][(c2+1) % 5]
        elif c1 == c2:
            ciphertext += grid[(r1+1) % 5][c1] + grid[(r2+1) % 5][c2]
        else:
            ciphertext += grid[r1][c2] + grid[r2][c1]
    return ciphertext

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

print("=" * 60)
print("DEBUGGING THE M vs Q DISCREPANCY")
print("=" * 60)

# CT1 has 'Q' at position 3
# Encrypting PAIRSCANBEDECEIVING gives 'M' at position 3

# This means the actual plaintext bigram at that position differs
# Position 3-4 in CT1 is "QR" 
# Position 3-4 in our encrypted version would be "MR"

# Let's see what "QR" decrypts to with DECEPTION
print(f"\nCT1[2:4] = {ct1[2:4]}")  # NQ
print(f"CT1[3:5] = {ct1[3:5]}")  # QR

# Actually, let me look at bigrams properly
# CT1 = AK NQ RP BA OT EC PC FD OA HW
# Encrypted PAIRSCAN... = AK NM RP BA OT EC PC FD OA HW (hypothetically)

enc_test = playfair_encrypt("PAIRSCANBEDECEIVING", "DECEPTION")
print(f"\nEncrypting PAIRSCANBEDECEIVING with DECEPTION:")
print(f"  Result:  {enc_test}")
print(f"  CT1:     {ct1}")

# Find difference
for i, (c1, c2) in enumerate(zip(enc_test, ct1)):
    if c1 != c2:
        print(f"  Diff at position {i}: '{c1}' vs '{c2}'")

# So NM vs NQ at position 2-3
# This means bigram 1 differs: NM vs NQ

# What would NQ decrypt to?
print(f"\nBigram analysis:")
print(f"  NQ (from CT1) decrypts to: {playfair_decrypt('NQ', 'DECEPTION')}")
print(f"  NM (from our encryption) decrypts to: {playfair_decrypt('NM', 'DECEPTION')}")

# So the actual plaintext has "OR" where we expected "IR"
# PAIRSCAN... vs PAORSCAN...

# This suggests the actual message IS "PAORSCANBEDECEIVING"
# Not "PAIRSCANBEDECEIVING"

print("\n" + "=" * 60)
print("CONCLUSION: The actual message is 'PAORSCANBEDECEIVING'")
print("=" * 60)

# So the flag might literally be PAORSCANBEDECEIVING
# Or we need to interpret PA ORS CAN BE DECEIVING

# "PA ORS" doesn't make sense in English
# But wait - maybe it's a different language?
# Or the message is intentionally scrambled?

# Let me try different interpretations
print("\n--- Interpretations of PAORSCANBEDECEIVING ---")

# 1. Could be an anagram?
from itertools import permutations

# 2. Maybe the spaces are different?
# PA ORS CAN BE DECEIVING
# or
# PA OR SCAN BE DECEIVING  <- "PA OR SCAN BE DECEIVING"?
# or
# PAOR SCAN BE DECEIVING
# or 
# P AORS CAN BE DECEIVING

print("Possible word splits:")
print("  PA ORS CAN BE DECEIVING")
print("  PAOR SCAN BE DECEIVING")  
print("  PA OR SCAN BE DECEIVING")
print("  P AORS CAN BE DECEIVING")

# 3. Maybe it's not English words at all
# Maybe PAORSCANBEDECEIVING is the actual flag

print("\n--- All possible flags ---")
possibilities = [
    # Raw messages
    "PAORSCANBEDECEIVING",
    "paorscanbedeceiving",
    
    # If interpreting as "pairs can be deceiving" despite the O
    "PAIRSCANBEDECEIVING", 
    "pairscanbedeceiving",
    
    # With underscores
    "PAORS_CAN_BE_DECEIVING",
    "paors_can_be_deceiving",
    "PAIRS_CAN_BE_DECEIVING",
    "pairs_can_be_deceiving",
    
    # Key only
    "DECEPTION",
    "deception",
    
    # Combination
    "PAORSCANBEDECEIVINGDECEPTION",
]

for p in possibilities:
    print(f"flag{{{p}}}")

# Let me also check if there's another key that gives cleaner output
print("\n--- Searching for cleaner key ---")
# If the intended message is "PAIRSCANBEDECEIVING", what key would encrypt it to ct1?

# We need: encrypt("PAIRSCANBEDECEIVING", key) == ct1
# Let's try bruteforce on simple keys

for key in ["FAIR", "FAIRNESS", "DECEIVE", "PAIRS", "LYING", "CHEAT", 
            "TRUTH", "FALSE", "HONEST", "EQUAL", "JUSTICE"]:
    enc = playfair_encrypt("PAIRSCANBEDECEIVING", key)
    if enc == ct1:
        print(f"FOUND KEY: {key}")
    else:
        # Check similarity
        matches = sum(1 for a, b in zip(enc, ct1) if a == b)
        if matches >= 18:  # High match
            print(f"  Key '{key}' gives {matches}/{len(ct1)} matches: {enc}")

# Maybe with X filler handling
print("\n--- With X filler ---")
for key in ["DECEPTION", "FAIR", "PAIRS"]:
    for msg in ["PAXIRSCANBEDECEIVING", "PAIRSXCANBEDECEIVING", 
                "PAIRSCANBEXDECEIVING", "PAIRSCANXBEDECEIVING"]:
        enc = playfair_encrypt(msg, key)
        if enc == ct1:
            print(f"FOUND: key={key}, msg={msg}")
        elif enc[:4] == ct1[:4]:
            print(f"  Partial match: key={key}, msg={msg} -> {enc}")
