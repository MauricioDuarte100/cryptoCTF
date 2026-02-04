#!/usr/bin/env python3
"""
Final attempt - Focus on the clear Playfair message and format it correctly
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
print("FINAL FLAG DETERMINATION")
print("=" * 60)

# Row 1 decrypts to: PAORSCANBEDECEIVINGX
# This is: PA-OR-SC-AN-BE-DE-CE-IV-IN-GX
# Reading as a phrase: PAIRS CAN BE DECEIVING (X is padding)

# But wait - "PAORS" is not "PAIRS"
# Let me double-check the decryption

pt1 = playfair_decrypt(ct1, "DECEPTION")
print(f"\nRow 1 raw: {pt1}")
print(f"Row 1 bigrams: {[pt1[i:i+2] for i in range(0, len(pt1), 2)]}")

# The bigrams are: PA OR SC AN BE DE CE IV IN GX
# If we read: PA-OR-S = "PA OR S" ... that's not right

# Actually, look at the Playfair encoding:
# "PAIRS" would be split as: PA IR S? but IR becomes separated...
# Let me trace backwards

# If the plaintext is "PAIRSCANBEDECEIVING"
# Playfair would encode: PA IR SC AN BE DE CE IV IN G(X)
# But wait - "PAIRS" in Playfair needs to handle double letters

# Actually... "PAIRS" = P-A-I-R-S, no doubles
# So it should encode as: PA + IR + SC + AN...
# But we got PA + OR, not PA + IR

# Maybe the key is different?
print("\n--- Testing alternate keys ---")
for key in ["DECEPTIVEFAIRNESS", "FAIRNESSDECEPTIVE", "DECEPTIONFAIR", 
            "FAIRDECEPTION", "FAIRPLAYFAIR", "SECRETKEY", "HIDDENKEY"]:
    pt = playfair_decrypt(ct1, key)
    if "PAIR" in pt or "AIR" in pt:
        print(f"Key '{key}': {pt}")

# Let me also consider that maybe we're supposed to read differently
# What if PAORS -> P(A)I(O)RS = PAIRS, where some letters are fillers?
print("\n--- Interpreting PAORSCANBEDECEIVINGX ---")
raw = "PAORSCANBEDECEIVINGX"

# Remove filler X
clean = raw.replace("X", "")
print(f"Without X: {clean}")

# PAORSCANBEDECEIVING
# If we assume O is an artifact: PAIRSCANBEDECEIVING
# Or: PA-[ORS = AIRS?] -> No

# Actually what if the message spans ALL THREE ROWS?
# Each row might contain a piece

pt2 = playfair_decrypt(ct2, "DECEPTION")
pt3 = playfair_decrypt(ct3, "DECEPTION")

print(f"\nRow 2: {pt2}")
print(f"Row 3: {pt3}")

# Row 1: PAORSCANBEDECEIVINGX -> PAIRS CAN BE DECEIVING?
# Row 2: SGCEIVSCORANBEDEIIVGXMB -> ?
# Row 3: SCANBEDEORPAIVINGXCERS -> SCAN BE DE OR PA IVING

# The message seems consistent: PAIRS CAN BE DECEIVING
# But the flag format might need to be specific

print("\n" + "=" * 60)
print("POSSIBLE FLAG FORMATS")
print("=" * 60)

# Based on "Pairs can be deceiving" as the core message
flags = [
    # Variations
    "PAIRSCANBEDECEIVING",
    "pairscanbedeceiving", 
    "PairsCanBeDeceiving",
    "pairs_can_be_deceiving",
    "PAIRS_CAN_BE_DECEIVING",
    "pairs-can-be-deceiving",
    
    # Maybe without the 's' on pairs
    "PAIRCANBEDECEIVING",
    "pair_can_be_deceiving",
    
    # Maybe the key
    "DECEPTION",
    "deception",
    
    # From the raw decryption
    "PAORSCANBEDECEIVING",
    "paorscanbedeceiving",
    
    # The full phrase
    "pairs can be deceiving",
    "PAIRS CAN BE DECEIVING",
    
    # Abbreviated
    "PCBD",
    "pcbd",
    
    # From unique bigrams (QK, UI, SU -> QKUISU)
    "QKUISU",
    "qkuisu",
    
    # Decoded unique bigrams
    "SGMBRS",
    "sgmbrs",
    
    # Challenge name hints
    "DECEPTIVEFAIRNESS",
    "deceptivefairness",
    
    # Other possibilities
    "DECEIVING",
    "deceiving",
    "FAIRNESS",
    "fairness",
]

for flag in flags:
    print(f"flag{{{flag}}}")

# One more idea - maybe the flag is more literal
# "Everything matters" - use the ENTIRE message from all 3 rows?
print("\n--- Combined message ---")
all_pt = pt1 + pt2 + pt3
print(f"All plaintext: {all_pt}")
clean_all = all_pt.replace("X", "")
print(f"Cleaned: {clean_all}")

# Maybe it's just the common parts repeated across all three?
# Looking for what appears consistently

# Or maybe it's about the ORIGINAL ciphertext structure
print("\n--- Original Structure Analysis ---")
print(f"CT1 length: {len(ct1)}")
print(f"CT2 length: {len(ct2)}")  
print(f"CT3 length: {len(ct3)}")

# 20, 22, 22 - row 2 and 3 have 2 extra characters each
# UI and SU are the extras
# Together: UI + SU = UISU
# Decoded with DECEPTION: UI->MB, SU->RS = MBRS
print(f"\nExtra characters decoded:")
print(f"UI (from row 2) -> {playfair_decrypt('UI', 'DECEPTION')}")
print(f"SU (from row 3) -> {playfair_decrypt('SU', 'DECEPTION')}")
