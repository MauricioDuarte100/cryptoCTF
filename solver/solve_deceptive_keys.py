#!/usr/bin/env python3
"""
Deceptive Fairness - Try different keys for each part
Common phrases: "X CAN BE DECEIVING"
- Looks can be deceiving
- Appearances can be deceiving
- Pairs can be deceiving
"""

import string
from itertools import permutations

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

# Target phrases (common "X CAN BE DECEIVING" phrases)
target_phrases = [
    "PAIRSCANBEDECEIVING",
    "LOOKSCANBEDECEIVING", 
    "SCORESCANBEDECEIVING",
    "FACESCANBEDECEIVING",
    "SEEMSCANBEDECEIVING",
    "FIRSTIMPRXESSIONSCANBEDECEIVING",
    "APPEARANCESCANBEDECEIVING",
    "STATISTICSCANBEDECEIVING",
]

# Try many keys
keys_to_try = [
    "DECEPTION", "DECEPTIVE", "FAIRNESS", "FAIR", "UNFAIR",
    "PLAYFAIR", "SECRET", "HIDDEN", "CIPHER", "CRYPTO",
    "LOOKS", "PAIRS", "SCORES", "FACES", "TRUTH", "LIES",
    "APPEAR", "APPEARANCE", "DECEIVE", "DECEIVER", "TRICK",
    "CHEAT", "FALSE", "TRUE", "HONEST", "DISHONEST",
    "KEY", "PASSWORD", "FLAG", "CTF", "HACK",
    "ABCDEFGHIKLMNOPQRSTUVWXYZ",  # Standard alphabet
    "DECEIVERS", "STATISTICS", "IMPRESSIONS",
]

print("=" * 70)
print("SEARCHING FOR CORRECT KEYS")
print("=" * 70)

for ct, name in [(ct1, "CT1"), (ct2, "CT2"), (ct3, "CT3")]:
    print(f"\n{name}: {ct}")
    for key in keys_to_try:
        pt = playfair_decrypt(ct, key).replace('X', '')
        # Check if it matches any target phrase pattern
        for target in target_phrases:
            if target[:10] in pt or pt[:10] in target:
                print(f"  Key '{key}': {pt}")
                break
        # Also check for common word patterns
        if "CANBE" in pt or "DECEIV" in pt or "LOOKS" in pt or "PAIRS" in pt:
            print(f"  Key '{key}': {pt}")

# Maybe the key is different for each!
print("\n" + "=" * 70)
print("TESTING KEY COMBINATIONS")
print("=" * 70)

# Based on the pattern, each row might need a different key
# But they all decrypt to "X CAN BE DECEIVING" patterns

# Let's try the DECEPTION key and manually parse
print("\nWith DECEPTION key:")
for ct, name in [(ct1, "Part 1"), (ct2, "Part 2"), (ct3, "Part 3")]:
    pt = playfair_decrypt(ct, "DECEPTION")
    bigrams = [pt[i:i+2] for i in range(0, len(pt), 2)]
    print(f"{name}: {' '.join(bigrams)}")

# Team's insight: Part 3 might be "SCAN BE DECEIVING PAIRS"
# Let me verify: SC AN BE DE CE IV IN G? PA IR S?
# But Part 3 bigrams are: SC AN BE DE OR PA IV IN GX CE RS
# That's: SCAN BEDE ORPA IVING (X filler) CERS

# What if we REORDER the bigrams to make sense?
print("\n" + "=" * 70)
print("REORDERING BIGRAMS TO MAKE PHRASES")
print("=" * 70)

# Part 3 bigrams: SC AN BE DE OR PA IV IN GX CE RS
# If reordered to: PA OR SC AN BE DE CE IV IN GX RS?
# That would give "PAIRS CAN BE DECEIVING" + RS

# Actually, what if the three phrases are:
# 1. PAIRS CAN BE DECEIVING
# 2. LOOKS CAN BE DECEIVING 
# 3. APPEARANCES CAN BE DECEIVING

# Let's see if Part 2 could decrypt to LOOKS...
print("\nPart 2 analysis:")
pt2 = playfair_decrypt(ct2, "DECEPTION")
print(f"Raw: {pt2}")
# SG CE IV SC OR AN BE DE IV GX MB
# What if SG should be LO? Let's check what key makes that happen

# Try to find a key that decrypts ct2 to start with "LO"
print("\nSearching for key that gives 'LO' from 'QK' (first bigram of ct2):")
# QK -> LO with what key?
for key in keys_to_try:
    pt = playfair_decrypt("QK", key)
    if pt == "LO":
        print(f"  Found! Key '{key}' makes QK -> LO")
        full_pt = playfair_decrypt(ct2, key)
        print(f"  Full decrypt: {full_pt}")

# Hmm, let me try another approach
# What if it's NOT Playfair but a simpler substitution?
print("\n" + "=" * 70)
print("TRYING SIMPLE SUBSTITUTION")
print("=" * 70)

# If we assume the plaintext is known phrases, we can derive the key
# CT1 should be "PAIRS CAN BE DECEIVING" = "PAIRSCANBEDECEIVING"
# Let's see the letter mapping

plain1 = "PAIRSCANBEDECEIVINGX"  # with X filler
cipher1 = ct1

print("CT1 mapping (if plaintext is PAIRSCANBEDECEIVING):")
for i, (p, c) in enumerate(zip(plain1, cipher1)):
    if p != c:
        print(f"  Position {i}: {p} -> {c}")

# Actually, bigram substitution for Playfair
print("\nPlayfair bigram mapping:")
plain_bg = [plain1[i:i+2] for i in range(0, len(plain1), 2)]
cipher_bg = [cipher1[i:i+2] for i in range(0, len(cipher1), 2)]
for p, c in zip(plain_bg, cipher_bg):
    print(f"  {p} -> {c}")

# So if we know the mapping, we can apply it to the other ciphertexts
print("\n" + "=" * 70)
print("DERIVING SECRETS FROM BIGRAM MAPPING")
print("=" * 70)

# Create a reverse mapping from the Part 1 analysis
# If we encrypt with DECEPTION, we get:
# PA -> AK, IR -> NM, SC -> RP, AN -> BA, BE -> OT, DE -> EC, 
# CE -> PC, IV -> FD, IN -> OA, GX -> HW

# But ct1 has NQ not NM, suggesting the plaintext is OR not IR
# So the actual mapping from ct1 is:
# PA -> AK, OR -> NQ, SC -> RP, AN -> BA, BE -> OT, DE -> EC,
# CE -> PC, IV -> FD, IN -> OA, GX -> HW

# Using this mapping, let's decode CT2 and CT3
bigram_map = {
    'AK': 'PA', 'NQ': 'OR', 'RP': 'SC', 'BA': 'AN', 'OT': 'BE',
    'EC': 'DE', 'PC': 'CE', 'FD': 'IV', 'OA': 'IN', 'HW': 'GX'
}

# CT2 extra bigrams that aren't in the map
ct2_bigrams = [ct2[i:i+2] for i in range(0, len(ct2), 2)]
ct3_bigrams = [ct3[i:i+2] for i in range(0, len(ct3), 2)]

print("CT2 bigrams and their meanings:")
for bg in ct2_bigrams:
    meaning = bigram_map.get(bg, f"??? ({playfair_decrypt(bg, 'DECEPTION')})")
    print(f"  {bg} -> {meaning}")

print("\nCT3 bigrams and their meanings:")
for bg in ct3_bigrams:
    meaning = bigram_map.get(bg, f"??? ({playfair_decrypt(bg, 'DECEPTION')})")
    print(f"  {bg} -> {meaning}")

# So the mysteries are:
# CT2: QK->SG, UI->MB
# CT3: SU->RS

# These are EXTRA content beyond Part 1!
print("\n" + "=" * 70)
print("FINAL INTERPRETATION")
print("=" * 70)
print("""
Based on the mapping:
Part 1: PA OR SC AN BE DE CE IV IN GX = "PAIRS CAN BE DECEIVING" (OR is PAIRS variant)
Part 2: SG CE IV SC OR AN BE DE IV GX MB = ??? 
Part 3: SC AN BE DE OR PA IV IN GX CE RS = ???

The extra decoded bigrams are:
- QK -> SG
- UI -> MB  
- SU -> RS

Maybe these spell something? SG + MB + RS = ???

Or the three phrases are meant to be read differently...

IMPORTANT: The team said "SCAN BE DECEIVING PAIRS"
From Part 3: SC AN BE DE CE IV IN G PA IR S (if reordered)
            = SCAN BE DECEIVING PAIRS!

So the flag might be about reordering!
""")

# Let's try the three classic phrases
final_flags = [
    # Classic phrasing with underscores
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_APPEARANCESCANBEDECEIVING",
    
    # The team's suggestion for Part 3
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # Without LOOKS, maybe SCORES?
    "PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # Lowercase versions
    "pairscanbedeceiving_lookscanbedeceiving_appearancescanbedeceiving",
    
    # Maybe just the key words?
    "PAIRS_LOOKS_APPEARANCES",
    "pairs_looks_appearances",
    
    # Or the three "X" values
    "PAIRS_SCORES_APPEARANCES",
]

print("\nPossible flags to try:")
for f in final_flags:
    print(f"flag{{{f}}}")
