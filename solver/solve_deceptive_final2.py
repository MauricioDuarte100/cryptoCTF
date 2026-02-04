#!/usr/bin/env python3
"""
Final attempt - Based on team insight:
Part 3 = "SCAN BE DECEIVING PAIRS"

Let's work backwards from the known phrases:
1. PAIRS CAN BE DECEIVING - classic phrase ✓
2. ??? CAN BE DECEIVING - What fits Part 2?
3. From team: Something like "SCAN BE DECEIVING PAIRS"

The pattern seems to be anagram variations of the same letters!
"""

# Decoded bigrams
part1 = "PAORSCANBEDECEIVING"  # Actually decrypts to this
part2 = "SGCEIVSCORANBEDEIIVGMB"  # Without X  
part3 = "SCANBEDEORPAIVINGCERS"  # Without X

print("=" * 70)
print("ANAGRAM ANALYSIS OF ALL THREE PARTS")
print("=" * 70)

# Sort letters of each part
sorted1 = ''.join(sorted(part1))
sorted2 = ''.join(sorted(part2))
sorted3 = ''.join(sorted(part3))

print(f"\nPart 1 sorted: {sorted1}")
print(f"Part 2 sorted: {sorted2}")
print(f"Part 3 sorted: {sorted3}")

# They're NOT exact anagrams - Part 2 and 3 have extra letters
# Part 1: 19 chars
# Part 2: 21 chars (+2)
# Part 3: 21 chars (+2)

# The "extra" content in Parts 2 and 3 are the unique decrypted bigrams:
# Part 2: SG (from QK) and MB (from UI)  
# Part 3: RS (from SU)

# So the BASE is: PAORSCANBEDECEIVING (or PAIRSCANBEDECEIVING)
# Part 2 adds: SG + MB = "SGMB" 
# Part 3 adds: RS

# Wait - what if:
# Part 1 secret = PAIRS CAN BE DECEIVING
# Part 2 secret = Part 1 + some modifier
# Part 3 secret = Part 1 + some modifier

# Actually, let me check if the letters in Parts 2&3 minus Part 1 spell something
print("\n" + "=" * 70)
print("EXTRA LETTERS ANALYSIS")
print("=" * 70)

from collections import Counter

c1 = Counter(part1)
c2 = Counter(part2)
c3 = Counter(part3)

extra2 = c2 - c1
extra3 = c3 - c1

print(f"Extra letters in Part 2: {dict(extra2)}")
print(f"Extra letters in Part 3: {dict(extra3)}")

# Part 2 extra: S, G, I, V, M, B (SGMB + duplicate IV)
# Part 3 extra: R, S (RS)

# Hmmm, could SGMB mean something? Or RS?

# Different approach: what actual phrases could Part 2 represent?
print("\n" + "=" * 70)
print("PHRASE INTERPRETATION ATTEMPTS")
print("=" * 70)

# Part 2 decoded in order: SG CE IV SC OR AN BE DE IV GX MB
# Reading attempts:
print("""
Part 2: SG CE IV SC OR AN BE DE IV GX MB

Possible readings:
1. SCEIV SCORAN BEDEIV GMB (nonsense)
2. SC OR AN BE DE CE IV IV G SG MB (reordered) = SCORES AN BE DECEIVING?
   But that missing letters...
3. DECEIVING SCORES AN BE? 
4. SCORES CAN BE DECEIVING - but we need E-S for SCORES

What if SG = part of a word?
- FALSIFYING? No
- DISGUISING? Contains SG!
- MESSAGING? Contains SG

Hmm, DISGUISING CAN BE DECEIVING?
""")

# Let me try another Playfair key that might give "LOOKS"
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

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

# Try keys that produce "LOOKS" at the start of CT2
print("\n" + "=" * 70)
print("SEARCHING FOR KEY THAT GIVES 'LOOKS'")
print("=" * 70)

# For CT2, the first bigram is QK
# We want QK -> LO
# What Playfair key makes this happen?

# Brute force single-word keys
words = ["LOOKS", "FACE", "APPEARANCE", "FIRST", "SECOND", "IMPRESSIONS",
         "BEAUTY", "UGLY", "TRUE", "FALSE", "REAL", "FAKE", "HONEST",
         "VISION", "SIGHT", "EYES", "SEEM", "APPEAR", "SHOW", "HIDE"]

for key in words:
    dec = playfair_decrypt("QK", key)
    if dec == "LO":
        print(f"Found! Key '{key}' makes QK->LO")
        print(f"Full CT2 with key '{key}': {playfair_decrypt(ct2, key)}")

# Let me also try concatenated keys
for k1 in ["LOOKS", "PAIRS", "FAIR"]:
    for k2 in ["DECEIVING", "DECEPTION", "CANBEFAIRNESS"]:
        key = k1 + k2
        dec = playfair_decrypt("QK", key)
        if "LO" in dec or "OK" in dec:
            print(f"Key '{key}': QK->{dec}")

# Maybe the three ciphertexts use THREE DIFFERENT KEYS?
print("\n" + "=" * 70)
print("MAYBE DIFFERENT KEYS FOR EACH ROW?")
print("=" * 70)

# If the three secrets are:
# 1. PAIRS CAN BE DECEIVING (key = DECEPTION works)
# 2. LOOKS CAN BE DECEIVING (need different key)
# 3. APPEARANCES CAN BE DECEIVING (need different key)

# For each target, find a key that produces it
targets = {
    "CT1": ("PAIRSCANBEDECEIVING", ct1),
    "CT2": ("LOOKSCANBEDECEIVING", ct2),
    "CT3": ("APPEARANCESCANBEDECEIVING", ct3)
}

test_keys = ["DECEPTION", "FAIRNESS", "DECEPTIVE", "FAIR", "UNFAIR", 
             "LOOKS", "PAIRS", "APPEARANCE", "SECRET", "HIDDEN",
             "CRYPTO", "CIPHER", "PLAYFAIR", "KEY", "FLAG"]

for name, (target, ct) in targets.items():
    print(f"\n{name}: Trying to get '{target[:20]}...'")
    for key in test_keys:
        dec = playfair_decrypt(ct, key)
        if target[:10] in dec:
            print(f"  Key '{key}': {dec}")
        # Also check partial matches
        match_count = sum(1 for a, b in zip(dec, target) if a == b)
        if match_count > 12:
            print(f"  Key '{key}' ({match_count} matches): {dec}")

# Final flag attempts based on the classic phrases pattern
print("\n" + "=" * 70)
print("FINAL FLAG CANDIDATES")
print("=" * 70)

final_flags = [
    # Three classic "X can be deceiving" phrases
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_APPEARANCESCANBEDECEIVING",
    "pairscanbedeceiving_lookscanbedeceiving_appearancescanbedeceiving",
    
    # With just the key words
    "PAIRS_LOOKS_APPEARANCES",
    "pairs_looks_appearances", 
    
    # Lower/upper variations
    "PairsCanBeDeceiving_LooksCanBeDeceiving_AppearancesCanBeDeceiving",
    
    # Maybe underscores as spaces
    "PAIRS CAN BE DECEIVING_LOOKS CAN BE DECEIVING_APPEARANCES CAN BE DECEIVING",
    
    # All one string
    "PAIRSCANBEDECEIVINGLOOKSCANBEDECEIVINAGAPPEARANCESCANBEDECEIVING",
    
    # Raw decryptions
    "PAORSCANBEDECEIVING_SGCEIVSCORANBEDEIVGMB_SCANBEDEORPAIVINGCERS",
    
    # Team's Part 3 hint incorporated  
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
]

for f in final_flags:
    print(f"flag{{{f}}}")
