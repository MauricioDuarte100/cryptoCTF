#!/usr/bin/env python3
"""
Deceptive Fairness - Final comprehensive analysis
Let's look at ALL possible interpretations
"""

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

print("=" * 60)
print("FINAL COMPREHENSIVE ANALYSIS")
print("=" * 60)

# Back to Playfair but with cleaner output
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

def find_pos(grid, char):
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

# Let's look more carefully at the DECEPTION decryption
print("\n--- DECEPTION Key Analysis ---")
key = "DECEPTION"
grid = create_playfair_grid(key)
print("Grid:")
for row in grid:
    print("  " + " ".join(row))

for name, ct in [("Row 1", ct1), ("Row 2", ct2), ("Row 3", ct3)]:
    pt = playfair_decrypt(ct, key)
    # Clean up X padding
    cleaned = pt.replace('X', ' ').strip()
    # Split into words
    print(f"\n{name}:")
    print(f"  Raw: {pt}")
    print(f"  Cleaned: {cleaned}")
    
    # Try to parse words
    # PAORSCANBEDECEIVING -> PAIRS CAN BE DECEIVING
    # Let me try manual parsing
    if "PAORS" in pt:
        print(f"  Parsed: P{pt[1]}AIRS CAN BE DECEIVING")

# Let's also try removing duplicates and re-analyzing
print("\n--- Clean Message Extraction ---")
# Row 1 decrypts to: PAORSCANBEDECEIVINGX
# That's: PA OR SC AN BE DE CE IV IN GX
# Which reads: pairs can be deceiving (with X as filler)

# Remove X and interpret
raw_pt = playfair_decrypt(ct1, "DECEPTION")
print(f"Raw Row 1: {raw_pt}")

# Manual fix: PAORS -> PAIRS (the 'O' should be 'I')
# Let me check if there's a different key that gives cleaner output

print("\n--- Key Bruteforce (common words) ---")
import itertools
test_keys = [
    "A", "AB", "ABCD", "KEY", "SECRET", "FLAG", "CTF",
    "FAIR", "PAIRS", "DECEIVE", "DECEPTIVE", "DECEPTION",
    "FAIRNESS", "UNFAIR", "FAIRPLAY", "PLAYFAIR", "CIPHER",
    "CRYPTO", "HIDDEN", "TRUTH", "LIES", "CHEAT"
]

best_results = []
for key in test_keys:
    pt1 = playfair_decrypt(ct1, key)
    # Check for common words
    score = 0
    for word in ["PAIR", "CAN", "BE", "DECEIV", "THE", "IS", "AND", "FLAG"]:
        if word in pt1:
            score += len(word)
    if score > 0:
        best_results.append((score, key, pt1))

best_results.sort(reverse=True)
print("Best matches:")
for score, key, pt in best_results[:5]:
    print(f"  Key '{key}' (score {score}): {pt}")

# What if we need to read the first word differently?
# PAORS -> reading each bigram: PA = first bigram, OR = second, etc
# But these are already decrypted...

# Let me check: maybe the key hint is in the title
# "Deceptive" -> DECEPTION is correct key
# "Fairness" -> maybe about "fair" distribution of message

print("\n--- Message Interpretation ---")
# The Playfair output is: PAORSCANBEDECEIVINGX
# Reading as: PA ORS CAN BE DE CE IV ING X
# 
# "PA ORS" is weird. But if we read it as one string without spaces:
# PAORSCANBEDECEIVINGX
#
# Looking closer: 
# - PAIRSCANBEDECEIVING (with filler)
# - The 'O' might be an artifact

# Try just removing filler
msg = playfair_decrypt(ct1, "DECEPTION")
# Remove X at end and any standalone X
clean_msg = msg.rstrip('X')
clean_msg = clean_msg.replace('XS', 'S').replace('XC', 'C')  # Common Playfair patterns
print(f"Cleaned message: {clean_msg}")

# The message seems to be: PAIRS CAN BE DECEIVING
# Let's try different flag formats

print("\n" + "=" * 60)
print("POSSIBLE FLAGS based on 'PAIRS CAN BE DECEIVING':")
print("=" * 60)

# Various formatting options
base = "PAIRSCANBEDECEIVING"
variations = [
    base,
    base.lower(),
    "pairs_can_be_deceiving",
    "PAIRS_CAN_BE_DECEIVING",
    "pairscanbedeceiving",
    # Maybe without the 's' on pairs?
    "PAIRCANBEDECEIVING",
    "paircanbedeceiving",
    # Or just the key message parts
    "DECEPTION",
    "deception", 
    "DECEIVING",
    "deceiving",
    # With spaces as underscores
    "pairs-can-be-deceiving",
    # CamelCase
    "PairsCanBeDeceiving",
    "pairsCanBeDeceiving",
    # Maybe it's the key itself
    "DECEPTION",
]

for v in variations:
    print(f"flag{{{v}}}")

# Or maybe we need to look at what's UNIQUE across all three rows
print("\n--- Extracting from Unique Elements ---")
# Row 2 has QK, UI that are unique
# Row 3 has SU that is unique
# Maybe: QK + UI + SU = QKUISU

# But also we should check if these bigrams decrypt to something
print("\nUnique bigrams decrypted with DECEPTION key:")
for bg in ['QK', 'UI', 'SU']:
    decrypted = playfair_decrypt(bg, "DECEPTION")
    print(f"  {bg} -> {decrypted}")

# Maybe the "extra" at the end of rows 2 and 3 contain the secret?
# Row 2 ends with 'UI'
# Row 3 ends with 'SU'
# Together: UISU or SUUI?

print("\n--- End Bigram Analysis ---")
extra_r2 = ct2[len(ct1):]  # Extra chars in row 2
extra_r3 = ct3[len(ct1):]  # Extra chars in row 3
print(f"Extra in Row 2: {extra_r2}")
print(f"Extra in Row 3: {extra_r3}")

# Decrypt these extras
if extra_r2:
    print(f"R2 extra decrypted: {playfair_decrypt(extra_r2, 'DECEPTION')}")
if extra_r3:
    print(f"R3 extra decrypted: {playfair_decrypt(extra_r3, 'DECEPTION')}")

# Wait - let me check all 3 full decryptions more carefully
print("\n--- All Three Full Decryptions ---")
for name, ct in [("Row 1", ct1), ("Row 2", ct2), ("Row 3", ct3)]:
    pt = playfair_decrypt(ct, "DECEPTION")
    # Parse into likely words
    print(f"{name}: {pt}")
    # Clean version
    words = []
    i = 0
    s = pt.replace('X', '')  # Remove fillers
    print(f"       Without X: {s}")

# What if the actual secret is hidden in a specific pattern?
# Let's try to find what the three plaintexts have in common
pt1 = playfair_decrypt(ct1, "DECEPTION").replace('X', '')
pt2 = playfair_decrypt(ct2, "DECEPTION").replace('X', '')
pt3 = playfair_decrypt(ct3, "DECEPTION").replace('X', '')

print("\n--- Common Substrings ---")
# Find longest common substring
def lcs(s1, s2):
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    max_len, end_idx = 0, 0
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i-1] == s2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
                if dp[i][j] > max_len:
                    max_len = dp[i][j]
                    end_idx = i
    return s1[end_idx - max_len:end_idx]

common_12 = lcs(pt1, pt2)
common_13 = lcs(pt1, pt3)
common_23 = lcs(pt2, pt3)
print(f"Common 1-2: {common_12}")
print(f"Common 1-3: {common_13}")
print(f"Common 2-3: {common_23}")

# All three
common_all = lcs(common_12, pt3)
print(f"Common all: {common_all}")
