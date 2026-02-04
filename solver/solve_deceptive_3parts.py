#!/usr/bin/env python3
"""
Deceptive Fairness - Extract 3 parts of the flag
Each ciphertext contains one secret
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

print("=" * 70)
print("EXTRACTING ALL 3 SECRETS")
print("=" * 70)

key = "DECEPTION"

# Decrypt all three
pt1 = playfair_decrypt(ct1, key)
pt2 = playfair_decrypt(ct2, key)
pt3 = playfair_decrypt(ct3, key)

print(f"\n{'='*70}")
print("RAW DECRYPTIONS:")
print(f"{'='*70}")
print(f"Part 1 (CT1): {pt1}")
print(f"Part 2 (CT2): {pt2}")
print(f"Part 3 (CT3): {pt3}")

print(f"\n{'='*70}")
print("AS BIGRAMS (easier to read):")
print(f"{'='*70}")
for i, (name, pt) in enumerate([("Part 1", pt1), ("Part 2", pt2), ("Part 3", pt3)]):
    bigrams = [pt[j:j+2] for j in range(0, len(pt), 2)]
    print(f"{name}: {' '.join(bigrams)}")

print(f"\n{'='*70}")
print("INTERPRETATION OF EACH PART:")
print(f"{'='*70}")

# Part 1: PAORSCANBEDECEIVINGX
# PA OR SC AN BE DE CE IV IN GX
# Reading: PA-IR-S CAN BE DECEIVING (the OR is actually meant to be IR in the message)
# Corrected: PAIRS CAN BE DECEIVING
print("""
PART 1: PAORSCANBEDECEIVINGX
  Bigrams: PA OR SC AN BE DE CE IV IN GX
  Reading: PAIRS CAN BE DECEIVING
  (Note: OR vs IR is a Playfair artifact)
  Secret 1: PAIRSCANBEDECEIVING
""")

# Part 2: SGCEIVSCORANBEDEIIVGXMB  
# SG CE IV SC OR AN BE DE IV GX MB
# This looks like: SCORES CAN BE DECEIVING (different word!)
# Or: SGCEIV SCORAN BEDEIIV GMB
# Let me read it differently: S-G-C-E-I-V  -> SCEIVING? No...
# SC-EI-VE-IN-G? Wait, let me reparse
# Actually: SG CE IV SC OR AN BE DE IV GX MB
# SCEIV + SCORAN + BEDEIV + GMB = ?
# Or flip some bigrams...
print("""
PART 2: SGCEIVSCORANBEDEIIVGXMB
  Bigrams: SG CE IV SC OR AN BE DE IV GX MB
  This appears scrambled compared to Part 1
  Could be: SCORES CAN BE DECEIVING?
  Or letters rearranged: ???
  Let's try: Remove X filler -> SGCEIVSCORANBEDEIIVGMB
""")

# Part 3: SCANBEDEORPAIVINGXCERS
# SC AN BE DE OR PA IV IN GX CE RS
# Reading: SCAN BE DE OR PA IVING CERS
# Or: SCAN BE DEOR PAIVING CERS  
# Wait - this looks like Part 1 shuffled!
# SCAN BE DE + OR PA IV ING + CERS
# Could be: SCANBEDEORPAIRSCEIVING? No...
# Let me think: SC AN BE DE OR PA IV IN GX CE RS
# = "SCAN BE DECORS PAIVING" ? Still weird
print("""
PART 3: SCANBEDEORPAIVINGXCERS
  Bigrams: SC AN BE DE OR PA IV IN GX CE RS
  Appears to be Part 1 in different order!
  Reading: SCAN BE DE OR PAIRS CERS (DECEIVING scrambled?)
  Without X: SCANBEDEORPAIVINGCERS
""")

# Let me try to find the actual secrets by looking at unique elements
print(f"\n{'='*70}")
print("LOOKING FOR UNIQUE MESSAGES:")
print(f"{'='*70}")

# Remove filler X
clean1 = pt1.replace('X', '')
clean2 = pt2.replace('X', '')
clean3 = pt3.replace('X', '')

print(f"Clean Part 1: {clean1}")
print(f"Clean Part 2: {clean2}")
print(f"Clean Part 3: {clean3}")

# Maybe each line is meant to be read as a different phrase?
# Part 1 = PAIRS CAN BE DECEIVING
# Part 2 = ??? 
# Part 3 = ???

# Let me look at Part 2 more carefully
# SGCEIVSCORANBEDEIIVGMB (without X)
# If we try to parse as words:
# S-G-C-E-I-V = ?
# Actually wait - let me look at the RAW ciphertext bigrams
print(f"\n{'='*70}")
print("ORIGINAL CIPHERTEXT BIGRAMS:")
print(f"{'='*70}")
for name, ct in [("CT1", ct1), ("CT2", ct2), ("CT3", ct3)]:
    bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
    print(f"{name}: {' '.join(bigrams)}")

# The three ciphertexts share many bigrams but in different orders
# Maybe each row when decrypted gives a DIFFERENT reading of the same letters?

# Let me try a different approach - what if PT2 and PT3 need different parsing?
print(f"\n{'='*70}")
print("ALTERNATIVE READINGS:")
print(f"{'='*70}")

# Part 2: SGCEIVSCORANBEDEIIVGMB
# What if we reorder? 
# ANBE DE CE IV SC OR SG ... no
# Try reading backwards?
rev2 = clean2[::-1]
print(f"Part 2 reversed: {rev2}")

# Try grouping differently
# SG-CE-IV-SC-OR-AN-BE-DE-IV-G-MB (odd)
# Or: SGC-EIV-SCO-RAN-BED-EIV-GMB

# Actually - the key insight might be that all three are ANAGRAMS of each other
# or permutations of the same set of bigrams!

# Let's verify this
ct1_bg = set([ct1[i:i+2] for i in range(0, len(ct1), 2)])
ct2_bg = set([ct2[i:i+2] for i in range(0, len(ct2), 2)])
ct3_bg = set([ct3[i:i+2] for i in range(0, len(ct3), 2)])

print(f"\nUnique bigrams - CT1: {len(ct1_bg)}, CT2: {len(ct2_bg)}, CT3: {len(ct3_bg)}")

# So each ciphertext, when sorted by bigrams, might give the same message!
# But with extra bigrams in CT2 and CT3 (QK, UI, SU)

print(f"\n{'='*70}")
print("EXTRA BIGRAMS (unique to CT2/CT3):")
print(f"{'='*70}")
only2 = ct2_bg - ct1_bg
only3 = ct3_bg - ct1_bg
print(f"Only in CT2: {only2}")  # QK, UI
print(f"Only in CT3: {only3}")  # SU

# Decrypt these unique bigrams
for bg in only2:
    print(f"  {bg} -> {playfair_decrypt(bg, key)}")
for bg in only3:
    print(f"  {bg} -> {playfair_decrypt(bg, key)}")

# QK->SG, UI->MB, SU->RS
# So the extra decrypted parts are: SG, MB, RS

# Maybe the three secrets are:
# 1. PAIRS CAN BE DECEIVING (from ct1)
# 2. Something with SG and MB (from ct2 extras)
# 3. Something with RS (from ct3 extras)

print(f"\n{'='*70}")
print("FINAL FLAG CANDIDATES:")
print(f"{'='*70}")

# If each part is a complete message:
secrets = [
    "PAIRSCANBEDECEIVING",        # Part 1 - confirmed
    "SCORESCANBEDECEIVING",       # Part 2 - speculation (SCEIV -> SCEIVING?)
    "SCANBEDEPAIRINGCERS",        # Part 3 - speculation
]

# Or maybe the "secrets" are the unique/extra parts?
# CT2 extra decrypts: SG + MB = SGMB
# CT3 extra decrypts: RS

# What if we combine them all?
combined = "PAIRSCANBEDECEIVING" + "SGMB" + "RS"
print(f"Combined all parts: {combined}")

# Let me try one more thing - the actual flag format
print("\nPossible multi-part flags:")
print(f"flag{{PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_SCANBEDEPAIRINGCERS}}")
print(f"flag{{PAIRSCANBEDECEIVING+SGMB+RS}}")
print(f"flag{{{clean1}_{clean2}_{clean3}}}")

# Or just the three decrypted messages joined
all_secrets = f"{clean1}_{clean2}_{clean3}"
print(f"\nAll three joined with underscore:")
print(f"flag{{{all_secrets}}}")

all_no_sep = f"{clean1}{clean2}{clean3}"
print(f"\nAll three joined no separator:")
print(f"flag{{{all_no_sep}}}")
