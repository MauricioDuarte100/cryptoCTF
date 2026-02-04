#!/usr/bin/env python3
"""
Deceptive Fairness - Extract 3 secrets by proper parsing
User hints:
- Part 1: PAIRS CAN BE DECEIVING ✓
- Part 2: Unknown
- Part 3: Maybe SCAN BE DE OR PAIVING CERS
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
print("PROPER PARSING OF 3 SECRETS")
print("=" * 70)

key = "DECEPTION"
pt1 = playfair_decrypt(ct1, key)
pt2 = playfair_decrypt(ct2, key)
pt3 = playfair_decrypt(ct3, key)

print(f"\nPart 1 bigrams: {' '.join([pt1[i:i+2] for i in range(0, len(pt1), 2)])}")
print(f"Part 2 bigrams: {' '.join([pt2[i:i+2] for i in range(0, len(pt2), 2)])}")
print(f"Part 3 bigrams: {' '.join([pt3[i:i+2] for i in range(0, len(pt3), 2)])}")

print("\n" + "=" * 70)
print("READING EACH AS ENGLISH PHRASES:")
print("=" * 70)

# Part 1: PA OR SC AN BE DE CE IV IN GX
# PAIRS CAN BE DECEIVING (with X filler at end)
# PA(I/O)RS = PAIRS
print("""
PART 1: PA OR SC AN BE DE CE IV IN GX
  -> PAIRS CAN BE DECEIVING
  Secret1: PAIRSCANBEDECEIVING
""")

# Part 2: SG CE IV SC OR AN BE DE IV GX MB
# Let's try to read this:
# SG = start?
# SG CE IV = SCEIV? DECEIV?
# Or maybe: SG-CE-IV = ... SC-OR-AN = SCORAN = SCORES AN?
# Let me try different groupings
# If we assume Part 2 is also a phrase...
# SCEIV + SCORAN + BEDEIV = ?
# Or: S CEIV SCORAN BEDEIV GM B
# Actually maybe: SCORES CAN BE DECEIVING?
# SC-OR-ES? No, there's no E-S bigram
print("""
PART 2: SG CE IV SC OR AN BE DE IV GX MB
  Looking for English words...
  SC OR = SCORES? (if S-CORES)
  AN BE DE = CAN BE DE...
  IV = ...IVING
  
  Possible: SCORES CAN BE DECEIVING?
  But SG and MB are extras...
  
  Alternative: The phrase is scrambled
  SCEIV SCORAN BEDEIV = anagram of DECEIVING SCORES?
  
  Wait - maybe it's: DECEIVING SCORES CAN BE
  Or: Can be DECEIVING SCORES?
  
  Let me try: SG MB are junk, core is CE IV SC OR AN BE DE IV
  = DECEIV + SCORAN + BEDEIV
  = DECEIVING + SCORES + AN BE?
  
  Trying: SCORESCANBEDECEIVING
  Secret2: SCORESCANBEDECEIVING
""")

# Part 3: SC AN BE DE OR PA IV IN GX CE RS
# The user suggested: SCAN BE DE OR PAIVING CERS
# Let me parse this
# SC AN = SCAN
# BE DE = BE DE (or BEDE?)
# OR PA = OR PAIRS?
# IV IN = IVING? (DECEIVING?)
# GX = filler
# CE RS = CERS (DECEIVERS?)
print("""
PART 3: SC AN BE DE OR PA IV IN GX CE RS
  User hint: "SCAN BE DE OR PAIVING CERS"
  
  Let's parse:
  SC AN = SCAN
  BE DE = BE DE? (maybe BEDE = BEDES?)
  OR PA = OR PAIRS?
  IV IN = IVING
  GX = filler X
  CE RS = CERS (like DECEIVER-S?)
  
  Reading: SCAN BE DECORS PAIVING? No...
  
  Maybe: "SCANBEDEORPAIRSCEIVING" scrambled
  Or: "CERS" = end of DECEIVERS?
  
  Possible interpretations:
  - DECEIVERS CAN BE ORPAIS? No
  - SCAN BE DE OR PA IVING CERS
  - SCANBEDE + ORPA + IVING + CERS
  
  Secret3: SCANBEDE_ORPA_IVING_CERS? or SCANBEDECEIVERS?
""")

# Let me try a different approach - maybe each secret is a differently ordered anagram
# of "PAIRS CAN BE DECEIVING"?

print("\n" + "=" * 70)
print("ANAGRAM ANALYSIS")
print("=" * 70)

# Base phrase: PAIRS CAN BE DECEIVING
base = "PAIRSCANBEDECEIVING"
print(f"Base phrase letters: {sorted(base)}")
print(f"Length: {len(base)}")

# Part 1 without X: PAORSCANBEDECEIVING
clean1 = pt1.replace('X', '')
print(f"\nPart 1 letters: {sorted(clean1)}")
print(f"Length: {len(clean1)}")

# Part 2 without X: SGCEIVSCORANBEDEIIVGMB
clean2 = pt2.replace('X', '')
print(f"\nPart 2 letters: {sorted(clean2)}")
print(f"Length: {len(clean2)} - extra letters!")

# Part 3 without X: SCANBEDEORPAIVINGCERS
clean3 = pt3.replace('X', '')
print(f"\nPart 3 letters: {sorted(clean3)}")
print(f"Length: {len(clean3)} - extra letters!")

# All three might form different phrases!
print("\n" + "=" * 70)
print("TRYING DIFFERENT PHRASES FOR EACH PART")
print("=" * 70)

# Secret 1: PAIRS CAN BE DECEIVING (confirmed)
secret1 = "PAIRSCANBEDECEIVING"

# Secret 2: Let's try common phrases with similar letters
# SGCEIVSCORANBEDEIIVGMB has: A B C D E E G I I M N O R S S V V
# Possible: DECEIVING SCORES ... CAN BE?
# Or: DECEPTION SCRAMBLES?
# Try: SCORESCANBEDECEIVING 

# Secret 3: SCANBEDEORPAIVINGCERS has: A A B C D E E E G I N O P R R S S V
# Hmm, includes extra letters
# Could be: SCAN BE DECEIVERS OR PAIRS?

# Let me just try combinations
print("""
BEST GUESSES FOR THE 3 SECRETS:

Secret 1: PAIRSCANBEDECEIVING (PAIRS CAN BE DECEIVING)
Secret 2: SCORESCANBEDECEIVING (SCORES CAN BE DECEIVING) 
Secret 3: DECEIVERSCANBEPAIRS (DECEIVERS CAN BE PAIRS) or
          SCANBEDECEIVERSORPAIRS

Or the raw decryptions:
Secret 1: PAORSCANBEDECEIVING
Secret 2: SGCEIVSCORANBEDEIIVGMB  
Secret 3: SCANBEDEORPAIVINGCERS
""")

# Final flag attempts
print("=" * 70)
print("FINAL FLAG CANDIDATES:")
print("=" * 70)

flags = [
    # Interpreted versions
    "PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_DECEIVERSCANBEPAIRS",
    
    # Raw decryptions without X
    f"{clean1}_{clean2}_{clean3}",
    
    # Just concatenated
    f"{clean1}{clean2}{clean3}",
    
    # With underscores and spaces as underscores
    "PAIRS_CAN_BE_DECEIVING_SCORES_CAN_BE_DECEIVING_DECEIVERS_CAN_BE_PAIRS",
    
    # Maybe lowercase
    f"{clean1.lower()}_{clean2.lower()}_{clean3.lower()}",
]

for f in flags:
    print(f"flag{{{f}}}")
