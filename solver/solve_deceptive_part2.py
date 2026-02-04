#!/usr/bin/env python3
"""
Based on user's team hint for Part 3: "SCAN BE DECEIVING PAIRS"
Let's decode all 3 parts properly

Part 3 decoded: SC AN BE DE OR PA IV IN GX CE RS
If rearranged: SC AN BE DE CE IV IN G (X filler) = SCAN BE DECEIVING
Plus: OR PA RS = could be "PAIRS" somehow

Let me find what Part 2 spells!
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

key = "DECEPTION"
pt1 = playfair_decrypt(ct1, key)
pt2 = playfair_decrypt(ct2, key)
pt3 = playfair_decrypt(ct3, key)

bg1 = [pt1[i:i+2] for i in range(0, len(pt1), 2)]
bg2 = [pt2[i:i+2] for i in range(0, len(pt2), 2)]
bg3 = [pt3[i:i+2] for i in range(0, len(pt3), 2)]

print("=" * 60)
print("DECODED BIGRAMS")
print("=" * 60)
print(f"Part 1: {bg1}")
print(f"Part 2: {bg2}")
print(f"Part 3: {bg3}")

# Part 1: PA OR SC AN BE DE CE IV IN GX
# This reads as: PAIRS CAN BE DECEIVING (OR is the I-R glitch in Playfair)

# Part 2: SG CE IV SC OR AN BE DE IV GX MB
# SG at start, MB at end are extra
# Core: CE IV SC OR AN BE DE IV GX
# = DECEIV + SCORAN + BEDEIV + G
# Rearranged: SC OR AN BE DE CE IV IV NG?
# SCOR AN BE DECEIV ING?
# "SCORES CAN BE DECEIVING"? But we have SC-OR not SC-OR-ES

# Part 3: SC AN BE DE OR PA IV IN GX CE RS  
# Team said: "SCAN BE DECEIVING PAIRS"
# SC AN = SCAN
# BE DE CE IV IN G = BE DECEIVING (?)
# But bigrams are: BE DE, then OR PA, then IV IN, then GX CE RS
# So: SCAN + BEDE + ORPA + IVING + CERS
# Rearranged: SCAN + BE + DECEIVING + PAIRS? 
# = SCAN BE DECEIVING PAIRS

print("\n" + "=" * 60)
print("INTERPRETATION")
print("=" * 60)

# So the three secrets might be:
# 1. PAIRS CAN BE DECEIVING
# 2. ??? CAN BE DECEIVING (or DECEIVING ???)
# 3. SCAN BE DECEIVING PAIRS

# For Part 2, let me try different rearrangements
print("\nPart 2 rearrangements:")
# SG CE IV SC OR AN BE DE IV GX MB
# What if SG = part of word at end? Like "...ISG" = ?
# What if we read: DECEIVING + SCORAN + BE + SGMB?
# Or: DECEIVIN + G + SCORAN + BE + SGMB?

# Wait - maybe the message is "DECEIVING SCOR(E)S CAN BE"?
# Or "SCEIV SCOR AN BE DEIV G MB" = nonsense

# Let's try: Remove SG and MB as "junk"
core2 = ['CE', 'IV', 'SC', 'OR', 'AN', 'BE', 'DE', 'IV', 'GX']
print(f"Part 2 core (no SG/MB): {''.join(core2)}")
# = CEIVSCORANBEDEIIVGX
# Rearranged: SC OR AN BE DE CE IV IV GX = SCOR AN BE DECEIV ING?
# But "SCOR" is not a word... unless it's SCORES?

# What if we consider that the extra IV is a "duplicate"?
# CE IV SC OR AN BE DE (IV) G = DECEIV + SCORAN + BEDE + G
# Nope, still not making sense

# Let me try a different approach - what if Part 2 is about something else entirely?
# SG CE IV SC OR AN BE DE IV GX MB
# What words can be made?
# SCRAMBLED? No...
# DESCRIBING? Hmm... DE SC R(I) B(E) I NG?
# No, we don't have those letters

# Maybe: "CAN BE DECEIVING SIGHTS"?
# Or "IMAGES CAN BE DECEIVING"?

print("\nWhat phrases fit Part 2's letters?")
# Part 2 letters (without X): S G C E I V S C O R A N B E D E I V G M B
# That's: A B B C C D E E E G G I I M N O R S S V V
# Possible words: DECEIVING (D E C E I V I N G) - uses: D C E E I V I N G
# After DECEIVING: A B B C E G M O R S S V
# SCORES? S C O R E S - uses: S C O R E S
# After DECEIVING + SCORES: A B B G M V
# Left: AB + BG + MV? or BGMV AB?

# So maybe Part 2 = SCORESCANBEDECEIVING !
# But wait, we need to fit CAN BE in there too
# SCORES (S C O R E S) + CAN (C A N) + BE (B E) + DECEIVING (D E C E I V I N G)
# = S C O R E S C A N B E D E C E I V I N G
# Available: A B B C C D E E E G G I I M N O R S S V V

# Hmm, we don't have A for CAN... but we have AN!
# SCOR + AN + BE + DECEIV + ING... 
# We have: SC OR AN BE DE CE IV IN G
# = SCOR AN BE DECEIVING?
# "SCOR AN" is like "SCORING" without the I and G at end?

# Actually I wonder if it's meant to be read with overlaps
# SC-OR-AN-BE-DE-CE-IV-IN-G 
# = (S)CORAN BE DECEIVING?
# CORAN = a name? Or SCORE with typo?

# Let me just try common "X can be deceiving" phrases:
phrases = [
    "SCORESCANBEDECEIVING",
    "SIGHTSCANBEDECEIVING",
    "SOUNDSCANBEDECEIVING",
    "SIGNSCANBEDECEIVING",
    "SEEMINGCANBEDECEIVING",
    "FACESCANBEDECEIVING",
    "EYESCANBEDECEIVING",
]

for phrase in phrases:
    # Check if Part 2's letters can form this phrase
    from collections import Counter
    phrase_letters = Counter(phrase.replace('X', ''))
    part2_letters = Counter(pt2.replace('X', ''))
    if phrase_letters <= part2_letters:
        print(f"  Part 2 CAN form: {phrase}")
    else:
        missing = phrase_letters - part2_letters
        if sum(missing.values()) <= 2:
            print(f"  Part 2 ALMOST forms: {phrase} (missing: {dict(missing)})")

print("\n" + "=" * 60)
print("FINAL THREE SECRETS")
print("=" * 60)

# Based on analysis:
print("""
Secret 1: PAIRS CAN BE DECEIVING (from Part 1)
Secret 2: ??? (Part 2 - unclear, maybe SCORES CAN BE DECEIVING?)
Secret 3: SCAN BE DECEIVING PAIRS (from Part 3 per team)

Flag attempts:
""")

# Flag variations
flags = [
    # Three secrets as phrases
    "PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    "pairs_can_be_deceiving_scores_can_be_deceiving_scan_be_deceiving_pairs",
    
    # If Part 2 is "DECEIVING SCORES CAN BE"
    "PAIRSCANBEDECEIVING_DECEIVINGSCORESCANBE_SCANBEDECEIVINGPAIRS",
    
    # Just the raw decrypts
    "PAORSCANBEDECEIVING_SGCEIVSCORANBEDEIVGMB_SCANBEDEORPAIVINGCERS",
    
    # Team's insight for Part 3
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # All lowercase
    "pairscanbedeceiving_scorescanbedeceiving_scanbedeceivingpairs",
    
    # Maybe different order
    "SCANBEDECEIVINGPAIRS_PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING",
    
    # The key words only
    "PAIRS_SCORES_SCAN",
    "PAIRS_LOOKS_SCAN", 
    "pairs_scores_scan",
]

for f in flags:
    print(f"flag{{{f}}}")
