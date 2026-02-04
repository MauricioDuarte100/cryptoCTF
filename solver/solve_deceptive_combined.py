#!/usr/bin/env python3
"""
Let me try reading the decoded texts in different directions
and order the bigrams differently
"""

# Decoded bigrams with DECEPTION key:
# Part 1: PA OR SC AN BE DE CE IV IN GX
# Part 2: SG CE IV SC OR AN BE DE IV GX MB  
# Part 3: SC AN BE DE OR PA IV IN GX CE RS

# The core structure seems to be variations of "X CAN BE DECEIVING"
# where X = PAIRS, SCORES, SCAN, etc.

print("=" * 60)
print("BIGRAM REARRANGEMENT ANALYSIS")
print("=" * 60)

# Part 1: PA OR SC AN BE DE CE IV IN GX
# Reading: PA(I)RS CAN BE DECEIVING (X filler)
# This is confirmed as: PAIRS CAN BE DECEIVING

# Part 2: SG CE IV SC OR AN BE DE IV GX MB
# Extra: SG at start, MB at end
# Core has IV twice!
# Let me try: ignore extras and read core
# CE IV SC OR AN BE DE IV GX
# = CEIV + SCOR + ANBE + DEIV + GX
# Rearrange to spell something?

# What if we read it as:
# SC OR [E] AN BE DE CE IV IV [N] G
# = SCORES AN BE DECEIVING?
# We're missing the E and N for SCORES and DECEIVING...

# Actually, let me look at this differently
# What if the PLAYFAIR BIGRAMS themselves spell the answer?
# Not the decrypted version, but the original?

print("\nOriginal ciphertext bigrams:")
ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

bg1 = [ct1[i:i+2] for i in range(0, len(ct1), 2)]
bg2 = [ct2[i:i+2] for i in range(0, len(ct2), 2)]
bg3 = [ct3[i:i+2] for i in range(0, len(ct3), 2)]

print(f"CT1: {bg1}")
print(f"CT2: {bg2}")
print(f"CT3: {bg3}")

# What if we just concatenate the FIRST letter of each bigram?
first1 = ''.join(bg[0] for bg in bg1)
first2 = ''.join(bg[0] for bg in bg2)
first3 = ''.join(bg[0] for bg in bg3)

print(f"\nFirst letters: {first1} | {first2} | {first3}")

# And second letters:
second1 = ''.join(bg[1] for bg in bg1)
second2 = ''.join(bg[1] for bg in bg2)
second3 = ''.join(bg[1] for bg in bg3)

print(f"Second letters: {second1} | {second2} | {second3}")

# Let me try another interpretation
# What if the three lines should be COMBINED in some way?
print("\n" + "=" * 60)
print("COMBINED READING")
print("=" * 60)

# Reading column-wise: first letter of each row, then second, etc.
max_len = max(len(ct1), len(ct2), len(ct3))
column_read = ""
for i in range(max_len):
    if i < len(ct1): column_read += ct1[i]
    if i < len(ct2): column_read += ct2[i]
    if i < len(ct3): column_read += ct3[i]
print(f"Column-wise: {column_read}")

# Maybe the secrets are hidden in the columns?
# Let me look at each column's letters
print("\nColumn letters:")
for i in range(max_len):
    col = ""
    if i < len(ct1): col += ct1[i]
    if i < len(ct2): col += ct2[i]
    if i < len(ct3): col += ct3[i]
    print(f"  Col {i}: {col}")

# I notice columns 1, 8, 9, 18 have repeated letters:
# Col 1: KKP (two K's)
# Col 8: ONN (two N's)
# Col 9: TQQ (two Q's)
# Col 18: HHP (two H's)

# Maybe the FLAG is formed by the repeated/consistent letters?
print("\nConsistent letters (2+ same in column):")
consistent = ""
for i in range(min(len(ct1), len(ct2), len(ct3))):
    col = ct1[i] + ct2[i] + ct3[i]
    # Most common letter
    from collections import Counter
    most_common = Counter(col).most_common(1)[0]
    if most_common[1] >= 2:
        consistent += most_common[0]
print(f"Consistent: {consistent}")

# Main discovery - the three secrets based on decoded bigrams:
print("\n" + "=" * 60)
print("FINAL INTERPRETATION (based on all analysis)")
print("=" * 60)

# Based on the structure, the three ciphertexts encode the same core message
# but with different leading/trailing bigrams

# Core message (appears in all 3): SC/PA AN/OR BE DE CE IV IN GX
# = (PAIRS/SCAN) CAN BE DECEIVING

# Extra elements:
# CT2: QK->SG at start, UI->MB at end, and has FD twice
# CT3: SU->RS at end

# So the three phrases might be:
# 1. PAIRS CAN BE DECEIVING 
# 2. SG... CAN BE DECEIVING ...MB
# 3. SCAN BE DECEIVING PAIRS RS(?)

# Wait - what if SG CE IV at the start of Part 2 forms a word?
# SG CE IV = SCEIV? Or if we rearrange: CEIVS + G = DECEIVS?
# And MB at end... BSM? MBS?

# Or maybe SG = "SOWING"? "SHOWING"?
# SG = part of DISGUISE? DIS + GU + ISE?

# Let me just try the most likely combinations:
print("""
Most likely three secrets:

Option A:
1. PAIRS CAN BE DECEIVING
2. DECEIVING SCORES CAN BE (reversed?)  
3. SCAN BE DECEIVING PAIRS

Option B:
1. PAIRS CAN BE DECEIVING
2. (Whatever SG...MB decodes to) CAN BE DECEIVING
3. SCAN BE DECEIVING PAIRS

Option C (if Part 2 is just a scrambled version):
1. PAIRS CAN BE DECEIVING
2. PAIRS CAN BE DECEIVING 
3. PAIRS CAN BE DECEIVING
(Just one secret repeated 3 ways)
""")

# Generate more flag attempts
flags = [
    # If all three are the same message
    "PAIRSCANBEDECEIVING",
    "pairscanbedeceiving",
    
    # Three different phrases
    "PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # Raw decoded without cleanup
    "PAORSCANBEDECEIVING_SGCEIVSCORANBEDEIIVGMB_SCANBEDEORPAIVINGCERS",
    
    # If Part 2 is "DECEIVING CAN BE SCORES"
    "PAIRSCANBEDECEIVING_DECEIVINGCANBESCORE_SCANBEDECEIVINGPAIRS",
    
    # Team suggestion incorporated
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # Underscores for spaces
    "PAIRS_CAN_BE_DECEIVING_LOOKS_CAN_BE_DECEIVING_SCAN_BE_DECEIVING_PAIRS",
    "PAIRS_CAN_BE_DECEIVING_SCORES_CAN_BE_DECEIVING_SCAN_BE_DECEIVING_PAIRS",
    
    # Just key subjects
    "PAIRS_LOOKS_SCAN",
    "PAIRS_SCORES_SCAN",
    "pairs_looks_scan",
    "pairs_scores_scan",
    
    # Lowercase versions
    "paorscanbedeceiving_sgceivscoranbedeiivgmb_scanbedeorpaivingcers",
    "pairscanbedeceiving_lookscanbedeceiving_scanbedeceivingpairs",
    "pairscanbedeceiving_scorescanbedeceiving_scanbedeceivingpairs",
]

print("\nFlag candidates:")
for f in flags:
    print(f"flag{{{f}}}")
