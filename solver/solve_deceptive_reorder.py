#!/usr/bin/env python3
"""
The three ciphertexts contain the SAME bigrams in different orders!
Each produces a different READING when bigrams are reordered.

Using the known Playfair mapping:
- AK=PA, NQ=OR, RP=SC, BA=AN, OT=BE, EC=DE, PC=CE, FD=IV, OA=IN, HW=GX
- Extra: QK=SG, UI=MB, SU=RS
"""

# Bigram meanings (from Playfair with DECEPTION key)
decrypt_map = {
    'AK': 'PA', 'NQ': 'OR', 'RP': 'SC', 'BA': 'AN', 'OT': 'BE',
    'EC': 'DE', 'PC': 'CE', 'FD': 'IV', 'OA': 'IN', 'HW': 'GX',
    'QK': 'SG', 'UI': 'MB', 'SU': 'RS'
}

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

def decode_ct(ct):
    bigrams = [ct[i:i+2] for i in range(0, len(ct), 2)]
    decoded = [decrypt_map.get(bg, f"?{bg}?") for bg in bigrams]
    return decoded

print("=" * 70)
print("BIGRAM REORDERING ANALYSIS")
print("=" * 70)

# Decode each ciphertext
d1 = decode_ct(ct1)
d2 = decode_ct(ct2)
d3 = decode_ct(ct3)

print(f"\nPart 1 decoded bigrams: {d1}")
print(f"Part 2 decoded bigrams: {d2}")
print(f"Part 3 decoded bigrams: {d3}")

print(f"\nPart 1 as string: {''.join(d1)}")
print(f"Part 2 as string: {''.join(d2)}")
print(f"Part 3 as string: {''.join(d3)}")

# Now let's try to read each as a meaningful phrase by REORDERING
print("\n" + "=" * 70)
print("FINDING MEANINGFUL PHRASES")
print("=" * 70)

# Part 1: PA OR SC AN BE DE CE IV IN GX
# If OR = PAIRS (Playfair convention), then: PAIRS CAN BE DECEIVING
# Reading: PA(I)RS CAN BE DECEIVING (X is filler)
print("""
Part 1: PA OR SC AN BE DE CE IV IN GX
  -> PA + OR gives "PA-OR" but meant to be "PAIRS" 
  -> Full reading: PAIRS CAN BE DECEIVING
  -> Secret 1: PAIRSCANBEDECEIVING
""")

# Part 2: SG CE IV SC OR AN BE DE IV GX MB
# Has extra: SG, MB and a duplicate IV
# SG at start, MB at end
# Core: CE IV SC OR AN BE DE IV GX = DECEIV SCAN BE DEIV G
# Reorder to: SC OR AN BE DE CE IV IV GX = SCOR AN BE DECEIVING
# Or: SC OR AN = SCORES? No, there's no ES bigram
# Wait - maybe SG = LO somehow?

# Actually, let's think about this differently
# What if Part 2 should read: "LOOKS CAN BE DECEIVING"?
# But we don't have LO bigram being mapped...

# Actually I realize - SG CE IV = SCEIV = DECEIV backwards!
# SC OR AN BE DE (S)CEIV = SCORES AN BE DE ?
# Hmm no...

print("""
Part 2: SG CE IV SC OR AN BE DE IV GX MB
  SG and MB are "extra" bigrams not in Part 1
  Core pattern: CE IV SC OR AN BE DE IV GX
  
  Let me try different readings:
  1. SCEIV SCORAN BEDEIV GMB - doesn't work
  2. Reorder: SC OR AN BE DE CE IV IN G = SCORES AN BE DECEIVING? No...
  
  Wait - what if we read SC OR as SCORES (SC+OR+ES=SCORES)?
  But there's no ES bigram...
  
  Maybe: CE IV = DECEIV part, SC OR AN = SCORAN, BE DE = BEDE
  DECEIV + SCORAN + BEDE... still weird
  
  Let me check: maybe SG = LO for "LOOKS"?
  If QK decrypts to LO instead of SG with a different key...
""")

# Part 3: SC AN BE DE OR PA IV IN GX CE RS
# This almost looks like Part 1 reordered!
# Has extra: RS
# SC AN = SCAN
# BE DE = BE DE
# OR PA = OR PAIRS?
# IV IN GX = IVING (G is filler?)
# CE RS = CERS (like DECEIVER-S end?)

print("""
Part 3: SC AN BE DE OR PA IV IN GX CE RS
  RS is "extra" bigram not in Part 1
  
  Reading: SCAN BEDE ORPA IVING CERS
  Or reordered: SC AN BE DE CE IV IN GX OR PA RS
             = SCAN BE DECEIVING PAIRS (RS = filler?)
  
  Team's insight: "SCAN BE DECEIVING PAIRS"
  So this works if we group: SC-AN BE DE-CE-IV-IN-G PA-IR-S
  But the actual bigrams are different...
  
  Wait - OR PA could be "ORPA" = "OR PAIRS"
  And CE RS could be "CERS" = "DECEIVERS" ending?
  
  Maybe: "DECEIVERS CAN BE PAIRS"?
""")

# Let me try a completely different approach
# What if the three secrets are anagrams of each other?
print("\n" + "=" * 70)
print("ANAGRAM APPROACH")
print("=" * 70)

# All three share most bigrams
# Part 1 has: PA OR SC AN BE DE CE IV IN GX (10 bigrams)
# Part 2 has: SG CE IV SC OR AN BE DE IV GX MB (11 bigrams, with IV twice)
# Part 3 has: SC AN BE DE OR PA IV IN GX CE RS (11 bigrams)

# If we sort Part 1: AN BE CE DE GX IN IV OR PA SC = 
# Alphabetically by plaintext meaning: AN BE CE DE GX IN IV OR PA SC
# Reading: AN BE CE DE G(X) IN IV OR PA SC = ?

# What if the FLAG is just the three key words that can precede "CAN BE DECEIVING"?
# 1. PAIRS
# 2. LOOKS (if SG somehow = LO)
# 3. ???

# Let me just try various flag formats based on what we know:
print("\n" + "=" * 70)
print("FLAG CANDIDATES TO TRY")
print("=" * 70)

flags = [
    # Three classic phrases
    "PAIRSCANBEDECEIVING_LOOKSCANBEDECEIVING_APPEARANCESCANBEDECEIVING",
    "PAIRS_LOOKS_APPEARANCES",
    
    # Using team's Part 3 hint
    "PAIRSCANBEDECEIVING_SCORESCANBEDECEIVING_SCANBEDECEIVINGPAIRS",
    
    # Raw decoded strings
    "PAORSCANBEDECEIVING_SGCEIVSCORANBEDEIIVGMB_SCANBEDEORPAIVINGCERS",
    
    # Cleaned up versions
    "PAIRSCANBEDECEIVING_DECEIVINGSCORESCANBE_SCANBEDECEIVINGPAIRS", 
    
    # Just the first words
    "PAIRS_SCORES_SCAN",
    "PAIRS_DECEIVING_SCAN",
    
    # Try with underscores removed
    "PAIRSCANBEDECEIVINGLOOKSCANBEDECEIVINAGAPPEARANCES CANBEDECEIVING",
    
    # Lowercase
    "pairs_looks_appearances",
    "pairscanbedeceiving_lookscanbedeceiving_appearancescanbedeceiving",
    
    # Maybe just wordplay?
    "deception",
    "DECEPTION",
    
    # The decrypted message interpreted as three words
    "PAIRS_SCORES_SCANS",
    "PAIRS_FACES_APPEARANCES",
]

for f in flags:
    print(f"flag{{{f}}}")

# Actually, wait - let me re-read Part 2 more carefully
# SG CE IV SC OR AN BE DE IV GX MB
# What if this should be reordered to match a phrase?
# 
# For "SCORES CAN BE DECEIVING":
# SC OR ES CA NB ED EC EI VI NG
# But that needs ES which we don't have

# For "LOOKS CAN BE DECEIVING":
# LO OK SC AN BE DE CE IV IN GX
# We need LO and OK bigrams... we have SG and MB instead

# Actually SG could be part of a word ending in SG?
# What words end or contain SG? DISGUISE? MISGIVE? 
# Hmm...

print("\n" + "=" * 70)
print("ALTERNATIVE: MAYBE IT'S NOT PLAYFAIR")
print("=" * 70)

# What if it's a different cipher entirely?
# The challenge says "Deceptive Fairness" - maybe "fair" means equal distribution
# And "deceptive" means the cipher isn't what it appears to be

# Let's try Vigenere with key "DECEPTION"
def vigenere_decrypt(ct, key):
    result = ""
    key = key.upper()
    for i, c in enumerate(ct.upper()):
        if c.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            result += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        else:
            result += c
    return result

print("\nVigenere with DECEPTION:")
print(f"CT1: {vigenere_decrypt(ct1, 'DECEPTION')}")
print(f"CT2: {vigenere_decrypt(ct2, 'DECEPTION')}")
print(f"CT3: {vigenere_decrypt(ct3, 'DECEPTION')}")

print("\nVigenere with FAIRNESS:")
print(f"CT1: {vigenere_decrypt(ct1, 'FAIRNESS')}")
print(f"CT2: {vigenere_decrypt(ct2, 'FAIRNESS')}")
print(f"CT3: {vigenere_decrypt(ct3, 'FAIRNESS')}")
