#!/usr/bin/env python3
"""
Re-thinking Deceptive Fairness completely
Maybe it's NOT a cipher at all - just a puzzle
"""

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

print("=" * 60)
print("THINKING OUTSIDE THE BOX")
print("=" * 60)

# What if the bigrams are just shuffled letters?
# Let's see what happens if we just look at all unique letters

all_text = ct1 + ct2 + ct3
letters_in_order = list(dict.fromkeys(all_text))  # Preserve order, dedupe
print(f"Unique letters in order: {''.join(letters_in_order)}")

# Maybe the SECRET is in the ANAGRAM?
from collections import Counter
freq = Counter(all_text)
print(f"Letter frequency: {dict(freq.most_common())}")

# Total letters: let's see the counts
print(f"\nTotal letters: {len(all_text)}")
for letter, count in freq.most_common():
    print(f"  {letter}: {count}")

# Can "PAIRS CAN BE DECEIVING" be anagrammed from these?
target = "PAIRSCANBEDECEIVING"
target_freq = Counter(target)
print(f"\nTarget 'PAIRSCANBEDECEIVING' needs: {dict(target_freq.most_common())}")

# Check if we have enough letters
missing = []
for letter, needed in target_freq.items():
    available = freq.get(letter, 0)
    if available < needed:
        missing.append(f"{letter}: need {needed}, have {available}")
print(f"Missing letters: {missing if missing else 'None!'}")

# Wait - the Playfair key might not be DECEPTION
# Let me try more systematically with dictionary words

print("\n--- Dictionary Attack on Playfair Key ---")
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

# Try lots of keys
keys_to_try = [
    # From the challenge
    "DECEPTIVE", "FAIRNESS", "DECEPTION", "FAIR",
    "UNFAIR", "DECEIVE", "DECEIVER", "CHEAT", "TRICK",
    # Common crypto keys
    "KEYWORD", "MONKEY", "PLAYFAIR", "CIPHER", "SECRET",
    # Numbers as words
    "ONE", "TWO", "THREE", "ZERO",
    # Other possibilities
    "TRUTH", "LIES", "FALSE", "TRUE",
    "HIDDEN", "REVEAL", "SOLVE", "ANSWER",
    "SECURITY", "CRYPTO", "PUZZLE",
    # Combinations
    "FAIRPLAY", "NOTSOFAIR", "DECEPTIVEFAIRNESS",
]

best_matches = []
for key in keys_to_try:
    pt = playfair_decrypt(ct1, key)
    # Score by English word fragments
    score = 0
    for word in ["THE", "AND", "CAN", "BE", "IS", "OR", "PAIR", "PAI", "ING", 
                 "ION", "TION", "DEC", "CEI", "EIV"]:
        if word in pt:
            score += len(word)
    if score >= 6:
        best_matches.append((score, key, pt))

best_matches.sort(reverse=True)
print("Best Playfair keys:")
for score, key, pt in best_matches[:10]:
    print(f"  {key} (score {score}): {pt}")

# What if there's NO cipher and the message is directly embedded?
print("\n--- Direct Reading Attempts ---")

# Reading every other character
print(f"CT1 odd positions: {ct1[::2]}")
print(f"CT1 even positions: {ct1[1::2]}")

# Reading diagonal
print(f"Combined odd: {ct1[::2] + ct2[::2] + ct3[::2]}")
print(f"Combined even: {ct1[1::2] + ct2[1::2] + ct3[1::2]}")

# What if the answer is the KEY itself?
# "Deceptive Fairness" -> the key is DECEPTION
# And the message confirms this

print("\n--- Final Check: Is the answer just the process? ---")
# Key found: DECEPTION
# Message decoded: PAIRS CAN BE DECEIVING
# Flag could be: DECEPTION or PAIRSCANBEDECEIVING

print("If the challenge wants the KEY: flag{DECEPTION} or flag{deception}")
print("If the challenge wants the MESSAGE: flag{PAIRSCANBEDECEIVING}")

# Perhaps the flag uses the actual decrypted text without filler
print("\n--- Clean Playfair Output ---")
pt = playfair_decrypt(ct1, "DECEPTION")
print(f"Raw: {pt}")
# Remove X fillers at end and between double letters
clean = pt.rstrip('X')
# But we also need to handle mid-word X
# In Playfair, X is inserted between double letters or at end

# The output is PAORSCANBEDECEIVINGX
# If we just remove trailing X: PAORSCANBEDECEIVING
# The OR vs AI inconsistency suggests maybe the key is slightly different

# Actually, let me look at what plaintext "PAIRSCANBEDECEIVING" would encrypt to
def playfair_encrypt(plaintext, key):
    grid = create_grid(key)
    # Prepare plaintext
    pt = plaintext.upper().replace('J', 'I')
    # Insert X between repeating letters
    prepared = ""
    i = 0
    while i < len(pt):
        prepared += pt[i]
        if i + 1 < len(pt):
            if pt[i] == pt[i+1]:
                prepared += 'X'
        i += 1
    # Pad with X if odd length
    if len(prepared) % 2 == 1:
        prepared += 'X'
    
    # Encrypt
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

print("\n--- Reverse Engineering ---")
plain = "PAIRSCANBEDECEIVING"
encrypted = playfair_encrypt(plain, "DECEPTION")
print(f"Encrypting '{plain}' with DECEPTION: {encrypted}")
print(f"Original CT1: {ct1}")
print(f"Match: {encrypted == ct1}")

# If they don't match, what plaintext would produce ct1?
# We already know: ct1 with DECEPTION -> PAORSCANBEDECEIVINGX
# So the plaintext stored is actually "PAORSCANBEDECEIVING" (with X filler)

# Hmm, "PAORS" instead of "PAIRS" - one letter different
# O vs I position 3

# Actually wait - maybe it's literally just PAORS as intended
# "PA ORS CAN BE DECEIVING" = "PA" + unknown word

# Let me check if "PAORS" is actually correct in some interpretation
print("\n--- PAORS Interpretation ---")
# Could be French or another language?
# Or an acronym?
# PAORS = ?

# Actually - let me check if there's a simpler pattern
# What if we just look at first letters of each bigram?
bg1 = [ct1[i:i+2] for i in range(0, len(ct1), 2)]
first_letters = "".join(bg[0] for bg in bg1)
second_letters = "".join(bg[1] for bg in bg1)
print(f"First letters: {first_letters}")
print(f"Second letters: {second_letters}")

# Decode just these
print(f"First letters decoded: {playfair_decrypt(first_letters + 'X', 'DECEPTION')}")
print(f"Second letters decoded: {playfair_decrypt(second_letters + 'X', 'DECEPTION')}")
