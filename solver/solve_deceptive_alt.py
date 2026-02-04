#!/usr/bin/env python3
"""
Alternative approach - What if both the key AND the message follow a different pattern?
"Deceptive Fairness" - FAIR might mean balanced/equal

Let me try:
1. Maybe the ciphertexts are encrypted with THREE different keys
2. Or maybe we read them in a special pattern (columns, diagonals)
3. Or the bigrams map to letters directly without Playfair
"""

import string

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

# What if we ignore Playfair entirely and look for a pattern in the raw ciphertexts?
print("=" * 60)
print("PATTERN ANALYSIS IN RAW CIPHERTEXT")
print("=" * 60)

# The bigrams are "shuffled" versions of each other
# What if the POSITION of each bigram in each row encodes information?

bg1 = [ct1[i:i+2] for i in range(0, len(ct1), 2)]
bg2 = [ct2[i:i+2] for i in range(0, len(ct2), 2)]
bg3 = [ct3[i:i+2] for i in range(0, len(ct3), 2)]

print(f"Row 1: {bg1}")
print(f"Row 2: {bg2}")
print(f"Row 3: {bg3}")

# Create a mapping from bigram to its position in row 1
row1_positions = {bg: i for i, bg in enumerate(bg1)}

print("\nBigram positions in each row (index in row 1 as baseline):")
for i, bg in enumerate(bg1):
    pos1 = i
    pos2 = bg2.index(bg) if bg in bg2 else -1
    pos3 = bg3.index(bg) if bg in bg3 else -1
    print(f"  {bg}: R1={pos1}, R2={pos2}, R3={pos3}")

# What letters appear in each position across all three?
print("\n" + "=" * 60)
print("COLUMN ANALYSIS")
print("=" * 60)

max_len = max(len(ct1), len(ct2), len(ct3))
for col in range(max_len):
    c1 = ct1[col] if col < len(ct1) else ' '
    c2 = ct2[col] if col < len(ct2) else ' '
    c3 = ct3[col] if col < len(ct3) else ' '
    print(f"Col {col:2}: {c1} {c2} {c3} -> {''.join([c1,c2,c3])}")

# What if the flag is formed by reading UNIQUE letters from each row?
print("\n" + "=" * 60)
print("UNIQUE LETTERS PER ROW")
print("=" * 60)

set1 = set(ct1)
set2 = set(ct2)
set3 = set(ct3)

only1 = set1 - set2 - set3
only2 = set2 - set1 - set3
only3 = set3 - set1 - set2

print(f"Only in CT1: {sorted(only1)}")
print(f"Only in CT2: {sorted(only2)}")
print(f"Only in CT3: {sorted(only3)}")

# CT1: nothing unique
# CT2: I (from UI)
# CT3: S (from SU)

# Hmm, I and S... maybe IS or SI?

# Let me look at this from the perspective of letter frequency
print("\n" + "=" * 60)
print("LETTER FREQUENCY")
print("=" * 60)

from collections import Counter
all_text = ct1 + ct2 + ct3
freq = Counter(all_text)
for letter, count in freq.most_common():
    print(f"  {letter}: {count}")

# Most common: A(7), P(6), C(6), O(5), ...

# What if we create a simple substitution cipher based on frequency?
# English letter frequency: E T A O I N S H R...
# Our frequency: A P C O Q F D K N R B T E H W U I S

# Hmm, A is most common (should be E?), P is second (should be T?)
# Let's try mapping: A->E, P->T, C->A, O->O, Q->I, F->N, D->S, K->H, N->R...

print("\n" + "=" * 60)
print("FREQUENCY-BASED SUBSTITUTION")
print("=" * 60)

# Create mapping (our cipher letters -> English by frequency)
our_freq = [letter for letter, _ in freq.most_common()]
english_freq = list("ETAOINSHRDLCUMWFGYPBVKJXQZ")

# Build substitution map
sub_map = {}
for i, letter in enumerate(our_freq):
    if i < len(english_freq):
        sub_map[letter] = english_freq[i]

def substitute(text, mapping):
    return ''.join(mapping.get(c, c) for c in text)

print(f"CT1 substituted: {substitute(ct1, sub_map)}")
print(f"CT2 substituted: {substitute(ct2, sub_map)}")
print(f"CT3 substituted: {substitute(ct3, sub_map)}")

# One more approach: what if the THREE ciphertexts are THREE DIFFERENT ENCRYPTIONS
# of THREE DIFFERENT plaintexts with the same key pattern?
print("\n" + "=" * 60)
print("TRY DIFFERENT KEYS FOR EACH CIPHERTEXT")
print("=" * 60)

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

# Try key1 = PAIRS, key2 = LOOKS, key3 = APPEARANCES
keys = ["PAIRS", "LOOKS", "APPEARANCES"]
for i, (ct, key) in enumerate(zip([ct1, ct2, ct3], keys)):
    dec = playfair_decrypt(ct, key)
    print(f"CT{i+1} with key '{key}': {dec}")

# Try key1 = DECEPTION, key2 = FAIRNESS, key3 = DECEPTIVEFAIR 
keys2 = ["DECEPTION", "FAIRNESS", "DECEPTIVEFAIRNESS"]
print()
for i, (ct, key) in enumerate(zip([ct1, ct2, ct3], keys2)):
    dec = playfair_decrypt(ct, key)
    print(f"CT{i+1} with key '{key}': {dec}")

# What if the THREE secrets are:
# 1. One uses DECEPTION key
# 2. One uses FAIRNESS key  
# 3. One uses combined key
print("\n" + "=" * 60)
print("ALL THREE WITH EACH KEY")
print("=" * 60)

for key in ["DECEPTION", "FAIRNESS", "DECEPTIVE", "FAIR", "PLAYFAIR", "UNFAIR"]:
    print(f"\nKey: {key}")
    for i, ct in enumerate([ct1, ct2, ct3]):
        dec = playfair_decrypt(ct, key).replace('X', '')
        print(f"  CT{i+1}: {dec}")

# Final idea: maybe the answer is much simpler
# The title "Deceptive Fairness" means APPEARANCES can be deceiving
# And the three rows are just three variations of the same theme
print("\n" + "=" * 60)
print("SIMPLEST INTERPRETATION")
print("=" * 60)

# Classic phrases about deception:
# 1. "Looks can be deceiving" - most common
# 2. "Appearances can be deceiving" - longer version
# 3. "Pairs can be deceiving" - math/stats context (like hypothesis testing)
# 4. "Numbers can be deceiving" - statistics
# 5. "First impressions can be deceiving"

# The flag might just be these words!
simple_flags = [
    # Just the subjects
    "pairs_looks_appearances",
    "PAIRS_LOOKS_APPEARANCES",
    "looks_pairs_appearances",
    "appearances_looks_pairs",
    
    # Full phrases
    "pairs_can_be_deceiving_looks_can_be_deceiving_appearances_can_be_deceiving",
    
    # Initials
    "PCBD_LCBD_ACBD",
    
    # Maybe it's actually about fairness
    "FAIRNESS_IS_DECEPTIVE",
    "DECEPTIVE_FAIRNESS",
    
    # Or just the decryption key
    "DECEPTION",
]

for f in simple_flags:
    print(f"flag{{{f}}}")
