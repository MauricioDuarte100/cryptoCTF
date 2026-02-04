#!/usr/bin/env python3
"""
Deceptive Fairness - Focus on transposition and pattern extraction
"Everything matters" - maybe we need to combine all three rows somehow
"""

ct1 = "AKNQRPBAOTECPCFDOAHW"
ct2 = "QKPCFDRPNQBAOTECFDHWUI"
ct3 = "RPBAOTECNQAKFDOAHWPCSU"

def to_bigrams(s):
    return [s[i:i+2] for i in range(0, len(s), 2)]

bg1, bg2, bg3 = to_bigrams(ct1), to_bigrams(ct2), to_bigrams(ct3)

print("=" * 60)
print("TRANSPOSITION & EXTRACTION ANALYSIS")
print("=" * 60)

# Key insight: Maybe instead of decrypting, extract based on UNIQUE elements
print("\n--- Unique Bigram Extraction ---")
all_unique = []
seen = set()
for bg_list in [bg1, bg2, bg3]:
    for bg in bg_list:
        if bg not in seen:
            all_unique.append(bg)
            seen.add(bg)
print(f"Unique bigrams in order of first appearance: {all_unique}")
print(f"Joined: {''.join(all_unique)}")

# What if we do the opposite - extract what's COMMON in a specific order?
print("\n--- Common Elements Order ---")
common = set(bg1) & set(bg2) & set(bg3)
print(f"Common: {sorted(common)}")

# Order by position in row 1
ordered = [bg for bg in bg1 if bg in common]
print(f"Ordered by R1: {ordered}")
print(f"Joined: {''.join(ordered)}")

# Maybe it's about reading diagonally or in a pattern
print("\n--- Snake/Zigzag Reading ---")
# If we put the 3 rows as a matrix and read zigzag
rows = [ct1, ct2, ct3]
zigzag = ""
for i in range(max(len(r) for r in rows)):
    if i % 2 == 0:  # Go down
        for j in range(3):
            if i < len(rows[j]):
                zigzag += rows[j][i]
    else:  # Go up
        for j in range(2, -1, -1):
            if i < len(rows[j]):
                zigzag += rows[j][i]
print(f"Zigzag: {zigzag}")

# What about extracting every Nth character?
print("\n--- Every Nth Character ---")
combined = ct1 + ct2 + ct3
for n in range(2, 6):
    extracted = combined[::n]
    print(f"Every {n}th: {extracted}")

# Rail fence decode
print("\n--- Rail Fence Decode ---")
def rail_fence_decode(cipher, rails):
    result = [''] * len(cipher)
    n = len(cipher)
    zigzag_idx = list(range(rails)) + list(range(rails-2, 0, -1))
    
    # Calculate length of each rail
    rail_lengths = [0] * rails
    for i in range(n):
        rail_lengths[zigzag_idx[i % len(zigzag_idx)]] += 1
    
    # Fill rails
    pos = 0
    rail_strings = []
    for length in rail_lengths:
        rail_strings.append(cipher[pos:pos+length])
        pos += length
    
    # Read off rails
    rail_pos = [0] * rails
    for i in range(n):
        rail = zigzag_idx[i % len(zigzag_idx)]
        if rail_pos[rail] < len(rail_strings[rail]):
            result[i] = rail_strings[rail][rail_pos[rail]]
            rail_pos[rail] += 1
    
    return ''.join(result)

for rails in range(2, 6):
    decoded = rail_fence_decode(combined, rails)
    print(f"Rail fence ({rails} rails): {decoded[:40]}...")

# What if the FIRST letters of each row spell something?
print("\n--- First/Last Letters ---")
first_letters = ct1[0] + ct2[0] + ct3[0]
last_letters = ct1[-1] + ct2[-1] + ct3[-1]
print(f"First letters: {first_letters}")
print(f"Last letters: {last_letters}")

# Column extraction - reading down columns
print("\n--- Pure Column Read ---")
max_len = max(len(ct1), len(ct2), len(ct3))
for col in range(max_len):
    c1 = ct1[col] if col < len(ct1) else ''
    c2 = ct2[col] if col < len(ct2) else ''
    c3 = ct3[col] if col < len(ct3) else ''
    print(f"Col {col:2}: {c1}{c2}{c3}", end="  ")
    if (col + 1) % 5 == 0:
        print()
print()

# Read columns as the message
col_msg = ""
for col in range(max_len):
    for row in [ct1, ct2, ct3]:
        if col < len(row):
            col_msg += row[col]
print(f"Column message: {col_msg}")

# What if we extract JUST the differences?
print("\n--- Unique per Row ---")
r1_only = set(bg1) - (set(bg2) | set(bg3))
r2_only = set(bg2) - (set(bg1) | set(bg3))
r3_only = set(bg3) - (set(bg1) | set(bg2))
print(f"Only R1: {r1_only}")
print(f"Only R2: {r2_only}")
print(f"Only R3: {r3_only}")

# R1: nothing unique, R2: QK, UI, R3: SU
# But also AK and OA are in R1 and R3 only (not R2)
r1_r3_only = (set(bg1) & set(bg3)) - set(bg2)
r1_r2_only = (set(bg1) & set(bg2)) - set(bg3)
r2_r3_only = (set(bg2) & set(bg3)) - set(bg1)
print(f"Only R1+R3: {r1_r3_only}")
print(f"Only R1+R2: {r1_r2_only}")
print(f"Only R2+R3: {r2_r3_only}")

# What about ordering by frequency?
print("\n--- Bigram Frequency ---")
from collections import Counter
all_bg = bg1 + bg2 + bg3
freq = Counter(all_bg)
print(f"Frequency: {freq.most_common()}")

# FD appears 4 times! Most frequent
# Others appear 2-3 times
# Single occurrences: QK, UI, SU

# Let's try treating this as a simple substitution with the bigrams as symbols
print("\n--- Bigram Substitution ---")
# Common bigrams mapped to standard letters
mapping = {
    'BA': 'A', 'EC': 'B', 'FD': 'C', 'HW': 'D',
    'NQ': 'E', 'OT': 'F', 'PC': 'G', 'RP': 'H',
    'AK': 'I', 'OA': 'J', 'QK': 'K', 'UI': 'L', 'SU': 'M'
}
for name, bgs in [("Row1", bg1), ("Row2", bg2), ("Row3", bg3)]:
    mapped = "".join(mapping.get(bg, '?') for bg in bgs)
    print(f"{name}: {mapped}")

# Re-order based on the first row positions
print("\n--- Reorder Rows 2,3 to Match Row 1 ---")
# Row 1 order: AK NQ RP BA OT EC PC FD OA HW
# Try to find where each appears in Row 2 and Row 3

print("Row 1 is baseline:")
for i, bg in enumerate(bg1):
    r2_pos = bg2.index(bg) if bg in bg2 else -1
    r3_pos = bg3.index(bg) if bg in bg3 else -1
    print(f"  {i}: {bg} -> R2[{r2_pos}], R3[{r3_pos}]")

# Maybe the secret is encoded in the POSITION SHIFTS
print("\n--- Position Shift Message ---")
shifts = []
for bg in bg1:
    if bg in bg2 and bg in bg3:
        r2_shift = bg2.index(bg) - bg1.index(bg)
        r3_shift = bg3.index(bg) - bg1.index(bg)
        shifts.append((bg, r2_shift, r3_shift))
        print(f"{bg}: shift R2={r2_shift:+d}, R3={r3_shift:+d}")

# Maybe extract based on shift values?
shift_vals_r2 = [s[1] for s in shifts]
shift_vals_r3 = [s[2] for s in shifts]
print(f"R2 shifts: {shift_vals_r2}")
print(f"R3 shifts: {shift_vals_r3}")

# Convert shifts to letters?
def shift_to_letter(shift):
    # Normalize: -5 to +5 -> 0 to 10
    return chr((shift + 13) % 26 + ord('A'))

shift_msg_r2 = "".join(shift_to_letter(s) for s in shift_vals_r2)
shift_msg_r3 = "".join(shift_to_letter(s) for s in shift_vals_r3)
print(f"R2 shift message: {shift_msg_r2}")
print(f"R3 shift message: {shift_msg_r3}")

# One more idea - maybe it's about which columns are "fair" (match across all 3)
print("\n--- Fair Columns (all 3 match) ---")
fair_cols = []
for i in range(min(len(ct1), len(ct2), len(ct3))):
    if ct1[i] == ct2[i] == ct3[i]:
        fair_cols.append((i, ct1[i]))
        
if fair_cols:
    print(f"Matching columns: {fair_cols}")
    print(f"Message: {''.join(c for _, c in fair_cols)}")
else:
    print("No matching columns found")
    
# Check which columns have at least 2 matching
print("\n--- Majority Vote per Column ---")
from collections import Counter
majority_msg = ""
for i in range(min(len(ct1), len(ct2), len(ct3))):
    chars = [ct1[i], ct2[i], ct3[i]]
    most_common = Counter(chars).most_common(1)[0]
    if most_common[1] >= 2:
        majority_msg += most_common[0]
    else:
        majority_msg += '?'
print(f"Majority message: {majority_msg}")

# What if we literally just need the content that differs?
# Row 2 starts with QK instead of AK (changed A->Q)
# Row 2 ends with UI (added)
# Row 3 ends with SU (added instead of UI)
print("\n--- Difference Characters ---")
for i in range(min(len(ct1), len(ct2), len(ct3))):
    if ct1[i] != ct2[i]:
        print(f"Pos {i}: R1={ct1[i]}, R2={ct2[i]}, diff={chr(abs(ord(ct2[i]) - ord(ct1[i])) + ord('A') - 1 if ct2[i] > ct1[i] else ord('A') + ord(ct1[i]) - ord(ct2[i]) - 1)}")
