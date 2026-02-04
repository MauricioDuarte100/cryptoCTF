#!/usr/bin/env python3
"""
Search for English words that can be formed from the Part 2 'subject' bigrams.
Bigrams available: SG, SC, OR, MB (plus potentially reusing CE, IV)
Letters: S, G, S, C, O, R, M, B
"""

from collections import Counter

# Letters available in the "subject" part of Part 2
# We assume "AN BE DE IV ..." forms the "CAN BE DECEIVING" part
# So the subject comes from the remaining bigrams: SG, SC, OR, MB
# And maybe parts of CE?
source_letters = list("SGSCORMB")
print(f"Source letters: {source_letters}")

# Common subjects for "... CAN BE DECEIVING"
candidates = [
    "LOOKS", "APPEARANCES", "PAIRS", "SCORES", "SCAMS", "SCHEMES",
    "SCALES", "SIGNS", "SIGHTS", "SCENES", "SCENTS", "SCRIPTS",
    "SCARS", "SCREENS", "SOURCES", "SPACES", "SMILES", "STYLES",
    "SHAPES", "SIZES", "SENSES", "SOUNDS", "STORIES", "STATS",
    "WORDS", "EYES", "FACES", "FIGURES", "NUMBERS", "IMAGES",
    "OBJECTS", "PATTERNS", "COLORS", "VIEWS", "ANGLES",
    
    # "Fairness" related
    "FAIRNESS", "JUSTICE", "BALANCE", "EQUITY",
    
    # "Deceptive" related
    "DECEPTION", "LIES", "TRUTH", "SECRETS"
]

def check_word(word, letters):
    w_count = Counter(word)
    l_count = Counter(letters)
    
    # Check if word can be formed
    missing = w_count - l_count
    if not missing:
        return True, {}
    return False, missing

print("\nChecking candidates against source letters (SGSCORMB):")
for word in candidates:
    possible, missing = check_word(word, source_letters)
    if possible:
        print(f"MATCH: {word}")
    elif sum(missing.values()) <= 2:
        print(f"CLOSE: {word} (missing {dict(missing)})")

# Let's try to decrypt QK and UI with brute force to see if they form meaningful bigrams
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

print("\n" + "="*50)
print("Brute forcing QK and UI decryption")
print("="*50)

common_bigrams = ["LO", "OK", "SC", "RE", "TE", "ST", "AP", "PE", "AR", "AN", "CE"]

dictionary = ["LOOKS", "APPEARANCES", "SCORES", "PAIRS", "DECEPTIVE", "FAIRNESS"]

for key in dictionary + candidates:
    dec_qk = playfair_decrypt("QK", key)
    dec_ui = playfair_decrypt("UI", key)
    
    if dec_qk in common_bigrams or dec_qk == "LO":
        print(f"Key '{key}': QK -> {dec_qk}")
        
    if dec_ui in common_bigrams or dec_ui == "ES":
        print(f"Key '{key}': UI -> {dec_ui}")

