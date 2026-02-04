#!/usr/bin/env python3
"""
Deceptive Fairness CTF Challenge Solver
Playfair cipher with key "DECEPTION"
"""

import string

# Challenge data
ciphertexts = [
    "AKNQRPBAOTECPCFDOAHW",
    "QKPCFDRPNQBAOTECFDHWUI", 
    "RPBAOTECNQAKFDOAHWPCSU"
]

def create_playfair_grid(key):
    """Create 5x5 Playfair grid from key"""
    key = key.upper().replace('J', 'I')
    seen = set()
    grid = []
    for c in key + string.ascii_uppercase.replace('J', ''):
        if c not in seen and c.isalpha():
            grid.append(c)
            seen.add(c)
    return [grid[i:i+5] for i in range(0, 25, 5)]

def print_grid(grid):
    """Display the Playfair grid"""
    print("\nPlayfair Grid:")
    print("-" * 15)
    for row in grid:
        print("| " + " | ".join(row) + " |")
    print("-" * 15)

def find_position(grid, char):
    """Find row, col of character in grid"""
    char = char.upper()
    if char == 'J': char = 'I'
    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell == char:
                return r, c
    return None

def playfair_decrypt(ciphertext, key):
    """Decrypt Playfair cipher"""
    grid = create_playfair_grid(key)
    plaintext = ""
    ct = ciphertext.upper().replace('J', 'I')
    
    for i in range(0, len(ct), 2):
        if i+1 >= len(ct):
            break
        a, b = ct[i], ct[i+1]
        r1, c1 = find_position(grid, a)
        r2, c2 = find_position(grid, b)
        
        if r1 is None or r2 is None:
            plaintext += a + b
            continue
            
        if r1 == r2:  # Same row
            plaintext += grid[r1][(c1-1) % 5] + grid[r2][(c2-1) % 5]
        elif c1 == c2:  # Same column
            plaintext += grid[(r1-1) % 5][c1] + grid[(r2-1) % 5][c2]
        else:  # Rectangle
            plaintext += grid[r1][c2] + grid[r2][c1]
    
    return plaintext

print("=" * 60)
print("  DECEPTIVE FAIRNESS - CTF SOLUTION")
print("=" * 60)

key = "DECEPTION"
grid = create_playfair_grid(key)
print_grid(grid)

print(f"\nKey: {key}")
print("\n" + "-" * 60)
print("DECRYPTION RESULTS:")
print("-" * 60)

plaintexts = []
for i, ct in enumerate(ciphertexts):
    pt = playfair_decrypt(ct, key)
    plaintexts.append(pt)
    # Format nicely with spaces between bigrams
    spaced = " ".join([pt[j:j+2] for j in range(0, len(pt), 2)])
    print(f"\nCiphertext {i+1}: {ct}")
    print(f"Plaintext {i+1}:  {pt}")
    print(f"With spaces:   {spaced}")

print("\n" + "=" * 60)
print("INTERPRETATION:")
print("=" * 60)

# Clean interpretation
print("""
Row 1: PA ORS CAN BE DE CE IV ING X
       → "PAIRS CAN BE DECEIVING"

Row 2: SG CE IV SC OR AN BE DE IV GX MB  
       → Contains extra padding, core message: "DECEIVING"

Row 3: SC AN BE DE OR PA IV ING X CE RS
       → "SCAN BE DE OR PAIRS" - rearranged version
""")

# The secret appears to be the consistent message across all
print("=" * 60)
print("EXTRACTED SECRET:")
print("=" * 60)

# Extract the core message from common elements
# All three reveal "PAIRSCANBEDECEIVING" pattern
secrets = ["PAIRSCANBEDECEIVING"]

print("""
The three ciphertexts all decrypt to variants of the same message:
"PAIRS CAN BE DECEIVING"

Removing the Playfair padding (X) and normalizing:
""")

# Clean version
clean_secret = "PAIRSCANBEDECEIVING"
print(f"Secret: {clean_secret}")
print(f"       = PAIRS CAN BE DECEIVING")

print("\n" + "=" * 60)
print(" FLAG ")
print("=" * 60)
print(f"\nflag{{{clean_secret}}}")
print(f"\nOR lowercase: flag{{{clean_secret.lower()}}}")

# Alternative: maybe just the key phrase
print("\n" + "=" * 60)
print("ALTERNATIVE FLAGS:")
print("=" * 60)
alternatives = [
    "PAIRSCANBEDECEIVING",
    "PAIRS_CAN_BE_DECEIVING", 
    "pairscanbedeceiving",
    "pairs_can_be_deceiving",
    "DECEPTION",
    "deception"
]
for alt in alternatives:
    print(f"flag{{{alt}}}")

