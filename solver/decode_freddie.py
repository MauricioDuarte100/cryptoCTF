"""
Decode the ASCII art. Theories:
1. Each art character = a digit (0-9), forming a large number
2. Whitespace-trimming patterns encode data
3. Non-space character positions encode binary data
4. The trailing spaces on each line encode data in their count
Let's try all approaches.
"""

with open("challenges/handout/Killer-Queen/Freddie.txt", 'r', encoding='utf-8') as f:
    lines = [l.rstrip('\r\n') for l in f.readlines()]

# The art lines are 1-100 (lines[0] to lines[99])
art_lines = lines[:100]

# Unique non-space chars in art
art_chars = set()
for line in art_lines:
    for ch in line:
        if ch != ' ':
            art_chars.add(ch)

art_chars_sorted = sorted(art_chars)
print(f"Art characters ({len(art_chars)}): {art_chars_sorted}")
print(f"Char -> ASCII values: {[(c, ord(c)) for c in art_chars_sorted]}")

# Theory 1: Map chars to digits by frequency or ASCII order
# ASCII order: # % * + - . : = @
# Sorted by frequency (from analysis): = : - . + * @ # %
# Try ASCII order mapping
ascii_order = sorted(art_chars_sorted)  # Already sorted
print(f"\nASCII order: {ascii_order}")

# Theory 2: Read the non-space characters left-to-right, top-to-bottom
# and map each to a digit
all_chars = ""
for line in art_lines:
    for ch in line:
        if ch != ' ':
            all_chars += ch

print(f"\nTotal non-space chars: {len(all_chars)}")
print(f"First 100 chars: {all_chars[:100]}")

# Theory 3: Trailing space count per line
print("\n=== Trailing space analysis ===")
for i, line in enumerate(art_lines[:10]):
    original = line
    stripped_right = original.rstrip()
    trailing_spaces = len(original) - len(stripped_right)
    stripped_left = original.lstrip()
    leading_spaces = len(original) - len(stripped_left)
    print(f"Line {i+1}: leading={leading_spaces}, trailing={trailing_spaces}, content_width={len(stripped_right) - leading_spaces}")

# Theory 4: Convert non-space chars to binary (presence/absence)
print("\n=== Binary from character positions ===")
binary_str = ""
for line in art_lines:
    for ch in line:
        binary_str += "1" if ch != ' ' else "0"

# Try interpreting as bits
print(f"Total bits: {len(binary_str)}")
# Check if divisible by 8
print(f"Divisible by 8: {len(binary_str) % 8 == 0}")
# Try extracting bytes
byte_count = len(binary_str) // 8
sample_bytes = bytes(int(binary_str[i*8:(i+1)*8], 2) for i in range(min(50, byte_count)))
print(f"First 50 bytes from binary: {sample_bytes}")

# Theory 5: Only non-space columns per line form a number
# Each character maps to a digit based on the set
# { '#':0, '%':1, '*':2, '+':3, '-':4, '.':5, ':':6, '=':7, '@':8 }
# or by frequency
char_to_digit_ascii = {c: i for i, c in enumerate(ascii_order)}
print(f"\nChar to digit (ASCII order): {char_to_digit_ascii}")

# Build a number from all non-space chars using this mapping
digits = ""
for ch in all_chars:
    digits += str(char_to_digit_ascii.get(ch, '?'))

print(f"Digits (first 200): {digits[:200]}")
print(f"Total digits: {len(digits)}")

# Theory 6: The 10 chars (including space = 10th) represent hex digits
# or: 9 non-space chars + space = base-10
# Let's try interpreting the whole thing as a number in different bases

# Actually, check if trailing spaces encode something
print("\n=== All trailing space counts ===")
trailing_counts = []
for line in art_lines:
    trailing = len(line) - len(line.rstrip())
    trailing_counts.append(trailing)
    
print(trailing_counts)

# Check the file for any non-visible bytes
with open("challenges/handout/Killer-Queen/Freddie.txt", 'rb') as f:
    raw = f.read()

# Check for bytes outside printable ASCII  
non_printable = []
for i, b in enumerate(raw):
    if b < 32 and b not in (10, 13):
        non_printable.append((i, b))
    elif b > 126:
        non_printable.append((i, b))

print(f"\nNon-printable bytes: {non_printable}")

# Check the em-dash area
em_idx = raw.find(b'\xe2\x80\x94')  # UTF-8 em dash
print(f"\nEm-dash at byte position: {em_idx}")
