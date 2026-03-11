"""Analyze Freddie.txt for hidden data - check character frequencies, 
line lengths, specific characters, hex values embedded, etc."""

with open("challenges/handout/Killer-Queen/Freddie.txt", 'rb') as f:
    raw = f.read()

print(f"File size: {len(raw)} bytes")
print(f"Printable chars only? {all(c in range(32, 127) or c in (13, 10) for c in raw)}")

# Count non-whitespace characters per line  
lines = raw.decode('utf-8', errors='replace').split('\n')
print(f"Total lines: {len(lines)}")

# Check if specific chars appear: look for hidden message in e.g. first chars, specific positions
print("\n=== First char of each line ===")
for i, line in enumerate(lines):
    stripped = line.rstrip('\r')
    if stripped:
        first_nonspace = None
        for ch in stripped:
            if ch not in ' \t':
                first_nonspace = ch
                break
        if first_nonspace:
            print(f"Line {i+1}: first_nonspace='{first_nonspace}' (ord={ord(first_nonspace)})")

# Check unique characters used
from collections import Counter
chars = Counter(raw.decode('utf-8', errors='replace'))
print(f"\n=== Unique characters ({len(chars)}) ===")
for ch, count in sorted(chars.items(), key=lambda x: -x[1]):
    if ch not in '\r\n':
        print(f"  '{ch}' (ord={ord(ch)}): {count} times")

# Check line lengths (could encode binary)
print("\n=== Line lengths ===")
for i, line in enumerate(lines):
    stripped = line.rstrip('\r')
    print(f"Line {i+1}: len={len(stripped)}")

# Check last 2 lines for hints
print("\n=== Last lines ===")
for line in lines[-5:]:
    print(repr(line))

# Look for patterns in the non-standard chars
print("\n=== Non-standard printable characters ===")
art_chars = set()
for line in lines:
    for ch in line:
        if ch not in ' \r\n\t' and not ch.isalnum():
            art_chars.add(ch)
print(f"Art characters: {sorted(art_chars)}")
