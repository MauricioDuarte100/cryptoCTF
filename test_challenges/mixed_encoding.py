#!/usr/bin/env python3
"""
Test Challenge: Mixed Encoding
Flag hidden with Base64 + Hex encoding
"""

import base64

# Original flag
flag = "flag{mixed_encodings_rock}"

# First encode as hex
hex_encoded = flag.encode().hex()

# Then encode with Base64
b64_encoded = base64.b64encode(hex_encoded.encode()).decode()

print("Mixed Encoding Challenge")
print("=" * 40)
print("Decode this to find the flag:")
print(b64_encoded)
print()
print("Hint: Multiple encoding layers used!")