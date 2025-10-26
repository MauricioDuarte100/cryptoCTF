#!/usr/bin/env python3
"""
Simple Base64 Test
"""

import base64

# Simple Base64 encoding
flag = "flag{base64_layers_decoded}"

# Apply 3 layers of Base64 encoding
encoded = flag
for i in range(3):
    encoded = base64.b64encode(encoded.encode()).decode()

print("Base64 Test - 3 Layers")
print("=" * 30)
print(f"Encoded message: {encoded}")
print()
print("Decode to find the flag!")