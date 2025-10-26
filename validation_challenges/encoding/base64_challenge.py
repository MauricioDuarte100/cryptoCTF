#!/usr/bin/env python3
"""
Base64 Encoding Challenge
Multiple layers of Base64 encoding
"""

import base64

# Challenge
flag = "flag{base64_layers_decoded}"

# Apply multiple layers of Base64 encoding
encoded = flag
for i in range(5):  # 5 layers
    encoded = base64.b64encode(encoded.encode()).decode()

print("Base64 Challenge - Multiple Layers")
print("=" * 40)
print(f"Encoded message: {encoded}")
print()
print("Decode all layers to find the flag!")
print("Hint: Keep decoding Base64 until you get readable text")

# Solution
# current = encoded
# layer = 0
# while True:
#     try:
#         decoded = base64.b64decode(current).decode()
#         layer += 1
#         print(f"Layer {layer}: {decoded}")
#         if decoded.startswith("flag{"):
#             break
#         current = decoded
#     except:
#         break