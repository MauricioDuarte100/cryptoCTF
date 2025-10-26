#!/usr/bin/env python3
"""
Test Challenge: Base64 Multi-layer
Flag hidden in multiple layers of Base64 encoding
"""

import base64

# Original flag
flag = "flag{base64_layers_are_fun}"

# Encode multiple times
layer1 = base64.b64encode(flag.encode()).decode()
layer2 = base64.b64encode(layer1.encode()).decode()
layer3 = base64.b64encode(layer2.encode()).decode()

print("Multi-layer Base64 Challenge")
print("=" * 40)
print("Decode this to find the flag:")
print(layer3)
print()
print("Hint: You might need to decode multiple times!")