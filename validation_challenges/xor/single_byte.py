#!/usr/bin/env python3
"""
Single Byte XOR Challenge
XOR with single byte key
"""

def single_byte_xor(data, key):
    return bytes([b ^ key for b in data])

# Challenge
flag = b"flag{single_byte_xor_cracked}"
key = 0x42  # Single byte key

encrypted = single_byte_xor(flag, key)
encrypted_hex = encrypted.hex()

print("Single Byte XOR Challenge")
print("=" * 35)
print(f"Encrypted (hex): {encrypted_hex}")
print()
print("Find the single byte key and decrypt!")
print("Hint: Try all possible byte values (0-255)")

# Solution
# encrypted_bytes = bytes.fromhex(encrypted_hex)
# for key in range(256):
#     decrypted = single_byte_xor(encrypted_bytes, key)
#     try:
#         text = decrypted.decode('ascii')
#         if "flag{" in text:
#             print(f"Key: {key} (0x{key:02x})")
#             print(f"Flag: {text}")
#     except:
#         pass