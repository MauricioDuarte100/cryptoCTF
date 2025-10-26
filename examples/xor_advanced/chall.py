# XOR Challenge - Advanced Single Byte
# XOR with a single byte key, output in hex

import binascii

# Original flag
flag = b"flag{xor_single_byte_advanced}"

# XOR key (single byte)
key = 0x5A  # 90 in decimal

# XOR encryption
encrypted = bytes([b ^ key for b in flag])

# Convert to hex for the challenge
encrypted_hex = encrypted.hex().upper()

print("Encrypted flag (hex):", encrypted_hex)
print("Hint: Single byte XOR key was used")
print("The key is between 0x00 and 0xFF")
print("Try all possible keys to find the flag!")

# Expected: XOR attack should try all 256 keys and find the flag