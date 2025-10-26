# XOR Single Byte Challenge - Real flag
import binascii

# Original flag
flag = b"flag{xor_single_byte_key}"

# XOR with single byte key
key = 0x42  # 66 in decimal
encrypted = bytes([b ^ key for b in flag])

# Convert to hex for the challenge
encrypted_hex = encrypted.hex()

print("Encrypted flag (hex):", encrypted_hex)
print("Hint: Single byte XOR key was used")
print("Try all 256 possible keys to find the flag!")