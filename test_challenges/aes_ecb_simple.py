#!/usr/bin/env python3
"""
Test Challenge: AES ECB Simple
Flag encrypted with AES ECB mode using common key
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

# Flag to encrypt
flag = "flag{aes_ecb_is_weak}"

# Common key used in many challenges
key = b"YELLOW SUBMARINE"

# Encrypt with AES ECB
cipher = AES.new(key, AES.MODE_ECB)
padded_flag = pad(flag.encode(), 16)
ciphertext = cipher.encrypt(padded_flag)

print("AES ECB Challenge")
print("=" * 40)
print("Encrypted flag (hex):")
print(binascii.hexlify(ciphertext).decode())
print()
print("Hint: This uses a very common key in CTF challenges!")
print("Hint: The mode might be ECB...")