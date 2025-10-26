#!/usr/bin/env python3
"""
Caesar Cipher Challenge
Classic shift cipher
"""

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Challenge
plaintext = "flag{caesar_cipher_is_easy_to_break}"
shift = 13  # ROT13

encrypted = caesar_encrypt(plaintext, shift)

print("Caesar Cipher Challenge")
print("=" * 30)
print(f"Encrypted message: {encrypted}")
print()
print("Decrypt to find the flag!")
print("Hint: Try all possible shifts (0-25)")

# Solution
# for i in range(26):
#     decrypted = caesar_encrypt(encrypted, -i)
#     if "flag{" in decrypted:
#         print(f"Shift {i}: {decrypted}")