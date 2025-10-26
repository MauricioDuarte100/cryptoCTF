#!/usr/bin/env python3
"""
MD5 Hash Cracking Challenge
Simple dictionary attack
"""

import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

# Challenge
flag_word = "password123"
flag = f"flag{{{flag_word}}}"

hashed = md5_hash(flag_word)

print("MD5 Hash Cracking Challenge")
print("=" * 35)
print(f"MD5 hash: {hashed}")
print()
print("Crack the hash to find the word, then format as flag{word}")
print("Hint: Try common passwords")

# Common passwords for dictionary attack
common_passwords = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "1234567890", "qwerty", "abc123"
]

# Solution
# for password in common_passwords:
#     if md5_hash(password) == hashed:
#         print(f"Found: {password}")
#         print(f"Flag: flag{{{password}}}")
#         break