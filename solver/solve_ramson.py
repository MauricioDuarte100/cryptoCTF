"""
Solver for ramson.py - 3-layer ransomware decryption

Layer 3 (RSA): d=56771, n=57833 - decrypt the encrypted message
Layer 2 (XOR): key "0x1337" - reverse the XOR
Layer 1 (ChaCha20): use the recovered key and given nonce
"""

import base64
from Crypto.Cipher import ChaCha20

# Given data
encrypted_flag = "4HGJ/3Y6iekXR+FXdpdpa+ww4601QUtLGAzHO/8="
nonce_b64 = "nFE+9jfXTKM="
d = 56771
n = 57833
encrypted_message = [41179, 49562, 30232, 7343, 51179, 49562, 24766, 36190, 30119, 33040, 22179, 44468, 15095, 22179, 3838, 28703, 32061, 17380, 34902, 51373, 41673, 6824, 41673, 26412, 27116, 51179, 34646, 15095, 10590, 11075, 1613, 20320, 31597, 51373, 20320, 44468, 23130, 47991, 11075, 15095, 34928, 20768, 15095, 8054]

print("🔓 Ransomware Decryption")
print("=" * 50)

# Layer 3: RSA Decryption
# c = m^e mod n, so m = c^d mod n
print("\n📜 Layer 3: RSA Decryption")
decrypted_chars = [chr(pow(c, d, n)) for c in encrypted_message]
obfuscated_key_b64 = ''.join(decrypted_chars)
print(f"   Decrypted (base64 of XOR'd key): {obfuscated_key_b64}")

# Decode base64 to get XOR'd key
obfuscated_key = base64.b64decode(obfuscated_key_b64)
print(f"   XOR'd key (bytes): {obfuscated_key.hex()}")

# Layer 2: XOR with "0x1337"
print("\n📜 Layer 2: XOR Decryption")
xor_key = "0x1337"
chacha_key = bytearray(obfuscated_key[i] ^ ord(xor_key[i % len(xor_key)]) for i in range(len(obfuscated_key)))
print(f"   ChaCha20 key: {chacha_key.hex()}")

# Layer 1: ChaCha20 Decryption
print("\n📜 Layer 1: ChaCha20 Decryption")
nonce = base64.b64decode(nonce_b64)
ciphertext = base64.b64decode(encrypted_flag)

cipher = ChaCha20.new(key=bytes(chacha_key), nonce=nonce)
plaintext = cipher.decrypt(ciphertext).decode('utf-8')

print(f"\n🚩 FLAG: {plaintext}")
