# Caesar Cipher Challenge - Medium
# ROT13 with mixed case and punctuation

# Original flag
flag = "flag{caesar_is_classical_crypto}"

# Apply ROT13 (shift by 13)
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

# Encrypt with ROT13
encrypted = caesar_encrypt(flag, 13)

print("Encrypted flag:", encrypted)
print("Hint: This is a classic Caesar cipher")
print("Try different shift values to decrypt!")

# Expected output: synt{pnrfne_vf_pynffvpny_pelcgb}