# Base64 Encoding Challenge
import base64

# Original flag
flag = b"flag{base64_is_not_encryption}"

# Encode with base64
encoded = base64.b64encode(flag).decode()

print("Encoded flag:", encoded)
print("Hint: This is just encoded, not encrypted!")
print("Decode it to get the flag.")