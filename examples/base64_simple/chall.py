# Base64 Encoding Challenge - Simple
# Just base64 encoding, not encryption

import base64

# Original flag
flag = b"flag{base64_is_encoding_not_encryption}"

# Encode with base64
encoded = base64.b64encode(flag).decode('ascii')

print("Encoded message:", encoded)
print("Hint: This is just encoded, not encrypted!")
print("Base64 is not a form of encryption")
print("Decode it to get the flag")

# Expected: decode_text should handle this automatically