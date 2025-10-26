"""
Create Sample Data for RAG
Genera datos sintéticos de writeups y challenges para probar RAG.
Basado en el dataset de la Fase 2.2.
"""

import json
from pathlib import Path
from rag.utils import save_jsonl, logger

def create_sample_writeups():
    """Crea writeups sintéticos para RAG"""
    writeups = [
        {
            "id": "writeup_001",
            "content": """
# RSA Small Exponent Attack (e=3)

This challenge presents a classic RSA vulnerability where the public exponent e=3 is too small.

## Challenge Analysis
- n = 12345678901234567890123456789012345678901234567890
- e = 3  
- c = 9876543210987654321098765432109876543210987654321

## Solution Approach
Since e=3 is very small, we can try a cube root attack. If the plaintext m is small enough that m^3 < n, then we can simply compute the cube root of c to get m.

## Implementation
```python
import gmpy2
c = 9876543210987654321098765432109876543210987654321
m = gmpy2.iroot(c, 3)[0]
print(long_to_bytes(m))
```

## Key Learning
Always check for small exponent vulnerabilities in RSA challenges.
            """,
            "repo": "github/ashutosh1206",
            "words": 150,
            "ctf_event": "PicoCTF 2023"
        },
        {
            "id": "writeup_002", 
            "content": """
# Caesar Cipher ROT13 Writeup

Simple substitution cipher where each letter is shifted by 13 positions.

## Challenge
ciphertext = "synt{pnrfne_pvcure_vf_abg_frpher}"

## Solution
ROT13 is its own inverse, so we just apply ROT13 again:
```python
def rot13(text):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + 13) % 26 + base)
        else:
            result += char
    return result

flag = rot13("synt{pnrfne_pvcure_vf_abg_frpher}")
print(flag)  # flag{caesar_cipher_is_not_secure}
```

## Pattern
Look for patterns in classical ciphers - frequency analysis, common words.
            """,
            "repo": "github/7rocky",
            "words": 120,
            "ctf_event": "CSAW 2023"
        },
        {
            "id": "writeup_003",
            "content": """
# XOR Single Byte Key Recovery

Challenge where flag is XORed with a single byte key.

## Analysis
encrypted = bytes.fromhex("1a0e1b1c5b7e0e1f5b1a0e1b1c5b0e1f5b7e0e1f")

## Brute Force Approach
Since it's single byte, only 256 possibilities:
```python
for key in range(256):
    decrypted = bytes([b ^ key for b in encrypted])
    if b'flag{' in decrypted:
        print(f"Key: {key}, Flag: {decrypted.decode()}")
        break
```

## Advanced: Frequency Analysis
Look for common English patterns like 'the', 'and', etc.

## Result
Key was 0x42, flag{xor_is_not_secure}
            """,
            "repo": "github/sajjadium", 
            "words": 100,
            "ctf_event": "DEFCON 31"
        },
        {
            "id": "writeup_004",
            "content": """
# Base64 Decoding Challenge

Not really encryption, just encoding.

## Challenge
encoded = "ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"

## Solution
```python
import base64
decoded = base64.b64decode(encoded)
print(decoded.decode())  # flag{base64_is_not_encryption}
```

## Key Point
Base64 is encoding, not encryption. Always try basic decoding first.
            """,
            "repo": "github/crypto-cat",
            "words": 60,
            "ctf_event": "BSides 2023"
        },
        {
            "id": "writeup_005",
            "content": """
# MD5 Hash Cracking

Hash cracking using dictionary attack.

## Challenge
target_hash = "5d41402abc4b2a76b9719d911017c592"

## Solution Approach
1. Try common passwords
2. Use rainbow tables
3. Brute force if needed

```python
import hashlib
common_words = ["hello", "world", "password", "admin"]
for word in common_words:
    if hashlib.md5(word.encode()).hexdigest() == target_hash:
        print(f"Found: {word}")
        break
```

Result: "hello" -> flag{hello_cracked}
            """,
            "repo": "github/hash-master",
            "words": 90,
            "ctf_event": "HackTheBox"
        }
    ]
    
    return writeups

def create_sample_challenges():
    """Crea challenges sintéticos para RAG"""
    challenges = [
        {
            "id": "challenge_001",
            "content": """
# RSA Challenge - Small Exponent
n = 12345678901234567890123456789012345678901234567890123456789012345678901234567890
e = 3
c = 9876543210987654321098765432109876543210987654321098765432109876543210987654321

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("Factor n to get the flag!")
            """,
            "label": "RSA",
            "repo": "ctf-challenges",
            "difficulty": "easy"
        },
        {
            "id": "challenge_002", 
            "content": """
# Caesar Cipher Challenge
ciphertext = "uryyb_pguq_vf_n_pnrfne_grfg"

print("Encrypted message:", ciphertext)
print("Hint: This is a Caesar cipher")
print("Try different rotations to decrypt!")
            """,
            "label": "Classical",
            "repo": "crypto-basics",
            "difficulty": "easy"
        },
        {
            "id": "challenge_003",
            "content": """
# XOR Single Byte Challenge
key = 0x42
encrypted = bytes([p ^ key for p in plaintext])

print("Encrypted flag (hex):", encrypted.hex())
print("Hint: Single byte XOR key was used")
print("Try all 256 possible keys!")
            """,
            "label": "XOR",
            "repo": "xor-challenges", 
            "difficulty": "easy"
        },
        {
            "id": "challenge_004",
            "content": """
# Base64 Encoding Challenge
import base64

encoded_message = "ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"

print("Encoded message:", encoded_message)
print("Hint: This is BASE64 encoded")
print("Decode it to get the flag!")
            """,
            "label": "Encoding",
            "repo": "encoding-challenges",
            "difficulty": "easy"
        },
        {
            "id": "challenge_005",
            "content": """
# Hash Challenge - MD5 Cracking
import hashlib

target_hash = "5d41402abc4b2a76b9719d911017c592"
print(f"Target hash: {target_hash}")
print("Hint: This is an MD5 hash of a simple word")
print("Try common words or use a dictionary attack!")
            """,
            "label": "Hash",
            "repo": "hash-challenges",
            "difficulty": "medium"
        }
    ]
    
    return challenges

def main():
    logger.info("🔄 Creating sample data for RAG...")
    
    # Crear writeups
    writeups = create_sample_writeups()
    writeups_file = Path("ml_phase2/evaluation/writeups_ml_dataset.jsonl")
    save_jsonl(writeups, writeups_file)
    logger.info(f"✅ Created {len(writeups)} writeups")
    
    # Crear challenges  
    challenges = create_sample_challenges()
    challenges_file = Path("ml_phase2/evaluation/challenges_ml_dataset.jsonl")
    save_jsonl(challenges, challenges_file)
    logger.info(f"✅ Created {len(challenges)} challenges")
    
    logger.info("✅ Sample data creation complete!")
    logger.info(f"   Writeups: {writeups_file}")
    logger.info(f"   Challenges: {challenges_file}")

if __name__ == "__main__":
    main()