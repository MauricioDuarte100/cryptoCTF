#!/usr/bin/env python3
"""
EXPAND CRYPTO DATASET
Expande el dataset con más ejemplos sintéticos para mejorar el entrenamiento de BERT
"""

import json
from pathlib import Path
from datetime import datetime

def create_expanded_crypto_dataset():
    """Crea un dataset expandido con más ejemplos"""
    
    writeups = []
    
    # RSA Writeups (más variedad)
    rsa_writeups = [
        {
            'id': 'rsa_factorization_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'RSA Factorization Challenge',
            'attack_type': 'RSA',
            'writeup': '''# RSA Factorization Challenge

## Challenge
We have RSA parameters where n can be factorized easily.

Given:
- n = p * q (small factors)
- e = 65537
- c = encrypted flag

## Solution
Factor n to find p and q, then compute private key d.

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def factorize_n(n):
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

n = 0x123456789abcdef
e = 65537
c = 0xfedcba987654321

p, q = factorize_n(n)
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())
```''',
            'solution_code': '''import gmpy2
from Crypto.Util.number import long_to_bytes

def factorize_n(n):
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

n = 0x123456789abcdef
e = 65537
c = 0xfedcba987654321

p, q = factorize_n(n)
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())''',
            'flag': 'flag{rsa_factorization}',
            'scraped_at': datetime.now().isoformat()
        },
        {
            'id': 'rsa_fermat_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'RSA Fermat Attack',
            'attack_type': 'RSA',
            'writeup': '''# RSA Fermat Attack

## Challenge
RSA with p and q very close to each other.

## Analysis
When p ≈ q, Fermat factorization works efficiently.

## Solution
```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def fermat_factor(n):
    a = gmpy2.isqrt(n) + 1
    while True:
        b_squared = a * a - n
        b = gmpy2.isqrt(b_squared)
        if b * b == b_squared:
            return a + b, a - b
        a += 1

n = 0x123456789abcdef
e = 65537
c = 0xfedcba987654321

p, q = fermat_factor(n)
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())
```''',
            'solution_code': '''import gmpy2
from Crypto.Util.number import long_to_bytes

def fermat_factor(n):
    a = gmpy2.isqrt(n) + 1
    while True:
        b_squared = a * a - n
        b = gmpy2.isqrt(b_squared)
        if b * b == b_squared:
            return a + b, a - b
        a += 1''',
            'flag': 'flag{fermat_attack}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # Classical Cipher Writeups
    classical_writeups = [
        {
            'id': 'caesar_basic_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'Caesar Cipher Basic',
            'attack_type': 'Classical',
            'writeup': '''# Caesar Cipher Challenge

## Challenge
Decrypt the Caesar cipher: "WKLV LV D WHVW"

## Solution
Try all 26 possible shifts.

```python
def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

ciphertext = "WKLV LV D WHVW"
for shift in range(26):
    plaintext = caesar_decrypt(ciphertext, shift)
    if "flag" in plaintext.lower():
        print(f"Shift {shift}: {plaintext}")
```''',
            'solution_code': '''def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

ciphertext = "WKLV LV D WHVW"
for shift in range(26):
    plaintext = caesar_decrypt(ciphertext, shift)
    if "flag" in plaintext.lower():
        print(f"Shift {shift}: {plaintext}")''',
            'flag': 'flag{this_is_a_test}',
            'scraped_at': datetime.now().isoformat()
        },
        {
            'id': 'substitution_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'Substitution Cipher',
            'attack_type': 'Classical',
            'writeup': '''# Substitution Cipher

## Challenge
Monoalphabetic substitution cipher with frequency analysis.

## Solution
Use frequency analysis to map letters.

```python
def frequency_analysis(text):
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)

def substitute(text, mapping):
    result = ""
    for char in text:
        if char.upper() in mapping:
            new_char = mapping[char.upper()]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char
    return result

ciphertext = "SYNT{FHOFGVGHGVBA_PVCURE}"
freq = frequency_analysis(ciphertext)
print("Frequency:", freq)

# Manual mapping based on frequency
mapping = {'S': 'F', 'Y': 'L', 'N': 'A', 'T': 'G', 'F': 'S', 'H': 'U', 'O': 'B', 'G': 'T', 'V': 'I', 'P': 'C', 'C': 'P', 'E': 'R', 'U': 'H'}
plaintext = substitute(ciphertext, mapping)
print(f"Plaintext: {plaintext}")
```''',
            'solution_code': '''def frequency_analysis(text):
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)

def substitute(text, mapping):
    result = ""
    for char in text:
        if char.upper() in mapping:
            new_char = mapping[char.upper()]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char
    return result''',
            'flag': 'flag{substitution_cipher}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # XOR Writeups
    xor_writeups = [
        {
            'id': 'xor_repeating_key_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'XOR Repeating Key',
            'attack_type': 'XOR',
            'writeup': '''# XOR Repeating Key

## Challenge
Text encrypted with repeating XOR key.

## Solution
Find key length using Hamming distance, then break each position.

```python
def hamming_distance(s1, s2):
    return sum(bin(a ^ b).count('1') for a, b in zip(s1, s2))

def find_key_length(ciphertext, max_len=20):
    best_len = 1
    best_score = float('inf')
    
    for length in range(2, max_len + 1):
        chunks = [ciphertext[i:i+length] for i in range(0, len(ciphertext), length)]
        if len(chunks) < 2:
            continue
        
        distances = []
        for i in range(len(chunks) - 1):
            if len(chunks[i]) == len(chunks[i+1]):
                distances.append(hamming_distance(chunks[i], chunks[i+1]) / length)
        
        if distances:
            avg_distance = sum(distances) / len(distances)
            if avg_distance < best_score:
                best_score = avg_distance
                best_len = length
    
    return best_len

ciphertext = bytes.fromhex("1a2b3c4d5e6f")
key_length = find_key_length(ciphertext)
print(f"Key length: {key_length}")
```''',
            'solution_code': '''def hamming_distance(s1, s2):
    return sum(bin(a ^ b).count('1') for a, b in zip(s1, s2))

def find_key_length(ciphertext, max_len=20):
    best_len = 1
    best_score = float('inf')
    
    for length in range(2, max_len + 1):
        chunks = [ciphertext[i:i+length] for i in range(0, len(ciphertext), length)]
        if len(chunks) < 2:
            continue
        
        distances = []
        for i in range(len(chunks) - 1):
            if len(chunks[i]) == len(chunks[i+1]):
                distances.append(hamming_distance(chunks[i], chunks[i+1]) / length)
        
        if distances:
            avg_distance = sum(distances) / len(distances)
            if avg_distance < best_score:
                best_score = avg_distance
                best_len = length
    
    return best_len''',
            'flag': 'flag{repeating_xor_key}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # AES Writeups
    aes_writeups = [
        {
            'id': 'aes_cbc_padding_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'AES CBC Padding Oracle',
            'attack_type': 'AES',
            'writeup': '''# AES CBC Padding Oracle

## Challenge
AES CBC with padding oracle vulnerability.

## Solution
Use padding oracle attack to decrypt byte by byte.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def padding_oracle(ciphertext, iv, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        unpad(plaintext, 16)
        return True
    except:
        return False

def padding_oracle_attack(ciphertext, iv, oracle_func):
    # Simplified padding oracle attack
    plaintext = b""
    
    for block_idx in range(len(ciphertext) // 16):
        block = ciphertext[block_idx*16:(block_idx+1)*16]
        prev_block = iv if block_idx == 0 else ciphertext[(block_idx-1)*16:block_idx*16]
        
        # Attack each byte in the block
        for byte_pos in range(15, -1, -1):
            for guess in range(256):
                # Modify previous block to test padding
                test_prev = bytearray(prev_block)
                test_prev[byte_pos] ^= guess
                
                if oracle_func(block, bytes(test_prev)):
                    # Found valid padding
                    plaintext_byte = guess ^ (16 - byte_pos)
                    plaintext = bytes([plaintext_byte]) + plaintext
                    break
    
    return plaintext

# Example usage
key = b"YELLOW SUBMARINE"
iv = b"0123456789abcdef"
ciphertext = bytes.fromhex("deadbeefcafebabe")

oracle = lambda ct, iv: padding_oracle(ct, iv, key)
plaintext = padding_oracle_attack(ciphertext, iv, oracle)
print(f"Plaintext: {plaintext}")
```''',
            'solution_code': '''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def padding_oracle(ciphertext, iv, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        unpad(plaintext, 16)
        return True
    except:
        return False

def padding_oracle_attack(ciphertext, iv, oracle_func):
    plaintext = b""
    
    for block_idx in range(len(ciphertext) // 16):
        block = ciphertext[block_idx*16:(block_idx+1)*16]
        prev_block = iv if block_idx == 0 else ciphertext[(block_idx-1)*16:block_idx*16]
        
        for byte_pos in range(15, -1, -1):
            for guess in range(256):
                test_prev = bytearray(prev_block)
                test_prev[byte_pos] ^= guess
                
                if oracle_func(block, bytes(test_prev)):
                    plaintext_byte = guess ^ (16 - byte_pos)
                    plaintext = bytes([plaintext_byte]) + plaintext
                    break
    
    return plaintext''',
            'flag': 'flag{padding_oracle_attack}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # Hash Writeups
    hash_writeups = [
        {
            'id': 'hash_collision_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'Hash Collision Attack',
            'attack_type': 'Hash',
            'writeup': '''# Hash Collision Attack

## Challenge
Find two different inputs that produce the same hash.

## Solution
Use birthday paradox or known collision techniques.

```python
import hashlib

def find_collision(hash_func, prefix_len=4):
    seen = {}
    counter = 0
    
    while True:
        data = f"input_{counter}".encode()
        hash_val = hash_func(data).hexdigest()[:prefix_len]
        
        if hash_val in seen:
            return seen[hash_val], data, hash_val
        
        seen[hash_val] = data
        counter += 1
        
        if counter > 100000:  # Prevent infinite loop
            break
    
    return None, None, None

# Find MD5 collision (first 4 hex chars)
input1, input2, collision_hash = find_collision(hashlib.md5, 4)

if input1 and input2:
    print(f"Collision found!")
    print(f"Input 1: {input1}")
    print(f"Input 2: {input2}")
    print(f"Hash prefix: {collision_hash}")
    
    # Verify
    hash1 = hashlib.md5(input1).hexdigest()[:4]
    hash2 = hashlib.md5(input2).hexdigest()[:4]
    print(f"Verification: {hash1} == {hash2}")
```''',
            'solution_code': '''import hashlib

def find_collision(hash_func, prefix_len=4):
    seen = {}
    counter = 0
    
    while True:
        data = f"input_{counter}".encode()
        hash_val = hash_func(data).hexdigest()[:prefix_len]
        
        if hash_val in seen:
            return seen[hash_val], data, hash_val
        
        seen[hash_val] = data
        counter += 1
        
        if counter > 100000:
            break
    
    return None, None, None''',
            'flag': 'flag{hash_collision_found}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # Encoding Writeups
    encoding_writeups = [
        {
            'id': 'base64_layers_1',
            'team': 'crypto_team',
            'repo': 'synthetic',
            'challenge_name': 'Base64 Multiple Layers',
            'attack_type': 'Encoding',
            'writeup': '''# Base64 Multiple Layers

## Challenge
Flag encoded with multiple layers of Base64.

## Solution
Decode recursively until we get readable text.

```python
import base64
import re

def decode_base64_recursive(data, max_depth=10):
    current = data.strip()
    
    for depth in range(max_depth):
        try:
            decoded = base64.b64decode(current).decode('utf-8')
            print(f"Layer {depth + 1}: {decoded[:50]}...")
            
            if 'flag{' in decoded.lower():
                return decoded
            
            # Check if it's still base64
            if re.match(r'^[A-Za-z0-9+/=]+$', decoded.strip()):
                current = decoded.strip()
            else:
                return decoded
                
        except:
            return current
    
    return current

encoded = "Vm14YUZvemRHbFpXRTVzVG1wU1ptSkhSalZhV0VwNldESkdlVnBXT1cxa1Z6VTU="
flag = decode_base64_recursive(encoded)
print(f"Flag: {flag}")
```''',
            'solution_code': '''import base64
import re

def decode_base64_recursive(data, max_depth=10):
    current = data.strip()
    
    for depth in range(max_depth):
        try:
            decoded = base64.b64decode(current).decode('utf-8')
            print(f"Layer {depth + 1}: {decoded[:50]}...")
            
            if 'flag{' in decoded.lower():
                return decoded
            
            if re.match(r'^[A-Za-z0-9+/=]+$', decoded.strip()):
                current = decoded.strip()
            else:
                return decoded
                
        except:
            return current
    
    return current''',
            'flag': 'flag{base64_layers_decoded}',
            'scraped_at': datetime.now().isoformat()
        }
    ]
    
    # Combinar todos los writeups
    writeups.extend(rsa_writeups)
    writeups.extend(classical_writeups)
    writeups.extend(xor_writeups)
    writeups.extend(aes_writeups)
    writeups.extend(hash_writeups)
    writeups.extend(encoding_writeups)
    
    return writeups

def main():
    """Función principal"""
    print("🚀 EXPANDING CRYPTO DATASET")
    print("=" * 50)
    
    # Cargar dataset existente
    existing_writeups = []
    existing_file = Path("data/writeups_real_ctf_teams.jsonl")
    
    if existing_file.exists():
        with open(existing_file, 'r', encoding='utf-8') as f:
            for line in f:
                existing_writeups.append(json.loads(line.strip()))
        print(f"📥 Loaded {len(existing_writeups)} existing writeups")
    
    # Crear writeups adicionales
    new_writeups = create_expanded_crypto_dataset()
    print(f"✨ Created {len(new_writeups)} new synthetic writeups")
    
    # Combinar todos
    all_writeups = existing_writeups + new_writeups
    
    # Guardar dataset expandido
    output_file = "data/writeups_real_ctf_teams.jsonl"
    with open(output_file, 'w', encoding='utf-8') as f:
        for writeup in all_writeups:
            f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
    
    print(f"💾 Saved {len(all_writeups)} total writeups to {output_file}")
    
    # Estadísticas
    attack_types = {}
    for writeup in all_writeups:
        attack_type = writeup['attack_type']
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    print(f"\n📊 Final Dataset Statistics:")
    print(f"Total writeups: {len(all_writeups)}")
    for attack_type, count in sorted(attack_types.items()):
        print(f"  {attack_type}: {count}")
    
    print("\n🎉 DATASET EXPANSION COMPLETED!")
    print("✅ Ready for improved BERT training")
    
    return True

if __name__ == "__main__":
    main()