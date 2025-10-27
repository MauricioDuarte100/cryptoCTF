#!/usr/bin/env python3
"""
Synthetic Writeup Generator
Genera writeups sintéticos de alta calidad para entrenar el modelo
"""

import json
import random
from pathlib import Path
from typing import List, Dict, Any

class SyntheticWriteupGenerator:
    """Generador de writeups sintéticos"""
    
    def __init__(self):
        self.rsa_templates = [
            {
                "title": "RSA Small Modulus Attack",
                "content": """# RSA Small Modulus Challenge

## Challenge Description
We have an RSA encryption with a small modulus that can be factorized.

## Given Parameters
- n = {n}
- e = {e} 
- c = {c}

## Solution
Since the modulus n is small, we can factorize it using trial division or online tools like factordb.com.

```python
import gmpy2

n = {n}
e = {e}
c = {c}

# Factorize n (small modulus)
p = {p}
q = {q}

# Calculate phi(n)
phi = (p - 1) * (q - 1)

# Calculate private key
d = gmpy2.invert(e, phi)

# Decrypt
m = pow(c, d, n)

# Convert to text
flag = bytes.fromhex(hex(m)[2:]).decode()
print(f"Flag: {{flag}}")
```

## Flag
`{flag}`

## Attack Type
RSA Factorization - Small Modulus
""",
                "attack_type": "rsa",
                "difficulty": "easy",
                "tags": ["rsa", "factorization", "small_modulus"]
            },
            {
                "title": "RSA Wiener Attack",
                "content": """# RSA Wiener Attack Challenge

## Challenge Description
RSA with a small private exponent d, vulnerable to Wiener's attack.

## Given Parameters
- n = {n}
- e = {e}
- c = {c}

## Solution
When d < n^0.25, we can use Wiener's attack based on continued fractions.

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

def wiener_attack(n, e):
    # Continued fraction expansion of e/n
    convergents = []
    a = e
    b = n
    
    while b != 0:
        q = a // b
        convergents.append(q)
        a, b = b, a % b
    
    # Test convergents
    for i in range(len(convergents)):
        k, d = get_convergent(convergents[:i+1])
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            disc = s * s - 4 * n
            if disc >= 0:
                sqrt_disc = gmpy2.isqrt(disc)
                if sqrt_disc * sqrt_disc == disc:
                    return d
    return None

n = {n}
e = {e}
c = {c}

d = wiener_attack(n, e)
if d:
    m = pow(c, d, n)
    flag = long_to_bytes(m).decode()
    print(f"Flag: {{flag}}")
```

## Flag
`{flag}`

## Attack Type
RSA Wiener Attack - Small Private Exponent
""",
                "attack_type": "rsa",
                "difficulty": "medium",
                "tags": ["rsa", "wiener", "continued_fractions", "small_d"]
            }
        ]
        
        self.classical_templates = [
            {
                "title": "Caesar Cipher Challenge",
                "content": """# Caesar Cipher Challenge

## Challenge Description
A simple Caesar cipher with unknown shift value.

## Given Ciphertext
`{ciphertext}`

## Solution
Try all possible shifts (0-25) and look for readable English text.

```python
def caesar_decrypt(ciphertext, shift):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

ciphertext = "{ciphertext}"

for shift in range(26):
    decrypted = caesar_decrypt(ciphertext, shift)
    if "flag" in decrypted.lower():
        print(f"Shift {{shift}}: {{decrypted}}")
        break
```

## Flag
`{flag}`

## Attack Type
Classical Cipher - Caesar Cipher Brute Force
""",
                "attack_type": "classical",
                "difficulty": "easy",
                "tags": ["caesar", "classical", "brute_force"]
            },
            {
                "title": "Vigenère Cipher with Known Key Length",
                "content": """# Vigenère Cipher Challenge

## Challenge Description
Vigenère cipher with hint about key length.

## Given Information
- Ciphertext: `{ciphertext}`
- Key length: {key_length}

## Solution
Use frequency analysis on each position modulo key length.

```python
def vigenere_decrypt(ciphertext, key):
    result = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

# Frequency analysis to find key
ciphertext = "{ciphertext}"
key_length = {key_length}

# ... frequency analysis code ...
key = "{key}"

flag = vigenere_decrypt(ciphertext, key)
print(f"Flag: {{flag}}")
```

## Flag
`{flag}`

## Attack Type
Classical Cipher - Vigenère Frequency Analysis
""",
                "attack_type": "classical",
                "difficulty": "medium",
                "tags": ["vigenere", "frequency_analysis", "classical"]
            }
        ]
        
        self.hash_templates = [
            {
                "title": "MD5 Hash Cracking",
                "content": """# MD5 Hash Cracking Challenge

## Challenge Description
Find the original message that produces this MD5 hash.

## Given Hash
`{hash_value}`

## Solution
Try common passwords and dictionary words.

```python
import hashlib

target_hash = "{hash_value}"
wordlist = ["password", "admin", "root", "flag", "ctf", "{original}"]

for word in wordlist:
    if hashlib.md5(word.encode()).hexdigest() == target_hash:
        print(f"Found: {{word}}")
        break
```

## Flag
`flag{{{original}}}`

## Attack Type
Hash Cracking - Dictionary Attack
""",
                "attack_type": "hash",
                "difficulty": "easy",
                "tags": ["md5", "hash_cracking", "dictionary"]
            }
        ]
        
        self.aes_templates = [
            {
                "title": "AES ECB Mode Detection",
                "content": """# AES ECB Mode Challenge

## Challenge Description
AES encrypted data with ECB mode and common key.

## Given Data
- Ciphertext: `{ciphertext}`
- Hint: Common CTF key

## Solution
Try common keys like "YELLOW SUBMARINE".

```python
from Crypto.Cipher import AES
import base64

ciphertext = base64.b64decode("{ciphertext}")
common_keys = [b"YELLOW SUBMARINE", b"KEYKEYKEYKEYKEY!", b"1234567890123456"]

for key in common_keys:
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        if b"flag" in decrypted.lower():
            print(f"Key: {{key}}")
            print(f"Flag: {{decrypted.decode()}}")
            break
    except:
        continue
```

## Flag
`{flag}`

## Attack Type
AES ECB - Common Key Attack
""",
                "attack_type": "aes",
                "difficulty": "easy",
                "tags": ["aes", "ecb", "common_key"]
            }
        ]
    
    def generate_rsa_writeup(self) -> Dict[str, Any]:
        """Genera un writeup de RSA"""
        template = random.choice(self.rsa_templates)
        
        # Generar parámetros RSA
        if "small modulus" in template["title"].lower():
            p, q = 17, 19  # Números primos pequeños
            n = p * q
            e = 5
            m = 123456
            c = pow(m, e, n)
            flag = "flag{small_rsa_cracked}"
        else:
            # Parámetros para Wiener
            p, q = 1009, 1013
            n = p * q
            e = 123456
            c = 654321
            flag = "flag{wiener_attack_success}"
        
        content = template["content"].format(
            n=n, e=e, c=c, p=p, q=q, flag=flag
        )
        
        return {
            "title": template["title"],
            "content": content,
            "attack_type": template["attack_type"],
            "difficulty": template["difficulty"],
            "source": "synthetic",
            "url": "generated",
            "tags": template["tags"]
        }
    
    def generate_classical_writeup(self) -> Dict[str, Any]:
        """Genera un writeup de cifrado clásico"""
        template = random.choice(self.classical_templates)
        
        if "caesar" in template["title"].lower():
            flag = "flag{caesar_cipher_solved}"
            shift = random.randint(1, 25)
            # Cifrar el flag con Caesar
            ciphertext = ""
            for char in flag:
                if char.isalpha():
                    base = ord('a')
                    ciphertext += chr((ord(char) - base + shift) % 26 + base)
                else:
                    ciphertext += char
        else:
            # Vigenère
            flag = "flag{vigenere_frequency_analysis}"
            key = "KEY"
            key_length = len(key)
            ciphertext = "encrypted_with_vigenere"
        
        content = template["content"].format(
            ciphertext=ciphertext,
            flag=flag,
            key_length=key_length if 'key_length' in locals() else 3,
            key=key if 'key' in locals() else "KEY"
        )
        
        return {
            "title": template["title"],
            "content": content,
            "attack_type": template["attack_type"],
            "difficulty": template["difficulty"],
            "source": "synthetic",
            "url": "generated",
            "tags": template["tags"]
        }
    
    def generate_hash_writeup(self) -> Dict[str, Any]:
        """Genera un writeup de hash"""
        template = random.choice(self.hash_templates)
        
        import hashlib
        original = random.choice(["password", "admin", "flag", "secret", "key"])
        hash_value = hashlib.md5(original.encode()).hexdigest()
        
        content = template["content"].format(
            hash_value=hash_value,
            original=original
        )
        
        return {
            "title": template["title"],
            "content": content,
            "attack_type": template["attack_type"],
            "difficulty": template["difficulty"],
            "source": "synthetic",
            "url": "generated",
            "tags": template["tags"]
        }
    
    def generate_aes_writeup(self) -> Dict[str, Any]:
        """Genera un writeup de AES"""
        template = random.choice(self.aes_templates)
        
        import base64
        flag = "flag{aes_ecb_cracked}"
        # Simular ciphertext
        ciphertext = base64.b64encode(b"fake_encrypted_data_here").decode()
        
        content = template["content"].format(
            ciphertext=ciphertext,
            flag=flag
        )
        
        return {
            "title": template["title"],
            "content": content,
            "attack_type": template["attack_type"],
            "difficulty": template["difficulty"],
            "source": "synthetic",
            "url": "generated",
            "tags": template["tags"]
        }
    
    def generate_writeups(self, count: int = 50) -> List[Dict[str, Any]]:
        """Genera múltiples writeups sintéticos"""
        writeups = []
        
        # Distribución por tipo
        types_distribution = {
            'rsa': 0.3,
            'classical': 0.25,
            'hash': 0.2,
            'aes': 0.25
        }
        
        for _ in range(count):
            rand = random.random()
            
            if rand < types_distribution['rsa']:
                writeup = self.generate_rsa_writeup()
            elif rand < types_distribution['rsa'] + types_distribution['classical']:
                writeup = self.generate_classical_writeup()
            elif rand < types_distribution['rsa'] + types_distribution['classical'] + types_distribution['hash']:
                writeup = self.generate_hash_writeup()
            else:
                writeup = self.generate_aes_writeup()
            
            writeups.append(writeup)
        
        return writeups

def main():
    """Función principal"""
    print("🚀 Synthetic Writeup Generator")
    print("=" * 40)
    
    generator = SyntheticWriteupGenerator()
    
    # Generar writeups sintéticos
    print("🎯 Generating synthetic writeups...")
    synthetic_writeups = generator.generate_writeups(50)
    
    print(f"📊 Generated {len(synthetic_writeups)} synthetic writeups")
    
    # Estadísticas
    attack_types = {}
    difficulties = {}
    
    for writeup in synthetic_writeups:
        attack_types[writeup['attack_type']] = attack_types.get(writeup['attack_type'], 0) + 1
        difficulties[writeup['difficulty']] = difficulties.get(writeup['difficulty'], 0) + 1
    
    print(f"\n📈 Attack Types:")
    for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   {attack_type}: {count}")
    
    print(f"\n📊 Difficulties:")
    for difficulty, count in sorted(difficulties.items(), key=lambda x: x[1], reverse=True):
        print(f"   {difficulty}: {count}")
    
    # Guardar writeups sintéticos
    output_path = Path("real_writeups_train/crypto_writeups_synthetic.jsonl")
    output_path.parent.mkdir(exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for writeup in synthetic_writeups:
            f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
    
    print(f"\n💾 Saved to: {output_path}")
    
    # Combinar con writeups reales si existen
    real_writeups_path = Path("real_writeups_train/crypto_writeups_scraped.jsonl")
    if real_writeups_path.exists():
        print(f"\n🔗 Combining with real writeups...")
        
        # Leer writeups reales
        real_writeups = []
        with open(real_writeups_path, 'r', encoding='utf-8') as f:
            for line in f:
                real_writeups.append(json.loads(line))
        
        # Combinar
        all_writeups = real_writeups + synthetic_writeups
        
        # Guardar dataset combinado
        combined_path = Path("real_writeups_train/crypto_writeups_combined.jsonl")
        with open(combined_path, 'w', encoding='utf-8') as f:
            for writeup in all_writeups:
                f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
        
        print(f"📊 Combined dataset: {len(all_writeups)} writeups")
        print(f"   Real: {len(real_writeups)}")
        print(f"   Synthetic: {len(synthetic_writeups)}")
        print(f"💾 Saved to: {combined_path}")
    
    print(f"\n🎉 Synthetic writeup generation completed!")

if __name__ == "__main__":
    main()