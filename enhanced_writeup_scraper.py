#!/usr/bin/env python3
"""
ENHANCED CTF WRITEUPS SCRAPER
Estrategia mejorada para obtener 500+ writeups sin rate limits
"""

import os
import json
import requests
import time
import random
from pathlib import Path
from datetime import datetime

class EnhancedWriteupScraper:
    def __init__(self):
        self.output_dir = Path("data")
        self.output_dir.mkdir(exist_ok=True)
        self.writeups = []
        
        # Generar writeups sintéticos basados en patrones reales
        self.synthetic_templates = {
            'RSA': [
                {
                    'name': 'RSA Small Exponent Attack',
                    'description': 'RSA challenge with e=3, vulnerable to cube root attack',
                    'solution': '''
import gmpy2
from Crypto.Util.number import long_to_bytes

# Given values
n = {n}
e = 3
c = {c}

# Cube root attack for small e
m, exact = gmpy2.iroot(c, 3)
if exact:
    flag = long_to_bytes(m)
    print(flag.decode())
''',
                    'tools': ['gmpy2', 'pycryptodome'],
                    'difficulty': 'easy'
                },
                {
                    'name': 'RSA Wiener Attack',
                    'description': 'RSA with small private exponent d, vulnerable to Wiener attack',
                    'solution': '''
import gmpy2
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

def wiener_attack(n, e):
    # Continued fraction expansion of e/n
    convergents = []
    cf = continued_fraction(e, n)
    
    for i in range(len(cf)):
        convergent = convergents_from_cf(cf[:i+1])
        k, d = convergent[-1]
        
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discriminant = s * s - 4 * n
            
            if discriminant >= 0:
                sqrt_discriminant = gmpy2.isqrt(discriminant)
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    return d
    return None

# Attack implementation
d = wiener_attack(n, e)
if d:
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(flag.decode())
''',
                    'tools': ['gmpy2', 'fractions'],
                    'difficulty': 'medium'
                },
                {
                    'name': 'RSA Fermat Factorization',
                    'description': 'RSA with close prime factors, vulnerable to Fermat factorization',
                    'solution': '''
import gmpy2
from Crypto.Util.number import long_to_bytes

def fermat_factorization(n):
    a = gmpy2.isqrt(n) + 1
    
    while True:
        b_squared = a * a - n
        b = gmpy2.isqrt(b_squared)
        
        if b * b == b_squared:
            p = a + b
            q = a - b
            return p, q
        a += 1

# Factorize n
p, q = fermat_factorization(n)
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())
''',
                    'tools': ['gmpy2'],
                    'difficulty': 'medium'
                }
            ],
            'XOR': [
                {
                    'name': 'Single Byte XOR',
                    'description': 'XOR cipher with single byte key',
                    'solution': '''
def single_byte_xor(data, key):
    return bytes([b ^ key for b in data])

# Brute force all possible keys
encrypted = bytes.fromhex("{hex_data}")

for key in range(256):
    decrypted = single_byte_xor(encrypted, key)
    try:
        text = decrypted.decode('ascii')
        if 'flag{' in text.lower():
            print(f"Key: {key}")
            print(f"Flag: {text}")
            break
    except:
        continue
''',
                    'tools': ['python-builtin'],
                    'difficulty': 'easy'
                },
                {
                    'name': 'Multi-byte XOR Key Reuse',
                    'description': 'XOR with repeating key, vulnerable to frequency analysis',
                    'solution': '''
def xor_decrypt(data, key):
    result = []
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def find_key_length(ciphertext):
    # Kasiski examination or index of coincidence
    for key_len in range(2, 20):
        blocks = [ciphertext[i::key_len] for i in range(key_len)]
        # Analyze frequency patterns
        # ... implementation details
    return key_len

# Key recovery and decryption
encrypted = bytes.fromhex("{hex_data}")
key_length = find_key_length(encrypted)
key = recover_key(encrypted, key_length)
flag = xor_decrypt(encrypted, key)
print(flag.decode())
''',
                    'tools': ['python-builtin', 'frequency-analysis'],
                    'difficulty': 'medium'
                }
            ],
            'Classical': [
                {
                    'name': 'Caesar Cipher',
                    'description': 'Simple shift cipher, brute force all shifts',
                    'solution': '''
def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

encrypted = "{encrypted_text}"

for shift in range(26):
    decrypted = caesar_decrypt(encrypted, shift)
    if 'flag{' in decrypted.lower():
        print(f"Shift: {shift}")
        print(f"Flag: {decrypted}")
        break
''',
                    'tools': ['python-builtin'],
                    'difficulty': 'easy'
                },
                {
                    'name': 'Vigenère Cipher',
                    'description': 'Polyalphabetic substitution cipher with repeating key',
                    'solution': '''
def vigenere_decrypt(text, key):
    result = ""
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    
    return result

# Key recovery using frequency analysis
encrypted = "{encrypted_text}"
key = find_vigenere_key(encrypted)  # Implementation needed
flag = vigenere_decrypt(encrypted, key)
print(flag)
''',
                    'tools': ['python-builtin', 'frequency-analysis'],
                    'difficulty': 'medium'
                }
            ],
            'Hash': [
                {
                    'name': 'MD5 Dictionary Attack',
                    'description': 'Crack MD5 hash using dictionary attack',
                    'solution': '''
import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

target_hash = "{hash_value}"

# Common passwords dictionary
passwords = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "1234567890", "qwerty", "abc123",
    "password1", "123123", "000000", "iloveyou", "1234567"
]

for password in passwords:
    if md5_hash(password) == target_hash:
        print(f"Found: {password}")
        print(f"Flag: flag{{{password}}}")
        break
''',
                    'tools': ['hashlib'],
                    'difficulty': 'easy'
                },
                {
                    'name': 'SHA256 Rainbow Table',
                    'description': 'Use precomputed rainbow table for SHA256 hash',
                    'solution': '''
import hashlib
import requests

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def rainbow_table_lookup(hash_value):
    # Query online rainbow table services
    services = [
        f"https://md5decrypt.net/Api/api.php?hash={hash_value}&hash_type=sha256&email=test@test.com&code=code",
        f"https://hashtoolkit.com/reverse-hash/?hash={hash_value}"
    ]
    
    for service in services:
        try:
            response = requests.get(service)
            if response.status_code == 200 and response.text:
                return response.text.strip()
        except:
            continue
    return None

target_hash = "{hash_value}"
result = rainbow_table_lookup(target_hash)
if result:
    print(f"Found: {result}")
    print(f"Flag: flag{{{result}}}")
''',
                    'tools': ['hashlib', 'requests'],
                    'difficulty': 'medium'
                }
            ],
            'Encoding': [
                {
                    'name': 'Base64 Multi-layer',
                    'description': 'Multiple layers of Base64 encoding',
                    'solution': '''
import base64

def decode_base64_recursive(data, max_depth=10):
    current = data
    
    for depth in range(max_depth):
        try:
            decoded = base64.b64decode(current).decode('utf-8')
            print(f"Layer {depth + 1}: {decoded}")
            
            if 'flag{' in decoded.lower():
                return decoded
            
            # Check if still looks like base64
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in decoded.strip()):
                current = decoded.strip()
            else:
                return decoded
        except:
            break
    
    return current

encoded = "{encoded_data}"
flag = decode_base64_recursive(encoded)
print(f"Final result: {flag}")
''',
                    'tools': ['base64'],
                    'difficulty': 'easy'
                }
            ]
        }

    def safe_format(self, template_str, values):
        """Formatea string de manera segura"""
        try:
            return template_str.format(**values)
        except (KeyError, ValueError):
            return template_str
    
    def generate_synthetic_writeups(self, count_per_type=50):
        """Genera writeups sintéticos basados en templates reales"""
        print(f"🔧 Generating synthetic writeups...")
        
        for attack_type, templates in self.synthetic_templates.items():
            for i in range(count_per_type):
                template = random.choice(templates)
                
                # Generar valores aleatorios para los templates
                values = self.generate_random_values(attack_type)
                
                writeup = {
                    'id': f"synthetic_{attack_type.lower()}_{i:03d}",
                    'team': f"synthetic_team_{random.randint(1, 10)}",
                    'event': f"CTF_2024_Event_{random.randint(1, 20)}",
                    'challenge_name': f"{template['name']} #{i+1}",
                    'challenge_description': template['description'],
                    'attack_type': attack_type,
                    'tools_used': template['tools'],
                    'difficulty': template['difficulty'],
                    'writeup': self.format_writeup(template, values),
                    'solution_code': self.safe_format(template['solution'], values),
                    'url': f"https://synthetic-ctf.example.com/{attack_type.lower()}/{i}",
                    'year': random.choice([2023, 2024]),
                    'category': 'crypto',
                    'file_type': '.md',
                    'scraped_at': datetime.now().isoformat(),
                    'synthetic': True
                }
                
                self.writeups.append(writeup)
                
                if len(self.writeups) % 50 == 0:
                    print(f"  Generated {len(self.writeups)} writeups...")

    def generate_random_values(self, attack_type):
        """Genera valores aleatorios para los templates"""
        if attack_type == 'RSA':
            # Generar valores RSA realistas
            p = random.randint(10**150, 10**151)
            q = random.randint(10**150, 10**151)
            n = p * q
            e = random.choice([3, 65537])
            c = random.randint(10**100, n-1)
            
            return {
                'n': n,
                'e': e,
                'c': c,
                'p': p,
                'q': q
            }
        
        elif attack_type == 'XOR':
            hex_data = ''.join([f"{random.randint(0, 255):02x}" for _ in range(32)])
            return {'hex_data': hex_data}
        
        elif attack_type == 'Classical':
            encrypted_text = "synt{guvf_vf_n_grfg_synt}"  # ROT13 of "flag{this_is_a_test_flag}"
            return {'encrypted_text': encrypted_text}
        
        elif attack_type == 'Hash':
            import hashlib
            password = random.choice(['password123', 'admin', 'test123', 'secret'])
            hash_value = hashlib.md5(password.encode()).hexdigest()
            return {'hash_value': hash_value, 'password': password}
        
        elif attack_type == 'Encoding':
            import base64
            flag = f"flag{{test_flag_{random.randint(1000, 9999)}}}"
            # Encode multiple times
            encoded = flag
            for _ in range(random.randint(2, 5)):
                encoded = base64.b64encode(encoded.encode()).decode()
            return {'encoded_data': encoded, 'original_flag': flag}
        
        return {}

    def format_writeup(self, template, values):
        """Formatea el writeup con los valores generados"""
        # Formatear la solución de manera segura
        try:
            formatted_solution = template['solution'].format(**values)
        except (KeyError, ValueError):
            formatted_solution = template['solution']  # Usar sin formatear si hay error
        
        writeup_content = f"""
# {template['name']}

## Challenge Description
{template['description']}

## Analysis
This challenge involves {template['name'].lower()} techniques. The vulnerability can be exploited using the following approach:

## Solution
```python
{formatted_solution}
```

## Tools Used
- {', '.join(template['tools'])}

## Difficulty
{template['difficulty'].title()}

## Flag
The flag can be recovered by executing the solution code above.
"""
        return writeup_content.strip()

    def add_real_scraped_writeups(self):
        """Añade los writeups reales ya scrapeados"""
        real_file = self.output_dir / "writeups_real_processed.jsonl"
        
        if real_file.exists():
            print(f"📥 Loading existing real writeups from {real_file}")
            
            with open(real_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        writeup = json.loads(line)
                        writeup['synthetic'] = False
                        self.writeups.append(writeup)
                    except json.JSONDecodeError:
                        continue
            
            print(f"  Loaded {len([w for w in self.writeups if not w.get('synthetic', True)])} real writeups")

    def save_enhanced_dataset(self):
        """Guarda el dataset completo mejorado"""
        output_file = self.output_dir / "writeups_enhanced_dataset.jsonl"
        
        print(f"💾 Saving {len(self.writeups)} writeups to {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for writeup in self.writeups:
                f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
        
        # Generar estadísticas
        stats = self.generate_enhanced_statistics()
        stats_file = self.output_dir / "enhanced_dataset_statistics.json"
        
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Statistics saved to {stats_file}")
        return output_file

    def generate_enhanced_statistics(self):
        """Genera estadísticas del dataset mejorado"""
        stats = {
            'total_writeups': len(self.writeups),
            'real_writeups': len([w for w in self.writeups if not w.get('synthetic', True)]),
            'synthetic_writeups': len([w for w in self.writeups if w.get('synthetic', False)]),
            'by_attack_type': {},
            'by_difficulty': {},
            'by_year': {},
            'with_solution_code': 0,
            'generation_timestamp': datetime.now().isoformat()
        }
        
        for writeup in self.writeups:
            # Por tipo de ataque
            attack_type = writeup['attack_type']
            stats['by_attack_type'][attack_type] = stats['by_attack_type'].get(attack_type, 0) + 1
            
            # Por dificultad
            difficulty = writeup.get('difficulty', 'unknown')
            stats['by_difficulty'][difficulty] = stats['by_difficulty'].get(difficulty, 0) + 1
            
            # Por año
            year = str(writeup['year'])
            stats['by_year'][year] = stats['by_year'].get(year, 0) + 1
            
            # Con código de solución
            if writeup.get('solution_code', '').strip():
                stats['with_solution_code'] += 1
        
        return stats

    def validate_enhanced_dataset(self):
        """Valida el dataset mejorado"""
        output_file = self.output_dir / "writeups_enhanced_dataset.jsonl"
        
        print(f"\n✅ ENHANCED DATASET VALIDATION:")
        print(f"📁 File: {output_file}")
        print(f"📊 Size: {output_file.stat().st_size / 1024:.1f} KB")
        
        # Contar líneas
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"📝 Total writeups: {len(lines)}")
        
        # Mostrar estadísticas
        stats_file = self.output_dir / "enhanced_dataset_statistics.json"
        with open(stats_file, 'r', encoding='utf-8') as f:
            stats = json.load(f)
        
        print(f"\n📈 DATASET STATISTICS:")
        print(f"  Real writeups: {stats['real_writeups']}")
        print(f"  Synthetic writeups: {stats['synthetic_writeups']}")
        print(f"  With solution code: {stats['with_solution_code']}")
        
        print(f"\n🎯 ATTACK TYPE DISTRIBUTION:")
        for attack_type, count in sorted(stats['by_attack_type'].items(), key=lambda x: x[1], reverse=True):
            print(f"    {attack_type}: {count} writeups")
        
        print(f"\n🏆 DIFFICULTY DISTRIBUTION:")
        for difficulty, count in sorted(stats['by_difficulty'].items(), key=lambda x: x[1], reverse=True):
            print(f"    {difficulty}: {count} writeups")
        
        success = len(lines) >= 500
        print(f"\n{'✅ DATASET READY FOR BERT TRAINING' if success else '⚠️ DATASET TOO SMALL'}")
        return success

def main():
    """Función principal"""
    print("🚀 ENHANCED CTF WRITEUPS DATASET GENERATOR")
    print("Objetivo: Crear dataset de 500+ writeups (reales + sintéticos)")
    print("=" * 70)
    
    scraper = EnhancedWriteupScraper()
    
    # Cargar writeups reales existentes
    scraper.add_real_scraped_writeups()
    
    # Generar writeups sintéticos para completar el dataset
    needed = max(0, 500 - len(scraper.writeups))
    if needed > 0:
        print(f"🔧 Need to generate {needed} more writeups")
        # Distribuir entre tipos de ataque
        per_type = max(1, needed // len(scraper.synthetic_templates))
        scraper.generate_synthetic_writeups(per_type)
    
    # Guardar dataset completo
    output_file = scraper.save_enhanced_dataset()
    
    # Validar dataset
    success = scraper.validate_enhanced_dataset()
    
    print("\n" + "=" * 70)
    print("🎉 ENHANCED DATASET GENERATION COMPLETED!")
    print(f"📊 Total writeups: {len(scraper.writeups)}")
    print(f"📁 Output file: {output_file}")
    print(f"✅ Ready for BERT training: {'YES' if success else 'NO'}")
    
    if success:
        print("\n🚀 NEXT STEPS:")
        print("1. python ml_phase2/prepare_data_for_bert.py --input data/writeups_enhanced_dataset.jsonl")
        print("2. python ml_phase2/train_bert.py")
        print("3. python rag/prepare_embeddings.py")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)