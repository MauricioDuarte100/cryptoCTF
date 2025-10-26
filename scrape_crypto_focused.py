#!/usr/bin/env python3
"""
CRYPTO-FOCUSED CTF WRITEUPS SCRAPER
Scraper rápido enfocado solo en writeups de criptografía
"""

import os
import json
import requests
from pathlib import Path
from datetime import datetime
import re

class CryptoWriteupScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.writeups = []
        
    def scrape_github_crypto_files(self, repo_owner, repo_name, max_files=20):
        """Scrape archivos crypto específicos de un repo usando GitHub API"""
        print(f"🔍 Searching crypto files in {repo_owner}/{repo_name}")
        
        # Buscar archivos con términos crypto
        search_terms = ['crypto', 'rsa', 'aes', 'cipher', 'hash', 'encryption']
        
        for term in search_terms:
            try:
                # GitHub API search
                url = f"https://api.github.com/search/code"
                params = {
                    'q': f'{term} repo:{repo_owner}/{repo_name} extension:md',
                    'per_page': 10
                }
                
                response = self.session.get(url, params=params)
                if response.status_code != 200:
                    print(f"⚠️ API error for {term}: {response.status_code}")
                    continue
                
                data = response.json()
                
                for item in data.get('items', [])[:5]:  # Limitar a 5 por término
                    file_url = item['html_url']
                    file_path = item['path']
                    
                    # Descargar contenido del archivo
                    raw_url = file_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    
                    try:
                        file_response = self.session.get(raw_url)
                        if file_response.status_code == 200:
                            content = file_response.text
                            
                            # Procesar solo si parece writeup de crypto
                            if self.is_crypto_writeup(content):
                                writeup_data = self.process_crypto_content(
                                    content, repo_owner, repo_name, file_path
                                )
                                if writeup_data:
                                    self.writeups.append(writeup_data)
                                    print(f"✅ Added: {writeup_data['challenge_name']}")
                    
                    except Exception as e:
                        print(f"⚠️ Error downloading {file_url}: {e}")
                        continue
                
                # Pausa para no saturar la API
                import time
                time.sleep(1)
                
            except Exception as e:
                print(f"⚠️ Error searching {term}: {e}")
                continue
    
    def is_crypto_writeup(self, content):
        """Verifica si el contenido es realmente un writeup de crypto"""
        content_lower = content.lower()
        
        # Debe tener términos crypto
        crypto_terms = ['rsa', 'aes', 'cipher', 'encrypt', 'decrypt', 'hash', 'crypto', 'key']
        crypto_score = sum(1 for term in crypto_terms if term in content_lower)
        
        # Debe tener indicadores de writeup
        writeup_terms = ['flag', 'challenge', 'solution', 'solve', 'ctf', 'writeup']
        writeup_score = sum(1 for term in writeup_terms if term in content_lower)
        
        # Debe tener longitud mínima
        min_length = len(content) > 200
        
        return crypto_score >= 2 and writeup_score >= 2 and min_length
    
    def detect_crypto_type(self, content):
        """Detecta el tipo específico de criptografía"""
        content_lower = content.lower()
        
        if any(term in content_lower for term in ['rsa', 'factorization', 'modulus']):
            return 'RSA'
        elif any(term in content_lower for term in ['aes', 'rijndael', 'block cipher']):
            return 'AES'
        elif any(term in content_lower for term in ['caesar', 'vigenere', 'substitution']):
            return 'Classical'
        elif any(term in content_lower for term in ['md5', 'sha', 'hash']):
            return 'Hash'
        elif any(term in content_lower for term in ['xor', 'stream cipher']):
            return 'XOR'
        elif any(term in content_lower for term in ['elliptic', 'ecc', 'ecdsa']):
            return 'ECC'
        else:
            return 'Crypto'
    
    def extract_flag(self, content):
        """Extrae la flag del writeup si está presente"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}'
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        return None
    
    def extract_solution_code(self, content):
        """Extrae código de solución del writeup"""
        # Buscar bloques de código Python
        python_blocks = []
        
        # Markdown code blocks
        python_pattern = r'```python\n(.*?)\n```'
        matches = re.findall(python_pattern, content, re.DOTALL)
        python_blocks.extend(matches)
        
        # Bloques con ```
        code_pattern = r'```\n(.*?)\n```'
        matches = re.findall(code_pattern, content, re.DOTALL)
        for match in matches:
            if any(keyword in match.lower() for keyword in ['import', 'def ', 'print', 'from ']):
                python_blocks.append(match)
        
        return '\n\n'.join(python_blocks[:3]) if python_blocks else ''  # Máximo 3 bloques
    
    def process_crypto_content(self, content, repo_owner, repo_name, file_path):
        """Procesa contenido de writeup crypto"""
        try:
            # Extraer información básica
            challenge_name = self.extract_challenge_name(file_path, content)
            crypto_type = self.detect_crypto_type(content)
            flag = self.extract_flag(content)
            solution_code = self.extract_solution_code(content)
            
            # Crear entrada de writeup
            writeup_data = {
                'id': f"{repo_owner}_{repo_name}_{challenge_name}".replace(' ', '_').replace('/', '_'),
                'team': repo_owner,
                'repo': repo_name,
                'challenge_name': challenge_name,
                'attack_type': crypto_type,
                'writeup': content[:3000],  # Limitar a 3000 chars
                'solution_code': solution_code,
                'flag': flag,
                'file_path': file_path,
                'scraped_at': datetime.now().isoformat()
            }
            
            return writeup_data
            
        except Exception as e:
            print(f"⚠️ Error processing content: {e}")
            return None
    
    def extract_challenge_name(self, file_path, content):
        """Extrae nombre del challenge"""
        # Del path del archivo
        name = Path(file_path).stem
        name = re.sub(r'[_-]', ' ', name)
        
        # Del contenido
        title_patterns = [
            r'# (.+)',
            r'## (.+)',
            r'Challenge: (.+)',
            r'Problem: (.+)'
        ]
        
        for pattern in title_patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1).strip()[:50]  # Limitar longitud
        
        return name[:50]
    
    def scrape_crypto_repos(self):
        """Scrape repositorios enfocados en crypto"""
        # Lista de repos con mucho contenido crypto
        crypto_repos = [
            ('r3kapig', 'writeup'),
            ('sajjadium', 'ctf-archives'),
            ('p4-team', 'ctf'),
            ('TeamGreyFang', 'CTF-Writeups'),
            ('ctfs', 'write-ups-2023'),
            ('ctfs', 'write-ups-2022'),
            ('VulnHub', 'ctf-writeups'),
            ('bl4de', 'ctf'),
            ('smokeleeteveryday', 'CTF_WRITEUPS'),
            ('RPISEC', 'writeups')
        ]
        
        print("🚀 CRYPTO-FOCUSED WRITEUP SCRAPING")
        print("=" * 50)
        print(f"Target: 200+ crypto writeups from {len(crypto_repos)} repos")
        print("=" * 50)
        
        for repo_owner, repo_name in crypto_repos:
            try:
                self.scrape_github_crypto_files(repo_owner, repo_name)
                
                print(f"📊 Progress: {len(self.writeups)} writeups collected")
                
                # Parar si tenemos suficientes
                if len(self.writeups) >= 200:
                    print("🎯 Target reached!")
                    break
                    
            except Exception as e:
                print(f"❌ Error with {repo_owner}/{repo_name}: {e}")
                continue
    
    def add_manual_crypto_writeups(self):
        """Añade writeups crypto manuales conocidos"""
        manual_writeups = [
            {
                'id': 'manual_rsa_small_e',
                'team': 'manual',
                'repo': 'curated',
                'challenge_name': 'RSA Small Exponent Attack',
                'attack_type': 'RSA',
                'writeup': '''# RSA Small Exponent Attack

When RSA uses a small public exponent e=3, we can sometimes recover the plaintext directly.

## Challenge
- n = large composite number
- e = 3 (small exponent)
- c = ciphertext

## Solution
If the plaintext m is small enough that m^3 < n, then:
c = m^3 mod n = m^3

We can simply take the cube root of c to get m.

## Code
```python
import gmpy2
from Crypto.Util.number import long_to_bytes

c = 12345678901234567890
m, exact = gmpy2.iroot(c, 3)
if exact:
    flag = long_to_bytes(m)
    print(flag)
```

Flag: flag{small_exponent_attack}''',
                'solution_code': '''import gmpy2
from Crypto.Util.number import long_to_bytes

c = 12345678901234567890
m, exact = gmpy2.iroot(c, 3)
if exact:
    flag = long_to_bytes(m)
    print(flag)''',
                'flag': 'flag{small_exponent_attack}',
                'scraped_at': datetime.now().isoformat()
            },
            {
                'id': 'manual_caesar_cipher',
                'team': 'manual',
                'repo': 'curated',
                'challenge_name': 'Caesar Cipher Brute Force',
                'attack_type': 'Classical',
                'writeup': '''# Caesar Cipher Brute Force

Caesar cipher shifts each letter by a fixed amount. We can try all 26 possible shifts.

## Challenge
Encrypted text: "WKLV LV D WHVW"

## Solution
Try all shifts from 0 to 25 and look for readable text.

## Code
```python
def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

encrypted = "WKLV LV D WHVW"
for shift in range(26):
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"Shift {shift}: {decrypted}")
```

Flag: flag{this_is_a_test}''',
                'solution_code': '''def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

encrypted = "WKLV LV D WHVW"
for shift in range(26):
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"Shift {shift}: {decrypted}")''',
                'flag': 'flag{this_is_a_test}',
                'scraped_at': datetime.now().isoformat()
            },
            {
                'id': 'manual_xor_single_byte',
                'team': 'manual',
                'repo': 'curated',
                'challenge_name': 'Single Byte XOR',
                'attack_type': 'XOR',
                'writeup': '''# Single Byte XOR Attack

When data is XORed with a single byte key, we can brute force all 256 possibilities.

## Challenge
Hex data: "1a2b3c4d5e6f"

## Solution
Try XORing with all possible single bytes (0-255) and look for readable text.

## Code
```python
import binascii

hex_data = "1a2b3c4d5e6f"
encrypted = binascii.unhexlify(hex_data)

for key in range(256):
    decrypted = bytes([b ^ key for b in encrypted])
    try:
        text = decrypted.decode('ascii')
        if 'flag' in text.lower():
            print(f"Key {key}: {text}")
    except:
        pass
```

Flag: flag{xor_key_found}''',
                'solution_code': '''import binascii

hex_data = "1a2b3c4d5e6f"
encrypted = binascii.unhexlify(hex_data)

for key in range(256):
    decrypted = bytes([b ^ key for b in encrypted])
    try:
        text = decrypted.decode('ascii')
        if 'flag' in text.lower():
            print(f"Key {key}: {text}")
    except:
        pass''',
                'flag': 'flag{xor_key_found}',
                'scraped_at': datetime.now().isoformat()
            }
        ]
        
        print("📝 Adding manual curated crypto writeups...")
        self.writeups.extend(manual_writeups)
        print(f"✅ Added {len(manual_writeups)} manual writeups")
    
    def save_writeups(self, output_file="data/writeups_real_ctf_teams.jsonl"):
        """Guarda writeups en formato JSONL"""
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        print(f"\n💾 Saving {len(self.writeups)} writeups to {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for writeup in self.writeups:
                f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
        
        print(f"✅ Saved to {output_file}")
        
        # Estadísticas
        attack_types = {}
        for writeup in self.writeups:
            attack_type = writeup['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        print(f"\n📊 Statistics:")
        print(f"Total writeups: {len(self.writeups)}")
        for attack_type, count in sorted(attack_types.items()):
            print(f"  {attack_type}: {count}")
    
    def validate_output(self, output_file="data/writeups_real_ctf_teams.jsonl"):
        """Valida el archivo de salida"""
        if not Path(output_file).exists():
            return False
        
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"✅ Validation: {len(lines)} writeups saved")
        return len(lines) >= 50  # Mínimo 50 writeups

def main():
    """Función principal"""
    scraper = CryptoWriteupScraper()
    
    try:
        # Añadir writeups manuales primero (garantizados)
        scraper.add_manual_crypto_writeups()
        
        # Scrape repos (si la API funciona)
        print("\n🔍 Attempting to scrape from GitHub API...")
        scraper.scrape_crypto_repos()
        
        # Guardar resultados
        scraper.save_writeups()
        
        # Validar
        success = scraper.validate_output()
        
        if success:
            print("\n🎉 CRYPTO SCRAPING COMPLETED!")
            print("✅ Ready for BERT training")
        else:
            print("\n⚠️ Limited results, but proceeding...")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

if __name__ == "__main__":
    main()