#!/usr/bin/env python3
"""
Dataset Expander para Fase 2.2 - ML Training
Genera dataset de 45-50 challenges para entrenar BERT
"""

import json
import os
import random
from pathlib import Path
from datetime import datetime

# Intentar importar Crypto, si no está disponible usar números aleatorios
try:
    from Crypto.Util.number import getPrime
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️  Warning: pycryptodome not available, using random primes")

class DatasetExpander:
    """Genera dataset de 50-100 challenges para entrenar BERT"""
    
    def __init__(self, output_dir="ml_dataset"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def _get_prime(self, bits):
        """Obtiene un primo, usando Crypto si está disponible"""
        if CRYPTO_AVAILABLE:
            return getPrime(bits)
        else:
            # Usar primos pequeños conocidos para testing
            small_primes = [
                61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
                137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
                199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
                277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
                359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
                439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
                521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
                607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
                683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
                773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
                863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
                967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033
            ]
            return random.choice(small_primes)
    
    def generate_rsa_challenges(self, count=20):
        """Genera RSA challenges variados"""
        challenges = []
        
        print(f"🔧 Generating {count} RSA challenges...")
        
        for i in range(count):
            # Parámetros variados
            if i < 5:
                # Primeros 5: números muy pequeños (fáciles de factorizar)
                p = self._get_prime(8)  # 8-bit primes
                q = self._get_prime(8)
            elif i < 10:
                # Siguientes 5: números pequeños
                p = self._get_prime(10)  # 10-bit primes
                q = self._get_prime(10)
            elif i < 15:
                # Siguientes 5: números medianos
                p = self._get_prime(12)  # 12-bit primes
                q = self._get_prime(12)
            else:
                # Últimos 5: números más grandes
                p = self._get_prime(16)  # 16-bit primes
                q = self._get_prime(16)
            
            n = p * q
            e = random.choice([3, 5, 17, 65537])
            
            # Asegurar que e y phi(n) sean coprimos
            phi = (p - 1) * (q - 1)
            while phi % e == 0:
                e = random.choice([3, 5, 17, 65537])
            
            # Mensaje random (más pequeño que n)
            m = random.randint(2, min(n-1, 999999))
            c = pow(m, e, n)
            
            challenge_type = self._classify_rsa(n, e, p, q)
            
            challenges.append({
                'id': f'rsa_{i+1}',
                'name': f'RSA Challenge {i+1} ({challenge_type})',
                'description': f'RSA challenge with {challenge_type}',
                'type': 'RSA',
                'challenge_type_detail': challenge_type,
                'difficulty': self._get_rsa_difficulty(n, e, p, q),
                'parameters': {
                    'n': n, 
                    'e': e, 
                    'c': c,
                    'p': p,  # Para verificación
                    'q': q,  # Para verificación
                    'm': m   # Para verificación
                },
                'expected_flag': f'flag{{m={m}}}',
                'source': 'generated',
                'content': self._generate_rsa_code(n, e, c, p, q, m)
            })
        
        return challenges
    
    def _classify_rsa(self, n, e, p, q):
        """Clasifica el tipo de RSA challenge"""
        p_q_ratio = abs(p - q) / max(p, q)
        
        if e in [3, 5, 17]:
            return 'Small Exponent'
        elif p_q_ratio < 0.1:
            return 'Fermat Factorization'
        elif n.bit_length() < 32:
            return 'Small Factors'
        else:
            return 'Standard RSA'
    
    def _get_rsa_difficulty(self, n, e, p, q):
        """Determina dificultad del RSA"""
        if n.bit_length() < 20:
            return 'Easy'
        elif n.bit_length() < 30:
            return 'Medium'
        else:
            return 'Hard'
    
    def _generate_rsa_code(self, n, e, c, p, q, m):
        """Genera código Python para el challenge RSA"""
        return f'''# RSA Challenge - Generated
# n = {n} (p = {p}, q = {q})
# e = {e}
# Encrypted message: {m}

n = {n}
e = {e}
c = {c}

print(f"n = {{n}}")
print(f"e = {{e}}")
print(f"c = {{c}}")
print("Factor n to decrypt the message!")
'''
    
    def generate_classical_challenges(self, count=15):
        """Genera cifrados clásicos"""
        challenges = []
        
        print(f"🔧 Generating {count} Classical challenges...")
        
        for i in range(count):
            rot = random.choice([1, 3, 5, 7, 11, 13, 17, 19, 23, 25])
            plaintext = f"flag{{caesar_challenge_{i+1}}}"
            
            ciphertext = ''.join(
                chr((ord(ch) - ord('a') + rot) % 26 + ord('a'))
                if ch.isalpha() and ch.islower() else
                chr((ord(ch) - ord('A') + rot) % 26 + ord('A'))
                if ch.isalpha() and ch.isupper() else ch
                for ch in plaintext
            )
            
            challenges.append({
                'id': f'caesar_{i+1}',
                'name': f'Caesar ROT{rot} Challenge {i+1}',
                'description': f'Caesar cipher with rotation {rot}',
                'type': 'Classical',
                'challenge_type_detail': f'Caesar ROT{rot}',
                'difficulty': 'Easy' if rot in [13, 25] else 'Medium',
                'parameters': {
                    'ciphertext': ciphertext, 
                    'rotation': rot,
                    'plaintext': plaintext
                },
                'expected_flag': plaintext,
                'source': 'generated',
                'content': self._generate_caesar_code(ciphertext, rot)
            })
        
        return challenges
    
    def _generate_caesar_code(self, ciphertext, rot):
        """Genera código Python para Caesar cipher"""
        return f'''# Caesar Cipher Challenge - ROT{rot}
# Encrypted with rotation {rot}

encrypted = "{ciphertext}"

print("Encrypted message:", encrypted)
print("Hint: This is a Caesar cipher")
print("Try different rotations to decrypt!")
'''
    
    def generate_xor_challenges(self, count=10):
        """Genera XOR challenges"""
        challenges = []
        
        print(f"🔧 Generating {count} XOR challenges...")
        
        for i in range(count):
            key = random.randint(1, 255)
            plaintext = f"flag{{xor_challenge_{i+1}}}".encode()
            ciphertext = bytes(p ^ key for p in plaintext)
            ciphertext_hex = ciphertext.hex().upper()
            
            challenges.append({
                'id': f'xor_{i+1}',
                'name': f'XOR Single-Byte Challenge {i+1}',
                'description': f'XOR with single byte key {hex(key)}',
                'type': 'XOR',
                'challenge_type_detail': 'XOR Single-Byte',
                'difficulty': 'Easy',
                'parameters': {
                    'ciphertext_hex': ciphertext_hex, 
                    'key': key,
                    'plaintext': plaintext.decode()
                },
                'expected_flag': plaintext.decode(),
                'source': 'generated',
                'content': self._generate_xor_code(ciphertext_hex, key)
            })
        
        return challenges
    
    def _generate_xor_code(self, ciphertext_hex, key):
        """Genera código Python para XOR challenge"""
        return f'''# XOR Single Byte Challenge
# Encrypted with key {hex(key)} ({key} decimal)

encrypted_hex = "{ciphertext_hex}"

print("Encrypted flag (hex):", encrypted_hex)
print("Hint: Single byte XOR key was used")
print("Try all 256 possible keys!")
'''
    
    def generate_encoding_challenges(self, count=5):
        """Genera challenges de encoding (Base64, Hex, etc.)"""
        challenges = []
        
        print(f"🔧 Generating {count} Encoding challenges...")
        
        encodings = ['base64', 'hex', 'url', 'rot13', 'base32']
        
        for i in range(count):
            encoding_type = encodings[i % len(encodings)]
            plaintext = f"flag{{encoding_challenge_{i+1}}}"
            
            if encoding_type == 'base64':
                import base64
                encoded = base64.b64encode(plaintext.encode()).decode()
            elif encoding_type == 'hex':
                encoded = plaintext.encode().hex()
            elif encoding_type == 'url':
                import urllib.parse
                encoded = urllib.parse.quote(plaintext)
            elif encoding_type == 'rot13':
                import codecs
                encoded = codecs.encode(plaintext, 'rot13')
            elif encoding_type == 'base32':
                import base64
                encoded = base64.b32encode(plaintext.encode()).decode()
            
            challenges.append({
                'id': f'encoding_{i+1}',
                'name': f'{encoding_type.upper()} Encoding Challenge {i+1}',
                'description': f'{encoding_type.upper()} encoded message',
                'type': 'Encoding',
                'challenge_type_detail': f'{encoding_type.upper()} Encoding',
                'difficulty': 'Easy',
                'parameters': {
                    'encoded': encoded,
                    'encoding_type': encoding_type,
                    'plaintext': plaintext
                },
                'expected_flag': plaintext,
                'source': 'generated',
                'content': self._generate_encoding_code(encoded, encoding_type)
            })
        
        return challenges
    
    def _generate_encoding_code(self, encoded, encoding_type):
        """Genera código Python para encoding challenge"""
        return f'''# {encoding_type.upper()} Encoding Challenge

encoded_message = "{encoded}"

print("Encoded message:", encoded_message)
print("Hint: This is {encoding_type.upper()} encoded")
print("Decode it to get the flag!")
'''
    
    def compile_full_dataset(self):
        """Compila dataset completo"""
        
        print("🚀 GENERATING FULL ML TRAINING DATASET")
        print("=" * 60)
        
        dataset = []
        
        # Generar challenges
        dataset.extend(self.generate_rsa_challenges(20))
        dataset.extend(self.generate_classical_challenges(15))
        dataset.extend(self.generate_xor_challenges(10))
        dataset.extend(self.generate_encoding_challenges(5))
        
        # Agregar timestamp y metadata
        metadata = {
            'generated_at': datetime.now().isoformat(),
            'total_challenges': len(dataset),
            'generator_version': '1.0',
            'purpose': 'ML training for CTF Crypto Agent Phase 2.2'
        }
        
        # Guardar dataset completo
        output_file = self.output_dir / "full_dataset.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': metadata,
                'challenges': dataset
            }, f, indent=2, ensure_ascii=False)
        
        # Guardar solo los challenges (sin metadata) para ML
        ml_output_file = self.output_dir / "challenges_only.json"
        with open(ml_output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)
        
        # Crear archivo JSONL para ML frameworks
        jsonl_output_file = self.output_dir / "challenges.jsonl"
        with open(jsonl_output_file, 'w', encoding='utf-8') as f:
            for challenge in dataset:
                json.dump(challenge, f, ensure_ascii=False)
                f.write('\n')
        
        print(f"\n✅ Generated {len(dataset)} challenges")
        print(f"   📁 Full dataset: {output_file}")
        print(f"   📁 ML dataset: {ml_output_file}")
        print(f"   📁 JSONL format: {jsonl_output_file}")
        
        # Estadísticas
        types = {}
        difficulties = {}
        for c in dataset:
            t = c['type']
            d = c['difficulty']
            types[t] = types.get(t, 0) + 1
            difficulties[d] = difficulties.get(d, 0) + 1
        
        print(f"\n📊 Dataset Composition:")
        print("   By Type:")
        for t, count in sorted(types.items()):
            percentage = (count / len(dataset)) * 100
            print(f"     {t}: {count} ({percentage:.1f}%)")
        
        print("   By Difficulty:")
        for d, count in sorted(difficulties.items()):
            percentage = (count / len(dataset)) * 100
            print(f"     {d}: {count} ({percentage:.1f}%)")
        
        return dataset
    
    def create_train_test_split(self, test_ratio=0.2):
        """Crea split de train/test para ML"""
        
        # Cargar dataset
        dataset_file = self.output_dir / "challenges_only.json"
        if not dataset_file.exists():
            print("❌ Dataset not found. Run compile_full_dataset() first.")
            return
        
        with open(dataset_file, 'r', encoding='utf-8') as f:
            dataset = json.load(f)
        
        # Shuffle dataset
        random.shuffle(dataset)
        
        # Split
        split_idx = int(len(dataset) * (1 - test_ratio))
        train_data = dataset[:split_idx]
        test_data = dataset[split_idx:]
        
        # Guardar splits
        train_file = self.output_dir / "train_dataset.json"
        test_file = self.output_dir / "test_dataset.json"
        
        with open(train_file, 'w', encoding='utf-8') as f:
            json.dump(train_data, f, indent=2, ensure_ascii=False)
        
        with open(test_file, 'w', encoding='utf-8') as f:
            json.dump(test_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 Train/Test Split Created:")
        print(f"   🏋️  Training: {len(train_data)} challenges ({train_file})")
        print(f"   🧪 Testing: {len(test_data)} challenges ({test_file})")
        
        return train_data, test_data

def main():
    """Función principal"""
    
    print("🚀 CTF CRYPTO DATASET EXPANDER")
    print("=" * 60)
    print("Generating ML training dataset for Phase 2.2")
    print()
    
    # Crear expander
    expander = DatasetExpander()
    
    # Generar dataset completo
    dataset = expander.compile_full_dataset()
    
    # Crear train/test split
    expander.create_train_test_split(test_ratio=0.2)
    
    print("\n" + "=" * 60)
    print("🎉 DATASET GENERATION COMPLETE!")
    print("=" * 60)
    print(f"📁 Output directory: {expander.output_dir}")
    print(f"📊 Total challenges: {len(dataset)}")
    print("\n🚀 Ready for Phase 2.2 - BERT Training!")
    
    return len(dataset)

if __name__ == "__main__":
    total_challenges = main()
    print(f"\n✅ Success! Generated {total_challenges} challenges for ML training.")
    exit(0)