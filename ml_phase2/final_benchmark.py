"""
Final Benchmark - Phase 2.2
Re-ejecuta el benchmark completo del proyecto con el nuevo agente (ML + tools + prompts).
Compara resultados con Fase 2.1 (baseline).
"""

import time
import json
from pathlib import Path
import sys

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tools.tools import analyze_files, classify_crypto

# Challenges de prueba más realistas
BENCHMARK_CHALLENGES = [
    {
        "name": "RSA e=3",
        "description": "RSA challenge with small exponent",
        "files": [{
            "name": "chall.py",
            "content": """
# RSA Challenge - Small Exponent Attack
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Public key parameters
n = 12345678901234567890123456789012345678901234567890123456789012345678901234567890
e = 3
c = 9876543210987654321098765432109876543210987654321098765432109876543210987654321

print(f"n = {n}")
print(f"e = {e}")  
print(f"c = {c}")
print("Hint: Small exponent vulnerability!")

# The flag is encrypted with RSA
# Try cube root attack since e=3
"""
        }],
        "type": "RSA",
        "expected_flag": "flag{small_exponent_attack}"
    },
    {
        "name": "Caesar ROT13",
        "description": "Caesar cipher with ROT13",
        "files": [{
            "name": "chall.py", 
            "content": """
# Caesar Cipher Challenge - ROT13
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Encrypted flag
ciphertext = "synt{pnrfne_pvcure_vf_abg_frpher}"
print(f"Encrypted flag: {ciphertext}")
print("Hint: This is a Caesar cipher with shift 13")
print("Try different rotations to decrypt!")

# Classical cryptography challenge
"""
        }],
        "type": "Classical",
        "expected_flag": "flag{caesar_cipher_is_not_secure}"
    },
    {
        "name": "XOR Single-Byte",
        "description": "XOR with single byte key",
        "files": [{
            "name": "chall.py",
            "content": """
# XOR Single Byte Challenge
def xor_encrypt(plaintext, key):
    return bytes([p ^ key for p in plaintext])

def xor_decrypt(ciphertext, key):
    return bytes([c ^ key for c in ciphertext])

# The flag was encrypted with a single byte XOR key
encrypted_flag = bytes.fromhex("1a0e1b1c5b7e0e1f5b1a0e1b1c5b0e1f5b7e0e1f5b1a0e1b1c")
print(f"Encrypted flag (hex): {encrypted_flag.hex()}")
print("Hint: Single byte XOR key was used")
print("Try all 256 possible keys!")

# XOR cryptography challenge
for key in range(256):
    try:
        decrypted = xor_decrypt(encrypted_flag, key)
        if b'flag{' in decrypted:
            print(f"Key found: {key}")
            print(f"Flag: {decrypted.decode()}")
            break
    except:
        continue
"""
        }],
        "type": "XOR", 
        "expected_flag": "flag{xor_is_not_secure}"
    },
    {
        "name": "Base64 Encoding",
        "description": "Base64 encoded flag",
        "files": [{
            "name": "chall.py",
            "content": """
# Base64 Encoding Challenge
import base64

def encode_flag(flag):
    return base64.b64encode(flag.encode()).decode()

def decode_flag(encoded):
    return base64.b64decode(encoded).decode()

# The flag is encoded with Base64
encoded_flag = "ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"
print(f"Encoded flag: {encoded_flag}")
print("Hint: This is BASE64 encoded")
print("Decode it to get the flag!")

# Encoding challenge - not encryption!
decoded = decode_flag(encoded_flag)
print(f"Decoded: {decoded}")
"""
        }],
        "type": "Encoding",
        "expected_flag": "flag{base64_is_not_encryption}"
    },
    {
        "name": "Hash Challenge",
        "description": "Hash cracking challenge",
        "files": [{
            "name": "chall.py",
            "content": """
# Hash Challenge - MD5 Cracking
import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

# The flag is hashed with MD5
target_hash = "5d41402abc4b2a76b9719d911017c592"
print(f"Target hash: {target_hash}")
print("Hint: This is an MD5 hash of a simple word")
print("Try common words or use a dictionary attack!")

# Hash cryptography challenge
common_words = ["hello", "world", "password", "admin", "flag", "secret"]
for word in common_words:
    if md5_hash(word) == target_hash:
        print(f"Found: {word}")
        print(f"Flag: flag{{{word}_cracked}}")
        break
"""
        }],
        "type": "Hash",
        "expected_flag": "flag{hello_cracked}"
    }
]

def run_phase_2_2_benchmark():
    print("\n" + "="*70)
    print("🚀 PHASE 2.2 - FINAL BENCHMARK WITH ML-ENHANCED AGENT")
    print("="*70 + "\n")
    
    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "challenges": [],
        "summary": {}
    }
    
    by_type = {}
    total_time = 0
    successful = 0
    bert_used = 0
    heuristic_used = 0
    
    for i, challenge in enumerate(BENCHMARK_CHALLENGES, 1):
        print(f"[{i}/{len(BENCHMARK_CHALLENGES)}] Testing: {challenge['name']}")
        
        try:
            # Analizar archivos
            start = time.time()
            analysis = analyze_files.invoke({'files': challenge['files']})
            
            # Clasificar con ML + heurística
            classification = classify_crypto.invoke({'analysis': analysis, 'use_ml': True})
            elapsed = time.time() - start
            total_time += elapsed
            
            # Verificar resultado
            expected_type = challenge['type']
            actual_type = classification['type']
            match = expected_type == actual_type
            method = classification.get('method', 'unknown')
            confidence = classification.get('confidence', 0)
            
            if match:
                successful += 1
                status = "✅ SUCCESS"
            else:
                status = "❌ FAILED"
            
            # Contar métodos usados
            if method == 'BERT':
                bert_used += 1
            elif method == 'heuristic':
                heuristic_used += 1
            
            print(f"   {status} | Expected: {expected_type}, Got: {actual_type}")
            print(f"   Method: {method} | Confidence: {confidence:.2f} | Time: {elapsed:.2f}s")
            
            # Registrar por tipo
            if expected_type not in by_type:
                by_type[expected_type] = {'total': 0, 'success': 0}
            by_type[expected_type]['total'] += 1
            if match:
                by_type[expected_type]['success'] += 1
            
            results['challenges'].append({
                'name': challenge['name'],
                'type': expected_type,
                'success': match,
                'predicted_type': actual_type,
                'method': method,
                'confidence': confidence,
                'time': elapsed
            })
            
        except Exception as e:
            print(f"   💥 ERROR: {e}")
            results['challenges'].append({
                'name': challenge['name'],
                'type': challenge['type'],
                'success': False,
                'error': str(e)
            })
        
        print()
    
    # Compilar summary
    total_challenges = len(BENCHMARK_CHALLENGES)
    success_rate = successful / total_challenges * 100
    
    results['summary'] = {
        'total': total_challenges,
        'successful': successful,
        'failed': total_challenges - successful,
        'success_rate': success_rate,
        'avg_time': total_time / total_challenges,
        'bert_usage': bert_used / total_challenges,
        'heuristic_usage': heuristic_used / total_challenges,
        'by_type': {
            t: {
                'success_rate': (stats['success'] / stats['total'] * 100)
            }
            for t, stats in by_type.items()
        }
    }
    
    # Imprimir reporte
    print("=" * 70)
    print("📊 FINAL BENCHMARK REPORT - PHASE 2.2")
    print("=" * 70)
    print(f"\n🎯 OVERALL:")
    print(f"   Total Challenges: {total_challenges}")
    print(f"   Successful: {successful} ({success_rate:.1f}%)")
    print(f"   Failed: {total_challenges - successful}")
    print(f"   Average Time: {total_time/total_challenges:.2f}s")
    
    print(f"\n🧠 METHOD USAGE:")
    print(f"   BERT: {bert_used}/{total_challenges} ({bert_used/total_challenges*100:.1f}%)")
    print(f"   Heuristic: {heuristic_used}/{total_challenges} ({heuristic_used/total_challenges*100:.1f}%)")
    
    print(f"\n📈 BY TYPE:")
    for ctype, stats in by_type.items():
        rate = stats['success'] / stats['total'] * 100
        print(f"   {ctype}: {stats['success']}/{stats['total']} ({rate:.1f}%)")
    
    # Comparación con Fase 2.1
    print(f"\n📉 COMPARISON WITH PHASE 2.1:")
    print(f"   Phase 2.1 (Baseline): 83.3% success")
    improvement = success_rate - 83.3
    if improvement > 0:
        print(f"   Phase 2.2 (With ML): {success_rate:.1f}% success")
        print(f"   ✅ IMPROVEMENT: +{improvement:.1f} percentage points")
    elif improvement < 0:
        print(f"   Phase 2.2 (With ML): {success_rate:.1f}% success")
        print(f"   ⚠️  Regression: {improvement:.1f} percentage points (investigate)")
    else:
        print(f"   Phase 2.2 (With ML): {success_rate:.1f}% success")
        print(f"   = SAME (ML integration didn't break baseline)")
    
    # Guardar JSON
    Path("ml_phase2/evaluation").mkdir(parents=True, exist_ok=True)
    with open("ml_phase2/evaluation/phase_2_2_benchmark.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Report saved to: ml_phase2/evaluation/phase_2_2_benchmark.json")
    print("=" * 70)
    
    return results

if __name__ == "__main__":
    results = run_phase_2_2_benchmark()
    
    # Evaluación final
    success_rate = results['summary']['success_rate']
    bert_usage = results['summary']['bert_usage']
    
    print(f"\n🏁 PHASE 2.2 FINAL EVALUATION:")
    if success_rate >= 90:
        print(f"🎉 EXCELLENT! {success_rate:.1f}% success rate")
    elif success_rate >= 80:
        print(f"✅ GOOD! {success_rate:.1f}% success rate")
    else:
        print(f"⚠️  NEEDS IMPROVEMENT: {success_rate:.1f}% success rate")
    
    if bert_usage >= 0.5:
        print(f"🧠 BERT is being used effectively ({bert_usage:.1%} of cases)")
    else:
        print(f"⚠️  BERT usage is low ({bert_usage:.1%} of cases)")
    
    print(f"\n📋 PHASE 2.2 STATUS: {'✅ COMPLETE' if success_rate >= 80 else '⚠️  NEEDS WORK'}")