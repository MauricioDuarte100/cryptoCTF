"""
Final Benchmark with RAG - Phase 2.3
Ejecuta benchmark completo del agente CON RAG integrado.
Compara vs Fase 2.2 (100% success rate).
"""

import time
import json
from pathlib import Path
import sys

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tools.tools import analyze_files, classify_crypto, RAG_AVAILABLE
from rag.rag_agent_tools import retrieve_similar_writeups, analyze_with_context

# Challenges de prueba (mismos que Fase 2.2 para comparación)
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

def run_phase_2_3_benchmark():
    print("\n" + "="*70)
    print("🚀 PHASE 2.3 - FINAL BENCHMARK WITH RAG-ENHANCED AGENT")
    print("="*70 + "\n")
    
    if not RAG_AVAILABLE:
        print("❌ RAG system not available - cannot run RAG benchmark")
        return None
    
    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "challenges": [],
        "summary": {}
    }
    
    by_type = {}
    total_time = 0
    successful = 0
    rag_used = 0
    patterns_retrieved = 0
    
    for i, challenge in enumerate(BENCHMARK_CHALLENGES, 1):
        print(f"[{i}/{len(BENCHMARK_CHALLENGES)}] Testing: {challenge['name']}")
        
        try:
            start = time.time()
            
            # PASO 0: RAG Retrieval (NUEVO)
            challenge_content = f"{challenge['description']}\n\n{challenge['files'][0]['content']}"
            
            rag_result = retrieve_similar_writeups.invoke({
                'challenge_text': challenge_content,
                'challenge_type': challenge['type']
            })
            
            rag_patterns = 0
            if rag_result['status'] == 'success':
                rag_used += 1
                rag_patterns = rag_result['count']
                patterns_retrieved += rag_patterns
                print(f"   🧠 RAG: Retrieved {rag_patterns} similar writeups")
            else:
                print(f"   ⚠️  RAG: {rag_result['message']}")
            
            # PASO 1: Análisis tradicional
            analysis = analyze_files.invoke({'files': challenge['files']})
            
            # PASO 2: Clasificación (BERT + heurística)
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
                'time': elapsed,
                'rag_patterns': rag_patterns,
                'rag_used': rag_result['status'] == 'success'
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
        'rag_usage': rag_used / total_challenges,
        'avg_patterns_per_challenge': patterns_retrieved / total_challenges,
        'by_type': {
            t: {
                'success_rate': (stats['success'] / stats['total'] * 100)
            }
            for t, stats in by_type.items()
        }
    }
    
    # Imprimir reporte
    print("=" * 70)
    print("📊 FINAL BENCHMARK REPORT - PHASE 2.3")
    print("=" * 70)
    print(f"\n🎯 OVERALL:")
    print(f"   Total Challenges: {total_challenges}")
    print(f"   Successful: {successful} ({success_rate:.1f}%)")
    print(f"   Failed: {total_challenges - successful}")
    print(f"   Average Time: {total_time/total_challenges:.2f}s")
    
    print(f"\n🧠 RAG PERFORMANCE:")
    print(f"   RAG Usage: {rag_used}/{total_challenges} ({rag_used/total_challenges*100:.1f}%)")
    print(f"   Avg Patterns/Challenge: {patterns_retrieved/total_challenges:.1f}")
    print(f"   Total Patterns Retrieved: {patterns_retrieved}")
    
    print(f"\n📈 BY TYPE:")
    for ctype, stats in by_type.items():
        rate = stats['success'] / stats['total'] * 100
        print(f"   {ctype}: {stats['success']}/{stats['total']} ({rate:.1f}%)")
    
    # Comparación con Fase 2.2
    print(f"\n📉 COMPARISON WITH PHASE 2.2:")
    print(f"   Phase 2.2 (ML Only): 100.0% success")
    improvement = success_rate - 100.0
    if improvement > 0:
        print(f"   Phase 2.3 (ML + RAG): {success_rate:.1f}% success")
        print(f"   ✅ IMPROVEMENT: +{improvement:.1f} percentage points")
    elif improvement < 0:
        print(f"   Phase 2.3 (ML + RAG): {success_rate:.1f}% success")
        print(f"   ⚠️  Regression: {improvement:.1f} percentage points")
    else:
        print(f"   Phase 2.3 (ML + RAG): {success_rate:.1f}% success")
        print(f"   = MAINTAINED (RAG integration didn't break performance)")
    
    # Guardar JSON
    Path("rag/evaluation").mkdir(parents=True, exist_ok=True)
    with open("rag/evaluation/phase_2_3_benchmark.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Report saved to: rag/evaluation/phase_2_3_benchmark.json")
    print("=" * 70)
    
    return results

def main():
    results = run_phase_2_3_benchmark()
    
    if not results:
        return 1
    
    # Evaluación final
    success_rate = results['summary']['success_rate']
    rag_usage = results['summary']['rag_usage']
    
    print(f"\n🏁 PHASE 2.3 FINAL EVALUATION:")
    if success_rate >= 95:
        print(f"🎉 EXCELLENT! {success_rate:.1f}% success rate")
    elif success_rate >= 90:
        print(f"✅ GOOD! {success_rate:.1f}% success rate")
    elif success_rate >= 80:
        print(f"⚠️  ACCEPTABLE: {success_rate:.1f}% success rate")
    else:
        print(f"❌ NEEDS IMPROVEMENT: {success_rate:.1f}% success rate")
    
    if rag_usage >= 0.8:
        print(f"🧠 RAG is being used effectively ({rag_usage:.1%} of cases)")
    elif rag_usage >= 0.5:
        print(f"🧠 RAG usage is moderate ({rag_usage:.1%} of cases)")
    else:
        print(f"⚠️  RAG usage is low ({rag_usage:.1%} of cases)")
    
    # Determinar estado final
    if success_rate >= 90 and rag_usage >= 0.5:
        print(f"\n📋 PHASE 2.3 STATUS: ✅ COMPLETE SUCCESS")
        return 0
    elif success_rate >= 80:
        print(f"\n📋 PHASE 2.3 STATUS: ✅ ACCEPTABLE")
        return 0
    else:
        print(f"\n📋 PHASE 2.3 STATUS: ⚠️  NEEDS WORK")
        return 1

if __name__ == "__main__":
    exit(main())