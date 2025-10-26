"""
Test de Integración BERT
Valida que el modelo BERT está integrado correctamente en el agente.
Prueba classify_crypto() con ejemplos reales.
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tools.tools import analyze_files, classify_crypto
import json

# Ejemplos de prueba
EXAMPLES = [
    {
        "name": "RSA Basic",
        "description": "RSA challenge",
        "files": [{
            "name": "chall.py",
            "content": """
# RSA Challenge
n = 123456789
e = 3
c = 987654321

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("Factor n to get the flag!")
"""
        }],
        "expected_type": "RSA"
    },
    {
        "name": "Caesar Cipher",
        "description": "Caesar cipher test",
        "files": [{
            "name": "chall.py",
            "content": """
# Caesar Cipher Challenge
ciphertext = "uryyb_pguq_vf_n_pnrfne_grfg"

print("Encrypted message:", ciphertext)
print("Hint: This is a Caesar cipher")
print("Try different rotations to decrypt!")
"""
        }],
        "expected_type": "Classical"
    },
    {
        "name": "XOR Challenge",
        "description": "XOR encryption",
        "files": [{
            "name": "chall.py",
            "content": """
# XOR Single Byte Challenge
key = 0x42
encrypted = bytes([p ^ key for p in plaintext])

print("Encrypted flag (hex):", encrypted.hex())
print("Hint: Single byte XOR key was used")
print("Try all 256 possible keys!")
"""
        }],
        "expected_type": "XOR"
    },
    {
        "name": "Base64 Encoding",
        "description": "Base64 encoded message",
        "files": [{
            "name": "chall.py",
            "content": """
# Base64 Encoding Challenge
import base64

encoded_message = "ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"

print("Encoded message:", encoded_message)
print("Hint: This is BASE64 encoded")
print("Decode it to get the flag!")
"""
        }],
        "expected_type": "Encoding"
    }
]

def test_integration():
    print("🧪 Testing BERT Integration\n")
    
    results = []
    
    for example in EXAMPLES:
        print(f"Testing: {example['name']}")
        
        # 1. Analizar
        analysis = analyze_files.invoke({'files': example['files']})
        print(f"  📊 Analysis: Variables={list(analysis['variables'].keys())}, Indicators={analysis['crypto_indicators']}")
        
        # 2. Clasificar con BERT + Heurística
        classification = classify_crypto.invoke({'analysis': analysis, 'use_ml': True})
        print(f"  🧠 Classification: {classification}")
        
        # Verificar
        match = classification['type'] == example['expected_type']
        status = "✅" if match else "❌"
        method = classification.get('method', 'unknown')
        confidence = classification.get('confidence', 0)
        
        print(f"  {status} Expected: {example['expected_type']}, Got: {classification['type']} ({confidence:.2f}) [{method}]\n")
        
        results.append({
            "name": example['name'],
            "expected": example['expected_type'],
            "got": classification['type'],
            "confidence": confidence,
            "method": method,
            "match": match
        })
    
    # Resumen
    print("\n" + "="*60)
    print("📊 INTEGRATION TEST SUMMARY")
    print("="*60)
    
    matches = sum(1 for r in results if r['match'])
    total = len(results)
    accuracy = matches / total * 100
    
    bert_used = sum(1 for r in results if r['method'] == 'BERT')
    heuristic_used = sum(1 for r in results if r['method'] == 'heuristic')
    
    for r in results:
        status = "✅" if r['match'] else "❌"
        print(f"{status} {r['name']:20} | {r['expected']:12} -> {r['got']:12} ({r['confidence']:.2f}) [{r['method']}]")
    
    print(f"\n🎯 Results:")
    print(f"   Accuracy: {matches}/{total} ({accuracy:.1f}%)")
    print(f"   BERT used: {bert_used}/{total} ({bert_used/total*100:.1f}%)")
    print(f"   Heuristic used: {heuristic_used}/{total} ({heuristic_used/total*100:.1f}%)")
    print(f"   Avg confidence: {sum(r['confidence'] for r in results)/len(results):.3f}")
    
    # Guardar reporte
    Path("ml_phase2/evaluation").mkdir(exist_ok=True)
    with open("ml_phase2/evaluation/integration_test.json", 'w') as f:
        json.dump({
            "total": total,
            "matches": matches,
            "accuracy": accuracy,
            "bert_usage": bert_used / total,
            "heuristic_usage": heuristic_used / total,
            "avg_confidence": sum(r['confidence'] for r in results) / len(results),
            "results": results
        }, f, indent=2)
    
    print(f"\n✅ Report saved to: ml_phase2/evaluation/integration_test.json")
    
    # Evaluación
    if accuracy >= 75:
        print(f"\n🎉 EXCELLENT! Integration test passed with {accuracy:.1f}% accuracy")
        if bert_used >= total * 0.5:
            print(f"🧠 BERT is being used effectively ({bert_used}/{total} cases)")
        return True
    else:
        print(f"\n⚠️  Integration needs work. Only {accuracy:.1f}% accuracy")
        return False

def test_bert_directly():
    """Test BERT classifier directamente"""
    print("\n🧠 Testing BERT Classifier Directly\n")
    
    try:
        from ml_phase2.bert_classifier import bert_classifier, BERT_AVAILABLE
        
        if not BERT_AVAILABLE:
            print("❌ BERT classifier not available")
            return False
        
        # Test directo
        test_cases = [
            ("RSA challenge with n=123 e=3 c=456", "RSA"),
            ("Caesar cipher with rotation 13", "Classical"),
            ("XOR encryption with single byte key", "XOR"),
            ("Base64 encoded message", "Encoding")
        ]
        
        correct = 0
        for text, expected in test_cases:
            result = bert_classifier.classify(text)
            match = result['type'] == expected
            status = "✅" if match else "❌"
            
            print(f"{status} '{text[:30]}...' -> {result['type']} ({result['confidence']:.2f})")
            if match:
                correct += 1
        
        accuracy = correct / len(test_cases) * 100
        print(f"\n🎯 Direct BERT accuracy: {correct}/{len(test_cases)} ({accuracy:.1f}%)")
        
        return accuracy >= 75
        
    except Exception as e:
        print(f"❌ Error testing BERT directly: {e}")
        return False

def main():
    print("🚀 BERT INTEGRATION VALIDATION")
    print("=" * 60)
    
    # Test 1: BERT directo
    bert_ok = test_bert_directly()
    
    # Test 2: Integración completa
    integration_ok = test_integration()
    
    print("\n" + "=" * 60)
    print("📊 FINAL VALIDATION RESULTS")
    print("=" * 60)
    
    print(f"🧠 BERT Direct Test: {'✅ PASS' if bert_ok else '❌ FAIL'}")
    print(f"🔌 Integration Test: {'✅ PASS' if integration_ok else '❌ FAIL'}")
    
    overall_success = bert_ok and integration_ok
    
    if overall_success:
        print(f"\n🎉 SUCCESS! BERT integration is working perfectly!")
        print(f"   Ready for production use")
        print(f"   Phase 2.2 validation: COMPLETE ✅")
    else:
        print(f"\n⚠️  Issues detected. Check logs above.")
        print(f"   Phase 2.2 validation: NEEDS WORK ❌")
    
    return overall_success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)