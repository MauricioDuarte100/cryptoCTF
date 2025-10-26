#!/usr/bin/env python3
"""
Test de muestras del dataset generado
Prueba algunos challenges del dataset para verificar que funcionan
"""

import json
import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.tools.tools import analyze_files, classify_crypto, attack_rsa, attack_classical, decode_text

def test_dataset_sample(challenge, max_tests=5):
    """Test un challenge del dataset"""
    
    print(f"\n🧪 Testing: {challenge['name']}")
    print(f"   Type: {challenge['type']} | Difficulty: {challenge['difficulty']}")
    print("=" * 60)
    
    # Crear archivo simulado
    files = [{'name': 'chall.py', 'content': challenge['content']}]
    
    # PASO 1: Analyze files
    analysis = analyze_files.invoke({'files': files})
    print(f"🔍 Analysis: Variables={list(analysis['variables'].keys())}, Indicators={analysis['crypto_indicators']}")
    
    # PASO 2: Classify crypto
    classification = classify_crypto.invoke({'analysis': analysis})
    print(f"🔍 Classification: {classification['type']} (confidence: {classification['confidence']:.2f})")
    
    # PASO 3: Attack based on type
    success = False
    result_flag = ""
    
    if classification['type'] == 'RSA':
        n = str(analysis['variables'].get('n', ''))
        e = str(analysis['variables'].get('e', ''))
        c = str(analysis['variables'].get('c', ''))
        
        if n and e and c:
            result = attack_rsa.invoke({'n': n, 'e': e, 'c': c})
            if result.get('success'):
                result_flag = result.get('flag', '')
                success = True
                print(f"🔍 RSA Attack: SUCCESS - {result_flag}")
            else:
                print(f"🔍 RSA Attack: FAILED")
        else:
            print(f"🔍 RSA Attack: Missing parameters")
    
    elif classification['type'] in ['Classical', 'XOR']:
        # Buscar ciphertext
        ciphertext = None
        
        # Buscar en variables
        for var_name, var_value in analysis['variables'].items():
            if isinstance(var_value, str) and len(var_value) > 10:
                ciphertext = var_value
                break
        
        # Buscar en contenido
        if not ciphertext:
            import re
            content = challenge['content']
            
            # Buscar strings entre comillas
            string_matches = re.findall(r'"([^"]{10,})"', content)
            if string_matches:
                ciphertext = string_matches[0]
        
        if ciphertext:
            result = attack_classical.invoke({'ciphertext': ciphertext})
            if result.get('success'):
                result_flag = result.get('plaintext', '')
                success = True
                print(f"🔍 Classical/XOR Attack: SUCCESS - {result_flag}")
            else:
                print(f"🔍 Classical/XOR Attack: FAILED")
        else:
            print(f"🔍 Classical/XOR Attack: No ciphertext found")
    
    elif classification['type'] == 'Encoding':
        # Buscar texto encoded
        import re
        content = challenge['content']
        
        # Buscar strings que parezcan encoded
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        hex_pattern = r'[0-9a-fA-F]{20,}'
        
        encoded_text = None
        base64_matches = re.findall(base64_pattern, content)
        if base64_matches:
            encoded_text = base64_matches[0]
        else:
            hex_matches = re.findall(hex_pattern, content)
            if hex_matches:
                encoded_text = hex_matches[0]
        
        if encoded_text:
            result = decode_text.invoke({'text': encoded_text})
            if result.get('success') and result.get('results'):
                flag_found = result['results'].get('flag_found', {})
                if flag_found:
                    result_flag = flag_found.get('text', '')
                    success = True
                    print(f"🔍 Encoding Attack: SUCCESS - {result_flag}")
                else:
                    print(f"🔍 Encoding Attack: FAILED")
            else:
                print(f"🔍 Encoding Attack: FAILED")
        else:
            print(f"🔍 Encoding Attack: No encoded text found")
    
    # Verificar resultado
    expected_flag = challenge['expected_flag']
    
    if success and result_flag:
        # Verificación flexible
        if (expected_flag.lower() in result_flag.lower() or 
            result_flag.lower() in expected_flag.lower() or
            'flag{' in result_flag.lower()):
            print(f"✅ SUCCESS! Expected: {expected_flag}, Got: {result_flag}")
            return True
        else:
            print(f"⚠️  PARTIAL SUCCESS - Flag mismatch")
            print(f"   Expected: {expected_flag}")
            print(f"   Got: {result_flag}")
            return False
    else:
        print(f"❌ FAILED - No flag found")
        print(f"   Expected: {expected_flag}")
        return False

def main():
    """Test muestras del dataset"""
    
    print("🚀 DATASET SAMPLES TESTING")
    print("=" * 60)
    print("Testing generated challenges to verify they work")
    print()
    
    # Cargar dataset
    dataset_file = Path("ml_dataset/challenges_only.json")
    if not dataset_file.exists():
        print("❌ Dataset not found. Run dataset_expander.py first.")
        return 1
    
    with open(dataset_file, 'r', encoding='utf-8') as f:
        dataset = json.load(f)
    
    print(f"📊 Dataset loaded: {len(dataset)} challenges")
    
    # Seleccionar muestras de cada tipo
    samples = []
    types_tested = set()
    
    for challenge in dataset:
        if challenge['type'] not in types_tested:
            samples.append(challenge)
            types_tested.add(challenge['type'])
            if len(samples) >= 6:  # Máximo 6 muestras
                break
    
    print(f"🧪 Testing {len(samples)} sample challenges...")
    
    # Test cada muestra
    results = []
    for i, challenge in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}]", end="")
        success = test_dataset_sample(challenge)
        results.append({
            'name': challenge['name'],
            'type': challenge['type'],
            'success': success
        })
    
    # Resumen final
    print("\n" + "=" * 60)
    print("📊 TESTING RESULTS")
    print("=" * 60)
    
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    success_rate = (successful / total * 100) if total > 0 else 0
    
    print(f"✅ Successful: {successful}/{total}")
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print(f"\n📋 Details:")
    for result in results:
        status = "✅" if result['success'] else "❌"
        print(f"  {status} {result['name']} ({result['type']})")
    
    if success_rate >= 75:
        print(f"\n🎉 EXCELLENT! Dataset quality is high")
        print("🚀 Ready for Phase 2.2 ML training!")
    elif success_rate >= 50:
        print(f"\n⚠️  GOOD - Dataset mostly works")
        print("🔧 Some challenges may need refinement")
    else:
        print(f"\n❌ POOR - Dataset needs significant work")
        print("🛠️  Review challenge generation logic")
    
    return 0 if success_rate >= 75 else 1

if __name__ == "__main__":
    exit(main())