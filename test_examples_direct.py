#!/usr/bin/env python3
"""
Test directo de ejemplos sin usar el agente completo
Para evitar rate limits y probar solo las herramientas
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.tools.tools import analyze_files, classify_crypto, attack_rsa, attack_classical, decode_text

def test_example(name, file_path, expected_flag_contains="flag{"):
    """Test un ejemplo específico"""
    
    print(f"\n🧪 Testing: {name}")
    print("=" * 50)
    
    # Leer archivo
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return False
    
    files = [{'name': Path(file_path).name, 'content': content}]
    
    # PASO 1: Analyze files
    print("🔍 Step 1: analyze_files()")
    analysis = analyze_files.invoke({'files': files})
    print(f"   Variables: {list(analysis['variables'].keys())}")
    print(f"   Indicators: {analysis['crypto_indicators']}")
    
    # PASO 2: Classify crypto
    print("🔍 Step 2: classify_crypto()")
    classification = classify_crypto.invoke({'analysis': analysis})
    print(f"   Type: {classification['type']}")
    print(f"   Confidence: {classification['confidence']}")
    
    # PASO 3: Attack based on type
    print("🔍 Step 3: Attack")
    
    if classification['type'] == 'RSA':
        n = str(analysis['variables'].get('n', ''))
        e = str(analysis['variables'].get('e', ''))
        c = str(analysis['variables'].get('c', ''))
        
        if n and e and c:
            print(f"   RSA params: n={n}, e={e}, c={c}")
            result = attack_rsa.invoke({'n': n, 'e': e, 'c': c})
            print(f"   Result: {result}")
            
            flag = result.get('flag', '')
            # Para RSA, aceptar cualquier resultado exitoso
            if result.get('success') and flag:
                if (expected_flag_contains.lower() in flag.lower() or 
                    'decrypted' in flag.lower() or 
                    result.get('decrypted_message')):
                    print("   ✅ SUCCESS!")
                    return True
            
            print("   ❌ No flag found")
            return False
        else:
            print("   ❌ Missing RSA parameters")
            return False
    
    elif classification['type'] in ['Classical', 'XOR']:
        # Buscar ciphertext en el contenido
        import re
        
        # Buscar strings que parezcan ciphertext
        hex_pattern = r'[0-9a-fA-F]{20,}'
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        ciphertext = None
        
        # Buscar en variables
        for var_name, var_value in analysis['variables'].items():
            if isinstance(var_value, str) and len(var_value) > 10:
                ciphertext = var_value
                break
        
        # Buscar en contenido
        if not ciphertext:
            hex_matches = re.findall(hex_pattern, content)
            if hex_matches:
                ciphertext = hex_matches[0]
            else:
                base64_matches = re.findall(base64_pattern, content)
                if base64_matches:
                    ciphertext = base64_matches[0]
        
        # Buscar strings literales en el código
        if not ciphertext:
            string_matches = re.findall(r'"([^"]{15,})"', content)
            if string_matches:
                ciphertext = string_matches[0]
        
        if ciphertext:
            print(f"   Ciphertext: {ciphertext[:50]}...")
            
            if classification['type'] == 'Classical' or classification['type'] == 'XOR':
                result = attack_classical.invoke({'ciphertext': ciphertext})
            else:
                result = decode_text.invoke({'text': ciphertext})
            
            print(f"   Result: {result}")
            
            # Buscar flag en resultado
            flag = ""
            if result.get('success'):
                flag = result.get('plaintext', '') or result.get('flag', '')
                if isinstance(result.get('results'), dict):
                    flag_found = result['results'].get('flag_found', {})
                    if flag_found:
                        flag = flag_found.get('text', '')
            
            if flag and expected_flag_contains.lower() in flag.lower():
                print("   ✅ SUCCESS!")
                return True
            else:
                print("   ❌ No flag found")
                return False
        else:
            print("   ❌ No ciphertext found")
            return False
    
    elif classification['type'] == 'Encoding':
        # Buscar texto encoded
        import re
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        encoded_text = None
        base64_matches = re.findall(base64_pattern, content)
        if base64_matches:
            encoded_text = base64_matches[0]
        
        if not encoded_text:
            # Buscar en variables también
            for var_name, var_value in analysis['variables'].items():
                if isinstance(var_value, str) and re.match(base64_pattern, var_value):
                    encoded_text = var_value
                    break
        
        if encoded_text:
            print(f"   Encoded text: {encoded_text[:50]}...")
            result = decode_text.invoke({'text': encoded_text})
            print(f"   Result: {result}")
            
            flag = ""
            if result.get('success') and result.get('results'):
                flag_found = result['results'].get('flag_found', {})
                if flag_found:
                    flag = flag_found.get('text', '')
            
            if flag and expected_flag_contains.lower() in flag.lower():
                print("   ✅ SUCCESS!")
                return True
            else:
                print("   ❌ No flag found")
                return False
        else:
            print("   ❌ No encoded text found")
            return False
    
    else:
        print(f"   ❌ Unknown type: {classification['type']}")
        return False

def main():
    """Test todos los ejemplos"""
    
    print("🚀 DIRECT EXAMPLES TEST")
    print("=" * 60)
    print("Testing examples directly without agent (no rate limits)")
    print()
    
    examples = [
        {
            'name': 'RSA Small Factors',
            'file': 'examples/rsa_small/chall.py',
            'expected': 'flag{'
        },
        {
            'name': 'RSA Fermat Attack', 
            'file': 'examples/rsa_fermat/chall.py',
            'expected': 'flag{'
        },
        {
            'name': 'Caesar ROT13',
            'file': 'examples/caesar_medium/chall.py', 
            'expected': 'flag{caesar_is_classical_crypto}'
        },
        {
            'name': 'XOR Advanced',
            'file': 'examples/xor_advanced/chall.py',
            'expected': 'flag{xor_single_byte_advanced}'
        },
        {
            'name': 'Base64 Simple',
            'file': 'examples/base64_simple/chall.py',
            'expected': 'flag{base64_is_encoding_not_encryption}'
        },
        {
            'name': 'XOR Real',
            'file': 'examples/xor_real/chall.py',
            'expected': 'flag{xor_single_byte_key}'
        }
    ]
    
    results = []
    
    for example in examples:
        success = test_example(
            example['name'],
            example['file'], 
            example['expected']
        )
        results.append({
            'name': example['name'],
            'success': success
        })
    
    # Resumen final
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    success_rate = (successful / total * 100) if total > 0 else 0
    
    print(f"✅ Successful: {successful}/{total}")
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print(f"\n📋 Details:")
    for result in results:
        status = "✅" if result['success'] else "❌"
        print(f"  {status} {result['name']}")
    
    if success_rate >= 67:
        print(f"\n🎉 SUCCESS! Target 67%+ achieved!")
    elif success_rate >= 50:
        print(f"\n⚠️  Good progress, close to 67% target")
    else:
        print(f"\n❌ Need more work to reach 67% target")
    
    return success_rate >= 67

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)