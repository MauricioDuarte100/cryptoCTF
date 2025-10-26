#!/usr/bin/env python3
"""
Test directo de herramientas mejoradas
"""

from src.tools.tools import attack_rsa, attack_classical, analyze_files, classify_crypto

def test_rsa_basic():
    """Test RSA con ejemplo del benchmark"""
    print("🔍 Testing RSA Basic...")
    
    # Parámetros del ejemplo rsa_basic
    n = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"
    e = "3"
    c = "2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783906491394253940160395513179434395215"
    
    result = attack_rsa.invoke({'n': n, 'e': e, 'c': c})
    print(f"   Result: {result}")
    
    if result.get('success'):
        print("   ✅ RSA attack successful!")
        return True
    else:
        print("   ❌ RSA attack failed")
        return False

def test_xor_single():
    """Test XOR con ejemplo del benchmark"""
    print("\n🔍 Testing XOR Single Byte...")
    
    # Ejemplo del benchmark
    ciphertext = "26646c60716c6f60756e6f60716c6f60756e6f60716c6f6073"
    
    result = attack_classical.invoke({'ciphertext': ciphertext})
    print(f"   Result: {result}")
    
    if result.get('success'):
        print("   ✅ XOR attack successful!")
        return True
    else:
        print("   ❌ XOR attack failed")
        return False

def test_caesar():
    """Test Caesar que sabemos que funciona"""
    print("\n🔍 Testing Caesar...")
    
    ciphertext = "synt{pnrfne_pvcure_vf_abg_frpher}"
    
    result = attack_classical.invoke({'ciphertext': ciphertext})
    print(f"   Result: {result}")
    
    if result.get('success'):
        print("   ✅ Caesar attack successful!")
        return True
    else:
        print("   ❌ Caesar attack failed")
        return False

def test_analyze_files():
    """Test análisis de archivos"""
    print("\n🔍 Testing File Analysis...")
    
    # Simular archivo RSA
    files = [{
        'name': 'chall.py',
        'content': '''
# RSA Challenge
from Crypto.PublicKey import RSA

n = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357
e = 3
c = 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783906491394253940160395513179434395215

print("Decrypt this!")
'''
    }]
    
    result = analyze_files.invoke({'files': files})
    print(f"   Analysis: {result}")
    
    # Test clasificación
    classification = classify_crypto.invoke({'analysis': result})
    print(f"   Classification: {classification}")
    
    if classification.get('type') == 'RSA':
        print("   ✅ File analysis successful!")
        return True
    else:
        print("   ❌ File analysis failed")
        return False

def main():
    print("=" * 60)
    print("🧪 DIRECT TOOLS TEST")
    print("=" * 60)
    
    results = []
    
    # Test individual tools
    results.append(test_analyze_files())
    results.append(test_caesar())
    results.append(test_xor_single())
    results.append(test_rsa_basic())
    
    print("\n" + "=" * 60)
    print("📊 RESULTS SUMMARY")
    print("=" * 60)
    
    success_count = sum(results)
    total_count = len(results)
    success_rate = (success_count / total_count) * 100
    
    print(f"✅ Successful: {success_count}/{total_count}")
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 75:
        print("🎉 Tools are working well!")
    elif success_rate >= 50:
        print("⚠️  Tools need some improvement")
    else:
        print("❌ Tools need major fixes")
    
    print("=" * 60)

if __name__ == "__main__":
    main()