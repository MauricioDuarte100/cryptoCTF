#!/usr/bin/env python3
"""
Test directo de prompts v2 mejorados
"""

from src.tools.tools import analyze_files, classify_crypto, attack_rsa
from src.prompts_v2 import SYSTEM_PROMPT_V2, SEQUENTIAL_ATTACK_PROMPT

def test_prompts_workflow():
    """Test del flujo completo con prompts v2"""
    
    print("🧪 TESTING PROMPTS V2 WORKFLOW")
    print("=" * 50)
    
    # Ejemplo RSA
    files = [{
        'name': 'chall.py',
        'content': '''
# RSA Challenge - Small factors
p = 61
q = 53
n = p * q  # 3233
e = 17
m = 1234
c = pow(m, e, n)  # This will be 2183

# For the challenge, here are the values:
n = 3233
e = 17
c = 2183

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("Factor n to decrypt the message!")
'''
    }]
    
    print("📁 Files to analyze:")
    for f in files:
        print(f"  - {f['name']}: {len(f['content'])} chars")
    
    # PASO 1: Analyze files
    print("\n🔍 PASO 1: analyze_files()")
    analysis = analyze_files.invoke({'files': files})
    print(f"   Variables found: {list(analysis['variables'].keys())}")
    print(f"   Crypto indicators: {analysis['crypto_indicators']}")
    
    # PASO 2: Classify crypto
    print("\n🔍 PASO 2: classify_crypto()")
    classification = classify_crypto.invoke({'analysis': analysis})
    print(f"   Type: {classification['type']}")
    print(f"   Confidence: {classification['confidence']}")
    
    # PASO 3: Extract parameters
    print("\n🔍 PASO 3: Extract parameters")
    if classification['type'] == 'RSA':
        n = str(analysis['variables'].get('n', ''))
        e = str(analysis['variables'].get('e', ''))
        c = str(analysis['variables'].get('c', ''))
        print(f"   n = {n}")
        print(f"   e = {e}")
        print(f"   c = {c}")
        
        # PASO 4: Attack RSA
        print("\n🔍 PASO 4: attack_rsa()")
        if n and e and c:
            result = attack_rsa.invoke({'n': n, 'e': e, 'c': c})
            print(f"   Success: {result.get('success')}")
            print(f"   Flag: {result.get('flag')}")
            print(f"   Attack type: {result.get('attack_type')}")
            
            if result.get('success'):
                print("\n✅ WORKFLOW SUCCESS!")
                return True
            else:
                print("\n❌ Attack failed")
                return False
        else:
            print("\n❌ Missing parameters")
            return False
    else:
        print(f"\n❌ Wrong classification: {classification['type']}")
        return False

def test_prompt_content():
    """Test del contenido de los prompts"""
    
    print("\n🧪 TESTING PROMPT CONTENT")
    print("=" * 50)
    
    print("📝 System Prompt V2 length:", len(SYSTEM_PROMPT_V2))
    print("📝 Sequential Prompt length:", len(SEQUENTIAL_ATTACK_PROMPT))
    
    # Verificar que contiene instrucciones clave
    key_phrases = [
        "analyze_files()",
        "classify_crypto()",
        "attack_rsa()",
        "PASO 1:",
        "PASO 2:",
        "RSA",
        "Classical",
        "XOR"
    ]
    
    combined_prompt = SYSTEM_PROMPT_V2 + SEQUENTIAL_ATTACK_PROMPT
    
    print("\n🔍 Key phrases check:")
    for phrase in key_phrases:
        found = phrase in combined_prompt
        status = "✅" if found else "❌"
        print(f"   {status} {phrase}")
    
    return all(phrase in combined_prompt for phrase in key_phrases)

def main():
    print("🚀 PROMPTS V2 VALIDATION TEST")
    print("=" * 60)
    
    # Test 1: Prompt content
    content_ok = test_prompt_content()
    
    # Test 2: Workflow
    workflow_ok = test_prompts_workflow()
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    
    print(f"✅ Prompt Content: {'PASS' if content_ok else 'FAIL'}")
    print(f"✅ Workflow Test: {'PASS' if workflow_ok else 'FAIL'}")
    
    overall_success = content_ok and workflow_ok
    print(f"\n🎯 Overall: {'SUCCESS' if overall_success else 'NEEDS WORK'}")
    
    if overall_success:
        print("\n🎉 Prompts V2 are ready for integration!")
    else:
        print("\n⚠️  Prompts V2 need more work")
    
    return overall_success

if __name__ == "__main__":
    main()