#!/usr/bin/env python3
"""
Test directo del benchmark para debugging
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_single_challenge():
    """Test de un solo desafío"""
    
    print("🧪 Test Directo de Benchmark")
    print("="*40)
    
    try:
        from src.core.simple_agent import solve_ctf_challenge_simple
        
        # Test Caesar cipher
        files = [{
            "name": "caesar.py",
            "content": '''# Caesar Cipher Challenge
ciphertext = "synt{pnrfne_pvcure_vf_abg_frpher}"

print("Encrypted flag:", ciphertext)
print("Hint: Julius Caesar would be proud!")

# The flag is encrypted with a simple Caesar cipher
# Try all possible shifts to find the readable text'''
        }]
        
        print("📝 Probando Caesar Cipher...")
        result = solve_ctf_challenge_simple(
            description="Caesar cipher challenge with ROT shift",
            files=files,
            challenge_name="Test Caesar",
            expected_flag="flag{caesar_cipher_is_not_secure}",
            log_to_db=False
        )
        
        print(f"✅ Resultado: {result}")
        
        if result.get("success"):
            print(f"🏁 Flag encontrada: {result.get('flag')}")
            print(f"🎯 Tipo: {result.get('challenge_type')}")
            print(f"📊 Confianza: {result.get('confidence')}")
            print(f"🔢 Pasos: {result.get('steps_used')}")
        else:
            print(f"❌ Error: {result.get('error')}")
        
        return result.get("success", False)
        
    except Exception as e:
        print(f"💥 Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Función principal"""
    success = test_single_challenge()
    
    if success:
        print("\n🎉 Test exitoso!")
    else:
        print("\n💥 Test falló")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)