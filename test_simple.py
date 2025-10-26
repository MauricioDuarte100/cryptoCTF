#!/usr/bin/env python3
"""
Test simple del agente sin LangGraph para debugging
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_simple_solve():
    """Test simple sin LangGraph"""
    
    print("🧪 Test Simple del Agente")
    print("="*40)
    
    try:
        # Test de herramientas básicas
        from src.tools.tools import analyze_files, classify_crypto, attack_classical
        
        # Test 1: Analyze files
        print("1. Probando analyze_files...")
        test_files = [{
            "name": "caesar.py",
            "content": 'ciphertext = "synt{pnrfne_pvcure_vf_abg_frpher}"'
        }]
        
        result = analyze_files.invoke({"files": test_files})
        print(f"   ✅ Resultado: {result}")
        
        # Test 2: Classify crypto
        print("2. Probando classify_crypto...")
        classification = classify_crypto.invoke({"analysis": result})
        print(f"   ✅ Clasificación: {classification}")
        
        # Test 3: Attack classical
        print("3. Probando attack_classical...")
        attack_result = attack_classical.invoke({"ciphertext": "synt{pnrfne_pvcure_vf_abg_frpher}"})
        print(f"   ✅ Ataque: {attack_result}")
        
        if attack_result.get("success"):
            print(f"   🏁 Flag encontrada: {attack_result.get('plaintext')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gemini_direct():
    """Test directo de Gemini"""
    
    print("\n🤖 Test Directo de Gemini")
    print("="*40)
    
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        from src.config.config import config
        
        llm = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            temperature=0.1,
            google_api_key=config.GOOGLE_API_KEY
        )
        
        response = llm.invoke("¿Qué es ROT13? Responde en una línea.")
        print(f"✅ Respuesta de Gemini: {response.content}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error con Gemini: {e}")
        return False

def main():
    """Función principal"""
    
    success1 = test_simple_solve()
    success2 = test_gemini_direct()
    
    if success1 and success2:
        print("\n🎉 Todos los tests pasaron!")
        return True
    else:
        print("\n💥 Algunos tests fallaron")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)