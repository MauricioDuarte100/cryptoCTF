#!/usr/bin/env python3
"""
Script de prueba para el agente CTF Crypto
Ejecuta ejemplos y valida funcionamiento
"""

import os
import sys
from pathlib import Path
from ..core.agent import solve_ctf_challenge

def load_challenge_files(challenge_dir):
    """Carga archivos de un desafío"""
    files = []
    challenge_path = Path(challenge_dir)
    
    if not challenge_path.exists():
        return files
    
    for file_path in challenge_path.glob("*.py"):
        with open(file_path, 'r', encoding='utf-8') as f:
            files.append({
                "name": file_path.name,
                "content": f.read()
            })
    
    return files

def test_rsa_basic():
    """Prueba desafío RSA básico"""
    print("🔐 Probando RSA Basic (e=3)...")
    
    files = load_challenge_files("examples/rsa_basic")
    
    result = solve_ctf_challenge(
        description="RSA challenge with small exponent e=3",
        files=files,
        max_steps=10
    )
    
    print(f"✅ Éxito: {result['success']}")
    if result['success']:
        print(f"🏁 Flag: {result['flag']}")
    else:
        print(f"❌ Error: {result.get('error', 'Unknown')}")
    
    return result['success']

def test_caesar_cipher():
    """Prueba desafío Caesar"""
    print("\n📜 Probando Caesar Cipher...")
    
    files = load_challenge_files("examples/caesar_cipher")
    
    result = solve_ctf_challenge(
        description="Caesar cipher challenge with ROT shift",
        files=files,
        max_steps=8
    )
    
    print(f"✅ Éxito: {result['success']}")
    if result['success']:
        print(f"🏁 Flag: {result['flag']}")
    
    return result['success']

def test_xor_single():
    """Prueba desafío XOR single byte"""
    print("\n⚡ Probando XOR Single Byte...")
    
    files = load_challenge_files("examples/xor_single")
    
    result = solve_ctf_challenge(
        description="XOR single byte key challenge",
        files=files,
        max_steps=8
    )
    
    print(f"✅ Éxito: {result['success']}")
    if result['success']:
        print(f"🏁 Flag: {result['flag']}")
    
    return result['success']

def main():
    """Ejecuta todas las pruebas"""
    print("🧪 Iniciando pruebas del agente CTF Crypto")
    print("="*50)
    
    # Verificar API key
    if not os.getenv("GOOGLE_API_KEY"):
        print("❌ GOOGLE_API_KEY no configurada!")
        print("📝 Edita .env con tu API key de Gemini")
        print("🔗 Obtén una gratis: https://aistudio.google.com/apikey")
        sys.exit(1)
    
    results = []
    
    # Ejecutar pruebas
    try:
        results.append(test_caesar_cipher())  # Más fácil primero
        results.append(test_xor_single())
        results.append(test_rsa_basic())      # Más complejo
    except Exception as e:
        print(f"💥 Error durante pruebas: {e}")
        return False
    
    # Resumen
    print("\n" + "="*50)
    print("📊 RESUMEN DE PRUEBAS")
    print("="*50)
    
    passed = sum(results)
    total = len(results)
    
    print(f"✅ Pasadas: {passed}/{total}")
    print(f"📈 Tasa de éxito: {passed/total*100:.1f}%")
    
    if passed == total:
        print("🎉 ¡Todas las pruebas pasaron!")
        return True
    else:
        print("⚠️  Algunas pruebas fallaron")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)