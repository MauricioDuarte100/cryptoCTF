#!/usr/bin/env python3
"""
Prueba rápida del sistema CTF Crypto Agent
Verifica que todo funcione antes de subir a GitHub
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Prueba imports básicos"""
    print("🔍 Probando imports...")
    
    try:
        # Añadir src al path
        sys.path.insert(0, "src")
        
        # Imports básicos
        from src.core.agent import solve_ctf_challenge
        from src.tools.tools import ALL_TOOLS
        from src.config.config import config
        
        print(f"✅ Imports OK - {len(ALL_TOOLS)} herramientas disponibles")
        return True
        
    except Exception as e:
        print(f"❌ Error en imports: {e}")
        return False

def test_configuration():
    """Prueba configuración"""
    print("\n⚙️  Probando configuración...")
    
    try:
        sys.path.insert(0, "src")
        from src.config.config import config
        
        # Verificar archivos básicos
        required_files = [
            ".env.example",
            "requirements.txt", 
            "src/core/agent.py",
            "src/tools/tools.py"
        ]
        
        missing = []
        for file in required_files:
            if not Path(file).exists():
                missing.append(file)
        
        if missing:
            print(f"❌ Archivos faltantes: {missing}")
            return False
        
        print("✅ Configuración OK")
        return True
        
    except Exception as e:
        print(f"❌ Error en configuración: {e}")
        return False

def test_examples():
    """Prueba ejemplos"""
    print("\n📁 Probando ejemplos...")
    
    examples_dir = Path("examples")
    if not examples_dir.exists():
        print("❌ Directorio examples no existe")
        return False
    
    example_dirs = [d for d in examples_dir.iterdir() if d.is_dir()]
    
    if len(example_dirs) == 0:
        print("❌ No hay ejemplos disponibles")
        return False
    
    # Verificar que cada ejemplo tenga archivos .py
    valid_examples = 0
    for example_dir in example_dirs:
        py_files = list(example_dir.glob("*.py"))
        if py_files:
            valid_examples += 1
    
    print(f"✅ Ejemplos OK - {valid_examples} ejemplos válidos")
    return True

def test_basic_functionality():
    """Prueba funcionalidad básica sin API key"""
    print("\n🧪 Probando funcionalidad básica...")
    
    try:
        sys.path.insert(0, "src")
        from src.tools.tools import analyze_files, classify_crypto
        
        # Prueba analyze_files con ejemplo simple
        test_files = [{
            "name": "test.py",
            "content": """
n = 123456789012345678901234567890
e = 65537
c = 987654321098765432109876543210
print("RSA challenge")
"""
        }]
        
        # Llamar la función directamente
        result = analyze_files.invoke({"files": test_files})
        
        if not isinstance(result, dict):
            print("❌ analyze_files no retorna dict")
            return False
        
        if "variables" not in result:
            print("❌ analyze_files no extrae variables")
            return False
        
        # Prueba classify_crypto
        classification = classify_crypto.invoke({"analysis": result})
        
        if not isinstance(classification, dict):
            print("❌ classify_crypto no retorna dict")
            return False
        
        print("✅ Funcionalidad básica OK")
        return True
        
    except Exception as e:
        print(f"❌ Error en funcionalidad: {e}")
        return False

def test_structure():
    """Prueba estructura del proyecto"""
    print("\n📂 Probando estructura...")
    
    required_structure = [
        "src/",
        "src/core/",
        "src/tools/", 
        "src/config/",
        "examples/",
        "docs/",
        "main.py",
        "run.py",
        "README.md"
    ]
    
    missing = []
    for item in required_structure:
        if not Path(item).exists():
            missing.append(item)
    
    if missing:
        print(f"❌ Estructura incompleta: {missing}")
        return False
    
    print("✅ Estructura OK")
    return True

def main():
    """Ejecuta todas las pruebas"""
    print("🚀 CTF Crypto Agent - Prueba Rápida")
    print("="*50)
    
    tests = [
        ("Estructura", test_structure),
        ("Configuración", test_configuration), 
        ("Imports", test_imports),
        ("Ejemplos", test_examples),
        ("Funcionalidad", test_basic_functionality)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"💥 Error en {test_name}: {e}")
            results.append(False)
    
    # Resumen
    print("\n" + "="*50)
    print("📊 RESUMEN DE PRUEBAS")
    print("="*50)
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_name, _) in enumerate(tests):
        status = "✅" if results[i] else "❌"
        print(f"{status} {test_name}")
    
    print(f"\n📈 Resultado: {passed}/{total} pruebas pasaron")
    
    if passed == total:
        print("\n🎉 ¡Todas las pruebas pasaron!")
        print("✅ El proyecto está listo para subir a GitHub")
        print("\n🚀 Próximos pasos:")
        print("1. Configura tu API key en .env")
        print("2. Ejecuta: python main.py test")
        print("3. Sube a GitHub con los comandos que tienes")
        return True
    else:
        print(f"\n⚠️  {total - passed} pruebas fallaron")
        print("🔧 Revisa los errores arriba antes de subir")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)