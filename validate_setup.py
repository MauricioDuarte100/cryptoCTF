#!/usr/bin/env python3
"""
Script de validación completa del setup
Verifica que todo esté configurado correctamente según Fase 1
"""

import sys
import os
from pathlib import Path
import importlib.util

def print_header(title):
    """Imprime header de sección"""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print('='*60)

def check_python_environment():
    """Verifica entorno Python"""
    print_header("ENTORNO PYTHON")
    
    checks = []
    
    # Versión Python
    version = sys.version_info
    if version >= (3, 8):
        checks.append(("Python Version", True, f"{version.major}.{version.minor}.{version.micro}"))
    else:
        checks.append(("Python Version", False, f"{version.major}.{version.minor} (requiere 3.8+)"))
    
    # Entorno virtual
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    checks.append(("Virtual Environment", in_venv, "Activo" if in_venv else "No detectado"))
    
    return checks

def check_dependencies():
    """Verifica dependencias principales"""
    print_header("DEPENDENCIAS PYTHON")
    
    deps = [
        ("langgraph", "LangGraph"),
        ("langchain", "LangChain"),
        ("langchain_google_genai", "Gemini AI"),
        ("langchain_core", "LangChain Core"),
        ("google.generativeai", "Google AI"),
        ("pwntools", "Pwntools"),
        ("pycryptodome", "PyCryptodome"),
        ("flask", "Flask"),
        ("dotenv", "Python-dotenv"),
        ("numpy", "NumPy"),
        ("sympy", "SymPy")
    ]
    
    checks = []
    for module, name in deps:
        try:
            spec = importlib.util.find_spec(module)
            if spec is not None:
                checks.append((name, True, "Instalado"))
            else:
                checks.append((name, False, "No encontrado"))
        except ImportError:
            checks.append((name, False, "Error de importación"))
    
    return checks

def check_file_structure():
    """Verifica estructura de archivos"""
    print_header("ESTRUCTURA DE ARCHIVOS")
    
    required_files = [
        ("src/core/agent.py", "Agente principal"),
        ("src/tools/tools.py", "Herramientas básicas"),
        ("src/tools/rsa_attacks.py", "Ataques RSA"),
        ("src/config/config.py", "Configuración"),
        ("src/web/web_interface.py", "Interfaz web"),
        ("requirements.txt", "Requirements"),
        ("main.py", "Punto de entrada"),
        ("run.py", "Script principal"),
        (".env.example", "Template de configuración")
    ]
    
    checks = []
    for file_path, description in required_files:
        path = Path(file_path)
        if path.exists():
            size = path.stat().st_size
            checks.append((description, True, f"{size} bytes"))
        else:
            checks.append((description, False, "Faltante"))
    
    return checks

def check_external_tools():
    """Verifica herramientas externas"""
    print_header("HERRAMIENTAS EXTERNAS")
    
    tools = [
        ("RsaCtfTool/RsaCtfTool.py", "RsaCtfTool"),
        ("git", "Git"),
        ("python", "Python executable")
    ]
    
    checks = []
    
    # RsaCtfTool
    rsactf_path = Path("RsaCtfTool/RsaCtfTool.py")
    if rsactf_path.exists():
        checks.append(("RsaCtfTool", True, "Presente"))
    else:
        checks.append(("RsaCtfTool", False, "No encontrado"))
    
    # Git
    try:
        import subprocess
        result = subprocess.run(["git", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            checks.append(("Git", True, version))
        else:
            checks.append(("Git", False, "No funcional"))
    except FileNotFoundError:
        checks.append(("Git", False, "No instalado"))
    
    # SageMath (opcional)
    try:
        result = subprocess.run(["sage", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            checks.append(("SageMath", True, "Disponible"))
        else:
            checks.append(("SageMath", False, "No funcional"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        checks.append(("SageMath", False, "No instalado (opcional)"))
    
    return checks

def check_configuration():
    """Verifica configuración"""
    print_header("CONFIGURACIÓN")
    
    checks = []
    
    # Archivo .env
    env_file = Path(".env")
    if env_file.exists():
        checks.append(("Archivo .env", True, "Presente"))
        
        # Verificar API key
        try:
            from dotenv import load_dotenv
            load_dotenv()
            
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key and api_key != "tu-api-key-aqui":
                if api_key.startswith("AIza"):
                    checks.append(("Google API Key", True, f"Configurada ({api_key[:10]}...)"))
                else:
                    checks.append(("Google API Key", False, "Formato inválido"))
            else:
                checks.append(("Google API Key", False, "No configurada"))
                
        except Exception as e:
            checks.append(("Google API Key", False, f"Error: {e}"))
    else:
        checks.append(("Archivo .env", False, "Faltante"))
        checks.append(("Google API Key", False, "No verificable"))
    
    # Configuración del sistema
    try:
        sys.path.insert(0, "src")
        from src.config.config import config
        
        validation_errors = config.validate()
        if not validation_errors:
            checks.append(("Configuración del sistema", True, "Válida"))
        else:
            checks.append(("Configuración del sistema", False, f"{len(validation_errors)} errores"))
            
    except Exception as e:
        checks.append(("Configuración del sistema", False, f"Error: {e}"))
    
    return checks

def check_examples():
    """Verifica ejemplos"""
    print_header("EJEMPLOS DE DESAFÍOS")
    
    examples_dir = Path("examples")
    checks = []
    
    if examples_dir.exists():
        example_dirs = [d for d in examples_dir.iterdir() if d.is_dir()]
        checks.append(("Directorio examples", True, f"{len(example_dirs)} ejemplos"))
        
        for example_dir in example_dirs:
            py_files = list(example_dir.glob("*.py"))
            if py_files:
                checks.append((f"Ejemplo {example_dir.name}", True, f"{len(py_files)} archivos"))
            else:
                checks.append((f"Ejemplo {example_dir.name}", False, "Sin archivos .py"))
    else:
        checks.append(("Directorio examples", False, "No existe"))
    
    return checks

def test_basic_functionality():
    """Prueba funcionalidad básica"""
    print_header("PRUEBAS FUNCIONALES")
    
    checks = []
    
    # Test 1: Importar agente
    try:
        sys.path.insert(0, "src")
        from src.core.agent import solve_ctf_challenge
        checks.append(("Importar agente", True, "OK"))
    except Exception as e:
        checks.append(("Importar agente", False, str(e)))
        return checks
    
    # Test 2: Importar herramientas
    try:
        from src.tools.tools import ALL_TOOLS
        checks.append(("Importar herramientas", True, f"{len(ALL_TOOLS)} tools"))
    except Exception as e:
        checks.append(("Importar herramientas", False, str(e)))
    
    # Test 3: Configuración
    try:
        from src.config.config import config
        checks.append(("Cargar configuración", True, "OK"))
    except Exception as e:
        checks.append(("Cargar configuración", False, str(e)))
    
    # Test 4: Crear agente (sin ejecutar)
    try:
        from src.core.agent import create_ctf_agent
        agent = create_ctf_agent()
        checks.append(("Crear agente", True, "OK"))
    except Exception as e:
        checks.append(("Crear agente", False, str(e)))
    
    return checks

def print_results(checks, title):
    """Imprime resultados de checks"""
    print(f"\n📋 {title}:")
    
    success_count = 0
    for name, success, details in checks:
        icon = "✅" if success else "❌"
        print(f"  {icon} {name}: {details}")
        if success:
            success_count += 1
    
    success_rate = success_count / len(checks) if checks else 0
    print(f"\n📊 Tasa de éxito: {success_rate:.1%} ({success_count}/{len(checks)})")
    
    return success_rate

def main():
    """Función principal"""
    print("""
🔐 CTF Crypto Agent - Validación de Setup
==========================================
Verificando instalación según Fase 1...
""")
    
    all_checks = []
    
    # Ejecutar todas las verificaciones
    checks = check_python_environment()
    rate = print_results(checks, "Entorno Python")
    all_checks.extend(checks)
    
    checks = check_dependencies()
    rate = print_results(checks, "Dependencias")
    all_checks.extend(checks)
    
    checks = check_file_structure()
    rate = print_results(checks, "Estructura de Archivos")
    all_checks.extend(checks)
    
    checks = check_external_tools()
    rate = print_results(checks, "Herramientas Externas")
    all_checks.extend(checks)
    
    checks = check_configuration()
    rate = print_results(checks, "Configuración")
    all_checks.extend(checks)
    
    checks = check_examples()
    rate = print_results(checks, "Ejemplos")
    all_checks.extend(checks)
    
    checks = test_basic_functionality()
    rate = print_results(checks, "Pruebas Funcionales")
    all_checks.extend(checks)
    
    # Resumen final
    print_header("RESUMEN FINAL")
    
    total_success = sum(1 for _, success, _ in all_checks if success)
    total_checks = len(all_checks)
    overall_rate = total_success / total_checks if total_checks > 0 else 0
    
    print(f"📊 Verificaciones totales: {total_checks}")
    print(f"✅ Exitosas: {total_success}")
    print(f"❌ Fallidas: {total_checks - total_success}")
    print(f"📈 Tasa de éxito general: {overall_rate:.1%}")
    
    if overall_rate >= 0.8:
        print(f"\n🎉 ¡Setup EXITOSO!")
        print("El sistema está listo para resolver desafíos CTF crypto.")
        print("\n🚀 Próximos pasos:")
        print("1. python main.py test     # Ejecutar pruebas")
        print("2. python main.py web      # Iniciar interfaz web")
        print("3. python main.py solve -d 'Test' -f examples/caesar_cipher/chall.py")
        return True
    elif overall_rate >= 0.6:
        print(f"\n⚠️  Setup PARCIAL")
        print("El sistema puede funcionar pero hay componentes faltantes.")
        print("Revisa los errores arriba y ejecuta setup_complete.py")
        return False
    else:
        print(f"\n❌ Setup FALLIDO")
        print("Hay demasiados componentes faltantes.")
        print("Ejecuta setup_complete.py para configurar todo automáticamente.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)