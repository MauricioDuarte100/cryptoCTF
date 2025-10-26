#!/usr/bin/env python3
"""
Setup completo para CTF Crypto Agent según Fase 1
Configuración automática con Gemini 2.5 Flash
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Muestra banner del setup"""
    print("""
🔐 CTF Crypto Agent - Setup Completo
=====================================
Powered by Gemini 2.5 Flash (100% GRATIS)
Especializado en resolver desafíos CTF crypto

Características:
✅ Gemini 2.5 Flash (1500 requests/día GRATIS)
✅ 13+ herramientas especializadas
✅ Interfaz web moderna
✅ Sistema de métricas y optimización
✅ Soporte para RSA, cifrados clásicos, XOR, etc.
""")

def check_python_version():
    """Verifica versión de Python"""
    print("🐍 Verificando Python...")
    
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requerido")
        print(f"   Versión actual: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} OK")
    return True

def create_virtual_environment():
    """Crea entorno virtual"""
    print("\n📦 Configurando entorno virtual...")
    
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("⏭️  Entorno virtual ya existe")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✅ Entorno virtual creado")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error creando entorno virtual: {e}")
        return False

def get_pip_command():
    """Obtiene comando pip según la plataforma"""
    if platform.system() == "Windows":
        return "venv\\Scripts\\pip"
    else:
        return "venv/bin/pip"

def install_dependencies():
    """Instala dependencias Python"""
    print("\n📚 Instalando dependencias...")
    
    pip_cmd = get_pip_command()
    
    # Actualizar pip
    try:
        subprocess.run([pip_cmd, "install", "--upgrade", "pip"], check=True)
        print("✅ pip actualizado")
    except subprocess.CalledProcessError:
        print("⚠️  Error actualizando pip (continuando...)")
    
    # Instalar requirements
    try:
        subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
        print("✅ Dependencias instaladas")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error instalando dependencias: {e}")
        return False

def clone_rsactftool():
    """Clona RsaCtfTool"""
    print("\n🔐 Configurando RsaCtfTool...")
    
    rsactf_path = Path("RsaCtfTool")
    
    if rsactf_path.exists():
        print("⏭️  RsaCtfTool ya existe")
        return True
    
    try:
        subprocess.run([
            "git", "clone", 
            "https://github.com/RsaCtfTool/RsaCtfTool.git"
        ], check=True)
        print("✅ RsaCtfTool clonado")
        
        # Instalar dependencias de RsaCtfTool
        pip_cmd = get_pip_command()
        req_file = rsactf_path / "requirements.txt"
        
        if req_file.exists():
            try:
                subprocess.run([pip_cmd, "install", "-r", str(req_file)], check=True)
                print("✅ Dependencias de RsaCtfTool instaladas")
            except subprocess.CalledProcessError:
                print("⚠️  Error instalando deps de RsaCtfTool (continuando...)")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error clonando RsaCtfTool: {e}")
        return False

def setup_environment_file():
    """Configura archivo .env"""
    print("\n🔑 Configurando archivo de entorno...")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("⏭️  Archivo .env ya existe")
        return True
    
    if env_example.exists():
        try:
            # Copiar .env.example a .env
            with open(env_example, 'r') as src, open(env_file, 'w') as dst:
                content = src.read()
                dst.write(content)
            
            print("✅ Archivo .env creado desde template")
            print("📝 IMPORTANTE: Edita .env y añade tu GOOGLE_API_KEY")
            return True
            
        except Exception as e:
            print(f"❌ Error creando .env: {e}")
            return False
    else:
        # Crear .env básico
        try:
            with open(env_file, 'w') as f:
                f.write("# CTF Crypto Agent - Configuración\n")
                f.write("# Obtén tu API key gratis en: https://aistudio.google.com/apikey\n")
                f.write("GOOGLE_API_KEY=tu-api-key-aqui\n")
                f.write("\n# Configuración básica\n")
                f.write("GEMINI_MODEL=gemini-2.5-flash\n")
                f.write("MAX_ITERATIONS=15\n")
                f.write("WEB_PORT=5000\n")
            
            print("✅ Archivo .env básico creado")
            print("📝 IMPORTANTE: Edita .env y añade tu GOOGLE_API_KEY")
            return True
            
        except Exception as e:
            print(f"❌ Error creando .env: {e}")
            return False

def create_directories():
    """Crea directorios necesarios"""
    print("\n📁 Creando directorios...")
    
    directories = [
        "logs",
        "cache",
        "outputs",
        "temp"
    ]
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        dir_path.mkdir(exist_ok=True)
    
    print("✅ Directorios creados")
    return True

def verify_installation():
    """Verifica la instalación"""
    print("\n🔍 Verificando instalación...")
    
    checks = []
    
    # Verificar Python
    try:
        import sys
        checks.append(("Python", True, f"{sys.version_info.major}.{sys.version_info.minor}"))
    except:
        checks.append(("Python", False, "No disponible"))
    
    # Verificar dependencias principales
    deps_to_check = [
        ("langgraph", "LangGraph"),
        ("langchain_google_genai", "Gemini AI"),
        ("pwntools", "Pwntools"),
        ("flask", "Flask"),
        ("dotenv", "Python-dotenv")
    ]
    
    for module, name in deps_to_check:
        try:
            __import__(module)
            checks.append((name, True, "Instalado"))
        except ImportError:
            checks.append((name, False, "No instalado"))
    
    # Verificar archivos
    files_to_check = [
        (".env", "Configuración"),
        ("RsaCtfTool/RsaCtfTool.py", "RsaCtfTool"),
        ("src/core/agent.py", "Agente principal"),
        ("requirements.txt", "Requirements")
    ]
    
    for file_path, name in files_to_check:
        if Path(file_path).exists():
            checks.append((name, True, "Presente"))
        else:
            checks.append((name, False, "Faltante"))
    
    # Mostrar resultados
    success_count = 0
    for name, success, status in checks:
        icon = "✅" if success else "❌"
        print(f"  {icon} {name}: {status}")
        if success:
            success_count += 1
    
    success_rate = success_count / len(checks)
    
    if success_rate >= 0.8:
        print(f"\n🎉 Instalación exitosa! ({success_count}/{len(checks)} componentes)")
        return True
    else:
        print(f"\n⚠️  Instalación incompleta ({success_count}/{len(checks)} componentes)")
        return False

def show_next_steps():
    """Muestra próximos pasos"""
    print("""
🎯 PRÓXIMOS PASOS:
==================

1. 🔑 Configurar API Key:
   - Ve a: https://aistudio.google.com/apikey
   - Crea una nueva API key (GRATIS)
   - Edita .env y reemplaza 'tu-api-key-aqui' con tu key

2. 🧪 Probar el sistema:
   python main.py test

3. 🌐 Iniciar interfaz web:
   python main.py web

4. 🚀 Resolver un desafío:
   python main.py solve -d "RSA challenge" -f examples/rsa_basic/chall.py

5. 📊 Ver métricas:
   python main.py config --summary

📚 Documentación completa en README.md
🐛 Reportar issues en GitHub
💡 Contribuir con nuevas herramientas

¡Happy Hacking! 🔓
""")

def main():
    """Función principal del setup"""
    print_banner()
    
    success = True
    
    # 1. Verificar Python
    if not check_python_version():
        return False
    
    # 2. Crear entorno virtual
    if not create_virtual_environment():
        success = False
    
    # 3. Instalar dependencias
    if not install_dependencies():
        success = False
    
    # 4. Clonar RsaCtfTool
    if not clone_rsactftool():
        success = False
    
    # 5. Configurar .env
    if not setup_environment_file():
        success = False
    
    # 6. Crear directorios
    if not create_directories():
        success = False
    
    # 7. Verificar instalación
    if not verify_installation():
        success = False
    
    # 8. Mostrar próximos pasos
    if success:
        show_next_steps()
        print("\n🎉 Setup completado exitosamente!")
        return True
    else:
        print("\n💥 Setup incompleto. Revisa los errores arriba.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)