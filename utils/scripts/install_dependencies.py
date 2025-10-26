#!/usr/bin/env python3
"""
Script para instalar dependencias adicionales del sistema
"""

import os
import sys
import subprocess
import platform

def run_command(cmd, description="", ignore_errors=False):
    """Ejecuta comando y maneja errores"""
    print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Completado")
        return True
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            print(f"⚠️  {description} - Falló (ignorado): {e.stderr}")
            return False
        else:
            print(f"❌ Error en {description}: {e.stderr}")
            return False

def install_system_dependencies():
    """Instala dependencias del sistema según la plataforma"""
    system = platform.system().lower()
    
    print(f"🖥️  Sistema detectado: {system}")
    
    if system == "linux":
        # Ubuntu/Debian
        if os.path.exists("/etc/debian_version"):
            print("📦 Instalando dependencias para Ubuntu/Debian...")
            commands = [
                ("sudo apt update", "Actualizar repositorios"),
                ("sudo apt install -y python3-dev python3-pip", "Instalar Python dev"),
                ("sudo apt install -y libgmp-dev libmpfr-dev libmpc-dev", "Instalar librerías matemáticas"),
                ("sudo apt install -y git build-essential", "Instalar herramientas de desarrollo"),
                ("sudo apt install -y sagemath", "Instalar SageMath (opcional)", True)
            ]
        
        # CentOS/RHEL/Fedora
        elif os.path.exists("/etc/redhat-release"):
            print("📦 Instalando dependencias para CentOS/RHEL/Fedora...")
            commands = [
                ("sudo yum update -y", "Actualizar repositorios"),
                ("sudo yum install -y python3-devel python3-pip", "Instalar Python dev"),
                ("sudo yum install -y gmp-devel mpfr-devel libmpc-devel", "Instalar librerías matemáticas"),
                ("sudo yum install -y git gcc gcc-c++ make", "Instalar herramientas de desarrollo"),
                ("sudo yum install -y sagemath", "Instalar SageMath (opcional)", True)
            ]
        
        else:
            print("⚠️  Distribución Linux no reconocida")
            return False
    
    elif system == "darwin":  # macOS
        print("📦 Instalando dependencias para macOS...")
        commands = [
            ("brew --version", "Verificar Homebrew"),
            ("brew install gmp mpfr libmpc", "Instalar librerías matemáticas"),
            ("brew install git", "Instalar Git"),
            ("brew install --cask sage", "Instalar SageMath (opcional)", True)
        ]
    
    elif system == "windows":
        print("📦 Windows detectado")
        print("⚠️  Instala manualmente:")
        print("   1. Git: https://git-scm.com/download/win")
        print("   2. Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/")
        print("   3. SageMath (opcional): https://www.sagemath.org/download-windows.html")
        return True
    
    else:
        print(f"❌ Sistema no soportado: {system}")
        return False
    
    # Ejecutar comandos
    success = True
    for cmd_info in commands:
        cmd = cmd_info[0]
        desc = cmd_info[1]
        ignore = len(cmd_info) > 2 and cmd_info[2]
        
        if not run_command(cmd, desc, ignore):
            if not ignore:
                success = False
    
    return success

def install_python_tools():
    """Instala herramientas Python adicionales"""
    print("\n🐍 Instalando herramientas Python adicionales...")
    
    tools = [
        ("pip install --upgrade pip setuptools wheel", "Actualizar pip y herramientas"),
        ("pip install gmpy2", "Instalar gmpy2 para matemáticas rápidas"),
        ("pip install sympy", "Instalar SymPy para matemáticas simbólicas"),
        ("pip install z3-solver", "Instalar Z3 solver (opcional)", True),
        ("pip install pwntools", "Instalar pwntools para CTF"),
    ]
    
    success = True
    for tool_info in tools:
        cmd = tool_info[0]
        desc = tool_info[1]
        ignore = len(tool_info) > 2 and tool_info[2]
        
        if not run_command(cmd, desc, ignore):
            if not ignore:
                success = False
    
    return success

def clone_additional_tools():
    """Clona herramientas adicionales útiles"""
    print("\n🛠️  Clonando herramientas adicionales...")
    
    tools = [
        {
            "url": "https://github.com/RsaCtfTool/RsaCtfTool.git",
            "name": "RsaCtfTool",
            "desc": "Herramienta principal para ataques RSA"
        },
        {
            "url": "https://github.com/Ganapati/RsaCtfTool.git",
            "name": "RsaCtfTool-Ganapati",
            "desc": "Fork alternativo de RsaCtfTool",
            "optional": True
        },
        {
            "url": "https://github.com/hellman/xortool.git",
            "name": "xortool",
            "desc": "Herramienta para análisis XOR",
            "optional": True
        }
    ]
    
    for tool in tools:
        if os.path.exists(tool["name"]):
            print(f"⏭️  {tool['name']} ya existe, saltando...")
            continue
        
        cmd = f"git clone {tool['url']} {tool['name']}"
        success = run_command(cmd, f"Clonar {tool['desc']}", tool.get("optional", False))
        
        # Instalar dependencias si existe requirements.txt
        req_file = os.path.join(tool["name"], "requirements.txt")
        if success and os.path.exists(req_file):
            install_cmd = f"pip install -r {req_file}"
            run_command(install_cmd, f"Instalar deps de {tool['name']}", True)

def verify_installation():
    """Verifica que todo esté instalado correctamente"""
    print("\n🔍 Verificando instalación...")
    
    checks = [
        ("python --version", "Python"),
        ("pip --version", "pip"),
        ("git --version", "Git"),
        ("python -c 'import gmpy2; print(gmpy2.version())'", "gmpy2"),
        ("python -c 'import pwntools; print(\"pwntools OK\")'", "pwntools"),
        ("sage --version", "SageMath (opcional)", True),
        ("ls RsaCtfTool/RsaCtfTool.py", "RsaCtfTool")
    ]
    
    success_count = 0
    for check_info in checks:
        cmd = check_info[0]
        name = check_info[1]
        optional = len(check_info) > 2 and check_info[2]
        
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            print(f"✅ {name}")
            success_count += 1
        except subprocess.CalledProcessError:
            if optional:
                print(f"⚠️  {name} (opcional)")
            else:
                print(f"❌ {name}")
    
    required_checks = len([c for c in checks if len(c) <= 2 or not c[2]])
    
    if success_count >= required_checks:
        print(f"\n🎉 Instalación completada exitosamente!")
        print(f"✅ {success_count}/{len(checks)} componentes verificados")
        return True
    else:
        print(f"\n⚠️  Instalación parcial")
        print(f"⚠️  {success_count}/{len(checks)} componentes verificados")
        return False

def main():
    """Función principal"""
    print("🚀 Instalador de dependencias - CTF Crypto Agent")
    print("=" * 60)
    
    # Verificar permisos
    if os.name != 'nt' and os.geteuid() == 0:
        print("⚠️  No ejecutes como root (usa sudo cuando sea necesario)")
        return False
    
    success = True
    
    # 1. Dependencias del sistema
    if not install_system_dependencies():
        print("⚠️  Algunas dependencias del sistema fallaron")
        success = False
    
    # 2. Herramientas Python
    if not install_python_tools():
        print("⚠️  Algunas herramientas Python fallaron")
        success = False
    
    # 3. Herramientas adicionales
    clone_additional_tools()
    
    # 4. Verificación
    if not verify_installation():
        success = False
    
    if success:
        print("\n🎯 Próximos pasos:")
        print("1. Configura tu API key: echo 'GOOGLE_API_KEY=tu-key' > .env")
        print("2. Prueba el agente: python test_agent.py")
        print("3. Inicia la web UI: python web_interface.py")
        return True
    else:
        print("\n💥 Instalación incompleta")
        print("Revisa los errores arriba y ejecuta manualmente los comandos fallidos")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)