#!/usr/bin/env python3
"""
Setup script para CTF Crypto Agent con Gemini
Instala dependencias y configura herramientas
"""

import os
import subprocess
import sys
from pathlib import Path

def run_command(cmd, description=""):
    """Ejecuta comando y maneja errores"""
    print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Completado")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error en {description}: {e.stderr}")
        return False

def main():
    print("🚀 Configurando CTF Crypto Agent con Gemini 2.5 Flash")
    print("="*60)
    
    # 1. Verificar Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requerido")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detectado")
    
    # 2. Crear entorno virtual
    if not os.path.exists("venv"):
        print("📦 Creando entorno virtual...")
        run_command("python -m venv venv", "Crear venv")
    
    # 3. Activar venv y instalar dependencias
    if os.name == 'nt':  # Windows
        pip_cmd = "venv\\Scripts\\pip"
        python_cmd = "venv\\Scripts\\python"
    else:  # Linux/Mac
        pip_cmd = "venv/bin/pip"
        python_cmd = "venv/bin/python"
    
    print("📚 Instalando dependencias Python...")
    run_command(f"{pip_cmd} install --upgrade pip", "Actualizar pip")
    run_command(f"{pip_cmd} install -r requirements.txt", "Instalar requirements")
    
    # 4. Clonar RsaCtfTool
    if not os.path.exists("RsaCtfTool"):
        print("🔐 Descargando RsaCtfTool...")
        run_command(
            "git clone https://github.com/RsaCtfTool/RsaCtfTool.git",
            "Clonar RsaCtfTool"
        )
        
        # Instalar dependencias de RsaCtfTool
        if os.path.exists("RsaCtfTool"):
            run_command(
                f"{pip_cmd} install -r RsaCtfTool/requirements.txt",
                "Instalar deps RsaCtfTool"
            )
    
    # 5. Crear archivo .env template
    if not os.path.exists(".env"):
        print("🔑 Creando template .env...")
        with open(".env", "w") as f:
            f.write("# Obtén tu API key gratis en: https://aistudio.google.com/apikey\n")
            f.write("GOOGLE_API_KEY=tu-api-key-aqui\n")
        print("📝 Edita .env con tu API key de Gemini")
    
    # 6. Crear directorio de ejemplos
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # 7. Verificar instalación opcional de SageMath
    try:
        subprocess.run(["sage", "--version"], capture_output=True, check=True)
        print("✅ SageMath detectado")
    except:
        print("⚠️  SageMath no encontrado (opcional para lattice attacks)")
        print("   Instalar con: sudo apt install sagemath")
    
    print("\n🎉 Setup completado!")
    print("\n📋 Próximos pasos:")
    print("1. Edita .env con tu API key de Gemini")
    print("2. Activa el entorno: source venv/bin/activate (Linux/Mac) o venv\\Scripts\\activate (Windows)")
    print("3. Prueba con: python agent.py --description 'Test challenge'")
    print("\n🔗 Obtén API key gratis: https://aistudio.google.com/apikey")

if __name__ == "__main__":
    main()