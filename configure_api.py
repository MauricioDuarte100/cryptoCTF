#!/usr/bin/env python3
"""
Script para configurar la API key de Gemini
"""

import os
from pathlib import Path

def configure_api_key():
    """Configura la API key interactivamente"""
    
    print("🔑 Configuración de API Key de Gemini")
    print("="*50)
    print()
    print("Para obtener tu API key GRATUITA:")
    print("1. Ve a: https://aistudio.google.com/apikey")
    print("2. Click en 'Create API Key'")
    print("3. Copia la key (empieza con 'AIza...')")
    print()
    
    # Verificar si ya existe .env
    env_file = Path(".env")
    if env_file.exists():
        print("✅ Archivo .env encontrado")
        
        # Leer contenido actual
        with open(env_file, 'r') as f:
            content = f.read()
        
        if "GOOGLE_API_KEY=" in content and "tu-api-key-aqui" not in content:
            print("✅ API key ya configurada")
            
            # Extraer la key para mostrar parcialmente
            for line in content.split('\n'):
                if line.startswith('GOOGLE_API_KEY=') and not line.endswith('tu-api-key-aqui'):
                    key = line.split('=', 1)[1]
                    if key and len(key) > 10:
                        print(f"   Key actual: {key[:10]}...{key[-4:]}")
                        break
            
            response = input("\n¿Quieres cambiar la API key? (y/N): ").lower()
            if response != 'y':
                return True
    else:
        print("❌ Archivo .env no encontrado")
        print("   Copiando desde .env.example...")
        
        if Path(".env.example").exists():
            import shutil
            shutil.copy(".env.example", ".env")
            print("✅ Archivo .env creado")
        else:
            # Crear .env básico
            with open(".env", 'w') as f:
                f.write("# CTF Crypto Agent - Configuración\n")
                f.write("# Obtén tu API key gratis en: https://aistudio.google.com/apikey\n")
                f.write("GOOGLE_API_KEY=tu-api-key-aqui\n")
                f.write("\n# Configuración básica\n")
                f.write("GEMINI_MODEL=gemini-2.5-flash\n")
                f.write("MAX_ITERATIONS=15\n")
                f.write("WEB_PORT=5000\n")
            print("✅ Archivo .env básico creado")
    
    # Solicitar API key
    print()
    api_key = input("Pega tu API key de Gemini aquí: ").strip()
    
    if not api_key:
        print("❌ No se proporcionó API key")
        return False
    
    if not api_key.startswith("AIza"):
        print("⚠️  La API key debería empezar con 'AIza'")
        response = input("¿Continuar de todos modos? (y/N): ").lower()
        if response != 'y':
            return False
    
    if len(api_key) < 30:
        print("⚠️  La API key parece muy corta")
        response = input("¿Continuar de todos modos? (y/N): ").lower()
        if response != 'y':
            return False
    
    # Actualizar archivo .env
    try:
        with open(".env", 'r') as f:
            content = f.read()
        
        # Reemplazar la línea de API key
        lines = content.split('\n')
        updated = False
        
        for i, line in enumerate(lines):
            if line.startswith('GOOGLE_API_KEY='):
                lines[i] = f'GOOGLE_API_KEY={api_key}'
                updated = True
                break
        
        if not updated:
            lines.append(f'GOOGLE_API_KEY={api_key}')
        
        # Escribir archivo actualizado
        with open(".env", 'w') as f:
            f.write('\n'.join(lines))
        
        print("✅ API key configurada exitosamente")
        print(f"   Key: {api_key[:10]}...{api_key[-4:]}")
        return True
        
    except Exception as e:
        print(f"❌ Error configurando API key: {e}")
        return False

def main():
    """Función principal"""
    success = configure_api_key()
    
    if success:
        print("\n🎉 ¡Configuración completada!")
        print("\n🚀 Próximos pasos:")
        print("1. python quick_test.py          # Probar sistema")
        print("2. python main.py test           # Ejecutar pruebas")
        print("3. python main.py web            # Interfaz web")
        print("4. Subir a GitHub con tus comandos")
    else:
        print("\n💥 Configuración fallida")
        print("Revisa los errores arriba e intenta de nuevo")
    
    return success

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)