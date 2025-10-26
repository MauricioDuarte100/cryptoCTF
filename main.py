#!/usr/bin/env python3
"""
CTF Crypto Agent - Punto de entrada principal
Gemini 2.5 Flash AI - 100% Gratuito
"""

import sys
import os
from pathlib import Path

# Añadir el directorio src al path para imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Punto de entrada principal"""
    
    # Verificar configuración básica
    try:
        from src.config.config import config
        
        # Validar configuración
        errors = config.validate()
        if errors:
            print("⚠️  Errores de configuración:")
            for error in errors:
                print(f"   - {error}")
            
            if any("GOOGLE_API_KEY" in str(error) for error in errors):
                print("\n🔑 Para configurar tu API key:")
                print("1. Copia .env.example a .env")
                print("2. Edita .env y añade tu API key de Gemini")
                print("3. Obtén una gratis en: https://aistudio.google.com/apikey")
                return 1
    
    except ImportError as e:
        print(f"❌ Error importando configuración: {e}")
        return 1
    
    # Importar y ejecutar run.py
    try:
        from run import main as run_main
        return run_main()
    except ImportError as e:
        print(f"❌ Error importando run: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())