#!/usr/bin/env python3
"""
Script principal para ejecutar benchmarks del CTF Crypto Agent
Punto de entrada para medir el rendimiento del agente
"""

import sys
import os
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Función principal del benchmark"""
    
    print("🚀 CTF Crypto Agent - Sistema de Benchmark")
    print("="*60)
    print("Midiendo rendimiento del agente contra desafíos conocidos...")
    print()
    
    try:
        # Verificar configuración
        from src.config.config import config
        
        if not config.GOOGLE_API_KEY or config.GOOGLE_API_KEY == "tu-api-key-aqui":
            print("❌ Error: GOOGLE_API_KEY no configurada")
            print("   Configura tu API key en .env antes de ejecutar el benchmark")
            print("   Ejecuta: python configure_api.py")
            return 1
        
        # Importar y ejecutar benchmark
        from src.benchmark.benchmark import run_benchmark_cli
        
        print("🔑 API Key configurada correctamente")
        print("📊 Iniciando benchmark...\n")
        
        # Ejecutar benchmark
        report = run_benchmark_cli()
        
        if report and report.get('success_rate', 0) > 0:
            print(f"\n🎉 Benchmark completado exitosamente!")
            print(f"📈 Tasa de éxito: {report['success_rate']:.1%}")
            return 0
        else:
            print(f"\n⚠️  Benchmark completado con resultados mixtos")
            return 0
            
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        print("   Asegúrate de que todas las dependencias estén instaladas")
        print("   Ejecuta: pip install -r requirements.txt")
        return 1
    
    except Exception as e:
        print(f"💥 Error ejecutando benchmark: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())