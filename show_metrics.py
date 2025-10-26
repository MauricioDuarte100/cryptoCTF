#!/usr/bin/env python3
"""
Script para mostrar métricas de la base de datos
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Muestra métricas de la base de datos"""
    
    print("📊 Métricas del CTF Crypto Agent")
    print("="*50)
    
    try:
        from src.database.database import get_database
        
        db = get_database()
        stats = db.get_overall_stats()
        
        print(f"🎯 Estadísticas Generales:")
        print(f"   Total de desafíos: {stats['total_challenges']}")
        print(f"   Total de intentos: {stats['total_attempts']}")
        print(f"   Intentos exitosos: {stats['successful_attempts']}")
        print(f"   Tasa de éxito: {stats['overall_success_rate']:.1%}")
        print(f"   Tiempo promedio: {stats['avg_time']:.2f}s")
        print(f"   Pasos promedio: {stats['avg_steps']:.1f}")
        
        print(f"\n📈 Por Tipo de Crypto:")
        for type_stats in stats['by_type']:
            print(f"   {type_stats['type']}:")
            print(f"      Intentos: {type_stats['attempts']}")
            print(f"      Éxitos: {type_stats['successes']}")
            print(f"      Tasa: {type_stats['success_rate']:.1%}")
        
        print(f"\n🔧 Herramientas Más Usadas:")
        for tool_stats in stats['top_tools'][:5]:
            print(f"   {tool_stats['tool']}: {tool_stats['usage']} usos ({tool_stats['success_rate']:.1%} éxito)")
        
        # Mostrar datos de entrenamiento disponibles
        training_data = db.export_training_data(min_attempts=1)
        print(f"\n🤖 Datos para ML:")
        print(f"   Registros disponibles: {len(training_data)}")
        print(f"   Listos para Fase 2.2: {'✅' if len(training_data) >= 10 else '❌'}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)