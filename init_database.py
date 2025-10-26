#!/usr/bin/env python3
"""
Script para inicializar la base de datos del CTF Crypto Agent
"""

import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Inicializa la base de datos"""
    
    print("🗄️  Inicializando Base de Datos CTF Crypto Agent")
    print("="*50)
    
    try:
        from src.database.database import CTFDatabase
        
        # Crear base de datos
        db = CTFDatabase()
        
        print("✅ Base de datos creada exitosamente")
        print(f"📁 Ubicación: {db.db_path}")
        
        # Mostrar estadísticas iniciales
        stats = db.get_overall_stats()
        print(f"📊 Estadísticas iniciales:")
        print(f"   - Desafíos: {stats['total_challenges']}")
        print(f"   - Intentos: {stats['total_attempts']}")
        print(f"   - Tasa de éxito: {stats['overall_success_rate']:.1%}")
        
        # Crear algunos datos de ejemplo si la DB está vacía
        if stats['total_challenges'] == 0:
            print("\n📝 Creando datos de ejemplo...")
            
            # Ejemplo 1: RSA
            challenge_id = db.log_challenge(
                name="Example RSA Challenge",
                description="RSA with small e for testing",
                challenge_type="RSA",
                difficulty="Easy",
                source="Example",
                expected_flag="flag{example_rsa}"
            )
            
            db.log_attempt(
                challenge_id=challenge_id,
                success=True,
                flag_found="flag{example_rsa}",
                confidence=0.95,
                steps_used=3,
                total_time=2.1,
                solution_steps=["analyze_files", "classify_crypto", "attack_rsa"]
            )
            
            # Ejemplo 2: Caesar
            challenge_id = db.log_challenge(
                name="Example Caesar Cipher",
                description="Simple ROT13 cipher",
                challenge_type="Classical",
                difficulty="Easy",
                source="Example",
                expected_flag="flag{example_caesar}"
            )
            
            db.log_attempt(
                challenge_id=challenge_id,
                success=True,
                flag_found="flag{example_caesar}",
                confidence=0.88,
                steps_used=2,
                total_time=1.3,
                solution_steps=["analyze_files", "attack_classical"]
            )
            
            print("✅ Datos de ejemplo creados")
            
            # Mostrar estadísticas actualizadas
            stats = db.get_overall_stats()
            print(f"📊 Estadísticas actualizadas:")
            print(f"   - Desafíos: {stats['total_challenges']}")
            print(f"   - Intentos: {stats['total_attempts']}")
            print(f"   - Tasa de éxito: {stats['overall_success_rate']:.1%}")
        
        print(f"\n🎯 Base de datos lista para usar")
        print(f"💡 Ejecuta 'python benchmark.py' para empezar a recopilar datos reales")
        
        return True
        
    except Exception as e:
        print(f"❌ Error inicializando base de datos: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)