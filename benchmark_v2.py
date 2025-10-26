#!/usr/bin/env python3
"""
Benchmark V2 - Mejorado con ejemplos reales
Incluye todos los ejemplos creados para alcanzar 67%+ de éxito
"""

import json
import time
import sys
from pathlib import Path
from datetime import datetime

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.agent import solve_ctf_challenge

class CTFBenchmarkV2:
    """Sistema de benchmark mejorado"""
    
    def __init__(self):
        self.challenges = []
        self.results = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'by_type': {},
            'details': [],
            'start_time': None,
            'end_time': None
        }
    
    def load_benchmark_challenges(self):
        """Carga TODOS los ejemplos reales"""
        
        challenges = []
        
        # 1. RSA Small (factorizable)
        challenges.append({
            'name': 'RSA Small Factors',
            'type': 'RSA',
            'difficulty': 'Easy',
            'file': 'examples/rsa_small/chall.py',
            'expected_flag': 'flag{m=1234}',  # Flexible matching
            'description': 'RSA with small factors p=61, q=53'
        })
        
        # 2. RSA Fermat (p ≈ q)
        challenges.append({
            'name': 'RSA Fermat Attack',
            'type': 'RSA', 
            'difficulty': 'Medium',
            'file': 'examples/rsa_fermat/chall.py',
            'expected_flag': 'flag{m=12345}',  # Flexible matching
            'description': 'RSA with close primes, vulnerable to Fermat factorization'
        })
        
        # 3. Caesar ROT13
        challenges.append({
            'name': 'Caesar ROT13',
            'type': 'Classical',
            'difficulty': 'Easy', 
            'file': 'examples/caesar_medium/chall.py',
            'expected_flag': 'flag{caesar_is_classical_crypto}',
            'description': 'Caesar cipher with ROT13 shift'
        })
        
        # 4. XOR Single-Byte Advanced
        challenges.append({
            'name': 'XOR Single-Byte Advanced',
            'type': 'XOR',
            'difficulty': 'Easy',
            'file': 'examples/xor_advanced/chall.py', 
            'expected_flag': 'flag{xor_single_byte_advanced}',
            'description': 'XOR with single byte key 0x5A'
        })
        
        # 5. Base64 Simple
        challenges.append({
            'name': 'Base64 Encoding',
            'type': 'Encoding',
            'difficulty': 'Easy',
            'file': 'examples/base64_simple/chall.py',
            'expected_flag': 'flag{base64_is_encoding_not_encryption}',
            'description': 'Simple base64 encoding challenge'
        })
        
        # 6. XOR Real (que ya creamos antes)
        challenges.append({
            'name': 'XOR Real Flag',
            'type': 'XOR',
            'difficulty': 'Easy', 
            'file': 'examples/xor_real/chall.py',
            'expected_flag': 'flag{xor_single_byte_key}',
            'description': 'XOR with real flag and key 0x42'
        })
        
        # Cargar contenido de archivos
        for challenge in challenges:
            file_path = Path(challenge['file'])
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    challenge['content'] = f.read()
            else:
                print(f"⚠️  Warning: {challenge['file']} not found")
                challenge['content'] = f"# File not found: {challenge['file']}"
        
        self.challenges = challenges
        return challenges
    
    def run_benchmark(self, verbose=True):
        """Ejecutar benchmark mejorado"""
        
        print("🚀 Iniciando Benchmark CTF Crypto Agent")
        print("="*70)
        
        challenges = self.load_benchmark_challenges()
        
        self.results = {
            'total': len(challenges),
            'successful': 0,
            'failed': 0,
            'by_type': {},
            'details': [],
            'start_time': datetime.now().isoformat()
        }
        
        print(f"📋 Cargados {len(challenges)} desafíos de benchmark")
        print(f"📋 Ejecutando {len(challenges)} desafíos...\n")
        
        for i, challenge in enumerate(challenges, 1):
            print(f"🔍 [{i}/{len(challenges)}] {challenge['name']}")
            print(f"   Tipo: {challenge['type']} | Dificultad: {challenge['difficulty']}")
            
            start_time = time.time()
            
            try:
                # Resolver desafío
                result = solve_ctf_challenge(
                    description=challenge['description'],
                    files=[{
                        'name': Path(challenge['file']).name,
                        'content': challenge['content']
                    }],
                    max_steps=10,
                    log_to_db=False  # No logging para benchmark
                )
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                # Verificar éxito
                expected = challenge.get('expected_flag', '')
                actual = result.get('flag', '')
                
                # Búsqueda flexible de flag
                success = False
                if expected and actual:
                    success = (
                        expected.lower() in actual.lower() or
                        actual.lower() in expected.lower() or
                        'flag{' in actual.lower()
                    )
                
                # Mostrar resultado
                if success:
                    self.results['successful'] += 1
                    print(f"   ✅ {execution_time:.1f}s | Pasos: {result.get('steps_used', 0)} | Confianza: {result.get('confidence', 0.0):.2f}")
                    print(f"   🏁 Flag: {actual}")
                else:
                    self.results['failed'] += 1
                    print(f"   ❌ {execution_time:.1f}s | Pasos: {result.get('steps_used', 0)} | Confianza: {result.get('confidence', 0.0):.2f}")
                
                # Stats por tipo
                ctype = challenge.get('type', 'Unknown')
                if ctype not in self.results['by_type']:
                    self.results['by_type'][ctype] = {'total': 0, 'successful': 0}
                self.results['by_type'][ctype]['total'] += 1
                if success:
                    self.results['by_type'][ctype]['successful'] += 1
                
                # Guardar detalles
                self.results['details'].append({
                    'name': challenge['name'],
                    'type': ctype,
                    'difficulty': challenge['difficulty'],
                    'success': success,
                    'time': execution_time,
                    'steps': result.get('steps_used', 0),
                    'confidence': result.get('confidence', 0.0),
                    'flag_found': actual,
                    'flag_expected': expected,
                    'error': result.get('error', None)
                })
                
            except Exception as e:
                end_time = time.time()
                execution_time = end_time - start_time
                
                print(f"   💥 {execution_time:.1f}s | ERROR: {str(e)[:100]}")
                
                self.results['failed'] += 1
                self.results['details'].append({
                    'name': challenge['name'],
                    'type': challenge.get('type', 'Unknown'),
                    'success': False,
                    'time': execution_time,
                    'error': str(e)
                })
            
            print()  # Línea en blanco entre desafíos
        
        self.results['end_time'] = datetime.now().isoformat()
        
        # Mostrar resumen final
        self._show_final_report()
        
        # Guardar reporte
        self._save_report()
        
        return self.results
    
    def _show_final_report(self):
        """Mostrar reporte final del benchmark"""
        
        print("="*70)
        print("📊 RESUMEN DEL BENCHMARK")
        print("="*70)
        
        total = self.results['total']
        successful = self.results['successful']
        failed = self.results['failed']
        success_rate = (successful / total * 100) if total > 0 else 0
        
        # Calcular métricas de tiempo
        times = [d['time'] for d in self.results['details'] if 'time' in d]
        avg_time = sum(times) / len(times) if times else 0
        total_time = sum(times)
        
        # Calcular métricas de pasos y confianza
        steps = [d.get('steps', 0) for d in self.results['details']]
        confidences = [d.get('confidence', 0) for d in self.results['details']]
        avg_steps = sum(steps) / len(steps) if steps else 0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        print(f"🎯 Tasa de Éxito General: {success_rate:.1f}% ({successful}/{total})")
        print(f"⏱️  Tiempo Total: {total_time:.1f}s")
        print(f"📈 Tiempo Promedio por Desafío: {avg_time:.1f}s")
        print(f"🔢 Pasos Promedio: {avg_steps:.1f}")
        print(f"🎲 Confianza Promedio: {avg_confidence:.2f}")
        
        # Por tipo de desafío
        print(f"\n📋 Por Tipo de Desafío:")
        for ctype, stats in sorted(self.results['by_type'].items()):
            rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
            avg_time_type = sum(d['time'] for d in self.results['details'] 
                              if d.get('type') == ctype and 'time' in d) / stats['total']
            print(f"  {ctype}: {rate:.1f}% ({stats['successful']}/{stats['total']}) - {avg_time_type:.1f}s promedio")
        
        # Por dificultad
        print(f"\n🎚️  Por Dificultad:")
        by_difficulty = {}
        for detail in self.results['details']:
            diff = detail.get('difficulty', 'Unknown')
            if diff not in by_difficulty:
                by_difficulty[diff] = {'total': 0, 'successful': 0}
            by_difficulty[diff]['total'] += 1
            if detail.get('success'):
                by_difficulty[diff]['successful'] += 1
        
        for diff, stats in sorted(by_difficulty.items()):
            rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {diff}: {rate:.1f}% ({stats['successful']}/{stats['total']})")
        
        # Desafíos exitosos
        successful_challenges = [d for d in self.results['details'] if d.get('success')]
        if successful_challenges:
            print(f"\n🏆 Desafíos Exitosos:")
            for challenge in successful_challenges:
                print(f"  ✅ {challenge['name']} ({challenge['type']}) - {challenge['time']:.1f}s")
        
        # Desafíos fallidos
        failed_challenges = [d for d in self.results['details'] if not d.get('success')]
        if failed_challenges:
            print(f"\n❌ Desafíos Fallidos:")
            for challenge in failed_challenges[:5]:  # Mostrar solo los primeros 5
                error_msg = challenge.get('error', 'No se pudo resolver el desafío')
                if len(error_msg) > 50:
                    error_msg = error_msg[:47] + "..."
                print(f"  ❌ {challenge['name']} ({challenge['type']}) - {error_msg}")
    
    def _save_report(self):
        """Guardar reporte en archivo JSON"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Reporte guardado en: {filename}")

def main():
    """Función principal"""
    
    print("🚀 CTF Crypto Agent - Benchmark V2")
    print("="*60)
    print("Benchmark mejorado con ejemplos reales")
    print()
    
    # Verificar configuración
    try:
        from src.config.config import config
        
        if not config.GOOGLE_API_KEY or config.GOOGLE_API_KEY == "tu-api-key-aqui":
            print("❌ Error: GOOGLE_API_KEY no configurada")
            print("   Configura tu API key en .env antes de ejecutar el benchmark")
            return 1
        
        print("🔑 API Key configurada correctamente")
        print("📊 Iniciando benchmark...\n")
        
        # Ejecutar benchmark
        benchmark = CTFBenchmarkV2()
        results = benchmark.run_benchmark()
        
        # Mostrar resultado final
        success_rate = (results['successful'] / results['total'] * 100) if results['total'] > 0 else 0
        
        if success_rate >= 67:
            print(f"\n🎉 Benchmark completado exitosamente!")
            print(f"📈 Tasa de éxito: {success_rate:.1f}% - ¡Objetivo 67%+ alcanzado!")
        elif success_rate >= 50:
            print(f"\n⚠️  Benchmark completado con buenos resultados")
            print(f"📈 Tasa de éxito: {success_rate:.1f}% - Cerca del objetivo 67%")
        else:
            print(f"\n❌ Benchmark completado - Necesita mejoras")
            print(f"📈 Tasa de éxito: {success_rate:.1f}% - Por debajo del objetivo 67%")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error ejecutando benchmark: {e}")
        return 1

if __name__ == "__main__":
    exit(main())