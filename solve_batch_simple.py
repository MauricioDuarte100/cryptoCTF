#!/usr/bin/env python3
"""
Simple Batch CTF Solver - Usa el solver simple mejorado
Procesa múltiples challenges con el solver que realmente funciona
"""

import sys
import os
import glob
import json
import time
from pathlib import Path
from datetime import datetime
from solve_simple import solve_ctf_challenge

def find_challenge_files(directory):
    """Encuentra todos los archivos de challenge en un directorio"""
    
    patterns = [
        "**/*.py",
        "**/*challenge*.py", 
        "**/*chall*.py",
        "**/*ctf*.py"
    ]
    
    challenge_files = set()
    
    for pattern in patterns:
        files = glob.glob(os.path.join(directory, pattern), recursive=True)
        challenge_files.update(files)
    
    # Filtrar archivos que probablemente no sean challenges
    exclude_patterns = [
        'test_', 'benchmark_', 'solve', '__pycache__', 
        '.git', 'venv', 'node_modules', 'scripts'
    ]
    
    filtered_files = []
    for file in challenge_files:
        if not any(pattern in file.lower() for pattern in exclude_patterns):
            filtered_files.append(file)
    
    return sorted(filtered_files)

def solve_single_challenge(challenge_file):
    """Resuelve un challenge individual"""
    
    print(f"\n🎯 Processing: {challenge_file}")
    start_time = time.time()
    
    try:
        flag = solve_ctf_challenge(challenge_file)
        end_time = time.time()
        
        result = {
            'challenge': challenge_file,
            'success': bool(flag),
            'flag': flag if flag else None,
            'time_taken': end_time - start_time,
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        if flag:
            print(f"✅ SOLVED: {challenge_file} → {flag}")
        else:
            print(f"❌ FAILED: {challenge_file}")
        
        return result
        
    except Exception as e:
        end_time = time.time()
        print(f"💥 ERROR: {challenge_file} → {str(e)}")
        
        return {
            'challenge': challenge_file,
            'success': False,
            'flag': None,
            'time_taken': end_time - start_time,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def generate_report(results, output_file=None):
    """Genera reporte detallado de resultados"""
    
    total_challenges = len(results)
    successful = sum(1 for r in results if r['success'])
    failed = total_challenges - successful
    success_rate = (successful / total_challenges * 100) if total_challenges > 0 else 0
    
    total_time = sum(r['time_taken'] for r in results)
    avg_time = total_time / total_challenges if total_challenges > 0 else 0
    
    # Reporte en consola
    print("\n" + "=" * 60)
    print("📊 SIMPLE BATCH SOLVER RESULTS")
    print("=" * 60)
    print(f"📁 Total challenges processed: {total_challenges}")
    print(f"✅ Successfully solved: {successful}")
    print(f"❌ Failed to solve: {failed}")
    print(f"🎯 Success rate: {success_rate:.1f}%")
    print(f"⏱️ Total time: {total_time:.2f}s")
    print(f"⏱️ Average time per challenge: {avg_time:.2f}s")
    
    # Detalles de éxitos
    if successful > 0:
        print(f"\n🏆 SUCCESSFUL CHALLENGES ({successful}):")
        for result in results:
            if result['success']:
                print(f"  ✅ {result['challenge']} → {result['flag']} ({result['time_taken']:.2f}s)")
    
    # Detalles de fallos
    if failed > 0:
        print(f"\n💔 FAILED CHALLENGES ({failed}):")
        for result in results:
            if not result['success']:
                error_msg = result['error'] if result['error'] else 'No flag found'
                print(f"  ❌ {result['challenge']} → {error_msg} ({result['time_taken']:.2f}s)")
    
    # Análisis por tipo de challenge
    challenge_types = {}
    for result in results:
        challenge_name = Path(result['challenge']).name.lower()
        
        # Detectar tipo por nombre
        if 'rsa' in challenge_name:
            challenge_type = 'RSA'
        elif 'xor' in challenge_name:
            challenge_type = 'XOR'
        elif 'caesar' in challenge_name or 'cipher' in challenge_name:
            challenge_type = 'Classical'
        elif 'hash' in challenge_name or 'md5' in challenge_name:
            challenge_type = 'Hash'
        elif 'base64' in challenge_name or 'encoding' in challenge_name:
            challenge_type = 'Encoding'
        else:
            challenge_type = 'Other'
        
        if challenge_type not in challenge_types:
            challenge_types[challenge_type] = {'total': 0, 'success': 0}
        
        challenge_types[challenge_type]['total'] += 1
        if result['success']:
            challenge_types[challenge_type]['success'] += 1
    
    if challenge_types:
        print(f"\n📈 SUCCESS RATE BY CHALLENGE TYPE:")
        for challenge_type, stats in challenge_types.items():
            type_success_rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {challenge_type}: {type_success_rate:.1f}% ({stats['success']}/{stats['total']})")
    
    # Guardar reporte detallado
    report_data = {
        'summary': {
            'total_challenges': total_challenges,
            'successful': successful,
            'failed': failed,
            'success_rate': success_rate,
            'total_time': total_time,
            'average_time': avg_time,
            'timestamp': datetime.now().isoformat()
        },
        'challenge_types': challenge_types,
        'detailed_results': results
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"\n📝 Detailed report saved to: {output_file}")
    
    return report_data

def main():
    """Función principal"""
    
    if len(sys.argv) < 2:
        print("Usage: python solve_batch_simple.py <directory> [output_file]")
        print("Example: python solve_batch_simple.py validation_challenges/ results.json")
        sys.exit(1)
    
    directory = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'simple_batch_results.json'
    
    print("🚀 SIMPLE BATCH CTF SOLVER")
    print("Using improved simple solver with Base64 and RSA fixes")
    print("=" * 60)
    
    # Verificar directorio
    if not os.path.exists(directory):
        print(f"❌ Error: Directory {directory} not found")
        sys.exit(1)
    
    # Encontrar archivos de challenge
    print(f"🔍 Searching for challenges in: {directory}")
    challenge_files = find_challenge_files(directory)
    
    if not challenge_files:
        print(f"❌ No challenge files found in {directory}")
        sys.exit(1)
    
    print(f"📁 Found {len(challenge_files)} challenge files:")
    for i, file in enumerate(challenge_files, 1):
        print(f"  {i:2d}. {file}")
    
    # Procesar challenges
    print(f"\n🎯 PROCESSING {len(challenge_files)} CHALLENGES...")
    print("=" * 60)
    
    start_time = time.time()
    results = []
    
    for i, challenge_file in enumerate(challenge_files, 1):
        print(f"\n[{i}/{len(challenge_files)}] Processing: {challenge_file}")
        result = solve_single_challenge(challenge_file)
        results.append(result)
    
    end_time = time.time()
    
    # Generar reporte
    print(f"\n⏱️ Total processing time: {end_time - start_time:.2f}s")
    report_data = generate_report(results, output_file)
    
    # Código de salida basado en tasa de éxito
    success_rate = report_data['summary']['success_rate']
    if success_rate >= 80:
        print(f"\n🎉 EXCELLENT! Success rate: {success_rate:.1f}% (Target: 80%+)")
        sys.exit(0)
    elif success_rate >= 60:
        print(f"\n👍 GOOD! Success rate: {success_rate:.1f}% (Target: 80%+)")
        sys.exit(0)
    else:
        print(f"\n⚠️ NEEDS IMPROVEMENT! Success rate: {success_rate:.1f}% (Target: 80%+)")
        sys.exit(1)

if __name__ == "__main__":
    main()