#!/usr/bin/env python3
"""
Benchmark del agente CTF Crypto
Mide rendimiento en diferentes tipos de desafíos
"""

import time
import json
import statistics
from pathlib import Path
from src.core.agent import solve_ctf_challenge

def load_challenge_files(challenge_dir):
    """Carga archivos de un desafío"""
    files = []
    challenge_path = Path(challenge_dir)
    
    if not challenge_path.exists():
        return files
    
    for file_path in challenge_path.glob("*.py"):
        with open(file_path, 'r', encoding='utf-8') as f:
            files.append({
                "name": file_path.name,
                "content": f.read()
            })
    
    return files

def benchmark_challenge(name, description, files, expected_success=True, runs=3):
    """Ejecuta benchmark de un desafío específico"""
    print(f"\n🔍 Benchmarking: {name}")
    print("-" * 40)
    
    results = []
    success_count = 0
    
    for run in range(runs):
        print(f"  Run {run + 1}/{runs}...", end=" ")
        
        start_time = time.time()
        
        try:
            result = solve_ctf_challenge(
                description=description,
                files=files,
                max_steps=15
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            results.append({
                "run": run + 1,
                "success": result["success"],
                "duration": duration,
                "steps_used": result.get("steps_used", 0),
                "challenge_type": result.get("challenge_type", "Unknown"),
                "confidence": result.get("confidence", 0.0)
            })
            
            if result["success"]:
                success_count += 1
                print(f"✅ {duration:.1f}s")
            else:
                print(f"❌ {duration:.1f}s")
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            results.append({
                "run": run + 1,
                "success": False,
                "duration": duration,
                "error": str(e)
            })
            print(f"💥 {duration:.1f}s - {str(e)[:50]}")
    
    # Calcular estadísticas
    durations = [r["duration"] for r in results]
    success_rate = success_count / runs
    
    stats = {
        "name": name,
        "runs": runs,
        "success_rate": success_rate,
        "avg_duration": statistics.mean(durations),
        "min_duration": min(durations),
        "max_duration": max(durations),
        "std_duration": statistics.stdev(durations) if len(durations) > 1 else 0,
        "expected_success": expected_success,
        "meets_expectation": success_rate >= 0.8 if expected_success else success_rate < 0.2,
        "results": results
    }
    
    print(f"  📊 Success Rate: {success_rate:.1%}")
    print(f"  ⏱️  Avg Duration: {stats['avg_duration']:.1f}s")
    print(f"  📈 Expectation: {'✅' if stats['meets_expectation'] else '❌'}")
    
    return stats

def run_full_benchmark():
    """Ejecuta benchmark completo"""
    print("🚀 CTF Crypto Agent - Benchmark Suite")
    print("=" * 50)
    
    benchmarks = []
    
    # 1. RSA Básico (debería funcionar)
    files = load_challenge_files("examples/rsa_basic")
    if files:
        stats = benchmark_challenge(
            "RSA Basic (e=3)",
            "RSA challenge with small exponent e=3",
            files,
            expected_success=True,
            runs=3
        )
        benchmarks.append(stats)
    
    # 2. Caesar Cipher (debería funcionar)
    files = load_challenge_files("examples/caesar_cipher")
    if files:
        stats = benchmark_challenge(
            "Caesar Cipher",
            "Caesar cipher challenge with ROT shift",
            files,
            expected_success=True,
            runs=3
        )
        benchmarks.append(stats)
    
    # 3. XOR Single Byte (debería funcionar)
    files = load_challenge_files("examples/xor_single")
    if files:
        stats = benchmark_challenge(
            "XOR Single Byte",
            "XOR single byte key challenge",
            files,
            expected_success=True,
            runs=3
        )
        benchmarks.append(stats)
    
    # 4. Desafío imposible (no debería funcionar)
    impossible_files = [{
        "name": "impossible.py",
        "content": """
# Desafío imposible - AES-256 con clave aleatoria
from Crypto.Cipher import AES
import os

key = os.urandom(32)  # Clave aleatoria de 256 bits
cipher = AES.new(key, AES.MODE_ECB)
flag = b"flag{this_is_impossible_to_crack}"
encrypted = cipher.encrypt(flag.ljust(32, b'\\x00'))
print("Encrypted flag:", encrypted.hex())
"""
    }]
    
    stats = benchmark_challenge(
        "Impossible AES",
        "AES-256 with random key (should fail)",
        impossible_files,
        expected_success=False,
        runs=2
    )
    benchmarks.append(stats)
    
    # Generar reporte final
    print("\n" + "=" * 50)
    print("📊 BENCHMARK RESULTS")
    print("=" * 50)
    
    total_runs = sum(b["runs"] for b in benchmarks)
    total_successes = sum(b["runs"] * b["success_rate"] for b in benchmarks)
    overall_success_rate = total_successes / total_runs if total_runs > 0 else 0
    
    avg_duration = statistics.mean([b["avg_duration"] for b in benchmarks])
    expectations_met = sum(1 for b in benchmarks if b["meets_expectation"])
    
    print(f"Overall Success Rate: {overall_success_rate:.1%}")
    print(f"Average Duration: {avg_duration:.1f}s")
    print(f"Expectations Met: {expectations_met}/{len(benchmarks)}")
    
    print(f"\n📋 Detailed Results:")
    for benchmark in benchmarks:
        status = "✅" if benchmark["meets_expectation"] else "❌"
        print(f"  {status} {benchmark['name']}: {benchmark['success_rate']:.1%} ({benchmark['avg_duration']:.1f}s)")
    
    # Guardar resultados
    timestamp = int(time.time())
    results_file = f"benchmark_results_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump({
            "timestamp": timestamp,
            "overall_success_rate": overall_success_rate,
            "average_duration": avg_duration,
            "expectations_met": expectations_met,
            "total_benchmarks": len(benchmarks),
            "benchmarks": benchmarks
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")
    
    # Determinar si el benchmark pasó
    benchmark_passed = (
        overall_success_rate >= 0.6 and  # Al menos 60% de éxito general
        expectations_met >= len(benchmarks) * 0.8 and  # 80% de expectativas cumplidas
        avg_duration <= 30  # Promedio menor a 30 segundos
    )
    
    if benchmark_passed:
        print("\n🎉 BENCHMARK PASSED!")
        return True
    else:
        print("\n⚠️  BENCHMARK FAILED!")
        print("   - Check individual test results above")
        return False

if __name__ == "__main__":
    import sys
    success = run_full_benchmark()
    sys.exit(0 if success else 1)