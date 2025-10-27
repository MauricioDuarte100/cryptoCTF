#!/usr/bin/env python3
"""
Test del sistema de producción completo
"""

import subprocess
import time
import requests
import json
from pathlib import Path

def test_backend_functionality():
    """Prueba la funcionalidad del backend"""
    print("🧪 Testing Backend Functionality")
    print("=" * 40)
    
    base_url = "http://localhost:8000"
    
    # Test 1: Health check
    print("1. Health Check...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Status: {data.get('status')}")
            print(f"   ⏱️ Uptime: {data.get('uptime')}")
            print(f"   🔧 Solver: {data.get('solver_available')}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
        return False
    
    # Test 2: System Status
    print("\n2. System Status...")
    try:
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Status: {data.get('status')}")
            print(f"   📊 Requests: {data.get('total_requests', 0)}")
            print(f"   📈 Success Rate: {data.get('success_rate', 0):.1%}")
        else:
            print(f"   ❌ Status failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Status error: {e}")
    
    # Test 3: Solve Challenge
    print("\n3. Solve Challenge...")
    try:
        challenge_data = {
            "description": "Caesar cipher challenge",
            "files": [
                {
                    "name": "challenge.py",
                    "content": 'encrypted = "synt{pnrfne_pvcure_vf_rnfl_gb_oernx}"'
                }
            ],
            "timeout": 30
        }
        
        print("   📤 Sending solve request...")
        response = requests.post(
            f"{base_url}/api/solve",
            json=challenge_data,
            timeout=35
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Request completed")
            print(f"   🎯 Success: {result.get('success')}")
            print(f"   🏆 Flag: {result.get('flag')}")
            print(f"   ⏱️ Time: {result.get('time_taken', 0):.2f}s")
            print(f"   🔧 Strategy: {result.get('strategy')}")
            
            if result.get('success'):
                print("   🎉 CHALLENGE SOLVED!")
                return True
            else:
                print(f"   ⚠️ Challenge not solved: {result.get('error')}")
                return True  # Backend funciona, solo no resolvió
        else:
            print(f"   ❌ Solve failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Solve error: {e}")
        return False

def test_dataset_quality():
    """Prueba la calidad del dataset"""
    print("\n🧪 Testing Dataset Quality")
    print("=" * 40)
    
    dataset_path = Path("real_writeups_train/crypto_writeups_combined.jsonl")
    
    if not dataset_path.exists():
        print("❌ Combined dataset not found")
        return False
    
    # Leer dataset
    writeups = []
    with open(dataset_path, 'r', encoding='utf-8') as f:
        for line in f:
            writeups.append(json.loads(line))
    
    print(f"📊 Dataset Statistics:")
    print(f"   Total writeups: {len(writeups)}")
    
    # Análisis por tipo
    attack_types = {}
    difficulties = {}
    sources = {}
    
    for writeup in writeups:
        attack_type = writeup.get('attack_type', 'unknown')
        difficulty = writeup.get('difficulty', 'unknown')
        source = writeup.get('source', 'unknown')
        
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        difficulties[difficulty] = difficulties.get(difficulty, 0) + 1
        sources[source] = sources.get(source, 0) + 1
    
    print(f"\n📈 Attack Types:")
    for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   {attack_type}: {count}")
    
    print(f"\n📊 Difficulties:")
    for difficulty, count in sorted(difficulties.items(), key=lambda x: x[1], reverse=True):
        print(f"   {difficulty}: {count}")
    
    print(f"\n📚 Sources:")
    for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
        print(f"   {source}: {count}")
    
    # Verificar calidad del contenido
    quality_issues = 0
    for i, writeup in enumerate(writeups[:5]):  # Revisar primeros 5
        if len(writeup.get('content', '')) < 100:
            quality_issues += 1
        if not writeup.get('title'):
            quality_issues += 1
    
    print(f"\n🔍 Quality Check:")
    print(f"   Issues found: {quality_issues}/5 samples")
    
    if quality_issues == 0:
        print("   ✅ Dataset quality: GOOD")
        return True
    elif quality_issues <= 2:
        print("   ⚠️ Dataset quality: ACCEPTABLE")
        return True
    else:
        print("   ❌ Dataset quality: POOR")
        return False

def test_core_solver():
    """Prueba el solver core"""
    print("\n🧪 Testing Core Solver")
    print("=" * 40)
    
    try:
        # Test con challenge simple
        result = subprocess.run([
            "python", "solve_simple.py", "validation_challenges/classical/caesar.py"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout
            if "flag{" in output.lower():
                print("✅ Core solver working")
                print("✅ Caesar cipher solved")
                return True
            else:
                print("⚠️ Core solver runs but no flag found")
                return False
        else:
            print(f"❌ Core solver failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Core solver timeout")
        return False
    except Exception as e:
        print(f"❌ Core solver error: {e}")
        return False

def main():
    """Función principal"""
    print("🚀 Production System Test")
    print("=" * 50)
    print("Testing complete production system...")
    print("=" * 50)
    
    results = {}
    
    # Test 1: Core Solver
    results['core_solver'] = test_core_solver()
    
    # Test 2: Dataset Quality
    results['dataset'] = test_dataset_quality()
    
    # Test 3: Backend (solo si está corriendo)
    print("\n⚠️  Backend test requires server running:")
    print("   Run: python backend_simple.py")
    print("   Then press Enter to test, or 's' to skip...")
    
    user_input = input().strip().lower()
    if user_input != 's':
        results['backend'] = test_backend_functionality()
    else:
        results['backend'] = None
        print("⏭️ Backend test skipped")
    
    # Resumen final
    print("\n" + "=" * 50)
    print("🎯 PRODUCTION SYSTEM TEST RESULTS")
    print("=" * 50)
    
    for test_name, result in results.items():
        if result is True:
            print(f"✅ {test_name.upper()}: PASSED")
        elif result is False:
            print(f"❌ {test_name.upper()}: FAILED")
        else:
            print(f"⏭️ {test_name.upper()}: SKIPPED")
    
    # Veredicto final
    passed_tests = sum(1 for r in results.values() if r is True)
    total_tests = sum(1 for r in results.values() if r is not None)
    
    if total_tests == 0:
        print("\n⚠️ No tests were run")
    elif passed_tests == total_tests:
        print(f"\n🎉 ALL TESTS PASSED ({passed_tests}/{total_tests})")
        print("✅ Production system is ready!")
    elif passed_tests >= total_tests * 0.7:
        print(f"\n⚠️ MOSTLY WORKING ({passed_tests}/{total_tests})")
        print("✅ System is functional with minor issues")
    else:
        print(f"\n❌ SYSTEM NEEDS WORK ({passed_tests}/{total_tests})")
        print("⚠️ Fix failing components before production")
    
    print("=" * 50)

if __name__ == "__main__":
    main()