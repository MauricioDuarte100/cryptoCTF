#!/usr/bin/env python3
"""
TEST COMPLETE SYSTEM
Prueba rápida del sistema completo integrado
"""

import sys
import time
import requests
import json
from datetime import datetime
from pathlib import Path

def test_backend_health():
    """Test de salud del backend"""
    print("🔧 Testing Backend Health...")
    
    try:
        response = requests.get("http://localhost:8000/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Backend is healthy: {data.get('message', 'OK')}")
            return True
        else:
            print(f"❌ Backend returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend (not running?)")
        return False
    except Exception as e:
        print(f"❌ Backend health check failed: {e}")
        return False

def test_backend_status():
    """Test del endpoint de status"""
    print("\n📊 Testing Backend Status...")
    
    try:
        response = requests.get("http://localhost:8000/api/status", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status endpoint working")
            print(f"   System Status: {data.get('status', 'unknown')}")
            
            components = data.get('components', {})
            print(f"   Components:")
            for component, available in components.items():
                status = "✅" if available else "❌"
                print(f"     {status} {component}")
            
            capabilities = data.get('capabilities', [])
            if capabilities:
                print(f"   Capabilities: {', '.join(capabilities)}")
            
            return True
        else:
            print(f"❌ Status endpoint returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Status test failed: {e}")
        return False

def test_backend_solve():
    """Test del endpoint de solve con un challenge simple"""
    print("\n🎯 Testing Backend Solve...")
    
    test_challenge = {
        "description": "Simple test challenge - Caesar cipher",
        "files": [{
            "name": "test.py",
            "content": "# Test challenge\nciphertext = 'KHOOR ZRUOG'\n# Caesar cipher with shift 3"
        }],
        "use_enhanced": False  # Usar fallback simple para test rápido
    }
    
    try:
        print("   Sending test challenge...")
        response = requests.post(
            "http://localhost:8000/api/solve",
            json=test_challenge,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Solve endpoint working")
            print(f"   Success: {data.get('success', False)}")
            print(f"   Time taken: {data.get('time_taken', 0):.2f}s")
            
            if data.get('flag'):
                print(f"   Flag found: {data['flag']}")
            
            if data.get('error'):
                print(f"   Error: {data['error']}")
            
            return True
        else:
            print(f"❌ Solve endpoint returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Solve test failed: {e}")
        return False

def test_frontend_health():
    """Test de salud del frontend"""
    print("\n🎨 Testing Frontend Health...")
    
    try:
        response = requests.get("http://localhost:3000/", timeout=10)
        if response.status_code == 200:
            print("✅ Frontend is accessible")
            
            # Verificar que contiene contenido esperado
            content = response.text
            if "Enhanced CTF Solver" in content:
                print("✅ Frontend contains expected content")
                return True
            else:
                print("⚠️ Frontend accessible but content unexpected")
                return False
        else:
            print(f"❌ Frontend returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to frontend (not running?)")
        return False
    except Exception as e:
        print(f"❌ Frontend health check failed: {e}")
        return False

def test_integration():
    """Test de integración frontend-backend"""
    print("\n🔗 Testing Frontend-Backend Integration...")
    
    # Test que el frontend puede hacer proxy al backend
    try:
        # Intentar acceder al API a través del frontend
        response = requests.get("http://localhost:3000/api/status", timeout=10)
        if response.status_code == 200:
            print("✅ Frontend-Backend proxy working")
            return True
        else:
            print(f"⚠️ Proxy returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def test_file_structure():
    """Verifica la estructura de archivos"""
    print("\n📁 Testing File Structure...")
    
    required_files = [
        'backend_fastapi_enhanced.py',
        'multi_agent/coordination/coordinator_enhanced.py',
        'ml_phase2/bert_classifier_enhanced.py',
        'rag/rag_engine_enhanced.py',
        'frontend_nextjs/package.json',
        'frontend_nextjs/src/app/page.tsx',
        'frontend_nextjs/src/lib/api.ts'
    ]
    
    missing_files = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️ Missing files: {len(missing_files)}")
        return False
    else:
        print("✅ All required files present")
        return True

def generate_test_report(results):
    """Genera reporte de test"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "test_results": results,
        "summary": {
            "total_tests": len(results),
            "passed": len([r for r in results.values() if r]),
            "failed": len([r for r in results.values() if not r]),
            "success_rate": len([r for r in results.values() if r]) / len(results)
        }
    }
    
    # Guardar reporte
    report_file = f"system_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return report_file

def main():
    """Función principal de test"""
    print("🧪 ENHANCED CTF SOLVER - COMPLETE SYSTEM TEST")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    # Ejecutar tests
    test_results = {
        'file_structure': test_file_structure(),
        'backend_health': test_backend_health(),
        'backend_status': test_backend_status(),
        'backend_solve': test_backend_solve(),
        'frontend_health': test_frontend_health(),
        'integration': test_integration()
    }
    
    # Resumen final
    print("\n" + "=" * 60)
    print("🎯 COMPLETE SYSTEM TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name.replace('_', ' ').title()}")
    
    total_tests = len(test_results)
    passed_tests = len([r for r in test_results.values() if r])
    success_rate = passed_tests / total_tests
    
    print(f"\n📊 Overall Results:")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {passed_tests}")
    print(f"   Failed: {total_tests - passed_tests}")
    print(f"   Success Rate: {success_rate:.1%}")
    
    # Generar reporte
    report_file = generate_test_report(test_results)
    print(f"\n📄 Report saved: {report_file}")
    
    # Recomendaciones
    print(f"\n💡 Recommendations:")
    if not test_results['backend_health']:
        print("   • Start the backend server: python start_enhanced_system.py")
    if not test_results['frontend_health']:
        print("   • Start the frontend server: cd frontend_nextjs && npm run dev")
    if not test_results['file_structure']:
        print("   • Ensure all system files are present")
    if not test_results['integration']:
        print("   • Check frontend proxy configuration")
    
    # Estado final
    if success_rate >= 0.8:
        print("\n🎉 SYSTEM TEST: SUCCESS")
        print("   Complete system is working correctly!")
        print("   🌐 Frontend: http://localhost:3000")
        print("   🔧 Backend: http://localhost:8000")
    elif success_rate >= 0.6:
        print("\n⚠️ SYSTEM TEST: PARTIAL SUCCESS")
        print("   System has some issues but core functionality works")
    else:
        print("\n❌ SYSTEM TEST: FAILED")
        print("   System needs fixes before use")
    
    print("=" * 60)
    
    return success_rate >= 0.6

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)