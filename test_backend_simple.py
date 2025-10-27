#!/usr/bin/env python3
"""
Test del backend simple
"""

import requests
import time
import json

def test_backend():
    """Prueba el backend simple"""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing Simple Backend API")
    print("=" * 40)
    
    # Test 1: Health check
    print("1. Testing health check...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ Health check OK")
            data = response.json()
            print(f"   📊 Uptime: {data.get('uptime')}")
            print(f"   🔧 Solver available: {data.get('solver_available')}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
        return False
    
    # Test 2: Status
    print("\n2. Testing status endpoint...")
    try:
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code == 200:
            print("   ✅ Status OK")
            data = response.json()
            print(f"   📈 Success rate: {data.get('success_rate', 0):.1%}")
            print(f"   📊 Total requests: {data.get('total_requests', 0)}")
        else:
            print(f"   ❌ Status failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Status error: {e}")
    
    # Test 3: Solve challenge
    print("\n3. Testing solve endpoint...")
    try:
        challenge_data = {
            "description": "Test Caesar cipher challenge",
            "files": [
                {
                    "name": "test.py",
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
            print(f"   ✅ Solve request completed")
            print(f"   🎯 Success: {result.get('success')}")
            print(f"   🏆 Flag: {result.get('flag')}")
            print(f"   ⏱️ Time: {result.get('time_taken', 0):.2f}s")
            print(f"   🔧 Strategy: {result.get('strategy')}")
            
            if result.get('success'):
                print("   🎉 CHALLENGE SOLVED!")
                return True
            else:
                print(f"   ❌ Challenge failed: {result.get('error')}")
                return False
        else:
            print(f"   ❌ Solve request failed: {response.status_code}")
            print(f"   📄 Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Solve error: {e}")
        return False

def test_built_in_endpoint():
    """Prueba el endpoint de test integrado"""
    base_url = "http://localhost:8000"
    
    print("\n4. Testing built-in test endpoint...")
    try:
        response = requests.post(f"{base_url}/api/test", timeout=35)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Built-in test completed")
            print(f"   🎯 Success: {result.get('success')}")
            print(f"   🏆 Flag: {result.get('flag')}")
            print(f"   ⏱️ Time: {result.get('time_taken', 0):.2f}s")
            
            if result.get('success'):
                print("   🎉 BUILT-IN TEST PASSED!")
                return True
            else:
                print(f"   ❌ Built-in test failed: {result.get('error')}")
                return False
        else:
            print(f"   ❌ Built-in test failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Built-in test error: {e}")
        return False

def main():
    """Función principal"""
    print("🚀 Backend Simple API Test")
    print("=" * 40)
    print("⚠️  Make sure the backend is running:")
    print("   python backend_simple.py")
    print("=" * 40)
    
    # Esperar un poco para que el usuario inicie el backend
    print("\n⏳ Waiting 3 seconds for backend to be ready...")
    time.sleep(3)
    
    # Ejecutar tests
    success = test_backend()
    
    if success:
        test_built_in_endpoint()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 BACKEND TEST: PASSED")
        print("✅ Simple backend is working correctly!")
    else:
        print("❌ BACKEND TEST: FAILED")
        print("⚠️  Check that backend is running and try again")
    print("=" * 40)

if __name__ == "__main__":
    main()