#!/usr/bin/env python3
"""
System Test Script
Script unificado para probar todo el sistema
"""

import sys
import os
from pathlib import Path

# Añadir el directorio raíz al path
root_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(root_dir))

def test_backend():
    """Test backend endpoints"""
    print("🧪 Testing Backend...")
    
    try:
        from phase3.test_simple import main as test_simple_main
        test_simple_main()
    except ImportError:
        print("❌ Backend test not available")
        return False
    except Exception as e:
        print(f"❌ Backend test failed: {e}")
        return False
    
    return True

def test_learning_system():
    """Test learning system"""
    print("\n🧠 Testing Learning System...")
    
    try:
        from phase3.test_learning_system import main as test_learning_main
        test_learning_main()
    except ImportError:
        print("❌ Learning system test not available")
        return False
    except Exception as e:
        print(f"❌ Learning system test failed: {e}")
        return False
    
    return True

def test_frontend_build():
    """Test frontend build"""
    print("\n💻 Testing Frontend...")
    
    frontend_dir = root_dir / "phase3" / "frontend"
    if not frontend_dir.exists():
        print("❌ Frontend directory not found")
        return False
    
    # Check if package.json exists
    package_json = frontend_dir / "package.json"
    if not package_json.exists():
        print("❌ package.json not found")
        return False
    
    print("✅ Frontend structure OK")
    print("💡 To test frontend: cd phase3/frontend && npm install && npm run dev")
    return True

def main():
    """Main test function"""
    print("🚀 PHASE 3.0 SYSTEM TEST")
    print("=" * 30)
    
    results = []
    
    # Test backend
    backend_ok = test_backend()
    results.append(("Backend", backend_ok))
    
    # Test learning system
    learning_ok = test_learning_system()
    results.append(("Learning System", learning_ok))
    
    # Test frontend
    frontend_ok = test_frontend_build()
    results.append(("Frontend", frontend_ok))
    
    # Summary
    print("\n" + "=" * 30)
    print("📊 TEST SUMMARY")
    print("=" * 30)
    
    passed = 0
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
        if result:
            passed += 1
    
    print(f"\n🎯 OVERALL: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 ALL SYSTEMS GO!")
    elif passed >= len(results) * 0.5:
        print("✅ System mostly functional")
    else:
        print("⚠️ System needs attention")
    
    # Instructions
    print("\n💡 QUICK START:")
    print("1. Start backend: python phase3/scripts/start_backend.py")
    print("2. Start frontend: cd phase3/frontend && npm run dev")
    print("3. Open browser: http://localhost:3000")

if __name__ == "__main__":
    main()