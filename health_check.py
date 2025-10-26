#!/usr/bin/env python3
"""
Health Check para CryptoSolver
Verifica que todas las herramientas funcionan correctamente
"""

import subprocess
import os
import sys
from pathlib import Path

def check_tools_health():
    """Verifica que todas las herramientas funcionan"""
    
    print("🔧 Checking tools health...\n")
    
    checks = {
        "RsaCtfTool": False,
        "SageMath": False,
        "pwntools": False,
        "Gemini API": False,
        "RSA Attack": False,
        "XOR Attack": False
    }
    
    # 1. RsaCtfTool
    try:
        result = subprocess.run(
            ["python", "-c", "from RsaCtfTool.main import main; print('OK')"],
            capture_output=True,
            timeout=5
        )
        checks["RsaCtfTool"] = result.returncode == 0
    except:
        pass
    
    # 2. SageMath
    try:
        result = subprocess.run(
            ["sage", "-v"],
            capture_output=True,
            timeout=5
        )
        checks["SageMath"] = result.returncode == 0
    except:
        pass
    
    # 3. pwntools
    try:
        from pwn import remote
        checks["pwntools"] = True
    except:
        pass
    
    # 4. Gemini API
    try:
        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.getenv("GOOGLE_API_KEY")
        checks["Gemini API"] = bool(api_key and len(api_key) > 10)
    except:
        pass
    
    # 5. RSA Attack Test
    try:
        from src.tools.tools import attack_rsa
        result = attack_rsa.invoke({'n': '143', 'e': '7', 'c': '119'})
        checks["RSA Attack"] = result.get("success", False)
    except Exception as e:
        print(f"RSA Attack Error: {e}")
    
    # 6. XOR Attack Test
    try:
        from src.tools.tools import attack_classical
        # Test XOR: 'flag{test}' XOR 42
        test_cipher = "4c464b4d51524558755e"
        result = attack_classical.invoke({'ciphertext': test_cipher})
        checks["XOR Attack"] = result.get("success", False)
    except Exception as e:
        print(f"XOR Attack Error: {e}")
    
    # Reporte
    print("📊 TOOLS STATUS:\n")
    for tool, ok in checks.items():
        status = "✅" if ok else "❌"
        print(f"  {status} {tool}")
    
    print("\n⚠️  INSTALLATION COMMANDS:\n")
    
    if not checks["RsaCtfTool"]:
        print("  RsaCtfTool:")
        print("    git clone https://github.com/RsaCtfTool/RsaCtfTool.git")
        print("    cd RsaCtfTool && pip install -e .")
        print("    pip install -r RsaCtfTool/requirements.txt\n")
    
    if not checks["SageMath"]:
        print("  SageMath (Linux):")
        print("    sudo apt install sagemath\n")
        print("  SageMath (macOS):")
        print("    brew install sage\n")
        print("  SageMath (Windows):")
        print("    Download from: https://www.sagemath.org/download-windows.html\n")
    
    if not checks["pwntools"]:
        print("  pwntools:")
        print("    pip install pwntools\n")
    
    if not checks["Gemini API"]:
        print("  Gemini API:")
        print("    1. Get key: https://aistudio.google.com/apikey")
        print("    2. Add to .env: GOOGLE_API_KEY=...\n")
    
    # Test específicos de ataques
    if not checks["RSA Attack"]:
        print("  RSA Attack Issues:")
        print("    - Check RsaCtfTool installation")
        print("    - Verify src/tools/tools.py has correct attack_rsa function\n")
    
    if not checks["XOR Attack"]:
        print("  XOR Attack Issues:")
        print("    - Check attack_classical function in src/tools/tools.py\n")
    
    all_ok = all(checks.values())
    critical_ok = checks["RSA Attack"] and checks["XOR Attack"] and checks["Gemini API"]
    
    print(f"\n{'✅ All tools ready!' if all_ok else '⚠️  Some tools missing.'}")
    print(f"{'✅ Critical tools OK!' if critical_ok else '❌ Critical tools missing!'}")
    
    if critical_ok:
        print("\n🚀 Ready to run benchmark!")
        print("   python benchmark.py")
    
    return checks

def test_individual_tools():
    """Prueba herramientas individualmente con ejemplos"""
    
    print("\n🧪 INDIVIDUAL TOOL TESTS:\n")
    
    # Test RSA
    print("1. Testing RSA Attack...")
    try:
        from src.tools.tools import attack_rsa
        result = attack_rsa.invoke({
            'n': '143',  # 11 * 13
            'e': '7',
            'c': '119'   # pow(102, 7, 143) where 102 = ord('f')
        })
        print(f"   Result: {result}")
        if result.get("success"):
            print("   ✅ RSA Attack working!")
        else:
            print("   ❌ RSA Attack failed")
    except Exception as e:
        print(f"   ❌ RSA Attack error: {e}")
    
    # Test XOR
    print("\n2. Testing XOR Attack...")
    try:
        from src.tools.tools import attack_classical
        # 'flag{test}' XOR 42 = 4c464b4d51524558755e
        result = attack_classical.invoke({'ciphertext': '4c464b4d51524558755e'})
        print(f"   Result: {result}")
        if result.get("success"):
            print("   ✅ XOR Attack working!")
        else:
            print("   ❌ XOR Attack failed")
    except Exception as e:
        print(f"   ❌ XOR Attack error: {e}")
    
    # Test Caesar
    print("\n3. Testing Caesar Attack...")
    try:
        from src.tools.tools import attack_classical
        # 'flag{test}' with ROT13
        result = attack_classical.invoke({'ciphertext': 'synt{grfg}'})
        print(f"   Result: {result}")
        if result.get("success"):
            print("   ✅ Caesar Attack working!")
        else:
            print("   ❌ Caesar Attack failed")
    except Exception as e:
        print(f"   ❌ Caesar Attack error: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("🔍 CRYPTOSOLVER HEALTH CHECK")
    print("=" * 60)
    
    checks = check_tools_health()
    
    if "--detailed" in sys.argv:
        test_individual_tools()
    
    print("\n" + "=" * 60)
    print("Health check complete!")
    print("Run with --detailed for individual tool tests")
    print("=" * 60)