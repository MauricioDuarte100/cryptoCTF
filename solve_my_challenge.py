#!/usr/bin/env python3
"""
Script para resolver tu challenge personalizado
"""

import sys
import json
import requests
from pathlib import Path

def solve_with_simple_solver(py_file, json_file=None):
    """Resuelve usando el solver simple"""
    print("🎯 Using Simple Solver")
    print("=" * 40)
    
    try:
        from solve_simple import solve_ctf_challenge
        
        # Intentar resolver el archivo .py
        print(f"📄 Analyzing: {py_file}")
        flag = solve_ctf_challenge(py_file)
        
        if flag:
            print(f"✅ SUCCESS!")
            print(f"🏆 FLAG: {flag}")
            return flag
        else:
            print("❌ Simple solver couldn't find flag")
            return None
            
    except Exception as e:
        print(f"❌ Error with simple solver: {e}")
        return None

def solve_with_api(py_file, json_file=None):
    """Resuelve usando la API backend"""
    print("\n🚀 Using API Backend")
    print("=" * 40)
    
    # Leer archivos
    files_data = []
    
    # Leer archivo .py
    if Path(py_file).exists():
        with open(py_file, 'r', encoding='utf-8') as f:
            py_content = f.read()
        files_data.append({
            "name": Path(py_file).name,
            "content": py_content
        })
        print(f"📄 Loaded: {py_file}")
    
    # Leer archivo .json si existe
    if json_file and Path(json_file).exists():
        with open(json_file, 'r', encoding='utf-8') as f:
            json_content = f.read()
        files_data.append({
            "name": Path(json_file).name,
            "content": json_content
        })
        print(f"📄 Loaded: {json_file}")
    
    # Preparar request
    challenge_data = {
        "description": f"Custom challenge with {len(files_data)} files",
        "files": files_data,
        "timeout": 60
    }
    
    try:
        # Verificar si el backend está corriendo
        health_response = requests.get("http://localhost:8000/health", timeout=2)
        if health_response.status_code != 200:
            print("❌ Backend not responding. Start it with: python backend_simple.py")
            return None
        
        print("📤 Sending to API...")
        response = requests.post(
            "http://localhost:8000/api/solve",
            json=challenge_data,
            timeout=70
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ API Response received")
            print(f"🎯 Success: {result.get('success')}")
            print(f"⏱️ Time: {result.get('time_taken', 0):.2f}s")
            print(f"🔧 Strategy: {result.get('strategy')}")
            
            if result.get('success'):
                flag = result.get('flag')
                print(f"🏆 FLAG: {flag}")
                return flag
            else:
                print(f"❌ API couldn't solve: {result.get('error')}")
                return None
        else:
            print(f"❌ API error: {response.status_code}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Can't connect to backend. Start it with: python backend_simple.py")
        return None
    except Exception as e:
        print(f"❌ API error: {e}")
        return None

def analyze_files(py_file, json_file=None):
    """Analiza los archivos para dar pistas"""
    print("\n🔍 File Analysis")
    print("=" * 40)
    
    # Analizar archivo .py
    if Path(py_file).exists():
        with open(py_file, 'r', encoding='utf-8') as f:
            py_content = f.read().lower()
        
        print(f"📄 Python file: {py_file}")
        
        # Detectar tipo de challenge
        if 'rsa' in py_content or 'modulus' in py_content:
            print("🔍 Detected: Likely RSA challenge")
        elif 'aes' in py_content or 'cipher' in py_content:
            print("🔍 Detected: Likely AES/Cipher challenge")
        elif 'hash' in py_content or 'md5' in py_content or 'sha' in py_content:
            print("🔍 Detected: Likely Hash challenge")
        elif 'base64' in py_content or 'encode' in py_content:
            print("🔍 Detected: Likely Encoding challenge")
        else:
            print("🔍 Detected: Unknown challenge type")
    
    # Analizar archivo .json
    if json_file and Path(json_file).exists():
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            print(f"📄 JSON file: {json_file}")
            print(f"🔍 JSON keys: {list(json_data.keys()) if isinstance(json_data, dict) else 'Not a dict'}")
            
        except Exception as e:
            print(f"⚠️ Couldn't parse JSON: {e}")

def main():
    """Función principal"""
    print("🎯 Custom Challenge Solver")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python solve_my_challenge.py challenge.py")
        print("  python solve_my_challenge.py challenge.py data.json")
        print("\nExample:")
        print("  python solve_my_challenge.py my_challenge/rsa.py")
        print("  python solve_my_challenge.py my_challenge/chall.py my_challenge/data.json")
        return
    
    py_file = sys.argv[1]
    json_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Verificar que los archivos existen
    if not Path(py_file).exists():
        print(f"❌ File not found: {py_file}")
        return
    
    if json_file and not Path(json_file).exists():
        print(f"❌ File not found: {json_file}")
        return
    
    print(f"📁 Challenge files:")
    print(f"   Python: {py_file}")
    if json_file:
        print(f"   JSON: {json_file}")
    
    # Analizar archivos
    analyze_files(py_file, json_file)
    
    # Intentar resolver con diferentes métodos
    flag = None
    
    # Método 1: Simple Solver
    flag = solve_with_simple_solver(py_file, json_file)
    
    # Método 2: API Backend (si el simple falló)
    if not flag:
        flag = solve_with_api(py_file, json_file)
    
    # Resultado final
    print("\n" + "=" * 50)
    if flag:
        print("🎉 CHALLENGE SOLVED!")
        print(f"🏆 FINAL FLAG: {flag}")
    else:
        print("❌ CHALLENGE NOT SOLVED")
        print("💡 Try:")
        print("   1. Check if files are correct")
        print("   2. Start backend: python backend_simple.py")
        print("   3. Check challenge type is supported")
    print("=" * 50)

if __name__ == "__main__":
    main()