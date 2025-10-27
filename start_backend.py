#!/usr/bin/env python3
"""
Script para iniciar el backend FastAPI Enhanced
"""

import subprocess
import sys
import time
import requests
from pathlib import Path

def check_dependencies():
    """Verifica que las dependencias estén instaladas"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'pydantic',
        'requests'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    return True

def wait_for_server(url="http://localhost:8000", timeout=30):
    """Espera a que el servidor esté listo"""
    print(f"⏳ Waiting for server at {url}...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                print(f"✅ Server is ready at {url}")
                return True
        except requests.exceptions.RequestException:
            pass
        
        time.sleep(1)
    
    print(f"❌ Server not ready after {timeout}s")
    return False

def test_basic_endpoints():
    """Prueba endpoints básicos"""
    base_url = "http://localhost:8000"
    
    endpoints = [
        "/",
        "/api/status",
        "/api/history",
        "/api/statistics"
    ]
    
    print("\n🧪 Testing basic endpoints:")
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✅" if response.status_code == 200 else "❌"
            print(f"   {status} {endpoint} - {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint} - Error: {e}")

def main():
    print("🚀 Starting Enhanced CTF Solver Backend")
    print("=" * 50)
    
    # Verificar dependencias
    if not check_dependencies():
        sys.exit(1)
    
    # Verificar que el archivo backend existe
    backend_file = Path("backend_fastapi_enhanced.py")
    if not backend_file.exists():
        print(f"❌ Backend file not found: {backend_file}")
        sys.exit(1)
    
    print("✅ Dependencies OK")
    print("✅ Backend file found")
    
    # Iniciar servidor
    print("\n🔄 Starting FastAPI server...")
    try:
        # Iniciar en background para poder hacer tests
        process = subprocess.Popen([
            sys.executable, "backend_fastapi_enhanced.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Esperar a que esté listo
        if wait_for_server():
            test_basic_endpoints()
            
            print("\n" + "=" * 50)
            print("🎯 Backend is running successfully!")
            print("📍 URL: http://localhost:8000")
            print("📚 API Docs: http://localhost:8000/docs")
            print("🔧 ReDoc: http://localhost:8000/redoc")
            print("=" * 50)
            print("\n⚠️  Press Ctrl+C to stop the server")
            
            # Mantener el proceso corriendo
            try:
                process.wait()
            except KeyboardInterrupt:
                print("\n🛑 Stopping server...")
                process.terminate()
                process.wait()
                print("✅ Server stopped")
        else:
            print("❌ Failed to start server")
            process.terminate()
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()