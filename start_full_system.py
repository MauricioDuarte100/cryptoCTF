#!/usr/bin/env python3
"""
Script para iniciar el sistema completo (Frontend + Backend)
"""

import subprocess
import sys
import time
import requests
import os
from pathlib import Path

def check_node_installed():
    """Verifica si Node.js está instalado"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Node.js version: {result.stdout.strip()}")
            return True
        else:
            print("❌ Node.js not found")
            return False
    except FileNotFoundError:
        print("❌ Node.js not installed")
        return False

def check_npm_installed():
    """Verifica si npm está instalado"""
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npm version: {result.stdout.strip()}")
            return True
        else:
            print("❌ npm not found")
            return False
    except FileNotFoundError:
        print("❌ npm not installed")
        return False

def install_frontend_dependencies():
    """Instala dependencias del frontend"""
    frontend_dir = Path("frontend_nextjs")
    
    if not frontend_dir.exists():
        print("❌ Frontend directory not found")
        return False
    
    print("📦 Installing frontend dependencies...")
    try:
        result = subprocess.run(
            ['npm', 'install'],
            cwd=frontend_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("✅ Frontend dependencies installed")
            return True
        else:
            print(f"❌ npm install failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def start_backend():
    """Inicia el backend"""
    print("🚀 Starting backend server...")
    try:
        backend_process = subprocess.Popen([
            sys.executable, "backend_simple.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Esperar a que el backend esté listo
        for i in range(30):  # 30 segundos máximo
            try:
                response = requests.get("http://localhost:8000/health", timeout=2)
                if response.status_code == 200:
                    print("✅ Backend is ready!")
                    return backend_process
            except:
                pass
            time.sleep(1)
        
        print("❌ Backend failed to start")
        backend_process.terminate()
        return None
        
    except Exception as e:
        print(f"❌ Error starting backend: {e}")
        return None

def start_frontend():
    """Inicia el frontend"""
    frontend_dir = Path("frontend_nextjs")
    
    print("🎨 Starting frontend server...")
    try:
        frontend_process = subprocess.Popen([
            'npm', 'run', 'dev'
        ], cwd=frontend_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Esperar a que el frontend esté listo
        for i in range(60):  # 60 segundos máximo
            try:
                response = requests.get("http://localhost:3000", timeout=2)
                if response.status_code == 200:
                    print("✅ Frontend is ready!")
                    return frontend_process
            except:
                pass
            time.sleep(1)
        
        print("❌ Frontend failed to start")
        frontend_process.terminate()
        return None
        
    except Exception as e:
        print(f"❌ Error starting frontend: {e}")
        return None

def main():
    """Función principal"""
    print("🚀 Enhanced CTF Solver - Full System Startup")
    print("=" * 50)
    
    # Verificar prerrequisitos
    print("🔍 Checking prerequisites...")
    
    if not check_node_installed():
        print("\n❌ Node.js is required for the frontend")
        print("📥 Install from: https://nodejs.org/")
        return
    
    if not check_npm_installed():
        print("\n❌ npm is required for the frontend")
        return
    
    # Instalar dependencias del frontend
    if not install_frontend_dependencies():
        print("\n❌ Failed to install frontend dependencies")
        return
    
    print("\n🚀 Starting system components...")
    
    # Iniciar backend
    backend_process = start_backend()
    if not backend_process:
        print("\n❌ Failed to start backend")
        return
    
    # Iniciar frontend
    frontend_process = start_frontend()
    if not frontend_process:
        print("\n❌ Failed to start frontend")
        backend_process.terminate()
        return
    
    # Sistema listo
    print("\n" + "=" * 50)
    print("🎉 SYSTEM READY!")
    print("=" * 50)
    print("🌐 Frontend: http://localhost:3000")
    print("🔧 Backend API: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 50)
    print("\n💡 How to use:")
    print("1. Open http://localhost:3000 in your browser")
    print("2. Upload your challenge files (.py, .json)")
    print("3. Add a description of the challenge")
    print("4. Click 'Solve Challenge'")
    print("5. Get your flag! 🏆")
    print("\n⚠️  Press Ctrl+C to stop both servers")
    
    try:
        # Mantener ambos procesos corriendo
        while True:
            time.sleep(1)
            
            # Verificar que ambos procesos sigan corriendo
            if backend_process.poll() is not None:
                print("\n❌ Backend process died")
                break
            
            if frontend_process.poll() is not None:
                print("\n❌ Frontend process died")
                break
                
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down system...")
        
        # Terminar procesos
        if backend_process:
            backend_process.terminate()
            print("✅ Backend stopped")
        
        if frontend_process:
            frontend_process.terminate()
            print("✅ Frontend stopped")
        
        print("👋 System shutdown complete")

if __name__ == "__main__":
    main()