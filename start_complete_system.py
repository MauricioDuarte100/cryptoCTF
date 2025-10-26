#!/usr/bin/env python3
"""
START COMPLETE ENHANCED SYSTEM
Script para iniciar el sistema CTF completo: Backend + Frontend
"""

import sys
import os
import time
import subprocess
import threading
import signal
from pathlib import Path
from datetime import datetime

class SystemManager:
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.running = True
        
    def check_dependencies(self):
        """Verifica dependencias del sistema"""
        print("🔍 Checking system dependencies...")
        
        # Python dependencies
        python_packages = [
            'fastapi', 'uvicorn', 'torch', 'transformers', 
            'sentence-transformers', 'faiss-cpu', 'numpy', 
            'pandas', 'requests', 'beautifulsoup4'
        ]
        
        missing_python = []
        for package in python_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"✅ Python: {package}")
            except ImportError:
                print(f"❌ Python: {package}")
                missing_python.append(package)
        
        # Node.js dependencies
        frontend_path = Path('frontend_nextjs')
        if frontend_path.exists():
            node_modules = frontend_path / 'node_modules'
            package_json = frontend_path / 'package.json'
            
            if package_json.exists():
                print("✅ Node.js: package.json found")
                if node_modules.exists():
                    print("✅ Node.js: node_modules found")
                else:
                    print("❌ Node.js: node_modules missing (run npm install)")
                    return False
            else:
                print("❌ Node.js: package.json missing")
                return False
        else:
            print("❌ Frontend directory missing")
            return False
        
        if missing_python:
            print(f"\n⚠️ Missing Python packages: {', '.join(missing_python)}")
            print("Install with: pip install " + " ".join(missing_python))
            return False
        
        return True
    
    def check_ports(self):
        """Verifica que los puertos estén disponibles"""
        print("\n🔌 Checking ports...")
        
        import socket
        
        ports_to_check = [
            (8000, "Backend API"),
            (3000, "Frontend")
        ]
        
        for port, service in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:
                print(f"⚠️ Port {port} ({service}) is already in use")
                return False
            else:
                print(f"✅ Port {port} ({service}) is available")
        
        return True
    
    def start_backend(self):
        """Inicia el servidor backend"""
        print("\n🚀 Starting backend server...")
        
        try:
            cmd = [
                sys.executable, "-m", "uvicorn",
                "backend_fastapi_enhanced:app",
                "--host", "0.0.0.0",
                "--port", "8000",
                "--reload"
            ]
            
            print(f"Command: {' '.join(cmd)}")
            
            self.backend_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Esperar un poco para que inicie
            time.sleep(5)
            
            if self.backend_process.poll() is None:
                print("✅ Backend server started successfully")
                print("📍 URL: http://localhost:8000")
                print("📚 Docs: http://localhost:8000/docs")
                return True
            else:
                stdout, stderr = self.backend_process.communicate()
                print(f"❌ Backend server failed to start")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error starting backend: {e}")
            return False
    
    def start_frontend(self):
        """Inicia el servidor frontend"""
        print("\n🎨 Starting frontend server...")
        
        frontend_path = Path('frontend_nextjs')
        if not frontend_path.exists():
            print("❌ Frontend directory not found")
            return False
        
        try:
            # Verificar si node_modules existe
            if not (frontend_path / 'node_modules').exists():
                print("📦 Installing frontend dependencies...")
                install_cmd = ['npm', 'install']
                install_process = subprocess.run(
                    install_cmd,
                    cwd=frontend_path,
                    capture_output=True,
                    text=True
                )
                
                if install_process.returncode != 0:
                    print(f"❌ Failed to install dependencies: {install_process.stderr}")
                    return False
                
                print("✅ Dependencies installed")
            
            # Iniciar servidor de desarrollo
            cmd = ['npm', 'run', 'dev']
            
            print(f"Command: {' '.join(cmd)} (in {frontend_path})")
            
            self.frontend_process = subprocess.Popen(
                cmd,
                cwd=frontend_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Esperar un poco para que inicie
            time.sleep(10)
            
            if self.frontend_process.poll() is None:
                print("✅ Frontend server started successfully")
                print("📍 URL: http://localhost:3000")
                return True
            else:
                stdout, stderr = self.frontend_process.communicate()
                print(f"❌ Frontend server failed to start")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error starting frontend: {e}")
            return False
    
    def monitor_processes(self):
        """Monitorea los procesos en ejecución"""
        print("\n📊 System monitoring started...")
        print("Press Ctrl+C to stop the system")
        print("-" * 50)
        
        try:
            while self.running:
                time.sleep(10)
                
                # Verificar backend
                backend_status = "✅" if self.backend_process and self.backend_process.poll() is None else "❌"
                
                # Verificar frontend
                frontend_status = "✅" if self.frontend_process and self.frontend_process.poll() is None else "❌"
                
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"[{current_time}] Backend: {backend_status} | Frontend: {frontend_status}")
                
                # Si algún proceso se detiene, intentar reiniciar
                if self.backend_process and self.backend_process.poll() is not None:
                    print("⚠️ Backend process stopped unexpectedly")
                    if input("Restart backend? (y/n): ").lower() == 'y':
                        self.start_backend()
                
                if self.frontend_process and self.frontend_process.poll() is not None:
                    print("⚠️ Frontend process stopped unexpectedly")
                    if input("Restart frontend? (y/n): ").lower() == 'y':
                        self.start_frontend()
                
        except KeyboardInterrupt:
            print("\n🛑 Shutdown requested by user")
            self.shutdown()
    
    def shutdown(self):
        """Detiene todos los procesos"""
        print("\n🛑 Shutting down system...")
        self.running = False
        
        # Terminar frontend
        if self.frontend_process:
            print("Stopping frontend server...")
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=10)
                print("✅ Frontend stopped")
            except subprocess.TimeoutExpired:
                print("⚠️ Frontend didn't stop gracefully, killing...")
                self.frontend_process.kill()
        
        # Terminar backend
        if self.backend_process:
            print("Stopping backend server...")
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=10)
                print("✅ Backend stopped")
            except subprocess.TimeoutExpired:
                print("⚠️ Backend didn't stop gracefully, killing...")
                self.backend_process.kill()
        
        print("✅ System shutdown complete")
    
    def show_system_info(self):
        """Muestra información del sistema"""
        print("\n" + "=" * 70)
        print("🎯 ENHANCED CTF SOLVER - COMPLETE SYSTEM v3.0")
        print("=" * 70)
        print("Components:")
        print("  🧠 Enhanced BERT Classification")
        print("  📚 Enhanced RAG with Real Writeups")
        print("  🤖 Multi-Agent Coordination System")
        print("  🌐 FastAPI Backend with Full REST API")
        print("  🎨 Next.js Frontend with Modern UI")
        print("  📊 Real-time Statistics and Monitoring")
        print("")
        print("Services:")
        print("  🔧 Backend API: http://localhost:8000")
        print("  📚 API Docs: http://localhost:8000/docs")
        print("  🎨 Frontend: http://localhost:3000")
        print("")
        print("Features:")
        print("  • Challenge solving with multiple strategies")
        print("  • Real-time system monitoring")
        print("  • Interactive web interface")
        print("  • File upload and processing")
        print("  • Performance analytics")
        print("  • Automatic fallback systems")
        print("=" * 70)
    
    def run(self):
        """Ejecuta el sistema completo"""
        print("🚀 ENHANCED CTF SOLVER - COMPLETE SYSTEM STARTUP")
        print("=" * 70)
        print(f"Timestamp: {datetime.now().isoformat()}")
        print("=" * 70)
        
        # Verificaciones previas
        if not self.check_dependencies():
            print("❌ Dependency check failed")
            return False
        
        if not self.check_ports():
            print("❌ Port check failed")
            return False
        
        # Mostrar información del sistema
        self.show_system_info()
        
        # Iniciar backend
        if not self.start_backend():
            print("❌ Failed to start backend")
            return False
        
        # Iniciar frontend
        if not self.start_frontend():
            print("❌ Failed to start frontend")
            self.shutdown()
            return False
        
        print("\n🎉 SYSTEM STARTUP COMPLETE!")
        print("=" * 70)
        print("🌐 Frontend: http://localhost:3000")
        print("🔧 Backend: http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/docs")
        print("=" * 70)
        
        # Configurar manejador de señales
        def signal_handler(signum, frame):
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Monitorear sistema
        try:
            self.monitor_processes()
        except Exception as e:
            print(f"❌ System monitoring error: {e}")
            self.shutdown()
            return False
        
        return True

def main():
    """Función principal"""
    manager = SystemManager()
    
    try:
        success = manager.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Startup interrupted by user")
        manager.shutdown()
        sys.exit(1)
    except Exception as e:
        print(f"❌ Critical startup error: {e}")
        manager.shutdown()
        sys.exit(1)

if __name__ == "__main__":
    main()