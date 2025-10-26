#!/usr/bin/env python3
"""
START ENHANCED SYSTEM
Script para iniciar el sistema CTF completo mejorado
"""

import sys
import os
import time
import subprocess
import threading
from pathlib import Path
from datetime import datetime

def check_dependencies():
    """Verifica dependencias del sistema"""
    print("🔍 Checking system dependencies...")
    
    required_packages = [
        'fastapi',
        'uvicorn',
        'torch',
        'transformers',
        'sentence-transformers',
        'faiss-cpu',
        'numpy',
        'pandas',
        'requests',
        'beautifulsoup4'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True

def check_data_files():
    """Verifica archivos de datos necesarios"""
    print("\n📁 Checking data files...")
    
    required_files = [
        'ml_phase2/bert_classifier_enhanced.py',
        'rag/rag_engine_enhanced.py',
        'multi_agent/coordination/coordinator_enhanced.py',
        'backend_fastapi_enhanced.py'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️ Missing files: {', '.join(missing_files)}")
        return False
    
    return True

def prepare_environment():
    """Prepara el entorno para el sistema"""
    print("\n🔧 Preparing environment...")
    
    # Crear directorios necesarios
    directories = [
        'data/embeddings',
        'data/models',
        'data/writeups',
        'logs',
        'temp'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created/verified: {directory}")
    
    # Verificar variables de entorno
    env_vars = {
        'GEMINI_API_KEY': 'Gemini API key for LLM functionality',
        'HUGGINGFACE_TOKEN': 'HuggingFace token for model downloads (optional)'
    }
    
    print("\n🔑 Environment variables:")
    for var, description in env_vars.items():
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: {'*' * min(len(value), 10)}")
        else:
            print(f"⚠️ {var}: Not set ({description})")
    
    return True

def test_components():
    """Test rápido de componentes principales"""
    print("\n🧪 Testing core components...")
    
    try:
        # Test BERT
        print("Testing Enhanced BERT...")
        from ml_phase2.bert_classifier_enhanced import get_bert_classifier
        bert = get_bert_classifier()
        if bert:
            print("✅ Enhanced BERT: Ready")
        else:
            print("⚠️ Enhanced BERT: Not ready")
    except Exception as e:
        print(f"❌ Enhanced BERT: Error - {e}")
    
    try:
        # Test RAG
        print("Testing Enhanced RAG...")
        from rag.rag_engine_enhanced import get_enhanced_rag_engine
        rag = get_enhanced_rag_engine()
        if rag:
            stats = rag.get_statistics()
            if stats.get('available'):
                print("✅ Enhanced RAG: Ready")
            else:
                print("⚠️ Enhanced RAG: Data not available")
        else:
            print("⚠️ Enhanced RAG: Not ready")
    except Exception as e:
        print(f"❌ Enhanced RAG: Error - {e}")
    
    try:
        # Test Multi-Agent
        print("Testing Multi-Agent Coordinator...")
        from multi_agent.coordination.coordinator_enhanced import get_enhanced_coordinator
        coordinator = get_enhanced_coordinator()
        if coordinator and coordinator.is_ready:
            print("✅ Multi-Agent: Ready")
        else:
            print("⚠️ Multi-Agent: Not ready")
    except Exception as e:
        print(f"❌ Multi-Agent: Error - {e}")
    
    return True

def start_backend_server():
    """Inicia el servidor backend"""
    print("\n🚀 Starting backend server...")
    
    try:
        # Comando para iniciar el servidor
        cmd = [
            sys.executable, "-m", "uvicorn",
            "backend_fastapi_enhanced:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        
        # Iniciar en proceso separado
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Esperar un poco para que inicie
        time.sleep(3)
        
        # Verificar si está corriendo
        if process.poll() is None:
            print("✅ Backend server started successfully")
            print("📍 URL: http://localhost:8000")
            print("📚 Docs: http://localhost:8000/docs")
            return process
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Backend server failed to start")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return None
            
    except Exception as e:
        print(f"❌ Error starting backend: {e}")
        return None

def monitor_system(backend_process):
    """Monitorea el sistema en ejecución"""
    print("\n📊 System monitoring started...")
    print("Press Ctrl+C to stop the system")
    
    try:
        while True:
            time.sleep(10)
            
            # Verificar backend
            if backend_process and backend_process.poll() is not None:
                print("⚠️ Backend process stopped unexpectedly")
                break
            
            # Mostrar estado cada minuto
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"[{current_time}] System running... (Backend: {'✅' if backend_process and backend_process.poll() is None else '❌'})")
            
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
        
        # Terminar backend
        if backend_process:
            print("Stopping backend server...")
            backend_process.terminate()
            backend_process.wait()
            print("✅ Backend stopped")
        
        print("✅ System shutdown complete")

def show_system_info():
    """Muestra información del sistema"""
    print("\n" + "=" * 60)
    print("🎯 ENHANCED CTF SOLVER SYSTEM v3.0")
    print("=" * 60)
    print("Features:")
    print("  🧠 Enhanced BERT Classification")
    print("  📚 Enhanced RAG with Real Writeups")
    print("  🤖 Multi-Agent Coordination System")
    print("  🌐 FastAPI Backend with Full REST API")
    print("  📊 Real-time Statistics and Monitoring")
    print("  🔄 Automatic Fallback Systems")
    print("")
    print("Endpoints:")
    print("  🏠 Main: http://localhost:8000")
    print("  📚 Docs: http://localhost:8000/docs")
    print("  🔧 Admin: http://localhost:8000/redoc")
    print("  🎯 Solve: POST /api/solve")
    print("  📊 Status: GET /api/status")
    print("  📈 Stats: GET /api/statistics")
    print("=" * 60)

def main():
    """Función principal"""
    print("🚀 ENHANCED CTF SOLVER - SYSTEM STARTUP")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    # Verificaciones previas
    if not check_dependencies():
        print("❌ Dependency check failed")
        return False
    
    if not check_data_files():
        print("❌ Data files check failed")
        return False
    
    if not prepare_environment():
        print("❌ Environment preparation failed")
        return False
    
    if not test_components():
        print("❌ Component testing failed")
        return False
    
    # Mostrar información del sistema
    show_system_info()
    
    # Iniciar backend
    backend_process = start_backend_server()
    if not backend_process:
        print("❌ Failed to start backend server")
        return False
    
    # Monitorear sistema
    try:
        monitor_system(backend_process)
    except Exception as e:
        print(f"❌ System monitoring error: {e}")
        if backend_process:
            backend_process.terminate()
        return False
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Startup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Critical startup error: {e}")
        sys.exit(1)