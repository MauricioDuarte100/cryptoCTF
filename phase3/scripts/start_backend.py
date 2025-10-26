#!/usr/bin/env python3
"""
Start Backend Script
Script unificado para iniciar cualquier backend
"""

import sys
import os
import argparse
from pathlib import Path

# Añadir el directorio raíz al path
root_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(root_dir))

def start_simple_backend():
    """Inicia el backend simple"""
    print("🚀 Starting Simple Backend (Recommended)")
    print("=" * 40)
    
    try:
        from phase3.simple_backend import run_server
        run_server()
    except ImportError:
        # Fallback: ejecutar directamente
        import subprocess
        backend_path = root_dir / "phase3" / "simple_backend.py"
        subprocess.run([sys.executable, str(backend_path)])

def start_mini_backend():
    """Inicia el backend mini"""
    print("⚡ Starting Mini Backend (Ultra Fast)")
    print("=" * 40)
    
    try:
        from phase3.mini_backend import run_server
        run_server()
    except ImportError:
        import subprocess
        backend_path = root_dir / "phase3" / "mini_backend.py"
        subprocess.run([sys.executable, str(backend_path)])

def start_fastapi_backend():
    """Inicia el backend FastAPI"""
    print("🏗️ Starting FastAPI Backend (Full Featured)")
    print("=" * 40)
    
    try:
        import uvicorn
        # Cambiar al directorio del backend
        backend_dir = root_dir / "phase3" / "backend"
        os.chdir(backend_dir)
        
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except ImportError:
        print("❌ FastAPI dependencies not installed")
        print("Install with: pip install fastapi uvicorn")

def main():
    parser = argparse.ArgumentParser(description="Start Multi-Agent CTF Backend")
    parser.add_argument(
        "--backend", 
        choices=["simple", "mini", "fastapi"], 
        default="simple",
        help="Backend type to start (default: simple)"
    )
    
    args = parser.parse_args()
    
    print("🤖 Multi-Agent CTF System - Backend Starter")
    print("=" * 50)
    
    if args.backend == "simple":
        start_simple_backend()
    elif args.backend == "mini":
        start_mini_backend()
    elif args.backend == "fastapi":
        start_fastapi_backend()

if __name__ == "__main__":
    main()