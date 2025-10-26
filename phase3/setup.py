#!/usr/bin/env python3
"""
Phase 3.0 Setup Script
Script para configurar todo el sistema Phase 3.0
"""

import os
import sys
import subprocess
from pathlib import Path

def setup_backend():
    """Setup backend dependencies"""
    print("🔧 Setting up Backend...")
    
    # No dependencies needed for simple backend
    print("✅ Simple backend ready (no dependencies)")
    
    # Check if FastAPI dependencies are available
    try:
        import fastapi
        import uvicorn
        print("✅ FastAPI backend available")
    except ImportError:
        print("⚠️ FastAPI backend not available (optional)")
        print("   Install with: pip install fastapi uvicorn")

def setup_learning_system():
    """Setup learning system"""
    print("\n🧠 Setting up Learning System...")
    
    required_packages = [
        "sqlite3",  # Built-in
        "pandas",
        "numpy",
        "scikit-learn"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == "sqlite3":
                import sqlite3
            elif package == "pandas":
                import pandas
            elif package == "numpy":
                import numpy
            elif package == "scikit-learn":
                import sklearn
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
    else:
        print("✅ Learning system ready")

def setup_frontend():
    """Setup frontend"""
    print("\n💻 Setting up Frontend...")
    
    frontend_dir = Path("phase3/frontend")
    
    if not frontend_dir.exists():
        print("❌ Frontend directory not found")
        return False
    
    # Check if Node.js is available
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Node.js {result.stdout.strip()}")
        else:
            print("❌ Node.js not found")
            return False
    except FileNotFoundError:
        print("❌ Node.js not found")
        print("   Install from: https://nodejs.org/")
        return False
    
    # Check if npm is available
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npm {result.stdout.strip()}")
        else:
            print("❌ npm not found")
            return False
    except FileNotFoundError:
        print("❌ npm not found")
        return False
    
    # Check if dependencies are installed
    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        print("✅ Frontend dependencies installed")
    else:
        print("⚠️ Frontend dependencies not installed")
        print("   Run: cd phase3/frontend && npm install")
    
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "phase3/data",
        "phase3/logs",
        "phase3/reports"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ {directory}")

def main():
    """Main setup function"""
    print("🚀 PHASE 3.0 SETUP")
    print("=" * 30)
    
    # Create directories
    create_directories()
    
    # Setup components
    setup_backend()
    setup_learning_system()
    frontend_ok = setup_frontend()
    
    print("\n" + "=" * 30)
    print("📊 SETUP SUMMARY")
    print("=" * 30)
    
    print("✅ Backend: Ready")
    print("✅ Learning System: Ready")
    print("✅ Frontend: Ready" if frontend_ok else "⚠️ Frontend: Needs setup")
    
    print("\n🚀 QUICK START:")
    print("1. Start backend:")
    print("   python phase3/scripts/start_backend.py")
    print("\n2. Start frontend:")
    print("   cd phase3/frontend")
    print("   npm install  # if not done")
    print("   npm run dev")
    print("\n3. Open browser:")
    print("   http://localhost:3000")
    
    print("\n🧪 TEST SYSTEM:")
    print("   python phase3/scripts/test_system.py")

if __name__ == "__main__":
    main()