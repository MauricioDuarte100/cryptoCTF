#!/usr/bin/env python3
"""
Clean Repository for GitHub
Limpia el repositorio para subirlo a GitHub sin archivos grandes
"""

import os
import shutil
import subprocess
from pathlib import Path

def remove_large_files():
    """Elimina archivos grandes que no deben estar en Git"""
    print("🧹 Cleaning large files...")
    
    # Archivos y directorios grandes a eliminar
    large_items = [
        "venv/",
        "env/",
        ".venv/",
        "RsaCtfTool/",
        "ml_phase2/trained_model/",
        "ml_phase2/model_checkpoints/",
        "rag/data/chroma_db/",
        "phase3/data/",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "node_modules/",
        ".next/",
        "dist/",
        "build/"
    ]
    
    removed_count = 0
    
    for item in large_items:
        for path in Path(".").glob(item):
            if path.exists():
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                        print(f"  ✅ Removed directory: {path}")
                    else:
                        path.unlink()
                        print(f"  ✅ Removed file: {path}")
                    removed_count += 1
                except Exception as e:
                    print(f"  ⚠️ Could not remove {path}: {e}")
    
    print(f"  📊 Removed {removed_count} items")
    return removed_count > 0

def remove_sensitive_files():
    """Elimina archivos sensibles"""
    print("\n🔒 Cleaning sensitive files...")
    
    sensitive_files = [
        ".env",
        ".env.local",
        ".env.production",
        "config/secrets.py",
        "**/api_keys.json",
        "**/secrets.json"
    ]
    
    removed_count = 0
    
    for pattern in sensitive_files:
        for path in Path(".").glob(pattern):
            if path.exists() and path.is_file():
                try:
                    path.unlink()
                    print(f"  ✅ Removed: {path}")
                    removed_count += 1
                except Exception as e:
                    print(f"  ⚠️ Could not remove {path}: {e}")
    
    print(f"  📊 Removed {removed_count} sensitive files")
    return removed_count > 0

def create_example_env():
    """Crea archivo .env.example"""
    print("\n📝 Creating .env.example...")
    
    env_example_content = """# Multi-Agent CTF System Environment Variables

# Google Gemini API Key (required)
GOOGLE_API_KEY=your_gemini_api_key_here

# Backend Configuration
API_HOST=localhost
API_PORT=8000

# Frontend Configuration  
NEXT_PUBLIC_API_URL=http://localhost:8000

# Learning System Configuration
PHASE3_ENV=development
DEBUG=true

# Database Configuration
DATABASE_URL=sqlite:///./phase3/data/feedback.db

# Optional: External Tools
RSACTFTOOL_PATH=./RsaCtfTool
SAGEMATH_PATH=/usr/bin/sage
"""
    
    with open(".env.example", "w") as f:
        f.write(env_example_content)
    
    print("  ✅ Created .env.example")

def optimize_git_history():
    """Optimiza el historial de Git"""
    print("\n🔧 Optimizing Git history...")
    
    try:
        # Git garbage collection
        result = subprocess.run(["git", "gc", "--aggressive"], capture_output=True, text=True)
        if result.returncode == 0:
            print("  ✅ Git garbage collection completed")
        else:
            print(f"  ⚠️ Git gc failed: {result.stderr}")
        
        # Verificar tamaño del repositorio
        result = subprocess.run(["git", "count-objects", "-vH"], capture_output=True, text=True)
        if result.returncode == 0:
            print("  📊 Repository size:")
            for line in result.stdout.split('\n'):
                if 'size-pack' in line or 'size' in line:
                    print(f"    {line}")
        
    except FileNotFoundError:
        print("  ⚠️ Git not found - skipping optimization")

def create_github_workflows():
    """Crea workflows de GitHub Actions"""
    print("\n⚙️ Creating GitHub workflows...")
    
    workflows_dir = Path(".github/workflows")
    workflows_dir.mkdir(parents=True, exist_ok=True)
    
    # CI workflow
    ci_workflow = """name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    - name: Test learning system
      run: python phase3/test_learning_system.py
    - name: Test multi-agent system
      run: python multi_agent/simple_test.py

  test-frontend:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
    - name: Install dependencies
      run: |
        cd phase3/frontend
        npm ci
    - name: Type check
      run: |
        cd phase3/frontend
        npm run type-check
    - name: Build
      run: |
        cd phase3/frontend
        npm run build
"""
    
    with open(workflows_dir / "ci.yml", "w") as f:
        f.write(ci_workflow)
    
    print("  ✅ Created CI workflow")

def main():
    """Función principal de limpieza"""
    print("🧹 CLEANING REPOSITORY FOR GITHUB")
    print("="*50)
    
    # Verificar que estamos en el directorio correcto
    if not Path("phase3").exists():
        print("❌ Error: Run this script from the project root directory")
        return
    
    # Ejecutar limpieza
    steps = [
        ("Remove Large Files", remove_large_files),
        ("Remove Sensitive Files", remove_sensitive_files),
        ("Create Example Env", create_example_env),
        ("Create GitHub Workflows", create_github_workflows),
        ("Optimize Git History", optimize_git_history)
    ]
    
    for step_name, step_func in steps:
        try:
            step_func()
        except Exception as e:
            print(f"  ❌ {step_name} failed: {e}")
    
    print("\n" + "="*50)
    print("✅ REPOSITORY CLEANED")
    print("="*50)
    
    print("\n🚀 READY FOR GITHUB:")
    print("1. git add .")
    print("2. git commit -m 'feat: Phase 3.0 production ready system'")
    print("3. git push origin main")
    
    print("\n💡 TIPS:")
    print("- Repository size should now be much smaller")
    print("- All sensitive files removed")
    print("- .env.example created for users")
    print("- GitHub Actions workflows added")

if __name__ == "__main__":
    main()