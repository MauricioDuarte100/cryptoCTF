#!/usr/bin/env python3
"""
Fix Large Repository for GitHub
Limpia archivos grandes y optimiza el repositorio para GitHub
"""

import os
import subprocess
import shutil
from pathlib import Path

def run_command(cmd, cwd=None):
    """Ejecuta un comando y retorna el resultado"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def find_large_files():
    """Encuentra archivos grandes en el repositorio"""
    print("🔍 Finding large files...")
    
    large_files = []
    for root, dirs, files in os.walk("."):
        # Ignorar directorios de git y venv
        dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__', 'node_modules']]
        
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                if size > 50 * 1024 * 1024:  # 50MB
                    large_files.append((file_path, size))
            except:
                pass
    
    large_files.sort(key=lambda x: x[1], reverse=True)
    
    for file_path, size in large_files[:10]:
        size_mb = size / (1024 * 1024)
        print(f"  📁 {file_path}: {size_mb:.1f} MB")
    
    return large_files

def clean_git_history():
    """Limpia el historial de git de archivos grandes"""
    print("\n🧹 Cleaning git history...")
    
    # Limpiar archivos grandes del historial
    large_patterns = [
        "*.pkl",
        "*.model",
        "*.bin",
        "*.h5",
        "*.weights",
        "venv/*",
        "*/venv/*",
        "RsaCrfTool/*",
        "*/RsaCrfTool/*",
        "trained_model/*",
        "*/trained_model/*",
        "model_checkpoints/*",
        "*/model_checkpoints/*",
        "chroma_db/*",
        "*/chroma_db/*",
        "data/*",
        "*/data/*"
    ]
    
    for pattern in large_patterns:
        success, stdout, stderr = run_command(f'git filter-branch --force --index-filter "git rm --cached --ignore-unmatch {pattern}" --prune-empty --tag-name-filter cat -- --all')
        if success:
            print(f"  ✅ Cleaned {pattern}")
        else:
            print(f"  ⚠️ Could not clean {pattern}")
    
    # Limpiar referencias
    success, _, _ = run_command("git for-each-ref --format='delete %(refname)' refs/original | git update-ref --stdin")
    success, _, _ = run_command("git reflog expire --expire=now --all")
    success, _, _ = run_command("git gc --prune=now --aggressive")
    
    print("  ✅ Git history cleaned")

def create_gitattributes():
    """Crea .gitattributes para archivos grandes"""
    print("\n📝 Creating .gitattributes...")
    
    gitattributes_content = """# Large files
*.pkl filter=lfs diff=lfs merge=lfs -text
*.model filter=lfs diff=lfs merge=lfs -text
*.bin filter=lfs diff=lfs merge=lfs -text
*.h5 filter=lfs diff=lfs merge=lfs -text
*.weights filter=lfs diff=lfs merge=lfs -text

# Archives
*.zip filter=lfs diff=lfs merge=lfs -text
*.tar.gz filter=lfs diff=lfs merge=lfs -text
*.rar filter=lfs diff=lfs merge=lfs -text

# Media files
*.mp4 filter=lfs diff=lfs merge=lfs -text
*.avi filter=lfs diff=lfs merge=lfs -text
*.mov filter=lfs diff=lfs merge=lfs -text
*.png filter=lfs diff=lfs merge=lfs -text
*.jpg filter=lfs diff=lfs merge=lfs -text
*.jpeg filter=lfs diff=lfs merge=lfs -text
"""
    
    with open(".gitattributes", "w") as f:
        f.write(gitattributes_content)
    
    print("  ✅ .gitattributes created")

def optimize_repository():
    """Optimiza el repositorio"""
    print("\n⚙️ Optimizing repository...")
    
    # Repack agresivo
    success, _, _ = run_command("git repack -ad --depth=250 --window=250")
    if success:
        print("  ✅ Repository repacked")
    
    # Garbage collection
    success, _, _ = run_command("git gc --aggressive --prune=now")
    if success:
        print("  ✅ Garbage collection completed")
    
    # Verificar tamaño final
    success, stdout, _ = run_command("git count-objects -vH")
    if success:
        print(f"  📊 Final repository size:")
        for line in stdout.split('\n'):
            if 'size' in line:
                print(f"    {line}")

def main():
    """Función principal"""
    print("🔧 FIXING LARGE REPOSITORY FOR GITHUB")
    print("=" * 50)
    
    # Encontrar archivos grandes
    large_files = find_large_files()
    
    if large_files:
        print(f"\n⚠️ Found {len(large_files)} large files")
        
        # Crear .gitattributes
        create_gitattributes()
        
        # Limpiar historial de git
        clean_git_history()
    
    # Optimizar repositorio
    optimize_repository()
    
    print("\n" + "=" * 50)
    print("✅ REPOSITORY OPTIMIZATION COMPLETE")
    print("=" * 50)
    
    print("\n🚀 NEXT STEPS:")
    print("1. git add .")
    print("2. git commit -m 'fix: optimize repository size'")
    print("3. git push origin main --force-with-lease")
    
    print("\n💡 TIPS:")
    print("- Repository should now be much smaller")
    print("- Use --force-with-lease for safer force push")
    print("- Consider using Git LFS for future large files")

if __name__ == "__main__":
    main()