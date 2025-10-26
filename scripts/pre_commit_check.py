#!/usr/bin/env python3
"""
Pre-commit Check Script
Verifica que todo esté listo para commit/push a GitHub
"""

import os
import sys
from pathlib import Path
import subprocess
import json

def check_required_files():
    """Verifica que existan los archivos requeridos"""
    print("🔍 Checking required files...")
    
    required_files = [
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        ".gitignore",
        "phase3/README.md",
        "phase3/setup.py",
        "phase3/config.py",
        "phase3/frontend/package.json",
        "phase3/frontend/README.md",
        "multi_agent/README_PHASE_2_4.md",
        "PHASE_3_0_FINAL_STATUS.md"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"  ❌ Missing: {file_path}")
        else:
            print(f"  ✅ Found: {file_path}")
    
    return len(missing_files) == 0, missing_files

def check_sensitive_files():
    """Verifica que no haya archivos sensibles"""
    print("\n🔒 Checking for sensitive files...")
    
    sensitive_patterns = [
        "*.env",
        "**/.env*",
        "**/secrets.json",
        "**/api_keys.json",
        "**/*secret*",
        "**/*password*",
        "**/*.key",
        "**/*.pem"
    ]
    
    sensitive_found = []
    
    # Verificar archivos que podrían ser sensibles
    for pattern in sensitive_patterns:
        for file_path in Path(".").glob(pattern):
            if file_path.is_file():
                sensitive_found.append(str(file_path))
                print(f"  ⚠️ Sensitive file found: {file_path}")
    
    if not sensitive_found:
        print("  ✅ No sensitive files found")
    
    return len(sensitive_found) == 0, sensitive_found

def check_large_files():
    """Verifica archivos grandes que no deberían estar en Git"""
    print("\n📦 Checking for large files...")
    
    large_files = []
    max_size_mb = 10  # 10MB limit
    
    for file_path in Path(".").rglob("*"):
        if file_path.is_file():
            try:
                size_mb = file_path.stat().st_size / (1024 * 1024)
                if size_mb > max_size_mb:
                    large_files.append((str(file_path), size_mb))
                    print(f"  ⚠️ Large file: {file_path} ({size_mb:.1f}MB)")
            except:
                pass
    
    if not large_files:
        print("  ✅ No large files found")
    
    return len(large_files) == 0, large_files

def check_git_status():
    """Verifica el estado de Git"""
    print("\n📝 Checking Git status...")
    
    try:
        # Verificar si hay cambios sin commit
        result = subprocess.run(
            ["git", "status", "--porcelain"], 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            if result.stdout.strip():
                print("  ⚠️ Uncommitted changes found:")
                for line in result.stdout.strip().split('\n'):
                    print(f"    {line}")
                return False
            else:
                print("  ✅ No uncommitted changes")
                return True
        else:
            print("  ❌ Git status check failed")
            return False
            
    except FileNotFoundError:
        print("  ⚠️ Git not found - skipping Git checks")
        return True

def check_package_json():
    """Verifica package.json del frontend"""
    print("\n📦 Checking frontend package.json...")
    
    package_json_path = Path("phase3/frontend/package.json")
    
    if not package_json_path.exists():
        print("  ❌ package.json not found")
        return False
    
    try:
        with open(package_json_path) as f:
            package_data = json.load(f)
        
        required_fields = ["name", "version", "scripts", "dependencies"]
        missing_fields = []
        
        for field in required_fields:
            if field not in package_data:
                missing_fields.append(field)
        
        if missing_fields:
            print(f"  ❌ Missing fields: {missing_fields}")
            return False
        
        # Verificar scripts importantes
        required_scripts = ["dev", "build", "start"]
        missing_scripts = []
        
        for script in required_scripts:
            if script not in package_data.get("scripts", {}):
                missing_scripts.append(script)
        
        if missing_scripts:
            print(f"  ❌ Missing scripts: {missing_scripts}")
            return False
        
        print("  ✅ package.json is valid")
        return True
        
    except json.JSONDecodeError:
        print("  ❌ package.json is not valid JSON")
        return False
    except Exception as e:
        print(f"  ❌ Error checking package.json: {e}")
        return False

def check_python_syntax():
    """Verifica sintaxis de archivos Python importantes"""
    print("\n🐍 Checking Python syntax...")
    
    important_files = [
        "phase3/setup.py",
        "phase3/config.py",
        "phase3/scripts/start_backend.py",
        "phase3/scripts/test_system.py",
        "phase3/simple_backend.py",
        "phase3/mini_backend.py"
    ]
    
    syntax_errors = []
    
    for file_path in important_files:
        if Path(file_path).exists():
            try:
                with open(file_path) as f:
                    compile(f.read(), file_path, 'exec')
                print(f"  ✅ {file_path}")
            except SyntaxError as e:
                syntax_errors.append((file_path, str(e)))
                print(f"  ❌ {file_path}: {e}")
            except Exception as e:
                print(f"  ⚠️ {file_path}: Could not check ({e})")
        else:
            print(f"  ⚠️ {file_path}: File not found")
    
    return len(syntax_errors) == 0, syntax_errors

def generate_github_ready_report():
    """Genera reporte final de preparación para GitHub"""
    print("\n" + "="*50)
    print("📊 GITHUB READINESS REPORT")
    print("="*50)
    
    checks = [
        ("Required Files", check_required_files),
        ("Sensitive Files", check_sensitive_files),
        ("Large Files", check_large_files),
        ("Git Status", lambda: (check_git_status(), [])),
        ("Package.json", lambda: (check_package_json(), [])),
        ("Python Syntax", check_python_syntax)
    ]
    
    results = []
    all_passed = True
    
    for check_name, check_func in checks:
        try:
            passed, issues = check_func()
            results.append((check_name, passed, issues))
            if not passed:
                all_passed = False
        except Exception as e:
            results.append((check_name, False, [str(e)]))
            all_passed = False
    
    # Mostrar resultados
    for check_name, passed, issues in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {check_name}")
        
        if not passed and issues:
            for issue in issues[:3]:  # Mostrar máximo 3 issues
                print(f"    - {issue}")
    
    print(f"\n🎯 OVERALL: {'✅ READY FOR GITHUB' if all_passed else '❌ NEEDS ATTENTION'}")
    
    if all_passed:
        print("\n🚀 NEXT STEPS:")
        print("1. git add .")
        print("2. git commit -m 'feat: Phase 3.0 complete - production ready system'")
        print("3. git push origin main")
        print("4. Create release on GitHub")
    else:
        print("\n🔧 FIX REQUIRED:")
        print("Address the issues above before pushing to GitHub")
    
    return all_passed

def main():
    """Función principal"""
    print("🔍 PRE-COMMIT CHECK - GITHUB READINESS")
    print("="*50)
    
    # Verificar que estamos en el directorio correcto
    if not Path("phase3").exists():
        print("❌ Error: Run this script from the project root directory")
        sys.exit(1)
    
    # Ejecutar verificación completa
    ready = generate_github_ready_report()
    
    # Exit code para CI/CD
    sys.exit(0 if ready else 1)

if __name__ == "__main__":
    main()