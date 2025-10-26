#!/usr/bin/env python3
"""
Hybrid CTF Solver - Combina multi-agente con solver simple
Usa el sistema multi-agente primero, fallback al solver simple
"""

import sys
import os
from pathlib import Path
from datetime import datetime

# Importar ambos solvers
from solve_simple import solve_ctf_challenge as solve_simple
from solve import solve_ctf_simple as solve_multiagent

def solve_hybrid(challenge_file, nc_host=None, nc_port=None):
    """
    Solver híbrido que combina ambos enfoques
    1. Intenta multi-agente primero
    2. Si falla, usa solver simple
    """
    
    print(f"🎯 HYBRID SOLVER: {challenge_file}")
    print("=" * 50)
    
    # Intentar multi-agente primero
    print("🤖 PHASE 1: Multi-Agent System")
    print("-" * 30)
    
    try:
        flag = solve_multiagent(challenge_file, nc_host, nc_port)
        if flag and 'flag{' in flag.lower():
            print(f"✅ Multi-Agent SUCCESS: {flag}")
            return flag
        else:
            print("❌ Multi-Agent failed or no flag found")
    except Exception as e:
        print(f"❌ Multi-Agent error: {e}")
    
    # Fallback al solver simple
    print("\n🔧 PHASE 2: Simple Solver (Fallback)")
    print("-" * 30)
    
    try:
        flag = solve_simple(challenge_file)
        if flag and 'flag{' in flag.lower():
            print(f"✅ Simple Solver SUCCESS: {flag}")
            return flag
        else:
            print("❌ Simple Solver failed or no flag found")
    except Exception as e:
        print(f"❌ Simple Solver error: {e}")
    
    return None

def main():
    """Función principal"""
    
    if len(sys.argv) < 2:
        print("Usage: python solve_hybrid.py <challenge.py> [host] [port]")
        sys.exit(1)
    
    challenge_file = sys.argv[1]
    nc_host = sys.argv[2] if len(sys.argv) > 2 else None
    nc_port = int(sys.argv[3]) if len(sys.argv) > 3 else None
    
    if not os.path.exists(challenge_file):
        print(f"❌ File not found: {challenge_file}")
        sys.exit(1)
    
    print("🚀 HYBRID CTF SOLVER")
    print("Multi-Agent System + Simple Solver Fallback")
    print()
    
    start_time = datetime.now()
    flag = solve_hybrid(challenge_file, nc_host, nc_port)
    end_time = datetime.now()
    
    print("\n" + "=" * 50)
    if flag:
        print("🏆 CHALLENGE SOLVED!")
        print(f"🎯 FLAG: {flag}")
        print(f"⏱️ Total time: {(end_time - start_time).total_seconds():.2f}s")
        sys.exit(0)
    else:
        print("💔 CHALLENGE NOT SOLVED")
        print("Both multi-agent and simple solver failed")
        print(f"⏱️ Time spent: {(end_time - start_time).total_seconds():.2f}s")
        sys.exit(1)

if __name__ == "__main__":
    main()