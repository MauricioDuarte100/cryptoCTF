#!/usr/bin/env python3
"""
CTF Challenge Solver - Interface Simplificada
Exactamente lo que pediste: archivo.py + host:port → flag automática

Uso:
    python solve.py challenge.py
    python solve.py challenge.py ctf.server.com 1337
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Añadir paths necesarios
sys.path.append('.')
sys.path.append('multi_agent')
sys.path.append('src')

def solve_ctf_simple(challenge_file, nc_host=None, nc_port=None):
    """
    EXACTAMENTE lo que pediste:
    - Recibe: archivo.py + (opcional) host:port
    - Devuelve: flag automáticamente
    """
    
    print(f"🎯 SOLVING CTF CHALLENGE: {challenge_file}")
    print("=" * 50)
    
    # Verificar que el archivo existe
    if not os.path.exists(challenge_file):
        print(f"❌ Error: File {challenge_file} not found")
        return None
    
    # Leer archivo del challenge
    try:
        with open(challenge_file, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"✅ Challenge file loaded: {len(content)} characters")
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None
    
    # Preparar datos del challenge
    challenge_data = {
        'description': f"Challenge from {challenge_file}",
        'files': [{
            'name': Path(challenge_file).name,
            'content': content
        }],
        'nc_host': nc_host or '',
        'nc_port': nc_port or 0
    }
    
    if nc_host and nc_port:
        print(f"🌐 Target server: {nc_host}:{nc_port}")
    
    # Intentar importar y usar el sistema multi-agente
    try:
        from multi_agent.coordination.coordinator import MultiAgentCoordinator
        print("🤖 Loading Multi-Agent System...")
        
        coordinator = MultiAgentCoordinator()
        print("✅ Multi-Agent System loaded")
        
        # RESOLVER CHALLENGE (aquí es donde pasa la magia)
        print("\n🔍 ANALYZING CHALLENGE...")
        
        # Preparar archivos en el formato correcto
        files = challenge_data['files']
        description = challenge_data['description']
        
        result = coordinator.solve_challenge(description, files)
        
        # DEVOLVER RESULTADO
        if result and result.get('success'):
            flag = result.get('flag', 'No flag found')
            print(f"\n🎉 SUCCESS!")
            print(f"✅ FLAG: {flag}")
            print(f"📊 Strategy used: {result.get('strategy', 'Unknown')}")
            print(f"⏱️ Time taken: {result.get('time_taken', 'Unknown')}s")
            return flag
        else:
            print(f"\n❌ FAILED TO SOLVE")
            print(f"💡 Reason: {result.get('error', 'Unknown error')}")
            return None
            
    except ImportError as e:
        print(f"❌ Multi-agent system not available: {e}")
        print("💡 Trying fallback to simple agent...")
        
        # Fallback al agente simple
        try:
            from src.core.simple_agent import SimpleAgent
            
            agent = SimpleAgent()
            print("✅ Simple agent loaded")
            
            # Analizar y resolver
            result = agent.solve_challenge(challenge_data)
            
            if result and result.get('success'):
                flag = result.get('flag', 'No flag found')
                print(f"\n🎉 SUCCESS!")
                print(f"✅ FLAG: {flag}")
                return flag
            else:
                print(f"\n❌ FAILED TO SOLVE")
                return None
                
        except ImportError as e2:
            print(f"❌ Simple agent also not available: {e2}")
            print("💡 Please ensure the project is properly set up")
            return None
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def main():
    """Función principal - CLI interface"""
    
    print("🚀 CTF CHALLENGE SOLVER")
    print("Automated CTF Challenge Solver with Multi-Agent System")
    print()
    
    # Verificar argumentos
    if len(sys.argv) < 2:
        print("❌ Usage: python solve.py <challenge.py> [host] [port]")
        print()
        print("Examples:")
        print("  python solve.py examples/rsa_basic/chall.py")
        print("  python solve.py challenge.py ctf.server.com 1337")
        print("  python solve.py crypto_challenge.py 192.168.1.100 9999")
        sys.exit(1)
    
    # Parsear argumentos
    challenge_file = sys.argv[1]
    nc_host = sys.argv[2] if len(sys.argv) > 2 else None
    nc_port = int(sys.argv[3]) if len(sys.argv) > 3 else None
    
    # Mostrar información
    print(f"📁 Challenge file: {challenge_file}")
    if nc_host and nc_port:
        print(f"🌐 Netcat target: {nc_host}:{nc_port}")
    else:
        print("🔍 Local analysis mode (no netcat)")
    print()
    
    # Resolver challenge
    start_time = datetime.now()
    flag = solve_ctf_simple(challenge_file, nc_host, nc_port)
    end_time = datetime.now()
    
    # Resultado final
    print("\n" + "=" * 50)
    if flag:
        print("🏆 CHALLENGE SOLVED SUCCESSFULLY!")
        print(f"🎯 FLAG: {flag}")
        print(f"⏱️ Total time: {(end_time - start_time).total_seconds():.2f}s")
        
        # Guardar resultado
        result_data = {
            'challenge_file': challenge_file,
            'nc_host': nc_host,
            'nc_port': nc_port,
            'flag': flag,
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'time_taken': (end_time - start_time).total_seconds()
        }
        
        # Guardar en archivo de resultados
        results_file = 'solve_results.json'
        try:
            if os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    results = json.load(f)
            else:
                results = []
            
            results.append(result_data)
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"📝 Result saved to {results_file}")
        except:
            pass
        
        sys.exit(0)
    else:
        print("💔 CHALLENGE NOT SOLVED")
        print("💡 Try with different parameters or check the challenge file")
        print(f"⏱️ Time spent: {(end_time - start_time).total_seconds():.2f}s")
        sys.exit(1)

if __name__ == "__main__":
    main()