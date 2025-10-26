#!/usr/bin/env python3
"""
Script principal para ejecutar CTF Crypto Agent
Punto de entrada unificado para todas las funcionalidades
"""

import sys
import argparse
import os
from pathlib import Path

def main():
    """Función principal con menú de opciones"""
    
    parser = argparse.ArgumentParser(
        description="CTF Crypto Agent - Gemini AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python run.py web                          # Iniciar interfaz web
  python run.py solve -d "RSA challenge"     # Resolver desde CLI
  python run.py test                         # Ejecutar pruebas
  python run.py benchmark                    # Ejecutar benchmark
  python run.py setup                       # Configurar dependencias
  python run.py config                      # Mostrar configuración
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comando: web
    web_parser = subparsers.add_parser('web', help='Iniciar interfaz web')
    web_parser.add_argument('--host', default='127.0.0.1', help='Host para la web UI')
    web_parser.add_argument('--port', type=int, default=5000, help='Puerto para la web UI')
    web_parser.add_argument('--debug', action='store_true', help='Modo debug')
    
    # Comando: solve
    solve_parser = subparsers.add_parser('solve', help='Resolver desafío desde CLI')
    solve_parser.add_argument('-d', '--description', required=True, help='Descripción del desafío')
    solve_parser.add_argument('-f', '--files', nargs='+', help='Archivos del desafío')
    solve_parser.add_argument('--host', help='Host netcat')
    solve_parser.add_argument('--port', type=int, help='Puerto netcat')
    solve_parser.add_argument('--max-steps', type=int, default=15, help='Máximo de pasos')
    solve_parser.add_argument('-o', '--output', help='Archivo de salida JSON')
    solve_parser.add_argument('--verbose', '-v', action='store_true', help='Salida detallada')
    
    # Comando: test
    test_parser = subparsers.add_parser('test', help='Ejecutar pruebas')
    test_parser.add_argument('--example', help='Probar ejemplo específico')
    test_parser.add_argument('--verbose', '-v', action='store_true', help='Salida detallada')
    
    # Comando: benchmark
    benchmark_parser = subparsers.add_parser('benchmark', help='Ejecutar benchmark')
    benchmark_parser.add_argument('--max-challenges', type=int, help='Máximo número de desafíos')
    benchmark_parser.add_argument('--types', nargs='+', help='Filtrar por tipos de desafío')
    benchmark_parser.add_argument('--difficulties', nargs='+', help='Filtrar por dificultades')
    benchmark_parser.add_argument('--no-db', action='store_true', help='No registrar en base de datos')
    benchmark_parser.add_argument('--output', help='Archivo de salida')
    
    # Comando: setup
    setup_parser = subparsers.add_parser('setup', help='Configurar dependencias')
    setup_parser.add_argument('--system', action='store_true', help='Instalar deps del sistema')
    setup_parser.add_argument('--python', action='store_true', help='Instalar deps Python')
    setup_parser.add_argument('--tools', action='store_true', help='Clonar herramientas')
    setup_parser.add_argument('--all', action='store_true', help='Instalar todo')
    
    # Comando: config
    config_parser = subparsers.add_parser('config', help='Mostrar configuración')
    config_parser.add_argument('--validate', action='store_true', help='Validar configuración')
    config_parser.add_argument('--summary', action='store_true', help='Mostrar resumen')
    
    # Comando: examples
    examples_parser = subparsers.add_parser('examples', help='Gestionar ejemplos')
    examples_parser.add_argument('--list', action='store_true', help='Listar ejemplos')
    examples_parser.add_argument('--create', help='Crear nuevo ejemplo')
    examples_parser.add_argument('--run', help='Ejecutar ejemplo específico')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Ejecutar comando
    try:
        if args.command == 'web':
            return run_web(args)
        elif args.command == 'solve':
            return run_solve(args)
        elif args.command == 'test':
            return run_test(args)
        elif args.command == 'benchmark':
            return run_benchmark(args)
        elif args.command == 'setup':
            return run_setup(args)
        elif args.command == 'config':
            return run_config(args)
        elif args.command == 'examples':
            return run_examples(args)
        else:
            print(f"❌ Comando desconocido: {args.command}")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️  Interrumpido por el usuario")
        return 1
    except Exception as e:
        print(f"💥 Error: {e}")
        if args.command in ['solve', 'test'] and hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        return 1

def run_web(args):
    """Ejecuta interfaz web"""
    print("🌐 Iniciando interfaz web...")
    
    try:
        from src.web.web_interface import run_web_interface
        run_web_interface(host=args.host, port=args.port, debug=args.debug)
        return 0
    except ImportError as e:
        print(f"❌ Error importando web interface: {e}")
        return 1

def run_solve(args):
    """Ejecuta resolución de desafío"""
    print("🔍 Resolviendo desafío...")
    
    try:
        from src.core.agent import solve_ctf_challenge
        import json
        
        # Cargar archivos
        files = []
        if args.files:
            for file_path in args.files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        files.append({
                            "name": os.path.basename(file_path),
                            "content": f.read()
                        })
                except Exception as e:
                    print(f"⚠️  Error cargando {file_path}: {e}")
        
        # Resolver
        result = solve_ctf_challenge(
            description=args.description,
            files=files,
            nc_host=args.host or "",
            nc_port=args.port or 0,
            max_steps=args.max_steps
        )
        
        # Mostrar resultado
        if result["success"]:
            print(f"✅ Flag encontrada: {result['flag']}")
        else:
            print("❌ No se pudo resolver el desafío")
        
        if args.verbose:
            print(f"\n📊 Detalles:")
            print(f"- Tipo: {result.get('challenge_type', 'Unknown')}")
            print(f"- Confianza: {result.get('confidence', 0):.2f}")
            print(f"- Pasos: {result.get('steps_used', 0)}")
        
        # Guardar resultado
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"💾 Resultado guardado en: {args.output}")
        
        return 0 if result["success"] else 1
        
    except ImportError as e:
        print(f"❌ Error importando agente: {e}")
        return 1

def run_test(args):
    """Ejecuta pruebas"""
    print("🧪 Ejecutando pruebas...")
    
    try:
        if args.example:
            # Probar ejemplo específico
            from src.tests.test_agent import load_challenge_files
            from src.core.agent import solve_ctf_challenge
            
            files = load_challenge_files(f"examples/{args.example}")
            if not files:
                print(f"❌ Ejemplo no encontrado: {args.example}")
                return 1
            
            result = solve_ctf_challenge(
                description=f"Test example: {args.example}",
                files=files,
                max_steps=10
            )
            
            if result["success"]:
                print(f"✅ Ejemplo {args.example} pasó")
                return 0
            else:
                print(f"❌ Ejemplo {args.example} falló")
                return 1
        else:
            # Ejecutar todas las pruebas
            from src.tests.test_agent import main as test_main
            return 0 if test_main() else 1
            
    except ImportError as e:
        print(f"❌ Error importando tests: {e}")
        return 1

def run_benchmark(args):
    """Ejecuta benchmark"""
    print("📊 Ejecutando benchmark...")
    
    try:
        from src.benchmark.benchmark import CTFBenchmark
        
        benchmark = CTFBenchmark(db_logging=not args.no_db)
        
        report = benchmark.run_benchmark(
            max_challenges=args.max_challenges,
            challenge_types=args.types,
            difficulties=args.difficulties
        )
        
        # Guardar en archivo si se especifica
        if args.output and report:
            import json
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"💾 Reporte guardado en: {args.output}")
        
        return 0 if report and report.get('success_rate', 0) > 0 else 1
        
    except ImportError as e:
        print(f"❌ Error importando benchmark: {e}")
        return 1

def run_setup(args):
    """Ejecuta setup"""
    print("🔧 Configurando dependencias...")
    
    try:
        from utils.scripts.install_dependencies import main as setup_main
        return 0 if setup_main() else 1
    except ImportError as e:
        print(f"❌ Error importando setup: {e}")
        return 1

def run_config(args):
    """Muestra configuración"""
    try:
        from src.config.config import config
        
        if args.validate:
            errors = config.validate()
            if errors:
                print("❌ Errores de configuración:")
                for error in errors:
                    print(f"   - {error}")
                return 1
            else:
                print("✅ Configuración válida")
                return 0
        
        if args.summary:
            summary = config.get_summary()
            print("📋 Resumen de configuración:")
            for key, value in summary.items():
                status = "✅" if value else "❌"
                print(f"   {status} {key}: {value}")
        else:
            print("⚙️  Configuración actual:")
            print(f"   - Modelo Gemini: {config.GEMINI_MODEL}")
            print(f"   - Max iteraciones: {config.MAX_ITERATIONS}")
            print(f"   - Cache habilitado: {config.ENABLE_CACHE}")
            print(f"   - Web host: {config.WEB_HOST}:{config.WEB_PORT}")
            print(f"   - RsaCtfTool: {'✅' if Path(config.RSACTFTOOL_PATH).exists() else '❌'}")
        
        return 0
        
    except ImportError as e:
        print(f"❌ Error importando config: {e}")
        return 1

def run_examples(args):
    """Gestiona ejemplos"""
    examples_dir = Path("examples")
    
    if args.list:
        print("📁 Ejemplos disponibles:")
        if examples_dir.exists():
            for example_dir in examples_dir.iterdir():
                if example_dir.is_dir():
                    files = list(example_dir.glob("*.py"))
                    print(f"   📂 {example_dir.name} ({len(files)} archivos)")
        else:
            print("   No hay ejemplos disponibles")
        return 0
    
    if args.run:
        try:
            from src.tests.test_agent import load_challenge_files
            from src.core.agent import solve_ctf_challenge
            
            files = load_challenge_files(f"examples/{args.run}")
            if not files:
                print(f"❌ Ejemplo no encontrado: {args.run}")
                return 1
            
            print(f"🚀 Ejecutando ejemplo: {args.run}")
            result = solve_ctf_challenge(
                description=f"Example: {args.run}",
                files=files
            )
            
            if result["success"]:
                print(f"✅ Flag: {result['flag']}")
                return 0
            else:
                print("❌ No se pudo resolver")
                return 1
                
        except ImportError as e:
            print(f"❌ Error: {e}")
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())