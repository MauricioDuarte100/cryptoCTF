"""
Sistema de Benchmark para CTF Crypto Agent
Mide el rendimiento del agente contra un conjunto de desafíos conocidos
"""

import json
import time
import statistics
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# Usar agente simplificado por ahora
from ..core.simple_agent import solve_ctf_challenge_simple as solve_ctf_challenge
from ..database.database import get_database

@dataclass
class BenchmarkChallenge:
    """Representa un desafío de benchmark"""
    name: str
    description: str
    challenge_type: str
    difficulty: str
    files: List[Dict[str, str]]
    expected_flag: str
    nc_host: str = ""
    nc_port: int = 0
    timeout: int = 60
    max_steps: int = 15
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class BenchmarkResult:
    """Resultado de un benchmark individual"""
    challenge: BenchmarkChallenge
    success: bool
    flag_found: str
    flag_correct: bool
    confidence: float
    steps_used: int
    total_time: float
    error_message: str = None
    solution_steps: List[str] = None
    
    def __post_init__(self):
        if self.solution_steps is None:
            self.solution_steps = []

class CTFBenchmark:
    """Sistema de benchmark para el agente CTF"""
    
    def __init__(self, db_logging: bool = True):
        self.db_logging = db_logging
        self.db = get_database() if db_logging else None
        self.challenges: List[BenchmarkChallenge] = []
        self.results: List[BenchmarkResult] = []
    
    def load_benchmark_challenges(self):
        """Carga desafíos de benchmark desde múltiples fuentes"""
        self.challenges = []
        
        # 1. Cargar desde examples/ directory
        self._load_from_examples()
        
        # 2. Cargar desde archivo JSON de benchmark
        self._load_from_json()
        
        # 3. Cargar desafíos hardcodeados
        self._load_hardcoded_challenges()
        
        print(f"📋 Cargados {len(self.challenges)} desafíos de benchmark")
    
    def _load_from_examples(self):
        """Carga desafíos desde la carpeta examples/"""
        examples_dir = Path("examples")
        
        if not examples_dir.exists():
            return
        
        # RSA Básico (e=3)
        rsa_basic_dir = examples_dir / "rsa_basic"
        if rsa_basic_dir.exists():
            files = []
            for py_file in rsa_basic_dir.glob("*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    files.append({"name": py_file.name, "content": f.read()})
            
            if files:
                self.challenges.append(BenchmarkChallenge(
                    name="RSA Basic (e=3)",
                    description="RSA challenge with small exponent e=3, vulnerable to Hastad's attack",
                    challenge_type="RSA",
                    difficulty="Easy",
                    files=files,
                    expected_flag="flag{small_e_is_vulnerable}",
                    max_steps=10,
                    tags=["rsa", "hastad", "small_e"]
                ))
        
        # Caesar Cipher
        caesar_dir = examples_dir / "caesar_cipher"
        if caesar_dir.exists():
            files = []
            for py_file in caesar_dir.glob("*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    files.append({"name": py_file.name, "content": f.read()})
            
            if files:
                self.challenges.append(BenchmarkChallenge(
                    name="Caesar Cipher (ROT13)",
                    description="Classic Caesar cipher with ROT13 encoding",
                    challenge_type="Classical",
                    difficulty="Easy",
                    files=files,
                    expected_flag="flag{caesar_cipher_is_not_secure}",
                    max_steps=8,
                    tags=["classical", "caesar", "rot13"]
                ))
        
        # XOR Single Byte
        xor_dir = examples_dir / "xor_single"
        if xor_dir.exists():
            files = []
            for py_file in xor_dir.glob("*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    files.append({"name": py_file.name, "content": f.read()})
            
            if files:
                self.challenges.append(BenchmarkChallenge(
                    name="XOR Single Byte",
                    description="XOR cipher with single byte key",
                    challenge_type="XOR",
                    difficulty="Easy",
                    files=files,
                    expected_flag="flag{xor_is_not_secure}",
                    max_steps=8,
                    tags=["xor", "single_byte"]
                ))
        
        # RSA Wiener
        wiener_dir = examples_dir / "rsa_wiener"
        if wiener_dir.exists():
            files = []
            for py_file in wiener_dir.glob("*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    files.append({"name": py_file.name, "content": f.read()})
            
            if files:
                self.challenges.append(BenchmarkChallenge(
                    name="RSA Wiener Attack",
                    description="RSA with small private exponent d, vulnerable to Wiener's attack",
                    challenge_type="RSA",
                    difficulty="Medium",
                    files=files,
                    expected_flag="flag{wiener_attack_works}",
                    max_steps=12,
                    tags=["rsa", "wiener", "small_d"]
                ))
        
        # RSA Common Modulus
        common_mod_dir = examples_dir / "rsa_common_modulus"
        if common_mod_dir.exists():
            files = []
            for py_file in common_mod_dir.glob("*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    files.append({"name": py_file.name, "content": f.read()})
            
            if files:
                self.challenges.append(BenchmarkChallenge(
                    name="RSA Common Modulus",
                    description="RSA with same modulus but different exponents",
                    challenge_type="RSA",
                    difficulty="Medium",
                    files=files,
                    expected_flag="flag{common_modulus_attack}",
                    max_steps=12,
                    tags=["rsa", "common_modulus"]
                ))
    
    def _load_from_json(self):
        """Carga desafíos desde archivo JSON"""
        benchmark_file = Path("benchmark_challenges.json")
        
        if not benchmark_file.exists():
            return
        
        try:
            with open(benchmark_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for challenge_data in data.get("challenges", []):
                challenge = BenchmarkChallenge(
                    name=challenge_data["name"],
                    description=challenge_data["description"],
                    challenge_type=challenge_data["challenge_type"],
                    difficulty=challenge_data["difficulty"],
                    files=challenge_data["files"],
                    expected_flag=challenge_data["expected_flag"],
                    nc_host=challenge_data.get("nc_host", ""),
                    nc_port=challenge_data.get("nc_port", 0),
                    timeout=challenge_data.get("timeout", 60),
                    max_steps=challenge_data.get("max_steps", 15),
                    tags=challenge_data.get("tags", [])
                )
                self.challenges.append(challenge)
                
        except Exception as e:
            print(f"⚠️  Error cargando benchmark_challenges.json: {e}")
    
    def _load_hardcoded_challenges(self):
        """Carga desafíos hardcodeados adicionales"""
        
        # Base64 Simple
        self.challenges.append(BenchmarkChallenge(
            name="Base64 Decode",
            description="Simple base64 encoded flag",
            challenge_type="Encoding",
            difficulty="Easy",
            files=[{
                "name": "challenge.txt",
                "content": "Encoded flag: ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"
            }],
            expected_flag="flag{base64_is_not_encryption}",
            max_steps=5,
            tags=["encoding", "base64"]
        ))
        
        # Hex Decode
        self.challenges.append(BenchmarkChallenge(
            name="Hex Decode",
            description="Hex encoded flag",
            challenge_type="Encoding",
            difficulty="Easy",
            files=[{
                "name": "challenge.txt",
                "content": "Hex: 666c61677b6865785f69735f6e6f745f656e6372797074696f6e7d"
            }],
            expected_flag="flag{hex_is_not_encryption}",
            max_steps=5,
            tags=["encoding", "hex"]
        ))
        
        # ROT47
        self.challenges.append(BenchmarkChallenge(
            name="ROT47 Cipher",
            description="ROT47 encoded message",
            challenge_type="Classical",
            difficulty="Easy",
            files=[{
                "name": "cipher.txt",
                "content": "Cipher: 7=28lC@?E2C:2?D_2C6_7F?n"
            }],
            expected_flag="flag{contrarians_are_fun}",
            max_steps=8,
            tags=["classical", "rot47"]
        ))
        
        # Vigenère Simple
        self.challenges.append(BenchmarkChallenge(
            name="Vigenère Cipher",
            description="Vigenère cipher with known key",
            challenge_type="Classical",
            difficulty="Medium",
            files=[{
                "name": "vigenere.py",
                "content": '''
# Vigenère cipher challenge
# Key: "KEY"
ciphertext = "DPEQ{FMKWVKX_MW_AEKMXK}"
print("Decrypt this:", ciphertext)
print("Hint: The key is 'KEY'")
'''
            }],
            expected_flag="flag{vigenere_is_secure}",
            max_steps=10,
            tags=["classical", "vigenere"]
        ))
    
    def run_benchmark(self, max_challenges: int = None, 
                     challenge_types: List[str] = None,
                     difficulties: List[str] = None) -> Dict[str, Any]:
        """
        Ejecuta el benchmark completo
        
        Args:
            max_challenges: Máximo número de desafíos a ejecutar
            challenge_types: Filtrar por tipos específicos
            difficulties: Filtrar por dificultades específicas
        
        Returns:
            Reporte completo del benchmark
        """
        print("🚀 Iniciando Benchmark CTF Crypto Agent")
        print("="*60)
        
        # Cargar desafíos
        self.load_benchmark_challenges()
        
        # Filtrar desafíos
        challenges_to_run = self.challenges
        
        if challenge_types:
            challenges_to_run = [c for c in challenges_to_run if c.challenge_type in challenge_types]
        
        if difficulties:
            challenges_to_run = [c for c in challenges_to_run if c.difficulty in difficulties]
        
        if max_challenges:
            challenges_to_run = challenges_to_run[:max_challenges]
        
        print(f"📋 Ejecutando {len(challenges_to_run)} desafíos...")
        
        # Ejecutar cada desafío
        self.results = []
        start_time = time.time()
        
        for i, challenge in enumerate(challenges_to_run, 1):
            print(f"\n🔍 [{i}/{len(challenges_to_run)}] {challenge.name}")
            print(f"   Tipo: {challenge.challenge_type} | Dificultad: {challenge.difficulty}")
            
            result = self._run_single_challenge(challenge)
            self.results.append(result)
            
            # Mostrar resultado inmediato
            status = "✅" if result.success else "❌"
            time_str = f"{result.total_time:.1f}s"
            print(f"   {status} {time_str} | Pasos: {result.steps_used} | Confianza: {result.confidence:.2f}")
            
            if result.success and result.flag_found:
                print(f"   🏁 Flag: {result.flag_found}")
        
        total_time = time.time() - start_time
        
        # Generar reporte
        report = self._generate_report(total_time)
        
        # Mostrar resumen
        self._print_summary(report)
        
        # Guardar reporte
        self._save_report(report)
        
        return report
    
    def _run_single_challenge(self, challenge: BenchmarkChallenge) -> BenchmarkResult:
        """Ejecuta un desafío individual"""
        try:
            result = solve_ctf_challenge(
                description=challenge.description,
                files=challenge.files,
                nc_host=challenge.nc_host,
                nc_port=challenge.nc_port,
                max_steps=challenge.max_steps,
                challenge_name=challenge.name,
                expected_flag=challenge.expected_flag,
                log_to_db=self.db_logging
            )
            
            # Verificar si la flag es correcta
            flag_correct = False
            if result.get("flag") and challenge.expected_flag:
                flag_correct = result["flag"].lower().strip() == challenge.expected_flag.lower().strip()
            
            return BenchmarkResult(
                challenge=challenge,
                success=result.get("success", False) and flag_correct,
                flag_found=result.get("flag", ""),
                flag_correct=flag_correct,
                confidence=result.get("confidence", 0.0),
                steps_used=result.get("steps_used", 0),
                total_time=result.get("total_time", 0.0),
                error_message=result.get("error"),
                solution_steps=result.get("solution_steps", [])
            )
            
        except Exception as e:
            return BenchmarkResult(
                challenge=challenge,
                success=False,
                flag_found="",
                flag_correct=False,
                confidence=0.0,
                steps_used=0,
                total_time=0.0,
                error_message=str(e),
                solution_steps=[]
            )
    
    def _generate_report(self, total_time: float) -> Dict[str, Any]:
        """Genera reporte completo del benchmark"""
        if not self.results:
            return {}
        
        # Estadísticas generales
        total_challenges = len(self.results)
        successful_challenges = sum(1 for r in self.results if r.success)
        success_rate = successful_challenges / total_challenges if total_challenges > 0 else 0
        
        # Estadísticas por tipo
        by_type = {}
        for result in self.results:
            challenge_type = result.challenge.challenge_type
            if challenge_type not in by_type:
                by_type[challenge_type] = {"total": 0, "successful": 0, "times": []}
            
            by_type[challenge_type]["total"] += 1
            if result.success:
                by_type[challenge_type]["successful"] += 1
            by_type[challenge_type]["times"].append(result.total_time)
        
        # Calcular métricas por tipo
        for type_name, stats in by_type.items():
            stats["success_rate"] = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
            stats["avg_time"] = statistics.mean(stats["times"]) if stats["times"] else 0
            stats["median_time"] = statistics.median(stats["times"]) if stats["times"] else 0
        
        # Estadísticas por dificultad
        by_difficulty = {}
        for result in self.results:
            difficulty = result.challenge.difficulty
            if difficulty not in by_difficulty:
                by_difficulty[difficulty] = {"total": 0, "successful": 0}
            
            by_difficulty[difficulty]["total"] += 1
            if result.success:
                by_difficulty[difficulty]["successful"] += 1
        
        for difficulty, stats in by_difficulty.items():
            stats["success_rate"] = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        
        # Tiempos
        times = [r.total_time for r in self.results if r.total_time > 0]
        avg_time = statistics.mean(times) if times else 0
        median_time = statistics.median(times) if times else 0
        
        # Pasos
        steps = [r.steps_used for r in self.results if r.steps_used > 0]
        avg_steps = statistics.mean(steps) if steps else 0
        
        # Confianza
        confidences = [r.confidence for r in self.results if r.confidence > 0]
        avg_confidence = statistics.mean(confidences) if confidences else 0
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_challenges": total_challenges,
            "successful_challenges": successful_challenges,
            "success_rate": success_rate,
            "total_benchmark_time": total_time,
            "avg_challenge_time": avg_time,
            "median_challenge_time": median_time,
            "avg_steps": avg_steps,
            "avg_confidence": avg_confidence,
            "by_type": by_type,
            "by_difficulty": by_difficulty,
            "detailed_results": [
                {
                    "name": r.challenge.name,
                    "type": r.challenge.challenge_type,
                    "difficulty": r.challenge.difficulty,
                    "success": r.success,
                    "flag_found": r.flag_found,
                    "flag_correct": r.flag_correct,
                    "expected_flag": r.challenge.expected_flag,
                    "confidence": r.confidence,
                    "steps_used": r.steps_used,
                    "total_time": r.total_time,
                    "error": r.error_message,
                    "tags": r.challenge.tags
                }
                for r in self.results
            ]
        }
    
    def _print_summary(self, report: Dict[str, Any]):
        """Imprime resumen del benchmark"""
        print("\n" + "="*60)
        print("📊 RESUMEN DEL BENCHMARK")
        print("="*60)
        
        print(f"🎯 Tasa de Éxito General: {report['success_rate']:.1%} ({report['successful_challenges']}/{report['total_challenges']})")
        print(f"⏱️  Tiempo Total: {report['total_benchmark_time']:.1f}s")
        print(f"📈 Tiempo Promedio por Desafío: {report['avg_challenge_time']:.1f}s")
        print(f"🔢 Pasos Promedio: {report['avg_steps']:.1f}")
        print(f"🎲 Confianza Promedio: {report['avg_confidence']:.2f}")
        
        print(f"\n📋 Por Tipo de Desafío:")
        for type_name, stats in report['by_type'].items():
            print(f"  {type_name}: {stats['success_rate']:.1%} ({stats['successful']}/{stats['total']}) - {stats['avg_time']:.1f}s promedio")
        
        print(f"\n🎚️  Por Dificultad:")
        for difficulty, stats in report['by_difficulty'].items():
            print(f"  {difficulty}: {stats['success_rate']:.1%} ({stats['successful']}/{stats['total']})")
        
        print(f"\n🏆 Desafíos Exitosos:")
        for result in report['detailed_results']:
            if result['success']:
                print(f"  ✅ {result['name']} ({result['type']}) - {result['total_time']:.1f}s")
        
        print(f"\n❌ Desafíos Fallidos:")
        for result in report['detailed_results']:
            if not result['success']:
                error_msg = result['error'][:50] + "..." if result['error'] and len(result['error']) > 50 else result['error']
                print(f"  ❌ {result['name']} ({result['type']}) - {error_msg or 'Sin flag encontrada'}")
    
    def _save_report(self, report: Dict[str, Any]):
        """Guarda el reporte en archivo JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Reporte guardado en: {filename}")

def run_benchmark_cli():
    """Función CLI para ejecutar benchmark"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CTF Crypto Agent Benchmark")
    parser.add_argument("--max-challenges", type=int, help="Máximo número de desafíos")
    parser.add_argument("--types", nargs="+", help="Filtrar por tipos de desafío")
    parser.add_argument("--difficulties", nargs="+", help="Filtrar por dificultades")
    parser.add_argument("--no-db", action="store_true", help="No registrar en base de datos")
    
    args = parser.parse_args()
    
    benchmark = CTFBenchmark(db_logging=not args.no_db)
    
    report = benchmark.run_benchmark(
        max_challenges=args.max_challenges,
        challenge_types=args.types,
        difficulties=args.difficulties
    )
    
    return report

if __name__ == "__main__":
    run_benchmark_cli()