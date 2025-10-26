"""
Multi-Agent System Utilities
Utilidades y funciones de apoyo para el sistema multi-agente
"""

import json
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configura el sistema de logging para multi-agente"""
    logger = logging.getLogger("multi_agent")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    if not logger.handlers:
        # Handler para consola
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # Handler para archivo (si el directorio existe)
        log_dir = Path("multi_agent/logs")
        if log_dir.exists():
            file_handler = logging.FileHandler(log_dir / "multi_agent.log")
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
    
    return logger

def format_time(seconds: float) -> str:
    """Formatea tiempo en segundos a formato legible"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"

def calculate_confidence(success_probability: float, attempts: int, max_attempts: int) -> float:
    """Calcula la confianza basada en probabilidad de éxito y intentos"""
    attempt_factor = 1.0 - (attempts - 1) / max_attempts * 0.3
    return success_probability * attempt_factor

def extract_flag_from_text(text: str, patterns: List[str]) -> Optional[str]:
    """Extrae flag de texto usando patrones regex"""
    import re
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            return matches[0]
    return None

def calculate_text_entropy(text: str) -> float:
    """Calcula la entropía de un texto"""
    import math
    from collections import Counter
    
    if not text:
        return 0.0
    
    # Contar frecuencia de caracteres
    char_counts = Counter(text)
    text_length = len(text)
    
    # Calcular entropía
    entropy = 0.0
    for count in char_counts.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def validate_flag_format(flag: str) -> Dict[str, Any]:
    """Valida el formato de una flag y retorna información detallada"""
    if not flag:
        return {
            "valid": False,
            "reason": "Empty flag",
            "entropy": 0.0,
            "length": 0,
            "format": "unknown"
        }
    
    # Calcular entropía
    entropy = calculate_text_entropy(flag)
    
    # Determinar formato
    flag_format = "unknown"
    if flag.startswith("flag{") and flag.endswith("}"):
        flag_format = "standard_flag"
    elif flag.startswith("FLAG{") and flag.endswith("}"):
        flag_format = "uppercase_flag"
    elif flag.startswith("ctf{") and flag.endswith("}"):
        flag_format = "ctf_flag"
    elif flag.startswith("{") and flag.endswith("}"):
        flag_format = "generic_flag"
    
    # Validar
    valid = (
        len(flag) >= 10 and  # Mínimo 10 caracteres
        entropy >= 3.0 and   # Mínima entropía
        flag_format != "unknown"
    )
    
    return {
        "valid": valid,
        "reason": "Valid flag" if valid else "Invalid format or low entropy",
        "entropy": entropy,
        "length": len(flag),
        "format": flag_format
    }

def save_execution_report(report: Dict[str, Any], filename: Optional[str] = None) -> str:
    """Guarda un reporte de ejecución en formato JSON"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"execution_report_{timestamp}.json"
    
    reports_dir = Path("multi_agent/reports")
    reports_dir.mkdir(exist_ok=True)
    
    filepath = reports_dir / filename
    
    # Añadir timestamp si no existe
    if "timestamp" not in report:
        report["timestamp"] = datetime.now().isoformat()
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return str(filepath)

def load_execution_report(filename: str) -> Dict[str, Any]:
    """Carga un reporte de ejecución desde archivo JSON"""
    filepath = Path("multi_agent/reports") / filename
    
    if not filepath.exists():
        raise FileNotFoundError(f"Report file not found: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def create_performance_summary(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Crea un resumen de rendimiento a partir de múltiples reportes"""
    if not reports:
        return {"error": "No reports provided"}
    
    total_challenges = len(reports)
    successful = sum(1 for r in reports if r.get("success", False))
    
    # Calcular métricas promedio
    avg_time = sum(r.get("total_time", 0) for r in reports) / total_challenges
    avg_strategies = sum(r.get("strategies_tried", 0) for r in reports) / total_challenges
    avg_rag_patterns = sum(r.get("rag_patterns", 0) for r in reports) / total_challenges
    
    # Agrupar por tipo
    by_type = {}
    for report in reports:
        challenge_type = report.get("challenge_type", "Unknown")
        if challenge_type not in by_type:
            by_type[challenge_type] = {"total": 0, "successful": 0}
        
        by_type[challenge_type]["total"] += 1
        if report.get("success", False):
            by_type[challenge_type]["successful"] += 1
    
    # Calcular tasas de éxito por tipo
    for type_data in by_type.values():
        type_data["success_rate"] = (
            type_data["successful"] / type_data["total"] * 100
            if type_data["total"] > 0 else 0
        )
    
    return {
        "summary": {
            "total_challenges": total_challenges,
            "successful": successful,
            "failed": total_challenges - successful,
            "success_rate": successful / total_challenges * 100,
            "avg_time": avg_time,
            "avg_strategies_per_challenge": avg_strategies,
            "avg_rag_patterns_per_challenge": avg_rag_patterns
        },
        "by_type": by_type,
        "timestamp": datetime.now().isoformat()
    }

def print_agent_status(agent_name: str, status: str, details: str = ""):
    """Imprime el estado de un agente con formato consistente"""
    icons = {
        "planner": "🧠",
        "executor": "⚡",
        "validator": "🔍",
        "coordinator": "🎯"
    }
    
    icon = icons.get(agent_name.lower(), "🤖")
    print(f"{icon} {agent_name.title()}Agent: {status}")
    if details:
        print(f"   {details}")

def print_phase_header(phase_name: str, description: str = ""):
    """Imprime encabezado de fase con formato consistente"""
    print("\n" + "="*50)
    print(f"📋 {phase_name}")
    if description:
        print(f"   {description}")
    print("="*50)

def print_results_summary(results: Dict[str, Any]):
    """Imprime resumen de resultados con formato consistente"""
    print("\n" + "="*50)
    print("🎯 MULTI-AGENT SYSTEM FINAL REPORT")
    print("="*50)
    
    status = "✅ SUCCESS" if results.get("success", False) else "❌ FAILED"
    print(f"Status: {status}")
    print(f"Total Time: {format_time(results.get('total_time', 0))}")
    print(f"Agents Used: {', '.join(results.get('agents_used', []))}")
    
    if results.get("flag"):
        print(f"🏁 FLAG FOUND: {results['flag']}")
    else:
        print("❌ NO FLAG FOUND")
    
    print("="*50)

class Timer:
    """Contexto para medir tiempo de ejecución"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
    
    @property
    def elapsed(self) -> float:
        """Tiempo transcurrido en segundos"""
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time
    
    def __str__(self) -> str:
        return f"{self.name}: {format_time(self.elapsed)}"

# Configurar logger por defecto
logger = setup_logging()