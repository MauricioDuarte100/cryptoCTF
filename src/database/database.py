"""
Sistema de Base de Datos para CTF Crypto Agent
Registra todos los intentos, éxitos, fallos y métricas
"""

import sqlite3
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib

class CTFDatabase:
    """Base de datos para tracking de desafíos CTF"""
    
    def __init__(self, db_path: str = "ctf_history.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Inicializa la base de datos con todas las tablas"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Tabla principal de desafíos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    challenge_type TEXT,
                    difficulty TEXT,
                    source TEXT,
                    files_json TEXT,
                    expected_flag TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabla de intentos de resolución
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id INTEGER,
                    success BOOLEAN NOT NULL,
                    flag_found TEXT,
                    confidence REAL,
                    steps_used INTEGER,
                    total_time REAL,
                    error_message TEXT,
                    solution_steps_json TEXT,
                    agent_version TEXT,
                    gemini_model TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
                )
            """)
            
            # Tabla de llamadas a herramientas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt_id INTEGER,
                    tool_name TEXT NOT NULL,
                    tool_args_json TEXT,
                    tool_result_json TEXT,
                    execution_time REAL,
                    success BOOLEAN,
                    error_message TEXT,
                    call_order INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attempt_id) REFERENCES attempts (id)
                )
            """)
            
            # Tabla de métricas agregadas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metadata_json TEXT,
                    period_start TIMESTAMP,
                    period_end TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Índices para performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_challenges_hash ON challenges(challenge_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_challenge ON attempts(challenge_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_success ON attempts(success)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_calls_attempt ON tool_calls(attempt_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type, metric_name)")
            
            conn.commit()
    
    def generate_challenge_hash(self, name: str, description: str, files: List[Dict]) -> str:
        """Genera hash único para un desafío"""
        content = f"{name}|{description}|{json.dumps(files, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def log_challenge(self, name: str, description: str, challenge_type: str = "Unknown",
                     difficulty: str = "Unknown", source: str = "Manual", 
                     files: List[Dict] = None, expected_flag: str = None) -> int:
        """
        Registra un nuevo desafío o obtiene el ID si ya existe
        
        Returns:
            challenge_id: ID del desafío en la base de datos
        """
        files = files or []
        challenge_hash = self.generate_challenge_hash(name, description, files)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Verificar si ya existe
            cursor.execute("SELECT id FROM challenges WHERE challenge_hash = ?", (challenge_hash,))
            existing = cursor.fetchone()
            
            if existing:
                return existing[0]
            
            # Insertar nuevo desafío
            cursor.execute("""
                INSERT INTO challenges 
                (challenge_hash, name, description, challenge_type, difficulty, source, files_json, expected_flag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (challenge_hash, name, description, challenge_type, difficulty, source, 
                  json.dumps(files), expected_flag))
            
            return cursor.lastrowid
    
    def log_attempt(self, challenge_id: int, success: bool, flag_found: str = None,
                   confidence: float = 0.0, steps_used: int = 0, total_time: float = 0.0,
                   error_message: str = None, solution_steps: List[str] = None,
                   agent_version: str = "1.0", gemini_model: str = "gemini-2.5-flash") -> int:
        """
        Registra un intento de resolución
        
        Returns:
            attempt_id: ID del intento en la base de datos
        """
        solution_steps = solution_steps or []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO attempts 
                (challenge_id, success, flag_found, confidence, steps_used, total_time,
                 error_message, solution_steps_json, agent_version, gemini_model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (challenge_id, success, flag_found, confidence, steps_used, total_time,
                  error_message, json.dumps(solution_steps), agent_version, gemini_model))
            
            return cursor.lastrowid
    
    def log_tool_call(self, attempt_id: int, tool_name: str, tool_args: Dict,
                     tool_result: Dict, execution_time: float, success: bool,
                     error_message: str = None, call_order: int = 0):
        """Registra una llamada a herramienta específica"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO tool_calls 
                (attempt_id, tool_name, tool_args_json, tool_result_json, 
                 execution_time, success, error_message, call_order)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (attempt_id, tool_name, json.dumps(tool_args), json.dumps(tool_result),
                  execution_time, success, error_message, call_order))
    
    def get_challenge_stats(self, challenge_id: int) -> Dict[str, Any]:
        """Obtiene estadísticas de un desafío específico"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Información básica del desafío
            cursor.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,))
            challenge = cursor.fetchone()
            
            if not challenge:
                return {}
            
            # Estadísticas de intentos
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_attempts,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_attempts,
                    AVG(total_time) as avg_time,
                    AVG(steps_used) as avg_steps,
                    AVG(confidence) as avg_confidence
                FROM attempts WHERE challenge_id = ?
            """, (challenge_id,))
            
            stats = cursor.fetchone()
            
            return {
                "challenge_id": challenge_id,
                "name": challenge[2],
                "challenge_type": challenge[4],
                "total_attempts": stats[0] or 0,
                "successful_attempts": stats[1] or 0,
                "success_rate": (stats[1] or 0) / max(stats[0] or 1, 1),
                "avg_time": stats[2] or 0,
                "avg_steps": stats[3] or 0,
                "avg_confidence": stats[4] or 0
            }
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas generales del agente"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Estadísticas generales
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT c.id) as total_challenges,
                    COUNT(a.id) as total_attempts,
                    SUM(CASE WHEN a.success = 1 THEN 1 ELSE 0 END) as successful_attempts,
                    AVG(a.total_time) as avg_time,
                    AVG(a.steps_used) as avg_steps
                FROM challenges c
                LEFT JOIN attempts a ON c.id = a.challenge_id
            """)
            
            general = cursor.fetchone()
            
            # Estadísticas por tipo
            cursor.execute("""
                SELECT 
                    c.challenge_type,
                    COUNT(a.id) as attempts,
                    SUM(CASE WHEN a.success = 1 THEN 1 ELSE 0 END) as successes
                FROM challenges c
                LEFT JOIN attempts a ON c.id = a.challenge_id
                GROUP BY c.challenge_type
                ORDER BY attempts DESC
            """)
            
            by_type = cursor.fetchall()
            
            # Herramientas más usadas
            cursor.execute("""
                SELECT 
                    tool_name,
                    COUNT(*) as usage_count,
                    AVG(execution_time) as avg_execution_time,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count
                FROM tool_calls
                GROUP BY tool_name
                ORDER BY usage_count DESC
                LIMIT 10
            """)
            
            top_tools = cursor.fetchall()
            
            return {
                "total_challenges": general[0] or 0,
                "total_attempts": general[1] or 0,
                "successful_attempts": general[2] or 0,
                "overall_success_rate": (general[2] or 0) / max(general[1] or 1, 1),
                "avg_time": general[3] or 0,
                "avg_steps": general[4] or 0,
                "by_type": [
                    {
                        "type": row[0],
                        "attempts": row[1],
                        "successes": row[2],
                        "success_rate": row[2] / max(row[1], 1)
                    }
                    for row in by_type
                ],
                "top_tools": [
                    {
                        "tool": row[0],
                        "usage": row[1],
                        "avg_time": row[2],
                        "success_rate": row[3] / max(row[1], 1)
                    }
                    for row in top_tools
                ]
            }
    
    def export_training_data(self, min_attempts: int = 2) -> List[Dict[str, Any]]:
        """
        Exporta datos para entrenamiento de ML
        Solo incluye desafíos con suficientes intentos
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    c.id, c.name, c.description, c.challenge_type, c.files_json,
                    a.success, a.confidence, a.steps_used, a.total_time,
                    a.solution_steps_json, a.flag_found
                FROM challenges c
                JOIN attempts a ON c.id = a.challenge_id
                WHERE c.id IN (
                    SELECT challenge_id 
                    FROM attempts 
                    GROUP BY challenge_id 
                    HAVING COUNT(*) >= ?
                )
                ORDER BY c.id, a.created_at
            """, (min_attempts,))
            
            results = cursor.fetchall()
            
            training_data = []
            for row in results:
                training_data.append({
                    "challenge_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "challenge_type": row[3],
                    "files": json.loads(row[4] or "[]"),
                    "success": bool(row[5]),
                    "confidence": row[6],
                    "steps_used": row[7],
                    "total_time": row[8],
                    "solution_steps": json.loads(row[9] or "[]"),
                    "flag_found": row[10]
                })
            
            return training_data
    
    def cleanup_old_data(self, days_old: int = 30):
        """Limpia datos antiguos para mantener la DB manejable"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Eliminar intentos antiguos
            cursor.execute("""
                DELETE FROM attempts 
                WHERE created_at < datetime('now', '-{} days')
            """.format(days_old))
            
            # Eliminar tool calls huérfanos
            cursor.execute("""
                DELETE FROM tool_calls 
                WHERE attempt_id NOT IN (SELECT id FROM attempts)
            """)
            
            # Eliminar desafíos sin intentos
            cursor.execute("""
                DELETE FROM challenges 
                WHERE id NOT IN (SELECT DISTINCT challenge_id FROM attempts WHERE challenge_id IS NOT NULL)
            """)
            
            conn.commit()

# Función de utilidad para integración fácil
def get_database() -> CTFDatabase:
    """Obtiene instancia singleton de la base de datos"""
    if not hasattr(get_database, '_instance'):
        get_database._instance = CTFDatabase()
    return get_database._instance

if __name__ == "__main__":
    # Crear y probar la base de datos
    print("🗄️  Inicializando base de datos CTF...")
    
    db = CTFDatabase()
    
    # Ejemplo de uso
    challenge_id = db.log_challenge(
        name="Test RSA Challenge",
        description="RSA with small e=3",
        challenge_type="RSA",
        difficulty="Easy",
        source="Test",
        expected_flag="flag{test_rsa}"
    )
    
    attempt_id = db.log_attempt(
        challenge_id=challenge_id,
        success=True,
        flag_found="flag{test_rsa}",
        confidence=0.95,
        steps_used=3,
        total_time=2.5,
        solution_steps=["analyze_files", "classify_crypto", "attack_rsa"]
    )
    
    # Mostrar estadísticas
    stats = db.get_overall_stats()
    print(f"✅ Base de datos creada exitosamente")
    print(f"📊 Estadísticas: {stats['total_challenges']} desafíos, {stats['total_attempts']} intentos")
    print(f"🎯 Tasa de éxito: {stats['overall_success_rate']:.1%}")