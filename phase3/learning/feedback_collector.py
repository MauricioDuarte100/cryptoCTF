"""
Feedback Collection System
Sistema de recolección de feedback para aprendizaje automático
"""

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import logging

@dataclass
class ExecutionFeedback:
    """Estructura de datos para feedback de ejecución"""
    timestamp: str
    challenge_id: str
    challenge_type: str
    challenge_name: str
    success: bool
    flag_found: Optional[str]
    total_time: float
    confidence: float
    quality_score: float
    
    # Agent performance
    agents_used: List[str]
    planner_confidence: float
    planner_strategies: int
    planner_rag_patterns: int
    executor_attempts: int
    executor_success_strategy: Optional[str]
    validator_confidence: float
    
    # Strategy details
    strategies_tried: List[Dict[str, Any]]
    winning_strategy: Optional[Dict[str, Any]]
    failed_strategies: List[Dict[str, Any]]
    
    # Error information
    errors: List[str]
    warnings: List[str]
    
    # Context
    rag_context: List[Dict[str, Any]]
    bert_prediction: str
    bert_confidence: float
    
    # Performance metrics
    memory_usage: float
    cpu_usage: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExecutionFeedback':
        """Crea instancia desde diccionario"""
        return cls(**data)

class FeedbackCollector:
    """Recolector de feedback para el sistema de aprendizaje"""
    
    def __init__(self, db_path: str = "phase3/data/feedback.db", 
                 jsonl_path: str = "phase3/data/feedback.jsonl"):
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path)
        self.logger = logging.getLogger(__name__)
        
        # Crear directorios si no existen
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Inicializar base de datos
        self._init_database()
    
    def _init_database(self):
        """Inicializa la base de datos SQLite"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    challenge_type TEXT NOT NULL,
                    challenge_name TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    flag_found TEXT,
                    total_time REAL NOT NULL,
                    confidence REAL NOT NULL,
                    quality_score REAL NOT NULL,
                    agents_used TEXT NOT NULL,
                    planner_confidence REAL NOT NULL,
                    planner_strategies INTEGER NOT NULL,
                    planner_rag_patterns INTEGER NOT NULL,
                    executor_attempts INTEGER NOT NULL,
                    executor_success_strategy TEXT,
                    validator_confidence REAL NOT NULL,
                    strategies_tried TEXT NOT NULL,
                    winning_strategy TEXT,
                    failed_strategies TEXT NOT NULL,
                    errors TEXT NOT NULL,
                    warnings TEXT NOT NULL,
                    rag_context TEXT NOT NULL,
                    bert_prediction TEXT NOT NULL,
                    bert_confidence REAL NOT NULL,
                    memory_usage REAL NOT NULL,
                    cpu_usage REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Índices para consultas rápidas
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON executions(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge_type ON executions(challenge_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_success ON executions(success)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON executions(created_at)")
    
    def collect_feedback(self, feedback: ExecutionFeedback) -> bool:
        """Recolecta feedback de una ejecución"""
        try:
            # Guardar en SQLite
            self._save_to_sqlite(feedback)
            
            # Guardar en JSONL
            self._save_to_jsonl(feedback)
            
            self.logger.info(f"Feedback collected for challenge: {feedback.challenge_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error collecting feedback: {e}")
            return False
    
    def _save_to_sqlite(self, feedback: ExecutionFeedback):
        """Guarda feedback en SQLite"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO executions (
                    timestamp, challenge_id, challenge_type, challenge_name,
                    success, flag_found, total_time, confidence, quality_score,
                    agents_used, planner_confidence, planner_strategies, planner_rag_patterns,
                    executor_attempts, executor_success_strategy, validator_confidence,
                    strategies_tried, winning_strategy, failed_strategies,
                    errors, warnings, rag_context, bert_prediction, bert_confidence,
                    memory_usage, cpu_usage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                feedback.timestamp,
                feedback.challenge_id,
                feedback.challenge_type,
                feedback.challenge_name,
                feedback.success,
                feedback.flag_found,
                feedback.total_time,
                feedback.confidence,
                feedback.quality_score,
                json.dumps(feedback.agents_used),
                feedback.planner_confidence,
                feedback.planner_strategies,
                feedback.planner_rag_patterns,
                feedback.executor_attempts,
                feedback.executor_success_strategy,
                feedback.validator_confidence,
                json.dumps(feedback.strategies_tried),
                json.dumps(feedback.winning_strategy) if feedback.winning_strategy else None,
                json.dumps(feedback.failed_strategies),
                json.dumps(feedback.errors),
                json.dumps(feedback.warnings),
                json.dumps(feedback.rag_context),
                feedback.bert_prediction,
                feedback.bert_confidence,
                feedback.memory_usage,
                feedback.cpu_usage
            ))
    
    def _save_to_jsonl(self, feedback: ExecutionFeedback):
        """Guarda feedback en JSONL para análisis rápido"""
        with open(self.jsonl_path, 'a', encoding='utf-8') as f:
            json.dump(feedback.to_dict(), f, ensure_ascii=False)
            f.write('\n')
    
    def get_recent_feedback(self, limit: int = 100) -> List[ExecutionFeedback]:
        """Obtiene feedback reciente"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM executions 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                # Convertir row a dict y reconstruir ExecutionFeedback
                data = dict(row)
                
                # Deserializar campos JSON
                data['agents_used'] = json.loads(data['agents_used'])
                data['strategies_tried'] = json.loads(data['strategies_tried'])
                data['winning_strategy'] = json.loads(data['winning_strategy']) if data['winning_strategy'] else None
                data['failed_strategies'] = json.loads(data['failed_strategies'])
                data['errors'] = json.loads(data['errors'])
                data['warnings'] = json.loads(data['warnings'])
                data['rag_context'] = json.loads(data['rag_context'])
                
                # Remover campos de SQLite que no están en ExecutionFeedback
                data.pop('id', None)
                data.pop('created_at', None)
                
                results.append(ExecutionFeedback.from_dict(data))
            
            return results
    
    def get_success_rate_by_type(self, days: int = 7) -> Dict[str, float]:
        """Obtiene tasa de éxito por tipo de challenge en los últimos N días"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    challenge_type,
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY challenge_type
            """.format(days))
            
            results = {}
            for row in cursor.fetchall():
                challenge_type, total, successful = row
                success_rate = (successful / total) * 100 if total > 0 else 0
                results[challenge_type] = success_rate
            
            return results
    
    def get_strategy_effectiveness(self, days: int = 7) -> Dict[str, Dict[str, Any]]:
        """Obtiene efectividad de estrategias en los últimos N días"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    executor_success_strategy,
                    challenge_type,
                    COUNT(*) as usage_count,
                    AVG(total_time) as avg_time,
                    AVG(confidence) as avg_confidence
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                AND executor_success_strategy IS NOT NULL
                GROUP BY executor_success_strategy, challenge_type
                ORDER BY usage_count DESC
            """.format(days))
            
            results = {}
            for row in cursor.fetchall():
                strategy, challenge_type, usage_count, avg_time, avg_confidence = row
                if strategy not in results:
                    results[strategy] = {}
                
                results[strategy][challenge_type] = {
                    'usage_count': usage_count,
                    'avg_time': avg_time,
                    'avg_confidence': avg_confidence
                }
            
            return results
    
    def get_performance_trends(self, days: int = 30) -> Dict[str, List[Dict[str, Any]]]:
        """Obtiene tendencias de rendimiento por día"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as total_executions,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_executions,
                    AVG(total_time) as avg_time,
                    AVG(confidence) as avg_confidence,
                    AVG(quality_score) as avg_quality
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY DATE(created_at)
                ORDER BY date
            """.format(days))
            
            daily_stats = []
            for row in cursor.fetchall():
                date, total, successful, avg_time, avg_confidence, avg_quality = row
                success_rate = (successful / total) * 100 if total > 0 else 0
                
                daily_stats.append({
                    'date': date,
                    'total_executions': total,
                    'successful_executions': successful,
                    'success_rate': success_rate,
                    'avg_time': avg_time,
                    'avg_confidence': avg_confidence,
                    'avg_quality': avg_quality
                })
            
            return {'daily_trends': daily_stats}
    
    def get_error_analysis(self, days: int = 7) -> Dict[str, Any]:
        """Analiza errores más comunes"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT errors, warnings, challenge_type, COUNT(*) as frequency
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                AND (errors != '[]' OR warnings != '[]')
                GROUP BY errors, warnings, challenge_type
                ORDER BY frequency DESC
                LIMIT 20
            """.format(days))
            
            error_patterns = []
            for row in cursor.fetchall():
                errors, warnings, challenge_type, frequency = row
                error_patterns.append({
                    'errors': json.loads(errors),
                    'warnings': json.loads(warnings),
                    'challenge_type': challenge_type,
                    'frequency': frequency
                })
            
            return {'error_patterns': error_patterns}

# Instancia global del collector
feedback_collector = FeedbackCollector()