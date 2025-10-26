"""
Metrics Analysis System
Sistema de análisis de métricas para optimización automática
"""

import json
import sqlite3
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import logging
from dataclasses import dataclass

@dataclass
class PerformanceMetrics:
    """Métricas de rendimiento del sistema"""
    overall_success_rate: float
    avg_response_time: float
    avg_confidence: float
    avg_quality_score: float
    total_executions: int
    successful_executions: int
    failed_executions: int
    
    # Por tipo de challenge
    success_by_type: Dict[str, float]
    time_by_type: Dict[str, float]
    
    # Por agente
    agent_performance: Dict[str, Dict[str, float]]
    
    # Tendencias
    trend_direction: str  # 'improving', 'declining', 'stable'
    trend_strength: float  # 0-1
    
    # Recomendaciones
    recommendations: List[str]

class MetricsAnalyzer:
    """Analizador de métricas para optimización automática"""
    
    def __init__(self, db_path: str = "phase3/data/feedback.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
    
    def analyze_current_performance(self, days: int = 7) -> PerformanceMetrics:
        """Analiza el rendimiento actual del sistema"""
        try:
            # Obtener datos básicos
            basic_stats = self._get_basic_stats(days)
            success_by_type = self._get_success_by_type(days)
            time_by_type = self._get_time_by_type(days)
            agent_performance = self._get_agent_performance(days)
            trend_info = self._analyze_trends(days)
            recommendations = self._generate_recommendations(basic_stats, success_by_type, trend_info)
            
            return PerformanceMetrics(
                overall_success_rate=basic_stats['success_rate'],
                avg_response_time=basic_stats['avg_time'],
                avg_confidence=basic_stats['avg_confidence'],
                avg_quality_score=basic_stats['avg_quality'],
                total_executions=basic_stats['total'],
                successful_executions=basic_stats['successful'],
                failed_executions=basic_stats['failed'],
                success_by_type=success_by_type,
                time_by_type=time_by_type,
                agent_performance=agent_performance,
                trend_direction=trend_info['direction'],
                trend_strength=trend_info['strength'],
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing performance: {e}")
            return self._get_default_metrics()
    
    def _get_basic_stats(self, days: int) -> Dict[str, float]:
        """Obtiene estadísticas básicas"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    AVG(total_time) as avg_time,
                    AVG(confidence) as avg_confidence,
                    AVG(quality_score) as avg_quality
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
            """.format(days))
            
            row = cursor.fetchone()
            total, successful, avg_time, avg_confidence, avg_quality = row
            
            return {
                'total': total or 0,
                'successful': successful or 0,
                'failed': (total or 0) - (successful or 0),
                'success_rate': (successful / total * 100) if total > 0 else 0,
                'avg_time': avg_time or 0,
                'avg_confidence': avg_confidence or 0,
                'avg_quality': avg_quality or 0
            }
    
    def _get_success_by_type(self, days: int) -> Dict[str, float]:
        """Obtiene tasa de éxito por tipo de challenge"""
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
                success_rate = (successful / total * 100) if total > 0 else 0
                results[challenge_type] = success_rate
            
            return results
    
    def _get_time_by_type(self, days: int) -> Dict[str, float]:
        """Obtiene tiempo promedio por tipo de challenge"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    challenge_type,
                    AVG(total_time) as avg_time
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY challenge_type
            """.format(days))
            
            results = {}
            for row in cursor.fetchall():
                challenge_type, avg_time = row
                results[challenge_type] = avg_time or 0
            
            return results
    
    def _get_agent_performance(self, days: int) -> Dict[str, Dict[str, float]]:
        """Obtiene rendimiento por agente"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    AVG(planner_confidence) as avg_planner_confidence,
                    AVG(planner_strategies) as avg_planner_strategies,
                    AVG(planner_rag_patterns) as avg_planner_rag_patterns,
                    AVG(executor_attempts) as avg_executor_attempts,
                    AVG(validator_confidence) as avg_validator_confidence,
                    COUNT(CASE WHEN executor_success_strategy IS NOT NULL THEN 1 END) as executor_successes,
                    COUNT(*) as total
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
            """.format(days))
            
            row = cursor.fetchone()
            if row:
                (avg_planner_conf, avg_planner_strat, avg_planner_rag, 
                 avg_executor_att, avg_validator_conf, executor_succ, total) = row
                
                return {
                    'planner': {
                        'avg_confidence': avg_planner_conf or 0,
                        'avg_strategies': avg_planner_strat or 0,
                        'avg_rag_patterns': avg_planner_rag or 0
                    },
                    'executor': {
                        'avg_attempts': avg_executor_att or 0,
                        'success_rate': (executor_succ / total * 100) if total > 0 else 0
                    },
                    'validator': {
                        'avg_confidence': avg_validator_conf or 0
                    }
                }
            
            return {}
    
    def _analyze_trends(self, days: int) -> Dict[str, Any]:
        """Analiza tendencias de rendimiento"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    AVG(total_time) as avg_time
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY DATE(created_at)
                ORDER BY date
            """.format(days))
            
            daily_data = []
            for row in cursor.fetchall():
                date, total, successful, avg_time = row
                success_rate = (successful / total * 100) if total > 0 else 0
                daily_data.append({
                    'date': date,
                    'success_rate': success_rate,
                    'avg_time': avg_time or 0
                })
            
            if len(daily_data) < 3:
                return {'direction': 'stable', 'strength': 0.0}
            
            # Calcular tendencia de success rate
            success_rates = [d['success_rate'] for d in daily_data]
            trend_slope = np.polyfit(range(len(success_rates)), success_rates, 1)[0]
            
            # Determinar dirección y fuerza
            if abs(trend_slope) < 1:
                direction = 'stable'
                strength = 0.0
            elif trend_slope > 0:
                direction = 'improving'
                strength = min(abs(trend_slope) / 10, 1.0)
            else:
                direction = 'declining'
                strength = min(abs(trend_slope) / 10, 1.0)
            
            return {
                'direction': direction,
                'strength': strength,
                'slope': trend_slope
            }
    
    def _generate_recommendations(self, basic_stats: Dict, success_by_type: Dict, 
                                trend_info: Dict) -> List[str]:
        """Genera recomendaciones basadas en el análisis"""
        recommendations = []
        
        # Recomendaciones basadas en success rate
        if basic_stats['success_rate'] < 80:
            recommendations.append("⚠️ Success rate below 80%. Consider reviewing strategy effectiveness.")
        
        # Recomendaciones basadas en tiempo de respuesta
        if basic_stats['avg_time'] > 5.0:
            recommendations.append("🐌 Average response time > 5s. Consider optimizing slow strategies.")
        
        # Recomendaciones basadas en tipos problemáticos
        for challenge_type, success_rate in success_by_type.items():
            if success_rate < 70:
                recommendations.append(f"🎯 {challenge_type} challenges have low success rate ({success_rate:.1f}%). Consider adding more strategies.")
        
        # Recomendaciones basadas en tendencias
        if trend_info['direction'] == 'declining' and trend_info['strength'] > 0.5:
            recommendations.append("📉 Performance is declining. Consider retraining models or reviewing recent changes.")
        elif trend_info['direction'] == 'improving' and trend_info['strength'] > 0.5:
            recommendations.append("📈 Performance is improving! Current optimizations are working well.")
        
        # Recomendaciones por defecto
        if not recommendations:
            recommendations.append("✅ System performance is stable. Continue monitoring.")
        
        return recommendations
    
    def _get_default_metrics(self) -> PerformanceMetrics:
        """Retorna métricas por defecto en caso de error"""
        return PerformanceMetrics(
            overall_success_rate=0.0,
            avg_response_time=0.0,
            avg_confidence=0.0,
            avg_quality_score=0.0,
            total_executions=0,
            successful_executions=0,
            failed_executions=0,
            success_by_type={},
            time_by_type={},
            agent_performance={},
            trend_direction='stable',
            trend_strength=0.0,
            recommendations=["⚠️ Unable to analyze metrics. Check database connection."]
        )
    
    def identify_optimization_opportunities(self, days: int = 14) -> Dict[str, Any]:
        """Identifica oportunidades de optimización"""
        opportunities = {
            'threshold_adjustments': [],
            'strategy_improvements': [],
            'model_retraining': [],
            'performance_issues': []
        }
        
        try:
            # Analizar thresholds que necesitan ajuste
            threshold_analysis = self._analyze_thresholds(days)
            opportunities['threshold_adjustments'] = threshold_analysis
            
            # Analizar estrategias que fallan frecuentemente
            strategy_analysis = self._analyze_failing_strategies(days)
            opportunities['strategy_improvements'] = strategy_analysis
            
            # Identificar necesidad de reentrenamiento
            retraining_analysis = self._analyze_retraining_needs(days)
            opportunities['model_retraining'] = retraining_analysis
            
            # Identificar problemas de rendimiento
            performance_analysis = self._analyze_performance_issues(days)
            opportunities['performance_issues'] = performance_analysis
            
        except Exception as e:
            self.logger.error(f"Error identifying optimization opportunities: {e}")
        
        return opportunities
    
    def _analyze_thresholds(self, days: int) -> List[Dict[str, Any]]:
        """Analiza thresholds que necesitan ajuste"""
        adjustments = []
        
        with sqlite3.connect(self.db_path) as conn:
            # Analizar BERT confidence vs success rate
            cursor = conn.execute("""
                SELECT 
                    CASE 
                        WHEN bert_confidence < 0.5 THEN 'low'
                        WHEN bert_confidence < 0.8 THEN 'medium'
                        ELSE 'high'
                    END as confidence_range,
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY confidence_range
            """.format(days))
            
            for row in cursor.fetchall():
                confidence_range, total, successful = row
                success_rate = (successful / total * 100) if total > 0 else 0
                
                if confidence_range == 'low' and success_rate > 70:
                    adjustments.append({
                        'type': 'bert_confidence_threshold',
                        'current': 'high',
                        'recommended': 'lower',
                        'reason': f'Low confidence range has {success_rate:.1f}% success rate'
                    })
                elif confidence_range == 'high' and success_rate < 80:
                    adjustments.append({
                        'type': 'bert_confidence_threshold',
                        'current': 'low',
                        'recommended': 'higher',
                        'reason': f'High confidence range only has {success_rate:.1f}% success rate'
                    })
        
        return adjustments
    
    def _analyze_failing_strategies(self, days: int) -> List[Dict[str, Any]]:
        """Analiza estrategias que fallan frecuentemente"""
        failing_strategies = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    challenge_type,
                    failed_strategies,
                    COUNT(*) as frequency
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                AND success = 0
                AND failed_strategies != '[]'
                GROUP BY challenge_type, failed_strategies
                HAVING frequency > 2
                ORDER BY frequency DESC
            """.format(days))
            
            for row in cursor.fetchall():
                challenge_type, failed_strategies_json, frequency = row
                try:
                    failed_strategies_list = json.loads(failed_strategies_json)
                    if failed_strategies_list:
                        failing_strategies.append({
                            'challenge_type': challenge_type,
                            'strategies': failed_strategies_list,
                            'failure_frequency': frequency,
                            'recommendation': 'Review strategy parameters or add alternative approaches'
                        })
                except json.JSONDecodeError:
                    continue
        
        return failing_strategies
    
    def _analyze_retraining_needs(self, days: int) -> List[Dict[str, Any]]:
        """Analiza necesidades de reentrenamiento"""
        retraining_needs = []
        
        # Verificar si BERT accuracy ha bajado
        recent_bert_accuracy = self._get_bert_accuracy(days=3)
        historical_bert_accuracy = self._get_bert_accuracy(days=14)
        
        if recent_bert_accuracy < historical_bert_accuracy - 5:
            retraining_needs.append({
                'model': 'BERT',
                'current_accuracy': recent_bert_accuracy,
                'historical_accuracy': historical_bert_accuracy,
                'recommendation': 'Consider retraining BERT with recent challenging cases'
            })
        
        # Verificar si RAG effectiveness ha bajado
        recent_rag_effectiveness = self._get_rag_effectiveness(days=3)
        historical_rag_effectiveness = self._get_rag_effectiveness(days=14)
        
        if recent_rag_effectiveness < historical_rag_effectiveness - 10:
            retraining_needs.append({
                'model': 'RAG',
                'current_effectiveness': recent_rag_effectiveness,
                'historical_effectiveness': historical_rag_effectiveness,
                'recommendation': 'Consider updating RAG embeddings with new writeups'
            })
        
        return retraining_needs
    
    def _analyze_performance_issues(self, days: int) -> List[Dict[str, Any]]:
        """Analiza problemas de rendimiento"""
        issues = []
        
        with sqlite3.connect(self.db_path) as conn:
            # Analizar tiempos de respuesta altos
            cursor = conn.execute("""
                SELECT 
                    challenge_type,
                    AVG(total_time) as avg_time,
                    MAX(total_time) as max_time,
                    COUNT(*) as count
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                GROUP BY challenge_type
                HAVING avg_time > 3.0
            """.format(days))
            
            for row in cursor.fetchall():
                challenge_type, avg_time, max_time, count = row
                issues.append({
                    'type': 'high_response_time',
                    'challenge_type': challenge_type,
                    'avg_time': avg_time,
                    'max_time': max_time,
                    'occurrences': count,
                    'recommendation': f'Optimize strategies for {challenge_type} challenges'
                })
        
        return issues
    
    def _get_bert_accuracy(self, days: int) -> float:
        """Obtiene accuracy de BERT en los últimos N días"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN bert_prediction = challenge_type THEN 1 ELSE 0 END) as correct
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
            """.format(days))
            
            row = cursor.fetchone()
            if row:
                total, correct = row
                return (correct / total * 100) if total > 0 else 0
            return 0
    
    def _get_rag_effectiveness(self, days: int) -> float:
        """Obtiene efectividad de RAG en los últimos N días"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    AVG(planner_rag_patterns) as avg_patterns,
                    AVG(CASE WHEN success = 1 THEN planner_rag_patterns ELSE 0 END) as avg_successful_patterns
                FROM executions 
                WHERE created_at >= datetime('now', '-{} days')
                AND planner_rag_patterns > 0
            """.format(days))
            
            row = cursor.fetchone()
            if row:
                avg_patterns, avg_successful_patterns = row
                if avg_patterns and avg_patterns > 0:
                    return (avg_successful_patterns / avg_patterns * 100)
            return 0

# Instancia global del analyzer
metrics_analyzer = MetricsAnalyzer()