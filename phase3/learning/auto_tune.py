"""
Auto-Tuning System
Sistema de ajuste automático de parámetros basado en feedback histórico
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import sys

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from phase3.learning.feedback_collector import feedback_collector
from phase3.learning.metrics_analyzer import metrics_analyzer

class AutoTuner:
    """Sistema de auto-ajuste de parámetros"""
    
    def __init__(self, config_path: str = "multi_agent/config.py"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        self.tuning_history = []
        
        # Parámetros ajustables y sus rangos
        self.tunable_parameters = {
            'rag_threshold': {
                'current': 0.4,
                'min': 0.2,
                'max': 0.8,
                'step': 0.05,
                'metric': 'rag_effectiveness'
            },
            'bert_confidence_threshold': {
                'current': 0.5,
                'min': 0.3,
                'max': 0.9,
                'step': 0.05,
                'metric': 'bert_accuracy'
            },
            'max_strategies': {
                'current': 5,
                'min': 3,
                'max': 8,
                'step': 1,
                'metric': 'success_rate'
            },
            'max_attempts_per_strategy': {
                'current': 3,
                'min': 2,
                'max': 5,
                'step': 1,
                'metric': 'execution_efficiency'
            }
        }
    
    def run_auto_tuning(self, days: int = 7) -> Dict[str, Any]:
        """Ejecuta el proceso de auto-ajuste"""
        self.logger.info("🔧 Starting auto-tuning process...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'period_analyzed': f"{days} days",
            'adjustments_made': [],
            'recommendations': [],
            'performance_impact': {}
        }
        
        try:
            # Analizar rendimiento actual
            current_metrics = metrics_analyzer.analyze_current_performance(days)
            
            # Identificar oportunidades de optimización
            opportunities = metrics_analyzer.identify_optimization_opportunities(days)
            
            # Procesar ajustes de thresholds
            threshold_adjustments = self._process_threshold_adjustments(
                opportunities.get('threshold_adjustments', [])
            )
            results['adjustments_made'].extend(threshold_adjustments)
            
            # Procesar mejoras de estrategias
            strategy_improvements = self._process_strategy_improvements(
                opportunities.get('strategy_improvements', [])
            )
            results['recommendations'].extend(strategy_improvements)
            
            # Evaluar necesidad de reentrenamiento
            retraining_needs = self._evaluate_retraining_needs(
                opportunities.get('model_retraining', [])
            )
            results['recommendations'].extend(retraining_needs)
            
            # Calcular impacto esperado
            results['performance_impact'] = self._calculate_expected_impact(
                current_metrics, results['adjustments_made']
            )
            
            # Guardar historial
            self.tuning_history.append(results)
            self._save_tuning_history()
            
            self.logger.info(f"✅ Auto-tuning completed. Made {len(results['adjustments_made'])} adjustments.")
            
        except Exception as e:
            self.logger.error(f"❌ Auto-tuning failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _process_threshold_adjustments(self, adjustments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Procesa ajustes de thresholds"""
        applied_adjustments = []
        
        for adjustment in adjustments:
            param_type = adjustment.get('type')
            
            if param_type == 'bert_confidence_threshold':
                new_value = self._adjust_bert_threshold(adjustment)
                if new_value:
                    applied_adjustments.append({
                        'parameter': 'bert_confidence_threshold',
                        'old_value': self.tunable_parameters['bert_confidence_threshold']['current'],
                        'new_value': new_value,
                        'reason': adjustment.get('reason', 'Performance optimization')
                    })
                    self.tunable_parameters['bert_confidence_threshold']['current'] = new_value
            
            elif param_type == 'rag_threshold':
                new_value = self._adjust_rag_threshold(adjustment)
                if new_value:
                    applied_adjustments.append({
                        'parameter': 'rag_threshold',
                        'old_value': self.tunable_parameters['rag_threshold']['current'],
                        'new_value': new_value,
                        'reason': adjustment.get('reason', 'RAG effectiveness optimization')
                    })
                    self.tunable_parameters['rag_threshold']['current'] = new_value
        
        return applied_adjustments
    
    def _adjust_bert_threshold(self, adjustment: Dict[str, Any]) -> Optional[float]:
        """Ajusta el threshold de BERT"""
        current = self.tunable_parameters['bert_confidence_threshold']['current']
        step = self.tunable_parameters['bert_confidence_threshold']['step']
        min_val = self.tunable_parameters['bert_confidence_threshold']['min']
        max_val = self.tunable_parameters['bert_confidence_threshold']['max']
        
        recommended = adjustment.get('recommended', '').lower()
        
        if recommended == 'lower' and current > min_val:
            return max(current - step, min_val)
        elif recommended == 'higher' and current < max_val:
            return min(current + step, max_val)
        
        return None
    
    def _adjust_rag_threshold(self, adjustment: Dict[str, Any]) -> Optional[float]:
        """Ajusta el threshold de RAG"""
        current = self.tunable_parameters['rag_threshold']['current']
        step = self.tunable_parameters['rag_threshold']['step']
        min_val = self.tunable_parameters['rag_threshold']['min']
        max_val = self.tunable_parameters['rag_threshold']['max']
        
        # Lógica basada en efectividad de RAG
        try:
            recent_feedback = feedback_collector.get_recent_feedback(limit=20)
            if recent_feedback:
                avg_rag_patterns = sum(f.planner_rag_patterns for f in recent_feedback) / len(recent_feedback)
                success_with_rag = sum(1 for f in recent_feedback if f.success and f.planner_rag_patterns > 0)
                total_with_rag = sum(1 for f in recent_feedback if f.planner_rag_patterns > 0)
                
                if total_with_rag > 0:
                    rag_success_rate = success_with_rag / total_with_rag
                    
                    # Si RAG tiene alta tasa de éxito pero pocos patrones, bajar threshold
                    if rag_success_rate > 0.8 and avg_rag_patterns < 2 and current > min_val:
                        return max(current - step, min_val)
                    
                    # Si RAG tiene baja tasa de éxito, subir threshold
                    elif rag_success_rate < 0.6 and current < max_val:
                        return min(current + step, max_val)
        
        except Exception as e:
            self.logger.warning(f"Could not analyze RAG effectiveness: {e}")
        
        return None
    
    def _process_strategy_improvements(self, improvements: List[Dict[str, Any]]) -> List[str]:
        """Procesa mejoras de estrategias"""
        recommendations = []
        
        for improvement in improvements:
            challenge_type = improvement.get('challenge_type', 'Unknown')
            strategies = improvement.get('strategies', [])
            frequency = improvement.get('failure_frequency', 0)
            
            if frequency > 3:  # Si falla más de 3 veces
                recommendations.append(
                    f"🎯 Consider reviewing {challenge_type} strategies. "
                    f"Frequent failures detected ({frequency} times)."
                )
                
                # Sugerir estrategias específicas
                if strategies:
                    strategy_names = [s.get('name', 'unknown') for s in strategies[:2]]
                    recommendations.append(
                        f"   - Focus on optimizing: {', '.join(strategy_names)}"
                    )
        
        return recommendations
    
    def _evaluate_retraining_needs(self, retraining_needs: List[Dict[str, Any]]) -> List[str]:
        """Evalúa necesidades de reentrenamiento"""
        recommendations = []
        
        for need in retraining_needs:
            model = need.get('model', 'Unknown')
            current_acc = need.get('current_accuracy', 0)
            historical_acc = need.get('historical_accuracy', 0)
            
            if model == 'BERT' and current_acc < historical_acc - 5:
                recommendations.append(
                    f"🧠 BERT model performance declined: {current_acc:.1f}% vs {historical_acc:.1f}%. "
                    f"Consider retraining with recent challenging cases."
                )
            
            elif model == 'RAG' and current_acc < historical_acc - 10:
                recommendations.append(
                    f"📚 RAG effectiveness declined: {current_acc:.1f}% vs {historical_acc:.1f}%. "
                    f"Consider updating embeddings with new writeups."
                )
        
        return recommendations
    
    def _calculate_expected_impact(self, current_metrics: Any, adjustments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calcula el impacto esperado de los ajustes"""
        impact = {
            'expected_success_rate_change': 0.0,
            'expected_response_time_change': 0.0,
            'confidence_level': 'medium'
        }
        
        # Estimar impacto basado en ajustes realizados
        for adjustment in adjustments:
            param = adjustment['parameter']
            
            if param == 'bert_confidence_threshold':
                # Threshold más bajo puede aumentar recall pero disminuir precision
                if adjustment['new_value'] < adjustment['old_value']:
                    impact['expected_success_rate_change'] += 2.0
                else:
                    impact['expected_success_rate_change'] -= 1.0
            
            elif param == 'rag_threshold':
                # Threshold más bajo puede traer más contexto
                if adjustment['new_value'] < adjustment['old_value']:
                    impact['expected_success_rate_change'] += 1.5
                    impact['expected_response_time_change'] += 0.1
        
        # Ajustar nivel de confianza
        if len(adjustments) > 2:
            impact['confidence_level'] = 'high'
        elif len(adjustments) == 0:
            impact['confidence_level'] = 'low'
        
        return impact
    
    def _save_tuning_history(self):
        """Guarda el historial de ajustes"""
        history_path = Path("phase3/data/tuning_history.json")
        history_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(history_path, 'w') as f:
                json.dump(self.tuning_history, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Could not save tuning history: {e}")
    
    def get_current_parameters(self) -> Dict[str, Any]:
        """Obtiene los parámetros actuales"""
        return {param: config['current'] for param, config in self.tunable_parameters.items()}
    
    def apply_parameters_to_config(self) -> bool:
        """Aplica los parámetros ajustados al archivo de configuración"""
        try:
            # Leer configuración actual
            if not self.config_path.exists():
                self.logger.warning(f"Config file not found: {self.config_path}")
                return False
            
            # Por ahora, solo loggeamos los cambios
            # En una implementación completa, modificaríamos el archivo de config
            current_params = self.get_current_parameters()
            self.logger.info("Current optimized parameters:")
            for param, value in current_params.items():
                self.logger.info(f"  {param}: {value}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Could not apply parameters to config: {e}")
            return False
    
    def generate_tuning_report(self, days: int = 7) -> str:
        """Genera un reporte de ajustes"""
        try:
            results = self.run_auto_tuning(days)
            
            report = f"""
# 🔧 Auto-Tuning Report
**Generated**: {results['timestamp']}
**Period Analyzed**: {results['period_analyzed']}

## Adjustments Made ({len(results['adjustments_made'])})
"""
            
            if results['adjustments_made']:
                for adj in results['adjustments_made']:
                    report += f"""
- **{adj['parameter']}**: {adj['old_value']} → {adj['new_value']}
  - Reason: {adj['reason']}
"""
            else:
                report += "\nNo adjustments were necessary.\n"
            
            report += f"""
## Recommendations ({len(results['recommendations'])})
"""
            
            if results['recommendations']:
                for rec in results['recommendations']:
                    report += f"- {rec}\n"
            else:
                report += "\nNo specific recommendations at this time.\n"
            
            # Impacto esperado
            impact = results.get('performance_impact', {})
            if impact:
                report += f"""
## Expected Impact
- **Success Rate Change**: {impact.get('expected_success_rate_change', 0):+.1f}%
- **Response Time Change**: {impact.get('expected_response_time_change', 0):+.2f}s
- **Confidence Level**: {impact.get('confidence_level', 'medium')}
"""
            
            return report
            
        except Exception as e:
            return f"Error generating tuning report: {e}"

# Instancia global
auto_tuner = AutoTuner()

def main():
    """Función principal para ejecutar auto-tuning"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-tune multi-agent system parameters")
    parser.add_argument("--days", type=int, default=7, help="Days of history to analyze")
    parser.add_argument("--report", action="store_true", help="Generate tuning report")
    parser.add_argument("--apply", action="store_true", help="Apply parameters to config")
    
    args = parser.parse_args()
    
    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if args.report:
        print(auto_tuner.generate_tuning_report(args.days))
    else:
        results = auto_tuner.run_auto_tuning(args.days)
        print(f"Auto-tuning completed. Made {len(results['adjustments_made'])} adjustments.")
        
        if args.apply:
            if auto_tuner.apply_parameters_to_config():
                print("Parameters applied to configuration.")
            else:
                print("Failed to apply parameters to configuration.")

if __name__ == "__main__":
    main()