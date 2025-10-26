"""
Optimizaciones y mejoras para el agente CTF Crypto
"""

import time
import functools
from typing import Dict, Any, Callable
import logging

# ============ SISTEMA DE CACHE ============

class ResultCache:
    """Cache inteligente para resultados de herramientas"""
    
    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
    
    def get_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Genera clave única para cache"""
        return f"{func_name}:{hash((args, tuple(sorted(kwargs.items()))))}"
    
    def get(self, key: str) -> Any:
        """Obtiene valor del cache"""
        if key in self.cache:
            self.access_times[key] = time.time()
            return self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """Guarda valor en cache"""
        # Limpiar cache si está lleno
        if len(self.cache) >= self.max_size:
            # Remover el menos usado recientemente
            oldest_key = min(self.access_times.keys(), 
                           key=lambda k: self.access_times[k])
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
        
        self.cache[key] = value
        self.access_times[key] = time.time()

# Cache global
result_cache = ResultCache()

def cached_tool(func: Callable) -> Callable:
    """Decorator para cachear resultados de herramientas"""
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Generar clave de cache
        cache_key = result_cache.get_key(func.__name__, args, kwargs)
        
        # Intentar obtener del cache
        cached_result = result_cache.get(cache_key)
        if cached_result is not None:
            logging.info(f"Cache hit for {func.__name__}")
            return cached_result
        
        # Ejecutar función y cachear resultado
        result = func(*args, **kwargs)
        result_cache.set(cache_key, result)
        
        return result
    
    return wrapper

# ============ SISTEMA DE TIMEOUTS ADAPTATIVOS ============

class AdaptiveTimeout:
    """Maneja timeouts adaptativos basados en historial"""
    
    def __init__(self):
        self.execution_times = {}
        self.success_rates = {}
    
    def record_execution(self, tool_name: str, duration: float, success: bool):
        """Registra tiempo de ejecución y éxito"""
        if tool_name not in self.execution_times:
            self.execution_times[tool_name] = []
            self.success_rates[tool_name] = []
        
        self.execution_times[tool_name].append(duration)
        self.success_rates[tool_name].append(success)
        
        # Mantener solo últimas 10 ejecuciones
        if len(self.execution_times[tool_name]) > 10:
            self.execution_times[tool_name] = self.execution_times[tool_name][-10:]
            self.success_rates[tool_name] = self.success_rates[tool_name][-10:]
    
    def get_optimal_timeout(self, tool_name: str, base_timeout: float = 30) -> float:
        """Calcula timeout óptimo basado en historial"""
        if tool_name not in self.execution_times:
            return base_timeout
        
        times = self.execution_times[tool_name]
        success_rate = sum(self.success_rates[tool_name]) / len(self.success_rates[tool_name])
        
        # Timeout = percentil 90 de tiempos + buffer basado en tasa de éxito
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        # Si la tasa de éxito es baja, dar más tiempo
        success_multiplier = 1.5 if success_rate < 0.5 else 1.0
        
        optimal = min(avg_time * 2 * success_multiplier, max_time * 1.2)
        return max(optimal, base_timeout)

# Instancia global
adaptive_timeout = AdaptiveTimeout()

# ============ PARALELIZACIÓN DE ATAQUES ============

import concurrent.futures
import threading

class ParallelAttackManager:
    """Ejecuta múltiples ataques en paralelo"""
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.results = {}
        self.lock = threading.Lock()
    
    def execute_parallel_attacks(self, attacks: list) -> Dict[str, Any]:
        """
        Ejecuta ataques en paralelo
        
        Args:
            attacks: Lista de dicts con 'name', 'func', 'args', 'kwargs'
        
        Returns:
            Dict con resultados de cada ataque
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Enviar todos los ataques
            future_to_attack = {}
            for attack in attacks:
                future = executor.submit(
                    attack['func'], 
                    *attack.get('args', []), 
                    **attack.get('kwargs', {})
                )
                future_to_attack[future] = attack['name']
            
            # Recoger resultados conforme completan
            for future in concurrent.futures.as_completed(future_to_attack):
                attack_name = future_to_attack[future]
                try:
                    result = future.result(timeout=60)  # Timeout por ataque
                    results[attack_name] = result
                    
                    # Si encontramos flag, cancelar otros
                    if isinstance(result, dict) and result.get('success') and result.get('flag'):
                        # Cancelar ataques restantes
                        for f in future_to_attack:
                            if not f.done():
                                f.cancel()
                        break
                        
                except Exception as e:
                    results[attack_name] = {
                        'success': False,
                        'error': str(e)
                    }
        
        return results

# ============ SISTEMA DE PRIORIDADES ============

class AttackPrioritizer:
    """Prioriza ataques basado en probabilidad de éxito"""
    
    def __init__(self):
        self.success_history = {
            'RSA': {
                'attack_rsa': 0.8,
                'factorize_number': 0.6,
                'execute_sage': 0.4
            },
            'Classical': {
                'attack_classical': 0.9,
                'decode_text': 0.7
            },
            'XOR': {
                'attack_classical': 0.8,
                'decode_text': 0.6
            }
        }
    
    def get_attack_priority(self, crypto_type: str, attack_name: str) -> float:
        """Obtiene prioridad de un ataque (0.0 - 1.0)"""
        return self.success_history.get(crypto_type, {}).get(attack_name, 0.5)
    
    def sort_attacks_by_priority(self, crypto_type: str, attacks: list) -> list:
        """Ordena ataques por prioridad descendente"""
        return sorted(
            attacks,
            key=lambda attack: self.get_attack_priority(crypto_type, attack['name']),
            reverse=True
        )
    
    def update_success_rate(self, crypto_type: str, attack_name: str, success: bool):
        """Actualiza tasa de éxito de un ataque"""
        if crypto_type not in self.success_history:
            self.success_history[crypto_type] = {}
        
        current_rate = self.success_history[crypto_type].get(attack_name, 0.5)
        # Promedio móvil simple
        new_rate = (current_rate * 0.8) + (1.0 if success else 0.0) * 0.2
        self.success_history[crypto_type][attack_name] = new_rate

# ============ LOGGING AVANZADO ============

def setup_advanced_logging():
    """Configura logging detallado"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ctf_agent.log'),
            logging.StreamHandler()
        ]
    )
    
    # Logger específico para herramientas
    tool_logger = logging.getLogger('tools')
    tool_logger.setLevel(logging.DEBUG)
    
    return tool_logger

# ============ MÉTRICAS DE RENDIMIENTO ============

class PerformanceMetrics:
    """Recolecta métricas de rendimiento del agente"""
    
    def __init__(self):
        self.metrics = {
            'total_challenges': 0,
            'successful_challenges': 0,
            'avg_solve_time': 0.0,
            'tool_usage': {},
            'crypto_type_success': {}
        }
    
    def record_challenge(self, success: bool, solve_time: float, 
                        crypto_type: str, tools_used: list):
        """Registra métricas de un desafío"""
        self.metrics['total_challenges'] += 1
        
        if success:
            self.metrics['successful_challenges'] += 1
        
        # Actualizar tiempo promedio
        total_time = self.metrics['avg_solve_time'] * (self.metrics['total_challenges'] - 1)
        self.metrics['avg_solve_time'] = (total_time + solve_time) / self.metrics['total_challenges']
        
        # Actualizar uso de herramientas
        for tool in tools_used:
            if tool not in self.metrics['tool_usage']:
                self.metrics['tool_usage'][tool] = 0
            self.metrics['tool_usage'][tool] += 1
        
        # Actualizar éxito por tipo
        if crypto_type not in self.metrics['crypto_type_success']:
            self.metrics['crypto_type_success'][crypto_type] = {'total': 0, 'success': 0}
        
        self.metrics['crypto_type_success'][crypto_type]['total'] += 1
        if success:
            self.metrics['crypto_type_success'][crypto_type]['success'] += 1
    
    def get_success_rate(self) -> float:
        """Obtiene tasa de éxito general"""
        if self.metrics['total_challenges'] == 0:
            return 0.0
        return self.metrics['successful_challenges'] / self.metrics['total_challenges']
    
    def get_report(self) -> str:
        """Genera reporte de métricas"""
        report = f"""
📊 MÉTRICAS DE RENDIMIENTO
========================
Total desafíos: {self.metrics['total_challenges']}
Éxitos: {self.metrics['successful_challenges']}
Tasa de éxito: {self.get_success_rate():.2%}
Tiempo promedio: {self.metrics['avg_solve_time']:.1f}s

🔧 Herramientas más usadas:
"""
        
        for tool, count in sorted(self.metrics['tool_usage'].items(), 
                                key=lambda x: x[1], reverse=True):
            report += f"  {tool}: {count} veces\n"
        
        report += "\n🎯 Éxito por tipo de crypto:\n"
        for crypto_type, stats in self.metrics['crypto_type_success'].items():
            rate = stats['success'] / stats['total'] if stats['total'] > 0 else 0
            report += f"  {crypto_type}: {rate:.2%} ({stats['success']}/{stats['total']})\n"
        
        return report

# Instancias globales
parallel_manager = ParallelAttackManager()
attack_prioritizer = AttackPrioritizer()
performance_metrics = PerformanceMetrics()