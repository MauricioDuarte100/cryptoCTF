"""
Multi-Agent System Configuration
Configuración centralizada para el sistema multi-agente
"""

import os
from typing import Dict, Any, List

class MultiAgentConfig:
    """Configuración centralizada para el sistema multi-agente"""
    
    # Configuración de agentes
    AGENT_CONFIG = {
        "planner": {
            "max_strategies": 5,
            "min_confidence": 0.5,
            "rag_threshold": 0.4,
            "max_rag_patterns": 5,
            "timeout": 30  # segundos
        },
        "executor": {
            "max_attempts_per_strategy": 3,
            "retry_delay": 0.1,  # segundos
            "timeout_per_strategy": 10,  # segundos
            "parameter_adaptation_rate": 0.1
        },
        "validator": {
            "flag_patterns": [
                r"flag\{[^}]+\}",
                r"FLAG\{[^}]+\}",
                r"ctf\{[^}]+\}",
                r"CTF\{[^}]+\}",
                r"\{[^}]{10,}\}",  # Generic flag pattern
            ],
            "min_entropy": 3.0,
            "quality_thresholds": {
                "excellent": 0.9,
                "good": 0.7,
                "acceptable": 0.5,
                "poor": 0.3
            }
        },
        "coordinator": {
            "max_total_time": 60,  # segundos
            "enable_parallel": False,  # Para futuras versiones
            "log_level": "INFO",
            "save_reports": True
        }
    }
    
    # Configuración de estrategias por tipo de desafío
    STRATEGY_CONFIG = {
        "RSA": {
            "strategies": [
                {
                    "name": "rsa_factorization_attacks",
                    "priority": 1,
                    "success_probability": 1.0,
                    "tool": "attack_rsa",
                    "parameters": {"method": "factorization"}
                },
                {
                    "name": "wiener_attack",
                    "priority": 2,
                    "success_probability": 0.9,
                    "tool": "attack_rsa",
                    "parameters": {"method": "wiener"}
                },
                {
                    "name": "fermat_factorization",
                    "priority": 3,
                    "success_probability": 0.8,
                    "tool": "attack_rsa",
                    "parameters": {"method": "fermat"}
                },
                {
                    "name": "common_modulus",
                    "priority": 4,
                    "success_probability": 0.7,
                    "tool": "attack_rsa",
                    "parameters": {"method": "common_modulus"}
                }
            ]
        },
        "Classical": {
            "strategies": [
                {
                    "name": "frequency_analysis",
                    "priority": 1,
                    "success_probability": 0.8,
                    "tool": "attack_classical",
                    "parameters": {"method": "frequency"}
                },
                {
                    "name": "brute_force_rotation",
                    "priority": 2,
                    "success_probability": 0.7,
                    "tool": "attack_classical",
                    "parameters": {"method": "brute_force"}
                },
                {
                    "name": "dictionary_attack",
                    "priority": 3,
                    "success_probability": 0.6,
                    "tool": "attack_classical",
                    "parameters": {"method": "dictionary"}
                }
            ]
        },
        "XOR": {
            "strategies": [
                {
                    "name": "single_byte_bruteforce",
                    "priority": 1,
                    "success_probability": 0.9,
                    "tool": "attack_classical",
                    "parameters": {"method": "xor_single"}
                },
                {
                    "name": "multi_byte_analysis",
                    "priority": 2,
                    "success_probability": 0.8,
                    "tool": "attack_classical",
                    "parameters": {"method": "xor_multi"}
                },
                {
                    "name": "key_reuse_attack",
                    "priority": 3,
                    "success_probability": 0.7,
                    "tool": "attack_classical",
                    "parameters": {"method": "xor_reuse"}
                }
            ]
        },
        "Encoding": {
            "strategies": [
                {
                    "name": "base64_decode",
                    "priority": 1,
                    "success_probability": 0.8,
                    "tool": "attack_classical",
                    "parameters": {"method": "base64"}
                },
                {
                    "name": "hex_decode",
                    "priority": 2,
                    "success_probability": 0.7,
                    "tool": "attack_classical",
                    "parameters": {"method": "hex"}
                },
                {
                    "name": "url_decode",
                    "priority": 3,
                    "success_probability": 0.6,
                    "tool": "attack_classical",
                    "parameters": {"method": "url"}
                }
            ]
        },
        "Hash": {
            "strategies": [
                {
                    "name": "rainbow_table",
                    "priority": 1,
                    "success_probability": 0.7,
                    "tool": "attack_classical",
                    "parameters": {"method": "rainbow"}
                },
                {
                    "name": "dictionary_hash",
                    "priority": 2,
                    "success_probability": 0.6,
                    "tool": "attack_classical",
                    "parameters": {"method": "hash_dict"}
                },
                {
                    "name": "brute_force_hash",
                    "priority": 3,
                    "success_probability": 0.5,
                    "tool": "attack_classical",
                    "parameters": {"method": "hash_brute"}
                }
            ]
        }
    }
    
    # Configuración de logging
    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "detailed": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "simple": {
                "format": "%(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "simple",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "formatter": "detailed",
                "filename": "multi_agent/logs/multi_agent.log",
                "mode": "a"
            }
        },
        "loggers": {
            "multi_agent": {
                "level": "DEBUG",
                "handlers": ["console", "file"],
                "propagate": False
            }
        }
    }
    
    # Rutas de archivos
    PATHS = {
        "logs": "multi_agent/logs/",
        "reports": "multi_agent/reports/",
        "evaluation": "multi_agent/evaluation/",
        "models": "ml_phase2/trained_model/",
        "rag_data": "rag/data/"
    }
    
    @classmethod
    def get_agent_config(cls, agent_name: str) -> Dict[str, Any]:
        """Obtiene la configuración de un agente específico"""
        return cls.AGENT_CONFIG.get(agent_name, {})
    
    @classmethod
    def get_strategies_for_type(cls, challenge_type: str) -> List[Dict[str, Any]]:
        """Obtiene las estrategias para un tipo de desafío"""
        return cls.STRATEGY_CONFIG.get(challenge_type, {}).get("strategies", [])
    
    @classmethod
    def get_flag_patterns(cls) -> List[str]:
        """Obtiene los patrones de flags para validación"""
        return cls.AGENT_CONFIG["validator"]["flag_patterns"]
    
    @classmethod
    def create_directories(cls):
        """Crea los directorios necesarios si no existen"""
        for path in cls.PATHS.values():
            os.makedirs(path, exist_ok=True)
    
    @classmethod
    def get_timeout(cls, component: str) -> int:
        """Obtiene el timeout para un componente específico"""
        timeouts = {
            "planner": cls.AGENT_CONFIG["planner"]["timeout"],
            "executor": cls.AGENT_CONFIG["executor"]["timeout_per_strategy"],
            "validator": 5,  # timeout fijo para validación
            "coordinator": cls.AGENT_CONFIG["coordinator"]["max_total_time"]
        }
        return timeouts.get(component, 30)

# Configuración global
CONFIG = MultiAgentConfig()

# Crear directorios necesarios al importar
CONFIG.create_directories()