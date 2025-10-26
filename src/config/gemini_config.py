"""
Configuración específica para Gemini 2.5 Flash
Optimizada según las especificaciones de la Fase 1
"""

import os
from typing import Dict, Any

class GeminiConfig:
    """Configuración optimizada para Gemini 2.5 Flash"""
    
    # Modelos disponibles en el tier gratuito
    AVAILABLE_MODELS = {
        "gemini-2.5-flash": {
            "rpm": 15,  # Requests per minute
            "rpd": 1500,  # Requests per day
            "tokens_per_minute": 250000,
            "context_window": 1000000,
            "cost": "FREE",
            "recommended": True
        },
        "gemini-1.5-flash": {
            "rpm": 15,
            "rpd": 1500,
            "tokens_per_minute": 250000,
            "context_window": 1000000,
            "cost": "FREE",
            "recommended": False
        }
    }
    
    # Configuración por defecto
    DEFAULT_MODEL = "gemini-2.5-flash"
    DEFAULT_TEMPERATURE = 0.1  # Baja para consistencia en crypto
    DEFAULT_MAX_TOKENS = 8192
    DEFAULT_TOP_P = 0.95
    DEFAULT_TOP_K = 40
    
    # Configuración específica para CTF Crypto
    CTF_OPTIMIZED_PARAMS = {
        "temperature": 0.1,  # Determinístico para crypto
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
        "candidate_count": 1,
        "stop_sequences": ["```END```"]
    }
    
    # Rate limiting
    RATE_LIMIT_BUFFER = 0.8  # Usar solo 80% del límite
    REQUEST_DELAY = 4.0  # Segundos entre requests (15 RPM = 4s)
    
    @classmethod
    def get_model_info(cls, model_name: str = None) -> Dict[str, Any]:
        """Obtiene información del modelo"""
        model_name = model_name or cls.DEFAULT_MODEL
        return cls.AVAILABLE_MODELS.get(model_name, {})
    
    @classmethod
    def get_optimized_params(cls, challenge_type: str = "general") -> Dict[str, Any]:
        """Obtiene parámetros optimizados según el tipo de desafío"""
        
        base_params = cls.CTF_OPTIMIZED_PARAMS.copy()
        
        # Ajustes específicos por tipo
        if challenge_type == "rsa":
            base_params["temperature"] = 0.05  # Muy determinístico
            base_params["max_output_tokens"] = 4096
        
        elif challenge_type == "classical":
            base_params["temperature"] = 0.15  # Algo más creativo
            base_params["max_output_tokens"] = 2048
        
        elif challenge_type == "lattice":
            base_params["temperature"] = 0.1
            base_params["max_output_tokens"] = 8192  # Más tokens para SageMath
        
        elif challenge_type == "unknown":
            base_params["temperature"] = 0.2  # Más exploración
            base_params["max_output_tokens"] = 6144
        
        return base_params
    
    @classmethod
    def validate_api_key(cls, api_key: str) -> bool:
        """Valida formato de API key de Gemini"""
        if not api_key:
            return False
        
        # Las API keys de Gemini empiezan con "AIza"
        if not api_key.startswith("AIza"):
            return False
        
        # Longitud típica de API key
        if len(api_key) < 35:
            return False
        
        return True
    
    @classmethod
    def get_rate_limit_info(cls, model_name: str = None) -> Dict[str, Any]:
        """Obtiene información de rate limits"""
        model_info = cls.get_model_info(model_name)
        
        return {
            "requests_per_minute": model_info.get("rpm", 15),
            "requests_per_day": model_info.get("rpd", 1500),
            "tokens_per_minute": model_info.get("tokens_per_minute", 250000),
            "recommended_delay": cls.REQUEST_DELAY,
            "buffer_factor": cls.RATE_LIMIT_BUFFER
        }
    
    @classmethod
    def estimate_token_usage(cls, prompt_length: int, max_response: int = None) -> Dict[str, int]:
        """Estima uso de tokens"""
        max_response = max_response or cls.DEFAULT_MAX_TOKENS
        
        # Estimación aproximada: 1 token ≈ 4 caracteres
        prompt_tokens = prompt_length // 4
        response_tokens = max_response
        total_tokens = prompt_tokens + response_tokens
        
        return {
            "prompt_tokens": prompt_tokens,
            "max_response_tokens": response_tokens,
            "total_tokens": total_tokens
        }
    
    @classmethod
    def get_safety_settings(cls) -> list:
        """Configuración de seguridad para CTF (permisiva)"""
        from google.generativeai.types import HarmCategory, HarmBlockThreshold
        
        return [
            {
                "category": HarmCategory.HARM_CATEGORY_HARASSMENT,
                "threshold": HarmBlockThreshold.BLOCK_NONE
            },
            {
                "category": HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                "threshold": HarmBlockThreshold.BLOCK_NONE
            },
            {
                "category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                "threshold": HarmBlockThreshold.BLOCK_NONE
            },
            {
                "category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                "threshold": HarmBlockThreshold.BLOCK_NONE
            }
        ]

# Configuración global de Gemini
gemini_config = GeminiConfig()