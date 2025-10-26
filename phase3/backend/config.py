"""
Backend Configuration
Configuración del backend FastAPI
"""

import os
from typing import List
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Configuración del backend"""
    
    # API Configuration
    API_V1_STR: str = "/api"
    PROJECT_NAME: str = "Multi-Agent CTF System"
    VERSION: str = "3.0.0"
    DESCRIPTION: str = "API profesional para el sistema multi-agente de resolución de CTFs"
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    RELOAD: bool = True
    
    # CORS Configuration
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ]
    
    # Database Configuration
    DATABASE_URL: str = "sqlite:///./phase3/data/feedback.db"
    
    # Learning System Configuration
    FEEDBACK_RETENTION_DAYS: int = 90
    METRICS_CACHE_TTL: int = 300  # 5 minutes
    AUTO_TUNE_INTERVAL: int = 86400  # 24 hours
    
    # Multi-Agent Configuration
    MAX_EXECUTION_TIME: int = 300  # 5 minutes
    MAX_CONCURRENT_EXECUTIONS: int = 5
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Security Configuration
    SECRET_KEY: str = "your-secret-key-here"  # Change in production
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Instancia global de configuración
settings = Settings()

# Configuración de logging
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": settings.LOG_FORMAT,
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s",
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "formatter": "detailed",
            "class": "logging.FileHandler",
            "filename": "phase3/logs/backend.log",
            "mode": "a",
        },
    },
    "root": {
        "level": settings.LOG_LEVEL,
        "handlers": ["default", "file"],
    },
}