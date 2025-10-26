"""
Phase 3.0 Configuration
Configuración centralizada para todo el sistema Phase 3.0
"""

import os
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).parent.parent
PHASE3_DIR = Path(__file__).parent
FRONTEND_DIR = PHASE3_DIR / "frontend"
BACKEND_DIR = PHASE3_DIR / "backend"
DATA_DIR = PHASE3_DIR / "data"
LOGS_DIR = PHASE3_DIR / "logs"
SCRIPTS_DIR = PHASE3_DIR / "scripts"

# API Configuration
API_HOST = "localhost"
API_PORT = 8000
API_URL = f"http://{API_HOST}:{API_PORT}"

# Frontend Configuration
FRONTEND_PORT = 3000
FRONTEND_URL = f"http://localhost:{FRONTEND_PORT}"

# Database Configuration
DATABASE_PATH = DATA_DIR / "feedback.db"
JSONL_PATH = DATA_DIR / "feedback.jsonl"

# Learning System Configuration
LEARNING_CONFIG = {
    "feedback_retention_days": 90,
    "metrics_cache_ttl": 300,  # 5 minutes
    "auto_tune_interval": 86400,  # 24 hours
}

# Multi-Agent Configuration
MULTIAGENT_CONFIG = {
    "max_execution_time": 300,  # 5 minutes
    "max_concurrent_executions": 5,
    "default_strategies": {
        "RSA": ["rsa_factorization_attacks", "wiener_attack", "fermat_factorization"],
        "Classical": ["frequency_analysis", "brute_force_rotation", "dictionary_attack"],
        "XOR": ["single_byte_bruteforce", "multi_byte_analysis", "key_reuse_attack"],
    }
}

# Backend Options
BACKEND_OPTIONS = {
    "simple": {
        "name": "Simple Backend",
        "description": "HTTP server with mock data (recommended for development)",
        "dependencies": [],
        "startup_time": "< 1s",
        "response_time": "< 10ms"
    },
    "mini": {
        "name": "Mini Backend", 
        "description": "Ultra-minimal socket server",
        "dependencies": [],
        "startup_time": "< 0.5s",
        "response_time": "< 5ms"
    },
    "fastapi": {
        "name": "FastAPI Backend",
        "description": "Full-featured API with real learning system",
        "dependencies": ["fastapi", "uvicorn"],
        "startup_time": "2-5s",
        "response_time": "50-200ms"
    }
}

# Environment
ENVIRONMENT = os.getenv("PHASE3_ENV", "development")
DEBUG = ENVIRONMENT == "development"

def ensure_directories():
    """Ensure all necessary directories exist"""
    directories = [DATA_DIR, LOGS_DIR, SCRIPTS_DIR]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

def get_backend_info(backend_type: str = "simple") -> dict:
    """Get information about a backend type"""
    return BACKEND_OPTIONS.get(backend_type, BACKEND_OPTIONS["simple"])

def get_api_url() -> str:
    """Get the API URL"""
    return API_URL

def get_frontend_url() -> str:
    """Get the frontend URL"""
    return FRONTEND_URL

# Initialize directories on import
ensure_directories()