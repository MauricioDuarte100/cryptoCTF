"""
Configuración centralizada para CTF Crypto Agent
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class Config:
    """Configuración principal"""
    
    # API Keys
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    
    # Gemini Configuration
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    GEMINI_TEMPERATURE = float(os.getenv("GEMINI_TEMPERATURE", "0.1"))
    GEMINI_MAX_TOKENS = int(os.getenv("GEMINI_MAX_TOKENS", "8192"))
    
    # Agent Configuration
    MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "15"))
    DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "60"))
    ENABLE_CACHE = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    ENABLE_PARALLEL = os.getenv("ENABLE_PARALLEL", "true").lower() == "true"
    
    # Paths
    BASE_DIR = Path(__file__).parent
    EXAMPLES_DIR = BASE_DIR / "examples"
    LOGS_DIR = BASE_DIR / "logs"
    CACHE_DIR = BASE_DIR / ".cache"
    TOOLS_DIR = BASE_DIR / "tools"
    
    # Web Interface
    WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
    WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
    WEB_DEBUG = os.getenv("WEB_DEBUG", "false").lower() == "true"
    
    # External Tools
    RSACTFTOOL_PATH = os.getenv("RSACTFTOOL_PATH", "./RsaCtfTool/RsaCtfTool.py")
    SAGE_PATH = os.getenv("SAGE_PATH", "sage")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = LOGS_DIR / "ctf_agent.log"
    
    # Performance
    CACHE_SIZE = int(os.getenv("CACHE_SIZE", "100"))
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "3"))
    
    @classmethod
    def validate(cls):
        """Valida la configuración"""
        errors = []
        
        if not cls.GOOGLE_API_KEY:
            errors.append("GOOGLE_API_KEY no configurada")
        
        if not cls.EXAMPLES_DIR.exists():
            cls.EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)
        
        if not cls.LOGS_DIR.exists():
            cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        
        if not cls.CACHE_DIR.exists():
            cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        
        return errors
    
    @classmethod
    def get_summary(cls):
        """Obtiene resumen de configuración"""
        return {
            "gemini_model": cls.GEMINI_MODEL,
            "max_iterations": cls.MAX_ITERATIONS,
            "cache_enabled": cls.ENABLE_CACHE,
            "parallel_enabled": cls.ENABLE_PARALLEL,
            "web_host": cls.WEB_HOST,
            "web_port": cls.WEB_PORT,
            "rsactftool_available": Path(cls.RSACTFTOOL_PATH).exists(),
            "sage_available": cls._check_sage_available()
        }
    
    @classmethod
    def _check_sage_available(cls):
        """Verifica si SageMath está disponible"""
        try:
            import subprocess
            subprocess.run([cls.SAGE_PATH, "--version"], 
                         capture_output=True, check=True, timeout=5)
            return True
        except:
            return False

# Configuración para diferentes entornos
class DevelopmentConfig(Config):
    """Configuración para desarrollo"""
    WEB_DEBUG = True
    LOG_LEVEL = "DEBUG"
    MAX_ITERATIONS = 10  # Menos iteraciones para pruebas rápidas

class ProductionConfig(Config):
    """Configuración para producción"""
    WEB_DEBUG = False
    LOG_LEVEL = "INFO"
    ENABLE_CACHE = True
    ENABLE_PARALLEL = True

class TestingConfig(Config):
    """Configuración para testing"""
    MAX_ITERATIONS = 5
    DEFAULT_TIMEOUT = 30
    ENABLE_CACHE = False  # No cache en tests
    LOG_LEVEL = "WARNING"

# Seleccionar configuración según entorno
ENV = os.getenv("ENVIRONMENT", "development").lower()

if ENV == "production":
    config = ProductionConfig()
elif ENV == "testing":
    config = TestingConfig()
else:
    config = DevelopmentConfig()

# Validar configuración al importar
validation_errors = config.validate()
if validation_errors:
    print("⚠️  Errores de configuración:")
    for error in validation_errors:
        print(f"   - {error}")
    
    if "GOOGLE_API_KEY" in str(validation_errors):
        print("\n🔑 Para obtener una API key gratuita:")
        print("   1. Ve a: https://aistudio.google.com/apikey")
        print("   2. Crea una nueva API key")
        print("   3. Añádela a .env: GOOGLE_API_KEY=tu-key-aqui")