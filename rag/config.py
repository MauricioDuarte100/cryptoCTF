"""
RAG Configuration
Archivo de configuración para todo el sistema RAG.
Centraliza paths, modelos, hyperparámetros.
"""

from pathlib import Path

# RUTAS
RAG_DIR = Path("rag")
CHROMADB_PATH = RAG_DIR / "chromadb"
EVALUATION_DIR = RAG_DIR / "evaluation"
LOGS_DIR = RAG_DIR / "logs"

# Crear directorios si no existen
for d in [CHROMADB_PATH, EVALUATION_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# MODELOS
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # 384 dimensiones, 22MB, rápido
# Alternativa: "sentence-transformers/all-mpnet-base-v2"  # 768 dims, 438MB, más preciso

# HYPERPARÁMETROS RAG
RETRIEVAL_K = 3  # Número de documentos a recuperar
SIMILARITY_THRESHOLD = 0.5  # Similitud mínima (0-1)
MAX_CONTEXT_LENGTH = 1000  # Caracteres máximos por documento
BATCH_SIZE = 32  # Para embedding de múltiples textos

# CHROMADB SETTINGS
CHROMADB_SETTINGS = {
    "chroma_db_impl": "duckdb",
    "is_persistent": True,
    "anonymized_telemetry": False
}

# COLECCIONES
COLLECTIONS = {
    "writeups": {
        "name": "writeups",
        "description": "CTF writeups indexed for retrieval",
        "metadata_keys": ["source", "words", "ctf_event"]
    },
    "challenges": {
        "name": "challenges",
        "description": "CTF challenges indexed by type",
        "metadata_keys": ["label", "repo", "difficulty"]
    },
    "solutions": {
        "name": "solutions",
        "description": "Successful solutions and patterns",
        "metadata_keys": ["attack_type", "tools_used", "success_rate"]
    }
}

# LOGGING
LOG_LEVEL = "INFO"
LOG_FILE = LOGS_DIR / "rag.log"

print("✅ RAG Configuration loaded")