"""
RAG Utils
Utilidades generales para todo el sistema RAG.
"""

import json
import logging
from pathlib import Path
from rag.config import LOG_FILE, LOG_LEVEL

def setup_logging():
    """Configura logging para toda la aplicación RAG"""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

def load_jsonl(filepath):
    """Carga archivo JSONL (una línea = un JSON)"""
    data = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Error en línea {line_num}: {e}")
    return data

def save_jsonl(data, filepath):
    """Guarda lista de dicts como JSONL"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    logger.info(f"Guardado: {filepath} ({len(data)} items)")

def truncate_text(text, max_length=1000):
    """Trunca texto a longitud máxima"""
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text

def calculate_similarity(score):
    """Convierte distancia a similitud (0-1)"""
    return max(0, 1 - score)

logger.info("✅ Utils module loaded")