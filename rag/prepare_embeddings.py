"""
BERT Embedding Preparation for RAG
Script que convierte writeups y challenges en embeddings.
Carga datos desde JSONL generado y crea colecciones ChromaDB con vectores embebidos.

EJECUTAR: python -m rag.prepare_embeddings
"""

import json
import time
from pathlib import Path
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
import chromadb

from rag.config import (
    CHROMADB_PATH, EMBEDDING_MODEL, MAX_CONTEXT_LENGTH,
    BATCH_SIZE, CHROMADB_SETTINGS, COLLECTIONS
)
from rag.utils import logger, load_jsonl, truncate_text

class EmbeddingPreparer:
    """Prepara embeddings y crea ChromaDB"""
    
    def __init__(self):
        """Inicializa modelo de embeddings"""
        logger.info(f"Cargando modelo de embeddings: {EMBEDDING_MODEL}")
        self.model = SentenceTransformer(EMBEDDING_MODEL)
        logger.info(f"Modelo cargado. Dimensiones: {self.model.get_sentence_embedding_dimension()}")
        
        # Conectar a ChromaDB (nueva API)
        self.client = chromadb.PersistentClient(path=str(CHROMADB_PATH))
        logger.info(f"ChromaDB inicializado en {CHROMADB_PATH}")
    
    def process_writeups(self, writeups_jsonl):
        """
        Procesa writeups y crea colección ChromaDB.
        
        Input: ml_phase2/evaluation/writeups_ml_dataset.jsonl
        Output: ChromaDB collection "writeups"
        """
        logger.info("Procesando writeups...")
        
        # Cargar datos
        writeups = load_jsonl(writeups_jsonl)
        logger.info(f"Cargados {len(writeups)} writeups")
        
        if len(writeups) == 0:
            logger.warning("No hay writeups para procesar")
            return None
        
        # Preparar textos (limitar longitud)
        texts = []
        ids = []
        metadatas = []
        
        for i, writeup in enumerate(writeups):
            # Truncar contenido
            content = truncate_text(writeup.get('content', ''), MAX_CONTEXT_LENGTH)
            
            if not content or len(content) < 50:
                continue
            
            texts.append(content)
            ids.append(f"writeup_{i:05d}")
            metadatas.append({
                "source": writeup.get('repo', 'unknown'),
                "words": writeup.get('words', 0),
                "ctf_event": writeup.get('ctf_event', 'unknown')
            })
        
        logger.info(f"Textos preparados: {len(texts)} (después de filtrado)")
        
        # Crear embeddings en batch
        logger.info("Generando embeddings (esto puede tardar 1-5 minutos)...")
        embeddings = self.model.encode(
            texts,
            batch_size=BATCH_SIZE,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        logger.info(f"{len(embeddings)} embeddings generados")
        
        # Crear/limpiar colección
        try:
            self.client.delete_collection(name="writeups")
            logger.info("Colección anterior eliminada")
        except:
            pass
        
        collection = self.client.create_collection(
            name="writeups",
            metadata={"hnsw:space": "cosine"}
        )
        
        # Añadir a ChromaDB
        logger.info("Añadiendo a ChromaDB...")
        collection.add(
            ids=ids,
            embeddings=embeddings.tolist(),
            documents=texts,
            metadatas=metadatas
        )
        
        logger.info(f"{len(ids)} writeups guardados en ChromaDB")
        return collection
    
    def process_challenges(self, challenges_jsonl):
        """
        Procesa challenges y crea colección ChromaDB.
        
        Input: ml_phase2/evaluation/challenges_ml_dataset.jsonl
        Output: ChromaDB collection "challenges"
        """
        logger.info("Procesando challenges...")
        
        # Cargar datos
        challenges = load_jsonl(challenges_jsonl)
        logger.info(f"Cargados {len(challenges)} challenges")
        
        if len(challenges) == 0:
            logger.warning("No hay challenges para procesar")
            return None
        
        # Preparar textos
        texts = []
        ids = []
        metadatas = []
        
        for i, challenge in enumerate(challenges):
            content = truncate_text(challenge.get('content', ''), MAX_CONTEXT_LENGTH)
            
            if not content or len(content) < 50:
                continue
            
            texts.append(content)
            ids.append(challenge.get('id', f"challenge_{i:05d}"))
            metadatas.append({
                "label": challenge.get('label', 'Unknown'),
                "repo": challenge.get('repo', 'unknown'),
                "difficulty": challenge.get('difficulty', 'medium')
            })
        
        logger.info(f"Textos preparados: {len(texts)} (después de filtrado)")
        
        # Crear embeddings
        logger.info("Generando embeddings para challenges...")
        embeddings = self.model.encode(
            texts,
            batch_size=BATCH_SIZE,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        logger.info(f"{len(embeddings)} embeddings generados")
        
        # Crear colección
        try:
            self.client.delete_collection(name="challenges")
        except:
            pass
        
        collection = self.client.create_collection(
            name="challenges",
            metadata={"hnsw:space": "cosine"}
        )
        
        # Añadir a ChromaDB
        logger.info("Añadiendo a ChromaDB...")
        collection.add(
            ids=ids,
            embeddings=embeddings.tolist(),
            documents=texts,
            metadatas=metadatas
        )
        
        logger.info(f"{len(ids)} challenges guardados en ChromaDB")
        return collection
    
    def persist(self):
        """Persiste la base de datos (automático en nueva API)"""
        logger.info("ChromaDB se persiste automáticamente")
        logger.info(f"Ubicación: {CHROMADB_PATH}")
    
    def get_collection_stats(self):
        """Obtiene estadísticas de colecciones"""
        stats = {}
        for name in ["writeups", "challenges"]:
            try:
                col = self.client.get_collection(name=name)
                count = col.count()
                stats[name] = count
                logger.info(f"   {name}: {count} items")
            except:
                stats[name] = 0
        return stats

def main():
    logger.info("="*70)
    logger.info("PHASE 2.3: EMBEDDING PREPARATION")
    logger.info("="*70)
    
    # Inicializar
    preparer = EmbeddingPreparer()
    
    # Paths de entrada (desde Fase 2.2)
    writeups_path = Path("ml_phase2/evaluation/writeups_ml_dataset.jsonl")
    challenges_path = Path("ml_phase2/evaluation/challenges_ml_dataset.jsonl")
    
    # Verificar que existen
    if not writeups_path.exists():
        logger.error(f"No encontrado: {writeups_path}")
        logger.info("   Asegúrate de haber ejecutado rag.create_sample_data primero")
        return
    
    if not challenges_path.exists():
        logger.error(f"No encontrado: {challenges_path}")
        logger.info("   Asegúrate de haber ejecutado rag.create_sample_data primero")
        return
    
    try:
        # Procesar
        start = time.time()
        
        preparer.process_writeups(str(writeups_path))
        preparer.process_challenges(str(challenges_path))
        
        # Persistir
        preparer.persist()
        
        # Estadísticas
        logger.info("ESTADÍSTICAS FINALES:")
        stats = preparer.get_collection_stats()
        
        elapsed = time.time() - start
        logger.info(f"   Tiempo total: {elapsed:.1f}s")
        
        logger.info("EMBEDDING PREPARATION COMPLETE!")
        logger.info("   ChromaDB listo para retrieval")
        logger.info(f"   Ubicación: {CHROMADB_PATH}")
        
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()