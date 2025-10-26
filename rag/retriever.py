"""
RAG Retriever
Motor de retrieval que busca documentos similares en ChromaDB.
Interfaz principal para acceso a la base de datos vectorial.
"""

import chromadb
from pathlib import Path
from rag.config import CHROMADB_PATH, RETRIEVAL_K, SIMILARITY_THRESHOLD
from rag.utils import logger, calculate_similarity

class RAGRetriever:
    """Motor de búsqueda vectorial para similitud"""
    
    def __init__(self):
        """Conecta a ChromaDB persistido"""
        logger.info("Inicializando RAGRetriever...")
        
        # Conectar a DB existente
        self.client = chromadb.PersistentClient(path=str(CHROMADB_PATH))
        
        # Obtener colecciones
        try:
            self.writeups_collection = self.client.get_collection(name="writeups")
            logger.info(f"Colección 'writeups': {self.writeups_collection.count()} items")
        except Exception as e:
            logger.warning(f"Colección 'writeups' no encontrada: {e}")
            self.writeups_collection = None
        
        try:
            self.challenges_collection = self.client.get_collection(name="challenges")
            logger.info(f"Colección 'challenges': {self.challenges_collection.count()} items")
        except Exception as e:
            logger.warning(f"Colección 'challenges' no encontrada: {e}")
            self.challenges_collection = None
    
    def retrieve_similar_writeups(
        self,
        query_text: str,
        k: int = RETRIEVAL_K,
        threshold: float = SIMILARITY_THRESHOLD
    ) -> dict:
        """
        Busca writeups similares al texto de entrada.
        
        Args:
            query_text: Código o descripción del challenge
            k: Número máximo de resultados
            threshold: Similitud mínima (0-1)
        
        Returns:
            {
                "success": bool,
                "writeups": [
                    {
                        "id": "writeup_00001",
                        "content": "...",
                        "similarity": 0.92,
                        "source": "github/ashutosh1206"
                    }
                ],
                "count": int
            }
        """
        
        if not self.writeups_collection:
            logger.warning("Colección writeups no disponible")
            return {"success": False, "writeups": [], "count": 0, "error": "Collection not available"}
        
        try:
            # Query
            results = self.writeups_collection.query(
                query_texts=[query_text],
                n_results=k
            )
            
            # Formatear resultados
            writeups = []
            for i in range(len(results['documents'][0])):
                distance = results['distances'][0][i]
                similarity = calculate_similarity(distance)
                
                # Filtrar por threshold
                if similarity >= threshold:
                    writeups.append({
                        "id": results['ids'][0][i],
                        "content": results['documents'][0][i],
                        "similarity": float(similarity),
                        "source": results['metadatas'][0][i].get('source', 'unknown'),
                        "words": results['metadatas'][0][i].get('words', 0)
                    })
            
            logger.info(f"Retrieved {len(writeups)} similar writeups (threshold: {threshold})")
            
            return {
                "success": True,
                "writeups": writeups,
                "count": len(writeups),
                "query": query_text[:100] + "..." if len(query_text) > 100 else query_text
            }
            
        except Exception as e:
            logger.error(f"Error en retrieval: {e}")
            return {"success": False, "writeups": [], "count": 0, "error": str(e)}
    
    def retrieve_similar_challenges(
        self,
        query_text: str,
        k: int = 5,
        crypto_type: str = None,
        threshold: float = SIMILARITY_THRESHOLD
    ) -> dict:
        """
        Busca challenges similares (para aprender patrones).
        
        Args:
            query_text: Código del challenge
            k: Número de resultados
            crypto_type: Filtro opcional por tipo (RSA, Classical, etc)
            threshold: Similitud mínima
        
        Returns:
            {
                "success": bool,
                "challenges": [...],
                "count": int
            }
        """
        
        if not self.challenges_collection:
            return {"success": False, "challenges": [], "count": 0}
        
        try:
            # Construir filtro si es necesario
            where_filter = None
            if crypto_type:
                where_filter = {"label": {"$eq": crypto_type}}
            
            # Query
            results = self.challenges_collection.query(
                query_texts=[query_text],
                n_results=k,
                where=where_filter
            )
            
            # Formatear
            challenges = []
            for i in range(len(results['documents'][0])):
                distance = results['distances'][0][i]
                similarity = calculate_similarity(distance)
                
                if similarity >= threshold:
                    challenges.append({
                        "id": results['ids'][0][i],
                        "content": results['documents'][0][i],
                        "similarity": float(similarity),
                        "type": results['metadatas'][0][i].get('label', 'Unknown'),
                        "repo": results['metadatas'][0][i].get('repo', 'unknown')
                    })
            
            logger.info(f"Retrieved {len(challenges)} similar challenges")
            
            return {
                "success": True,
                "challenges": challenges,
                "count": len(challenges)
            }
            
        except Exception as e:
            logger.error(f"Error en retrieval: {e}")
            return {"success": False, "challenges": [], "count": 0, "error": str(e)}
    
    def get_stats(self) -> dict:
        """Retorna estadísticas de las colecciones"""
        stats = {
            "writeups": self.writeups_collection.count() if self.writeups_collection else 0,
            "challenges": self.challenges_collection.count() if self.challenges_collection else 0
        }
        logger.info(f"DB Stats: {stats}")
        return stats

# Instancia global para usar en todo el sistema
try:
    rag_retriever = RAGRetriever()
    RAG_AVAILABLE = True
except Exception as e:
    logger.error(f"No se pudo inicializar RAGRetriever: {e}")
    rag_retriever = None
    RAG_AVAILABLE = False

logger.info(f"RAG_AVAILABLE: {RAG_AVAILABLE}")