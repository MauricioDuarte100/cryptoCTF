#!/usr/bin/env python3
"""
ENHANCED RAG Engine
Motor RAG actualizado que usa los embeddings mejorados
"""

import chromadb
from pathlib import Path
from typing import List, Dict, Any, Optional

class EnhancedRAGEngine:
    """Motor RAG mejorado con embeddings de writeups reales"""
    
    def __init__(self, chromadb_path="rag/chromadb"):
        """Inicializa el motor RAG"""
        self.chromadb_path = Path(chromadb_path)
        self.client = None
        self.writeups_collection = None
        self.challenges_collection = None
        self.is_available = False
        
        try:
            self._initialize_collections()
            self.is_available = True
            print("✅ Enhanced RAG Engine initialized successfully")
        except Exception as e:
            print(f"⚠️ Enhanced RAG Engine initialization failed: {e}")
            self.is_available = False

    def _initialize_collections(self):
        """Inicializa las colecciones de ChromaDB"""
        if not self.chromadb_path.exists():
            raise FileNotFoundError(f"ChromaDB path not found: {self.chromadb_path}")
        
        # Conectar a ChromaDB
        self.client = chromadb.PersistentClient(path=str(self.chromadb_path))
        
        # Obtener colecciones
        self.writeups_collection = self.client.get_collection("writeups")
        self.challenges_collection = self.client.get_collection("challenges")
        
        print(f"📚 Writeups collection: {self.writeups_collection.count()} documents")
        print(f"🎯 Challenges collection: {self.challenges_collection.count()} documents")

    def retrieve_similar_writeups(self, query: str, n_results: int = 5, 
                                 attack_type: Optional[str] = None,
                                 difficulty: Optional[str] = None,
                                 real_only: bool = False) -> List[Dict[str, Any]]:
        """
        Recupera writeups similares basados en la consulta.
        
        Args:
            query: Consulta de búsqueda
            n_results: Número de resultados a retornar
            attack_type: Filtrar por tipo de ataque específico
            difficulty: Filtrar por dificultad
            real_only: Solo writeups reales (no sintéticos)
            
        Returns:
            Lista de writeups similares con metadata
        """
        if not self.is_available:
            print("⚠️ RAG system not available")
            return []
        
        try:
            # Preparar filtros de metadata
            where_clause = {}
            if attack_type:
                where_clause["attack_type"] = attack_type
            if difficulty:
                where_clause["difficulty"] = difficulty
            if real_only:
                where_clause["synthetic"] = False
            
            # Realizar búsqueda
            results = self.writeups_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause if where_clause else None
            )
            
            # Formatear resultados
            similar_writeups = []
            for i, (doc, metadata, distance) in enumerate(zip(
                results['documents'][0], 
                results['metadatas'][0],
                results['distances'][0]
            )):
                writeup = {
                    'rank': i + 1,
                    'challenge_name': metadata.get('challenge_name', 'Unknown'),
                    'attack_type': metadata.get('attack_type', 'Unknown'),
                    'team': metadata.get('team', 'Unknown'),
                    'difficulty': metadata.get('difficulty', 'unknown'),
                    'event': metadata.get('event', 'Unknown'),
                    'year': metadata.get('year', 2024),
                    'tools_used': metadata.get('tools_used', '').split(',') if metadata.get('tools_used') else [],
                    'url': metadata.get('url', ''),
                    'content': doc,
                    'similarity': 1 - distance,  # Convertir distancia a similaridad
                    'synthetic': metadata.get('synthetic', False)
                }
                similar_writeups.append(writeup)
            
            return similar_writeups
            
        except Exception as e:
            print(f"❌ Error retrieving writeups: {e}")
            return []

    def retrieve_similar_challenges(self, query: str, n_results: int = 3,
                                  challenge_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Recupera challenges similares.
        
        Args:
            query: Consulta de búsqueda
            n_results: Número de resultados
            challenge_type: Filtrar por tipo de challenge
            
        Returns:
            Lista de challenges similares
        """
        if not self.is_available:
            return []
        
        try:
            where_clause = {}
            if challenge_type:
                where_clause["type"] = challenge_type
            
            results = self.challenges_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause if where_clause else None
            )
            
            similar_challenges = []
            for i, (doc, metadata, distance) in enumerate(zip(
                results['documents'][0],
                results['metadatas'][0], 
                results['distances'][0]
            )):
                challenge = {
                    'rank': i + 1,
                    'name': metadata.get('name', 'Unknown'),
                    'type': metadata.get('type', 'Unknown'),
                    'difficulty': metadata.get('difficulty', 'unknown'),
                    'team': metadata.get('team', 'Unknown'),
                    'event': metadata.get('event', 'Unknown'),
                    'year': metadata.get('year', 2024),
                    'content': doc,
                    'similarity': 1 - distance,
                    'writeup_id': metadata.get('writeup_id', ''),
                    'synthetic': metadata.get('synthetic', False)
                }
                similar_challenges.append(challenge)
            
            return similar_challenges
            
        except Exception as e:
            print(f"❌ Error retrieving challenges: {e}")
            return []

    def get_context_for_challenge(self, challenge_data: Dict[str, Any], 
                                 max_writeups: int = 3) -> Dict[str, Any]:
        """
        Obtiene contexto RAG completo para un challenge.
        Compatible con la interfaz del multi-agente existente.
        
        Args:
            challenge_data: Datos del challenge
            max_writeups: Máximo número de writeups a recuperar
            
        Returns:
            Contexto RAG con writeups y estrategias
        """
        if not self.is_available:
            return {'available': False, 'writeups': [], 'strategies': []}
        
        # Preparar query basado en el challenge
        query_parts = []
        if challenge_data.get('description'):
            query_parts.append(challenge_data['description'])
        
        if challenge_data.get('files'):
            for file_info in challenge_data['files']:
                if file_info.get('content'):
                    query_parts.append(file_info['content'][:200])
        
        query = ' '.join(query_parts)
        
        # Recuperar writeups similares
        similar_writeups = self.retrieve_similar_writeups(
            query=query,
            n_results=max_writeups
        )
        
        # Extraer estrategias de los writeups
        strategies = []
        for writeup in similar_writeups:
            if writeup['similarity'] > 0.5:  # Solo writeups relevantes
                strategy = {
                    'attack_type': writeup['attack_type'],
                    'tools': writeup['tools_used'],
                    'difficulty': writeup['difficulty'],
                    'source_team': writeup['team'],
                    'confidence': writeup['similarity']
                }
                strategies.append(strategy)
        
        # Eliminar estrategias duplicadas
        unique_strategies = []
        seen_types = set()
        for strategy in strategies:
            if strategy['attack_type'] not in seen_types:
                unique_strategies.append(strategy)
                seen_types.add(strategy['attack_type'])
        
        context = {
            'available': True,
            'writeups': similar_writeups,
            'strategies': unique_strategies,
            'total_retrieved': len(similar_writeups),
            'relevant_count': len([w for w in similar_writeups if w['similarity'] > 0.5])
        }
        
        return context

    def search_by_attack_type(self, attack_type: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Busca writeups por tipo de ataque específico"""
        return self.retrieve_similar_writeups(
            query=f"{attack_type} attack techniques",
            n_results=n_results,
            attack_type=attack_type
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas del sistema RAG"""
        if not self.is_available:
            return {'available': False}
        
        try:
            writeups_count = self.writeups_collection.count()
            challenges_count = self.challenges_collection.count()
            
            # Obtener muestra para estadísticas
            sample_results = self.writeups_collection.query(
                query_texts=["sample query"],
                n_results=min(100, writeups_count)
            )
            
            # Contar por tipo de ataque
            attack_type_counts = {}
            team_counts = {}
            
            for metadata in sample_results['metadatas'][0]:
                attack_type = metadata.get('attack_type', 'Unknown')
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
                
                team = metadata.get('team', 'Unknown')
                team_counts[team] = team_counts.get(team, 0) + 1
            
            return {
                'available': True,
                'writeups_count': writeups_count,
                'challenges_count': challenges_count,
                'attack_types': attack_type_counts,
                'teams': team_counts,
                'chromadb_path': str(self.chromadb_path)
            }
            
        except Exception as e:
            print(f"❌ Error getting RAG statistics: {e}")
            return {'available': False, 'error': str(e)}

# Instancia global para compatibilidad
_enhanced_rag_engine = None

def get_enhanced_rag_engine(chromadb_path="rag/chromadb"):
    """Obtiene la instancia global del motor RAG mejorado"""
    global _enhanced_rag_engine
    if _enhanced_rag_engine is None:
        _enhanced_rag_engine = EnhancedRAGEngine(chromadb_path)
    return _enhanced_rag_engine

# Funciones de compatibilidad con el sistema existente
def retrieve_similar_writeups(query: str, n_results: int = 5) -> List[Dict[str, Any]]:
    """Función de compatibilidad para retrieve_similar_writeups"""
    engine = get_enhanced_rag_engine()
    return engine.retrieve_similar_writeups(query, n_results)

def get_rag_context(challenge_data: Dict[str, Any]) -> Dict[str, Any]:
    """Función de compatibilidad para get_rag_context"""
    engine = get_enhanced_rag_engine()
    return engine.get_context_for_challenge(challenge_data)

if __name__ == "__main__":
    # Test del motor RAG
    print("🧪 Testing Enhanced RAG Engine")
    print("=" * 50)
    
    engine = EnhancedRAGEngine()
    
    if engine.is_available:
        # Test de búsqueda
        results = engine.retrieve_similar_writeups("RSA small exponent attack", n_results=3)
        
        print(f"📊 Found {len(results)} similar writeups:")
        for result in results:
            print(f"  - {result['challenge_name']} ({result['attack_type']}) - {result['similarity']:.4f}")
        
        # Test de contexto
        test_challenge = {
            'description': 'RSA challenge with e=3',
            'files': [{'content': 'n = 123...\ne = 3\nc = 456...'}]
        }
        
        context = engine.get_context_for_challenge(test_challenge)
        print(f"\n📋 Context for test challenge:")
        print(f"  Available: {context['available']}")
        print(f"  Strategies: {len(context['strategies'])}")
        
        for strategy in context['strategies']:
            print(f"    - {strategy['attack_type']} (confidence: {strategy['confidence']:.4f})")
    
    else:
        print("❌ RAG Engine not available")