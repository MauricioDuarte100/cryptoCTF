#!/usr/bin/env python3
"""
Test del sistema RAG mejorado
Verifica que el RAG funciona correctamente con los nuevos embeddings
"""

import chromadb
from pathlib import Path

def test_rag_system():
    """Prueba el sistema RAG"""
    chromadb_path = Path("rag/chromadb")
    
    print("🧪 TESTING ENHANCED RAG SYSTEM")
    print("=" * 50)
    
    if not chromadb_path.exists():
        print(f"❌ ChromaDB not found: {chromadb_path}")
        return False
    
    try:
        # Conectar a ChromaDB
        client = chromadb.PersistentClient(path=str(chromadb_path))
        
        # Obtener colecciones
        writeups_collection = client.get_collection("writeups")
        challenges_collection = client.get_collection("challenges")
        
        print(f"✅ Connected to ChromaDB")
        print(f"📚 Writeups collection: {writeups_collection.count()} documents")
        print(f"🎯 Challenges collection: {challenges_collection.count()} documents")
        
        # Casos de prueba
        test_queries = [
            "RSA small exponent attack with e=3",
            "Caesar cipher ROT13 shift",
            "Single byte XOR brute force",
            "Base64 multiple layers decoding",
            "MD5 hash dictionary attack"
        ]
        
        print(f"\n🔍 Testing {len(test_queries)} queries...")
        
        for i, query in enumerate(test_queries, 1):
            print(f"\n📋 Query {i}: '{query}'")
            
            # Buscar en writeups
            results = writeups_collection.query(
                query_texts=[query],
                n_results=3
            )
            
            print(f"  📚 Writeups results:")
            for j, (doc, metadata) in enumerate(zip(results['documents'][0], results['metadatas'][0])):
                print(f"    {j+1}. {metadata['challenge_name']} ({metadata['attack_type']})")
                print(f"       Team: {metadata['team']} | Difficulty: {metadata['difficulty']}")
            
            # Buscar en challenges
            challenge_results = challenges_collection.query(
                query_texts=[query],
                n_results=2
            )
            
            print(f"  🎯 Challenges results:")
            for j, (doc, metadata) in enumerate(zip(challenge_results['documents'][0], challenge_results['metadatas'][0])):
                print(f"    {j+1}. {metadata['name']} ({metadata['type']})")
                print(f"       Event: {metadata['event']} | Year: {metadata['year']}")
        
        # Test de filtrado por metadata
        print(f"\n🔧 Testing metadata filtering...")
        
        # Buscar solo RSA challenges
        rsa_results = writeups_collection.query(
            query_texts=["RSA factorization"],
            n_results=5,
            where={"attack_type": "RSA"}
        )
        
        print(f"  🔐 RSA-only results: {len(rsa_results['documents'][0])} found")
        for doc, metadata in zip(rsa_results['documents'][0], rsa_results['metadatas'][0]):
            print(f"    - {metadata['challenge_name']} (Team: {metadata['team']})")
        
        # Test de búsqueda por equipo
        team_results = writeups_collection.query(
            query_texts=["cryptography challenge"],
            n_results=3,
            where={"synthetic": False}  # Solo writeups reales
        )
        
        print(f"  🏆 Real writeups only: {len(team_results['documents'][0])} found")
        for doc, metadata in zip(team_results['documents'][0], team_results['metadatas'][0]):
            print(f"    - {metadata['challenge_name']} (Team: {metadata['team']})")
        
        print(f"\n✅ RAG system test: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ RAG system test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_rag_system()
    exit(0 if success else 1)