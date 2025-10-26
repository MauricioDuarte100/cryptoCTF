"""
Test RAG Retriever
Script de prueba para validar que el retriever funciona correctamente.

EJECUTAR: python -m rag.test_retriever
"""

from rag.retriever import rag_retriever, RAG_AVAILABLE
from rag.utils import logger

def test_retriever():
    if not RAG_AVAILABLE:
        logger.error("RAG not available")
        return
    
    logger.info("="*70)
    logger.info("TESTING RAG RETRIEVER")
    logger.info("="*70)
    
    # Test 1: Writeup retrieval
    logger.info("TEST 1: Retrieving similar writeups...")
    query = "RSA encryption with small exponent e=3"
    result = rag_retriever.retrieve_similar_writeups(query, k=3)
    
    if result['success']:
        logger.info(f"Retrieved {result['count']} writeups:")
        for w in result['writeups']:
            logger.info(f"   - {w['id']} (similarity: {w['similarity']:.2%}) from {w['source']}")
    else:
        logger.error(f"Failed: {result.get('error')}")
    
    # Test 2: Challenge retrieval
    logger.info("TEST 2: Retrieving similar challenges...")
    query2 = "n = 12345...\ne = 3\nc = 98765..."
    result2 = rag_retriever.retrieve_similar_challenges(query2, k=5, crypto_type="RSA")
    
    if result2['success']:
        logger.info(f"Retrieved {result2['count']} challenges:")
        for c in result2['challenges']:
            logger.info(f"   - {c['id']} (type: {c['type']}, similarity: {c['similarity']:.2%})")
    else:
        logger.error(f"Failed: {result2.get('error')}")
    
    # Test 3: Stats
    logger.info("TEST 3: Database statistics...")
    stats = rag_retriever.get_stats()
    logger.info(f"Stats: {stats}")
    
    logger.info("="*70)
    logger.info("ALL TESTS COMPLETE")
    logger.info("="*70)

if __name__ == "__main__":
    test_retriever()