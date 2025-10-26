"""
RAG Agent Tools
Nuevas tools que integran RAG en el flujo del agente.
"""

from langchain_core.tools import tool
from rag.rag_engine import RAGEngine, get_rag_context
from rag.retriever import RAG_AVAILABLE, rag_retriever

@tool
def retrieve_similar_writeups(challenge_text: str, challenge_type: str = "Unknown") -> dict:
    """
    Retrieves similar writeups from RAG database.
    
    Use this when you want to learn from previous successful solutions.
    This should be your FIRST step when analyzing any crypto challenge.
    
    Args:
        challenge_text: The challenge code or description
        challenge_type: Type of crypto (RSA, Classical, XOR, etc.)
    
    Returns:
        Dictionary with similar writeups and patterns
    """
    if not RAG_AVAILABLE:
        return {
            "status": "not_available",
            "message": "RAG system not initialized",
            "writeups": []
        }
    
    result = rag_retriever.retrieve_similar_writeups(
        query_text=challenge_text,
        k=3,
        threshold=0.4
    )
    
    if result['success']:
        return {
            "status": "success",
            "writeups": result['writeups'],
            "count": result['count'],
            "message": f"Found {result['count']} similar writeups"
        }
    else:
        return {
            "status": "error",
            "message": result.get('error', 'Unknown error'),
            "writeups": []
        }

@tool
def analyze_with_context(challenge_content: str, challenge_type: str) -> dict:
    """
    Full RAG analysis with reasoning prompt generation.
    
    This combines retrieval with contextual reasoning to provide
    enhanced analysis based on historical CTF solutions.
    
    Args:
        challenge_content: The challenge code
        challenge_type: Detected crypto type
    
    Returns:
        Enhanced analysis with historical context
    """
    if not RAG_AVAILABLE:
        return {
            "status": "not_available",
            "message": "RAG system not initialized"
        }
    
    result = get_rag_context(challenge_content, challenge_type)
    
    if result.get('success'):
        return {
            "status": "success",
            "reasoning_prompt": result['reasoning_prompt'],
            "patterns_found": result['num_patterns'],
            "writeups": result['writeups'],
            "message": f"Generated reasoning with {result['num_patterns']} historical patterns"
        }
    else:
        return {
            "status": "error",
            "message": result.get('error', 'Analysis failed')
        }