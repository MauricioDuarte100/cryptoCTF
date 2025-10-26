"""
RAG Engine
Motor que combina retrieval + LLM prompt para razonamiento contextual.
"""

from rag.retriever import rag_retriever, RAG_AVAILABLE
from rag.utils import logger

class RAGEngine:
    """Motor de razonamiento con contexto de writeups."""
    
    @staticmethod
    def generate_reasoning_prompt(challenge_content: str, challenge_type: str, similar_writeups: list) -> str:
        """
        Genera prompt enriquecido con contexto de writeups similares.
        
        Args:
            challenge_content: Código/descripción del challenge
            challenge_type: Tipo detectado (RSA, Classical, etc.)
            similar_writeups: Writeups recuperados del RAG
        
        Returns:
            Prompt mejorado con contexto
        """
        
        # Base del prompt
        prompt = f"""You are analyzing a CTF {challenge_type} challenge with the following code:

{challenge_content[:500]}

Based on similar challenges from writeups, here are relevant patterns:

"""
        
        # Añadir contexto de writeups
        for i, writeup in enumerate(similar_writeups, 1):
            prompt += f"""
PATTERN {i} (Similarity: {writeup['similarity']:.2%}):
{writeup['content'][:400]}...

"""
        
        prompt += """
Based on these patterns, what are the key attack vectors for this challenge? 
Provide specific attack methods and tools to use.
"""
        
        return prompt
    
    @staticmethod
    def retrieve_and_generate(challenge_content: str, challenge_type: str) -> dict:
        """
        Retrieva contexto + genera prompt de razonamiento.
        """
        
        if not RAG_AVAILABLE:
            return {"error": "RAG not available", "writeups": []}
        
        # 1. Retrieval
        similar_writeups = rag_retriever.retrieve_similar_writeups(
            query_text=challenge_content,
            k=3,
            threshold=0.4  # Threshold más bajo para más contexto
        )
        
        if not similar_writeups['success']:
            return {"error": "Retrieval failed", "writeups": []}
        
        # 2. Generate prompt
        reasoning_prompt = RAGEngine.generate_reasoning_prompt(
            challenge_content,
            challenge_type,
            similar_writeups['writeups']
        )
        
        return {
            "reasoning_prompt": reasoning_prompt,
            "writeups": similar_writeups['writeups'],
            "num_patterns": len(similar_writeups['writeups']),
            "success": True
        }

# Función de conveniencia
def get_rag_context(challenge_content: str, challenge_type: str = "Unknown") -> dict:
    """
    Función de conveniencia para obtener contexto RAG.
    
    Args:
        challenge_content: Código del challenge
        challenge_type: Tipo de crypto detectado
    
    Returns:
        Contexto RAG con writeups similares
    """
    return RAGEngine.retrieve_and_generate(challenge_content, challenge_type)