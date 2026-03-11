"""
RAG Solver - Retrieval-Augmented Generation for CTF Solving
============================================================

Provides full solution context from past challenges to help solve new ones.
This is the core of the "learn from experience" system.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import sys
from pathlib import Path

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from src.learning.experience_storage import (
        ExperienceStorage, 
        SolvedChallengeExperience,
        get_experience_storage
    )
    HAS_STORAGE = True
except ImportError:
    HAS_STORAGE = False


@dataclass
class SolutionContext:
    """Complete context from a similar solved challenge."""
    challenge_name: str
    challenge_type: str
    attack_pattern: str
    solution_code: str
    solution_steps: List[str]
    similarity_score: float
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.challenge_name,
            "type": self.challenge_type,
            "attack": self.attack_pattern,
            "code": self.solution_code,
            "steps": self.solution_steps,
            "similarity": self.similarity_score,
            "description": self.description
        }


class RAGSolver:
    """
    Retrieval-Augmented Generation solver.
    
    Retrieves full past solutions and provides context for AI-assisted solving.
    """
    
    def __init__(self, storage: ExperienceStorage = None):
        """Initialize with optional custom storage."""
        if HAS_STORAGE:
            self.storage = storage or get_experience_storage()
        else:
            self.storage = None
            print("[!] Experience storage not available")
    
    def get_solution_context(
        self, 
        challenge_text: str, 
        challenge_code: str = "",
        challenge_type: str = None,
        k: int = 3,
        query_params: dict = None
    ) -> List[SolutionContext]:
        """
        Get full solution context from similar past challenges.
        
        Args:
            challenge_text: Challenge description
            challenge_code: Challenge source code
            challenge_type: Optional pre-classified type for filtering
            k: Number of similar solutions to return
            query_params: Optional extracted crypto params for reranking
                          (e.g. {"n_bits": 2048, "e": 3, "mode": "CBC"})
            
        Returns:
            List of SolutionContext with complete solution info
        """
        if not self.storage:
            return []
        
        # Build query from description + code
        query = f"{challenge_text}\n{challenge_code}"
        
        # Use reranked retrieval if query_params available
        if query_params and hasattr(self.storage, 'get_similar_experiences_reranked'):
            similar = self.storage.get_similar_experiences_reranked(
                query=query,
                k=k,
                challenge_type=challenge_type,
                query_params=query_params
            )
        else:
            # Fallback to basic retrieval
            similar = self.storage.get_similar_experiences(
                query=query,
                k=k,
                challenge_type=challenge_type
            )
        
        contexts = []
        for exp in similar:
            contexts.append(SolutionContext(
                challenge_name=exp.challenge_name,
                challenge_type=exp.challenge_type,
                attack_pattern=exp.attack_pattern,
                solution_code=exp.solution_code,
                solution_steps=exp.solution_steps,
                similarity_score=getattr(exp, '_similarity', 0.5),
                description=exp.challenge_description
            ))
        
        return contexts
    
    def build_ai_prompt(
        self, 
        challenge_text: str,
        challenge_code: str,
        similar_solutions: List[SolutionContext]
    ) -> str:
        """
        Build a prompt for AI showing past solutions as context.
        
        Args:
            challenge_text: New challenge description
            challenge_code: New challenge code
            similar_solutions: Retrieved similar solutions
            
        Returns:
            Formatted prompt string for AI
        """
        prompt_parts = [
            "# 🎯 Nuevo Desafío CTF",
            "",
            "## Descripción del Desafío",
            challenge_text,
            "",
        ]
        
        if challenge_code:
            prompt_parts.extend([
                "## Código Fuente del Challenge (`challenge.py`)",
                "```python",
                challenge_code[:2000],  # Limit code length
                "```",
                "",
            ])
        
        if similar_solutions:
            prompt_parts.extend([
                "---",
                "",
                "# 🧠 Contexto de Soluciones Anteriores (RAG)",
                "",
                "> **Instrucción:** Los siguientes retos **muy similares** ya fueron resueltos en el pasado.",
                "> Usa este conocimiento empírico para adaptar la solución al desafío actual. ¡No empieces desde cero!",
                "",
            ])
            
            for i, sol in enumerate(similar_solutions, 1):
                prompt_parts.extend([
                    f"## 📚 Experiencia {i}: {sol.challenge_name} (Similitud: {sol.similarity_score:.0%})",
                    "",
                    f"- **Tipo de Reto:** `{sol.challenge_type}`",
                    f"- **Patrón de Ataque:** `{sol.attack_pattern}`",
                    "",
                ])
                
                if sol.solution_steps:
                    prompt_parts.append("### Resumen de Pasos Lógicos")
                    for step in sol.solution_steps[:5]:
                        prompt_parts.append(f"1. {step}")
                    prompt_parts.append("")
                
                if sol.solution_code:
                    prompt_parts.extend([
                        "### Código de la Solución Anterior",
                        "```python",
                        sol.solution_code[:1500],
                        "```",
                        "",
                    ])
                    
            prompt_parts.extend([
                "---",
                "## 🛑 Reglas de Limpieza Post-Resolución",
                "Cuando encuentres la Flag y resuelvas el reto, **DEBES HACER LO SIGUIENTE**:",
                "1. Entrenar al RAG ejecutando: `python add_experience.py` con los datos correspondientes.",
                "2. Borrar todos los scripts sueltos y carpetas usadas para este reto (`challenges/NombreReto` y cualquier `.py` o `.sage` temporal en la raíz o en `solver/`) para no dejar basura en el repositorio Git.",
                ""
            ])
        
        return "\n".join(prompt_parts)
    
    def auto_adapt_solution(
        self,
        past_solution: SolutionContext,
        new_params: Dict[str, Any]
    ) -> Optional[str]:
        """
        Try to automatically adapt a past solution with new parameters.
        
        Args:
            past_solution: Solution to adapt
            new_params: New parameters (n, e, c, etc.)
            
        Returns:
            Adapted code string or None if can't auto-adapt
        """
        if not past_solution.solution_code:
            return None
        
        code = past_solution.solution_code
        
        # Simple parameter substitution
        for param, value in new_params.items():
            if param in ['n', 'e', 'c', 'p', 'q', 'd']:
                # Replace parameter assignments
                import re
                pattern = rf'{param}\s*=\s*\d+'
                replacement = f'{param} = {value}'
                code = re.sub(pattern, replacement, code)
        
        return code
    
    def store_success(
        self,
        challenge_name: str,
        challenge_description: str,
        challenge_type: str,
        source_code: str,
        attack_pattern: str,
        solution_steps: List[str],
        solution_code: str,
        flag: str,
        solve_time: float = 0.0
    ) -> str:
        """
        Store a successfully solved challenge for future retrieval.
        
        Args:
            challenge_name: Name of the challenge
            challenge_description: Challenge description
            challenge_type: Type (RSA, AES, etc.)
            source_code: Original challenge code
            attack_pattern: Attack used
            solution_steps: List of solution steps
            solution_code: Python code that solved it
            flag: The flag found
            solve_time: Time to solve in seconds
            
        Returns:
            Experience ID
        """
        if not self.storage:
            print("[!] Cannot store: no storage available")
            return ""
        
        exp = SolvedChallengeExperience(
            challenge_id="",  # Auto-generated
            challenge_name=challenge_name,
            challenge_description=challenge_description,
            challenge_type=challenge_type,
            difficulty="Medium",
            source_files=[{"name": "challenge.py", "content": source_code}],
            solution_successful=True,
            flag_found=flag,
            solution_steps=solution_steps,
            attack_pattern=attack_pattern,
            solution_code=solution_code,
            solve_time_seconds=solve_time,
            confidence_score=0.9
        )
        
        exp_id = self.storage.store_experience(exp)
        print(f"[+] Experience stored: {exp_id}")
        return exp_id
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored experiences."""
        if not self.storage:
            return {"error": "No storage available"}
        return self.storage.get_statistics()


# Singleton instance
_rag_solver = None

def get_rag_solver() -> RAGSolver:
    """Get singleton RAG solver instance."""
    global _rag_solver
    if _rag_solver is None:
        _rag_solver = RAGSolver()
    return _rag_solver


if __name__ == "__main__":
    print("[*] Testing RAG Solver...")
    
    solver = RAGSolver()
    
    # Test get similar
    contexts = solver.get_solution_context(
        "RSA challenge with small exponent e=3",
        "n = 12345\ne = 3\nc = 67890"
    )
    
    print(f"[+] Found {len(contexts)} similar solutions")
    for ctx in contexts:
        print(f"  - {ctx.challenge_name}: {ctx.attack_pattern} ({ctx.similarity_score:.0%})")
    
    # Test build prompt
    if contexts:
        prompt = solver.build_ai_prompt(
            "New RSA challenge",
            "n = 999\ne = 3\nc = 123",
            contexts
        )
        print(f"\n[+] Generated prompt ({len(prompt)} chars)")
        print(prompt[:500] + "...")
    
    # Show stats
    stats = solver.get_statistics()
    print(f"\n[+] Storage stats: {stats.get('total_experiences', 0)} experiences")
