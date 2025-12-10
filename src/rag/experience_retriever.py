"""
Experience Retriever for RAG-based CTF Solver
Retrieves and adapts past solutions for new challenges.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    from .challenge_embeddings import ChallengeEmbedder, get_embedding_index, EmbeddingConfig
    HAS_EMBEDDINGS = True
except ImportError:
    HAS_EMBEDDINGS = False

try:
    from ..learning.experience_storage import ExperienceStorage, SolvedChallengeExperience
    HAS_EXPERIENCE = True
except ImportError:
    HAS_EXPERIENCE = False


@dataclass
class RetrievalResult:
    """A retrieved experience with relevance score."""
    experience_id: str
    challenge_name: str
    challenge_type: str
    attack_pattern: str
    solution_code: str
    solution_steps: List[str]
    similarity_score: float
    relevance_explanation: str = ""


class ExperienceRetriever:
    """
    Retrieves similar past solutions for new challenges using embeddings.
    Supports solution adaptation based on context differences.
    """
    
    def __init__(self, 
                 experience_storage: 'ExperienceStorage' = None,
                 index_path: str = None):
        """
        Initialize retriever.
        
        Args:
            experience_storage: ExperienceStorage instance
            index_path: Path to pre-built embedding index
        """
        if not HAS_EMBEDDINGS:
            raise ImportError("RAG embeddings module required")
        
        self.embedder = ChallengeEmbedder()
        self.experience_storage = experience_storage
        self.index = get_embedding_index()
        
        if index_path:
            self._load_index(index_path)
        elif experience_storage:
            self._build_index_from_storage()
    
    def _build_index_from_storage(self) -> None:
        """Build embedding index from experience storage."""
        if not self.experience_storage:
            return
        
        # Export training data
        experiences = self.experience_storage.export_for_training()
        
        for exp in experiences:
            # Create embedding
            embedding = self.embedder.embed_challenge(
                exp.get("description", ""),
                exp.get("files", []),
                exp.get("type")
            )
            
            # Add to index
            self.index.add(
                embedding,
                exp["id"],
                {
                    "name": exp.get("name"),
                    "type": exp.get("type"),
                    "attack": exp.get("attack_pattern")
                }
            )
    
    def _load_index(self, path: str) -> None:
        """Load pre-built index."""
        self.index.load(path)
    
    def retrieve_similar(self, 
                        challenge_text: str,
                        files: List[Dict] = None,
                        challenge_type: str = None,
                        k: int = 5) -> List[RetrievalResult]:
        """
        Find similar solved challenges.
        
        Args:
            challenge_text: New challenge description
            files: Challenge source files
            challenge_type: Optional pre-classified type
            k: Number of results to return
            
        Returns:
            List of RetrievalResult with similar experiences
        """
        # Compute query embedding
        query_embedding = self.embedder.embed_challenge(
            challenge_text, files, challenge_type
        )
        
        # Search index
        similar_ids = self.index.search(query_embedding, k=k)
        
        results = []
        for exp_id, score in similar_ids:
            # Get full experience if storage available
            if self.experience_storage:
                exp = self.experience_storage.get_experience(exp_id)
                if exp:
                    results.append(RetrievalResult(
                        experience_id=exp_id,
                        challenge_name=exp.challenge_name,
                        challenge_type=exp.challenge_type,
                        attack_pattern=exp.attack_pattern,
                        solution_code=exp.solution_code,
                        solution_steps=exp.solution_steps,
                        similarity_score=score,
                        relevance_explanation=self._explain_relevance(
                            challenge_text, exp.challenge_description, score
                        )
                    ))
            else:
                # Use metadata from index
                meta = self.index.metadata.get(exp_id, {})
                results.append(RetrievalResult(
                    experience_id=exp_id,
                    challenge_name=meta.get("name", "Unknown"),
                    challenge_type=meta.get("type", "Unknown"),
                    attack_pattern=meta.get("attack", ""),
                    solution_code="",
                    solution_steps=[],
                    similarity_score=score,
                    relevance_explanation=""
                ))
        
        return results
    
    def _explain_relevance(self, query: str, retrieved: str, score: float) -> str:
        """Generate a brief explanation of why this result is relevant."""
        if score > 0.8:
            return "Very similar challenge structure and keywords"
        elif score > 0.6:
            return "Similar challenge type with matching patterns"
        elif score > 0.4:
            return "Potentially related attack methodology"
        else:
            return "Weak similarity, may provide inspiration"
    
    def adapt_solution(self, 
                      past_solution: RetrievalResult,
                      new_challenge: str,
                      new_files: List[Dict] = None,
                      new_params: Dict = None) -> Dict[str, Any]:
        """
        Adapt a past solution for a new challenge.
        
        Args:
            past_solution: Retrieved solution to adapt
            new_challenge: New challenge description
            new_files: New challenge files
            new_params: Extracted parameters from new challenge
            
        Returns:
            Dictionary with adapted solution suggestions
        """
        # Extract key differences
        adaptations = []
        
        # Parameter substitution suggestions
        if new_params:
            for param, value in new_params.items():
                adaptations.append({
                    "type": "parameter_substitution",
                    "param": param,
                    "new_value": str(value),
                    "instruction": f"Replace {param} with {value}"
                })
        
        # Check if attack pattern still applies
        attack_still_valid = self._check_attack_validity(
            past_solution.attack_pattern,
            new_challenge,
            new_files
        )
        
        if not attack_still_valid["valid"]:
            adaptations.append({
                "type": "attack_change",
                "original": past_solution.attack_pattern,
                "suggestion": attack_still_valid.get("alternative", "manual_analysis"),
                "reason": attack_still_valid.get("reason", "Attack may not apply")
            })
        
        return {
            "original_solution": past_solution.solution_code,
            "original_steps": past_solution.solution_steps,
            "attack_pattern": past_solution.attack_pattern,
            "attack_valid": attack_still_valid["valid"],
            "adaptations": adaptations,
            "confidence": past_solution.similarity_score * (1.0 if attack_still_valid["valid"] else 0.7),
            "can_auto_adapt": len(adaptations) <= 2 and attack_still_valid["valid"]
        }
    
    def _check_attack_validity(self, attack: str, challenge: str, 
                              files: List[Dict] = None) -> Dict[str, Any]:
        """Check if a past attack pattern applies to new challenge."""
        if not attack:
            return {"valid": False, "reason": "No attack pattern specified"}
        
        challenge_lower = challenge.lower()
        if files:
            for f in files:
                challenge_lower += " " + f.get("content", "").lower()
        
        # Attack-specific checks
        attack_requirements = {
            "small_e_attack": ["e = 3", "e=3", "small exponent", "e is 3"],
            "wiener_attack": ["small d", "wiener", "d is small"],
            "padding_oracle": ["padding", "oracle", "cbc"],
            "ecb_detection": ["ecb", "same blocks"],
            "nonce_reuse": ["nonce", "iv reuse", "counter"],
            "caesar_bruteforce": ["caesar", "shift", "rot"],
            "xor_single_byte": ["xor", "single byte"],
            "lagrange_interpolation": ["polynomial", "interpolation", "lagrange", "points"],
        }
        
        if attack in attack_requirements:
            required = attack_requirements[attack]
            found = any(r in challenge_lower for r in required)
            return {
                "valid": found,
                "reason": "No matching keywords" if not found else "Keywords match",
                "alternative": self._suggest_alternative(challenge_lower) if not found else None
            }
        
        # Default: assume valid if we can't check
        return {"valid": True, "reason": "Cannot verify, assuming valid"}
    
    def _suggest_alternative(self, challenge: str) -> str:
        """Suggest alternative attack based on challenge content."""
        attack_keywords = {
            "rsa": "analyze_rsa",
            "aes": "analyze_aes",
            "xor": "xor_analysis",
            "hash": "hash_analysis",
            "base64": "base64_decode",
            "caesar": "caesar_bruteforce",
            "polynomial": "lagrange_interpolation"
        }
        
        for keyword, attack in attack_keywords.items():
            if keyword in challenge:
                return attack
        
        return "manual_analysis"
    
    def get_attack_recommendations(self, 
                                   challenge_text: str,
                                   files: List[Dict] = None,
                                   top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Get attack recommendations based on similar solved challenges.
        
        Args:
            challenge_text: Challenge description
            files: Challenge files
            top_k: Number of recommendations
            
        Returns:
            List of attack recommendations
        """
        # Get similar challenges
        similar = self.retrieve_similar(challenge_text, files, k=top_k * 2)
        
        # Collect and rank attack patterns
        attack_counts = {}
        attack_scores = {}
        
        for result in similar:
            if result.attack_pattern:
                attack = result.attack_pattern
                attack_counts[attack] = attack_counts.get(attack, 0) + 1
                attack_scores[attack] = max(
                    attack_scores.get(attack, 0),
                    result.similarity_score
                )
        
        # Rank by count * score
        ranked = sorted(
            attack_counts.keys(),
            key=lambda a: attack_counts[a] * attack_scores[a],
            reverse=True
        )
        
        recommendations = []
        for attack in ranked[:top_k]:
            recommendations.append({
                "attack": attack,
                "confidence": attack_scores[attack],
                "frequency": attack_counts[attack],
                "based_on": [
                    r.challenge_name for r in similar 
                    if r.attack_pattern == attack
                ][:3]
            })
        
        return recommendations
    
    def save(self, path: str) -> None:
        """Save retriever state."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        self.index.save(str(path / "index"))
    
    def load(self, path: str) -> None:
        """Load retriever state."""
        self.index.load(str(Path(path) / "index"))


class SimpleRetriever:
    """
    Fallback retriever using keyword matching when embeddings unavailable.
    """
    
    def __init__(self, experiences: List[Dict] = None):
        """Initialize with optional experience list."""
        self.experiences = experiences or []
    
    def add_experience(self, exp: Dict) -> None:
        """Add an experience to the store."""
        self.experiences.append(exp)
    
    def retrieve_similar(self, 
                        challenge_text: str,
                        files: List[Dict] = None,
                        challenge_type: str = None,
                        k: int = 5) -> List[RetrievalResult]:
        """Find similar experiences using keyword matching."""
        # Build query keywords
        query = challenge_text.lower()
        if files:
            for f in files:
                query += " " + f.get("content", "").lower()
        
        query_words = set(query.split())
        
        # Score each experience
        scored = []
        for exp in self.experiences:
            exp_text = f"{exp.get('name', '')} {exp.get('description', '')} {exp.get('type', '')} {exp.get('attack_pattern', '')}"
            exp_words = set(exp_text.lower().split())
            
            # Jaccard similarity
            intersection = len(query_words & exp_words)
            union = len(query_words | exp_words)
            score = intersection / union if union > 0 else 0
            
            # Bonus for matching type
            if challenge_type and exp.get("type") == challenge_type:
                score *= 1.5
            
            scored.append((exp, min(score, 1.0)))
        
        # Sort and return top k
        scored.sort(key=lambda x: x[1], reverse=True)
        
        results = []
        for exp, score in scored[:k]:
            results.append(RetrievalResult(
                experience_id=exp.get("id", "unknown"),
                challenge_name=exp.get("name", "Unknown"),
                challenge_type=exp.get("type", "Unknown"),
                attack_pattern=exp.get("attack_pattern", ""),
                solution_code=exp.get("solution_code", ""),
                solution_steps=exp.get("solution_steps", []),
                similarity_score=score,
                relevance_explanation="Keyword matching"
            ))
        
        return results


def get_experience_retriever(experience_storage=None, index_path=None):
    """Get appropriate retriever implementation."""
    if HAS_EMBEDDINGS:
        try:
            return ExperienceRetriever(experience_storage, index_path)
        except Exception as e:
            print(f"⚠️ Could not initialize embedding retriever: {e}")
            return SimpleRetriever()
    else:
        return SimpleRetriever()


if __name__ == "__main__":
    print("🧪 Testing Experience Retriever...")
    
    # Create simple retriever for testing
    retriever = SimpleRetriever([
        {
            "id": "exp_001",
            "name": "RSA Small E",
            "description": "RSA with e=3",
            "type": "RSA",
            "attack_pattern": "small_e_attack",
            "solution_code": "from gmpy2 import iroot; m, _ = iroot(c, 3)",
            "solution_steps": ["extract_params", "compute_cube_root"]
        },
        {
            "id": "exp_002",
            "name": "Caesar Cipher",
            "description": "ROT13 encoded message",
            "type": "Classical",
            "attack_pattern": "caesar_bruteforce",
            "solution_code": "import codecs; codecs.decode(ct, 'rot13')",
            "solution_steps": ["detect_caesar", "bruteforce_shifts"]
        }
    ])
    
    results = retriever.retrieve_similar(
        "RSA challenge with small exponent e=3",
        challenge_type="RSA"
    )
    
    print(f"✅ Found {len(results)} similar experiences")
    for r in results:
        print(f"  - {r.challenge_name}: {r.similarity_score:.2f}")
