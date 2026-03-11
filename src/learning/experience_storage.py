"""
Experience Storage System for CTF Solver Deep Learning
Stores solved challenges as training experiences for continuous learning.
"""

import json
import sqlite3
import hashlib
import numpy as np
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import os

# Identify the project root based on this script's location
PROJECT_ROOT = Path(__file__).parent.parent.parent

# SentenceTransformers import moved inside the embedder property to save memory and boot time.

try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False


@dataclass
class SolvedChallengeExperience:
    """
    Represents a solved CTF challenge experience for training.
    Captures all information needed to learn from this solution.
    """
    # Challenge identification
    challenge_id: str
    challenge_name: str
    challenge_description: str
    challenge_type: str  # RSA, XOR, AES, Classical, Hash, etc.
    difficulty: str  # Easy, Medium, Hard
    
    # Challenge content
    source_files: List[Dict[str, str]]  # [{name: str, content: str}]
    server_host: str = ""
    server_port: int = 0
    
    # Solution details
    solution_successful: bool = True
    flag_found: str = ""
    solution_steps: List[str] = field(default_factory=list)
    attack_pattern: str = ""  # e.g., "small_e_attack", "padding_oracle", etc.
    solution_code: str = ""  # Python code that solved it
    
    # Timing and metadata
    solve_time_seconds: float = 0.0
    confidence_score: float = 0.0
    attempts_before_success: int = 1
    
    # Embeddings (populated by ExperienceStorage)
    description_embedding: Optional[List[float]] = None
    code_embedding: Optional[List[float]] = None
    
    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SolvedChallengeExperience':
        """Create from dictionary."""
        return cls(**data)
    
    def get_full_text(self) -> str:
        """Get full text representation for embedding."""
        parts = [
            f"Challenge: {self.challenge_name}",
            f"Type: {self.challenge_type}",
            f"Description: {self.challenge_description}",
            f"Attack: {self.attack_pattern}",
        ]
        
        # Add file contents
        for f in self.source_files:
            parts.append(f"File {f.get('name', 'unknown')}:\n{f.get('content', '')[:1000]}")
        
        # Add solution steps
        if self.solution_steps:
            parts.append("Solution steps: " + " -> ".join(self.solution_steps))
        
        return "\n\n".join(parts)


class ExperienceStorage:
    """
    Manages storage and retrieval of solved challenge experiences.
    Uses embeddings for similarity search and SQLite for persistence.
    """
    
    EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 dimension
    
    def __init__(self, db_path: str = "ctf_experiences.db", 
                 model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize experience storage.
        
        Args:
            db_path: Path to SQLite database (will be resolved against project root)
            model_name: Sentence transformer model for embeddings
        """
        # Ensure db_path is absolute to the project root to prevent leaking duplicates in cwd
        if not os.path.isabs(db_path):
            self.db_path = PROJECT_ROOT / db_path
        else:
            self.db_path = Path(db_path)
            
        self.model_name = model_name
        self._embedder = None
        self._faiss_index = None
        self._experience_ids = []  # Maps FAISS index to experience IDs
        
        self._init_database()
        self._load_faiss_index()
    
    @property
    def embedder(self):
        """Lazy load the sentence transformer model."""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer(self.model_name)
            except ImportError as e:
                print(f"⚠️ Warning: sentence_transformers not installed: {e}")
                return None
            except Exception as e:
                print(f"⚠️ Warning: Could not load SentenceTransformer: {e}")
                return None
        return self._embedder
    
    def _init_database(self):
        """Initialize SQLite database with experience tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Main experiences table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS experiences (
                    id TEXT PRIMARY KEY,
                    challenge_name TEXT NOT NULL,
                    challenge_description TEXT,
                    challenge_type TEXT,
                    difficulty TEXT,
                    source_files_json TEXT,
                    server_host TEXT,
                    server_port INTEGER,
                    solution_successful INTEGER,
                    flag_found TEXT,
                    solution_steps_json TEXT,
                    attack_pattern TEXT,
                    solution_code TEXT,
                    solve_time_seconds REAL,
                    confidence_score REAL,
                    attempts_before_success INTEGER,
                    description_embedding BLOB,
                    code_embedding BLOB,
                    created_at TEXT
                )
            """)
            
            # Attack patterns table (for statistics)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT UNIQUE NOT NULL,
                    challenge_type TEXT,
                    success_count INTEGER DEFAULT 0,
                    total_count INTEGER DEFAULT 0,
                    avg_solve_time REAL,
                    description TEXT
                )
            """)
            
            # Insert common attack patterns
            patterns = [
                ("small_e_attack", "RSA", "RSA with small exponent e (e.g., e=3)"),
                ("wiener_attack", "RSA", "RSA with small private exponent d"),
                ("common_modulus", "RSA", "Same modulus with different exponents"),
                ("factordb_lookup", "RSA", "Lookup n in FactorDB"),
                ("hastad_broadcast", "RSA", "Same message encrypted to multiple recipients"),
                ("padding_oracle", "AES", "CBC padding oracle attack"),
                ("ecb_detection", "AES", "ECB mode detection and exploitation"),
                ("nonce_reuse", "AES", "GCM/CTR nonce reuse attack"),
                ("frequency_analysis", "Classical", "Letter frequency analysis"),
                ("caesar_bruteforce", "Classical", "Caesar cipher brute force"),
                ("vigenere_attack", "Classical", "Vigenère cipher key recovery"),
                ("xor_single_byte", "XOR", "Single byte XOR key recovery"),
                ("xor_repeating", "XOR", "Repeating key XOR attack"),
                ("hash_collision", "Hash", "Find hash collisions"),
                ("length_extension", "Hash", "Hash length extension attack"),
                ("lagrange_interpolation", "Math", "Polynomial interpolation"),
                ("discrete_log", "ECC", "Discrete logarithm attack"),
            ]
            
            for pattern, ctype, desc in patterns:
                cursor.execute("""
                    INSERT OR IGNORE INTO attack_patterns 
                    (pattern_name, challenge_type, description)
                    VALUES (?, ?, ?)
                """, (pattern, ctype, desc))
            
            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exp_type ON experiences(challenge_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exp_attack ON experiences(attack_pattern)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exp_success ON experiences(solution_successful)")
            
            # Migration: add times_helpful column if not present
            try:
                cursor.execute("ALTER TABLE experiences ADD COLUMN times_helpful INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass  # column already exists
            
            conn.commit()
    
    def _load_faiss_index(self):
        """Load or create FAISS index for similarity search."""
        if not HAS_FAISS:
            return
        
        # Try to load existing index
        index_path = self.db_path.parent / "experience_index.faiss"
        ids_path = self.db_path.parent / "experience_ids.json"
        
        if index_path.exists() and ids_path.exists():
            self._faiss_index = faiss.read_index(str(index_path))
            with open(ids_path) as f:
                self._experience_ids = json.load(f)
        else:
            # Create new index
            self._faiss_index = faiss.IndexFlatIP(self.EMBEDDING_DIM)  # Inner product
            self._experience_ids = []
    
    def _save_faiss_index(self):
        """Save FAISS index to disk."""
        if not HAS_FAISS or self._faiss_index is None:
            return
        
        index_path = self.db_path.parent / "experience_index.faiss"
        ids_path = self.db_path.parent / "experience_ids.json"
        
        faiss.write_index(self._faiss_index, str(index_path))
        with open(ids_path, 'w') as f:
            json.dump(self._experience_ids, f)
    
    def _generate_id(self, experience: SolvedChallengeExperience) -> str:
        """Generate unique ID for an experience."""
        content = f"{experience.challenge_name}|{experience.challenge_description}|{experience.created_at}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _compute_embedding(self, text: str) -> np.ndarray:
        """Compute embedding for text."""
        embedder = self.embedder
        if embedder is None:
             # Return zero vector if no embedder (simulating 384 dimensions)
             return np.zeros(self.EMBEDDING_DIM, dtype=np.float32)
             
        embedding = embedder.encode(text, normalize_embeddings=True)
        return embedding.astype(np.float32)
    
    def store_experience(self, experience: SolvedChallengeExperience) -> str:
        """
        Store a solved challenge experience.
        
        Args:
            experience: The solved challenge experience
            
        Returns:
            experience_id: Unique ID for this experience
        """
        # Generate ID
        experience_id = experience.challenge_id or self._generate_id(experience)
        experience.challenge_id = experience_id
        
        # Compute embeddings
        full_text = experience.get_full_text()
        desc_embedding = self._compute_embedding(full_text)
        experience.description_embedding = desc_embedding.tolist()
        
        # Compute code embedding if solution code exists
        code_embedding_bytes = None
        if experience.solution_code:
            code_embedding = self._compute_embedding(experience.solution_code)
            experience.code_embedding = code_embedding.tolist()
            code_embedding_bytes = code_embedding.tobytes()
        
        # Store in SQLite
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO experiences VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                experience_id,
                experience.challenge_name,
                experience.challenge_description,
                experience.challenge_type,
                experience.difficulty,
                json.dumps(experience.source_files),
                experience.server_host,
                experience.server_port,
                int(experience.solution_successful),
                experience.flag_found,
                json.dumps(experience.solution_steps),
                experience.attack_pattern,
                experience.solution_code,
                experience.solve_time_seconds,
                experience.confidence_score,
                experience.attempts_before_success,
                desc_embedding.tobytes(),
                code_embedding_bytes,  # Fixed: serialize as bytes, not list
                experience.created_at
            ))
            
            # Update attack pattern statistics
            if experience.attack_pattern:
                cursor.execute("""
                    UPDATE attack_patterns 
                    SET success_count = success_count + ?,
                        total_count = total_count + 1
                    WHERE pattern_name = ?
                """, (int(experience.solution_successful), experience.attack_pattern))
            
            conn.commit()
        
        # Update FAISS index
        if HAS_FAISS and self._faiss_index is not None:
            self._faiss_index.add(desc_embedding.reshape(1, -1))
            self._experience_ids.append(experience_id)
            self._save_faiss_index()
        
        return experience_id
    
    def get_similar_experiences(self, query: str, k: int = 5, 
                                challenge_type: str = None) -> List[SolvedChallengeExperience]:
        """
        Find similar solved challenges using embedding similarity.
        
        Args:
            query: Query text (challenge description, code, etc.)
            k: Number of similar experiences to return
            challenge_type: Optional filter by challenge type
            
        Returns:
            List of similar experiences, sorted by relevance
        """
        # Compute query embedding
        query_embedding = self._compute_embedding(query)
        
        if HAS_FAISS and self._faiss_index is not None and self._faiss_index.ntotal > 0:
            # Use FAISS for fast search
            scores, indices = self._faiss_index.search(
                query_embedding.reshape(1, -1), 
                min(k * 2, self._faiss_index.ntotal)  # Get more for filtering
            )
            
            experience_ids = [self._experience_ids[i] for i in indices[0] if i < len(self._experience_ids)]
        else:
            # Fallback: Get all experiences and compute similarity
            experience_ids = self._get_all_experience_ids()
        
        # Load experiences and filter
        experiences = []
        for exp_id in experience_ids:
            exp = self.get_experience(exp_id)
            if exp is None:
                continue
            if challenge_type and exp.challenge_type != challenge_type:
                continue
            
            # Compute similarity if not using FAISS
            if not HAS_FAISS or self._faiss_index is None:
                exp_embedding = np.array(exp.description_embedding, dtype=np.float32)
                similarity = np.dot(query_embedding, exp_embedding)
                exp._similarity = similarity
            else:
                # Use FAISS score
                idx = experience_ids.index(exp_id) if exp_id in experience_ids else 0
                exp._similarity = scores[0][idx] if idx < len(scores[0]) else 0
            
            experiences.append(exp)
        
        # Sort by similarity and return top k
        experiences.sort(key=lambda x: getattr(x, '_similarity', 0), reverse=True)
        return experiences[:k]
    
    def get_similar_experiences_reranked(
        self, query: str, k: int = 5,
        challenge_type: str = None,
        query_params: Dict[str, Any] = None
    ) -> List[SolvedChallengeExperience]:
        """
        Find similar solved challenges with domain-aware reranking.
        
        First retrieves top candidates from FAISS, then applies
        domain-specific scoring bonuses.
        
        Args:
            query: Query text (challenge description, code, etc.)
            k: Number of similar experiences to return
            challenge_type: Optional filter/bonus by challenge type
            query_params: Extracted params from the new challenge
                          (e.g. {"n_bits": 2048, "e": 3, "attack_pattern": "small_e"})
        
        Returns:
            List of similar experiences, sorted by reranked score
        """
        # Step 1: Get broad FAISS results (fetch more than needed)
        candidates = self.get_similar_experiences(
            query=query,
            k=k * 3,  # overretrieve for reranking
            challenge_type=None  # don't filter yet, let reranker bonus it
        )
        
        if not candidates:
            return []
        
        # Step 2: Rerank with domain scoring
        reranked = self.rerank_results(
            candidates, challenge_type, query, query_params or {}
        )
        
        return reranked[:k]
    
    def rerank_results(
        self,
        experiences: List[SolvedChallengeExperience],
        target_type: str = None,
        query: str = "",
        query_params: Dict[str, Any] = None
    ) -> List[SolvedChallengeExperience]:
        """
        Rerank FAISS results using domain-specific scoring.
        
        Scoring bonuses:
        - Type match: x1.5 if challenge_type matches
        - Attack pattern keyword match: x1.3
        - Battle-tested: x(1 + 0.1 * times_helpful)
        - Structural similarity: bonus for matching n size, e value, etc.
        
        Args:
            experiences: Pre-filtered candidates from FAISS
            target_type: Expected challenge type (RSA, AES, etc.)
            query: Original query text
            query_params: Extracted parameters from the new challenge
        
        Returns:
            Reranked list of experiences
        """
        query_params = query_params or {}
        query_lower = query.lower()
        
        # Load times_helpful for each candidate
        helpful_map = self._get_helpful_counts(
            [exp.challenge_id for exp in experiences]
        )
        
        for exp in experiences:
            base_score = getattr(exp, '_similarity', 0.5)
            multiplier = 1.0
            
            # 1. Type match bonus
            if target_type and exp.challenge_type == target_type:
                multiplier *= 1.5
            elif target_type and exp.challenge_type != target_type:
                multiplier *= 0.7  # penalty for type mismatch
            
            # 2. Attack pattern keyword bonus
            if exp.attack_pattern and exp.attack_pattern.lower() in query_lower:
                multiplier *= 1.3
            
            # 3. Battle-tested bonus
            helpful = helpful_map.get(exp.challenge_id, 0)
            if helpful > 0:
                multiplier *= (1.0 + 0.1 * min(helpful, 10))  # cap at 2x
            
            # 4. Structural similarity bonus
            struct_bonus = self._structural_similarity(
                exp, query_params
            )
            multiplier *= (1.0 + struct_bonus)
            
            exp._similarity = base_score * multiplier
        
        # Re-sort by updated score
        experiences.sort(key=lambda x: getattr(x, '_similarity', 0), reverse=True)
        return experiences
    
    def _structural_similarity(
        self,
        exp: SolvedChallengeExperience,
        query_params: Dict[str, Any]
    ) -> float:
        """
        Compute structural similarity bonus [0.0 - 0.5] based on parameter matching.
        
        Checks: n bit-length similarity, same e value, same AES mode, etc.
        """
        bonus = 0.0
        
        if not query_params:
            return 0.0
        
        # Parse experience's source files for structural features
        exp_code = ""
        for f in (exp.source_files or []):
            exp_code += f.get("content", "") + "\n"
        exp_code += exp.solution_code or ""
        exp_lower = exp_code.lower()
        
        # RSA: same e value
        q_e = query_params.get("e") or query_params.get("e_bits")
        if q_e and str(q_e) in exp_lower:
            bonus += 0.15
        
        # RSA: similar n bit length (within 256 bits)
        q_n_bits = query_params.get("n_bits", 0)
        if q_n_bits > 0:
            import re
            n_match = re.search(r'n\s*=\s*(\d+)', exp_code)
            if n_match:
                exp_n_bits = int(n_match.group(1)).bit_length()
                if abs(q_n_bits - exp_n_bits) <= 256:
                    bonus += 0.15
        
        # AES: same mode
        q_mode = str(query_params.get("mode", "")).lower()
        if q_mode and q_mode in exp_lower:
            bonus += 0.2
        
        return min(bonus, 0.5)  # cap bonus at 0.5
    
    def _get_helpful_counts(self, exp_ids: List[str]) -> Dict[str, int]:
        """Get times_helpful counts for a batch of experience IDs."""
        if not exp_ids:
            return {}
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in exp_ids)
            try:
                cursor.execute(
                    f"SELECT id, times_helpful FROM experiences WHERE id IN ({placeholders})",
                    exp_ids
                )
                return {row[0]: row[1] or 0 for row in cursor.fetchall()}
            except sqlite3.OperationalError:
                return {}
    
    def increment_helpful(self, experience_id: str) -> None:
        """Mark an experience as having helped solve a new challenge."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "UPDATE experiences SET times_helpful = COALESCE(times_helpful, 0) + 1 WHERE id = ?",
                    (experience_id,)
                )
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column may not exist yet
    
    def get_experience(self, experience_id: str) -> Optional[SolvedChallengeExperience]:
        """Get a specific experience by ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM experiences WHERE id = ?", (experience_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return SolvedChallengeExperience(
                challenge_id=row[0],
                challenge_name=row[1],
                challenge_description=row[2],
                challenge_type=row[3],
                difficulty=row[4],
                source_files=json.loads(row[5]) if row[5] else [],
                server_host=row[6] or "",
                server_port=row[7] or 0,
                solution_successful=bool(row[8]),
                flag_found=row[9] or "",
                solution_steps=json.loads(row[10]) if row[10] else [],
                attack_pattern=row[11] or "",
                solution_code=row[12] or "",
                solve_time_seconds=row[13] or 0.0,
                confidence_score=row[14] or 0.0,
                attempts_before_success=row[15] or 1,
                description_embedding=list(np.frombuffer(row[16], dtype=np.float32)) if row[16] else None,
                code_embedding=list(np.frombuffer(row[17], dtype=np.float32)) if row[17] else None,
                created_at=row[18]
            )
    
    def _get_all_experience_ids(self) -> List[str]:
        """Get all experience IDs from database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM experiences")
            return [row[0] for row in cursor.fetchall()]
    
    def export_for_training(self) -> List[Dict[str, Any]]:
        """
        Export all experiences for model training.
        
        Returns:
            List of experience dictionaries ready for training
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, challenge_name, challenge_description, challenge_type,
                       difficulty, source_files_json, attack_pattern, solution_code,
                       solution_steps_json, solution_successful
                FROM experiences
                WHERE solution_successful = 1
            """)
            
            training_data = []
            for row in cursor.fetchall():
                training_data.append({
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "type": row[3],
                    "difficulty": row[4],
                    "files": json.loads(row[5]) if row[5] else [],
                    "attack_pattern": row[6],
                    "solution_code": row[7],
                    "solution_steps": json.loads(row[8]) if row[8] else [],
                    "successful": bool(row[9])
                })
            
            return training_data
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored experiences."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total experiences
            cursor.execute("SELECT COUNT(*) FROM experiences")
            total = cursor.fetchone()[0]
            
            # Successful experiences
            cursor.execute("SELECT COUNT(*) FROM experiences WHERE solution_successful = 1")
            successful = cursor.fetchone()[0]
            
            # By challenge type
            cursor.execute("""
                SELECT challenge_type, COUNT(*), 
                       SUM(CASE WHEN solution_successful = 1 THEN 1 ELSE 0 END)
                FROM experiences
                GROUP BY challenge_type
            """)
            by_type = {row[0]: {"total": row[1], "successful": row[2]} 
                      for row in cursor.fetchall()}
            
            # Attack pattern effectiveness
            cursor.execute("""
                SELECT pattern_name, success_count, total_count
                FROM attack_patterns
                WHERE total_count > 0
            """)
            attack_stats = {row[0]: {"successes": row[1], "attempts": row[2],
                                     "rate": row[1]/row[2] if row[2] > 0 else 0}
                          for row in cursor.fetchall()}
            
            return {
                "total_experiences": total,
                "successful_experiences": successful,
                "success_rate": successful / total if total > 0 else 0,
                "by_challenge_type": by_type,
                "attack_pattern_stats": attack_stats
            }


# Utility function for easy integration
def get_experience_storage() -> ExperienceStorage:
    """Get singleton instance of experience storage."""
    if not hasattr(get_experience_storage, '_instance'):
        get_experience_storage._instance = ExperienceStorage()
    return get_experience_storage._instance


if __name__ == "__main__":
    # Test the experience storage
    print("🧠 Testing Experience Storage System...")
    
    storage = ExperienceStorage()
    
    # Create a test experience
    exp = SolvedChallengeExperience(
        challenge_id="test_001",
        challenge_name="RSA Small e Attack",
        challenge_description="RSA encryption with e=3, vulnerable to cube root attack",
        challenge_type="RSA",
        difficulty="Easy",
        source_files=[{
            "name": "challenge.py",
            "content": "n = 12345...\ne = 3\nc = 67890..."
        }],
        solution_successful=True,
        flag_found="flag{small_e_is_bad}",
        solution_steps=["analyze_files", "detect_small_e", "compute_cube_root"],
        attack_pattern="small_e_attack",
        solution_code="""
from gmpy2 import iroot
m, exact = iroot(c, 3)
if exact:
    print(bytes.fromhex(hex(m)[2:]))
""",
        solve_time_seconds=2.5,
        confidence_score=0.95
    )
    
    # Store it
    exp_id = storage.store_experience(exp)
    print(f"✅ Stored experience: {exp_id}")
    
    # Query similar
    similar = storage.get_similar_experiences("RSA challenge with small exponent", k=3)
    print(f"🔍 Found {len(similar)} similar experiences")
    
    # Show stats
    stats = storage.get_statistics()
    print(f"📊 Statistics: {stats['total_experiences']} experiences, "
          f"{stats['success_rate']:.1%} success rate")
