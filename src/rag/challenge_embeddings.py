"""
Challenge Embedding System for RAG-based CTF Solver
Generates embeddings for challenges, code, and solutions for similarity search.
"""

import json
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False


@dataclass
class EmbeddingConfig:
    """Configuration for challenge embeddings."""
    text_model: str = "all-MiniLM-L6-v2"  # Fast and effective
    code_model: str = "microsoft/codebert-base"  # Better for code
    embedding_dim: int = 384  # For MiniLM
    use_code_model: bool = False  # Use simpler model by default
    normalize: bool = True
    batch_size: int = 32


class ChallengeEmbedder:
    """
    Generates embeddings for CTF challenges and solutions.
    Supports multiple embedding strategies for different content types.
    """
    
    def __init__(self, config: EmbeddingConfig = None):
        """Initialize embedder with optional config."""
        if not HAS_SENTENCE_TRANSFORMERS:
            raise ImportError(
                "sentence-transformers required. Run: pip install sentence-transformers"
            )
        
        self.config = config or EmbeddingConfig()
        self._text_model = None
        self._code_model = None
    
    @property
    def text_model(self) -> SentenceTransformer:
        """Lazy load text embedding model."""
        if self._text_model is None:
            self._text_model = SentenceTransformer(self.config.text_model)
        return self._text_model
    
    @property
    def code_model(self) -> SentenceTransformer:
        """Lazy load code embedding model."""
        if self._code_model is None:
            if self.config.use_code_model:
                self._code_model = SentenceTransformer(self.config.code_model)
            else:
                self._code_model = self.text_model
        return self._code_model
    
    def embed_challenge(self, description: str, files: List[Dict] = None,
                       challenge_type: str = None) -> np.ndarray:
        """
        Create embedding for a CTF challenge.
        
        Args:
            description: Challenge description
            files: Source files [{name, content}]
            challenge_type: Optional challenge type
            
        Returns:
            numpy array of shape (embedding_dim,)
        """
        # Prepare text representation
        parts = []
        
        if challenge_type:
            parts.append(f"[{challenge_type}]")
        
        parts.append(description)
        
        if files:
            # Add file content summaries
            for f in files:
                name = f.get("name", "unknown")
                content = f.get("content", "")
                # Extract key parts of code
                summary = self._summarize_code(content)
                parts.append(f"File {name}: {summary}")
        
        full_text = "\n".join(parts)
        
        # Generate embedding
        embedding = self.text_model.encode(
            full_text,
            normalize_embeddings=self.config.normalize,
            show_progress_bar=False
        )
        
        return embedding.astype(np.float32)
    
    def embed_code(self, code: str) -> np.ndarray:
        """
        Create embedding for solution code.
        
        Args:
            code: Python code string
            
        Returns:
            numpy array embedding
        """
        # Clean and summarize code
        clean_code = self._clean_code(code)
        
        embedding = self.code_model.encode(
            clean_code,
            normalize_embeddings=self.config.normalize,
            show_progress_bar=False
        )
        
        return embedding.astype(np.float32)
    
    def embed_attack_pattern(self, pattern_name: str, 
                            description: str = None) -> np.ndarray:
        """
        Create embedding for an attack pattern.
        
        Args:
            pattern_name: Name of attack (e.g., "small_e_attack")
            description: Optional description
            
        Returns:
            numpy array embedding
        """
        # Convert pattern name to natural text
        text = pattern_name.replace("_", " ").title()
        
        if description:
            text = f"{text}: {description}"
        
        # Add attack context
        text = f"Cryptographic Attack: {text}"
        
        embedding = self.text_model.encode(
            text,
            normalize_embeddings=self.config.normalize,
            show_progress_bar=False
        )
        
        return embedding.astype(np.float32)
    
    def embed_batch(self, texts: List[str]) -> np.ndarray:
        """
        Embed multiple texts efficiently.
        
        Args:
            texts: List of text strings
            
        Returns:
            numpy array of shape (n_texts, embedding_dim)
        """
        embeddings = self.text_model.encode(
            texts,
            normalize_embeddings=self.config.normalize,
            batch_size=self.config.batch_size,
            show_progress_bar=False
        )
        
        return embeddings.astype(np.float32)
    
    def _summarize_code(self, code: str, max_length: int = 500) -> str:
        """Extract key parts of code for embedding."""
        if not code:
            return ""
        
        lines = code.split("\n")
        important_lines = []
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Prioritize variable assignments and function calls
            if "=" in line or "(" in line:
                important_lines.append(line)
            
            # Stop if we've collected enough
            if len(" ".join(important_lines)) > max_length:
                break
        
        return " ".join(important_lines)[:max_length]
    
    def _clean_code(self, code: str) -> str:
        """Clean code for embedding."""
        lines = code.split("\n")
        clean_lines = []
        
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
            
            # Skip pure comment lines
            if line.strip().startswith("#"):
                continue
            
            clean_lines.append(line)
        
        return "\n".join(clean_lines)
    
    def similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """
        Compute cosine similarity between two embeddings.
        
        Args:
            emb1, emb2: Embedding vectors
            
        Returns:
            Similarity score between 0 and 1
        """
        if self.config.normalize:
            # Already normalized, just dot product
            return float(np.dot(emb1, emb2))
        else:
            # Compute cosine similarity
            norm1 = np.linalg.norm(emb1)
            norm2 = np.linalg.norm(emb2)
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return float(np.dot(emb1, emb2) / (norm1 * norm2))


class EmbeddingIndex:
    """
    FAISS-based index for fast similarity search.
    """
    
    def __init__(self, embedding_dim: int = 384):
        """Initialize index."""
        if not HAS_FAISS:
            raise ImportError("faiss required. Run: pip install faiss-cpu")
        
        self.embedding_dim = embedding_dim
        self.index = faiss.IndexFlatIP(embedding_dim)  # Inner product
        self.id_map: List[str] = []  # Maps index position to ID
        self.metadata: Dict[str, Dict] = {}  # Additional info per ID
    
    def add(self, embedding: np.ndarray, item_id: str, 
            metadata: Dict = None) -> None:
        """Add embedding to index."""
        # Ensure correct shape
        embedding = embedding.reshape(1, -1).astype(np.float32)
        
        # Normalize for cosine similarity
        faiss.normalize_L2(embedding)
        
        self.index.add(embedding)
        self.id_map.append(item_id)
        
        if metadata:
            self.metadata[item_id] = metadata
    
    def search(self, query_embedding: np.ndarray, k: int = 5) -> List[Tuple[str, float]]:
        """
        Find k most similar items.
        
        Args:
            query_embedding: Query vector
            k: Number of results
            
        Returns:
            List of (item_id, similarity_score) tuples
        """
        if self.index.ntotal == 0:
            return []
        
        # Prepare query
        query = query_embedding.reshape(1, -1).astype(np.float32)
        faiss.normalize_L2(query)
        
        # Search
        k = min(k, self.index.ntotal)
        scores, indices = self.index.search(query, k)
        
        results = []
        for i, (score, idx) in enumerate(zip(scores[0], indices[0])):
            if idx < len(self.id_map):
                results.append((self.id_map[idx], float(score)))
        
        return results
    
    def save(self, path: str) -> None:
        """Save index to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        faiss.write_index(self.index, str(path / "index.faiss"))
        
        with open(path / "id_map.json", "w") as f:
            json.dump(self.id_map, f)
        
        with open(path / "metadata.json", "w") as f:
            json.dump(self.metadata, f)
    
    def load(self, path: str) -> None:
        """Load index from disk."""
        path = Path(path)
        
        if (path / "index.faiss").exists():
            self.index = faiss.read_index(str(path / "index.faiss"))
        
        if (path / "id_map.json").exists():
            with open(path / "id_map.json") as f:
                self.id_map = json.load(f)
        
        if (path / "metadata.json").exists():
            with open(path / "metadata.json") as f:
                self.metadata = json.load(f)


# Fallback for when FAISS is not available
class SimpleIndex:
    """Simple numpy-based similarity search (slower but no dependencies)."""
    
    def __init__(self, embedding_dim: int = 384):
        self.embedding_dim = embedding_dim
        self.embeddings: List[np.ndarray] = []
        self.id_map: List[str] = []
        self.metadata: Dict[str, Dict] = {}
    
    def add(self, embedding: np.ndarray, item_id: str, 
            metadata: Dict = None) -> None:
        """Add embedding to index."""
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        self.embeddings.append(embedding)
        self.id_map.append(item_id)
        
        if metadata:
            self.metadata[item_id] = metadata
    
    def search(self, query_embedding: np.ndarray, k: int = 5) -> List[Tuple[str, float]]:
        """Find k most similar items."""
        if not self.embeddings:
            return []
        
        # Normalize query
        norm = np.linalg.norm(query_embedding)
        if norm > 0:
            query_embedding = query_embedding / norm
        
        # Compute all similarities
        embeddings_matrix = np.vstack(self.embeddings)
        similarities = embeddings_matrix @ query_embedding
        
        # Get top k
        k = min(k, len(self.embeddings))
        top_indices = np.argsort(similarities)[-k:][::-1]
        
        results = [
            (self.id_map[i], float(similarities[i]))
            for i in top_indices
        ]
        
        return results
    
    def save(self, path: str) -> None:
        """Save to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        np.save(str(path / "embeddings.npy"), np.array(self.embeddings))
        
        with open(path / "id_map.json", "w") as f:
            json.dump(self.id_map, f)
        
        with open(path / "metadata.json", "w") as f:
            json.dump(self.metadata, f)
    
    def load(self, path: str) -> None:
        """Load from disk."""
        path = Path(path)
        
        if (path / "embeddings.npy").exists():
            embeddings = np.load(str(path / "embeddings.npy"))
            self.embeddings = [embeddings[i] for i in range(len(embeddings))]
        
        if (path / "id_map.json").exists():
            with open(path / "id_map.json") as f:
                self.id_map = json.load(f)
        
        if (path / "metadata.json").exists():
            with open(path / "metadata.json") as f:
                self.metadata = json.load(f)


def get_embedding_index(embedding_dim: int = 384):
    """Get appropriate index implementation."""
    if HAS_FAISS:
        return EmbeddingIndex(embedding_dim)
    else:
        print("⚠️ FAISS not available, using simple numpy index")
        return SimpleIndex(embedding_dim)


if __name__ == "__main__":
    print("🧪 Testing Challenge Embedder...")
    
    if not HAS_SENTENCE_TRANSFORMERS:
        print("❌ sentence-transformers not installed")
        exit(1)
    
    embedder = ChallengeEmbedder()
    
    # Test challenge embedding
    emb1 = embedder.embed_challenge(
        "RSA challenge with small exponent e=3",
        [{"name": "chall.py", "content": "n = 123\ne = 3\nc = 456"}],
        challenge_type="RSA"
    )
    print(f"✅ Challenge embedding shape: {emb1.shape}")
    
    # Test code embedding
    emb2 = embedder.embed_code("""
from gmpy2 import iroot
m, exact = iroot(c, 3)
print(bytes.fromhex(hex(m)[2:]))
""")
    print(f"✅ Code embedding shape: {emb2.shape}")
    
    # Test similarity
    sim = embedder.similarity(emb1, emb2)
    print(f"📊 Similarity: {sim:.3f}")
    
    # Test index
    index = get_embedding_index()
    index.add(emb1, "challenge_001", {"type": "RSA"})
    index.add(emb2, "solution_001", {"type": "solution"})
    
    results = index.search(emb1, k=2)
    print(f"🔍 Search results: {results}")
