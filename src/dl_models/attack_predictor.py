"""
LSTM-based Attack Predictor for CTF Solver
Predicts optimal attack sequences for solving challenges.
"""

import json
import torch
import torch.nn as nn
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False


@dataclass
class PredictorConfig:
    """Configuration for Attack Predictor."""
    embedding_dim: int = 384  # Sentence transformer dimension
    hidden_dim: int = 256
    num_layers: int = 2
    dropout: float = 0.2
    max_sequence_length: int = 10  # Max attack steps to predict
    
    # Available attacks to predict
    attacks: List[str] = field(default_factory=lambda: [
        # RSA attacks
        "small_e_attack", "wiener_attack", "common_modulus", 
        "factordb_lookup", "hastad_broadcast", "fermat_factorization",
        
        # AES/Symmetric attacks
        "padding_oracle", "ecb_detection", "nonce_reuse",
        "byte_at_a_time", "cbc_bitflip",
        
        # Classical attacks
        "frequency_analysis", "caesar_bruteforce", "vigenere_kasiski",
        "substitution_solve",
        
        # XOR attacks
        "xor_single_byte", "xor_repeating", "xor_known_plaintext",
        
        # Hash attacks
        "hash_collision", "length_extension", "rainbow_table",
        
        # Math attacks
        "lagrange_interpolation", "discrete_log", "pohlig_hellman",
        
        # General
        "base64_decode", "hex_decode", "rot13",
        
        # Special tokens
        "<START>", "<END>", "<PAD>"
    ])


class AttackPredictorModel(nn.Module):
    """
    LSTM-based sequence model for predicting attack steps.
    Uses attention mechanism for better context understanding.
    """
    
    def __init__(self, config: PredictorConfig):
        super().__init__()
        self.config = config
        
        num_attacks = len(config.attacks)
        
        # Attack embedding layer
        self.attack_embedding = nn.Embedding(
            num_embeddings=num_attacks,
            embedding_dim=config.embedding_dim // 2
        )
        
        # Challenge context projection
        self.context_projection = nn.Linear(
            config.embedding_dim, 
            config.embedding_dim // 2
        )
        
        # Combine attack + context
        combined_dim = config.embedding_dim
        
        # LSTM for sequence prediction
        self.lstm = nn.LSTM(
            input_size=combined_dim,
            hidden_size=config.hidden_dim,
            num_layers=config.num_layers,
            dropout=config.dropout if config.num_layers > 1 else 0,
            batch_first=True
        )
        
        # Attention mechanism
        self.attention = nn.MultiheadAttention(
            embed_dim=config.hidden_dim,
            num_heads=4,
            dropout=config.dropout,
            batch_first=True
        )
        
        # Output layers
        self.output_projection = nn.Linear(config.hidden_dim, num_attacks)
        
        # Success probability estimator
        self.success_estimator = nn.Sequential(
            nn.Linear(config.hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
        
        self.dropout = nn.Dropout(config.dropout)
    
    def forward(self, challenge_embedding, attack_sequence=None):
        """
        Forward pass.
        
        Args:
            challenge_embedding: [batch, embedding_dim] challenge context
            attack_sequence: [batch, seq_len] previous attack indices (for training)
            
        Returns:
            attack_logits: [batch, seq_len, num_attacks] logits for next attack
            success_prob: [batch] estimated success probability
        """
        batch_size = challenge_embedding.size(0)
        device = challenge_embedding.device
        
        # Project challenge context
        context = self.context_projection(challenge_embedding)  # [batch, emb/2]
        
        if attack_sequence is None:
            # Inference mode: generate sequence autoregressively
            return self._generate_sequence(context, batch_size, device)
        
        # Training mode: teacher forcing
        seq_len = attack_sequence.size(1)
        
        # Embed attack sequence
        attack_emb = self.attack_embedding(attack_sequence)  # [batch, seq, emb/2]
        
        # Expand context to match sequence
        context_expanded = context.unsqueeze(1).expand(-1, seq_len, -1)
        
        # Combine attack embeddings with context
        combined = torch.cat([attack_emb, context_expanded], dim=-1)  # [batch, seq, emb]
        combined = self.dropout(combined)
        
        # LSTM processing
        lstm_out, (hidden, cell) = self.lstm(combined)  # [batch, seq, hidden]
        
        # Self-attention
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
        
        # Residual connection
        output = lstm_out + attn_out
        
        # Project to attack vocabulary
        attack_logits = self.output_projection(output)  # [batch, seq, num_attacks]
        
        # Estimate overall success probability using final hidden state
        success_prob = self.success_estimator(hidden[-1])  # [batch, 1]
        
        return attack_logits, success_prob.squeeze(-1)
    
    def _generate_sequence(self, context, batch_size, device):
        """Generate attack sequence autoregressively."""
        start_idx = self.config.attacks.index("<START>")
        end_idx = self.config.attacks.index("<END>")
        
        # Start with <START> token
        current = torch.full((batch_size, 1), start_idx, dtype=torch.long, device=device)
        generated = [current]
        
        hidden = None
        all_probs = []
        
        for step in range(self.config.max_sequence_length):
            # Embed current attack
            attack_emb = self.attack_embedding(current[:, -1:])  # [batch, 1, emb/2]
            
            # Combine with context
            combined = torch.cat([attack_emb, context.unsqueeze(1)], dim=-1)
            
            # LSTM step
            lstm_out, hidden = self.lstm(combined, hidden)
            
            # Project to vocabulary
            logits = self.output_projection(lstm_out[:, -1])  # [batch, num_attacks]
            probs = torch.softmax(logits, dim=-1)
            all_probs.append(probs)
            
            # Greedy selection
            next_attack = probs.argmax(dim=-1, keepdim=True)
            generated.append(next_attack)
            current = next_attack
            
            # Stop if all sequences have generated <END>
            if (next_attack == end_idx).all():
                break
        
        return torch.cat(generated, dim=1), torch.stack(all_probs, dim=1)


class AttackPredictor:
    """
    High-level interface for attack sequence prediction.
    """
    
    def __init__(self, config: PredictorConfig = None, model_path: str = None):
        """Initialize predictor."""
        self.config = config or PredictorConfig()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize sentence transformer for challenge embedding
        self._embedder = None
        
        # Initialize model
        self.model = AttackPredictorModel(self.config)
        
        if model_path and Path(model_path).exists():
            self.load(model_path)
        
        self.model.to(self.device)
    
    @property
    def embedder(self):
        """Lazy load sentence transformer."""
        if self._embedder is None:
            if not HAS_SENTENCE_TRANSFORMERS:
                raise ImportError("sentence-transformers required")
            self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
        return self._embedder
    
    def predict(self, challenge_text: str, files: List[Dict] = None,
               challenge_type: str = None) -> Dict[str, Any]:
        """
        Predict attack sequence for a challenge.
        
        Args:
            challenge_text: Challenge description
            files: Source files
            challenge_type: Optional pre-classified type
            
        Returns:
            Dictionary with predicted attacks and probabilities
        """
        # Prepare input
        full_text = self._prepare_input(challenge_text, files, challenge_type)
        
        # Get challenge embedding
        embedding = self.embedder.encode(full_text, convert_to_tensor=True)
        embedding = embedding.unsqueeze(0).to(self.device)
        
        # Generate attack sequence
        self.model.eval()
        with torch.no_grad():
            sequence, probs = self.model(embedding)
        
        # Convert to attack names
        attacks = []
        for idx in sequence[0].tolist():
            attack = self.config.attacks[idx]
            if attack in ["<START>", "<PAD>"]:
                continue
            if attack == "<END>":
                break
            attacks.append(attack)
        
        # Get probabilities
        attack_probs = []
        for i, attack in enumerate(attacks):
            if i < probs.size(1):
                prob = probs[0, i, sequence[0, i+1]].item()
                attack_probs.append((attack, prob))
            else:
                attack_probs.append((attack, 0.5))
        
        return {
            "predicted_attacks": attacks,
            "attack_probabilities": attack_probs,
            "sequence_length": len(attacks),
            "total_confidence": sum(p for _, p in attack_probs) / len(attacks) if attacks else 0
        }
    
    def _prepare_input(self, description: str, files: List[Dict] = None,
                      challenge_type: str = None) -> str:
        """Prepare input text for embedding."""
        parts = []
        
        if challenge_type:
            parts.append(f"Type: {challenge_type}")
        
        parts.append(f"Challenge: {description}")
        
        if files:
            for f in files:
                name = f.get("name", "unknown")
                content = f.get("content", "")[:1500]
                parts.append(f"File {name}:\n{content}")
        
        return "\n".join(parts)
    
    def save(self, path: str):
        """Save model."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), path / "predictor.pt")
        
        with open(path / "predictor_config.json", "w") as f:
            json.dump({
                "attacks": self.config.attacks,
                "hidden_dim": self.config.hidden_dim,
                "num_layers": self.config.num_layers
            }, f, indent=2)
    
    def load(self, path: str):
        """Load model."""
        path = Path(path)
        
        if (path / "predictor.pt").exists():
            state_dict = torch.load(path / "predictor.pt", map_location=self.device)
            self.model.load_state_dict(state_dict)
        
        if (path / "predictor_config.json").exists():
            with open(path / "predictor_config.json") as f:
                config_dict = json.load(f)
                self.config.attacks = config_dict.get("attacks", self.config.attacks)


# Rule-based fallback for attack prediction
class RuleBasedAttackPredictor:
    """
    Rule-based attack predictor as fallback.
    Uses heuristics based on challenge type and patterns.
    """
    
    ATTACK_CHAINS = {
        "RSA": [
            ["factordb_lookup", "small_e_attack"],
            ["wiener_attack"],
            ["common_modulus"],
            ["fermat_factorization"],
            ["hastad_broadcast"]
        ],
        "AES": [
            ["ecb_detection", "byte_at_a_time"],
            ["padding_oracle"],
            ["nonce_reuse"],
            ["cbc_bitflip"]
        ],
        "Classical": [
            ["caesar_bruteforce"],
            ["frequency_analysis", "substitution_solve"],
            ["vigenere_kasiski"]
        ],
        "XOR": [
            ["xor_single_byte"],
            ["xor_repeating"],
            ["xor_known_plaintext"]
        ],
        "Hash": [
            ["length_extension"],
            ["hash_collision"],
            ["rainbow_table"]
        ],
        "Encoding": [
            ["base64_decode"],
            ["hex_decode"],
            ["rot13"]
        ],
        "ECC": [
            ["discrete_log"],
            ["pohlig_hellman"]
        ],
        "Math": [
            ["lagrange_interpolation"]
        ]
    }
    
    PATTERN_ATTACKS = {
        "e = 3": ["small_e_attack"],
        "e=3": ["small_e_attack"],
        "small exponent": ["small_e_attack"],
        "small d": ["wiener_attack"],
        "wiener": ["wiener_attack"],
        "same modulus": ["common_modulus"],
        "padding": ["padding_oracle"],
        "oracle": ["padding_oracle"],
        "ecb": ["ecb_detection"],
        "nonce": ["nonce_reuse"],
        "caesar": ["caesar_bruteforce"],
        "rot13": ["rot13"],
        "frequency": ["frequency_analysis"],
        "base64": ["base64_decode"],
        "hex": ["hex_decode"],
        "xor": ["xor_single_byte", "xor_repeating"],
        "lagrange": ["lagrange_interpolation"],
        "polynomial": ["lagrange_interpolation"],
        "discrete log": ["discrete_log"],
        "dlog": ["discrete_log"],
    }
    
    def predict(self, challenge_text: str, files: List[Dict] = None,
               challenge_type: str = None) -> Dict[str, Any]:
        """Predict attacks using rules."""
        # Combine text
        full_text = challenge_text.lower()
        if files:
            for f in files:
                full_text += " " + f.get("content", "").lower()
        
        attacks = []
        
        # First, check for specific patterns
        for pattern, pattern_attacks in self.PATTERN_ATTACKS.items():
            if pattern in full_text:
                attacks.extend(pattern_attacks)
        
        # If challenge type is known, add type-based attacks
        if challenge_type and challenge_type in self.ATTACK_CHAINS:
            for chain in self.ATTACK_CHAINS[challenge_type]:
                for attack in chain:
                    if attack not in attacks:
                        attacks.append(attack)
        
        # Deduplicate and limit
        seen = set()
        unique_attacks = []
        for a in attacks:
            if a not in seen:
                seen.add(a)
                unique_attacks.append(a)
        
        attacks = unique_attacks[:5]  # Max 5 attacks
        
        if not attacks:
            attacks = ["frequency_analysis", "base64_decode"]  # Generic fallback
        
        return {
            "predicted_attacks": attacks,
            "attack_probabilities": [(a, 0.7) for a in attacks],
            "sequence_length": len(attacks),
            "total_confidence": 0.6,
            "method": "rule_based"
        }


def get_attack_predictor(model_path: str = None) -> AttackPredictor:
    """Get predictor, using DL if available."""
    if HAS_SENTENCE_TRANSFORMERS:
        try:
            return AttackPredictor(model_path=model_path)
        except Exception as e:
            print(f"⚠️ Could not load DL predictor: {e}")
            return RuleBasedAttackPredictor()
    else:
        return RuleBasedAttackPredictor()


if __name__ == "__main__":
    print("🧪 Testing Attack Predictor...")
    
    # Test rule-based
    predictor = RuleBasedAttackPredictor()
    
    result = predictor.predict(
        "RSA challenge with e=3, find the flag",
        [{"name": "chall.py", "content": "n = 123\ne = 3\nc = 456"}],
        challenge_type="RSA"
    )
    
    print(f"✅ Predicted attacks: {result['predicted_attacks']}")
    print(f"📊 Confidence: {result['total_confidence']:.2f}")
    
    # Test DL if available
    if HAS_SENTENCE_TRANSFORMERS:
        try:
            dl_predictor = AttackPredictor()
            print("\n🧠 Testing DL Predictor...")
            result = dl_predictor.predict(
                "RSA challenge with e=3",
                [{"name": "chall.py", "content": "n = 123\ne = 3\nc = 456"}]
            )
            print(f"✅ Predicted attacks: {result['predicted_attacks']}")
        except Exception as e:
            print(f"⚠️ DL predictor error: {e}")
