"""
Transformer-based Challenge Classifier for CTF Solver
Uses fine-tuned CodeBERT/SecureBERT for challenge type classification.
"""

import json
import torch
import torch.nn as nn
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

try:
    from transformers import (
        AutoTokenizer, 
        AutoModel, 
        AutoConfig,
        Trainer,
        TrainingArguments,
        DataCollatorWithPadding
    )
    from datasets import Dataset
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


@dataclass
class ClassifierConfig:
    """Configuration for Challenge Classifier."""
    model_name: str = "microsoft/codebert-base"  # Can also use "microsoft/graphcodebert-base"
    num_labels: int = 8  # RSA, XOR, AES, Classical, Hash, ECC, Encoding, Other
    hidden_dropout: float = 0.1
    classifier_dropout: float = 0.2
    max_length: int = 512
    learning_rate: float = 2e-5
    batch_size: int = 8
    num_epochs: int = 5
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    
    # Challenge type labels
    labels: List[str] = field(default_factory=lambda: [
        "RSA", "XOR", "AES", "Classical", "Hash", "ECC", "Encoding", "Other"
    ])
    
    # Attack pattern labels for multi-label classification
    attack_labels: List[str] = field(default_factory=lambda: [
        "small_e_attack", "wiener_attack", "common_modulus", "factordb_lookup",
        "hastad_broadcast", "padding_oracle", "ecb_detection", "nonce_reuse",
        "frequency_analysis", "caesar_bruteforce", "vigenere_attack",
        "xor_single_byte", "xor_repeating", "hash_collision", "length_extension",
        "lagrange_interpolation", "discrete_log"
    ])


class ChallengeClassifierModel(nn.Module):
    """
    Neural network for CTF challenge classification.
    Built on top of CodeBERT/SecureBERT for code understanding.
    """
    
    def __init__(self, config: ClassifierConfig):
        super().__init__()
        self.config = config
        
        if not HAS_TRANSFORMERS:
            raise ImportError("transformers library required. Run: pip install transformers")
        
        # Load pretrained model
        self.encoder = AutoModel.from_pretrained(config.model_name)
        hidden_size = self.encoder.config.hidden_size
        
        # Classification heads
        self.dropout = nn.Dropout(config.classifier_dropout)
        
        # Challenge type classifier (multi-class)
        self.type_classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(config.hidden_dropout),
            nn.Linear(hidden_size // 2, config.num_labels)
        )
        
        # Attack pattern classifier (multi-label)
        self.attack_classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(config.hidden_dropout),
            nn.Linear(hidden_size // 2, len(config.attack_labels))
        )
        
        # Difficulty estimator
        self.difficulty_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Linear(64, 3)  # Easy, Medium, Hard
        )
        
        # Confidence estimator
        self.confidence_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, input_ids, attention_mask, token_type_ids=None):
        """Forward pass through the classifier."""
        # Get contextual embeddings
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids
        )
        
        # Use [CLS] token representation
        pooled = outputs.last_hidden_state[:, 0, :]
        pooled = self.dropout(pooled)
        
        # Classification outputs
        type_logits = self.type_classifier(pooled)
        attack_logits = self.attack_classifier(pooled)
        difficulty_logits = self.difficulty_head(pooled)
        confidence = self.confidence_head(pooled)
        
        return {
            "type_logits": type_logits,
            "attack_logits": attack_logits,
            "difficulty_logits": difficulty_logits,
            "confidence": confidence.squeeze(-1)
        }


class ChallengeClassifier:
    """
    High-level interface for CTF challenge classification.
    Handles tokenization, inference, and training.
    """
    
    def __init__(self, config: ClassifierConfig = None, model_path: str = None):
        """
        Initialize classifier.
        
        Args:
            config: Classifier configuration
            model_path: Path to saved model weights (optional)
        """
        if not HAS_TRANSFORMERS:
            raise ImportError("transformers library required. Run: pip install transformers")
        
        self.config = config or ClassifierConfig()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        
        # Initialize model
        self.model = ChallengeClassifierModel(self.config)
        
        # Load weights if provided
        if model_path and Path(model_path).exists():
            self.load(model_path)
        
        self.model.to(self.device)
    
    def classify(self, challenge_text: str, files: List[Dict] = None) -> Dict[str, Any]:
        """
        Classify a CTF challenge.
        
        Args:
            challenge_text: Challenge description
            files: List of source files [{name, content}]
            
        Returns:
            Dictionary with classification results
        """
        # Prepare input text
        full_text = self._prepare_input(challenge_text, files)
        
        # Tokenize
        inputs = self.tokenizer(
            full_text,
            max_length=self.config.max_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt"
        )
        
        # Move to device
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Inference
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        # Process outputs
        type_probs = torch.softmax(outputs["type_logits"], dim=-1)[0]
        attack_probs = torch.sigmoid(outputs["attack_logits"])[0]
        difficulty_probs = torch.softmax(outputs["difficulty_logits"], dim=-1)[0]
        confidence = outputs["confidence"][0].item()
        
        # Get predictions
        type_idx = type_probs.argmax().item()
        challenge_type = self.config.labels[type_idx]
        type_confidence = type_probs[type_idx].item()
        
        # Get likely attack patterns (threshold 0.5)
        attack_patterns = [
            (self.config.attack_labels[i], attack_probs[i].item())
            for i in range(len(self.config.attack_labels))
            if attack_probs[i] > 0.3  # Lower threshold for multi-label
        ]
        attack_patterns.sort(key=lambda x: x[1], reverse=True)
        
        # Get difficulty
        difficulties = ["Easy", "Medium", "Hard"]
        difficulty_idx = difficulty_probs.argmax().item()
        
        return {
            "challenge_type": challenge_type,
            "type_confidence": type_confidence,
            "all_type_scores": {
                label: type_probs[i].item() 
                for i, label in enumerate(self.config.labels)
            },
            "attack_patterns": attack_patterns[:5],  # Top 5
            "difficulty": difficulties[difficulty_idx],
            "difficulty_confidence": difficulty_probs[difficulty_idx].item(),
            "overall_confidence": confidence
        }
    
    def _prepare_input(self, description: str, files: List[Dict] = None) -> str:
        """Prepare input text for classification."""
        parts = [f"Challenge: {description}"]
        
        if files:
            for f in files:
                name = f.get("name", "unknown")
                content = f.get("content", "")[:2000]  # Limit content length
                parts.append(f"\nFile: {name}\n{content}")
        
        return "\n".join(parts)
    
    def train(self, training_data: List[Dict], output_dir: str = "trained_classifier"):
        """
        Fine-tune the classifier on training data.
        
        Args:
            training_data: List of {text, label, attack_labels, difficulty}
            output_dir: Directory to save trained model
        """
        # Prepare dataset
        def preprocess(examples):
            texts = [self._prepare_input(ex.get("description", ""), ex.get("files", []))
                    for ex in examples]
            
            encodings = self.tokenizer(
                texts,
                truncation=True,
                max_length=self.config.max_length,
                padding="max_length"
            )
            
            # Prepare labels
            type_labels = [
                self.config.labels.index(ex.get("type", "Other"))
                if ex.get("type") in self.config.labels else len(self.config.labels) - 1
                for ex in examples
            ]
            
            encodings["labels"] = type_labels
            return encodings
        
        # Create HuggingFace dataset
        dataset = Dataset.from_list(training_data)
        dataset = dataset.map(lambda batch: preprocess([batch]), batched=False)
        
        # Split train/eval
        split = dataset.train_test_split(test_size=0.1)
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            warmup_ratio=self.config.warmup_ratio,
            weight_decay=self.config.weight_decay,
            learning_rate=self.config.learning_rate,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            logging_steps=50,
            report_to="none"  # Disable wandb/tensorboard
        )
        
        # Data collator
        data_collator = DataCollatorWithPadding(self.tokenizer)
        
        # Trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=split["train"],
            eval_dataset=split["test"],
            data_collator=data_collator
        )
        
        # Train
        trainer.train()
        
        # Save
        self.save(output_dir)
    
    def save(self, path: str):
        """Save model weights and config."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        torch.save(self.model.state_dict(), path / "model.pt")
        
        with open(path / "config.json", "w") as f:
            json.dump({
                "model_name": self.config.model_name,
                "num_labels": self.config.num_labels,
                "labels": self.config.labels,
                "attack_labels": self.config.attack_labels,
                "max_length": self.config.max_length
            }, f, indent=2)
    
    def load(self, path: str):
        """Load model weights."""
        path = Path(path)
        
        if (path / "config.json").exists():
            with open(path / "config.json") as f:
                config_dict = json.load(f)
                self.config.labels = config_dict.get("labels", self.config.labels)
                self.config.attack_labels = config_dict.get("attack_labels", self.config.attack_labels)
        
        if (path / "model.pt").exists():
            state_dict = torch.load(path / "model.pt", map_location=self.device)
            self.model.load_state_dict(state_dict)


# Fallback rule-based classifier when DL is not available
class RuleBasedClassifier:
    """
    Simple rule-based classifier as fallback when DL models aren't trained.
    Uses keyword matching and pattern detection.
    """
    
    PATTERNS = {
        "RSA": ["n =", "e =", "c =", "rsa", "modulus", "public key", "private key", 
                "encrypt", "decrypt", "factorization"],
        "AES": ["aes", "cbc", "ecb", "gcm", "cipher", "iv", "nonce", "block cipher",
                "padding", "encrypt", "decrypt", "key"],
        "XOR": ["xor", "^", "hex", "byte", "single byte", "repeating key"],
        "Classical": ["caesar", "rot13", "vigenere", "substitution", "shift", 
                     "cipher", "frequency", "alphabet"],
        "Hash": ["hash", "md5", "sha", "collision", "digest", "hmac", "bcrypt"],
        "ECC": ["elliptic", "curve", "ecc", "ecdsa", "secp", "generator", "point"],
        "Encoding": ["base64", "base32", "hex", "encode", "decode", "ascii"],
    }
    
    ATTACK_PATTERNS = {
        "small_e_attack": ["e = 3", "small exponent", "e=3", "cube root"],
        "wiener_attack": ["small d", "wiener", "continued fraction", "d is small"],
        "common_modulus": ["same modulus", "common modulus", "two ciphertexts"],
        "padding_oracle": ["padding", "oracle", "cbc", "pkcs"],
        "ecb_detection": ["ecb", "block", "identical", "pattern"],
        "nonce_reuse": ["nonce", "reuse", "iv", "counter"],
        "caesar_bruteforce": ["caesar", "shift", "rot"],
        "xor_single_byte": ["single byte", "xor", "one key byte"],
    }
    
    def classify(self, text: str, files: List[Dict] = None) -> Dict[str, Any]:
        """Classify using pattern matching."""
        # Combine all text
        full_text = text.lower()
        if files:
            for f in files:
                full_text += " " + f.get("content", "").lower()
        
        # Score each type
        type_scores = {}
        for ctype, patterns in self.PATTERNS.items():
            score = sum(1 for p in patterns if p.lower() in full_text)
            type_scores[ctype] = score
        
        # Get best type
        if max(type_scores.values()) == 0:
            challenge_type = "Other"
            confidence = 0.3
        else:
            challenge_type = max(type_scores, key=type_scores.get)
            total = sum(type_scores.values())
            confidence = type_scores[challenge_type] / total if total > 0 else 0.5
        
        # Find attack patterns
        attack_patterns = []
        for attack, patterns in self.ATTACK_PATTERNS.items():
            if any(p.lower() in full_text for p in patterns):
                attack_patterns.append((attack, 0.7))
        
        return {
            "challenge_type": challenge_type,
            "type_confidence": min(confidence, 0.9),
            "all_type_scores": type_scores,
            "attack_patterns": attack_patterns,
            "difficulty": "Medium",
            "difficulty_confidence": 0.5,
            "overall_confidence": min(confidence, 0.9),
            "method": "rule_based"
        }


def get_classifier(model_path: str = None) -> ChallengeClassifier:
    """
    Get a classifier instance, using DL if available, else rule-based.
    """
    if HAS_TRANSFORMERS:
        try:
            return ChallengeClassifier(model_path=model_path)
        except Exception as e:
            print(f"⚠️ Could not load DL classifier: {e}")
            print("📋 Falling back to rule-based classifier")
            return RuleBasedClassifier()
    else:
        print("⚠️ transformers not installed, using rule-based classifier")
        return RuleBasedClassifier()


if __name__ == "__main__":
    print("🧪 Testing Challenge Classifier...")
    
    # Test with rule-based (always works)
    classifier = RuleBasedClassifier()
    
    result = classifier.classify(
        "RSA challenge with small exponent e=3. Decrypt the message.",
        [{"name": "chall.py", "content": "n = 12345\ne = 3\nc = 67890"}]
    )
    
    print(f"✅ Type: {result['challenge_type']}")
    print(f"📊 Confidence: {result['type_confidence']:.2f}")
    print(f"⚔️ Attacks: {result['attack_patterns']}")
    
    # Try DL classifier if available
    if HAS_TRANSFORMERS:
        try:
            dl_classifier = ChallengeClassifier()
            print("\n🧠 Testing DL Classifier...")
            result = dl_classifier.classify(
                "RSA challenge with small exponent e=3",
                [{"name": "chall.py", "content": "n = 12345\ne = 3\nc = 67890"}]
            )
            print(f"✅ Type: {result['challenge_type']}")
            print(f"📊 Confidence: {result['type_confidence']:.2f}")
        except Exception as e:
            print(f"⚠️ DL classifier error: {e}")
