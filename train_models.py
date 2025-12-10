"""
Standalone Training Script for CTF Deep Learning Models
Runs without requiring langgraph or other optional dependencies.
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field

print("🚀 CTF Deep Learning Trainer")
print("=" * 50)

# Check dependencies
try:
    import torch
    import torch.nn as nn
    print(f"✅ PyTorch {torch.__version__}")
except ImportError:
    print("❌ PyTorch not installed. Run: pip install torch")
    exit(1)

try:
    from transformers import AutoTokenizer, AutoModel
    print("✅ Transformers available")
    HAS_TRANSFORMERS = True
except ImportError:
    print("⚠️ Transformers not installed - using rule-based classifier")
    HAS_TRANSFORMERS = False

try:
    from sentence_transformers import SentenceTransformer
    print("✅ Sentence-Transformers available")
    HAS_ST = True
except ImportError:
    print("⚠️ Sentence-Transformers not installed")
    HAS_ST = False

print("=" * 50)


@dataclass
class ClassifierConfig:
    """Configuration for classifier."""
    model_name: str = "microsoft/codebert-base"
    num_labels: int = 8
    max_length: int = 512
    batch_size: int = 8
    num_epochs: int = 5
    learning_rate: float = 2e-5
    
    labels: List[str] = field(default_factory=lambda: [
        "RSA", "XOR", "AES", "Classical", "Hash", "ECC", "Encoding", "Other"
    ])


def load_jsonl(path: str) -> List[Dict]:
    """Load JSONL file."""
    data = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return data


def prepare_examples(data: List[Dict], config: ClassifierConfig) -> List[Dict]:
    """Prepare training examples."""
    examples = []
    
    for item in data:
        desc = item.get("description", item.get("problem", item.get("challenge_description", "")))
        # Use attack_type (RSA, XOR, Hash, etc.) - the 'type' field contains 'crypto' for all
        ctype = item.get("attack_type", item.get("category", "Unknown"))

        
        # Map to label index
        if ctype in config.labels:
            label = config.labels.index(ctype)
        else:
            label = config.labels.index("Other")
        
        examples.append({
            "text": desc[:config.max_length],
            "label": label,
            "type_name": ctype
        })
    
    return examples


class SimpleClassifier(nn.Module):
    """Simple classifier without transformers."""
    
    def __init__(self, vocab_size: int = 10000, embed_dim: int = 128, 
                 hidden_dim: int = 64, num_labels: int = 8):
        super().__init__()
        self.embedding = nn.EmbeddingBag(vocab_size, embed_dim, sparse=False)
        self.fc = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, num_labels)
        )
    
    def forward(self, x):
        embedded = self.embedding(x)
        return self.fc(embedded)


def train_simple(data_path: str, output_dir: str, epochs: int = 5, test_mode: bool = False):
    """Train simple classifier without transformers."""
    print("\n📥 Loading data...")
    raw_data = load_jsonl(data_path)
    print(f"   Loaded {len(raw_data)} examples")
    
    if test_mode:
        raw_data = raw_data[:100]
        epochs = 2
        print(f"   ⚠️ Test mode: {len(raw_data)} examples, {epochs} epochs")
    
    config = ClassifierConfig(num_epochs=epochs)
    examples = prepare_examples(raw_data, config)
    
    # Count types
    type_counts = {}
    for ex in examples:
        t = ex["type_name"]
        type_counts[t] = type_counts.get(t, 0) + 1
    print(f"   Types: {type_counts}")
    
    # Build vocabulary
    print("\n🔤 Building vocabulary...")
    vocab = {"<PAD>": 0, "<UNK>": 1}
    for ex in examples:
        for word in ex["text"].lower().split():
            if word not in vocab and len(vocab) < 10000:
                vocab[word] = len(vocab)
    print(f"   Vocabulary size: {len(vocab)}")
    
    # Prepare tensors
    def text_to_tensor(text):
        indices = [vocab.get(w, 1) for w in text.lower().split()[:100]]
        if not indices:
            indices = [0]
        return torch.tensor(indices, dtype=torch.long)
    
    # Simple training
    print("\n🏋️ Training simple classifier...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"   Device: {device}")
    
    model = SimpleClassifier(vocab_size=len(vocab), num_labels=len(config.labels))
    model.to(device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.CrossEntropyLoss()
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct = 0
        
        for i, ex in enumerate(examples):
            x = text_to_tensor(ex["text"]).unsqueeze(0).to(device)
            y = torch.tensor([ex["label"]], dtype=torch.long).to(device)
            
            optimizer.zero_grad()
            logits = model(x)
            loss = criterion(logits, y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            pred = logits.argmax(dim=1).item()
            if pred == ex["label"]:
                correct += 1
            
            if (i + 1) % 100 == 0:
                print(f"      Epoch {epoch+1}/{epochs}, Step {i+1}/{len(examples)}, Loss: {loss.item():.4f}")
        
        acc = correct / len(examples)
        avg_loss = total_loss / len(examples)
        print(f"   Epoch {epoch+1}: Loss={avg_loss:.4f}, Accuracy={acc:.1%}")
    
    # Save model
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    torch.save({
        "model_state_dict": model.state_dict(),
        "vocab": vocab,
        "config": {
            "labels": config.labels,
            "vocab_size": len(vocab)
        }
    }, output_path / "simple_classifier.pt")
    
    print(f"\n✅ Model saved to {output_path / 'simple_classifier.pt'}")
    
    return {
        "output_dir": output_dir,
        "epochs": epochs,
        "examples": len(examples),
        "accuracy": acc,
        "type_distribution": type_counts
    }


def train_transformer(data_path: str, output_dir: str, epochs: int = 3, test_mode: bool = False):
    """Train transformer-based classifier."""
    if not HAS_TRANSFORMERS:
        print("❌ Transformers not available, using simple classifier")
        return train_simple(data_path, output_dir, epochs, test_mode)
    
    print("\n📥 Loading data...")
    raw_data = load_jsonl(data_path)
    print(f"   Loaded {len(raw_data)} examples")
    
    if test_mode:
        raw_data = raw_data[:50]
        epochs = 1
        print(f"   ⚠️ Test mode: {len(raw_data)} examples, {epochs} epochs")
    
    config = ClassifierConfig(num_epochs=epochs)
    examples = prepare_examples(raw_data, config)
    
    # Count types
    type_counts = {}
    for ex in examples:
        t = ex["type_name"]
        type_counts[t] = type_counts.get(t, 0) + 1
    print(f"   Types: {type_counts}")
    
    print("\n🧠 Loading tokenizer and model...")
    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
    encoder = AutoModel.from_pretrained(config.model_name)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"   Device: {device}")
    
    # Classifier head
    classifier = nn.Linear(encoder.config.hidden_size, len(config.labels))
    
    encoder.to(device)
    classifier.to(device)
    
    optimizer = torch.optim.AdamW(
        list(encoder.parameters()) + list(classifier.parameters()),
        lr=config.learning_rate
    )
    criterion = nn.CrossEntropyLoss()
    
    print(f"\n🏋️ Training for {epochs} epochs...")
    
    for epoch in range(epochs):
        encoder.train()
        classifier.train()
        total_loss = 0
        correct = 0
        
        for i, ex in enumerate(examples):
            inputs = tokenizer(
                ex["text"],
                max_length=config.max_length,
                truncation=True,
                padding="max_length",
                return_tensors="pt"
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}
            label = torch.tensor([ex["label"]], dtype=torch.long).to(device)
            
            optimizer.zero_grad()
            
            outputs = encoder(**inputs)
            cls_repr = outputs.last_hidden_state[:, 0, :]
            logits = classifier(cls_repr)
            
            loss = criterion(logits, label)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            pred = logits.argmax(dim=1).item()
            if pred == ex["label"]:
                correct += 1
            
            if (i + 1) % 20 == 0:
                print(f"      Step {i+1}/{len(examples)}, Loss: {loss.item():.4f}")
        
        acc = correct / len(examples)
        avg_loss = total_loss / len(examples)
        print(f"   Epoch {epoch+1}: Loss={avg_loss:.4f}, Accuracy={acc:.1%}")
    
    # Save
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    encoder.save_pretrained(output_path / "encoder")
    tokenizer.save_pretrained(output_path / "encoder")
    torch.save(classifier.state_dict(), output_path / "classifier_head.pt")
    
    with open(output_path / "config.json", "w") as f:
        json.dump({"labels": config.labels}, f, indent=2)
    
    print(f"\n✅ Model saved to {output_path}")
    
    return {
        "output_dir": output_dir,
        "epochs": epochs,
        "examples": len(examples),
        "accuracy": acc,
        "type_distribution": type_counts
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CTF Classifier")
    parser.add_argument("--data", "-d", required=True, help="Path to training data (JSONL)")
    parser.add_argument("--output", "-o", default="trained_model", help="Output directory")
    parser.add_argument("--epochs", "-e", type=int, default=5, help="Epochs")
    parser.add_argument("--test", action="store_true", help="Quick test mode")
    parser.add_argument("--simple", action="store_true", help="Use simple classifier (no transformers)")
    
    args = parser.parse_args()
    
    if args.simple or not HAS_TRANSFORMERS:
        result = train_simple(
            data_path=args.data,
            output_dir=args.output,
            epochs=args.epochs,
            test_mode=args.test
        )
    else:
        result = train_transformer(
            data_path=args.data,
            output_dir=args.output,
            epochs=args.epochs,
            test_mode=args.test
        )
    
    print("\n" + "=" * 50)
    print("📋 TRAINING COMPLETE")
    print("=" * 50)
    print(f"   Output: {result['output_dir']}")
    print(f"   Examples: {result['examples']}")
    print(f"   Final Accuracy: {result['accuracy']:.1%}")
    print(f"   Type Distribution: {result['type_distribution']}")
