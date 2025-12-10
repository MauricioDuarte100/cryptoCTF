"""
Training script for Challenge Classifier
Fine-tunes CodeBERT on CTF challenge classification.
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

try:
    import torch
    from torch.utils.data import DataLoader, Dataset
    from transformers import get_linear_schedule_with_warmup
    from tqdm import tqdm
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.dl_models.challenge_classifier import ChallengeClassifier, ClassifierConfig


def load_training_data(data_path: str) -> List[Dict[str, Any]]:
    """
    Load training data from JSONL file.
    
    Expected format per line:
    {
        "description": "RSA challenge...",
        "files": [{"name": "chall.py", "content": "..."}],
        "type": "RSA",
        "attack_pattern": "small_e_attack",
        "difficulty": "Easy"
    }
    """
    data = []
    path = Path(data_path)
    
    if path.suffix == ".jsonl":
        with open(path) as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))
    elif path.suffix == ".json":
        with open(path) as f:
            data = json.load(f)
    
    return data


def prepare_training_examples(data: List[Dict], config: ClassifierConfig) -> List[Dict]:
    """Convert raw data to training examples."""
    examples = []
    
    for item in data:
        # Extract fields
        description = item.get("description", item.get("problem", ""))
        files = item.get("files", [])
        challenge_type = item.get("type", item.get("category", "Other"))
        attack = item.get("attack_pattern", item.get("attack", ""))
        difficulty = item.get("difficulty", "Medium")
        solution = item.get("solution", item.get("solution_code", ""))
        
        # Map challenge type to label index
        if challenge_type in config.labels:
            type_label = config.labels.index(challenge_type)
        else:
            type_label = config.labels.index("Other") if "Other" in config.labels else 0
        
        # Map difficulty to index
        difficulty_map = {"Easy": 0, "Medium": 1, "Hard": 2}
        difficulty_label = difficulty_map.get(difficulty, 1)
        
        # Multi-label attack patterns
        attack_labels = [0] * len(config.attack_labels)
        if attack and attack in config.attack_labels:
            attack_labels[config.attack_labels.index(attack)] = 1
        
        examples.append({
            "description": description,
            "files": files,
            "type_label": type_label,
            "attack_labels": attack_labels,
            "difficulty_label": difficulty_label,
            "solution": solution
        })
    
    return examples


def train_classifier(
    data_path: str,
    output_dir: str = "trained_classifier",
    epochs: int = 5,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
    test_mode: bool = False
) -> Dict[str, Any]:
    """
    Train the challenge classifier.
    
    Args:
        data_path: Path to training data (JSONL or JSON)
        output_dir: Directory to save trained model
        epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate
        test_mode: If True, run only 1 epoch with small data
        
    Returns:
        Dictionary with training metrics
    """
    if not HAS_TORCH:
        raise ImportError("PyTorch required. Run: pip install torch")
    
    print("🚀 Starting Challenge Classifier Training")
    print(f"   Data: {data_path}")
    print(f"   Output: {output_dir}")
    print(f"   Epochs: {epochs}")
    
    # Load data
    print("\n📥 Loading training data...")
    raw_data = load_training_data(data_path)
    print(f"   Loaded {len(raw_data)} examples")
    
    if test_mode:
        raw_data = raw_data[:50]
        epochs = 1
        print("   ⚠️ Test mode: using 50 examples, 1 epoch")
    
    # Initialize classifier with config
    config = ClassifierConfig(
        num_epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate
    )
    
    # Prepare examples
    print("\n🔄 Preparing training examples...")
    examples = prepare_training_examples(raw_data, config)
    print(f"   Prepared {len(examples)} examples")
    
    # Count types
    type_counts = {}
    for ex in examples:
        t = config.labels[ex["type_label"]]
        type_counts[t] = type_counts.get(t, 0) + 1
    print(f"   Types: {type_counts}")
    
    # Initialize classifier
    print("\n🧠 Initializing classifier...")
    classifier = ChallengeClassifier(config)
    
    # Train using HuggingFace Trainer
    print("\n📊 Starting training...")
    training_data = [
        {
            "description": ex["description"],
            "files": ex["files"],
            "type": config.labels[ex["type_label"]]
        }
        for ex in examples
    ]
    
    classifier.train(training_data, output_dir)
    
    print(f"\n✅ Training complete! Model saved to: {output_dir}")
    
    # Quick evaluation
    print("\n🧪 Running quick evaluation...")
    correct = 0
    total = min(10, len(examples))
    
    for ex in examples[:total]:
        result = classifier.classify(ex["description"], ex["files"])
        predicted = result["challenge_type"]
        actual = config.labels[ex["type_label"]]
        if predicted == actual:
            correct += 1
    
    accuracy = correct / total
    print(f"   Quick eval accuracy: {accuracy:.1%} ({correct}/{total})")
    
    return {
        "output_dir": output_dir,
        "epochs": epochs,
        "examples": len(examples),
        "accuracy": accuracy,
        "type_distribution": type_counts
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CTF Challenge Classifier")
    parser.add_argument("--data", "-d", required=True, help="Path to training data")
    parser.add_argument("--output", "-o", default="trained_classifier", help="Output directory")
    parser.add_argument("--epochs", "-e", type=int, default=5, help="Training epochs")
    parser.add_argument("--batch-size", "-b", type=int, default=8, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--test", action="store_true", help="Test mode (small data, 1 epoch)")
    
    args = parser.parse_args()
    
    result = train_classifier(
        data_path=args.data,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        test_mode=args.test
    )
    
    print("\n📋 Final Results:")
    print(f"   Model: {result['output_dir']}")
    print(f"   Accuracy: {result['accuracy']:.1%}")
