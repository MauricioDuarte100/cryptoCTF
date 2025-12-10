"""
Training script for Attack Predictor
Trains LSTM-based sequence model on solution patterns.
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    from tqdm import tqdm
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.dl_models.attack_predictor import AttackPredictor, PredictorConfig


class AttackSequenceDataset(Dataset):
    """Dataset for attack sequence training."""
    
    def __init__(self, examples: List[Dict], config: PredictorConfig, embedder):
        self.examples = examples
        self.config = config
        self.embedder = embedder
        
        # Build attack vocabulary
        self.attack_to_idx = {a: i for i, a in enumerate(config.attacks)}
        self.start_idx = self.attack_to_idx["<START>"]
        self.end_idx = self.attack_to_idx["<END>"]
        self.pad_idx = self.attack_to_idx["<PAD>"]
    
    def __len__(self):
        return len(self.examples)
    
    def __getitem__(self, idx):
        ex = self.examples[idx]
        
        # Get challenge embedding
        text = ex["description"]
        if ex.get("files"):
            for f in ex["files"]:
                text += f"\n{f.get('content', '')[:500]}"
        
        embedding = self.embedder.encode(text, convert_to_tensor=True)
        
        # Convert attack sequence to indices
        attacks = ex.get("solution_steps", [])
        attack_indices = [self.start_idx]
        
        for attack in attacks:
            if attack in self.attack_to_idx:
                attack_indices.append(self.attack_to_idx[attack])
        
        attack_indices.append(self.end_idx)
        
        # Pad sequence
        max_len = self.config.max_sequence_length + 2  # +2 for START/END
        if len(attack_indices) < max_len:
            attack_indices += [self.pad_idx] * (max_len - len(attack_indices))
        else:
            attack_indices = attack_indices[:max_len]
            attack_indices[-1] = self.end_idx
        
        return {
            "embedding": embedding,
            "sequence": torch.tensor(attack_indices[:-1], dtype=torch.long),  # Input
            "target": torch.tensor(attack_indices[1:], dtype=torch.long),  # Output
            "success": torch.tensor(1.0 if ex.get("successful", True) else 0.0)
        }


def load_training_data(data_path: str) -> List[Dict[str, Any]]:
    """Load training data from JSONL file."""
    data = []
    path = Path(data_path)
    
    if path.suffix == ".jsonl":
        with open(path, encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    elif path.suffix == ".json":
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    
    # Filter for examples with solution steps
    data = [d for d in data if d.get("solution_steps") or d.get("attack_pattern")]
    
    # Convert attack_pattern to solution_steps if needed
    for d in data:
        if not d.get("solution_steps") and d.get("attack_pattern"):
            d["solution_steps"] = [d["attack_pattern"]]
    
    return data


def train_predictor(
    data_path: str,
    output_dir: str = "trained_predictor",
    epochs: int = 10,
    batch_size: int = 16,
    learning_rate: float = 1e-3,
    test_mode: bool = False
) -> Dict[str, Any]:
    """
    Train the attack predictor.
    
    Args:
        data_path: Path to training data
        output_dir: Output directory
        epochs: Training epochs
        batch_size: Batch size
        learning_rate: Learning rate
        test_mode: Quick test mode
        
    Returns:
        Training metrics
    """
    if not HAS_TORCH:
        raise ImportError("PyTorch required")
    if not HAS_SENTENCE_TRANSFORMERS:
        raise ImportError("sentence-transformers required")
    
    print("🚀 Starting Attack Predictor Training")
    print(f"   Data: {data_path}")
    print(f"   Output: {output_dir}")
    print(f"   Epochs: {epochs}")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"   Device: {device}")
    
    # Load data
    print("\n📥 Loading training data...")
    raw_data = load_training_data(data_path)
    print(f"   Loaded {len(raw_data)} examples with solution steps")
    
    if test_mode:
        raw_data = raw_data[:30]
        epochs = 2
        print("   ⚠️ Test mode: using 30 examples, 2 epochs")
    
    if len(raw_data) < 1:
        print("❌ Not enough training data (need at least 1 examples)")
        return {"error": "insufficient_data"}
    
    # Initialize embedder
    print("\n🔄 Loading sentence transformer...")
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    
    # Initialize config and model
    config = PredictorConfig()
    predictor = AttackPredictor(config)
    model = predictor.model.to(device)
    
    # Create dataset
    print("\n📊 Preparing dataset...")
    dataset = AttackSequenceDataset(raw_data, config, embedder)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    # Training setup
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss(ignore_index=config.attacks.index("<PAD>"))
    success_criterion = nn.BCELoss()
    
    # Training loop
    print("\n🏋️ Training...")
    history = []
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        num_batches = 0
        
        progress = tqdm(dataloader, desc=f"Epoch {epoch+1}/{epochs}")
        for batch in progress:
            embedding = batch["embedding"].to(device)
            sequence = batch["sequence"].to(device)
            target = batch["target"].to(device)
            success = batch["success"].to(device)
            
            optimizer.zero_grad()
            
            # Forward pass
            logits, success_pred = model(embedding, sequence)
            
            # Compute losses
            logits_flat = logits.view(-1, len(config.attacks))
            target_flat = target.view(-1)
            
            seq_loss = criterion(logits_flat, target_flat)
            success_loss = success_criterion(success_pred, success)
            
            loss = seq_loss + 0.1 * success_loss
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            num_batches += 1
            
            progress.set_postfix({"loss": loss.item()})
        
        avg_loss = total_loss / num_batches
        history.append(avg_loss)
        print(f"   Epoch {epoch+1}: Loss = {avg_loss:.4f}")
    
    # Save model
    print(f"\n💾 Saving model to {output_dir}...")
    predictor.save(output_dir)
    
    print("\n✅ Training complete!")
    
    return {
        "output_dir": output_dir,
        "epochs": epochs,
        "examples": len(raw_data),
        "final_loss": history[-1] if history else 0,
        "loss_history": history
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CTF Attack Predictor")
    parser.add_argument("--data", "-d", required=True, help="Path to training data")
    parser.add_argument("--output", "-o", default="trained_predictor", help="Output directory")
    parser.add_argument("--epochs", "-e", type=int, default=10, help="Training epochs")
    parser.add_argument("--batch-size", "-b", type=int, default=16, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--test", action="store_true", help="Test mode")
    
    args = parser.parse_args()
    
    result = train_predictor(
        data_path=args.data,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        test_mode=args.test
    )
    
    print("\n📋 Final Results:")
    print(f"   Model: {result.get('output_dir', 'N/A')}")
    print(f"   Final Loss: {result.get('final_loss', 'N/A'):.4f}")
