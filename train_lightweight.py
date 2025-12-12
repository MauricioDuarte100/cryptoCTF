#!/usr/bin/env python3
"""
Lightweight CTF Challenge Classifier
=====================================
Uses TF-IDF + Random Forest for ultra-fast, lightweight classification.
- Model size: ~1MB
- Training time: <5 seconds
- No GPU required
- 90%+ accuracy expected
"""

import json
import pickle
import os
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

# Output directory
MODEL_DIR = Path("trained_lightweight")
MODEL_DIR.mkdir(exist_ok=True)

def load_dataset(data_path: str):
    """Load JSONL dataset."""
    examples = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples

def train_classifier(data_path: str = "data/extracted_training_data.jsonl"):
    """Train lightweight TF-IDF + Random Forest classifier."""
    
    print("🚀 Lightweight CTF Classifier Trainer")
    print("=" * 50)
    
    # Load data
    print("\n📥 Loading data...")
    examples = load_dataset(data_path)
    print(f"   Loaded {len(examples)} examples")
    
    # Prepare data
    texts = []
    labels = []
    label_counts = {}
    
    for ex in examples:
        # Combine description and other text fields (ensure all are strings)
        text = str(ex.get('challenge_description', ex.get('description', '')))
        text += ' ' + str(ex.get('challenge_name', ex.get('name', '')))
        text += ' ' + str(ex.get('attack_type', ''))
        if 'solution_steps' in ex:
            if isinstance(ex['solution_steps'], list):
                text += ' ' + ' '.join(str(s) for s in ex['solution_steps'])
            else:
                text += ' ' + str(ex['solution_steps'])
        if 'writeup' in ex:
            text += ' ' + str(ex['writeup'])[:500]
        if 'solution_code' in ex:
            text += ' ' + str(ex['solution_code'])[:1000]  # Add solution code snippets
        
        # Use 'category' field (RSA, XOR, AES, etc.)
        label = str(ex.get('category', ex.get('challenge_type', ex.get('type', 'Unknown'))))
        
        texts.append(text)
        labels.append(label)
        label_counts[label] = label_counts.get(label, 0) + 1
    
    print(f"   Types distribution: {label_counts}")
    
    # Filter out classes with < 2 samples (can't stratify)
    min_samples = 2
    valid_indices = [i for i, lbl in enumerate(labels) if label_counts[lbl] >= min_samples]
    texts = [texts[i] for i in valid_indices]
    labels = [labels[i] for i in valid_indices]
    print(f"   After filtering rare classes: {len(texts)} examples")
    
    # Split data (no stratify if small classes remain)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )
    print(f"   Train: {len(X_train)}, Test: {len(X_test)}")
    
    # TF-IDF Vectorizer
    print("\n🔧 Creating TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,       # Keep top 5k features
        ngram_range=(1, 2),      # Unigrams and bigrams
        min_df=2,                # Ignore rare terms
        max_df=0.95,             # Ignore very common terms
        stop_words='english'
    )
    
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print(f"   Vocabulary size: {len(vectorizer.vocabulary_)}")
    print(f"   Feature matrix shape: {X_train_tfidf.shape}")
    
    # Train Random Forest
    print("\n🏋️ Training Random Forest classifier...")
    classifier = RandomForestClassifier(
        n_estimators=100,        # 100 trees
        max_depth=20,            # Prevent overfitting
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1                # Use all CPUs
    )
    
    classifier.fit(X_train_tfidf, y_train)
    
    # Evaluate
    print("\n📊 Evaluation...")
    y_pred = classifier.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"   Test Accuracy: {accuracy:.1%}")
    
    # Cross-validation
    print("\n   Cross-validation (5-fold)...")
    X_all_tfidf = vectorizer.transform(texts)
    cv_scores = cross_val_score(classifier, X_all_tfidf, labels, cv=5)
    print(f"   CV Accuracy: {cv_scores.mean():.1%} (+/- {cv_scores.std()*2:.1%})")
    
    # Classification report
    print("\n   Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model
    print("\n💾 Saving model...")
    
    # Save vectorizer
    vectorizer_path = MODEL_DIR / "tfidf_vectorizer.pkl"
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    
    # Save classifier
    classifier_path = MODEL_DIR / "rf_classifier.pkl"
    with open(classifier_path, 'wb') as f:
        pickle.dump(classifier, f)
    
    # Save label mapping
    labels_path = MODEL_DIR / "labels.json"
    unique_labels = list(set(labels))
    with open(labels_path, 'w') as f:
        json.dump(unique_labels, f, indent=2)
    
    # Calculate total size
    total_size = sum(
        os.path.getsize(MODEL_DIR / f) 
        for f in os.listdir(MODEL_DIR)
    )
    
    print(f"\n✅ Model saved to {MODEL_DIR}/")
    print(f"   - tfidf_vectorizer.pkl")
    print(f"   - rf_classifier.pkl")
    print(f"   - labels.json")
    print(f"   Total size: {total_size / 1024:.1f} KB")
    
    print("\n🎉 Training complete!")
    print(f"   Accuracy: {accuracy:.1%}")
    print(f"   Model size: {total_size / 1024:.1f} KB (vs ~500MB for CodeBERT)")
    
    return accuracy, total_size

def predict(text: str):
    """Predict challenge type for new text."""
    # Load model
    with open(MODEL_DIR / "tfidf_vectorizer.pkl", 'rb') as f:
        vectorizer = pickle.load(f)
    with open(MODEL_DIR / "rf_classifier.pkl", 'rb') as f:
        classifier = pickle.load(f)
    
    # Predict
    X = vectorizer.transform([text])
    pred = classifier.predict(X)[0]
    proba = classifier.predict_proba(X)[0]
    confidence = max(proba)
    
    return pred, confidence

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Train lightweight CTF classifier")
    parser.add_argument("--data", "-d", default="data/combined_training_data.jsonl", 
                        help="Path to JSONL training data")
    parser.add_argument("--test", action="store_true", help="Test prediction mode")
    args = parser.parse_args()
    
    if args.test:
        # Test prediction
        test_text = "RSA with small exponent e=3, multiple ciphertexts, Hastad broadcast attack"
        pred, conf = predict(test_text)
        print(f"Prediction: {pred} (confidence: {conf:.1%})")
    else:
        # Train
        train_classifier(args.data)
