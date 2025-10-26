"""
BERT Training Script
Entrena un modelo BERT fine-tuned para clasificar tipos de crypto.
Entrada: ml_phase2/data/train.csv, ml_phase2/data/label_map.json
Salida: ml_phase2/trained_model/ (modelo guardado)
"""

import json
import torch
import pandas as pd
import numpy as np
from pathlib import Path
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# CONFIGURACIÓN
DATA_DIR = Path("ml_phase2/data")
MODEL_CHECKPOINT = "bert-base-uncased"
OUTPUT_DIR = Path("ml_phase2/model_checkpoints")
FINAL_MODEL_DIR = Path("ml_phase2/trained_model")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
FINAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Parámetros de entrenamiento optimizados para dataset pequeño
EPOCHS = 8  # Más epochs para dataset pequeño
BATCH_SIZE = 4  # Batch size más pequeño
LEARNING_RATE = 3e-5  # Learning rate ligeramente más alto
MAX_LENGTH = 256
SEED = 42
WARMUP_STEPS = 10

# Configurar seeds para reproducibilidad
torch.manual_seed(SEED)
np.random.seed(SEED)

def load_label_map():
    """Carga mapeo de etiquetas"""
    with open(DATA_DIR / "label_map.json", 'r') as f:
        return json.load(f)

def load_datasets():
    """Carga datasets de CSV"""
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    
    print(f"✅ Loaded {len(train_df)} train samples")
    print(f"✅ Loaded {len(test_df)} test samples")
    
    # Mostrar distribución
    print(f"\n📊 Training distribution:")
    train_dist = train_df['type'].value_counts()
    for label, count in train_dist.items():
        print(f"   {label}: {count}")
    
    # Convertir a HuggingFace Dataset
    train_dataset = Dataset.from_dict({
        "text": train_df["text"].tolist(),
        "label": train_df["label"].tolist()
    })
    
    test_dataset = Dataset.from_dict({
        "text": test_df["text"].tolist(),
        "label": test_df["label"].tolist()
    })
    
    return train_dataset, test_dataset

def tokenize_function(examples, tokenizer):
    """Tokeniza texto para BERT"""
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH
    )

def compute_metrics(eval_pred):
    """Calcula métricas de evaluación"""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    
    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='weighted', zero_division=0
    )
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

def print_confusion_matrix(trainer, test_dataset, label_map):
    """Imprime matriz de confusión"""
    predictions = trainer.predict(test_dataset)
    y_pred = np.argmax(predictions.predictions, axis=-1)
    y_true = predictions.label_ids
    
    cm = confusion_matrix(y_true, y_pred)
    
    print("\n📊 Confusion Matrix:")
    print("   ", end="")
    for i in range(len(label_map['id_to_label'])):
        if str(i) in label_map['id_to_label']:
            print(f"{label_map['id_to_label'][str(i)][:3]:>4}", end="")
    print()
    
    for i, row in enumerate(cm):
        if str(i) in label_map['id_to_label']:
            print(f"{label_map['id_to_label'][str(i)][:3]:>3}:", end="")
            for val in row:
                print(f"{val:>4}", end="")
            print()

def main():
    print("🧠 Starting BERT Fine-tuning for Crypto Classification\n")
    
    # Verificar archivos de entrada
    if not (DATA_DIR / "train.csv").exists():
        print("❌ Training data not found. Run prepare_data_for_bert.py first.")
        return 1
    
    # 1. Cargar datos
    print("📂 Loading datasets...")
    train_dataset, test_dataset = load_datasets()
    label_map = load_label_map()
    num_labels = len([k for k in label_map["id_to_label"].keys() if k.isdigit()])
    
    print(f"   Number of labels: {num_labels}")
    print(f"   Labels: {list(label_map['label_to_id'].keys())}\n")
    
    # 2. Tokenizer + Modelo
    print("⚙️  Loading tokenizer and model...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)
        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_CHECKPOINT,
            num_labels=num_labels
        )
        print("   ✅ Model and tokenizer loaded successfully")
    except Exception as e:
        print(f"   ❌ Error loading model: {e}")
        return 1
    
    # 3. Tokenizar datasets
    print("🔤 Tokenizing datasets...")
    try:
        train_dataset = train_dataset.map(
            lambda x: tokenize_function(x, tokenizer),
            batched=True,
            remove_columns=["text"]
        )
        test_dataset = test_dataset.map(
            lambda x: tokenize_function(x, tokenizer),
            batched=True,
            remove_columns=["text"]
        )
        print("   ✅ Tokenization complete")
    except Exception as e:
        print(f"   ❌ Error tokenizing: {e}")
        return 1
    
    # 4. Configurar entrenamiento
    print("⚙️  Configuring training arguments...\n")
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        warmup_steps=WARMUP_STEPS,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model='f1',
        greater_is_better=True,
        logging_steps=5,
        report_to="none",  # Sin WandB
        seed=SEED,
        dataloader_pin_memory=False,  # Para evitar problemas en Windows
        remove_unused_columns=False
    )
    
    # 5. Crear Trainer
    print("🏋️  Creating trainer...")
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
    )
    
    # 6. ENTRENAR
    print("🚀 Training started...\n")
    print(f"   Model: {MODEL_CHECKPOINT}")
    print(f"   Epochs: {EPOCHS}")
    print(f"   Batch Size: {BATCH_SIZE}")
    print(f"   Learning Rate: {LEARNING_RATE}")
    print(f"   Training samples: {len(train_dataset)}")
    print(f"   Test samples: {len(test_dataset)}")
    print()
    
    try:
        trainer.train()
        print("\n✅ Training completed successfully!")
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        return 1
    
    # 7. Evaluar
    print("\n📊 Evaluating on test set...")
    try:
        test_results = trainer.evaluate()
        print(f"   Accuracy: {test_results['eval_accuracy']:.4f}")
        print(f"   F1 Score: {test_results['eval_f1']:.4f}")
        print(f"   Precision: {test_results['eval_precision']:.4f}")
        print(f"   Recall: {test_results['eval_recall']:.4f}")
        
        # Matriz de confusión
        print_confusion_matrix(trainer, test_dataset, label_map)
        
    except Exception as e:
        print(f"   ❌ Evaluation failed: {e}")
        return 1
    
    # 8. Guardar modelo final
    print(f"\n💾 Saving final model to {FINAL_MODEL_DIR}...")
    try:
        trainer.save_model(str(FINAL_MODEL_DIR))
        tokenizer.save_pretrained(str(FINAL_MODEL_DIR))
        
        # Guardar label map al lado del modelo
        with open(FINAL_MODEL_DIR / "label_map.json", 'w') as f:
            json.dump(label_map, f, indent=2)
        
        # Guardar métricas
        metrics = {
            "test_accuracy": test_results['eval_accuracy'],
            "test_f1": test_results['eval_f1'],
            "test_precision": test_results['eval_precision'],
            "test_recall": test_results['eval_recall'],
            "model_checkpoint": MODEL_CHECKPOINT,
            "epochs": EPOCHS,
            "batch_size": BATCH_SIZE,
            "learning_rate": LEARNING_RATE,
            "num_labels": num_labels
        }
        
        with open(FINAL_MODEL_DIR / "training_metrics.json", 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print("   ✅ Model saved successfully")
        
    except Exception as e:
        print(f"   ❌ Error saving model: {e}")
        return 1
    
    print(f"\n🎉 Training complete!")
    print(f"   Model saved to: {FINAL_MODEL_DIR}")
    print(f"   Test Accuracy: {test_results['eval_accuracy']:.1%}")
    print(f"   Ready for integration into agent!")
    
    return 0

if __name__ == "__main__":
    exit(main())