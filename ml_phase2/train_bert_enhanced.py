#!/usr/bin/env python3
"""
ENHANCED BERT Training Script
Entrena BERT con el dataset mejorado de writeups reales
"""

import json
import torch
import pandas as pd
import numpy as np
import argparse
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

class BERTTrainer:
    def __init__(self, train_file, test_file, model_name="bert-base-uncased", output_dir="ml_phase2/trained_model_real"):
        self.train_file = Path(train_file)
        self.test_file = Path(test_file)
        self.model_name = model_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Parámetros de entrenamiento optimizados
        self.epochs = 5
        self.batch_size = 8
        self.learning_rate = 2e-5
        self.max_length = 512
        self.warmup_steps = 100
        
        # Configurar seeds
        torch.manual_seed(42)
        np.random.seed(42)
        
        # Cargar label map
        self.label_map = self.load_label_map()
        self.num_labels = self.label_map['num_labels']
        self.id_to_label = self.label_map['id_to_label']
        
        print(f"🏷️ Loaded {self.num_labels} labels: {list(self.label_map['label_to_id'].keys())}")

    def load_label_map(self):
        """Carga mapeo de etiquetas"""
        label_map_file = self.train_file.parent / "label_map.json"
        
        if not label_map_file.exists():
            raise FileNotFoundError(f"Label map not found: {label_map_file}")
        
        with open(label_map_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_datasets(self):
        """Carga datasets de entrenamiento y prueba"""
        print("📂 Loading datasets...")
        
        # Cargar datos de entrenamiento
        train_df = pd.read_csv(self.train_file)
        print(f"✅ Loaded {len(train_df)} train samples")
        
        # Cargar datos de prueba
        test_df = pd.read_csv(self.test_file)
        print(f"✅ Loaded {len(test_df)} test samples")
        
        # Mostrar distribución
        print(f"\n📊 Training distribution:")
        train_dist = train_df['label'].value_counts().sort_index()
        for label_id, count in train_dist.items():
            attack_type = self.id_to_label[str(label_id)]
            print(f"    {attack_type}: {count} samples")
        
        print(f"\n📊 Test distribution:")
        test_dist = test_df['label'].value_counts().sort_index()
        for label_id, count in test_dist.items():
            attack_type = self.id_to_label[str(label_id)]
            print(f"    {attack_type}: {count} samples")
        
        # Convertir a datasets de HuggingFace
        train_dataset = Dataset.from_pandas(train_df)
        test_dataset = Dataset.from_pandas(test_df)
        
        return train_dataset, test_dataset

    def tokenize_function(self, examples):
        """Tokeniza los textos"""
        return self.tokenizer(
            examples['text'],
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt"
        )

    def prepare_datasets(self, train_dataset, test_dataset):
        """Prepara datasets tokenizados"""
        print("🔧 Tokenizing datasets...")
        
        # Inicializar tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        
        # Tokenizar datasets
        train_tokenized = train_dataset.map(self.tokenize_function, batched=True)
        test_tokenized = test_dataset.map(self.tokenize_function, batched=True)
        
        # Configurar formato para PyTorch
        train_tokenized.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
        test_tokenized.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
        
        print(f"✅ Tokenized {len(train_tokenized)} train samples")
        print(f"✅ Tokenized {len(test_tokenized)} test samples")
        
        return train_tokenized, test_tokenized

    def compute_metrics(self, eval_pred):
        """Calcula métricas de evaluación"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        # Calcular métricas
        accuracy = accuracy_score(labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='weighted')
        
        return {
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }

    def train_model(self, train_dataset, test_dataset):
        """Entrena el modelo BERT"""
        print(f"🚀 Starting BERT training...")
        print(f"📊 Model: {self.model_name}")
        print(f"📊 Epochs: {self.epochs}")
        print(f"📊 Batch size: {self.batch_size}")
        print(f"📊 Learning rate: {self.learning_rate}")
        print(f"📊 Max length: {self.max_length}")
        
        # Inicializar modelo
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=self.num_labels,
            id2label=self.id_to_label,
            label2id=self.label_map['label_to_id']
        )
        
        # Configurar argumentos de entrenamiento
        training_args = TrainingArguments(
            output_dir=str(self.output_dir / "checkpoints"),
            num_train_epochs=self.epochs,
            per_device_train_batch_size=self.batch_size,
            per_device_eval_batch_size=self.batch_size,
            warmup_steps=self.warmup_steps,
            weight_decay=0.01,
            learning_rate=self.learning_rate,
            logging_dir=str(self.output_dir / "logs"),
            logging_steps=10,
            eval_strategy="epoch",  # Cambio de evaluation_strategy a eval_strategy
            save_strategy="epoch",
            save_total_limit=2,
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            greater_is_better=True,
            report_to=None,  # Disable wandb
            seed=42
        )
        
        # Inicializar trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset,
            tokenizer=self.tokenizer,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
        )
        
        # Entrenar modelo
        print("\n🔥 Training started...")
        train_result = trainer.train()
        
        # Evaluar modelo
        print("\n📊 Evaluating model...")
        eval_result = trainer.evaluate()
        
        # Mostrar resultados
        print(f"\n🎉 Training completed!")
        print(f"📈 Final accuracy: {eval_result['eval_accuracy']:.4f}")
        print(f"📈 Final F1 score: {eval_result['eval_f1']:.4f}")
        print(f"📈 Final precision: {eval_result['eval_precision']:.4f}")
        print(f"📈 Final recall: {eval_result['eval_recall']:.4f}")
        
        # Guardar modelo final
        print(f"\n💾 Saving model to {self.output_dir}")
        trainer.save_model(str(self.output_dir))
        self.tokenizer.save_pretrained(str(self.output_dir))
        
        # Guardar métricas
        metrics = {
            'train_loss': train_result.training_loss,
            'eval_accuracy': eval_result['eval_accuracy'],
            'eval_f1': eval_result['eval_f1'],
            'eval_precision': eval_result['eval_precision'],
            'eval_recall': eval_result['eval_recall'],
            'num_train_epochs': self.epochs,
            'total_train_samples': len(train_dataset),
            'total_eval_samples': len(test_dataset)
        }
        
        with open(self.output_dir / "training_metrics.json", 'w') as f:
            json.dump(metrics, f, indent=2)
        
        return trainer, eval_result

    def generate_detailed_evaluation(self, trainer, test_dataset):
        """Genera evaluación detallada con matriz de confusión"""
        print("\n📊 Generating detailed evaluation...")
        
        # Hacer predicciones
        predictions = trainer.predict(test_dataset)
        y_pred = np.argmax(predictions.predictions, axis=1)
        y_true = predictions.label_ids
        
        # Matriz de confusión
        cm = confusion_matrix(y_true, y_pred)
        
        # Métricas por clase
        precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, average=None)
        
        # Crear reporte detallado
        report = {
            'overall_accuracy': accuracy_score(y_true, y_pred),
            'confusion_matrix': cm.tolist(),
            'per_class_metrics': {}
        }
        
        print(f"\n🎯 DETAILED EVALUATION RESULTS:")
        print(f"Overall Accuracy: {report['overall_accuracy']:.4f}")
        print(f"\nPer-class metrics:")
        
        for i in range(self.num_labels):
            if i < len(precision):
                attack_type = self.id_to_label[str(i)]
                report['per_class_metrics'][attack_type] = {
                    'precision': float(precision[i]) if not np.isnan(precision[i]) else 0.0,
                    'recall': float(recall[i]) if not np.isnan(recall[i]) else 0.0,
                    'f1': float(f1[i]) if not np.isnan(f1[i]) else 0.0,
                    'support': int(support[i])
                }
                
                print(f"  {attack_type}:")
                print(f"    Precision: {report['per_class_metrics'][attack_type]['precision']:.4f}")
                print(f"    Recall: {report['per_class_metrics'][attack_type]['recall']:.4f}")
                print(f"    F1: {report['per_class_metrics'][attack_type]['f1']:.4f}")
                print(f"    Support: {report['per_class_metrics'][attack_type]['support']}")
        
        # Guardar reporte
        with open(self.output_dir / "detailed_evaluation.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

    def validate_model(self):
        """Valida que el modelo se guardó correctamente"""
        print(f"\n✅ VALIDATION RESULTS:")
        
        required_files = [
            "config.json",
            "tokenizer_config.json",
            "vocab.txt",
            "training_metrics.json"
        ]
        
        # Verificar si existe pytorch_model.bin o model.safetensors
        model_files = ["pytorch_model.bin", "model.safetensors"]
        model_exists = any((self.output_dir / f).exists() for f in model_files)
        
        all_exist = True
        for file in required_files:
            file_path = self.output_dir / file
            exists = file_path.exists()
            print(f"📁 {file}: {'✅' if exists else '❌'}")
            if not exists:
                all_exist = False
        
        # Verificar archivo del modelo
        print(f"📁 Model file: {'✅' if model_exists else '❌'}")
        if not model_exists:
            all_exist = False
        
        # Verificar tamaño del modelo
        for model_file_name in model_files:
            model_file = self.output_dir / model_file_name
            if model_file.exists():
                size_mb = model_file.stat().st_size / (1024 * 1024)
                print(f"📊 Model size ({model_file_name}): {size_mb:.1f} MB")
                break
        
        print(f"✅ Model validation: {'PASSED' if all_exist else 'FAILED'}")
        return all_exist

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Train BERT on enhanced CTF writeups dataset')
    parser.add_argument('--train-file', default='ml_phase2/data/train.csv',
                       help='Training CSV file')
    parser.add_argument('--test-file', default='ml_phase2/data/test.csv',
                       help='Test CSV file')
    parser.add_argument('--model', default='bert-base-uncased',
                       help='Pre-trained model name')
    parser.add_argument('--output-dir', default='ml_phase2/trained_model_real',
                       help='Output directory for trained model')
    parser.add_argument('--epochs', type=int, default=5,
                       help='Number of training epochs')
    parser.add_argument('--batch-size', type=int, default=8,
                       help='Training batch size')
    parser.add_argument('--learning-rate', type=float, default=2e-5,
                       help='Learning rate')
    
    args = parser.parse_args()
    
    print("🔥 PHASE 3.0 - STEP 3: BERT TRAINING WITH REAL DATA")
    print("Training BERT classifier on enhanced CTF writeups dataset")
    print("=" * 70)
    
    # Inicializar trainer
    bert_trainer = BERTTrainer(
        train_file=args.train_file,
        test_file=args.test_file,
        model_name=args.model,
        output_dir=args.output_dir
    )
    
    # Configurar parámetros
    bert_trainer.epochs = args.epochs
    bert_trainer.batch_size = args.batch_size
    bert_trainer.learning_rate = args.learning_rate
    
    # Cargar datasets
    train_dataset, test_dataset = bert_trainer.load_datasets()
    
    # Preparar datasets tokenizados
    train_tokenized, test_tokenized = bert_trainer.prepare_datasets(train_dataset, test_dataset)
    
    # Entrenar modelo
    trainer, eval_result = bert_trainer.train_model(train_tokenized, test_tokenized)
    
    # Evaluación detallada
    detailed_report = bert_trainer.generate_detailed_evaluation(trainer, test_tokenized)
    
    # Validar modelo guardado
    success = bert_trainer.validate_model()
    
    print("\n" + "=" * 70)
    print("🎉 BERT TRAINING COMPLETED!")
    print(f"📊 Final accuracy: {eval_result['eval_accuracy']:.4f}")
    print(f"📁 Model saved to: {args.output_dir}")
    print(f"✅ Training successful: {'YES' if success else 'NO'}")
    
    if success and eval_result['eval_accuracy'] >= 0.85:
        print("\n🚀 NEXT STEPS:")
        print("1. python rag/prepare_embeddings.py --writeups data/writeups_enhanced_dataset.jsonl")
        print("2. Update multi-agent system to use new model")
        print("3. Create Next.js frontend")
    elif success:
        print(f"\n⚠️ Model accuracy ({eval_result['eval_accuracy']:.4f}) is below 85%")
        print("Consider training for more epochs or adjusting hyperparameters")
    
    return success and eval_result['eval_accuracy'] >= 0.80

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)