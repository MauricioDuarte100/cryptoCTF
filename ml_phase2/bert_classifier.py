"""
BERT Crypto Classifier
Este módulo encapsula el modelo BERT entrenado.
Lo hace compatible con el agente sin cambiar la interfaz existente.
"""

import json
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import warnings
warnings.filterwarnings('ignore')

class BERTCryptoClassifier:
    """Clasificador BERT para tipos de crypto CTF"""
    
    def __init__(self, model_dir="ml_phase2/trained_model", use_gpu=False):
        """
        Inicializa el clasificador.
        
        Args:
            model_dir: Ruta al modelo entrenado
            use_gpu: Si usar GPU (si disponible)
        """
        self.model_dir = Path(model_dir)
        self.device = torch.device("cuda" if use_gpu and torch.cuda.is_available() else "cpu")
        
        print(f"🧠 Loading BERT classifier from {self.model_dir}")
        print(f"   Device: {self.device}")
        
        try:
            # Cargar modelo + tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir))
            self.model = AutoModelForSequenceClassification.from_pretrained(str(self.model_dir))
            self.model.to(self.device)
            self.model.eval()
            
            # Cargar label map
            with open(self.model_dir / "label_map.json", 'r') as f:
                label_data = json.load(f)
                self.id_to_label = label_data["id_to_label"]
                self.label_to_id = label_data["label_to_id"]
            
            # Cargar métricas de entrenamiento
            metrics_file = self.model_dir / "training_metrics.json"
            if metrics_file.exists():
                with open(metrics_file, 'r') as f:
                    self.training_metrics = json.load(f)
                    print(f"   Training accuracy: {self.training_metrics.get('test_accuracy', 'N/A'):.1%}")
            else:
                self.training_metrics = {}
            
            print(f"   ✅ BERT classifier loaded successfully")
            print(f"   Labels: {list(self.label_to_id.keys())}")
            
        except Exception as e:
            print(f"   ❌ Error loading BERT classifier: {e}")
            raise
    
    def classify(self, text: str, return_all_scores=False) -> dict:
        """
        Clasifica texto y retorna tipo de crypto + confianza.
        
        Args:
            text: Contenido del challenge
            return_all_scores: Si retornar scores para todas las clases
        
        Returns:
            {
                "type": "RSA",
                "confidence": 0.95,
                "all_scores": {...}  # si return_all_scores=True
            }
        """
        try:
            # Tokenizar
            inputs = self.tokenizer(
                text,
                padding="max_length",
                truncation=True,
                max_length=256,
                return_tensors="pt"
            )
            
            # Mover a device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Predict
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)[0]
            
            # Obtener predicción
            predicted_idx = torch.argmax(probs).item()
            predicted_type = self.id_to_label[str(predicted_idx)]
            confidence = probs[predicted_idx].item()
            
            result = {
                "type": predicted_type,
                "confidence": confidence
            }
            
            if return_all_scores:
                result["all_scores"] = {
                    label: probs[int(label_id)].item()
                    for label, label_id in self.label_to_id.items()
                    if str(label_id) in self.id_to_label  # Solo labels válidos
                }
            
            return result
            
        except Exception as e:
            return {
                "type": "Unknown",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def classify_batch(self, texts: list) -> list:
        """
        Clasifica múltiples textos de una vez (más eficiente).
        
        Args:
            texts: Lista de textos a clasificar
        
        Returns:
            Lista de resultados de clasificación
        """
        results = []
        
        try:
            # Tokenizar batch
            inputs = self.tokenizer(
                texts,
                padding="max_length",
                truncation=True,
                max_length=256,
                return_tensors="pt"
            )
            
            # Mover a device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Predict batch
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
            
            # Procesar cada resultado
            for i in range(len(texts)):
                predicted_idx = torch.argmax(probs[i]).item()
                predicted_type = self.id_to_label[str(predicted_idx)]
                confidence = probs[i][predicted_idx].item()
                
                results.append({
                    "type": predicted_type,
                    "confidence": confidence
                })
            
            return results
            
        except Exception as e:
            # Fallback a clasificación individual
            return [self.classify(text) for text in texts]
    
    def get_model_info(self) -> dict:
        """
        Retorna información sobre el modelo cargado.
        """
        return {
            "model_path": str(self.model_dir),
            "device": str(self.device),
            "labels": list(self.label_to_id.keys()),
            "num_labels": len(self.label_to_id),
            "training_metrics": self.training_metrics
        }

# Instancia global (se carga una sola vez)
try:
    bert_classifier = BERTCryptoClassifier(use_gpu=False)
    BERT_AVAILABLE = True
    print(f"🎉 BERT classifier ready! Training accuracy: {bert_classifier.training_metrics.get('test_accuracy', 'N/A'):.1%}")
except Exception as e:
    print(f"⚠️  BERT classifier not available: {e}")
    bert_classifier = None
    BERT_AVAILABLE = False

# Función de conveniencia
def classify_crypto_with_bert(text: str) -> dict:
    """
    Función de conveniencia para clasificar con BERT.
    
    Args:
        text: Texto a clasificar
    
    Returns:
        Resultado de clasificación o error si BERT no disponible
    """
    if not BERT_AVAILABLE:
        return {
            "type": "Unknown",
            "confidence": 0.0,
            "error": "BERT classifier not available"
        }
    
    return bert_classifier.classify(text, return_all_scores=True)