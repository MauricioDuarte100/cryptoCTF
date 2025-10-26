#!/usr/bin/env python3
"""
ENHANCED BERT Crypto Classifier
Clasificador BERT actualizado que usa el modelo entrenado con datos reales
"""

import json
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import warnings
warnings.filterwarnings('ignore')

class EnhancedBERTCryptoClassifier:
    """Clasificador BERT mejorado para tipos de crypto CTF"""
    
    def __init__(self, model_dir="ml_phase2/trained_model_real", use_gpu=False):
        """
        Inicializa el clasificador con el modelo entrenado.
        
        Args:
            model_dir: Ruta al modelo entrenado
            use_gpu: Si usar GPU (si disponible)
        """
        self.model_dir = Path(model_dir)
        self.device = torch.device("cuda" if use_gpu and torch.cuda.is_available() else "cpu")
        self.is_loaded = False
        
        print(f"🧠 Loading Enhanced BERT classifier from {self.model_dir}")
        print(f"   Device: {self.device}")
        
        try:
            self._load_model()
            self.is_loaded = True
            print(f"✅ Enhanced BERT classifier loaded successfully")
        except Exception as e:
            print(f"❌ Error loading BERT classifier: {e}")
            self.is_loaded = False

    def _load_model(self):
        """Carga el modelo y componentes necesarios"""
        # Verificar que el directorio existe
        if not self.model_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {self.model_dir}")
        
        # Cargar tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir))
        
        # Cargar modelo
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.model_dir))
        self.model.to(self.device)
        self.model.eval()
        
        # Cargar label map
        label_map_file = self.model_dir / "label_map.json"
        if not label_map_file.exists():
            # Buscar en el directorio de datos
            label_map_file = Path("ml_phase2/data/label_map.json")
        
        with open(label_map_file, 'r') as f:
            label_data = json.load(f)
            self.id_to_label = {int(k): v for k, v in label_data["id_to_label"].items()}
            self.label_to_id = label_data["label_to_id"]
            self.num_labels = len(self.id_to_label)
        
        print(f"   Labels: {list(self.label_to_id.keys())}")
        
        # Cargar métricas de entrenamiento si existen
        metrics_file = self.model_dir / "training_metrics.json"
        if metrics_file.exists():
            with open(metrics_file, 'r') as f:
                self.training_metrics = json.load(f)
                accuracy = self.training_metrics.get('eval_accuracy', 0)
                print(f"   Training accuracy: {accuracy:.1%}")
        else:
            self.training_metrics = {}

    def prepare_text(self, challenge_data):
        """
        Prepara el texto del challenge para clasificación.
        Compatible con la interfaz existente del agente.
        """
        text_parts = []
        
        # Descripción del challenge
        if isinstance(challenge_data, dict):
            if challenge_data.get('description'):
                text_parts.append(f"Description: {challenge_data['description']}")
            
            # Archivos del challenge
            if challenge_data.get('files'):
                for file_info in challenge_data['files']:
                    if file_info.get('content'):
                        content = file_info['content'][:500]  # Limitar longitud
                        text_parts.append(f"File: {content}")
            
            # Información adicional
            if challenge_data.get('hints'):
                text_parts.append(f"Hints: {challenge_data['hints']}")
        
        elif isinstance(challenge_data, str):
            # Si es solo texto
            text_parts.append(challenge_data)
        
        # Combinar todo el texto
        combined_text = ' | '.join(text_parts)
        
        # Limpiar y normalizar
        combined_text = combined_text.replace('\n', ' ').replace('\r', ' ')
        combined_text = ' '.join(combined_text.split())  # Normalizar espacios
        
        return combined_text

    def classify(self, challenge_data):
        """
        Clasifica un challenge y retorna el tipo de ataque.
        
        Args:
            challenge_data: Datos del challenge (dict o string)
            
        Returns:
            tuple: (predicted_type, confidence)
        """
        if not self.is_loaded:
            print("⚠️ BERT classifier not loaded, using heuristic fallback")
            return self._heuristic_classify(challenge_data)
        
        try:
            # Preparar texto
            text = self.prepare_text(challenge_data)
            
            if not text.strip():
                return "Unknown", 0.0
            
            # Tokenizar
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=512
            )
            
            # Mover a device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Hacer predicción
            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                predicted_id = torch.argmax(predictions, dim=-1).item()
                confidence = predictions[0][predicted_id].item()
            
            predicted_type = self.id_to_label[predicted_id]
            
            return predicted_type, confidence
            
        except Exception as e:
            print(f"⚠️ Error in BERT classification: {e}")
            return self._heuristic_classify(challenge_data)

    def _heuristic_classify(self, challenge_data):
        """
        Clasificación heurística como fallback.
        Mantiene compatibilidad con el sistema existente.
        """
        text = self.prepare_text(challenge_data).lower()
        
        # Patrones heurísticos
        if any(word in text for word in ['rsa', 'factorization', 'wiener', 'fermat', 'small e']):
            return "RSA", 0.7
        elif any(word in text for word in ['xor', 'single byte', 'multi byte', 'key reuse']):
            return "XOR", 0.7
        elif any(word in text for word in ['caesar', 'vigenere', 'shift', 'rot13', 'cipher']):
            return "Classical", 0.7
        elif any(word in text for word in ['base64', 'hex', 'encoding', 'decode']):
            return "Encoding", 0.7
        elif any(word in text for word in ['md5', 'sha', 'hash', 'dictionary']):
            return "Hash", 0.7
        elif any(word in text for word in ['aes', 'des', 'block cipher', 'cbc', 'ecb']):
            return "AES", 0.7
        elif any(word in text for word in ['elliptic', 'ecc', 'curve']):
            return "ECC", 0.7
        elif any(word in text for word in ['lattice', 'lll', 'cvp']):
            return "Lattice", 0.7
        else:
            return "Unknown", 0.5

    def get_supported_types(self):
        """Retorna los tipos de ataque soportados"""
        if self.is_loaded:
            return list(self.label_to_id.keys())
        else:
            return ["RSA", "Classical", "XOR", "Encoding", "Hash", "AES", "ECC", "Lattice", "Unknown"]

    def get_model_info(self):
        """Retorna información del modelo"""
        info = {
            'model_loaded': self.is_loaded,
            'model_path': str(self.model_dir),
            'device': str(self.device),
            'num_labels': getattr(self, 'num_labels', 0),
            'supported_types': self.get_supported_types()
        }
        
        if hasattr(self, 'training_metrics'):
            info['training_metrics'] = self.training_metrics
        
        return info

# Función de compatibilidad con el sistema existente
def classify_crypto(challenge_data, model_dir="ml_phase2/trained_model_real"):
    """
    Función de compatibilidad para el sistema existente.
    
    Args:
        challenge_data: Datos del challenge
        model_dir: Directorio del modelo
        
    Returns:
        tuple: (predicted_type, confidence)
    """
    # Crear instancia global si no existe
    global _bert_classifier
    if '_bert_classifier' not in globals():
        _bert_classifier = EnhancedBERTCryptoClassifier(model_dir)
    
    return _bert_classifier.classify(challenge_data)

# Instancia global para reutilización
_bert_classifier = None

def get_bert_classifier(model_dir="ml_phase2/trained_model_real"):
    """Obtiene la instancia global del clasificador"""
    global _bert_classifier
    if _bert_classifier is None:
        _bert_classifier = EnhancedBERTCryptoClassifier(model_dir)
    return _bert_classifier

if __name__ == "__main__":
    # Test del clasificador
    print("🧪 Testing Enhanced BERT Classifier")
    print("=" * 50)
    
    classifier = EnhancedBERTCryptoClassifier()
    
    # Casos de prueba
    test_cases = [
        {
            'description': 'RSA challenge with small exponent e=3',
            'files': [{'content': 'n = 12345...\ne = 3\nc = 67890...'}]
        },
        {
            'description': 'Caesar cipher with shift',
            'files': [{'content': 'encrypted = "synt{grfg}"'}]
        },
        "Single byte XOR encryption challenge"
    ]
    
    for i, case in enumerate(test_cases, 1):
        predicted_type, confidence = classifier.classify(case)
        print(f"Test {i}: {predicted_type} ({confidence:.4f})")
    
    # Mostrar información del modelo
    info = classifier.get_model_info()
    print(f"\nModel Info: {info}")