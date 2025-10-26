#!/usr/bin/env python3
"""
Test del modelo BERT entrenado
Verifica que el modelo funciona correctamente
"""

import json
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

def test_bert_model():
    """Prueba el modelo BERT entrenado"""
    model_dir = Path("ml_phase2/trained_model_real")
    
    print("🧪 TESTING TRAINED BERT MODEL")
    print("=" * 50)
    
    # Verificar que el directorio existe
    if not model_dir.exists():
        print(f"❌ Model directory not found: {model_dir}")
        return False
    
    try:
        # Cargar tokenizer y modelo
        print("📥 Loading tokenizer and model...")
        tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        
        print("✅ Model loaded successfully")
        print(f"📊 Model has {model.config.num_labels} labels")
        
        # Cargar label map
        label_map_file = Path("ml_phase2/data/label_map.json")
        with open(label_map_file, 'r') as f:
            label_map = json.load(f)
        
        id_to_label = label_map['id_to_label']
        
        # Casos de prueba
        test_cases = [
            {
                'text': "Challenge: RSA Small Exponent | Description: RSA with e=3 vulnerable to cube root attack | Solution: import gmpy2; m = gmpy2.iroot(c, 3)[0]",
                'expected': 'RSA'
            },
            {
                'text': "Challenge: Caesar Cipher | Description: Shift cipher with ROT13 | Solution: for shift in range(26): decrypt with shift",
                'expected': 'Classical'
            },
            {
                'text': "Challenge: Single Byte XOR | Description: XOR with single byte key | Solution: for key in range(256): xor decrypt",
                'expected': 'XOR'
            },
            {
                'text': "Challenge: Base64 Decode | Description: Multiple layers of base64 encoding | Solution: base64.b64decode recursively",
                'expected': 'Encoding'
            },
            {
                'text': "Challenge: MD5 Hash Crack | Description: Dictionary attack on MD5 hash | Solution: hashlib.md5 with wordlist",
                'expected': 'Hash'
            }
        ]
        
        print(f"\n🎯 Testing {len(test_cases)} cases...")
        correct = 0
        
        for i, case in enumerate(test_cases, 1):
            # Tokenizar
            inputs = tokenizer(
                case['text'],
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=512
            )
            
            # Hacer predicción
            with torch.no_grad():
                outputs = model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                predicted_id = torch.argmax(predictions, dim=-1).item()
                confidence = predictions[0][predicted_id].item()
            
            predicted_label = id_to_label[str(predicted_id)]
            is_correct = predicted_label == case['expected']
            
            if is_correct:
                correct += 1
            
            print(f"  Test {i}: {'✅' if is_correct else '❌'}")
            print(f"    Expected: {case['expected']}")
            print(f"    Predicted: {predicted_label} ({confidence:.4f})")
        
        accuracy = correct / len(test_cases)
        print(f"\n📊 Test Results:")
        print(f"  Correct: {correct}/{len(test_cases)}")
        print(f"  Accuracy: {accuracy:.4f}")
        
        success = accuracy >= 0.8
        print(f"✅ Model test: {'PASSED' if success else 'FAILED'}")
        
        return success
        
    except Exception as e:
        print(f"❌ Error testing model: {e}")
        return False

if __name__ == "__main__":
    success = test_bert_model()
    exit(0 if success else 1)