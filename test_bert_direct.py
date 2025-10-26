"""
Test directo del clasificador BERT
"""

import sys
from pathlib import Path

# Añadir ml_phase2 al path
sys.path.insert(0, str(Path(__file__).parent / "ml_phase2"))

try:
    from bert_classifier import bert_classifier, BERT_AVAILABLE
    
    print(f"🧠 BERT Available: {BERT_AVAILABLE}")
    
    if BERT_AVAILABLE:
        # Test cases
        test_cases = [
            "RSA challenge with n=123 e=3 c=456",
            "Caesar cipher with rotation 13", 
            "XOR encryption with single byte key",
            "Base64 encoded message"
        ]
        
        print("\n📊 Testing BERT classifier:")
        for text in test_cases:
            result = bert_classifier.classify(text)
            print(f"   '{text[:30]}...' -> {result['type']} ({result['confidence']:.2f})")
    else:
        print("❌ BERT classifier not available")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()