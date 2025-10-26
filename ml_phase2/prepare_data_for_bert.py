"""
BERT Data Preparation Script
Convierte el dataset JSON existente a formato compatible con HuggingFace Transformers.
Entrada: ml_dataset/train_dataset.json, ml_dataset/test_dataset.json
Salida: ml_phase2/data/train.csv, ml_phase2/data/test.csv, ml_phase2/data/label_map.json
"""

import json
import csv
from pathlib import Path
import random

# CONFIGURACIÓN
TRAIN_INPUT = Path("ml_dataset/train_dataset.json")
TEST_INPUT = Path("ml_dataset/test_dataset.json")
DATA_OUTPUT_DIR = Path("ml_phase2/data")
DATA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LABEL_TO_ID = {
    "RSA": 0,
    "Classical": 1,
    "XOR": 2,
    "Encoding": 3,
    "Hash": 4,
    "Lattice": 5,
    "ECC": 6,
    "Unknown": 7,
}

ID_TO_LABEL = {v: k for k, v in LABEL_TO_ID.items()}

def load_dataset(filepath):
    """Carga challenges del JSON"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def prepare_csv_from_json(input_json, output_csv, label_map):
    """
    Convierte JSON challenges a CSV compatible con HuggingFace.
    Columns: text (content), label (tipo crypto como ID)
    """
    data = load_dataset(input_json)
    
    rows = []
    skipped = 0
    
    for challenge in data:
        challenge_type = challenge.get('type', 'Unknown')
        
        # Mapear tipo a ID
        if challenge_type not in label_map:
            challenge_type = 'Unknown'
        
        label_id = label_map[challenge_type]
        content = challenge.get('content', '').strip()
        
        # Validación: no vacío
        if not content or len(content) < 50:
            skipped += 1
            continue
        
        # Limitar a 512 tokens (BERT max)
        content = content[:2000]  # ~512 tokens
        
        # Crear texto enriquecido para BERT
        description = challenge.get('description', '')
        name = challenge.get('name', '')
        
        # Combinar información para mejor clasificación
        text_parts = []
        if name:
            text_parts.append(f"Challenge: {name}")
        if description:
            text_parts.append(f"Description: {description}")
        text_parts.append(f"Code: {content}")
        
        full_text = "\n".join(text_parts)
        
        rows.append({
            'text': full_text,
            'label': label_id,
            'type': challenge_type,
            'original_id': challenge.get('id', 'unknown')
        })
    
    # Guardar CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label', 'type', 'original_id'])
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"✅ Saved {len(rows)} rows to {output_csv} (skipped {skipped})")
    return len(rows)

def analyze_dataset_distribution(csv_file):
    """Analiza la distribución de labels en el dataset"""
    import pandas as pd
    
    df = pd.read_csv(csv_file)
    distribution = df['type'].value_counts()
    
    print(f"\n📊 Distribution in {csv_file.name}:")
    for label, count in distribution.items():
        percentage = (count / len(df)) * 100
        print(f"   {label}: {count} ({percentage:.1f}%)")
    
    return distribution

def main():
    print("🔄 Preparing datasets for BERT training...\n")
    
    # Verificar archivos de entrada
    if not TRAIN_INPUT.exists():
        print(f"❌ Training file not found: {TRAIN_INPUT}")
        print("   Run dataset_expander.py first to generate the dataset")
        return 1
    
    if not TEST_INPUT.exists():
        print(f"❌ Test file not found: {TEST_INPUT}")
        print("   Run dataset_expander.py first to generate the dataset")
        return 1
    
    # Preparar train
    train_count = prepare_csv_from_json(TRAIN_INPUT, DATA_OUTPUT_DIR / "train.csv", LABEL_TO_ID)
    
    # Preparar test
    test_count = prepare_csv_from_json(TEST_INPUT, DATA_OUTPUT_DIR / "test.csv", LABEL_TO_ID)
    
    # Analizar distribuciones
    train_dist = analyze_dataset_distribution(DATA_OUTPUT_DIR / "train.csv")
    test_dist = analyze_dataset_distribution(DATA_OUTPUT_DIR / "test.csv")
    
    # Guardar label map
    with open(DATA_OUTPUT_DIR / "label_map.json", 'w') as f:
        json.dump({
            "label_to_id": LABEL_TO_ID,
            "id_to_label": ID_TO_LABEL,
            "total_labels": len(LABEL_TO_ID)
        }, f, indent=2)
    
    print(f"\n📊 Dataset Summary:")
    print(f"   Train: {train_count} samples")
    print(f"   Test: {test_count} samples")
    print(f"   Labels: {list(LABEL_TO_ID.keys())}")
    print(f"   Total unique labels: {len(LABEL_TO_ID)}")
    
    print(f"\n✅ Files created:")
    print(f"   📁 {DATA_OUTPUT_DIR / 'train.csv'}")
    print(f"   📁 {DATA_OUTPUT_DIR / 'test.csv'}")
    print(f"   📁 {DATA_OUTPUT_DIR / 'label_map.json'}")
    
    # Validación final
    if train_count < 10:
        print(f"\n⚠️  Warning: Training set is very small ({train_count} samples)")
        print("   Consider generating more data for better model performance")
    
    if test_count < 3:
        print(f"\n⚠️  Warning: Test set is very small ({test_count} samples)")
        print("   Results may not be statistically significant")
    
    print(f"\n🚀 Data preparation complete! Ready for BERT training.")
    return 0

if __name__ == "__main__":
    exit(main())