#!/usr/bin/env python3
"""
Analizador de Dataset ML
Analiza el dataset generado y muestra estadísticas detalladas
"""

import json
import sys
from pathlib import Path
from collections import Counter

def analyze_dataset(dataset_path):
    """Analiza un dataset y muestra estadísticas"""
    
    print(f"📊 ANALYZING DATASET: {dataset_path}")
    print("=" * 60)
    
    # Cargar dataset
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            if dataset_path.suffix == '.jsonl':
                dataset = []
                for line in f:
                    dataset.append(json.loads(line.strip()))
            else:
                data = json.load(f)
                if isinstance(data, dict) and 'challenges' in data:
                    dataset = data['challenges']
                    print(f"📋 Metadata: {data.get('metadata', {})}")
                    print()
                else:
                    dataset = data
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        return
    
    if not dataset:
        print("❌ Dataset is empty")
        return
    
    print(f"📈 Total Challenges: {len(dataset)}")
    print()
    
    # Análisis por tipo
    types = Counter(c['type'] for c in dataset)
    print("🔍 By Type:")
    for type_name, count in sorted(types.items()):
        percentage = (count / len(dataset)) * 100
        print(f"   {type_name}: {count} ({percentage:.1f}%)")
    print()
    
    # Análisis por dificultad
    difficulties = Counter(c['difficulty'] for c in dataset)
    print("🎚️  By Difficulty:")
    for diff, count in sorted(difficulties.items()):
        percentage = (count / len(dataset)) * 100
        print(f"   {diff}: {count} ({percentage:.1f}%)")
    print()
    
    # Análisis por subtipo
    subtypes = Counter(c.get('challenge_type_detail', 'Unknown') for c in dataset)
    print("🔬 By Challenge Subtype:")
    for subtype, count in sorted(subtypes.items()):
        percentage = (count / len(dataset)) * 100
        print(f"   {subtype}: {count} ({percentage:.1f}%)")
    print()
    
    # Análisis de contenido
    content_lengths = [len(c.get('content', '')) for c in dataset]
    avg_content_length = sum(content_lengths) / len(content_lengths)
    min_content_length = min(content_lengths)
    max_content_length = max(content_lengths)
    
    print("📝 Content Analysis:")
    print(f"   Average content length: {avg_content_length:.0f} chars")
    print(f"   Min content length: {min_content_length} chars")
    print(f"   Max content length: {max_content_length} chars")
    print()
    
    # Ejemplos por tipo
    print("📋 Sample Challenges:")
    for type_name in sorted(types.keys()):
        sample = next(c for c in dataset if c['type'] == type_name)
        print(f"   {type_name} Example:")
        print(f"     Name: {sample['name']}")
        print(f"     Description: {sample['description']}")
        print(f"     Expected Flag: {sample['expected_flag']}")
        print()
    
    return dataset

def compare_datasets():
    """Compara train y test datasets"""
    
    print("🔄 COMPARING TRAIN/TEST SPLIT")
    print("=" * 60)
    
    ml_dir = Path("ml_dataset")
    train_file = ml_dir / "train_dataset.json"
    test_file = ml_dir / "test_dataset.json"
    
    if not train_file.exists() or not test_file.exists():
        print("❌ Train/test files not found")
        return
    
    # Cargar datasets
    with open(train_file, 'r', encoding='utf-8') as f:
        train_data = json.load(f)
    
    with open(test_file, 'r', encoding='utf-8') as f:
        test_data = json.load(f)
    
    print(f"🏋️  Training Set: {len(train_data)} challenges")
    print(f"🧪 Test Set: {len(test_data)} challenges")
    print(f"📊 Split Ratio: {len(train_data)/(len(train_data)+len(test_data))*100:.1f}% train / {len(test_data)/(len(train_data)+len(test_data))*100:.1f}% test")
    print()
    
    # Comparar distribuciones
    train_types = Counter(c['type'] for c in train_data)
    test_types = Counter(c['type'] for c in test_data)
    
    print("📊 Type Distribution Comparison:")
    all_types = set(train_types.keys()) | set(test_types.keys())
    for type_name in sorted(all_types):
        train_count = train_types.get(type_name, 0)
        test_count = test_types.get(type_name, 0)
        train_pct = (train_count / len(train_data)) * 100 if train_data else 0
        test_pct = (test_count / len(test_data)) * 100 if test_data else 0
        print(f"   {type_name}:")
        print(f"     Train: {train_count} ({train_pct:.1f}%)")
        print(f"     Test:  {test_count} ({test_pct:.1f}%)")
    print()

def validate_dataset_quality():
    """Valida la calidad del dataset"""
    
    print("✅ DATASET QUALITY VALIDATION")
    print("=" * 60)
    
    ml_dir = Path("ml_dataset")
    dataset_file = ml_dir / "challenges_only.json"
    
    if not dataset_file.exists():
        print("❌ Dataset file not found")
        return False
    
    with open(dataset_file, 'r', encoding='utf-8') as f:
        dataset = json.load(f)
    
    issues = []
    
    # Validar estructura
    required_fields = ['id', 'name', 'type', 'difficulty', 'expected_flag', 'content']
    for i, challenge in enumerate(dataset):
        for field in required_fields:
            if field not in challenge:
                issues.append(f"Challenge {i}: Missing field '{field}'")
        
        # Validar que expected_flag contiene 'flag{'
        if 'expected_flag' in challenge:
            flag = challenge['expected_flag']
            if not flag.lower().startswith('flag{'):
                issues.append(f"Challenge {i}: Invalid flag format: {flag}")
        
        # Validar que content no esté vacío
        if 'content' in challenge and len(challenge['content'].strip()) < 10:
            issues.append(f"Challenge {i}: Content too short")
    
    # Validar distribución
    types = Counter(c['type'] for c in dataset)
    if len(types) < 3:
        issues.append("Dataset has too few challenge types")
    
    for type_name, count in types.items():
        if count < 3:
            issues.append(f"Type '{type_name}' has too few examples ({count})")
    
    # Mostrar resultados
    if issues:
        print("❌ Quality Issues Found:")
        for issue in issues[:10]:  # Mostrar solo los primeros 10
            print(f"   • {issue}")
        if len(issues) > 10:
            print(f"   ... and {len(issues) - 10} more issues")
        print()
        return False
    else:
        print("✅ Dataset quality validation passed!")
        print("   • All required fields present")
        print("   • All flags have correct format")
        print("   • Content length adequate")
        print("   • Good type distribution")
        print()
        return True

def main():
    """Función principal"""
    
    print("🚀 CTF CRYPTO DATASET ANALYZER")
    print("=" * 60)
    
    ml_dir = Path("ml_dataset")
    
    if not ml_dir.exists():
        print("❌ ml_dataset directory not found")
        print("   Run dataset_expander.py first")
        return 1
    
    # Analizar dataset principal
    full_dataset_file = ml_dir / "full_dataset.json"
    if full_dataset_file.exists():
        analyze_dataset(full_dataset_file)
    
    # Comparar train/test split
    compare_datasets()
    
    # Validar calidad
    quality_ok = validate_dataset_quality()
    
    print("=" * 60)
    print("📊 ANALYSIS COMPLETE")
    print("=" * 60)
    
    if quality_ok:
        print("🎉 Dataset is ready for ML training!")
        print("📁 Files available:")
        for file in sorted(ml_dir.glob("*.json*")):
            print(f"   • {file.name}")
        return 0
    else:
        print("⚠️  Dataset has quality issues that should be fixed")
        return 1

if __name__ == "__main__":
    exit(main())