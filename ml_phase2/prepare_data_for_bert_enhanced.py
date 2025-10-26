#!/usr/bin/env python3
"""
ENHANCED BERT Data Preparation Script
Convierte el dataset JSONL mejorado a formato compatible con HuggingFace Transformers
"""

import json
import csv
import argparse
from pathlib import Path
import random
from sklearn.model_selection import train_test_split

class BERTDataPreparator:
    def __init__(self, input_file, output_dir, train_split=0.8, test_split=0.2):
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.train_split = train_split
        self.test_split = test_split
        
        # Mapeo de etiquetas mejorado
        self.label_to_id = {
            "RSA": 0,
            "Classical": 1,
            "XOR": 2,
            "Encoding": 3,
            "Hash": 4,
            "Lattice": 5,
            "ECC": 6,
            "AES": 7,
            "Unknown": 8,
        }
        
        self.id_to_label = {v: k for k, v in self.label_to_id.items()}
        
        self.data = []

    def load_jsonl_dataset(self):
        """Carga writeups del archivo JSONL"""
        print(f"📥 Loading dataset from {self.input_file}")
        
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {self.input_file}")
        
        with open(self.input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    writeup = json.loads(line.strip())
                    self.data.append(writeup)
                except json.JSONDecodeError as e:
                    print(f"⚠️ Skipping invalid JSON at line {line_num}: {e}")
                    continue
        
        print(f"✅ Loaded {len(self.data)} writeups")
        return len(self.data)

    def prepare_text_features(self, writeup):
        """Prepara las características de texto para BERT"""
        # Combinar múltiples campos de texto
        text_parts = []
        
        # Nombre del challenge
        if writeup.get('challenge_name'):
            text_parts.append(f"Challenge: {writeup['challenge_name']}")
        
        # Descripción
        if writeup.get('challenge_description'):
            desc = writeup['challenge_description'][:500]  # Limitar longitud
            text_parts.append(f"Description: {desc}")
        
        # Contenido del writeup (primeras líneas)
        if writeup.get('writeup'):
            writeup_content = writeup['writeup'][:1000]  # Limitar longitud
            text_parts.append(f"Writeup: {writeup_content}")
        
        # Código de solución (si existe)
        if writeup.get('solution_code'):
            code = writeup['solution_code'][:500]  # Limitar longitud
            text_parts.append(f"Solution: {code}")
        
        # Herramientas utilizadas
        if writeup.get('tools_used'):
            tools = ', '.join(writeup['tools_used'])
            text_parts.append(f"Tools: {tools}")
        
        # Combinar todo el texto
        combined_text = ' | '.join(text_parts)
        
        # Limpiar y normalizar
        combined_text = combined_text.replace('\n', ' ').replace('\r', ' ')
        combined_text = ' '.join(combined_text.split())  # Normalizar espacios
        
        return combined_text

    def prepare_bert_data(self):
        """Prepara los datos en formato BERT"""
        print("🔧 Preparing data for BERT training...")
        
        prepared_data = []
        skipped = 0
        
        for writeup in self.data:
            attack_type = writeup.get('attack_type', 'Unknown')
            
            # Mapear tipo a ID
            if attack_type not in self.label_to_id:
                print(f"⚠️ Unknown attack type: {attack_type}, mapping to 'Unknown'")
                attack_type = 'Unknown'
            
            label_id = self.label_to_id[attack_type]
            
            # Preparar texto
            text = self.prepare_text_features(writeup)
            
            # Validar que el texto no esté vacío
            if not text.strip():
                skipped += 1
                continue
            
            # Limitar longitud máxima (BERT tiene límite de tokens)
            if len(text) > 4000:  # Aproximadamente 512 tokens
                text = text[:4000] + "..."
            
            prepared_data.append({
                'text': text,
                'label': label_id,
                'attack_type': attack_type,
                'challenge_name': writeup.get('challenge_name', 'Unknown'),
                'team': writeup.get('team', 'Unknown'),
                'difficulty': writeup.get('difficulty', 'unknown')
            })
        
        print(f"✅ Prepared {len(prepared_data)} samples")
        print(f"⚠️ Skipped {skipped} samples (empty text)")
        
        return prepared_data

    def split_data(self, prepared_data):
        """Divide los datos en train y test"""
        print(f"📊 Splitting data: {self.train_split:.1%} train, {self.test_split:.1%} test")
        
        # Verificar distribución de clases
        label_counts = {}
        for item in prepared_data:
            label = item['label']
            label_counts[label] = label_counts.get(label, 0) + 1
        
        print("📈 Class distribution:")
        for label_id, count in sorted(label_counts.items()):
            attack_type = self.id_to_label[label_id]
            print(f"    {attack_type}: {count} samples")
        
        # Verificar si podemos estratificar
        min_samples = min(label_counts.values())
        can_stratify = min_samples >= 2
        
        texts = [item['text'] for item in prepared_data]
        labels = [item['label'] for item in prepared_data]
        
        if can_stratify:
            print("✅ Using stratified split")
            train_texts, test_texts, train_labels, test_labels = train_test_split(
                texts, labels, 
                test_size=self.test_split,
                random_state=42,
                stratify=labels
            )
        else:
            print("⚠️ Using random split (some classes have too few samples)")
            train_texts, test_texts, train_labels, test_labels = train_test_split(
                texts, labels, 
                test_size=self.test_split,
                random_state=42
            )
        
        # Reconstruir datos completos
        train_data = []
        test_data = []
        
        # Crear mapeo para reconstruir datos completos
        text_to_data = {item['text']: item for item in prepared_data}
        
        for text in train_texts:
            train_data.append(text_to_data[text])
        
        for text in test_texts:
            test_data.append(text_to_data[text])
        
        print(f"📈 Train set: {len(train_data)} samples")
        print(f"📈 Test set: {len(test_data)} samples")
        
        return train_data, test_data

    def save_csv_data(self, train_data, test_data):
        """Guarda los datos en formato CSV para BERT"""
        # Guardar datos de entrenamiento
        train_file = self.output_dir / "train.csv"
        print(f"💾 Saving training data to {train_file}")
        
        with open(train_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['text', 'label'])  # Header
            
            for item in train_data:
                writer.writerow([item['text'], item['label']])
        
        # Guardar datos de prueba
        test_file = self.output_dir / "test.csv"
        print(f"💾 Saving test data to {test_file}")
        
        with open(test_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['text', 'label'])  # Header
            
            for item in test_data:
                writer.writerow([item['text'], item['label']])
        
        # Guardar mapeo de etiquetas
        label_map_file = self.output_dir / "label_map.json"
        print(f"💾 Saving label mapping to {label_map_file}")
        
        label_map = {
            'label_to_id': self.label_to_id,
            'id_to_label': self.id_to_label,
            'num_labels': len(self.label_to_id)
        }
        
        with open(label_map_file, 'w', encoding='utf-8') as f:
            json.dump(label_map, f, indent=2, ensure_ascii=False)
        
        return train_file, test_file, label_map_file

    def generate_statistics(self, train_data, test_data):
        """Genera estadísticas del dataset preparado"""
        print("\n📊 DATASET STATISTICS:")
        
        # Estadísticas generales
        total_samples = len(train_data) + len(test_data)
        print(f"  Total samples: {total_samples}")
        print(f"  Training samples: {len(train_data)}")
        print(f"  Test samples: {len(test_data)}")
        
        # Distribución por tipo de ataque
        train_dist = {}
        test_dist = {}
        
        for item in train_data:
            attack_type = item['attack_type']
            train_dist[attack_type] = train_dist.get(attack_type, 0) + 1
        
        for item in test_data:
            attack_type = item['attack_type']
            test_dist[attack_type] = test_dist.get(attack_type, 0) + 1
        
        print(f"\n🎯 ATTACK TYPE DISTRIBUTION:")
        for attack_type in self.label_to_id.keys():
            train_count = train_dist.get(attack_type, 0)
            test_count = test_dist.get(attack_type, 0)
            total_count = train_count + test_count
            percentage = (total_count / total_samples * 100) if total_samples > 0 else 0
            
            print(f"    {attack_type}: {total_count} ({percentage:.1f}%) - Train: {train_count}, Test: {test_count}")
        
        # Distribución por dificultad
        difficulty_dist = {}
        for item in train_data + test_data:
            difficulty = item.get('difficulty', 'unknown')
            difficulty_dist[difficulty] = difficulty_dist.get(difficulty, 0) + 1
        
        print(f"\n🏆 DIFFICULTY DISTRIBUTION:")
        for difficulty, count in sorted(difficulty_dist.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_samples * 100) if total_samples > 0 else 0
            print(f"    {difficulty}: {count} ({percentage:.1f}%)")
        
        # Estadísticas de texto
        text_lengths = [len(item['text']) for item in train_data + test_data]
        avg_length = sum(text_lengths) / len(text_lengths) if text_lengths else 0
        max_length = max(text_lengths) if text_lengths else 0
        min_length = min(text_lengths) if text_lengths else 0
        
        print(f"\n📝 TEXT STATISTICS:")
        print(f"    Average text length: {avg_length:.0f} characters")
        print(f"    Max text length: {max_length} characters")
        print(f"    Min text length: {min_length} characters")

    def validate_output(self):
        """Valida los archivos de salida"""
        train_file = self.output_dir / "train.csv"
        test_file = self.output_dir / "test.csv"
        label_map_file = self.output_dir / "label_map.json"
        
        print(f"\n✅ VALIDATION RESULTS:")
        
        # Verificar que los archivos existen
        files_exist = all(f.exists() for f in [train_file, test_file, label_map_file])
        print(f"📁 All files exist: {'YES' if files_exist else 'NO'}")
        
        if not files_exist:
            return False
        
        # Verificar contenido de archivos CSV
        try:
            with open(train_file, 'r', encoding='utf-8') as f:
                train_lines = len(f.readlines()) - 1  # -1 para header
            
            with open(test_file, 'r', encoding='utf-8') as f:
                test_lines = len(f.readlines()) - 1  # -1 para header
            
            print(f"📊 Train CSV: {train_lines} samples")
            print(f"📊 Test CSV: {test_lines} samples")
            
            # Verificar label map
            with open(label_map_file, 'r', encoding='utf-8') as f:
                label_map = json.load(f)
            
            print(f"🏷️ Label map: {label_map['num_labels']} labels")
            
            success = train_lines > 0 and test_lines > 0 and label_map['num_labels'] > 0
            print(f"✅ Validation: {'PASSED' if success else 'FAILED'}")
            
            return success
            
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return False

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Prepare enhanced dataset for BERT training')
    parser.add_argument('--input', default='data/writeups_enhanced_dataset.jsonl',
                       help='Input JSONL file with writeups')
    parser.add_argument('--output', default='ml_phase2/data',
                       help='Output directory for BERT data')
    parser.add_argument('--train-split', type=float, default=0.8,
                       help='Training data split ratio')
    parser.add_argument('--test-split', type=float, default=0.2,
                       help='Test data split ratio')
    
    args = parser.parse_args()
    
    print("🔥 PHASE 3.0 - STEP 2: BERT DATA PREPARATION")
    print("Preparing enhanced dataset for BERT training")
    print("=" * 60)
    
    # Inicializar preparador
    preparator = BERTDataPreparator(
        input_file=args.input,
        output_dir=args.output,
        train_split=args.train_split,
        test_split=args.test_split
    )
    
    # Cargar dataset
    total_writeups = preparator.load_jsonl_dataset()
    
    # Preparar datos para BERT
    prepared_data = preparator.prepare_bert_data()
    
    # Dividir en train/test
    train_data, test_data = preparator.split_data(prepared_data)
    
    # Guardar archivos CSV
    train_file, test_file, label_map_file = preparator.save_csv_data(train_data, test_data)
    
    # Generar estadísticas
    preparator.generate_statistics(train_data, test_data)
    
    # Validar output
    success = preparator.validate_output()
    
    print("\n" + "=" * 60)
    print("🎉 BERT DATA PREPARATION COMPLETED!")
    print(f"📊 Processed {total_writeups} writeups")
    print(f"📁 Output files:")
    print(f"  - {train_file}")
    print(f"  - {test_file}")
    print(f"  - {label_map_file}")
    print(f"✅ Ready for BERT training: {'YES' if success else 'NO'}")
    
    if success:
        print("\n🚀 NEXT STEP:")
        print(f"python ml_phase2/train_bert.py --train-file {train_file} --test-file {test_file}")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)