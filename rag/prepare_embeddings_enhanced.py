#!/usr/bin/env python3
"""
ENHANCED RAG Embeddings Preparation
Crea embeddings de writeups reales para el sistema RAG mejorado
"""

import json
import argparse
from pathlib import Path
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
import chromadb
import hashlib

class EnhancedEmbeddingPreparer:
    def __init__(self, model_name="all-MiniLM-L6-v2", chromadb_path="rag/chromadb"):
        """Inicializa el preparador de embeddings"""
        self.model_name = model_name
        self.chromadb_path = Path(chromadb_path)
        self.chromadb_path.mkdir(parents=True, exist_ok=True)
        
        print(f"🔧 Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        print(f"✅ Model loaded. Dimensions: {self.model.get_sentence_embedding_dimension()}")
        
        # Conectar a ChromaDB
        self.client = chromadb.PersistentClient(path=str(self.chromadb_path))
        print(f"✅ ChromaDB initialized at {self.chromadb_path}")

    def load_writeups(self, writeups_file):
        """Carga writeups del archivo JSONL"""
        print(f"📥 Loading writeups from {writeups_file}")
        
        writeups = []
        with open(writeups_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    writeup = json.loads(line.strip())
                    writeups.append(writeup)
                except json.JSONDecodeError as e:
                    print(f"⚠️ Skipping invalid JSON at line {line_num}: {e}")
        
        print(f"✅ Loaded {len(writeups)} writeups")
        return writeups

    def prepare_writeup_text(self, writeup):
        """Prepara el texto del writeup para embedding"""
        text_parts = []
        
        # Información básica
        if writeup.get('challenge_name'):
            text_parts.append(f"Challenge: {writeup['challenge_name']}")
        
        if writeup.get('attack_type'):
            text_parts.append(f"Type: {writeup['attack_type']}")
        
        if writeup.get('team'):
            text_parts.append(f"Team: {writeup['team']}")
        
        # Descripción del challenge
        if writeup.get('challenge_description'):
            desc = writeup['challenge_description'][:500]  # Limitar longitud
            text_parts.append(f"Description: {desc}")
        
        # Contenido del writeup
        if writeup.get('writeup'):
            writeup_content = writeup['writeup'][:1000]  # Limitar longitud
            text_parts.append(f"Writeup: {writeup_content}")
        
        # Código de solución
        if writeup.get('solution_code'):
            code = writeup['solution_code'][:500]  # Limitar longitud
            text_parts.append(f"Solution: {code}")
        
        # Herramientas
        if writeup.get('tools_used'):
            tools = ', '.join(writeup['tools_used'])
            text_parts.append(f"Tools: {tools}")
        
        # Combinar todo
        combined_text = ' | '.join(text_parts)
        
        # Limpiar texto
        combined_text = combined_text.replace('\n', ' ').replace('\r', ' ')
        combined_text = ' '.join(combined_text.split())  # Normalizar espacios
        
        return combined_text

    def create_writeups_collection(self, writeups):
        """Crea colección de writeups en ChromaDB"""
        print("🔧 Creating writeups collection...")
        
        # Eliminar colección existente si existe
        try:
            self.client.delete_collection("writeups")
            print("🗑️ Deleted existing writeups collection")
        except:
            pass
        
        # Crear nueva colección
        collection = self.client.create_collection(
            name="writeups",
            metadata={"description": "Enhanced CTF writeups with real data"}
        )
        
        # Preparar datos para embeddings
        documents = []
        metadatas = []
        ids = []
        
        print("📝 Preparing writeup texts...")
        for i, writeup in enumerate(tqdm(writeups)):
            # Preparar texto
            text = self.prepare_writeup_text(writeup)
            
            if not text.strip():
                continue
            
            # Generar ID único basado en contenido y posición
            base_id = writeup.get('id', f"writeup_{i}")
            content_hash = hashlib.md5(text.encode()).hexdigest()[:8]
            writeup_id = f"{base_id}_{content_hash}_{i}"
            
            documents.append(text)
            ids.append(writeup_id)
            
            # Metadata
            metadata = {
                'challenge_name': writeup.get('challenge_name', 'Unknown'),
                'attack_type': writeup.get('attack_type', 'Unknown'),
                'team': writeup.get('team', 'Unknown'),
                'difficulty': writeup.get('difficulty', 'unknown'),
                'year': writeup.get('year', 2024),
                'synthetic': writeup.get('synthetic', False),
                'tools_used': ','.join(writeup.get('tools_used', [])),
                'url': writeup.get('url', ''),
                'event': writeup.get('event', 'Unknown')
            }
            metadatas.append(metadata)
        
        print(f"📊 Prepared {len(documents)} documents for embedding")
        
        # Crear embeddings en lotes
        batch_size = 100
        print(f"🔧 Creating embeddings in batches of {batch_size}...")
        
        for i in tqdm(range(0, len(documents), batch_size)):
            batch_docs = documents[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            batch_metadata = metadatas[i:i+batch_size]
            
            # Crear embeddings
            embeddings = self.model.encode(batch_docs).tolist()
            
            # Añadir a colección
            collection.add(
                documents=batch_docs,
                embeddings=embeddings,
                metadatas=batch_metadata,
                ids=batch_ids
            )
        
        print(f"✅ Created writeups collection with {len(documents)} documents")
        return collection

    def create_challenges_collection(self, writeups):
        """Crea colección de challenges en ChromaDB"""
        print("🔧 Creating challenges collection...")
        
        # Eliminar colección existente si existe
        try:
            self.client.delete_collection("challenges")
            print("🗑️ Deleted existing challenges collection")
        except:
            pass
        
        # Crear nueva colección
        collection = self.client.create_collection(
            name="challenges",
            metadata={"description": "CTF challenges extracted from writeups"}
        )
        
        # Preparar datos de challenges
        documents = []
        metadatas = []
        ids = []
        
        print("📝 Preparing challenge texts...")
        for i, writeup in enumerate(tqdm(writeups)):
            # Texto del challenge (más enfocado)
            challenge_parts = []
            
            if writeup.get('challenge_name'):
                challenge_parts.append(writeup['challenge_name'])
            
            if writeup.get('challenge_description'):
                challenge_parts.append(writeup['challenge_description'][:300])
            
            if writeup.get('attack_type'):
                challenge_parts.append(f"Attack type: {writeup['attack_type']}")
            
            challenge_text = ' | '.join(challenge_parts)
            
            if not challenge_text.strip():
                continue
            
            # ID del challenge único
            base_id = writeup.get('id', f"challenge_{i}")
            content_hash = hashlib.md5(challenge_text.encode()).hexdigest()[:8]
            challenge_id = f"{base_id}_{content_hash}_{i}"
            
            documents.append(challenge_text)
            ids.append(challenge_id)
            
            # Metadata del challenge
            metadata = {
                'name': writeup.get('challenge_name', 'Unknown'),
                'type': writeup.get('attack_type', 'Unknown'),
                'difficulty': writeup.get('difficulty', 'unknown'),
                'team': writeup.get('team', 'Unknown'),
                'event': writeup.get('event', 'Unknown'),
                'year': writeup.get('year', 2024),
                'writeup_id': writeup.get('id', ''),
                'synthetic': writeup.get('synthetic', False)
            }
            metadatas.append(metadata)
        
        print(f"📊 Prepared {len(documents)} challenges for embedding")
        
        # Crear embeddings en lotes
        batch_size = 100
        print(f"🔧 Creating challenge embeddings in batches of {batch_size}...")
        
        for i in tqdm(range(0, len(documents), batch_size)):
            batch_docs = documents[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            batch_metadata = metadatas[i:i+batch_size]
            
            # Crear embeddings
            embeddings = self.model.encode(batch_docs).tolist()
            
            # Añadir a colección
            collection.add(
                documents=batch_docs,
                embeddings=embeddings,
                metadatas=batch_metadata,
                ids=batch_ids
            )
        
        print(f"✅ Created challenges collection with {len(documents)} documents")
        return collection

    def validate_collections(self):
        """Valida las colecciones creadas"""
        print("\n✅ VALIDATION RESULTS:")
        
        try:
            # Verificar colección de writeups
            writeups_collection = self.client.get_collection("writeups")
            writeups_count = writeups_collection.count()
            print(f"📚 Writeups collection: {writeups_count} documents")
            
            # Verificar colección de challenges
            challenges_collection = self.client.get_collection("challenges")
            challenges_count = challenges_collection.count()
            print(f"🎯 Challenges collection: {challenges_count} documents")
            
            # Probar búsqueda
            print("\n🔍 Testing search functionality...")
            test_query = "RSA small exponent attack"
            
            results = writeups_collection.query(
                query_texts=[test_query],
                n_results=3
            )
            
            print(f"📊 Search test for '{test_query}':")
            for i, (doc, metadata) in enumerate(zip(results['documents'][0], results['metadatas'][0])):
                print(f"  {i+1}. {metadata['challenge_name']} ({metadata['attack_type']})")
                print(f"     Team: {metadata['team']}")
            
            success = writeups_count > 0 and challenges_count > 0
            print(f"\n✅ Validation: {'PASSED' if success else 'FAILED'}")
            
            return success
            
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return False

    def generate_statistics(self, writeups):
        """Genera estadísticas del dataset procesado"""
        print("\n📊 RAG DATASET STATISTICS:")
        
        # Estadísticas por tipo de ataque
        attack_types = {}
        teams = set()
        difficulties = {}
        synthetic_count = 0
        
        for writeup in writeups:
            attack_type = writeup.get('attack_type', 'Unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            teams.add(writeup.get('team', 'Unknown'))
            
            difficulty = writeup.get('difficulty', 'unknown')
            difficulties[difficulty] = difficulties.get(difficulty, 0) + 1
            
            if writeup.get('synthetic', False):
                synthetic_count += 1
        
        print(f"  Total writeups: {len(writeups)}")
        print(f"  Real writeups: {len(writeups) - synthetic_count}")
        print(f"  Synthetic writeups: {synthetic_count}")
        print(f"  Unique teams: {len(teams)}")
        
        print(f"\n🎯 Attack types:")
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    {attack_type}: {count}")
        
        print(f"\n🏆 Difficulties:")
        for difficulty, count in sorted(difficulties.items(), key=lambda x: x[1], reverse=True):
            print(f"    {difficulty}: {count}")

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Prepare enhanced RAG embeddings')
    parser.add_argument('--writeups', default='data/writeups_enhanced_dataset.jsonl',
                       help='Input JSONL file with writeups')
    parser.add_argument('--output', default='rag/chromadb',
                       help='Output ChromaDB directory')
    parser.add_argument('--model', default='all-MiniLM-L6-v2',
                       help='Sentence transformer model name')
    
    args = parser.parse_args()
    
    print("🔥 PHASE 3.0 - STEP 4: RAG EMBEDDINGS PREPARATION")
    print("Creating embeddings from enhanced writeups dataset")
    print("=" * 70)
    
    # Inicializar preparador
    preparer = EnhancedEmbeddingPreparer(
        model_name=args.model,
        chromadb_path=args.output
    )
    
    # Cargar writeups
    writeups = preparer.load_writeups(args.writeups)
    
    # Generar estadísticas
    preparer.generate_statistics(writeups)
    
    # Crear colecciones
    writeups_collection = preparer.create_writeups_collection(writeups)
    challenges_collection = preparer.create_challenges_collection(writeups)
    
    # Validar colecciones
    success = preparer.validate_collections()
    
    print("\n" + "=" * 70)
    print("🎉 RAG EMBEDDINGS PREPARATION COMPLETED!")
    print(f"📊 Processed {len(writeups)} writeups")
    print(f"📁 ChromaDB saved to: {args.output}")
    print(f"✅ RAG system ready: {'YES' if success else 'NO'}")
    
    if success:
        print("\n🚀 NEXT STEPS:")
        print("1. Test RAG system with sample queries")
        print("2. Update multi-agent system to use new RAG")
        print("3. Create Next.js frontend")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)