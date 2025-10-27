#!/usr/bin/env python3
"""
Production Writeup Scraper
Scraper robusto para obtener writeups reales de CTF
"""

import requests
import json
import time
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WriteupData:
    title: str
    content: str
    attack_type: str
    difficulty: str
    source: str
    url: str
    tags: List[str]

class WriteupScraper:
    """Scraper de writeups de CTF"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.writeups = []
        
        # Patrones para detectar tipos de ataque
        self.attack_patterns = {
            'rsa': ['rsa', 'modulus', 'factorization', 'wiener', 'coppersmith'],
            'classical': ['caesar', 'vigenere', 'substitution', 'transposition'],
            'hash': ['md5', 'sha1', 'sha256', 'hash', 'collision'],
            'aes': ['aes', 'des', 'symmetric', 'block cipher', 'ecb', 'cbc'],
            'elliptic': ['ecc', 'elliptic', 'curve', 'ecdsa', 'ecdh'],
            'misc': ['xor', 'base64', 'encoding', 'steganography']
        }
    
    def scrape_github_repo(self, repo_url: str, max_files: int = 50) -> List[WriteupData]:
        """Scrape writeups de un repositorio de GitHub"""
        logger.info(f"🔍 Scraping {repo_url}")
        
        try:
            # Convertir URL de GitHub a API URL
            if 'github.com' in repo_url:
                parts = repo_url.replace('https://github.com/', '').split('/')
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
                    
                    return self._scrape_github_contents(api_url, owner, repo, max_files)
        except Exception as e:
            logger.error(f"Error scraping {repo_url}: {e}")
        
        return []
    
    def _scrape_github_contents(self, api_url: str, owner: str, repo: str, max_files: int) -> List[WriteupData]:
        """Scrape contenidos de GitHub usando API"""
        writeups = []
        
        try:
            response = self.session.get(api_url, timeout=10)
            if response.status_code != 200:
                logger.warning(f"GitHub API error: {response.status_code}")
                return []
            
            contents = response.json()
            files_processed = 0
            
            for item in contents:
                if files_processed >= max_files:
                    break
                
                if item['type'] == 'file' and self._is_writeup_file(item['name']):
                    writeup = self._process_github_file(item, owner, repo)
                    if writeup:
                        writeups.append(writeup)
                        files_processed += 1
                
                elif item['type'] == 'dir' and files_processed < max_files:
                    # Recursivamente buscar en directorios
                    subdir_writeups = self._scrape_github_contents(
                        item['url'], owner, repo, max_files - files_processed
                    )
                    writeups.extend(subdir_writeups)
                    files_processed += len(subdir_writeups)
                
                # Rate limiting
                time.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error processing GitHub contents: {e}")
        
        return writeups
    
    def _is_writeup_file(self, filename: str) -> bool:
        """Determina si un archivo es un writeup"""
        writeup_indicators = [
            'readme.md', 'writeup.md', 'solution.md', 'solve.py',
            'exploit.py', 'attack.py', 'crack.py'
        ]
        
        filename_lower = filename.lower()
        
        # Archivos específicos
        if filename_lower in writeup_indicators:
            return True
        
        # Patrones
        if any(pattern in filename_lower for pattern in ['writeup', 'solution', 'solve', 'exploit']):
            return True
        
        # Extensiones relevantes
        if filename_lower.endswith(('.md', '.py', '.txt')):
            return True
        
        return False
    
    def _process_github_file(self, file_item: Dict, owner: str, repo: str) -> Optional[WriteupData]:
        """Procesa un archivo de GitHub"""
        try:
            # Obtener contenido del archivo
            response = self.session.get(file_item['download_url'], timeout=10)
            if response.status_code != 200:
                return None
            
            content = response.text
            
            # Detectar tipo de ataque
            attack_type = self._detect_attack_type(content)
            
            # Detectar dificultad
            difficulty = self._detect_difficulty(content, file_item['name'])
            
            # Extraer tags
            tags = self._extract_tags(content)
            
            # Crear writeup
            writeup = WriteupData(
                title=f"{repo} - {file_item['name']}",
                content=content[:5000],  # Limitar contenido
                attack_type=attack_type,
                difficulty=difficulty,
                source=f"{owner}/{repo}",
                url=file_item['html_url'],
                tags=tags
            )
            
            logger.info(f"✅ Processed: {writeup.title} ({attack_type})")
            return writeup
            
        except Exception as e:
            logger.error(f"Error processing file {file_item['name']}: {e}")
            return None
    
    def _detect_attack_type(self, content: str) -> str:
        """Detecta el tipo de ataque basado en el contenido"""
        content_lower = content.lower()
        
        # Contar matches por tipo
        type_scores = {}
        for attack_type, patterns in self.attack_patterns.items():
            score = sum(content_lower.count(pattern) for pattern in patterns)
            if score > 0:
                type_scores[attack_type] = score
        
        # Retornar el tipo con mayor score
        if type_scores:
            return max(type_scores, key=type_scores.get)
        
        return 'misc'
    
    def _detect_difficulty(self, content: str, filename: str) -> str:
        """Detecta la dificultad del challenge"""
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        # Indicadores de dificultad
        if any(word in content_lower or word in filename_lower 
               for word in ['easy', 'beginner', 'warmup', 'simple']):
            return 'easy'
        
        if any(word in content_lower or word in filename_lower 
               for word in ['hard', 'difficult', 'advanced', 'expert']):
            return 'hard'
        
        if any(word in content_lower or word in filename_lower 
               for word in ['insane', 'extreme', 'impossible']):
            return 'expert'
        
        return 'medium'
    
    def _extract_tags(self, content: str) -> List[str]:
        """Extrae tags del contenido"""
        tags = []
        content_lower = content.lower()
        
        # Tags técnicos
        tech_tags = [
            'python', 'sage', 'pycrypto', 'gmpy2', 'sympy',
            'factorization', 'discrete_log', 'lattice', 'lll',
            'coppersmith', 'wiener', 'hastad', 'franklin_reiter'
        ]
        
        for tag in tech_tags:
            if tag in content_lower:
                tags.append(tag)
        
        return tags[:5]  # Limitar a 5 tags
    
    def scrape_multiple_repos(self, repo_urls: List[str], max_files_per_repo: int = 20) -> List[WriteupData]:
        """Scrape múltiples repositorios"""
        all_writeups = []
        
        for repo_url in repo_urls:
            try:
                writeups = self.scrape_github_repo(repo_url, max_files_per_repo)
                all_writeups.extend(writeups)
                logger.info(f"📊 {repo_url}: {len(writeups)} writeups found")
                
                # Rate limiting entre repos
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error with repo {repo_url}: {e}")
        
        return all_writeups
    
    def save_writeups(self, writeups: List[WriteupData], output_file: str = "crypto_writeups.jsonl"):
        """Guarda writeups en formato JSONL"""
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for writeup in writeups:
                data = {
                    'title': writeup.title,
                    'content': writeup.content,
                    'attack_type': writeup.attack_type,
                    'difficulty': writeup.difficulty,
                    'source': writeup.source,
                    'url': writeup.url,
                    'tags': writeup.tags
                }
                f.write(json.dumps(data, ensure_ascii=False) + '\n')
        
        logger.info(f"💾 Saved {len(writeups)} writeups to {output_path}")

def main():
    """Función principal"""
    print("🚀 Production Writeup Scraper")
    print("=" * 40)
    
    # Repositorios principales (los más accesibles)
    target_repos = [
        "https://github.com/project-sekai-ctf/sekaictf-2024",
        "https://github.com/justcatthefish/justctf-2023",
        "https://github.com/TheRomanXpl0it/TRX-CTF-2025",
        "https://github.com/L3AK-TEAM/L3akCTF-2024-public",
        "https://github.com/Cryptonite-MIT/niteCTF-2024",
        "https://github.com/srdnlen/srdnlenctf-2023_public",
        "https://github.com/ashutosh1206/Crypto-CTF-Writeups",
        "https://github.com/Crypto-Cat/ctf-writeups"
    ]
    
    scraper = WriteupScraper()
    
    print(f"🎯 Target repositories: {len(target_repos)}")
    print("📥 Starting scraping process...")
    
    # Scrape writeups
    all_writeups = scraper.scrape_multiple_repos(target_repos, max_files_per_repo=15)
    
    print(f"\n📊 Scraping Results:")
    print(f"   Total writeups: {len(all_writeups)}")
    
    # Estadísticas por tipo
    attack_types = {}
    difficulties = {}
    
    for writeup in all_writeups:
        attack_types[writeup.attack_type] = attack_types.get(writeup.attack_type, 0) + 1
        difficulties[writeup.difficulty] = difficulties.get(writeup.difficulty, 0) + 1
    
    print(f"\n📈 Attack Types:")
    for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   {attack_type}: {count}")
    
    print(f"\n📊 Difficulties:")
    for difficulty, count in sorted(difficulties.items(), key=lambda x: x[1], reverse=True):
        print(f"   {difficulty}: {count}")
    
    # Guardar resultados
    if all_writeups:
        scraper.save_writeups(all_writeups, "real_writeups_train/crypto_writeups_scraped.jsonl")
        
        # Crear también un archivo de muestra
        sample_writeups = all_writeups[:10]
        scraper.save_writeups(sample_writeups, "real_writeups_train/crypto_writeups_sample.jsonl")
        
        print(f"\n💾 Files saved:")
        print(f"   Full dataset: real_writeups_train/crypto_writeups_scraped.jsonl")
        print(f"   Sample: real_writeups_train/crypto_writeups_sample.jsonl")
        
        print(f"\n🎉 Scraping completed successfully!")
        print(f"   {len(all_writeups)} writeups ready for training")
    else:
        print(f"\n❌ No writeups found. Check network connection and repo access.")

if __name__ == "__main__":
    main()