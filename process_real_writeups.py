#!/usr/bin/env python3
"""
PHASE 3.0 - STEP 1: MASSIVE CTF WRITEUPS SCRAPER
Descarga y procesa 500+ writeups reales de equipos top de CTF
"""

import os
import sys
import json
import requests
import re
import time
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import base64
import hashlib

class CTFWriteupScraper:
    def __init__(self, output_dir="data", max_writeups=500):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.max_writeups = max_writeups
        self.scraped_writeups = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Patrones para detectar tipos de ataques
        self.attack_patterns = {
            'RSA': [r'rsa', r'wiener', r'fermat', r'hastad', r'small.?e', r'factorization', r'coppersmith'],
            'XOR': [r'xor', r'single.?byte', r'multi.?byte', r'key.?reuse'],
            'Classical': [r'caesar', r'vigenere', r'substitution', r'shift', r'rot13', r'affine'],
            'Hash': [r'md5', r'sha', r'hash', r'dictionary', r'rainbow', r'collision'],
            'Encoding': [r'base64', r'hex', r'url.?encod', r'ascii'],
            'Lattice': [r'lll', r'cvp', r'lattice', r'knapsack'],
            'ECC': [r'elliptic', r'ecc', r'ecdsa', r'curve'],
            'AES': [r'aes', r'des', r'block.?cipher', r'cbc', r'ecb', r'padding']
        }
        
        # Repositorios a scrapear (de TOP_CRYPTO_CTF_REPOS)
        self.repositories = [
            # TIER 1 - TOP 5 EQUIPOS
            {'team': 'r3kapig', 'url': 'https://github.com/r3kapig/writeup', 'priority': 1},
            {'team': 'kalmarunionenctf', 'url': 'https://github.com/kalmarunionenctf/kalmarctf', 'priority': 1},
            {'team': 'project-sekai-ctf', 'url': 'https://github.com/project-sekai-ctf/sekaictf-2025', 'priority': 1},
            {'team': 'project-sekai-ctf', 'url': 'https://github.com/project-sekai-ctf/sekaictf-2024', 'priority': 1},
            {'team': 'justcatthefish', 'url': 'https://github.com/justcatthefish/justctf-2023', 'priority': 1},
            {'team': 'justcatthefish', 'url': 'https://github.com/justcatthefish/justctf-2022', 'priority': 1},
            
            # TIER 2 - TOP 6-20 EQUIPOS
            {'team': 'l3ak-team', 'url': 'https://github.com/L3AK-TEAM/L3akCTF-2024-public', 'priority': 2},
            {'team': 'theromanxpl0it', 'url': 'https://github.com/TheRomanXpl0it/TRX-CTF-2025', 'priority': 2},
            {'team': 'teambi0s', 'url': 'https://github.com/teambi0s', 'priority': 2},
            {'team': 'srdnlen', 'url': 'https://github.com/srdnlen/ctf-writeups', 'priority': 2},
            
            # TIER 3 + Generales
            {'team': 'cryptonite-mit', 'url': 'https://github.com/Cryptonite-MIT/Write-ups', 'priority': 3},
            {'team': 'bitskrieg', 'url': 'https://github.com/bitskriegofficial/OSCTF_2024_Write-ups', 'priority': 3},
            {'team': 'sajjadium', 'url': 'https://github.com/sajjadium/ctf-archives', 'priority': 3},
            {'team': 'crypto-cat', 'url': 'https://github.com/Crypto-Cat/ctf-writeups', 'priority': 3},
            {'team': 'ashutosh1206', 'url': 'https://github.com/ashutosh1206/Crypto-CTF-Writeups', 'priority': 3},
            {'team': 'p4-team', 'url': 'https://github.com/p4-team/ctf', 'priority': 3},
            {'team': 'google', 'url': 'https://github.com/google/google-ctf', 'priority': 3},
        ]

    def get_github_api_url(self, github_url):
        """Convierte URL de GitHub a API URL"""
        parts = github_url.replace('https://github.com/', '').split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            return f"https://api.github.com/repos/{owner}/{repo}/contents"
        return None

    def get_repo_contents(self, api_url, path=""):
        """Obtiene contenidos de un repositorio via GitHub API"""
        try:
            url = f"{api_url}/{path}" if path else api_url
            response = self.session.get(url)
            
            if response.status_code == 403:
                print(f"⚠️ Rate limit reached, waiting 60s...")
                time.sleep(60)
                response = self.session.get(url)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Error {response.status_code} accessing {url}")
                return None
        except Exception as e:
            print(f"❌ Exception getting repo contents: {e}")
            return None

    def is_crypto_related(self, path, content=""):
        """Determina si un archivo/carpeta es relacionado con crypto"""
        crypto_indicators = [
            'crypto', 'cryptography', 'cipher', 'rsa', 'aes', 'hash',
            'xor', 'lattice', 'ecc', 'elliptic', 'wiener', 'fermat'
        ]
        
        path_lower = path.lower()
        content_lower = content.lower()
        
        return any(indicator in path_lower or indicator in content_lower 
                  for indicator in crypto_indicators)

    def detect_attack_type(self, content):
        """Detecta el tipo de ataque basado en el contenido"""
        content_lower = content.lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    return attack_type
        
        return "Unknown"

    def extract_code_blocks(self, content):
        """Extrae bloques de código Python del markdown"""
        python_blocks = re.findall(r'```python\n(.*?)\n```', content, re.DOTALL)
        py_blocks = re.findall(r'```py\n(.*?)\n```', content, re.DOTALL)
        generic_blocks = re.findall(r'```\n(.*?)\n```', content, re.DOTALL)
        
        all_blocks = python_blocks + py_blocks
        
        # Filtrar bloques genéricos que parecen Python
        for block in generic_blocks:
            if any(keyword in block for keyword in ['import', 'def ', 'print(', 'from ']):
                all_blocks.append(block)
        
        return '\n\n'.join(all_blocks) if all_blocks else ""

    def extract_tools_mentioned(self, content):
        """Extrae herramientas mencionadas en el writeup"""
        tools = []
        tool_patterns = [
            r'RsaCtfTool', r'SageMath', r'Wireshark', r'John', r'Hashcat',
            r'pycrypto', r'cryptodome', r'gmpy2', r'sympy', r'z3',
            r'factordb', r'yafu', r'msieve', r'openssl'
        ]
        
        for pattern in tool_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                tools.append(pattern)
        
        return tools

    def process_file_content(self, file_info, team, repo_name):
        """Procesa el contenido de un archivo"""
        try:
            if file_info.get('encoding') == 'base64':
                content = base64.b64decode(file_info['content']).decode('utf-8', errors='ignore')
            else:
                content = file_info.get('content', '')
            
            if not self.is_crypto_related(file_info['name'], content):
                return None
            
            # Extraer información
            attack_type = self.detect_attack_type(content)
            solution_code = self.extract_code_blocks(content)
            tools_used = self.extract_tools_mentioned(content)
            
            # Generar ID único
            file_id = hashlib.md5(f"{team}_{repo_name}_{file_info['name']}".encode()).hexdigest()[:12]
            
            writeup_data = {
                'id': f"{team}_{repo_name}_{file_id}",
                'team': team,
                'event': repo_name,
                'challenge_name': Path(file_info['name']).stem,
                'challenge_description': content[:500] + "..." if len(content) > 500 else content,
                'attack_type': attack_type,
                'tools_used': tools_used,
                'difficulty': 'unknown',
                'writeup': content,
                'solution_code': solution_code,
                'url': file_info.get('html_url', ''),
                'year': 2024,  # Default, could be extracted from repo name
                'category': 'crypto',
                'file_type': Path(file_info['name']).suffix,
                'scraped_at': datetime.now().isoformat()
            }
            
            return writeup_data
            
        except Exception as e:
            print(f"❌ Error processing file {file_info.get('name', 'unknown')}: {e}")
            return None

    def scrape_repository(self, repo_info):
        """Scrapea un repositorio completo"""
        team = repo_info['team']
        url = repo_info['url']
        priority = repo_info['priority']
        
        print(f"\n🔍 Scraping {team} - {url} (Priority {priority})")
        
        api_url = self.get_github_api_url(url)
        if not api_url:
            print(f"❌ Invalid GitHub URL: {url}")
            return 0
        
        repo_name = url.split('/')[-1]
        scraped_count = 0
        
        # Obtener contenidos del repositorio
        contents = self.get_repo_contents(api_url)
        if not contents:
            return 0
        
        # Buscar carpetas relacionadas con crypto
        crypto_paths = []
        for item in contents:
            if item['type'] == 'dir':
                if self.is_crypto_related(item['name']):
                    crypto_paths.append(item['path'])
        
        # Si no hay carpetas crypto específicas, buscar en la raíz
        if not crypto_paths:
            crypto_paths = [""]
        
        # Procesar cada carpeta crypto
        for path in crypto_paths:
            if scraped_count >= 50:  # Límite por repo
                break
                
            path_contents = self.get_repo_contents(api_url, path)
            if not path_contents:
                continue
            
            for item in path_contents:
                if scraped_count >= 50:
                    break
                
                if item['type'] == 'file' and item['name'].endswith(('.md', '.py', '.sol', '.txt')):
                    # Obtener contenido del archivo
                    file_response = self.session.get(item['url'])
                    if file_response.status_code == 200:
                        file_data = file_response.json()
                        
                        writeup = self.process_file_content(file_data, team, repo_name)
                        if writeup:
                            self.scraped_writeups.append(writeup)
                            scraped_count += 1
                            print(f"  ✅ {writeup['challenge_name']} ({writeup['attack_type']})")
                    
                    time.sleep(0.1)  # Rate limiting
        
        print(f"📊 Scraped {scraped_count} writeups from {team}")
        return scraped_count

    def scrape_all_repositories(self):
        """Scrapea todos los repositorios en orden de prioridad"""
        print("🚀 STARTING MASSIVE CTF WRITEUPS SCRAPING")
        print("=" * 60)
        
        # Ordenar por prioridad
        sorted_repos = sorted(self.repositories, key=lambda x: x['priority'])
        
        total_scraped = 0
        for repo_info in sorted_repos:
            if total_scraped >= self.max_writeups:
                break
            
            scraped = self.scrape_repository(repo_info)
            total_scraped += scraped
            
            print(f"📈 Progress: {total_scraped}/{self.max_writeups} writeups")
            
            if scraped > 0:
                time.sleep(2)  # Pausa entre repos
        
        return total_scraped

    def save_writeups(self):
        """Guarda los writeups en formato JSONL"""
        output_file = self.output_dir / "writeups_real_processed.jsonl"
        
        print(f"\n💾 Saving {len(self.scraped_writeups)} writeups to {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for writeup in self.scraped_writeups:
                f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
        
        # Generar estadísticas
        stats = self.generate_statistics()
        stats_file = self.output_dir / "scraping_statistics.json"
        
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Statistics saved to {stats_file}")
        return output_file

    def generate_statistics(self):
        """Genera estadísticas de los writeups scrapeados"""
        stats = {
            'total_writeups': len(self.scraped_writeups),
            'by_team': {},
            'by_attack_type': {},
            'by_year': {},
            'with_solution_code': 0,
            'scraping_timestamp': datetime.now().isoformat()
        }
        
        for writeup in self.scraped_writeups:
            # Por equipo
            team = writeup['team']
            stats['by_team'][team] = stats['by_team'].get(team, 0) + 1
            
            # Por tipo de ataque
            attack_type = writeup['attack_type']
            stats['by_attack_type'][attack_type] = stats['by_attack_type'].get(attack_type, 0) + 1
            
            # Por año
            year = str(writeup['year'])
            stats['by_year'][year] = stats['by_year'].get(year, 0) + 1
            
            # Con código de solución
            if writeup['solution_code'].strip():
                stats['with_solution_code'] += 1
        
        return stats

    def validate_output(self):
        """Valida el output generado"""
        output_file = self.output_dir / "writeups_real_processed.jsonl"
        
        if not output_file.exists():
            print("❌ Output file not found!")
            return False
        
        print(f"\n✅ VALIDATION RESULTS:")
        print(f"📁 File: {output_file}")
        print(f"📊 Size: {output_file.stat().st_size / 1024:.1f} KB")
        
        # Contar líneas
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"📝 Lines: {len(lines)}")
        
        # Validar JSON
        valid_json = 0
        for i, line in enumerate(lines[:5]):  # Primeras 5 líneas
            try:
                data = json.loads(line)
                valid_json += 1
                print(f"  ✅ Line {i+1}: {data['team']} - {data['challenge_name']} ({data['attack_type']})")
            except json.JSONDecodeError as e:
                print(f"  ❌ Line {i+1}: Invalid JSON - {e}")
        
        # Mostrar estadísticas
        stats_file = self.output_dir / "scraping_statistics.json"
        if stats_file.exists():
            with open(stats_file, 'r', encoding='utf-8') as f:
                stats = json.load(f)
            
            print(f"\n📈 STATISTICS:")
            print(f"  Total writeups: {stats['total_writeups']}")
            print(f"  Teams: {len(stats['by_team'])}")
            print(f"  Attack types: {len(stats['by_attack_type'])}")
            print(f"  With solution code: {stats['with_solution_code']}")
            
            print(f"\n🏆 TOP TEAMS:")
            for team, count in sorted(stats['by_team'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {team}: {count} writeups")
            
            print(f"\n🎯 ATTACK TYPES:")
            for attack_type, count in sorted(stats['by_attack_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"    {attack_type}: {count} writeups")
        
        success = len(lines) >= 100 and valid_json == 5
        print(f"\n{'✅ VALIDATION PASSED' if success else '⚠️ VALIDATION NEEDS REVIEW'}")
        return success

def main():
    """Función principal"""
    print("🔥 PHASE 3.0 - STEP 1: MASSIVE CTF WRITEUPS SCRAPER")
    print("Objetivo: Descargar 500+ writeups reales de equipos top de CTF")
    print("=" * 70)
    
    # Crear directorio de datos
    os.makedirs("data", exist_ok=True)
    
    # Inicializar scraper
    scraper = CTFWriteupScraper(output_dir="data", max_writeups=500)
    
    # Scrapear repositorios
    total_scraped = scraper.scrape_all_repositories()
    
    # Guardar resultados
    output_file = scraper.save_writeups()
    
    # Validar output
    success = scraper.validate_output()
    
    print("\n" + "=" * 70)
    print("🎉 SCRAPING COMPLETED!")
    print(f"📊 Total writeups scraped: {total_scraped}")
    print(f"📁 Output file: {output_file}")
    print(f"✅ Ready for BERT training: {'YES' if success else 'NEEDS REVIEW'}")
    
    if success:
        print("\n🚀 NEXT STEPS:")
        print("1. python ml_phase2/prepare_data_for_bert.py")
        print("2. python ml_phase2/train_bert.py")
        print("3. python rag/prepare_embeddings.py")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)