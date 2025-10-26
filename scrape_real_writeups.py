#!/usr/bin/env python3
"""
REAL CTF WRITEUPS SCRAPER
Descarga 500+ writeups de repositorios TOP de equipos CTF profesionales
"""

import os
import json
import time
import requests
import subprocess
from pathlib import Path
from datetime import datetime
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class CTFWriteupScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.writeups = []
        self.stats = {
            'total_repos': 0,
            'total_writeups': 0,
            'by_attack_type': {},
            'by_team': {},
            'errors': []
        }
    
    def clone_or_update_repo(self, repo_url, local_path):
        """Clona o actualiza un repositorio"""
        try:
            if Path(local_path).exists():
                print(f"📁 Updating existing repo: {local_path}")
                result = subprocess.run(['git', 'pull'], cwd=local_path, 
                                      capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    print(f"⚠️ Git pull failed, re-cloning...")
                    import shutil
                    shutil.rmtree(local_path, ignore_errors=True)
                    return self.clone_or_update_repo(repo_url, local_path)
            else:
                print(f"📥 Cloning repo: {repo_url}")
                result = subprocess.run(['git', 'clone', repo_url, local_path], 
                                      capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    print(f"❌ Failed to clone {repo_url}: {result.stderr}")
                    return False
            
            return True
        except Exception as e:
            print(f"❌ Error with repo {repo_url}: {e}")
            return False
    
    def detect_attack_type(self, content):
        """Detecta el tipo de ataque basado en el contenido"""
        content_lower = content.lower()
        
        # Patrones específicos para cada tipo
        attack_patterns = {
            'RSA': ['rsa', 'factorization', 'fermat', 'wiener', 'small exponent', 'common modulus'],
            'AES': ['aes', 'advanced encryption', 'rijndael', 'block cipher', 'ecb', 'cbc'],
            'Classical': ['caesar', 'vigenere', 'substitution', 'transposition', 'rot13'],
            'Hash': ['md5', 'sha1', 'sha256', 'hash collision', 'length extension'],
            'XOR': ['xor', 'one time pad', 'stream cipher', 'keystream'],
            'ECC': ['elliptic curve', 'ecdsa', 'ecdh', 'point addition'],
            'Misc': ['base64', 'encoding', 'steganography', 'forensics'],
            'Web': ['sql injection', 'xss', 'csrf', 'web application'],
            'Pwn': ['buffer overflow', 'rop', 'shellcode', 'binary exploitation'],
            'Reverse': ['reverse engineering', 'disassembly', 'ida', 'ghidra']
        }
        
        scores = {}
        for attack_type, keywords in attack_patterns.items():
            score = sum(1 for keyword in keywords if keyword in content_lower)
            if score > 0:
                scores[attack_type] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'Unknown'
    
    def extract_tools_used(self, content):
        """Extrae herramientas mencionadas en el writeup"""
        content_lower = content.lower()
        
        tools = []
        tool_patterns = {
            'sage': r'\bsage\b',
            'python': r'\bpython\b',
            'pycryptodome': r'pycryptodome|crypto\.util',
            'gmpy2': r'\bgmpy2\b',
            'z3': r'\bz3\b',
            'factordb': r'factordb',
            'rsactftool': r'rsactftool',
            'john': r'john the ripper|john',
            'hashcat': r'hashcat',
            'burp': r'burp suite|burp',
            'ida': r'\bida\b',
            'ghidra': r'ghidra',
            'gdb': r'\bgdb\b',
            'radare2': r'radare2|r2',
            'wireshark': r'wireshark',
            'nmap': r'\bnmap\b'
        }
        
        for tool, pattern in tool_patterns.items():
            if re.search(pattern, content_lower):
                tools.append(tool)
        
        return tools
    
    def process_file(self, file_path, team_name, repo_name):
        """Procesa un archivo individual para extraer writeup"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Filtrar archivos muy pequeños o que no parecen writeups
            if len(content) < 100:
                return None
            
            # Extraer información
            file_name = file_path.name
            challenge_name = self.extract_challenge_name(file_name, content)
            attack_type = self.detect_attack_type(content)
            tools = self.extract_tools_used(content)
            
            # Extraer código Python si existe
            python_code = self.extract_python_code(content)
            
            writeup_data = {
                'id': f"{team_name}_{repo_name}_{challenge_name}".replace(' ', '_').replace('/', '_'),
                'team': team_name,
                'repo': repo_name,
                'challenge_name': challenge_name,
                'attack_type': attack_type,
                'writeup': content[:5000],  # Limitar tamaño
                'solution_code': python_code,
                'tools': tools,
                'file_path': str(file_path),
                'file_size': len(content),
                'scraped_at': datetime.now().isoformat()
            }
            
            return writeup_data
            
        except Exception as e:
            print(f"⚠️ Error processing {file_path}: {e}")
            return None
    
    def extract_challenge_name(self, file_name, content):
        """Extrae el nombre del challenge"""
        # Intentar extraer del nombre del archivo
        name = file_name.replace('.md', '').replace('.py', '').replace('.txt', '')
        name = re.sub(r'[_-]', ' ', name)
        
        # Intentar extraer del contenido
        title_patterns = [
            r'# (.+)',
            r'## (.+)',
            r'Challenge: (.+)',
            r'Problem: (.+)',
            r'Title: (.+)'
        ]
        
        for pattern in title_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return name
    
    def extract_python_code(self, content):
        """Extrae código Python del writeup"""
        # Buscar bloques de código Python
        python_blocks = []
        
        # Markdown code blocks
        python_pattern = r'```python\n(.*?)\n```'
        matches = re.findall(python_pattern, content, re.DOTALL)
        python_blocks.extend(matches)
        
        # Bloques indentados
        indented_pattern = r'\n((?:    .+\n)+)'
        matches = re.findall(indented_pattern, content)
        for match in matches:
            if any(keyword in match.lower() for keyword in ['import', 'def ', 'print', 'from ']):
                python_blocks.append(match)
        
        return '\n\n'.join(python_blocks) if python_blocks else ''
    
    def scrape_repo(self, repo_info):
        """Scrape un repositorio específico"""
        repo_url, team_name = repo_info
        repo_name = repo_url.split('/')[-1]
        local_path = f"temp_repos/{team_name}_{repo_name}"
        
        print(f"\n🎯 Scraping: {team_name} - {repo_name}")
        print(f"📍 URL: {repo_url}")
        
        # Clonar repositorio
        if not self.clone_or_update_repo(repo_url, local_path):
            self.stats['errors'].append(f"Failed to clone {repo_url}")
            return
        
        # Buscar archivos de writeups
        writeup_files = []
        search_patterns = ['**/*.md', '**/*.py', '**/*.txt']
        search_dirs = ['crypto', 'writeups', 'challenges', 'solutions', 'ctf']
        
        repo_path = Path(local_path)
        
        # Buscar en directorios específicos primero
        for search_dir in search_dirs:
            for pattern in search_patterns:
                writeup_files.extend(repo_path.glob(f"**/{search_dir}/**/{pattern}"))
        
        # Buscar en todo el repo si no encontramos suficientes
        if len(writeup_files) < 5:
            for pattern in search_patterns:
                writeup_files.extend(repo_path.glob(pattern))
        
        print(f"📁 Found {len(writeup_files)} potential writeup files")
        
        # Procesar archivos
        repo_writeups = 0
        for file_path in writeup_files[:50]:  # Limitar a 50 archivos por repo
            writeup_data = self.process_file(file_path, team_name, repo_name)
            if writeup_data:
                self.writeups.append(writeup_data)
                repo_writeups += 1
                
                # Actualizar estadísticas
                attack_type = writeup_data['attack_type']
                self.stats['by_attack_type'][attack_type] = self.stats['by_attack_type'].get(attack_type, 0) + 1
                self.stats['by_team'][team_name] = self.stats['by_team'].get(team_name, 0) + 1
        
        print(f"✅ Extracted {repo_writeups} writeups from {team_name}")
        self.stats['total_repos'] += 1
        self.stats['total_writeups'] += repo_writeups
    
    def scrape_all_repos(self):
        """Scrape todos los repositorios objetivo"""
        # Lista de repositorios TOP (en orden de prioridad)
        target_repos = [
            ('https://github.com/r3kapig/writeup', 'r3kapig'),
            ('https://github.com/project-sekai-ctf/sekaictf-2025', 'project-sekai'),
            ('https://github.com/kalmarunionenctf/kalmarctf', 'kalmar'),
            ('https://github.com/L3AK-TEAM/L3akCTF-2024-public', 'l3ak-team'),
            ('https://github.com/justcatthefish/justctf-2023', 'justcatthefish'),
            ('https://github.com/sajjadium/ctf-archives', 'ctf-archives'),
            ('https://github.com/p4-team/ctf', 'p4-team'),
            ('https://github.com/TeamGreyFang/CTF-Writeups', 'greyfang'),
            ('https://github.com/VulnHub/ctf-writeups', 'vulnhub'),
            ('https://github.com/ctfs/write-ups-2023', 'ctfs-2023')
        ]
        
        print("🚀 STARTING REAL CTF WRITEUPS SCRAPING")
        print("=" * 60)
        print(f"Target: 500+ writeups from {len(target_repos)} TOP teams")
        print("=" * 60)
        
        # Crear directorio temporal
        Path("temp_repos").mkdir(exist_ok=True)
        
        # Scrape cada repositorio
        for repo_info in target_repos:
            try:
                self.scrape_repo(repo_info)
                
                # Parar si ya tenemos suficientes writeups
                if len(self.writeups) >= 500:
                    print(f"🎯 Target reached: {len(self.writeups)} writeups collected!")
                    break
                    
                # Pequeña pausa entre repos
                time.sleep(2)
                
            except Exception as e:
                print(f"❌ Error scraping repo {repo_info[0]}: {e}")
                self.stats['errors'].append(f"Error scraping {repo_info[0]}: {str(e)}")
                continue
    
    def save_writeups(self, output_file="data/writeups_real_ctf_teams.jsonl"):
        """Guarda los writeups en formato JSONL"""
        # Crear directorio si no existe
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        print(f"\n💾 Saving {len(self.writeups)} writeups to {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for writeup in self.writeups:
                f.write(json.dumps(writeup, ensure_ascii=False) + '\n')
        
        print(f"✅ Saved to {output_file}")
        
        # Guardar estadísticas
        stats_file = output_file.replace('.jsonl', '_stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Statistics saved to {stats_file}")
    
    def show_statistics(self):
        """Muestra estadísticas del scraping"""
        print("\n" + "=" * 60)
        print("📊 SCRAPING STATISTICS")
        print("=" * 60)
        print(f"Total Repositories: {self.stats['total_repos']}")
        print(f"Total Writeups: {self.stats['total_writeups']}")
        print()
        
        print("📈 By Attack Type:")
        for attack_type, count in sorted(self.stats['by_attack_type'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {attack_type}: {count}")
        
        print("\n🏆 By Team:")
        for team, count in sorted(self.stats['by_team'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {team}: {count}")
        
        if self.stats['errors']:
            print(f"\n⚠️ Errors ({len(self.stats['errors'])}):")
            for error in self.stats['errors'][:5]:  # Mostrar solo los primeros 5
                print(f"  {error}")
        
        print("=" * 60)
    
    def validate_output(self, output_file="data/writeups_real_ctf_teams.jsonl"):
        """Valida el archivo de salida"""
        print(f"\n🔍 Validating output file: {output_file}")
        
        if not Path(output_file).exists():
            print("❌ Output file does not exist!")
            return False
        
        try:
            line_count = 0
            valid_json_count = 0
            attack_types = set()
            
            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line_count += 1
                    try:
                        data = json.loads(line.strip())
                        valid_json_count += 1
                        attack_types.add(data.get('attack_type', 'Unknown'))
                    except json.JSONDecodeError:
                        print(f"⚠️ Invalid JSON at line {line_count}")
            
            print(f"✅ Total lines: {line_count}")
            print(f"✅ Valid JSON lines: {valid_json_count}")
            print(f"✅ Unique attack types: {len(attack_types)}")
            print(f"✅ Attack types: {', '.join(sorted(attack_types))}")
            
            if line_count >= 500:
                print("🎯 SUCCESS: Target of 500+ writeups achieved!")
                return True
            else:
                print(f"⚠️ Only {line_count} writeups collected (target: 500+)")
                return False
                
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return False

def main():
    """Función principal"""
    scraper = CTFWriteupScraper()
    
    try:
        # Scrape todos los repositorios
        scraper.scrape_all_repos()
        
        # Mostrar estadísticas
        scraper.show_statistics()
        
        # Guardar resultados
        scraper.save_writeups()
        
        # Validar salida
        success = scraper.validate_output()
        
        # Limpiar archivos temporales
        print("\n🧹 Cleaning up temporary files...")
        import shutil
        try:
            shutil.rmtree('temp_repos', ignore_errors=True)
        except:
            pass
        
        if success:
            print("\n🎉 SCRAPING COMPLETED SUCCESSFULLY!")
            print("✅ 500+ real CTF writeups collected")
            print("✅ Ready for BERT training")
        else:
            print("\n⚠️ SCRAPING COMPLETED WITH WARNINGS")
            print("📊 Check statistics for details")
        
        return success
        
    except KeyboardInterrupt:
        print("\n🛑 Scraping interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)