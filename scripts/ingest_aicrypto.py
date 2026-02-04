import os
import yaml
import json
import glob

# Paths
BASE_DIR = r"c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\data\external\aicrypto\CTF"
OUTPUT_FILE = r"c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\data\training_data.jsonl"

def simple_attack_pattern_extraction(text):
    text = text.lower()
    patterns = {
        "common modulus": "Common Modulus Attack",
        "hastad": "Hastad Broadcast",
        "wiener": "Wiener's Attack",
        "boneh": "Boneh-Durfee",
        "padding oracle": "Padding Oracle",
        "ecb": "ECB Byte-at-a-time",
        "nonce reuse": "ECDSA Nonce Reuse",
        "biased nonce": "ECDSA Biased Nonce",
        "invalid curve": "ECC Invalid Curve",
        "small e": "Low Exponent",
        "pollard": "Pollard's Rho",
        "xor": "XOR Analysis",
        "mt19937": "Mersenne Twister Predictor"
    }
    for key, val in patterns.items():
        if key in text:
            return val
    return "Unknown Pattern"

def ingest():
    new_entries = []
    
    # Walk through category directories (e.g., 04-RSA)
    for category_dir in os.listdir(BASE_DIR):
        category_path = os.path.join(BASE_DIR, category_dir)
        if not os.path.isdir(category_path) or category_dir.startswith("._"):
            continue
            
        print(f"Processing category: {category_dir}")
        
        # Walk through challenge directories
        for chall_dir in os.listdir(category_path):
            chall_path = os.path.join(category_path, chall_dir)
            if not os.path.isdir(chall_path) or chall_dir.startswith("._"):
                continue
                
            config_path = os.path.join(chall_path, "config.yaml")
            solution_path = os.path.join(chall_path, "solution", "solution.md")
            
            if not os.path.exists(config_path):
                print(f"Skipping {chall_dir}: No config.yaml")
                continue
                
            # Parse Config
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
            except Exception as e:
                print(f"Error reading config for {chall_dir}: {e}")
                continue
                
            # Parse Solution
            solution_content = ""
            if os.path.exists(solution_path):
                try:
                    with open(solution_path, "r", encoding="utf-8") as f:
                        solution_content = f.read()
                except Exception as e:
                    print(f"Error reading solution for {chall_dir}: {e}")
            
            # Extract Fields
            name = config.get("name", chall_dir)
            category = config.get("category", category_dir.split("-")[-1]) # e.g., 'RSA' from '04-RSA'
            flag = config.get("flag", "Unknown Flag")
            
            # Heuristics for description vs solution
            parts = solution_content.split("## Write-Up")
            if len(parts) > 1:
                description = parts[0].replace("# description", "").replace("## Description", "").strip()
                solution_steps_text = parts[1].strip()
            else:
                description = f"Challenge {name} from category {category}"
                solution_steps_text = solution_content
                
            attack_pattern = simple_attack_pattern_extraction(solution_steps_text)
            
            entry = {
                "challenge_name": name,
                "challenge_type": category,
                "description": description,
                "solution_steps": [line for line in solution_steps_text.splitlines() if line.strip()],
                "attack_pattern": attack_pattern,
                "flag_found": flag
            }
            
            new_entries.append(entry)
            
    print(f"Found {len(new_entries)} new entries.")
    
    # Append to output file
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for entry in new_entries:
            f.write(json.dumps(entry) + "\n")
            
    print(f"Successfully appended {len(new_entries)} entries to {OUTPUT_FILE}")

if __name__ == "__main__":
    ingest()
