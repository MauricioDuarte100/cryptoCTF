"""
Script to export experiences from storage to training dataset.
"""

from src.learning.experience_storage import get_experience_storage
import json
import os

def export_data():
    storage = get_experience_storage()
    print("🧠 Connected to Experience Storage")
    
    # We need to access the database directly or add a method to ExperienceStorage
    # Since ExperienceStorage interface might not have 'get_all', let's use sqlite3 directly
    # to be safe and quick.
    
    import sqlite3
    db_path = "ctf_experiences.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT challenge_name, challenge_description, challenge_type, attack_pattern, solution_steps_json, flag_found FROM experiences")
    rows = cursor.fetchall()
    
    new_data = []
    for row in rows:
        name, desc, ctype, attack, steps_json, flag = row
        steps = json.loads(steps_json)
        
        # Format for training dataset
        entry = {
            "challenge_name": name,
            "description": desc,
            "attack_type": ctype, # Or attack_pattern, depending on what we want to classify
            # Let's map strict types:
            # "Block Cipher" -> "AES" (or "Other")
            # "VDF" -> "Other" (or create new category)
            # Actually, train_models.py uses 'attack_type' or 'category'.
            # Current allowed labels: RSA, XOR, AES, Classical, Hash, ECC, Encoding, Other
            "category": ctype,
            "attack_pattern": attack,
            "solution_steps": steps,
            "flag": flag,
            "synthetic": False
        }
        new_data.append(entry)
    
    print(f"✅ Found {len(new_data)} experiences in storage")
    
    # Append to existing dataset
    dataset_path = "data/writeups_enhanced_dataset.jsonl"
    
    # Read existing to avoid duplicates (naive check)
    existing_ids = set()
    if os.path.exists(dataset_path):
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        obj = json.loads(line)
                        existing_ids.add(obj.get('challenge_name'))
                    except:
                        pass
    
    with open(dataset_path, 'a', encoding='utf-8') as f:
        count = 0
        for entry in new_data:
            if entry['challenge_name'] not in existing_ids:
                f.write(json.dumps(entry) + "\n")
                count += 1
                print(f"   Added: {entry['challenge_name']}")
            else:
                print(f"   Skipped (already exists): {entry['challenge_name']}")
                
    print(f"🎉 Added {count} new examples to {dataset_path}")

if __name__ == "__main__":
    export_data()
