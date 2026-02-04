#!/usr/bin/env python3
"""
Migrate Training Data to RAG Database
======================================

Imports all experiences from JSONL files into the SQLite database
for the RAG solver to use for similarity search.
"""

import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.learning.experience_storage import (
    ExperienceStorage, 
    SolvedChallengeExperience
)


def migrate_jsonl_to_db(jsonl_path: str, storage: ExperienceStorage) -> int:
    """
    Migrate experiences from JSONL file to SQLite database.
    
    Returns:
        Number of experiences imported
    """
    imported = 0
    skipped = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [!] Line {line_num}: Invalid JSON - {e}")
                skipped += 1
                continue
            
            # Map JSONL fields to SolvedChallengeExperience
            try:
                # Handle solution_steps - ensure it's a list of strings
                solution_steps = data.get('solution_steps', [])
                if isinstance(solution_steps, str):
                    solution_steps = [solution_steps]
                elif not isinstance(solution_steps, list):
                    solution_steps = []
                else:
                    # Convert all items to strings
                    solution_steps = [str(s) for s in solution_steps if s]
                
                # Handle tools_used similarly
                tools_used = data.get('tools_used', [])
                if isinstance(tools_used, list):
                    tools_used = [str(t) for t in tools_used if t]
                else:
                    tools_used = []
                
                exp = SolvedChallengeExperience(
                    challenge_id=data.get('id', ''),
                    challenge_name=data.get('challenge_name', data.get('name', 'Unknown')),
                    challenge_description=data.get('challenge_description', data.get('description', data.get('writeup', '')))[:2000],
                    challenge_type=data.get('challenge_type', data.get('category', data.get('attack_type', 'Unknown'))),
                    difficulty=data.get('difficulty', 'Medium'),
                    source_files=[],  # Not in JSONL format
                    solution_successful=True,
                    flag_found='',
                    solution_steps=solution_steps[:10],  # Limit to 10 steps
                    attack_pattern=data.get('attack_type', data.get('attack_pattern', '')),
                    solution_code=data.get('solution_code', '')[:5000],  # Limit size
                    solve_time_seconds=0.0,
                    confidence_score=0.8,
                    # DO NOT pass code_embedding - let storage compute it fresh
                    code_embedding=None
                )
                
                # Store experience
                exp_id = storage.store_experience(exp)
                imported += 1
                
                if imported % 100 == 0:
                    print(f"  [{imported}] Imported {exp.challenge_name[:50]}...")
                    
            except Exception as e:
                print(f"  [!] Line {line_num}: Failed to import - {e}")
                skipped += 1
                continue
    
    return imported, skipped


def main():
    print("=" * 60)
    print("   MIGRATE TRAINING DATA TO RAG DATABASE")
    print("=" * 60)
    
    # Initialize storage
    storage = ExperienceStorage()
    
    # Get initial stats
    initial_stats = storage.get_statistics()
    print(f"\n[*] Initial experiences in DB: {initial_stats['total_experiences']}")
    
    # Files to migrate
    data_dir = PROJECT_ROOT / "data"
    files_to_migrate = [
        data_dir / "training_data.jsonl",
        data_dir / "combined_training_data.jsonl",
        data_dir / "writeups_enhanced_dataset.jsonl",
    ]
    
    total_imported = 0
    total_skipped = 0
    
    for jsonl_path in files_to_migrate:
        if not jsonl_path.exists():
            print(f"\n[!] File not found: {jsonl_path}")
            continue
        
        print(f"\n[*] Processing: {jsonl_path.name}")
        
        # Count lines first
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            line_count = sum(1 for _ in f)
        print(f"    Lines: {line_count}")
        
        imported, skipped = migrate_jsonl_to_db(str(jsonl_path), storage)
        total_imported += imported
        total_skipped += skipped
        print(f"    Imported: {imported}, Skipped: {skipped}")
    
    # Final stats
    final_stats = storage.get_statistics()
    
    print("\n" + "=" * 60)
    print("   MIGRATION COMPLETE")
    print("=" * 60)
    print(f"\n[+] Total imported: {total_imported}")
    print(f"[+] Total skipped: {total_skipped}")
    print(f"[+] Final experiences in DB: {final_stats['total_experiences']}")
    print(f"\n[*] Experiences by type:")
    for ctype, counts in final_stats.get('by_challenge_type', {}).items():
        print(f"    - {ctype}: {counts['total']}")
    
    print("\n[*] Done! RAG solver now has access to all experiences.")


if __name__ == "__main__":
    main()
