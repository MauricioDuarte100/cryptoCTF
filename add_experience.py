#!/usr/bin/env python3
"""
Add Experience to RAG Database
==============================

Simple CLI tool to add a solved challenge to the RAG database.
Use this after solving a challenge to train the model.

Usage:
    python add_experience.py
    python add_experience.py --name "RSA Baby" --type RSA --attack "Wiener" --code solve.py
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.learning.experience_storage import (
    ExperienceStorage, 
    SolvedChallengeExperience,
    get_experience_storage
)


def main():
    parser = argparse.ArgumentParser(
        description="Add a solved challenge to the RAG database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python add_experience.py
    python add_experience.py --name "RSA-Weak-e" --type RSA --attack "Low Exponent"
    python add_experience.py --name "AES-ECB" --type AES --attack "ECB Byte-at-a-time" --code solve.py
        """
    )
    
    parser.add_argument('--name', '-n', help='Challenge name')
    parser.add_argument('--type', '-t', help='Challenge type (RSA, AES, ECC, XOR, etc.)')
    parser.add_argument('--attack', '-a', help='Attack pattern used')
    parser.add_argument('--code', '-c', help='Path to solution code file')
    parser.add_argument('--flag', '-f', help='Flag found (optional)')
    parser.add_argument('--description', '-d', help='Challenge description')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("   ADD EXPERIENCE TO RAG DATABASE")
    print("=" * 50)
    
    # Get values interactively if not provided
    name = args.name or input("\nChallenge name: ").strip()
    if not name:
        print("[!] Name is required")
        return 1
    
    ctype = args.type or input("Challenge type (RSA/AES/ECC/XOR/Classical/Lattice/Hash): ").strip()
    attack = args.attack or input("Attack pattern (e.g., 'Wiener', 'Low Exponent'): ").strip()
    flag = args.flag or input("Flag found (optional, press Enter to skip): ").strip()
    desc = args.description or input("Brief description (optional): ").strip()
    
    # Get solution code
    code_path = args.code
    solution_code = ""
    
    if code_path:
        try:
            with open(code_path, 'r', encoding='utf-8') as f:
                solution_code = f.read()
            print(f"[+] Loaded solution from: {code_path}")
        except Exception as e:
            print(f"[!] Could not read code file: {e}")
    else:
        paste = input("Paste solution code? (y/N): ").strip().lower()
        if paste == 'y':
            print("Paste your code, then type 'END' on a new line:")
            lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                lines.append(line)
            solution_code = '\n'.join(lines)
    
    # Create experience
    storage = get_experience_storage()
    
    exp = SolvedChallengeExperience(
        challenge_id="",
        challenge_name=name,
        challenge_description=desc or f"{ctype} challenge solved with {attack}",
        challenge_type=ctype or "Unknown",
        difficulty="Medium",
        source_files=[],
        solution_successful=True,
        flag_found=flag,
        solution_steps=[
            f"Identified as {ctype} challenge",
            f"Applied {attack} attack",
            "Recovered flag" if flag else "Solved"
        ],
        attack_pattern=attack or ctype,
        solution_code=solution_code,
        solve_time_seconds=0.0,
        confidence_score=0.9
    )
    
    exp_id = storage.store_experience(exp)
    
    stats = storage.get_statistics()
    
    print("\n" + "=" * 50)
    print("   EXPERIENCE ADDED SUCCESSFULLY")
    print("=" * 50)
    print(f"\n[+] Experience ID: {exp_id}")
    print(f"[+] Total experiences in DB: {stats['total_experiences']}")
    print(f"\n[*] The RAG model will now use this experience")
    print("[*] for similar challenges in the future.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
