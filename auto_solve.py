#!/usr/bin/env python3
"""
CryptoCTF Unified Auto-Solver
==============================

A complete pipeline for solving cryptographic CTF challenges:
1. CLASSIFY - Identify challenge type using ML classifier
2. RETRIEVE - Find similar solved challenges from experience DB
3. SOLVE - Apply appropriate attack modules

Usage:
    python auto_solve.py challenge.py
    python auto_solve.py --host ctf.com --port 1337
    python auto_solve.py --file output.txt --type RSA
    python auto_solve.py --interactive
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path
from typing import Optional, Dict, List, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


class AutoSolver:
    """Unified CTF challenge solver with ML classification and RAG retrieval."""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.classifier = None
        self.retriever = None
        self.solvers = {}
        self._load_components()
    
    def _log(self, msg: str, level: str = "info"):
        if not self.verbose:
            return
        icons = {"info": "[*]", "success": "[+]", "error": "[-]", "warn": "[!]"}
        print(f"{icons.get(level, '[*]')} {msg}")
    
    def _load_components(self):
        """Load ML classifier and solver modules."""
        # Load classifier
        try:
            from train_lightweight import predict
            self.classifier = predict
            self._log("Classifier loaded")
        except Exception as e:
            self._log(f"Classifier not available: {e}", "warn")
        
        # Load experience retriever
        try:
            from src.learning.experience_storage import get_experience_storage
            self.retriever = get_experience_storage()
            self._log("Experience retriever loaded")
        except Exception as e:
            self._log(f"Retriever not available: {e}", "warn")
        
        # Load solver modules
        try:
            from solver.modules.rsa import RSASolver
            self.solvers["RSA"] = RSASolver()
        except:
            pass
        
        try:
            from solver.modules.xor import XORSolver
            self.solvers["XOR"] = XORSolver()
        except:
            pass
        
        try:
            from solver.modules.ecc import ECCSolver
            self.solvers["ECC"] = ECCSolver()
        except:
            pass
        
        try:
            from solver.modules.classical import ClassicalSolver
            self.solvers["Classical"] = ClassicalSolver()
        except:
            pass
        
        self._log(f"Loaded {len(self.solvers)} solver modules")
    
    def classify(self, description: str, code: str = "") -> Dict[str, Any]:
        """
        Step 1: Classify the challenge type using ML.
        
        Returns:
            {"type": str, "confidence": float, "alternatives": list}
        """
        text = f"{description}\n{code}"
        
        if self.classifier:
            try:
                challenge_type, confidence = self.classifier(text)
                return {
                    "type": challenge_type,
                    "confidence": confidence,
                    "alternatives": []
                }
            except Exception as e:
                self._log(f"Classification error: {e}", "error")
        
        # Fallback: keyword-based classification
        return self._classify_keywords(text)
    
    def _classify_keywords(self, text: str) -> Dict[str, Any]:
        """Fallback keyword-based classification."""
        text = text.lower()
        
        patterns = {
            "RSA": ["rsa", "factor", "prime", "modulus", "n=", "e=", "phi"],
            "ECC": ["elliptic", "curve", "ecc", "point", "ed25519"],
            "ECDSA": ["ecdsa", "signature", "nonce", "k="],
            "AES": ["aes", "cbc", "ecb", "padding", "block"],
            "XOR": ["xor", "otp", "stream"],
            "Hash": ["hash", "sha", "md5", "collision"],
            "Classical": ["caesar", "vigenere", "substitution"],
            "Lattice": ["lll", "lattice", "cvp", "svp"]
        }
        
        scores = {}
        for cat, keywords in patterns.items():
            score = sum(1 for kw in keywords if kw in text)
            if score > 0:
                scores[cat] = score
        
        if scores:
            best = max(scores.items(), key=lambda x: x[1])
            return {
                "type": best[0],
                "confidence": min(best[1] / 3.0, 1.0),
                "alternatives": [k for k, v in sorted(scores.items(), key=lambda x: -x[1])[1:3]]
            }
        
        return {"type": "Unknown", "confidence": 0.0, "alternatives": []}
    
    def retrieve(self, challenge_type: str, description: str, k: int = 3) -> List[Dict]:
        """
        Step 2: Retrieve similar solved challenges.
        
        Returns:
            List of similar experiences with attack patterns
        """
        if not self.retriever:
            return []
        
        try:
            results = self.retriever.search_similar(description, top_k=k)
            return [
                {
                    "name": r.challenge_name,
                    "type": r.challenge_type,
                    "attack": r.attack_pattern,
                    "steps": r.solution_steps[:3] if hasattr(r, 'solution_steps') else []
                }
                for r in results
            ]
        except Exception as e:
            self._log(f"Retrieval error: {e}", "warn")
            return []
    
    def solve(self, 
              challenge_type: str,
              params: Dict[str, Any],
              similar_attacks: List[str] = None) -> Optional[str]:
        """
        Step 3: Attempt to solve using appropriate modules.
        
        Args:
            challenge_type: Classified type (RSA, ECC, etc)
            params: Extracted parameters (n, e, c, etc)
            similar_attacks: Attack patterns from similar challenges
        
        Returns:
            Flag if found, None otherwise
        """
        solver = self.solvers.get(challenge_type)
        
        if not solver:
            self._log(f"No solver for type: {challenge_type}", "warn")
            return None
        
        try:
            if challenge_type == "RSA":
                n = params.get("n")
                e = params.get("e")
                c = params.get("c")
                if n and e and c:
                    result = solver.solve(n, e, c)
                    if result:
                        return result
            
            elif challenge_type == "XOR":
                ciphertext = params.get("ciphertext")
                known = params.get("known_plaintext")
                if ciphertext and known:
                    result = solver.solve(ciphertext, known)
                    if result:
                        return result
            
            elif challenge_type == "ECC":
                # ECC solver needs curve params
                pass
            
        except Exception as e:
            self._log(f"Solve error: {e}", "error")
        
        return None
    
    def extract_params(self, code: str) -> Dict[str, Any]:
        """Extract cryptographic parameters from code/text."""
        import re
        
        params = {}
        
        # RSA parameters
        n_match = re.search(r'n\s*=\s*(\d+)', code)
        if n_match:
            params["n"] = int(n_match.group(1))
        
        e_match = re.search(r'e\s*=\s*(\d+)', code)
        if e_match:
            params["e"] = int(e_match.group(1))
        
        c_match = re.search(r'c\s*=\s*(\d+)', code)
        if c_match:
            params["c"] = int(c_match.group(1))
        
        # Try to find hex-encoded values
        hex_matches = re.findall(r'["\']([0-9a-fA-F]{16,})["\']', code)
        if hex_matches:
            params["hex_values"] = hex_matches
        
        return params
    
    def run_pipeline(self, 
                     file_path: str = None,
                     description: str = None,
                     code: str = None,
                     force_type: str = None) -> Dict[str, Any]:
        """
        Run the complete solve pipeline.
        
        Returns:
            {
                "classification": {...},
                "similar": [...],
                "params": {...},
                "result": str or None,
                "time": float
            }
        """
        start_time = time.time()
        
        # Load file if provided
        if file_path:
            path = Path(file_path)
            if path.exists():
                code = path.read_text(encoding='utf-8', errors='ignore')
                description = f"Challenge from {path.name}"
            else:
                return {"error": f"File not found: {file_path}"}
        
        if not description and not code:
            return {"error": "No input provided"}
        
        description = description or ""
        code = code or ""
        
        print("\n" + "="*60)
        print("   CRYPTOCTF AUTO-SOLVER PIPELINE")
        print("="*60)
        
        # Step 1: Classify
        print("\n[STEP 1] Classifying challenge...")
        if force_type:
            classification = {"type": force_type, "confidence": 1.0, "alternatives": []}
        else:
            classification = self.classify(description, code)
        
        print(f"   Type: {classification['type']} ({classification['confidence']:.0%})")
        if classification.get('alternatives'):
            print(f"   Alternatives: {', '.join(classification['alternatives'])}")
        
        # Step 2: Retrieve similar
        print("\n[STEP 2] Retrieving similar challenges...")
        similar = self.retrieve(classification['type'], description + code)
        
        if similar:
            print(f"   Found {len(similar)} similar challenges:")
            for s in similar[:3]:
                print(f"   - {s['name']}: {s['attack']}")
        else:
            print("   No similar challenges found")
        
        # Step 3: Extract parameters
        print("\n[STEP 3] Extracting parameters...")
        params = self.extract_params(code)
        
        if params:
            for k, v in params.items():
                if isinstance(v, int) and v > 1000000:
                    print(f"   {k} = {v} ({v.bit_length()} bits)")
                else:
                    print(f"   {k} = {v}")
        else:
            print("   No parameters extracted")
        
        # Step 4: Solve
        print("\n[STEP 4] Attempting to solve...")
        attack_hints = [s['attack'] for s in similar] if similar else []
        result = self.solve(classification['type'], params, attack_hints)
        
        elapsed = time.time() - start_time
        
        if result:
            print(f"\n{'='*60}")
            print(f"   FLAG FOUND: {result}")
            print(f"{'='*60}")
        else:
            print("\n   Could not automatically solve.")
            print("   Suggestions:")
            print("   - Check extracted parameters")
            print("   - Try manual solver scripts in solver/")
            if similar:
                print(f"   - Review similar challenge: {similar[0]['name']}")
        
        print(f"\n[*] Completed in {elapsed:.2f}s")
        
        return {
            "classification": classification,
            "similar": similar,
            "params": params,
            "result": result,
            "time": elapsed
        }


def interactive_mode():
    """Interactive menu for solving challenges."""
    solver = AutoSolver()
    
    while True:
        print("\n" + "="*50)
        print("   CRYPTOCTF AUTO-SOLVER")
        print("="*50)
        print("\n[1] Solve a challenge file")
        print("[2] Solve from description/code")
        print("[3] List available solver modules")
        print("[4] Check system status")
        print("[5] Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == "1":
            # List challenge files
            challenges_dir = Path("challenges")
            if not challenges_dir.exists():
                print("\n[!] 'challenges' folder not found")
                continue
            
            files = [f for f in challenges_dir.iterdir() 
                     if f.is_file() and not f.name.startswith('.')]
            
            if not files:
                print("\n[!] No files in 'challenges' folder")
                continue
            
            print("\nAvailable files:")
            for i, f in enumerate(files, 1):
                print(f"  [{i}] {f.name}")
            
            idx = input(f"\nSelect file (1-{len(files)}): ").strip()
            try:
                file_path = files[int(idx) - 1]
                force_type = input("Force type (or Enter to auto): ").strip() or None
                solver.run_pipeline(file_path=str(file_path), force_type=force_type)
            except (ValueError, IndexError):
                print("[!] Invalid selection")
        
        elif choice == "2":
            print("\nPaste challenge description (Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            
            description = "\n".join(lines)
            if description:
                force_type = input("Force type (or Enter to auto): ").strip() or None
                solver.run_pipeline(description=description, force_type=force_type)
        
        elif choice == "3":
            print("\nAvailable solver modules:")
            for name, mod in solver.solvers.items():
                print(f"  - {name}: {type(mod).__name__}")
        
        elif choice == "4":
            print("\nSystem Status:")
            print(f"  Classifier: {'Loaded' if solver.classifier else 'Not available'}")
            print(f"  Retriever: {'Loaded' if solver.retriever else 'Not available'}")
            print(f"  Solvers: {len(solver.solvers)} modules")
            
            from solver.modules.lattice import get_backend_info
            info = get_backend_info()
            print(f"  Lattice backend: {info['recommended']}")
            print(f"    fpylll: {'Yes' if info['fpylll'] else 'No'}")
        
        elif choice == "5":
            print("\nGoodbye!")
            break


def main():
    parser = argparse.ArgumentParser(
        description="CryptoCTF Auto-Solver - Unified challenge solving pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python auto_solve.py challenge.py
    python auto_solve.py --file output.txt --type RSA
    python auto_solve.py --interactive
    python auto_solve.py --status
        """
    )
    
    parser.add_argument("file", nargs="?", help="Challenge file to solve")
    parser.add_argument("-f", "--file", dest="file_arg", help="Challenge file (alternative)")
    parser.add_argument("-t", "--type", help="Force challenge type (RSA, ECC, AES, etc)")
    parser.add_argument("-d", "--description", help="Challenge description text")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-s", "--status", action="store_true", help="Show system status")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--host", help="Remote host for netcat challenges")
    parser.add_argument("--port", type=int, help="Remote port")
    
    args = parser.parse_args()
    
    # Status check
    if args.status:
        solver = AutoSolver(verbose=False)
        print("CryptoCTF Auto-Solver Status")
        print("-" * 30)
        print(f"Classifier: {'OK' if solver.classifier else 'Not loaded'}")
        print(f"Retriever: {'OK' if solver.retriever else 'Not loaded'}")
        print(f"Solvers: {list(solver.solvers.keys())}")
        
        from solver.modules.lattice import get_backend_info
        info = get_backend_info()
        print(f"Lattice: {info['recommended']} (fpylll: {info['fpylll']})")
        return
    
    # Interactive mode
    if args.interactive or (not args.file and not args.file_arg and not args.description):
        interactive_mode()
        return
    
    # Pipeline mode
    solver = AutoSolver(verbose=not args.quiet)
    
    file_path = args.file or args.file_arg
    result = solver.run_pipeline(
        file_path=file_path,
        description=args.description,
        force_type=args.type
    )
    
    # Exit with appropriate code
    sys.exit(0 if result.get("result") else 1)


if __name__ == "__main__":
    main()
