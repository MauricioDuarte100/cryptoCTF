---
description: How to train the RAG model after solving a crypto challenge
---

# Train RAG After Solving a Challenge

After you solve a CTF crypto challenge (either manually or with AI help), you should train the RAG model so it can help with similar challenges in the future.

## Quick Train (One Command)

// turbo
```bash
python add_experience.py --name "Challenge Name" --type RSA --attack "Wiener's Attack" --code solve.py
```

## Step-by-Step Training

### 1. Prepare Your Solution

Make sure you have:
- [ ] The challenge source code (e.g., `challenge.py`)
- [ ] Your solution code (e.g., `solve.py`)
- [ ] The flag you found
- [ ] A brief description of the attack

### 2. Add Experience to RAG Database

// turbo
Run the training script:
```bash
python add_experience.py
```

This will prompt you for:
- **Challenge name**: e.g., "RSA-Wiener-2025"
- **Challenge type**: RSA, AES, ECC, XOR, Classical, Lattice, Hash, etc.
- **Attack pattern**: e.g., "Wiener's Attack", "Low Exponent", "Nonce Reuse"
- **Solution code path**: Path to your solve script

### 3. Verify Training

// turbo
Check that your experience was added:
```bash
python -c "from src.learning.experience_storage import get_experience_storage; s = get_experience_storage(); print(f'Total experiences: {s.get_statistics()[\"total_experiences\"]}')"
```

## Automatic Training

The auto-solver will automatically train when it finds a flag:
- When `auto_solve.py` successfully solves a challenge, it saves the experience
- No manual intervention needed for auto-solved challenges

## For AI/IDE Users (Antigravity, Cursor, Claude)

When the AI solves a challenge in your IDE:

1. **Copy the solution** from the chat to a file (e.g., `solve.py`)
2. **Run the solution** to get the flag
3. **Train the RAG** with:

// turbo
```bash
python add_experience.py --name "ChallengeNameFromCTF" --type RSA --attack "Attack Used" --code solve.py --flag "flag{...}"
```

4. **Clean the Workspace**:
Delete the challenge source files and your `solve.py` script to keep the Git workspace clean, as the solution is now safely stored in the `ctf_experiences.db`.

## Example: Training After Solving "Baby RSA"

```bash
# You solved a challenge with Wiener's attack
python add_experience.py \
    --name "Baby RSA - CTF2025" \
    --type RSA \
    --attack "Wiener's Attack - small d" \
    --code ./solve_baby_rsa.py \
    --flag "CTF{w13n3r_4tt4ck}"
```

## Bulk Import from JSONL

If you have multiple challenges in JSONL format:

// turbo
```bash
python migrate_to_rag_db.py
```

## Check RAG Statistics

// turbo
```bash
python -c "from src.rag.rag_solver import RAGSolver; s = RAGSolver(); print(s.get_statistics())"
```
