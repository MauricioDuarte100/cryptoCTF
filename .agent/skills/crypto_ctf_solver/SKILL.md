---
name: Crystal - Crypto CTF Solver
description: Specialized skill for solving Capture The Flag (CTF) cryptography challenges using RAG, automated analysis, and a structured solver workflow.
---

# Crystal: Crypto CTF Solver Skill

This skill provides a standardized workflow for solving cryptography challenges by leveraging a Retrieval-Augmented Generation (RAG) system trained on thousands of solved CTF challenges.

## 1. Core Workflow

When presented with a crypto challenge, always follow this **Analysis -> Retrieval -> Solve -> Learn** loop:

### Phase 1: Analysis & Classification
1. **Locate Challenge Files**: Identify the key files (source code, output logs, encrypted files).
2. **Auto-Analysis**: Run the auto-solver to classify the challenge and check for easy wins.
   ```bash
   python auto_solve.py path/to/challenge_source.py
   ```
3. **Manual Verification**: If `auto_solve.py` fails, manually inspect the code to identify the vulnerability type (RSA bad padding, XOR reuse, LCG prediction, etc.).

### Phase 2: RAG Retrieval
Use the RAG system to find relevant solution patterns. The RAG database contains over 4000 solved challenges.

```python
from src.rag.rag_solver import RAGSolver
rag = RAGSolver()
# Find similar challenges based on description or code
similar = rag.get_solution_context(""Challenge Description or Code Snippet"")
print(similar)
```

### Phase 3: Solver Construction
Create a standalone solver script in `solver/solve_<challenge_name>.py`.
- **Structure**:
  - `Imports`: Use standard libraries (`Crypto.Util.number`, `pwn`, `sympy`).
  - `Inputs`: Hardcode known values (n, e, c) or load them from files.
  - `Attack Logic`: Implement the mathematical attack clearly.
  - `Output`: Print the final flag.

### Phase 4: Training (Crucial)
After solving the challenge, **you MUST add the experience to the RAG database**. This allows the AI to learn and solve similar future challenges instantly.

```bash
python add_experience.py \
  --name "Challenge Name" \
  --type "RSA/AES/ECC/..." \
  --attack "Name of attack used (e.g., Wiener's Attack)" \
  --code solver/solve_<challenge_name>.py \
  --flag "CTF{flag_value}" \
  --description "Brief explanation of the vulnerability and solution"
```

## 2. Tools & Scripts

| Script | Purpose |
| :--- | :--- |
| `auto_solve.py` | First-pass tool. Classifies challenge, queries RAG, and attempts auto-solution. |
| `add_experience.py` | **MANDATORY** after solving. Feeds the solution back into the brain. |
| `solver/modules/*.py` | Library of reusable attack modules (RSA, XOR, etc.). |
| `src/rag/rag_solver.py` | Core RAG interface for programmatic queries. |

## 3. Best Practices

- **One Script per Challenge**: Keep solvers isolated in `solver/` with descriptive names.
- **Explain the Math**: In the `add_experience.py` description, explain *why* the attack works (e.g., "m^e < n allowing e-th root").
- **Check Precision**: For math-heavy challenges, use `Decimal` or `gmpy2` to avoid floating-point errors.
- **Side-Channel**: For timing/power attacks, collect data first, then analyze off-line.

## 4. Example: Solving an RSA Challenge

1. **Analyze**: "This looks like RSA with e=3 and small m."
2. **Check**: `python auto_solve.py challenge.py` -> "Detected RSA Low Exponent".
3. **Solve**: Create `solver/solve_rsa_cube.py` implementing cube root attack.
4. **Train**:
   ```bash
   python add_experience.py --name "Simple Cube Root" --type RSA --attack "Low Public Exponent" --code solver/solve_rsa_cube.py
   ```
