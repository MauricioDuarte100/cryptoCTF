# CryptoCTF

AI-powered cryptographic CTF challenge solver using lightweight ML classification and RAG (Retrieval-Augmented Generation).

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Accuracy](https://img.shields.io/badge/accuracy-79%25-brightgreen.svg)

---

## Features

- **Fast Classification**: TF-IDF + Random Forest classifier (79% accuracy, ~3.6MB model)
- **Experience Database**: 1750+ solved challenges with attack patterns from 2023-2025 CTFs
- **RAG System**: Retrieves similar challenges using FAISS embeddings
- **Auto Solver**: Complete pipeline (classify → retrieve → solve)
- **Solver Modules**: RSA, ECDSA, AES, ECC, XOR, Lattice attacks

---

## Quick Start
```bash
# Clone and install
git clone https://github.com/MauricioDuarte100/cryptoCTF.git
cd cryptoCTF
pip install -r requirements.txt

# Auto-solve a challenge
python auto_solve.py challenge.py
```

---

## Training the Model

You can retrain the classifier with your own dataset or updated challenge solutions.

1. **Prepare Data**: Add your JSONL examples to `data/training_data.jsonl`.
   ```json
   {"challenge_name": "...", "description": "...", "solution_steps": ["..."]}
   ```

2. **Run Training**:
   ```bash
   python train_lightweight.py --data data/training_data.jsonl
   ```

3. **Output**: The optimized model is saved to `trained_lightweight/`.

---

## Integration with AI Agents

CryptoCTF is built to accept commands from AI coding assistants like Gemini CLI, Antigravity, Claude Code, or OpenCode.

### Gemini CLI / Antigravity
Since these agents have shell access, you can instruct them to use the auto-solver directly:

> "Solve the challenge in `chall.py` using `auto_solve.py`."

```bash
python auto_solve.py --file chall.py
```

### Claude Code / OpenCode
For agents that ingest context, you can provide the solver modules as a toolkit.

1. **Load Context**: Provide the `solver/modules/` directory to the agent.
2. **Prompt**:
   > "Use the `RSASolver` class to recover the private key from these parameters..."

```python
# Example agent usage pattern
from solver.modules.rsa import RSASolver
solver = RSASolver()
print(solver.solve(n, e, c))
```

---

## Project Structure

```
cryptoCTF/
├── src/
│   ├── core/               # Agent and classifier
│   ├── rag/                # Experience retrieval
│   └── learning/           # Experience storage (SQLite + FAISS)
├── solver/
│   └── modules/
│       ├── rsa.py          # RSA attacks (9 methods)
│       ├── ecdsa.py        # ECDSA attacks (nonce reuse, HNP)
│       ├── aes.py          # AES attacks (padding oracle, ECB, CBC)
│       ├── ecc.py          # ECC attacks (Pohlig-Hellman, Invalid Curve)
│       ├── lattice.py      # LLL/BKZ lattice reduction
│       └── xor.py          # XOR attacks
├── data/
│   └── training_data.jsonl # 1700+ training examples (Updated 2025)
├── auto_solve.py           # Unified auto-solver
├── tests/
│   └── test_modules.py     # Unit tests (20+ tests)
└── train_lightweight.py    # Training script
```

---

## Auto Solver

```bash
# Solve from file
python auto_solve.py challenge.py

# Force type
python auto_solve.py --file output.txt --type RSA

# Interactive mode
python auto_solve.py --interactive
```

The auto solver runs a complete pipeline:
1. **CLASSIFY** - Identifies challenge type (RSA, ECC, AES, etc.)
2. **RETRIEVE** - Finds similar solved challenges
3. **EXTRACT** - Extracts parameters (n, e, c, etc.)
4. **SOLVE** - Applies appropriate attack modules

---

## Solver Modules

### RSA (`solver/modules/rsa.py`)
```python
from solver.modules.rsa import RSASolver

solver = RSASolver()
result = solver.solve(n, e, c)  # Auto-tries multiple attacks

# Individual attacks
solver.hastad_broadcast(ciphertexts, moduli, e)
solver.common_modulus(n, e1, e2, c1, c2)
solver.pollard_rho(n, e, c)
```

### ECDSA (`solver/modules/ecdsa.py`)
```python
from solver.modules.ecdsa import ECDSASolver, ecdsa_nonce_reuse

# Nonce reuse attack (when r1 == r2)
d = ecdsa_nonce_reuse(r, s1, s2, z1, z2, n)

# Biased nonce (HNP + LLL)
solver = ECDSASolver()
d = solver.biased_nonce_attack(signatures, n, bias_bits)
```

### AES (`solver/modules/aes.py`)
```python
from solver.modules.aes import AESSolver, padding_oracle

# Padding oracle attack
plaintext = padding_oracle(oracle_func, ciphertext, iv)

# ECB byte-at-a-time
solver = AESSolver()
secret = solver.ecb_oracle_attack(oracle_func)

# CBC bit flipping
modified = solver.cbc_bit_flip(ct, known, target, position)
```

### Lattice (`solver/modules/lattice.py`)
```python
from solver.modules.lattice import LLL, BKZ, Matrix, solve_hnp

# LLL reduction
M = Matrix([[1, 0, 0, 1021], [0, 1, 0, 2011]])
reduced = LLL(M)

# Hidden Number Problem (ECDSA biased nonce)
d = solve_hnp(signatures, curve_order, nonce_bits)
```

---

## Supported Attacks

| Module | Attacks |
|--------|---------|
| **RSA** | Cube Root, Wiener, Fermat, Pollard p-1, Pollard Rho, Hastad Broadcast, Common Modulus, Franklin-Reiter |
| **ECDSA** | Nonce Reuse, Biased Nonce (HNP), Signature Malleability |
| **AES** | Padding Oracle, ECB Oracle, CBC Bit Flip, GCM Forbidden Attack |
| **ECC** | BSGS, Pohlig-Hellman, Invalid Curve Attack, Smart's Attack |
| **Lattice** | LLL, BKZ, Hidden Number Problem |
| **XOR** | Single-byte, Repeating Key |
| **Classical** | Caesar, Frequency Analysis |

---

## Model Stats

| Metric | Value |
|--------|-------|
| Training Examples | 1782 |
| Test Accuracy | 79% |
| Total Categories | 20+ |
| Model Size | 3.6 MB |
| Training Time | ~5 sec |

---

## Running Tests

```bash
# Run all tests
python tests/test_modules.py

# With pytest
python -m pytest tests/test_modules.py -v
```

---

## Adding Experiences

```python
from src.learning.experience_storage import get_experience_storage

storage = get_experience_storage()
storage.store_experience(
    challenge_name="Challenge Name",
    challenge_type="RSA",
    attack_pattern="Hastad Broadcast",
    solution_steps=["Collect ciphertexts", "Apply CRT", "Take e-th root"],
    flag_found="flag{...}"
)
```

---

## License

MIT License - See [LICENSE](LICENSE)

---

**Mauricio Duarte** - [GitHub](https://github.com/MauricioDuarte100)
