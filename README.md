# CryptoCTF

AI-powered cryptographic CTF challenge solver using lightweight ML classification and RAG (Retrieval-Augmented Generation).

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Accuracy](https://img.shields.io/badge/accuracy-94.9%25-brightgreen.svg)

---

## Features

- **Fast Classification**: TF-IDF + Random Forest classifier (94.9% accuracy, <1MB model)
- **Experience Database**: 44+ solved challenges with attack patterns
- **RAG System**: Retrieves similar challenges using FAISS embeddings
- **Solver Modules**: Reusable attack implementations (RSA, XOR, Hash, ECC)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/MauricioDuarte100/cryptoCTF.git
cd cryptoCTF
pip install -r requirements.txt

# Classify a challenge
python train_lightweight.py --test

# Train the model (optional)
python train_lightweight.py
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
│   ├── modules/            # Attack modules (rsa.py, xor.py, etc.)
│   └── solve_*.py          # Individual challenge solutions
├── challenges/             # CTF challenge files
├── data/
│   └── training_data.jsonl # 1176 training examples
├── trained_lightweight/    # Trained classifier (~1MB)
├── train_lightweight.py    # Main training script
└── register_experiences.py # Add solved challenges
```

---

## Usage

### Classify a Challenge

```python
from train_lightweight import predict

challenge = "RSA with small exponent e=3, broadcast attack"
type_, confidence = predict(challenge)
print(f"{type_} ({confidence:.0%})")  # RSA (87%)
```

### Use Solver Modules

```python
from solver.modules.rsa import wiener_attack
from solver.modules.xor import find_xor_key

# Wiener attack for small d
d = wiener_attack(n, e)

# XOR known-plaintext attack
key = find_xor_key(ciphertext, known_plaintext)
```

### Retrieve Similar Challenges

```python
from src.learning.experience_storage import get_experience_storage

storage = get_experience_storage()
similar = storage.search_similar("AES padding oracle attack", top_k=3)

for exp in similar:
    print(f"{exp.challenge_name}: {exp.attack_pattern}")
```

---

## Model Stats

| Metric | Value |
|--------|-------|
| Training Examples | 1176 |
| Test Accuracy | 94.9% |
| Cross-Validation | 94.6% |
| Model Size | 1.08 MB |
| Training Time | ~3 sec |

### Categories

| Type | Examples | Type | Examples |
|------|----------|------|----------|
| crypto | 1088 | RSA | 31 |
| Hash | 34 | ECC | 27 |
| AES | 20 | XOR | 12 |
| misc | 36 | DSA | 2 |

---

## Adding New Challenges

1. Edit `register_experiences.py`:

```python
new_exp = SolvedChallengeExperience(
    challenge_name="Challenge Name",
    challenge_type="RSA",
    attack_pattern="Attack Name",
    solution_steps=["Step 1", "Step 2"],
    flag_found="flag{...}"
)
storage.store_experience(new_exp)
```

2. Run: `python register_experiences.py`

3. Retrain: `python train_lightweight.py`

---

## Supported Attacks

| Type | Attacks |
|------|---------|
| **RSA** | Wiener, Fermat, Hastad, Common Factor, Bleichenbacher |
| **XOR** | Known Plaintext, Frequency Analysis, Repeating Key |
| **Hash** | Length Extension, Birthday Attack, Collision |
| **AES** | Padding Oracle, ECB Detection, Bit Flipping |
| **ECC** | Invalid Curve, Small Subgroup, Nonce Reuse |

---

## License

MIT License - See [LICENSE](LICENSE)

---

**Mauricio Duarte** - [GitHub](https://github.com/MauricioDuarte100)