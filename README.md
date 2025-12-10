# CryptoCTF

An AI-powered system for analyzing and solving cryptographic CTF challenges using Machine Learning and Retrieval-Augmented Generation (RAG).

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![PyTorch](https://img.shields.io/badge/pytorch-2.0+-red.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## Overview

CryptoCTF is a framework that combines machine learning classification with a knowledge base of solved challenges to assist in solving cryptographic CTF problems. The system:

1. **Classifies** challenges by type (RSA, Hash, Classical, XOR, etc.)
2. **Retrieves** similar solved challenges from an experience database
3. **Suggests** attack patterns based on historical solutions
4. **Provides** reusable solver modules for common cryptographic attacks

---

## Project Structure

```
cryptoCTF/
│
├── src/                              # Core source code
│   ├── core/                         # Agent and classification engine
│   │   ├── enhanced_agent.py         # Main solving agent
│   │   └── challenge_classifier.py   # Type classification
│   │
│   ├── rag/                          # Retrieval-Augmented Generation
│   │   ├── experience_retriever.py   # Similar challenge lookup
│   │   └── challenge_embeddings.py   # Vector embeddings
│   │
│   ├── learning/                     # Experience management
│   │   └── experience_storage.py     # SQLite + FAISS storage
│   │
│   └── training/                     # ML model training
│       ├── train_classifier.py       # Challenge type classifier
│       └── train_predictor.py        # Attack pattern predictor
│
├── solver/                           # Challenge-specific solvers
│   ├── modules/                      # Reusable attack modules
│   │   ├── rsa.py                    # RSA attacks
│   │   ├── dlog.py                   # Discrete logarithm
│   │   ├── xor.py                    # XOR analysis
│   │   └── classical.py              # Classical ciphers
│   │
│   └── solve_*.py                    # Individual challenge solutions
│
├── challenges/                       # Challenge source files
├── data/                             # Training datasets
├── trained_model/                    # Trained classifier model
├── trained_predictor/                # Attack predictor model
│
├── train_models.py                   # Model training script
├── register_experiences.py           # Add solved challenges
├── export_training_data.py           # Export for training
└── requirements.txt                  # Dependencies
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/MauricioDuarte100/cryptoCTF.git
cd cryptoCTF

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Optional: API Keys

For LLM-enhanced analysis (optional), create a `.env` file:

```ini
GOOGLE_API_KEY=your-gemini-api-key
```

---

## Usage

### 1. Solving a Challenge

The solver modules provide functions for common cryptographic attacks:

```python
from solver.modules.rsa import wiener_attack, fermat_factorization
from solver.modules.xor import xor_with_key, find_xor_key

# Example: RSA with small private exponent
d = wiener_attack(n, e)
if d:
    plaintext = pow(ciphertext, d, n)

# Example: XOR with known plaintext
key = find_xor_key(ciphertext, known_plaintext)
decrypted = xor_with_key(ciphertext, key)
```

### 2. Using the Classification System

```python
from src.core.challenge_classifier import ChallengeClassifier

classifier = ChallengeClassifier()
classifier.load("trained_model/simple_classifier.pt")

# Classify a challenge description
challenge_type = classifier.predict(
    "RSA encryption with small public exponent e=3"
)
print(challenge_type)  # Output: "RSA"
```

### 3. Retrieving Similar Challenges

```python
from src.learning.experience_storage import get_experience_storage

storage = get_experience_storage()
similar = storage.search_similar(
    "Block cipher with modular inverse S-box",
    top_k=3
)

for exp in similar:
    print(f"Challenge: {exp.challenge_name}")
    print(f"Attack: {exp.attack_pattern}")
    print(f"Steps: {exp.solution_steps}")
```

---

## Training the Models

### Train the Classifier

```bash
python train_models.py \
    --data data/writeups_enhanced_dataset.jsonl \
    --epochs 3 \
    --simple
```

Expected output:
```
Loaded 507 examples
Epoch 3: Loss=0.0675, Accuracy=98.8%
Model saved to trained_model/simple_classifier.pt
```

### Adding New Solved Challenges

1. Edit `register_experiences.py` to add your solution:

```python
new_exp = SolvedChallengeExperience(
    challenge_id=str(uuid.uuid4()),
    challenge_name="Your Challenge Name",
    challenge_description="Description of the challenge",
    challenge_type="RSA",  # or Hash, XOR, Classical, etc.
    attack_pattern="Attack Name",
    solution_steps=[
        "Step 1: Analyze the cipher",
        "Step 2: Apply the attack",
        "Step 3: Recover the flag"
    ],
    flag_found="flag{...}"
)
storage.store_experience(new_exp)
```

2. Register and export:

```bash
python register_experiences.py
python export_training_data.py
```

3. Retrain the model:

```bash
python train_models.py --data data/writeups_enhanced_dataset.jsonl --epochs 3 --simple
```

---

## Supported Challenge Types

| Type | Description | Example Attacks |
|------|-------------|-----------------|
| RSA | RSA encryption vulnerabilities | Wiener, Fermat, Hastad, Common Factor |
| Hash | Hash function weaknesses | Length Extension, Collision |
| XOR | XOR-based encryption | Known Plaintext, Frequency Analysis |
| Classical | Historical ciphers | Caesar, Vigenere, Substitution |
| AES | AES implementation flaws | Padding Oracle, ECB Detection |
| ECC | Elliptic curve attacks | Invalid Curve, Small Subgroup |
| VDF | Verifiable Delay Functions | Protocol Malleability |

---

## Model Performance

- **Training Examples**: 507
- **Classification Accuracy**: 98.8%
- **Challenge Types**: 14 categories

---

## Contributing

1. Solve a cryptographic CTF challenge
2. Document the solution in `register_experiences.py`
3. Run the registration and export scripts
4. Retrain the model
5. Submit a pull request

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Author

**Mauricio Duarte** - [GitHub](https://github.com/MauricioDuarte100)