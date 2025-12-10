# 🔐 CryptoCTF - AI-Powered Cryptography CTF Solver

An intelligent system for analyzing and solving cryptographic CTF challenges using Machine Learning and RAG (Retrieval-Augmented Generation).

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![PyTorch](https://img.shields.io/badge/pytorch-2.0+-red.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

## 🏆 Solved Challenges

| Challenge | Type | Attack | Flag |
|-----------|------|--------|------|
| Convergent Cipher | Block Cipher | Differential Cryptanalysis | `FlagY{m33t_1n_th3_m1ddl3_0r_d1ff3r3n714l?}` |
| Wesolowski VDF | VDF | Protocol Malleability | `FlagY{Wesolowski's_VDF_is_less_secure_in_Fiat-Shamir!}` |
| Quadratic CRT | Number Theory | Z-CRT Reduction | `FlagY{qu4dr4t1c_1nt3g3rs_ar3_fun_...}` |
| Ramson | Multi-Layer | Layer-by-layer Decryption | `FlagY{Hybr!d_Encryp7i0n_Fl4g}` |
| Leaky RSA | RSA | Bellcore Fault Attack | `FlagY{f6fdd9f8ac38f5397731a3be3856c904}` |
| Tux BMP | XOR Cipher | Known Plaintext | Visual in image |
| Simple Encryption | Stream Cipher | Z3 Algebraic Solver | `FlagY{e4sy_3nc_3asy_d3c_a6cebdf01bf8a8feb61f}` |

## 🏗️ Architecture

```
cryptoCTF/
├── src/                          # Core source code
│   ├── core/                     # Agent and classification engine
│   │   ├── enhanced_agent.py     # Main solving agent
│   │   └── challenge_classifier.py
│   ├── rag/                      # RAG system for writeup retrieval
│   │   ├── experience_retriever.py
│   │   └── challenge_embeddings.py
│   ├── learning/                 # Experience storage
│   │   └── experience_storage.py
│   └── training/                 # ML model training
│       ├── train_classifier.py
│       └── train_predictor.py
│
├── solver/                       # Challenge-specific solvers
│   ├── modules/                  # Reusable attack modules
│   │   ├── rsa.py               # RSA attacks (Wiener, Fermat, etc.)
│   │   ├── dlog.py              # Discrete log attacks
│   │   └── xor.py               # XOR analysis
│   ├── solve_*.py               # Individual challenge solvers
│   └── main.py                  # Solver entry point
│
├── challenges/                   # Challenge files
├── data/                         # Training datasets
│   └── writeups_enhanced_dataset.jsonl
├── trained_model/                # Trained classifier (98.8% accuracy)
└── trained_predictor/            # Attack predictor model
```

## 🧠 ML Pipeline

### Challenge Classifier
- **Architecture**: TF-IDF + Neural Network
- **Training Data**: 507 examples
- **Accuracy**: 98.8%
- **Types Supported**: RSA, Hash, Classical, Encoding, XOR, AES, ECC, VDF, etc.

### Attack Predictor
- **Purpose**: Predict best attack pattern for a challenge type
- **Integration**: Works with experience database for RAG retrieval

### Experience Storage
- **Database**: SQLite with FAISS indexing
- **Content**: Solved challenges with step-by-step solutions
- **Usage**: Retrieves similar past solutions for new challenges

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/MauricioDuarte100/cryptoCTF.git
cd cryptoCTF

# Install dependencies
pip install -r requirements.txt
```

### Train Models

```bash
# Train the classifier with existing data
python train_models.py --data data/writeups_enhanced_dataset.jsonl --epochs 3 --simple
```

### Register New Solutions

```bash
# After solving a challenge, register it
python register_experiences.py

# Export training data
python export_training_data.py
```

### Solve a Challenge

```python
from solver.main import solve_challenge

# Analyze and solve a challenge
result = solve_challenge("path/to/challenge.py", host="server.com", port=1234)
print(result.flag)
```

## 🛠️ Key Components

### Solver Modules

| Module | Attacks |
|--------|---------|
| `rsa.py` | Wiener, Fermat, Common Factor, Small e |
| `dlog.py` | Baby-Step Giant-Step, Pohlig-Hellman |
| `xor.py` | Known Plaintext, Frequency Analysis |

### Core Classes

- **`EnhancedAgent`**: Main solving agent with ML classification
- **`ExperienceStorage`**: SQLite + FAISS for solution retrieval
- **`ChallengeClassifier`**: Neural network for type classification

## 📊 Training Data Format

```json
{
  "challenge_name": "Example RSA",
  "challenge_description": "RSA with small e and related messages",
  "challenge_type": "RSA",
  "attack_pattern": "Hastad Broadcast",
  "solution_steps": ["Step 1...", "Step 2...", "Step 3..."],
  "flag_found": "FlagY{example_flag}"
}
```

## 🔧 Configuration

Create a `.env` file for API keys (optional):

```ini
GOOGLE_API_KEY=your-gemini-api-key  # For LLM integration
```

## 📈 Model Performance

```
Types Distribution:
- RSA: 102 examples
- Hash: 100 examples  
- Classical: 99 examples
- Encoding: 97 examples
- XOR: 97 examples
- Others: 12 examples

Final Accuracy: 98.8%
```

## 🤝 Contributing

1. Solve a new challenge
2. Add solution to `register_experiences.py`
3. Run `python register_experiences.py`
4. Run `python export_training_data.py`
5. Retrain: `python train_models.py --data data/writeups_enhanced_dataset.jsonl`

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 👤 Author

**Mauricio Duarte** - [GitHub](https://github.com/MauricioDuarte100)