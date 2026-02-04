# SageMath Integration for CryptoCTF

To enable advanced solver capabilities (Lattices, Elliptic Curves, Gröbner Bases), `cryptoCTF` can integrate with SageMath.

## Prerequisites

- **WSL2 (Windows Subsystem for Linux)** or Native Linux/macOS.
- `conda` (Miniconda or Anaconda) recommended.

## Installation

We recommend using the configuration adapted from `aicrypto-agent`.

### 1. Create Conda Environment

```bash
conda create -n crypto_sage sage python=3.10
conda activate crypto_sage
```

### 2. Install SageMath

If not installed via conda above:

```bash
conda install -c conda-forge sage
# OR on Ubuntu/Debian
sudo apt update && sudo apt install sagemath
```

### 3. Install Dependencies

Install the python requirements **inside** the sage environment:

```bash
# Important: use sage -pip to install into sage's python
sage -pip install -r requirements.txt
```

### 4. Install External Tools (Optional but Recommended)

For lattice attacks (LLL/BKZ) and factoring:

*   **Yafu**: https://github.com/bbuhrow/yafu
*   **Flatter**: https://github.com/keeganryan/flatter (Fast LLL)

## Usage in CryptoCTF

The `solver/modules/sage_bridge.py` module detects if `sage` is available in your PATH.

If available, it will automatically route complex attacks (like Coppersmith or HNP) to SageMath scripts.

```python
from solver.modules.sage_bridge import run_sage_script

script = """
R.<x> = PolynomialRing(Zmod(n))
f = x^3 + ...
small_roots(f, ...)
"""
output = run_sage_script(script)
```
