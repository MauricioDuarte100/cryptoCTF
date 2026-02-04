---
name: Lattice Attack Expert
description: Specialized skill for modeling and searching for solutions in lattice-based cryptography challenges (LLL, BKZ, CVP, SVP, Coppersmith).
---

# Lattice Attack Expert Skill

This skill focuses on transforming cryptographic problems into lattice problems and using basis reduction algorithms to find short vectors that reveal secrets. This is the "nuclear weapon" of cryptanalysis for many public key systems and PRNGs.

## 1. When to Use

Apply this skill when you encounter:
- **Knapsack / Subset Sum** problems (Merkle-Hellman, etc.).
- **RSA with small public exponent** and partial knowledge of message (Coppersmith's Short Pad).
- **RSA with partial key exposure** (knowing bits of p, q, or d).
- **LCGs (Linear Congruential Generators)** with truncated outputs or unknown parameters.
- **Hidden Number Problem (HNP)** often seen in vague DSA/ECDSA nonces.
- **Polynomial equations** modulo N with small roots.

## 2. Core Workflow

### Step 1: Formulate the Lattice
The hardest part is constructing the basis matrix.
- **Row-based vs Column-based**: Typically, we use row-based lattices where rows are the basis vectors.
- **Scaling**: If variables have different sizes (e.g., x is small, y is large), scale the corresponding columns of the basis matrix to balance the "expected size" of the target vector.

### Step 2: Choose the Reduction
- **LLL (Lenstra-Lenstra-Lovász)**: Fast, good for most CTF challenges. Finds a vector within $2^{(n-1)/2}$ of the shortest.
- **BKZ (Block Korkine-Zolotarev)**: Stronger than LLL, slower. Use with block size 20-30 if LLL fails.

### Step 3: Execution (SageMath)
Lattice reduction in standard Python is slow/non-existent. **ALWAYS use SageMath via the `execute_sage_code` tool.**

```python
# SageMath Template for LLL
M = Matrix(ZZ, [
    [1, 0, large_A],
    [0, 1, large_B],
    [0, 0, large_M]
])
reduced_M = M.LLL()
for row in reduced_M:
    print(row)
```

## 3. Common Attack Templates

### A. Coppersmith's Small Root (Stereotyped Messages)
When you know the high or low bits of an RSA message.
**Use SageMath's built-in**: `polynomial.small_roots()`

```python
# finding x where (prefix + x)^3 = c (mod n)
P.<x> = PolynomialRing(Zmod(n))
f = (known_prefix + x)^e - c
# epsilon determines how small x needs to be relative to n
roots = f.small_roots(epsilon=0.03) 
```

### B. Knapsack / Subset Sum
Given weights $w_i$ and target $S$, find binary $x_i$ such that $\sum x_i w_i = S$.
Construct the "closure" lattice:
$$
\begin{pmatrix}
1 & 0 & \dots & 0 & w_1 \\
0 & 1 & \dots & 0 & w_2 \\
\vdots & \vdots & \ddots & \vdots & \vdots \\
0 & 0 & \dots & 1 & w_n \\
0 & 0 & \dots & 0 & S
\end{pmatrix}
$$
Look for a vector of form $(\pm x_1, \dots, \pm x_n, 0)$.

### C. HNP (Hidden Number Problem) / DSA Nonce
For optimizing finding hidden nonces in ECDSA.
Usually involves constructing a matrix with the curve order and the known relations.

## 4. Troubleshooting
- **Vector not found?** Try increasing the precision or using BKZ with a higher block size.
- **Too slow?** Your lattice dimension might be too high (>50-100 starts getting hard for vanilla LLL in seconds).
- **Wrong vector?** Check your scaling. If one column represents a value $X \approx 2^{100}$ and another $Y \approx 1$, LLL will bias towards reducing $X$ drastically. Multiply the $Y$ column by $2^{100}$ to make them equally important.
