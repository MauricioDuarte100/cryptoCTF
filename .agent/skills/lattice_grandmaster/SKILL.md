---
name: Lattice & HNP Grandmaster
description: God-level skill for solving Hidden Number Problems (HNP), Extended HNP, and advanced Lattice attacks on ECDSA/DSA.
---

# Lattice & HNP Grandmaster Skill

This skill represents the pinnacle of cryptanalytic attacks involving lattices, specifically targeting ECDSA and DSA via the Hidden Number Problem (HNP) and its variants. This is the "Final Boss" of practical ECDSA attacks.

## 1. The Hidden Number Problem (HNP)

**Scenario**: You have $m$ ECDSA signatures $(r_i, s_i)$ and some partial information about the nonces $k_i$.
- **Bias**: The nonces are generated with a weak RNG (e.g., top bits are always 0).
- **Leakage**: A side-channel leaks the MSB or LSB of $k$.

**Goal**: Recover the private key $d$ using the relation:
$$ s_i \equiv k_i^{-1} (z_i + r_i d) \pmod n $$
Rewritten as:
$$ k_i - d \cdot (r_i s_i^{-1}) - (z_i s_i^{-1}) \equiv 0 \pmod n $$
This is a linear relation suitable for lattice reduction.

### Workflow
1. **Construct the Lattice**: Build a matrix where rows capture the modular linear relations.
2. **CVP/SVP**: The "target" vector containing the small nonces $k_i$ is a Shortest Vector in this lattice.
3. **Reduction**: Use LLL or BKZ to find this vector.

## 2. Extended HNP (EHNP)

**Scenario**: The nonce leakage is "hole-y" or non-contiguous. You might know chunks of bits in the middle, or the leakage varies per signature.
**Difficulty**: Standard HNP solvers fail here. You must construct a specific CVP instance for the known bitmasks.

**Tools**:
- **SageMath**: `Matrix.LLL()`, `Matrix.BKZ()`.
- **fplll**: Underlying C++ library for speed.
- **Repos**:
  - `crypto-attacks/attacks/hnp/extended_hnp.py`: For complex hole-y leakage.
  - `demining/lattice-attack`: For classic biased nonce attacks.

## 3. Post-Quantum & Kyber

For PQC challenges (LWE/Reg-LWE):
1. **Model as LWE**: $A s + e = b$.
2. **Primal Attack**: Construct the lattice $\begin{pmatrix} A & -b \\ 0 & q \end{pmatrix}$. Look for short vector $(s, e, 1)$.
3. **Dual Attack**: Find short vector $v$ in dual lattice such that $vA \approx 0$.

## 4. Execution Templates (SageMath)

### Standard ECDSA Biased Nonce (MSB Zero)
```python
# HNP Construction for l-bit nonce where top bits are 0
# B = Upper bound of nonce (e.g., 2^120 for 128-bit leakage on P-256)
M = Matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M[i, i] = n
    M[m, i] = t_i  # derived from r, s, z
    M[m+1, i] = u_i # derived constant

M[m, m] = B / n # Scaling factor
M[m+1, m+1] = B
# ... Reduce and extract d
```

## 5. References for "Impossible" Challenges
- **Polynonce Attack**: When nonces are related polynomially but unknown.
- **LadderLeak**: ECDSA key recovery from Montgomery Ladder side-channels.
