---
name: Algebraic & Multivariate Analyst
description: Expert in solving polynomial systems, Coppersmith's Methods, and algebraic attacks on MPC/DKG.
---

# Algebraic & Multivariate Analyst Skill

This skill focuses on "breaking crypto with pure algebra": finding roots of polynomials modulo $N$, solving systems of multivariate equations (Gröbner Bases), and attacking complex multi-party protocols.

## 1. Coppersmith's Methods (Univariate & Multivariate)

**Concept**: finding small roots of polynomials modulo $N$.
**Crucial Theorem**: We can find roots $x_0$ if $|x_0| < N^{1/d - \epsilon}$.

### A. Stereotyped Messages (Univariate)
Knowing the prefix/suffix of a message encrypted with small $e$ (RSA).
- **SageMath**: `f.small_roots()`

### B. Coppersmith's Short Pad (Multivariate)
Two messages $m_1, m_2$ differ by a small unknown $\Delta$, and are encrypted with same $(N, e)$.
- **Attack**: Use Franklin-Reiter Related Message Attack.
- **Implementation**: Construct univariate polynomials involving the relation and take their GCD.

### C. Boneh-Durfee Attack
Attacking RSA with small private exponent $d < N^{0.292}$.
- **Method**: Lattices/Coppersmith on the equation $ed \equiv 1 \pmod{\phi(N)}$.
- **Tool**: `defund/boneh_durfee` (GitHub).

## 2. Gröbner Bases (Multivariate Systems)

**Scenario**: You have a system of polynomial equations over a field or ring.
$$ f_1(x, y, z) = 0, \dots, f_k(x, y, z) = 0 $$
**Goal**: Solve for $x, y, z$.

**Method**: Compute the **Gröbner Basis** of the ideal $\langle f_1, \dots, f_k \rangle$. The basis often has a triangular form (like Gaussian elimination) allowing easy solving.
**Complexity**: Exponential in worst case (Buchberger's Algorithm, F4, F5), but fast for overdefined or structured systems in CTFs.

**SageMath**:
```python
R.<x,y,z> = PolynomialRing(GF(p), order='lex')
I = Ideal([eq1, eq2, eq3])
B = I.groebner_basis()
# If B = [x - a, y - b, z - c], we are done.
```

## 3. Algebraic Attacks on MPC & ZK Proofs

**Scenario**: Threshold Signatures (TSS), DKG (Distributed Key Gen), or Zero-Knowledge Proofs (Schnorr/Fiat-Shamir).

### A. Fiat-Shamir Weakness
If the challenge $c$ in a ZK proof $(A, c, z)$ is not hashed properly from *all* contribution data (or is weak/predictable), the prover can forge a proof.
**Attack**: Solve for the secret scalar knowing the predictable $c$.

### B. DKG Bias or Manipulation
In Multi-Party Computation, if one party can manipulate their commitment or "rush" (wait for others to commit then send theirs), they can bias the final key.
**Attack**: Check if the "Commitment" phase enforces binding properly.

## 4. White-Box Cryptography & DCA

**Scenario**: You have the binary/code of an AES implementation, but the key is "baked in" via Look-Up Tables (LUTs) and random bijections.
**Method**: **Differential Computation Analysis (DCA)**.
- It is DPA (Side-Channel) applied to software execution traces (memory access/register values) instead of power traces.
- **Tool**: `SideChannelMarvels/Daredevil` or `SanSSoN`.
- **Steps**:
  1. Instrument the binary (add probes to record values).
  2. Encrypt random plaintexts and record traces.
  3. Run CPA attack (as defined in Side-Channel Skill) on the software traces.
