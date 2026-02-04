---
name: ECC & Isogeny Master
description: Expert in advanced Elliptic Curve attacks: Invalid Curves, Pairings (MOV/FR), and Isogenies (SIDH).
---

# ECC & Isogeny Master Skill

This skill handles the most mathematically abstract attacks in CTFs: those involving the geometric structure of elliptic curves and isogenies between them.

## 1. Invalid Curve Attack

**Scenario**: The server calculates $Q = d \cdot P$ but does not check if point $P$ is actually on the standard curve $E$.
**Attack**:
1. Craft a point $P'$ on a "weaker" curve $E'$ (by changing only the $b$ parameter of $y^2 = x^3 + ax + b$).
2. Choose $E'$ such that its order has small prime factors (Pohlig-Hellman friendly).
3. Send $P'$, receive $Q' = d \cdot P'$.
4. Solve Discrete Log in small subgroups to recover $d \pmod{order\_subgroup}$.
5. Use CRT (Chinese Remainder Theorem) to combine results.

## 2. Pairing-Based Attacks (MOV / FR)

**Scenario**: A curve is used where the Discrete Log Problem (DLP) is hard, but its **Embedding Degree** $k$ is small.
**The Trick**: Map the DLP from the curve group $E(\mathbb{F}_p)$ (hard) to the multiplicative group of a extension field $\mathbb{F}_{p^k}^*$ (easier).

### MOV Attack (Menezes-Okamoto-Vanstone)
- **Condition**: Curve is Supersingular or has very small $k$ (e.g., $k=2, 3, 4, 6$).
- **Tool**: Weil Pairing or Tate Pairing.
- **SageMath**:
  ```python
  # E is the curve, P is base point, Q = d*P
  # Check embedding degree
  k = E.embedding_degree(order)
  # Map to finite field
  val_P = P.weil_pairing(R, order) # R is linearly independent point
  val_Q = Q.weil_pairing(R, order)
  # Solve DLP in Field
  d = val_Q.log(val_P)
  ```

## 3. Isogeny-Based Attacks (The Cutting Edge)

**Scenario**: CTFs involving SIKE, SIDH, or supersingular isogeny graphs.
**Concept**: An isogeny is a morphism (map) between two elliptic curves. The "secret" is the path (chain of isogenies) between them.

### Attacks:
- **Torsion Point Attacks**: If you are given the images of torsion points under the secret isogeny (like in SIDH), the scheme is broken (Castryck-Decru attack).
- **Path Finding**: Viewing the isogeny graph as a generic graph (Expander Graph) and finding paths (collisions) using Meet-in-the-Middle.

**Tools**:
- **SageMath**: Has robust support for Isogenies.
  ```python
  phi = E.isogeny(kernel_generator)
  E_next = phi.codomain()
  ```
- **Algorithms**: `Kani's Lemma` for navigating the isogeny volcano/graph.

## 4. Smart/Anomalous Curves (Satoh's Attack)
**Scenario**: Trace of Frobenius is 1 (Curve order $N = p$).
**Attack**: The DLP can be solved in linear time $O(1)$ by lifting the curve to the $p$-adic numbers ($\mathbb{Q}_p$) and using the formal logarithm.
**SageMath**: `E.is_supersingular()` check helps, but for anomalous curves use specialized scripts bridging to `p-adic` logs.
