# sixse - LACTF 2025

| Field | Value |
|---|---|
| Challenge Type | RSA |
| Attack Pattern | Digit-by-digit Factorization (Special Primes) |
| Difficulty | Low-Mid |
| Code | solver/solve_sixse.py |
| Flag | lactf{wh4t_67s_15_blud_f4ct0r1ng_15_blud_31nst31n} |

## Attack Description
The challenge generates two 256-digit primes `p` and `q` such that every digit (except the last, which is always 7) is chosen randomly from `{6, 7}`.
This restriction drastically reduces the keyspace for standard factorization but allows for a specialized approach because the digits are highly constrained.

Since $N = p \cdot q$, the lower digits of $N$ only depend on the lower digits of $p$ and $q$.
We can determine $p$ and $q$ digit by digit from least significant to most significant (modulo $10^k$).
Because there are only 2 choices per digit ($6$ or $7$), even a simple Depth First Search (DFS) or Beam Search is efficient enough.

## Steps
1. Connect to server, solve Proof of Work (PoW) if present.
2. Retrieve public key $N$ and ciphertext $c$.
3. Initialize DFS state with known last digits: $p_0=7, q_0=7$.
4. For each position $k$ from $1$ to $255$:
   - Try all digital combinations $(d_p, d_q) \in \{6, 7\}^2$.
   - Compute tentative $p_{next}, q_{next}$.
   - Verify if $p_{next} \cdot q_{next} \equiv N \pmod{10^{k+1}}$.
   - Prune invalid branches.
5. Once full $p, q$ are found, verify $p \cdot q = N$.
6. Decrypt ciphertext using RSA private exponent $d = e^{-1} \pmod{\phi(N)}$.

## Mathematical Core
$$ N \equiv \left(\sum a_i 10^i\right) \cdot \left(\sum b_i 10^i\right) \pmod{10^k} $$
Allows iterative solving for $a_i, b_i$.
