---
name: Side-Channel Attack Expert
description: Expert in physical and software side-channel attacks: CPA/DPA, Fault Injection, and White-Box DCA.
---

# Side-Channel Attack Expert Skill

This skill focuses on breaking cryptography by observing *how* it runs (power, time, EM, memory) rather than just the math. It covers both Physical Side-Channels (Hardware) and Differential Computation Analysis (White-Box Software).

## 1. Classification

- **Simple Power Analysis (SPA)**: You can visually see the key bits (e.g., RSA Square-and-Multiply).
- **Differential/Correlation Power Analysis (DPA/CPA)**: Statistical attacks extracting keys byte-by-byte using many traces.
- **Timing Attacks**: Exploiting duration differences (e.g., `if user_pass == db_pass` exiting early).
- **Fault Injection**: Introduction of errors (glitching) to bypass checks or leak keys (RSA CRT Fault, AES DFA).
- **White-Box DCA**: DPA applied to software execution traces (memory/registers) for obfuscated crypto.

## 2. Correlation Power Analysis (CPA) Protocol

**Target**: AES-128 (most common).
**Model**: Hamming Weight (HW) of the S-Box output.

### Workflow:
1. **Model Hypothesis**: $H(d, k) = \text{HW}(\text{SBox}[d \oplus k])$
   - $d$ is known data (plaintext byte).
   - $k$ is the guessed key byte.
2. **Measure**: Capture $T$ traces with varying plaintexts.
3. **Correlate**: For each key guess $K \in [0, 255]$:
   - Calculate theoretical power vector $H_{vec}$.
   - Calculate Pearson Correlation between $H_{vec}$ and real traces $T_{matrix}$.
   - Max correlation reveals the correct key byte.

### Numpy Implementation Snippet
```python
import numpy as np

def pearson_correlation(X, Y):
    # X: (Traces, Timepoints), Y: (Traces,)
    # Returns (Timepoints,)
    x_mean = X.mean(axis=0)
    y_mean = Y.mean()
    numerator = ((X - x_mean).T @ (Y - y_mean)).T
    denominator = np.sqrt(((X - x_mean)**2).sum(axis=0) * ((Y - y_mean)**2).sum())
    return numerator / denominator
```

## 3. White-Box Cryptography (DCA)

**Context**: You have an obfuscated binary (e.g., Android NDK lib, DRM module) that performs AES. The key is hidden in massive tables.
**Attack**: Differential Computation Analysis (DCA).
**Why it works**: Even if the math is hidden in tables, the *values* flowing through memory still correlate with the standard AES intermediate states.

**Workflow**:
1. **Tracing**: Use `Intel PIN`, `Frida`, or `Valgrind` to record every memory write or register value during encryption.
2. **Virtual Probes**: Treat specific memory addresses or registers as your "power probe".
3. **Attack**: Run standard CPA (see above) on these "software traces". The correct key byte will show a massive correlation peak at the instruction where the S-Box lookup happens.

## 4. Fault Injection (RSA-CRT)
If you can corrupt the signature calculation modulo $p$ (or $q$) but not the other:
$$ s_p \equiv m^d \pmod p $$
$$ \hat{s}_q \neq m^d \pmod q $$

Then:
$$ \gcd(s - \hat{s}, n) = \gcd(s - \hat{s}, p \cdot q) = q $$
This factorizes $N$ instantly with a single faulty signature!

## 5. Tools
- **Numpy/Scipy**: Essential for CPA math.
- **ChipWhisperer**: The gold standard hardware framework (Python).
- **Daredevil**: Fast C++ tool for DPA/DCA on large datasets.
- **PhoenixAES**: Tool for automated Differential Fault Analysis (DFA) on AES.
