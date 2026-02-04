---
name: Classical Cipher Breaker
description: Expert in breaking classical polyalphabetic and monoalphabetic ciphers (Vigenère, Substitution, Affine, Hill).
---

# Classical Cipher Breaker Skill

This skill is dedicated to breaking "pre-computer" age ciphers. While mathematically simpler, they often require statistical analysis, frequency attacks, and heuristic search (hill climbing) rather than algebraic solving.

## 1. Identification

Before attacking, identify the cipher type:
- **Monoalphabetic**: Symbol frequency matches English (or target language). 'e' is most common.
  - *Examples*: Caesar, Affine, Atbash, Simple Substitution.
- **Polyalphabetic**: Frequency distribution is "flat" or smooth.
  - *Examples*: Vigenère, Beaufort, Autokey, verify using Index of Coincidence (IoC).
- **Digraph/Trigraph**: Analysis of pairs/triplets.
  - *Examples*: Playfair, Hill.

## 2. Statistical Tools

### Index of Coincidence (IoC)
Calculates the probability that two randomly selected letters are the same.
- **English IoC**: $\approx 0.0667$
- **Randon/Encrypted**: $\approx 0.038$

Use this to determine **Key Length** in Vigenère-like ciphers.
1. Shift ciphertext by $k$ positions.
2. Count coincidences (equal characters at same index).
3. Peaks indicate potential key length periods.

### Chi-Squared ($\chi^2$) Test
Measure "fitness" of decrypted text against English distribution.
Lower $\chi^2$ value = More like English.

## 3. Automated Solving Strategies

### A. Vigenère / Variant Cracking
Avoid manual analysis. Use a solver that:
1. Guesses key lengths (1 to 20).
2. For each length $L$, splits text into $L$ columns.
3. Solves each column as a Caesar shift by minimizing $\chi^2$.

```python
def solve_vigenere(ciphertext):
    # Pseudocode for solver logic
    best_text = ""
    min_chi = infinity
    for key_len in range(1, 20):
        # ... solve columns ...
        if score < min_chi:
            best_text = candidate
            min_chi = score
    return best_text
```

### B. Substitution Ciphers (Hill Climbing)
For general substitution (random alphabet map), Brute force ($26!$) is impossible. Use **Hill Climbing**:
1. Start with a random key (alphabet permutation).
2. Decrypt.
3. Score using **Quadgram Statistics** (log-probability of seeing 4-letter sequences like "THEY", "TION").
4. Swap two letters in the key.
5. Decrypt and Score.
   - If better score: Keep new key.
   - If worse: Revert swap.
6. Repeat for 5,000+ iterations. Restart with new random key if stuck in local maximum.

## 4. Python Tools to Use
- **`pycipher`**: Library with implementations of many classical ciphers.
- **`collections.Counter`**: For fast frequency analysis.
- **`nltk` / `english_quadgrams.txt`**: Essential for scoring plaintext candidates.

## 5. Reference: Common English Freqs
`ETAOIN SHRDLU`
- E: ~12.7%
- T: ~9.1%
- A: ~8.2%
