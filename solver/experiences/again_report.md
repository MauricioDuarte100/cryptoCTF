# again - LACTF 2026

| Field | Value |
|---|---|
| Challenge Type | RSA / Lattice |
| Attack Pattern | Coppersmith's Method (Partial Key Exposure / Middle Digits) |
| Difficulty | Medium |
| Code | solver/solve_again.sage |
| Flag | lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337} |

## Attack Description
The challenge generates two prime factors `p` and `q` for RSA.
`p` is constructed as:
- 67 digits of '6' (Most Significant)
- 67 digits of random '6' or '7' (Middle)
- 67 digits of '7' (Least Significant)
`q` is a random 670-bit prime.
(Note: `p` is approx 201 digits $\approx 668$ bits).

So we know $\approx 134$ digits of $p$ out of 201 digits (approx 2/3 known).
Standard Coppersmith method for finding small roots of univariate modular polynomials allows factoring $N$ if we know at least 1/2 of the bits of $p$ (specifically $1/4$ of bits of $N$). Here we know 2/3 of $p$, which is plenty.

We formulate a polynomial $f(x) = x \cdot 10^{67} + (P_{high} + P_{low}) \pmod p$.
Here $x$ is the unknown middle part (67 digits).
We seek a root $x_0$ such that $f(x_0) \equiv 0 \pmod p$.
Since $p$ is a factor of $N$, we can use `small_roots` with parameter $\beta \approx 0.5$ (since $p \approx N^{0.5}$).
The condition for finding the root is $X < N^{\beta^2}$. With $\beta=0.5$, $X < N^{0.25}$.
$X = 10^{67} \approx N^{0.166}$. Since $0.166 < 0.25$, the condition holds comfortably.

## Steps
1. Connect to server, solve PoW.
2. Retrieve modulus $N$.
3. Construct known parts of $p$: $P_{known} = \text{int}("6"*67) \cdot 10^{134} + \text{int}("7"*67)$.
4. Use SageMath `small_roots()` on $f(x) = x \cdot 10^{67} + P_{known}$ with $\beta \approx 0.5$.
5. Recover $p$, factor $N$, decrypt flag.

## Mathematical Core
$$ f(x) = x \cdot 10^{67} + K \pmod p $$
$$ \text{Find } x_0 \text{ s.t. } f(x_0) \equiv 0 \pmod p \text{ and } |x_0| < 10^{67} $$
$$ \text{Condition: } |x_0| < N^{\frac{1}{4}} $$
