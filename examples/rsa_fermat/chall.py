# RSA Challenge - Fermat Factorization (p ≈ q)
# When p and q are close, Fermat's method works quickly

import math

# Choose primes that are close to each other
p = 10007
q = 10009  # Very close to p
n = p * q  # 100160063
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# Encrypt a simple message
message = 12345
c = pow(message, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("Hint: p and q are very close to each other!")
print("Use Fermat factorization: a² - n = b²")

# Expected: Fermat attack should find p and q quickly
# Flag will be the decrypted message: 12345