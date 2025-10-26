#!/usr/bin/env python3
"""
RSA Small Exponent Challenge
Classic RSA vulnerability with e=3
"""

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import gmpy2

# Challenge parameters
e = 3
flag = b"flag{small_exponent_attack_works}"

# Generate RSA keys
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)

# Encrypt flag
m = bytes_to_long(flag)
c = pow(m, e, n)

print("RSA Challenge - Small Exponent")
print("=" * 40)
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print()
print("Find the flag!")

# Solution hint (for validation)
# Since e=3 is small, try cube root attack
# m = gmpy2.iroot(c, 3)[0]
# flag = long_to_bytes(m)