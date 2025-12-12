#!/usr/bin/python3

from Crypto.Util.number import getPrime, bytes_to_long
import flag 

assert(len(flag.flag) == 131)

p = getPrime(512)
q = getPrime(512)
N = p * q
phi = (p - 1) * (q - 1)
e = 0x10001
d = pow(e, -1, phi)

flag = bytes_to_long(flag.flag)


c = pow(flag, e, N)

print(f'N = {N}')
print(f'e = {e}')
print(f'c = {c}')
print(f'd = {d}')
