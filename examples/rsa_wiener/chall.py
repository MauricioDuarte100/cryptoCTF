# RSA Challenge - Wiener Attack (d pequeño)
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

# Parámetros RSA vulnerables a Wiener Attack
# d es pequeño (d < N^0.25)
n = 20313365319875646582736588152425381916508620233362344885622071806460897313445978692925740736779055984109844056943896263140465141275583836698516527174754797
e = 18441522748892352679183700985264806119495761193071187138185238124942655896171
c = 1234567890123456789012345678901234567890123456789012345678901234567890

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("This RSA has a small private exponent d. Use Wiener's attack!")

# La flag está cifrada en c
# Hint: d < N^(1/4), perfect for Wiener's attack