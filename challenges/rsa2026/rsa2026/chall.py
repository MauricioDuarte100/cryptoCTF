import math
import os
import random
import sys
from Crypto.Util.number import isPrime

sys.set_int_max_str_digits(20 << 26)

flag = os.environ.get("FLAG", "Alpaca{****** REDACTED ******}").encode()
m = int(flag.hex(), 16)

primes = [x for x in range(2026) if isPrime(x) and m % x != 0]
ps = random.choices(primes, k=2026)
n = math.prod(ps)
assert m < n

e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
