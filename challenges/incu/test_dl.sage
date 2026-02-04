
from sage.all import *
import time

p = 75649310163467338537242488401191577447135093741127329417060926665079335289551
factor_72 = 5233803906150819415957
exponent = (p-1) // factor_72
Fp = GF(p)
g = Fp.multiplicative_generator()
h = g**exponent

# Target
target = h**123456789

print(f"Starting DL test in subgroup of order {factor_72}...")
start = time.time()
l = discrete_log(target, h, ord=factor_72)
end = time.time()
print(f"Done! Log: {l}")
print(f"Time: {end - start:.2f} seconds")
