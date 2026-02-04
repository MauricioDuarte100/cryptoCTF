
from sage.all import *
n = 33706105179137483720382763858941811011514787082216064845474913024213096359
print(f"Is prime: {is_prime(n)}")
if not is_prime(n):
    print(f"Factors: {n.factor()}")
