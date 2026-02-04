
from sage.all import *
import ast

def analyze():
    with open('data.txt', 'r') as f:
        data = f.read().strip()
    
    parts = data.split('\n')
    params = ast.literal_eval(parts[0])
    p = params['p']
    primes = params['primes']
    roots = params['roots']
    
    print(f"p: {p}")
    print(f"p bit length: {p.bit_length()}")
    
    prod_primes = 1
    for pr in primes:
        prod_primes *= pr
    
    print(f"Product of 64 primes bit length: {prod_primes.bit_length()}")
    
    p_minus_1 = p - 1
    factors = p_minus_1.factor()
    print(f"p-1 factors: {factors}")

analyze()
