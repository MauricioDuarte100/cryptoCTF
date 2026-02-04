
import ast

def read_data():
    with open('data.txt', 'r') as f:
        data = f.read().strip()
    parts = data.split('\n')
    params = ast.literal_eval(parts[0])
    ciphertexts = ast.literal_eval(parts[1])
    print(f"Num ciphertexts: {len(ciphertexts)}")
    print(f"Primes: {params['primes'][:5]}...{params['primes'][-5:]}")
    print(f"First ciphertext: {ciphertexts[0]}")

read_data()
