import sys
import os
sys.path.append(r"c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\challenges\crypto_dot")
from add import build_adder, int_to_bits
import dpp

def test():
    n = 64
    circuit = build_adder(n)
    
    a, b = 1, 1
    c_correct = 2
    c_wrong = 3
    
    # Check output for correct sum
    inputs_correct = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c_correct, n)
    outputs, trace = circuit.evaluate(inputs_correct)
    print(f"Correct sum output: {outputs}") # Expected [1]
    
    # Check output for wrong sum
    inputs_wrong = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c_wrong, n)
    outputs, trace = circuit.evaluate(inputs_wrong)
    print(f"Wrong sum output: {outputs}") # Expected [0]

if __name__ == "__main__":
    test()
