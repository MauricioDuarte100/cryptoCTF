
from sage.all import *
import ast

def solve():
    print("Loading data...")
    with open('/home/sage/repo/challenges/incu/data.txt', 'r') as f:
        content = f.read().strip()
    parts = content.split('\n')
    params = ast.literal_eval(parts[0])
    ciphertexts = ast.literal_eval(parts[1])
    
    p = params['p']
    primes = params['primes']
    roots = params['roots']
    
    Fp = GF(p)
    n = len(roots)  # 64
    
    print(f"p = {p}")
    print(f"n = {n} roots")
    print(f"Number of ciphertexts: {len(ciphertexts)}")
    
    # Key insight: ciphertext = prod(roots[i]^bit[i]) mod p
    # We need to find bits such that this holds.
    
    # Since roots[i] = primes[i]^(s^-1) mod p, we have:
    # If we can compute s, then c^s = prod(primes[i]^bit[i]) and we can factor to get bits.
    
    # But we can also directly solve using the Coppersmith/Lattice approach on the product.
    # However, for this challenge, we can try a different approach:
    # Meet-in-the-Middle on the subset product.
    
    # Alternative: Use the structure that the plaintext is ASCII text (flag).
    # ASCII characters are 7-bit, so we know some structure.
    
    # Let's try direct verification with meet-in-the-middle for each 64-bit block.
    
    def mitm_solve(c):
        """Solve prod(roots[i]^b[i]) = c mod p for bits b[i]"""
        c_fp = Fp(c)
        half = n // 2  # 32
        
        # Build table for first half
        print("  Building MITM table...")
        table = {}
        for mask in range(1 << half):
            prod = Fp(1)
            for i in range(half):
                if mask & (1 << i):
                    prod *= Fp(roots[i])
            table[prod] = mask
        
        # Search second half
        print("  Searching second half...")
        for mask2 in range(1 << (n - half)):
            prod2 = Fp(1)
            for i in range(n - half):
                if mask2 & (1 << i):
                    prod2 *= Fp(roots[half + i])
            
            # We need prod1 * prod2 = c => prod1 = c / prod2
            target = c_fp / prod2
            
            if target in table:
                mask1 = table[target]
                # Found! Reconstruct bits
                bits = []
                for i in range(half):
                    bits.append((mask1 >> i) & 1)
                for i in range(n - half):
                    bits.append((mask2 >> i) & 1)
                return bits
        
        return None
    
    all_bits = []
    for k, ct in enumerate(ciphertexts):
        print(f"Solving block {k}...")
        bits = mitm_solve(ct)
        if bits:
            print(f"  Block {k} solved!")
            all_bits.extend(bits)
        else:
            print(f"  Block {k} FAILED!")
            break
    
    if all_bits:
        # Reconstruct the integer
        total_val = ZZ(0)
        for i, b in enumerate(all_bits):
            total_val += ZZ(b) << i
        
        print(f"Total value: {total_val}")
        # Convert to bytes (big-endian as in the challenge)
        byte_len = (total_val.bit_length() + 7) // 8
        flag_bytes = []
        temp = total_val
        while temp > 0:
            flag_bytes.append(int(temp % 256))
            temp //= 256
        flag = bytes(flag_bytes[::-1])
        print(f"FLAG: {flag}")

if __name__ == "__main__":
    solve()
