from functools import reduce
from Crypto.Util.number import isPrime

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def chinese_remainder_theorem(residues, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi % m, m)
        result += r * Mi * inv
    return result % M

def solve_from_log():
    residues = []
    moduli = []
    
    # Read log
    try:
        with open("solver_debug.log", "r") as f:
            for line in f:
                # Format: "p = 91 (mod 128)"
                if "p =" in line and "(mod" in line:
                    try:
                        parts = line.split()
                        # parts: ['p', '=', '91', '(mod', '128)']
                        r = int(parts[2])
                        m = int(parts[4].replace(')', ''))
                        residues.append(r)
                        moduli.append(m)
                        print(f"Loaded: p = {r} (mod {m})")
                    except:
                        pass
    except FileNotFoundError:
        print("Log file not found.")
        return

    if not residues:
        print("No residues found in log.")
        return

    print(f"[*] Loaded {len(residues)} residues.")
    
    # CRT
    try:
        M = reduce(lambda a, b: a * b, moduli)
        p_crt = chinese_remainder_theorem(residues, moduli)
        print(f"[*] CRT Result: p = {p_crt} (mod {M})")
        print(f"[*] log2(M) = {M.bit_length()}")
        
        # Brute force k
        # p = p_crt + k*M
        # p is 128 bit.
        # k ranges?
        
        target_bits = 128
        
        # Since M might be > p (if enough residues), p = p_crt potentially
        if p_crt.bit_length() == 128 and isPrime(p_crt):
            print(f"[!!!] Found p directly from CRT: {p_crt}")
            return
            
        # If M < 2^128, search k
        if M.bit_length() < 128:
            limit = (2**128) // M + 5
            print(f"[*] Searching k in range [0, {limit}]")
            for k in range(limit + 1):
                cand = p_crt + k * M
                if cand.bit_length() == 128 and isPrime(cand):
                    print(f"[!!!] Found prime candidate p: {cand}")
                    # We can't verify flag strictly without ciphertexts, 
                    # but we can try basic check if we had them.
                    # Assuming this is the one.
        else:
            # M > 2^128. p must be p_crt (or p_crt - M, etc)
            # Find the value in range [2^127, 2^128)
            # p_crt might be larger than 2^128
            cand = p_crt
            while cand >= 2**128:
                cand -= M
            if cand.bit_length() == 128 and isPrime(cand):
                print(f"[!!!] Found p: {cand}")
            else:
                 print(f"[*] p_crt {p_crt} does not yield 128-bit prime?")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve_from_log()
