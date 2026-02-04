import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import *

# Path to the output file
OUT_FILE = "challenges/dorya/out.txt"

# Challenge parameters
KEY_BITS = 1024
e = 7

def solve():
    print("[-] Reading output file...")
    with open(OUT_FILE, 'r') as f:
        # The file content is a python list printed, so we can replace single quotes with double quotes (if needed) or use eval carefully
        # Actually it's valid JSON-ish if we replace ' with "
        content = f.read().replace("'", '"')
        data = json.loads(content)
    
    # Reconstruct coefficients
    # coeffs = [a, b, c_coef, d]
    coeffs = [1 * 2**1024, 3 * 2**1024, 3 * 2**1024, 7 * 2**1024]
    
    # List to store (polynomial, modulus) pairs ? 
    # Actually we just want to build the CRT polynomial directly.
    # But for that we need the individual polynomials modulo n_i first.
    
    moduli = []
    polynomials = []
    
    x = PolynomialRing(Zmod(prod([d['n'] for d in data])), 'x').gen()
    # But wait, we need to construct CRT from integer polynomials efficiently.
    # Standard way: construct P_i in Zmod(n_i)[x], assume it equals 0 mod n_i.
    # Then lift to Z and use CRT.
    
    # Let's collect n_i and P_i (symbolic/coefficients)
    
    N_list = []
    P_list = []
    
    for i, entry in enumerate(data):
        n = entry['n']
        c = entry['c']
        
        a, b, k_term, d = coeffs
        
        # P_i(x) = (a*x + b)^7 - c * (k_term*x + d)^7  (mod n)
        # Note: coefficients are huge, reduce them mod n
        
        a_r = a % n
        b_r = b % n
        k_r = k_term % n
        d_r = d % n
        c_r = c % n
        
        R = PolynomialRing(Zmod(n), 'x')
        x_poly = R.gen()
        
        poly = (a_r * x_poly + b_r)**7 - c_r * (k_r * x_poly + d_r)**7
        
        # Make the polynomial monic to be safe? 
        # Standard CRT works with whatever coefficients.
        # But we need coefficients as integers to pass to CRT.
        
        N_list.append(n)
        P_list.append(poly.change_ring(ZZ)) 
        
        # Update coefficients for next iteration
        coeffs[0] += 2**1024
        coeffs[1] += 4**1024
        coeffs[2] += 6**1024
        coeffs[3] += 8**1024
    
    print("[-] Constructing CRT polynomial...")
    # Manual CRT for polynomials
    # P(x) = sum( P_i(x) * M_i * y_i ) mod N
    # where M_i = N / n_i, y_i = M_i^-1 mod n_i
    
    big_N = prod(N_list)
    final_poly_coeffs = []
    
    # All polynomials are degree 7. We can CRT coefficient by coefficient.
    degree = 7
    
    # P_list[i] might have degree less than 7 if leading term cancels (unlikely)
    # So we should iterate up to max degree
    
    c_coeffs = [0] * (degree + 1)
    
    for i in range(len(data)):
        n_i = N_list[i]
        p_i = P_list[i]
        coefs_i = p_i.list()
        # Pad with zeros if needed
        while len(coefs_i) <= degree:
            coefs_i.append(0)
            
        M_i = big_N // n_i
        y_i = inverse_mod(M_i, n_i)
        
        term = M_i * y_i
        
        for deg in range(degree + 1):
            c_coeffs[deg] = (c_coeffs[deg] + coefs_i[deg] * term) % big_N
            
    # Construct polynomial in Zmod(N)
    P_ring = PolynomialRing(Zmod(big_N), 'x')
    P = P_ring(c_coeffs)
    
    # We want to solve P(m) = 0 mod N for small m.
    # m is approx 60 bytes * 8 = 480 bits.
    # N is approx 7 * 1024 = 7168 bits.
    # Small roots allows finding root < N^(1/degree).
    # N^(1/7) is approx 1024 bits.
    # 480 < 1024, so it should work.
    
    # Make monic first (Coppersmith implementation usually likes monic)
    # To make monic, multiply by inverse of leading coefficient.
    # Leading coefficient is coeff of x^7.
    
    lead = P.coefficients()[7]
    inv_lead = inverse_mod(lead, big_N)
    P_monic = P * inv_lead
    
    print("[-] Finding small roots...")
    # beta=1.0 because we want exact root mod N (not divisors)
    # epsilon can be adjusted if needed, default is usually fine
    
    # Set X bound slightly higher than expected flag size to be safe
    X_bound = 2**500 
    
    roots = P_monic.small_roots(X=X_bound, beta=1.0, epsilon=0.03)
    
    if roots:
        print(f"[+] Found roots: {roots}")
        for r in roots:
            try:
                flag = long_to_bytes(int(r))
                if b'0xL4ugh' in flag or b'CTF' in flag or b'flag' in flag.lower():
                    print(f"[!] FLAG: {flag.decode()}")
                    return
                else:
                     print(f"[?] Candidate: {flag}")
            except:
                pass
    else:
        print("[-] No roots found.")

if __name__ == "__main__":
    solve()
