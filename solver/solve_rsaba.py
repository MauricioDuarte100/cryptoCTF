#!/usr/bin/env python3
"""
RSA Basics CTF Solver
Target: tcp.flagyard.com:13509

3 Challenges:
1. Factor n from n and phi(n) - algebraic approach
2. Factor n from multiple of phi(n) - Miller factorization
3. Decryption oracle attack - chosen ciphertext/blinding
"""

from pwn import *
import gmpy2
from gmpy2 import mpz, isqrt, gcd
import random

context.log_level = 'info'

def factor_from_phi(n, phi):
    """
    Challenge 1: Given n = p*q and phi = (p-1)*(q-1)
    
    n - phi + 1 = p + q
    We solve: x^2 - (p+q)*x + n = 0
    """
    n, phi = mpz(n), mpz(phi)
    sum_pq = n - phi + 1  # p + q
    
    # Quadratic: x^2 - sum_pq*x + n = 0
    # x = (sum_pq ± sqrt(sum_pq^2 - 4n)) / 2
    discriminant = sum_pq * sum_pq - 4 * n
    sqrt_disc = isqrt(discriminant)
    
    p = (sum_pq + sqrt_disc) // 2
    q = (sum_pq - sqrt_disc) // 2
    
    assert p * q == n, "Factorization failed!"
    return int(p), int(q)


def factor_from_phi_multiple(n, phi_mult):
    """
    Challenge 2: Given n = p*q and phi_mult = k * (p-1)*(q-1) for some k
    
    Uses Miller's algorithm: 
    phi_mult = 2^s * t where t is odd
    For random a, if a^t != 1 mod n, then gcd(a^(2^i * t) - 1, n) may give a factor
    """
    n, phi_mult = mpz(n), mpz(phi_mult)
    
    # Write phi_mult = 2^s * t
    t = phi_mult
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1
    
    for attempt in range(100):
        a = random.randint(2, int(n) - 2)
        a = mpz(a)
        
        x = pow(a, int(t), int(n))
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(s - 1):
            prev_x = x
            x = pow(x, 2, int(n))
            
            if x == 1:
                # gcd(prev_x - 1, n) or gcd(prev_x + 1, n) might be factor
                g = gcd(prev_x - 1, n)
                if 1 < g < n:
                    return int(g), int(n // g)
                g = gcd(prev_x + 1, n)
                if 1 < g < n:
                    return int(g), int(n // g)
                break
            
            if x == n - 1:
                break
    
    raise Exception("Factorization failed after many attempts")


def decrypt_oracle_attack(n, enc, decrypt_func):
    """
    Challenge 3: Chosen ciphertext attack with blinding
    
    e = 65537
    enc = msg^e mod n
    We can't send enc directly but can send 2^e * enc mod n
    Response will be: (2^e * enc)^d mod n = 2 * msg mod n
    Then msg = response * inverse(2) mod n
    """
    e = (1 << 16) + 1  # 65537
    n = mpz(n)
    enc = mpz(enc)
    
    # Blinding factor: use 2
    blind = mpz(2)
    blinded_ct = (pow(blind, e, int(n)) * enc) % n
    
    # Get decryption of blinded ciphertext
    response = decrypt_func(int(blinded_ct))
    response = mpz(response)
    
    # Unblind: msg = response / 2 mod n
    msg = (response * gmpy2.invert(blind, n)) % n
    
    return int(msg)


def solve():
    host = "tcp.flagyard.com"
    port = 13509
    
    io = remote(host, port)
    
    # Intro
    io.recvuntil(b"Let's go over some RSA basics for your CTF Journey!")
    
    # =================== CHALLENGE 1 ===================
    log.info("Solving Challenge 1: factor n from n and phi(n)")
    
    io.recvuntil(b"n = ")
    n1 = int(io.recvline().strip())
    io.recvuntil(b"phi = ")
    phi1 = int(io.recvline().strip())
    
    log.info(f"n1 = {n1}")
    log.info(f"phi1 = {phi1}")
    
    p1, q1 = factor_from_phi(n1, phi1)
    log.success(f"Challenge 1 factors: p={p1}, q={q1}")
    
    io.recvuntil(b"input factors")
    io.sendline(str(p1).encode())
    io.sendline(str(q1).encode())
    
    # =================== CHALLENGE 2 ===================
    log.info("Solving Challenge 2: factor n from multiple of phi(n)")
    
    io.recvuntil(b"n = ")
    n2 = int(io.recvline().strip())
    io.recvuntil(b"phi = ")
    phi2 = int(io.recvline().strip())
    
    log.info(f"n2 = {n2}")
    log.info(f"phi2 (multiple) = {phi2}")
    
    p2, q2 = factor_from_phi_multiple(n2, phi2)
    log.success(f"Challenge 2 factors: p={p2}, q={q2}")
    
    io.recvuntil(b"input factors")
    io.sendline(str(p2).encode())
    io.sendline(str(q2).encode())
    
    # =================== CHALLENGE 3 ===================
    log.info("Solving Challenge 3: decryption oracle attack")
    
    io.recvuntil(b"n = ")
    n3 = int(io.recvline().strip())
    io.recvuntil(b"encryption result = ")
    enc3 = int(io.recvline().strip())
    
    log.info(f"n3 = {n3}")
    log.info(f"enc3 = {enc3}")
    
    # Define decrypt function
    def decrypt_func(ct):
        io.sendline(str(ct).encode())
        io.recvuntil(b"decryption result = ")
        return int(io.recvline().strip())
    
    msg3 = decrypt_oracle_attack(n3, enc3, decrypt_func)
    log.success(f"Recovered msg: {msg3}")
    
    io.sendline(str(msg3).encode())
    
    # Get flag - try multiple methods
    import time
    time.sleep(1)
    
    try:
        flag_data = io.recvall(timeout=10).decode()
    except:
        flag_data = io.recv(timeout=5).decode()
    
    print("\n" + "="*60)
    print("FLAG OUTPUT:")
    print(flag_data)
    print("="*60)
    
    # Extract flag pattern
    import re
    flag_match = re.search(r'(FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|ctf\{[^}]+\})', flag_data, re.IGNORECASE)
    if flag_match:
        print(f"\n[!] FLAG: {flag_match.group(1)}")
    
    io.close()
    return flag_data


if __name__ == "__main__":
    flag = solve()
