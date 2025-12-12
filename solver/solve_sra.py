"""
Solver para SRA - Versión optimizada

Análisis de los factores de e*d - 1:
- Factores pequeños: 2^5, 3^3, 11, 17^2, 47, 53, 1163, 2741
- Factores grandes: 159866885483, 1760287713403, 337662244925487988813, 600178629614813335391

Los factores grandes de ~40 bits y ~60 bits deben combinarse para formar (p-1) y (q-1)
que son de ~128 bits cada uno.

Estrategia:
1. Separar factores grandes de pequeños
2. Los factores grandes se combinan para dar (p-1) y (q-1)
3. Los factores pequeños se distribuyen entre k, (p-1), y (q-1)
"""

from pwn import *
from Crypto.Util.number import long_to_bytes, isPrime
from sympy import factorint
from itertools import combinations, product

def solve():
    host = "saturn.picoctf.net"
    port = 62318
    
    conn = remote(host, port)
    
    # Parse
    line1 = conn.recvline().decode().strip()
    line2 = conn.recvline().decode().strip()
    
    print(f"[*] {line1}")
    print(f"[*] {line2}")
    
    anger = int(line1.split(" = ")[1])
    envy = int(line2.split(" = ")[1])
    
    e = 65537
    c = anger
    d = envy
    
    ed_minus_1 = e * d - 1
    print(f"[*] e*d - 1 bits: {ed_minus_1.bit_length()}")
    
    # Factorizar
    print("[*] Factorizando...")
    factors = factorint(ed_minus_1)
    print(f"[*] Factores: {dict(factors)}")
    
    # Separar factores grandes (> 2^30) de pequeños
    large_factors = []
    small_factor_product = 1
    
    for p, k in factors.items():
        if p > 2**30:
            large_factors.append((int(p), k))
        else:
            small_factor_product *= p ** k
    
    print(f"[*] Factores grandes (>2^30): {large_factors}")
    print(f"[*] Producto de factores pequeños: {small_factor_product}")
    print(f"[*] Bits del producto pequeño: {small_factor_product.bit_length()}")
    
    # Los factores grandes deben formar (p-1) y (q-1)
    # Generamos todas las particiones posibles
    
    large_primes = [p for p, k in large_factors for _ in range(k)]  # Expand by multiplicity
    print(f"[*] Primos grandes expandidos: {large_primes}")
    
    # Para cada subconjunto de primos grandes, verificar si forman p-1 y q-1
    found = False
    p_found, q_found = None, None
    
    n_large = len(large_primes)
    
    # Probar todas las particiones de los primos grandes en dos grupos
    for r in range(n_large + 1):
        if found:
            break
        for subset in combinations(range(n_large), r):
            # Grupo 1: primos en subset
            # Grupo 2: primos no en subset
            
            prod1 = 1
            prod2 = 1
            subset_set = set(subset)
            
            for i, p in enumerate(large_primes):
                if i in subset_set:
                    prod1 *= p
                else:
                    prod2 *= p
            
            # Ahora necesito distribuir los factores pequeños
            # e*d - 1 = k * (p-1) * (q-1)
            # k es típicamente pequeño (< 2*e según teoría)
            
            # Los factores pequeños se distribuyen entre k, p-1, q-1
            # Pero es más fácil probar: para cada k pequeño, verificar si funciona
            
            # prod1 y prod2 contienen los factores grandes
            # small_factor_product contiene los pequeños
            
            # Probamos: (p-1) = prod1 * d1, (q-1) = prod2 * d2
            # donde d1 * d2 * k_remaining = small_factor_product
            
            # Para simplificar, probamos k pequeños directamente
            for k in range(1, min(small_factor_product + 1, 2 * e)):
                if small_factor_product % k != 0:
                    continue
                
                remaining = small_factor_product // k
                
                # remaining = d1 * d2 donde d1 | (p-1) y d2 | (q-1)
                # Probamos distribuciones
                
                for d1 in range(1, min(remaining + 1, 10000)):
                    if remaining % d1 != 0:
                        continue
                    d2 = remaining // d1
                    
                    pm1 = prod1 * d1
                    qm1 = prod2 * d2
                    
                    p_cand = pm1 + 1
                    q_cand = qm1 + 1
                    
                    # Verificar tamaño (~128 bits)
                    if not (127 <= p_cand.bit_length() <= 130):
                        continue
                    if not (127 <= q_cand.bit_length() <= 130):
                        continue
                    
                    # Verificar primalidad
                    if isPrime(p_cand) and isPrime(q_cand):
                        # Verificar que e*d ≡ 1 mod φ(n)
                        phi = pm1 * qm1
                        if (e * d) % phi == 1:
                            print(f"[+] Encontrado p = {p_cand}")
                            print(f"[+] Encontrado q = {q_cand}")
                            print(f"[+] k = {k}")
                            p_found, q_found = p_cand, q_cand
                            found = True
                            break
                if found:
                    break
            if found:
                break
    
    if not found:
        print("[!] No se encontraron p y q con el método de partición")
        
        # Método alternativo: probar k directamente
        print("[*] Probando método alternativo...")
        
        for k in range(1, 2 * e):
            if ed_minus_1 % k != 0:
                continue
            
            phi_n = ed_minus_1 // k
            
            # φ(n) debe ser ~256 bits
            if not (250 <= phi_n.bit_length() <= 260):
                continue
            
            # Factorizar φ(n) directamente (puede ser lento)
            # Pero si ya factorizamos ed-1, podemos derivar los factores
            
            # φ(n) = (ed-1) / k, así que sus factores son un subconjunto
            phi_factors = {}
            temp = phi_n
            for p_factor, count in factors.items():
                while temp % p_factor == 0:
                    phi_factors[p_factor] = phi_factors.get(p_factor, 0) + 1
                    temp //= p_factor
            
            if temp != 1:
                continue  # φ(n) tiene factores que no estaban en ed-1
            
            # Ahora buscamos (p-1) entre los divisores de φ(n)
            # (p-1) * (q-1) = φ(n)
            
            # Generar divisores de φ(n) cercanos a sqrt(φ(n))
            sqrt_phi = int(phi_n ** 0.5)
            
            # Los factores grandes probablemente están en p-1 y q-1
            for subset in combinations(range(len(large_primes)), len(large_primes) // 2):
                prod_a = 1
                prod_b = 1
                subset_set = set(subset)
                
                for i, lp in enumerate(large_primes):
                    if i in subset_set:
                        prod_a *= lp
                    else:
                        prod_b *= lp
                
                # Ahora distribuir factores pequeños
                if phi_n % (prod_a * prod_b) != 0:
                    continue
                
                small_remaining = phi_n // (prod_a * prod_b)
                
                for factor in range(1, min(int(small_remaining ** 0.5) + 2, 10000)):
                    if small_remaining % factor != 0:
                        continue
                    
                    other = small_remaining // factor
                    
                    pm1 = prod_a * factor
                    qm1 = prod_b * other
                    
                    p_cand = pm1 + 1
                    q_cand = qm1 + 1
                    
                    if 127 <= p_cand.bit_length() <= 130 and 127 <= q_cand.bit_length() <= 130:
                        if isPrime(p_cand) and isPrime(q_cand):
                            phi_check = pm1 * qm1
                            if (e * d) % phi_check == 1:
                                print(f"[+] p = {p_cand}")
                                print(f"[+] q = {q_cand}")
                                p_found, q_found = p_cand, q_cand
                                found = True
                                break
                if found:
                    break
            if found:
                break
    
    if not found:
        print("[!] Falló completamente")
        conn.close()
        return
    
    # Descifrar
    n = p_found * q_found
    m = pow(c, d, n)
    
    try:
        pride = long_to_bytes(m).decode()
        print(f"[+] pride = {pride}")
    except UnicodeDecodeError as ue:
        print(f"[!] Error decodificando: {ue}")
        print(f"[*] m = {m}")
        print(f"[*] m bytes = {long_to_bytes(m)}")
        
        # Podría ser que p y q están invertidos, o que encontramos los incorrectos
        # Probemos la otra opción
        print("[*] Probando otros candidatos...")
        conn.close()
        return
    
    # Enviar
    conn.recvuntil(b"> ")
    conn.sendline(pride.encode())
    
    # Flag
    response = conn.recvall(timeout=5).decode()
    print(f"\n[*] Response:\n{response}")
    
    conn.close()

if __name__ == "__main__":
    solve()
