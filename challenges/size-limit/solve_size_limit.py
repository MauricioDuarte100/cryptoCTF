#!/usr/bin/env python3
"""
Size-Limit Challenge Solver
===========================
Tipo: RSA Decryption
Patrón: Tenemos N, e, c, d. Descifrar directamente.
Si eso falla, factorizar N usando e*d para verificar.
"""

from Crypto.Util.number import long_to_bytes
import random
import math

# Datos del challenge
N = 65667982563395257456152578363358687414628050739860770903063206052667362178166666380390723634587933595241827767873104710537142458025201334420236653463444534018710274020834864080096247524541536313609304410859158429347482458882414275205742819080566766561312731091051276328620677195262137013588957713118640118673
e = 65537
c = 58443816925218320329602359198394095572237417576497896076618137604965419783093911328796166409276903249508047338019341719597113848471431947372873538253571717690982768328452282012361099369599755904288363602972252305949989677897650696581947849811037791349546750246816657184156675665729104603485387966759433211643
d = 14647215605104168233120807948419630020096019740227424951721591560155202409637919482865428659999792686501442518131270040719470657054982576354654918600616933355973824403026082055356501271036719280033851192012142309772828216012662939598631302504166489383155079998940570839539052860822636744356963005556392864865

def factor_with_ed(N, e, d):
    """Factoriza N cuando conocemos e y d usando un enfoque probabilístico."""
    k = e * d - 1
    
    # k = 2^t * r donde r es impar
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    
    for _ in range(100):
        g = random.randint(2, N - 2)
        x = pow(g, k, N)
        
        if x == 1 or x == N - 1:
            continue
            
        for _ in range(t - 1):
            y = pow(x, 2, N)
            if y == 1:
                p = math.gcd(x - 1, N)
                if 1 < p < N:
                    return p, N // p
            if y == N - 1:
                break
            x = y
    
    return None, None

print("[*] Factorizando N usando e y d...")
p, q = factor_with_ed(N, e, d)

if p and q:
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    print(f"[*] Verificando: p*q == N: {p*q == N}")
    
    # Recalcular phi y d para verificar
    phi = (p - 1) * (q - 1)
    d_check = pow(e, -1, phi)
    print(f"[*] d provisto == d calculado: {d == d_check}")
    
    # Descifrar
    m = pow(c, d, N)
    flag_bytes = long_to_bytes(m)
    print(f"\n[*] Descifrado (hex): {flag_bytes.hex()}")
    print(f"[*] Descifrado (len): {len(flag_bytes)}")
    
    # Intentar como string
    try:
        print(f"[+] FLAG: {flag_bytes.decode()}")
    except:
        # Mostrar printable
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag_bytes)
        print(f"[*] Printable: {printable}")
else:
    print("[-] No se pudo factorizar N")
    
    # Intentar descifrar directamente de todos modos
    m = pow(c, d, N)
    flag_bytes = long_to_bytes(m)
    print(f"\n[*] Descifrado directo (hex): {flag_bytes.hex()}")
    try:
        print(f"[+] FLAG: {flag_bytes.decode()}")
    except:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag_bytes)
        print(f"[*] Printable: {printable}")
