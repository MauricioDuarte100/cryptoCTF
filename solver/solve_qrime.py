"""
Solver para el desafío qrime - RSA con generación de p débil

Estructura clave:
    p = q * nextPrime(r) + nextPrime(q) * r
    n = p * q

Dado r, podemos calcular nextPrime(r) = r'.
Dado que n = p * q y p tiene estructura conocida, podemos factorizar.

Ataque: 
- n = q * p = q * (q * r' + q' * r) donde q' = nextPrime(q)
- q' es muy cercano a q (diferencia pequeña δ)
- Aproximamos: n ≈ q² * r' + q² * r = q² * (r' + r)
- Entonces q ≈ sqrt(n / (r' + r))
- Buscamos primos cerca de esta estimación que dividan n
"""

from Crypto.Util.number import isPrime, long_to_bytes
from math import isqrt

def nextPrime(n):
    """Encuentra el siguiente primo mayor que n"""
    while not isPrime(n := n + 1):
        continue
    return n

def solve():
    # Datos del desafío
    n = 1597349797582252189737622221791988995702203505409122048213056145385432056678668011744383472026126622313229593211723275251532300454579372254725326775404977015496304747248416324105306138292084116374337609917577700786808299040936359837
    e = 65537
    c = 972720840499592344446463443980685660383495734796643528156038336075094110601869565083456517200700906514513655122880885701228182964785192363570987340004695486727354284548049636771649892722940274205296325372249242376864953467610809561
    r = 93306715077150526900611207656501624167797808502485855834333355823957291927822
    
    # Calcular r' = nextPrime(r)
    r_prime = nextPrime(r)
    print(f"r' = nextPrime(r) = {r_prime}")
    
    # Estimación inicial de q
    # n = q * (q * r' + q' * r) ≈ q² * (r' + r)  (ya que q' ≈ q)
    q_estimate = isqrt(n // (r_prime + r))
    print(f"Estimación inicial de q: {q_estimate}")
    print(f"Bits de q_estimate: {q_estimate.bit_length()}")
    
    # Buscar q cerca de la estimación
    # Probamos un rango alrededor de la estimación
    search_range = 10**8  # Rango de búsqueda
    
    print(f"\nBuscando q que divida n en rango [{q_estimate - search_range}, {q_estimate + search_range}]...")
    
    # Método más eficiente: buscar primos y verificar divisibilidad
    q_found = None
    
    # Primero verificar si la estimación directa funciona
    for offset in range(-search_range, search_range + 1):
        candidate = q_estimate + offset
        if candidate > 1 and n % candidate == 0:
            if isPrime(candidate):
                q_found = candidate
                print(f"Encontrado q = {q_found} (offset: {offset})")
                break
    
    if not q_found:
        print("No se encontró q en el rango inicial. Probando enfoque alternativo...")
        
        # Enfoque alternativo: resolver la ecuación cuadrática más precisamente
        # n = q * p = q * (q * r' + q' * r)
        # Sabemos que q' = q + δ donde δ es pequeño (<1000 típicamente para primos de 256 bits)
        # n = q² * r' + q * (q + δ) * r = q² * r' + q² * r + q * δ * r
        # n = q² * (r' + r) + q * δ * r
        
        # Iteramos sobre posibles valores de δ
        for delta in range(1, 10000):
            # Para cada δ, resolvemos: q² * (r' + r) + q * δ * r - n = 0
            # Ecuación cuadrática: a*q² + b*q + c = 0
            a = r_prime + r
            b = delta * r
            c_coef = -n
            
            # Discriminante: b² - 4ac
            discriminant = b * b - 4 * a * c_coef
            if discriminant < 0:
                continue
                
            sqrt_disc = isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue  # No es un cuadrado perfecto
            
            # q = (-b + sqrt(discriminant)) / (2a)
            q_candidate = (-b + sqrt_disc) // (2 * a)
            
            if q_candidate > 0 and n % q_candidate == 0 and isPrime(q_candidate):
                # Verificar que nextPrime(q) = q + delta
                if nextPrime(q_candidate) == q_candidate + delta:
                    q_found = q_candidate
                    print(f"Encontrado q = {q_found} con δ = {delta}")
                    break
    
    if not q_found:
        print("Error: No se pudo encontrar q")
        return None
    
    q = q_found
    p = n // q
    
    print(f"\nFactorización exitosa:")
    print(f"q = {q}")
    print(f"p = {p}")
    print(f"Verificación: p * q == n: {p * q == n}")
    
    # Verificar la estructura de p
    q_prime = nextPrime(q)
    p_calculated = q * r_prime + q_prime * r
    print(f"Verificación estructura: p == q*r' + q'*r: {p == p_calculated}")
    
    # Descifrar RSA
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    
    flag = long_to_bytes(m)
    print(f"\nFlag: {flag.decode()}")
    
    return flag

if __name__ == "__main__":
    solve()
