"""
Herramientas especializadas para ataques RSA
Implementación de los ataques mencionados en Fase 1
"""

import math
import subprocess
import tempfile
import os
from typing import Dict, Any, Optional
from langchain_core.tools import tool
from fractions import Fraction

# ============ WIENER'S ATTACK ============

@tool
def wiener_attack(n: str, e: str, c: str = "") -> Dict[str, Any]:
    """
    Implementa Wiener's Attack contra RSA con d pequeño.
    
    Args:
        n: Módulo RSA (string)
        e: Exponente público (string)
        c: Ciphertext opcional (string)
        
    Returns:
        Dict con resultado del ataque
    """
    try:
        n_int = int(n)
        e_int = int(e)
        c_int = int(c) if c else None
        
        # Generar fracciones continuas de e/n
        def continued_fractions(a, b):
            fractions = []
            while b != 0:
                fractions.append(a // b)
                a, b = b, a % b
            return fractions
        
        # Generar convergentes
        def convergents(cf):
            convergents = []
            for i in range(len(cf)):
                if i == 0:
                    convergents.append(Fraction(cf[0]))
                elif i == 1:
                    convergents.append(Fraction(cf[1] * cf[0] + 1, cf[1]))
                else:
                    convergents.append(Fraction(
                        cf[i] * convergents[i-1].numerator + convergents[i-2].numerator,
                        cf[i] * convergents[i-1].denominator + convergents[i-2].denominator
                    ))
            return convergents
        
        cf = continued_fractions(e_int, n_int)
        convs = convergents(cf)
        
        for frac in convs:
            k, d = frac.numerator, frac.denominator
            if k == 0:
                continue
            
            # Verificar si (e*d - 1) es divisible por k
            if (e_int * d - 1) % k != 0:
                continue
            
            phi = (e_int * d - 1) // k
            
            # Resolver ecuación cuadrática para encontrar p y q
            s = n_int - phi + 1
            discriminant = s * s - 4 * n_int
            
            if discriminant >= 0:
                sqrt_discriminant = int(math.sqrt(discriminant))
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    p = (s + sqrt_discriminant) // 2
                    q = (s - sqrt_discriminant) // 2
                    
                    if p * q == n_int and p > 1 and q > 1:
                        # Encontramos p y q!
                        result = {
                            "success": True,
                            "attack_type": "Wiener's Attack",
                            "p": p,
                            "q": q,
                            "d": d,
                            "phi": phi
                        }
                        
                        # Si tenemos ciphertext, descifrarlo
                        if c_int:
                            try:
                                m = pow(c_int, d, n_int)
                                # Convertir a bytes y buscar flag
                                m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                                plaintext = m_bytes.decode('utf-8', errors='ignore')
                                
                                if 'flag{' in plaintext.lower():
                                    result["flag"] = plaintext
                                else:
                                    result["plaintext"] = plaintext
                                    
                            except Exception as e:
                                result["decrypt_error"] = str(e)
                        
                        return result
        
        return {
            "success": False,
            "attack_type": "Wiener's Attack",
            "error": "No vulnerable d found"
        }
        
    except Exception as e:
        return {
            "success": False,
            "attack_type": "Wiener's Attack",
            "error": str(e)
        }

# ============ FERMAT FACTORIZATION ============

@tool
def fermat_factorization(n: str, max_iterations: int = 10000) -> Dict[str, Any]:
    """
    Implementa Fermat Factorization para números con factores cercanos.
    
    Args:
        n: Número a factorizar (string)
        max_iterations: Máximo de iteraciones
        
    Returns:
        Dict con factores encontrados
    """
    try:
        n_int = int(n)
        
        # Verificar que n es impar
        if n_int % 2 == 0:
            return {
                "success": True,
                "attack_type": "Fermat Factorization",
                "p": 2,
                "q": n_int // 2
            }
        
        # Empezar desde ceil(sqrt(n))
        a = int(math.ceil(math.sqrt(n_int)))
        
        for i in range(max_iterations):
            b_squared = a * a - n_int
            
            if b_squared >= 0:
                b = int(math.sqrt(b_squared))
                
                if b * b == b_squared:
                    # Encontramos factores
                    p = a + b
                    q = a - b
                    
                    if p * q == n_int and p > 1 and q > 1:
                        return {
                            "success": True,
                            "attack_type": "Fermat Factorization",
                            "p": max(p, q),  # p > q por convención
                            "q": min(p, q),
                            "iterations": i + 1
                        }
            
            a += 1
        
        return {
            "success": False,
            "attack_type": "Fermat Factorization",
            "error": f"No factors found in {max_iterations} iterations"
        }
        
    except Exception as e:
        return {
            "success": False,
            "attack_type": "Fermat Factorization",
            "error": str(e)
        }

# ============ HASTAD'S BROADCAST ATTACK ============

@tool
def hastads_attack(n_list: list, e: int, c_list: list) -> Dict[str, Any]:
    """
    Implementa Hastad's Broadcast Attack para e pequeño.
    
    Args:
        n_list: Lista de módulos RSA
        e: Exponente común (pequeño)
        c_list: Lista de ciphertexts
        
    Returns:
        Dict con mensaje recuperado
    """
    try:
        # Verificar que tenemos suficientes ecuaciones
        if len(n_list) < e:
            return {
                "success": False,
                "attack_type": "Hastad's Broadcast Attack",
                "error": f"Need at least {e} equations, got {len(n_list)}"
            }
        
        # Usar Chinese Remainder Theorem
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        def chinese_remainder_theorem(remainders, moduli):
            total = 0
            prod = 1
            for m in moduli:
                prod *= m
            
            for r, m in zip(remainders, moduli):
                p = prod // m
                _, inv, _ = extended_gcd(p, m)
                total += r * inv * p
            
            return total % prod
        
        # Aplicar CRT
        n_ints = [int(n) for n in n_list[:e]]
        c_ints = [int(c) for c in c_list[:e]]
        
        result_crt = chinese_remainder_theorem(c_ints, n_ints)
        
        # Calcular raíz e-ésima
        def nth_root(x, n):
            # Método de Newton para raíz n-ésima
            if x == 0:
                return 0
            
            # Estimación inicial
            root = x
            while True:
                new_root = ((n - 1) * root + x // (root ** (n - 1))) // n
                if abs(new_root - root) < 1:
                    break
                root = new_root
            
            # Verificar exactitud
            if root ** n == x:
                return root
            elif (root + 1) ** n == x:
                return root + 1
            else:
                return None
        
        m = nth_root(result_crt, e)
        
        if m is not None:
            # Convertir a texto
            try:
                m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                plaintext = m_bytes.decode('utf-8', errors='ignore')
                
                return {
                    "success": True,
                    "attack_type": "Hastad's Broadcast Attack",
                    "message": m,
                    "plaintext": plaintext,
                    "flag": plaintext if 'flag{' in plaintext.lower() else None
                }
            except Exception as e:
                return {
                    "success": True,
                    "attack_type": "Hastad's Broadcast Attack",
                    "message": m,
                    "decode_error": str(e)
                }
        else:
            return {
                "success": False,
                "attack_type": "Hastad's Broadcast Attack",
                "error": "Could not compute exact root"
            }
            
    except Exception as e:
        return {
            "success": False,
            "attack_type": "Hastad's Broadcast Attack",
            "error": str(e)
        }

# ============ COMMON MODULUS ATTACK ============

@tool
def common_modulus_attack(n: str, e1: str, e2: str, c1: str, c2: str) -> Dict[str, Any]:
    """
    Implementa Common Modulus Attack cuando se usa el mismo n con diferentes e.
    
    Args:
        n: Módulo común
        e1, e2: Exponentes diferentes
        c1, c2: Ciphertexts correspondientes
        
    Returns:
        Dict con mensaje recuperado
    """
    try:
        n_int = int(n)
        e1_int = int(e1)
        e2_int = int(e2)
        c1_int = int(c1)
        c2_int = int(c2)
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        # Encontrar s y t tal que s*e1 + t*e2 = gcd(e1, e2)
        gcd, s, t = extended_gcd(e1_int, e2_int)
        
        if gcd != 1:
            return {
                "success": False,
                "attack_type": "Common Modulus Attack",
                "error": f"gcd(e1, e2) = {gcd} != 1"
            }
        
        # Calcular inversos modulares si es necesario
        def mod_inverse(a, m):
            gcd, x, _ = extended_gcd(a, m)
            if gcd != 1:
                return None
            return (x % m + m) % m
        
        # Ajustar para exponentes negativos
        if s < 0:
            s = -s
            c1_int = mod_inverse(c1_int, n_int)
            if c1_int is None:
                return {
                    "success": False,
                    "attack_type": "Common Modulus Attack",
                    "error": "Cannot compute modular inverse of c1"
                }
        
        if t < 0:
            t = -t
            c2_int = mod_inverse(c2_int, n_int)
            if c2_int is None:
                return {
                    "success": False,
                    "attack_type": "Common Modulus Attack",
                    "error": "Cannot compute modular inverse of c2"
                }
        
        # Calcular mensaje
        m = (pow(c1_int, s, n_int) * pow(c2_int, t, n_int)) % n_int
        
        # Convertir a texto
        try:
            m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            plaintext = m_bytes.decode('utf-8', errors='ignore')
            
            return {
                "success": True,
                "attack_type": "Common Modulus Attack",
                "message": m,
                "plaintext": plaintext,
                "flag": plaintext if 'flag{' in plaintext.lower() else None,
                "coefficients": {"s": s, "t": t}
            }
            
        except Exception as e:
            return {
                "success": True,
                "attack_type": "Common Modulus Attack",
                "message": m,
                "decode_error": str(e)
            }
            
    except Exception as e:
        return {
            "success": False,
            "attack_type": "Common Modulus Attack",
            "error": str(e)
        }

# Lista de herramientas RSA
RSA_ATTACK_TOOLS = [
    wiener_attack,
    fermat_factorization,
    hastads_attack,
    common_modulus_attack
]