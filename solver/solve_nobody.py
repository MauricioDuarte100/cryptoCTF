#!/usr/bin/env python3
"""
Solver para el challenge "nobody" - CTF RSA
Vulnerabilidad: Inconsistencia de módulos en firma (mod p) vs verificación (mod n)

Ataque:
1. Extraer q usando cifrado (opción 3) - GCD de (m^e - c) para múltiples m
2. Extraer p usando firma (opción 1) - GCD de (sig^e - h) para múltiples firmas
3. Forjar firma válida mod n para "give_me_flag"
"""

from pwn import *
from hashlib import sha256
from math import gcd
from Crypto.Util.number import bytes_to_long
import gmpy2

# Configuración
HOST = "tcp.flagyard.com"
PORT = 27538
e = 65537

def bytes_to_long_hash(msg: bytes) -> int:
    """Calcula el hash SHA256 del mensaje como entero"""
    return bytes_to_long(sha256(msg).digest())

def encrypt_message(io, msg: str) -> int:
    """Opción 3: Cifra un mensaje y retorna el ciphertext"""
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Message to encrypt: ", msg.encode())
    io.recvuntil(b"enc: ")
    enc = int(io.recvline().strip())
    return enc

def sign_message(io, msg: str) -> int:
    """Opción 1: Firma un mensaje y retorna la firma"""
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Message to sign: ", msg.encode())
    io.recvuntil(b"Signature: ")
    sig = int(io.recvline().strip())
    return sig

def extract_q(io) -> int:
    """Extrae q usando cifrado de dos mensajes conocidos"""
    print("[*] Extrayendo q via opción de cifrado...")
    
    # Usar caracteres simples
    m1_real = bytes_to_long(b"A")  # 65
    m2_real = bytes_to_long(b"B")  # 66
    
    c1 = encrypt_message(io, "A")
    c2 = encrypt_message(io, "B")
    
    print(f"    m1={m1_real}, c1={c1}")
    print(f"    m2={m2_real}, c2={c2}")
    
    # q divide a (m^e - c) para ambos mensajes
    val1 = pow(m1_real, e) - c1
    val2 = pow(m2_real, e) - c2
    
    q = gcd(val1, val2)
    
    # Limpiar factores pequeños
    for small_prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        while q % small_prime == 0 and q.bit_length() > 500:
            q //= small_prime
    
    print(f"[+] q extraído (bits): {q.bit_length()}")
    return q

def extract_p(io) -> int:
    """Extrae p usando firmas - método GCD optimizado"""
    print("[*] Extrayendo p via análisis de firma...")
    
    # Obtener firmas de dos mensajes
    h1 = bytes_to_long_hash(b"hello")
    h2 = bytes_to_long_hash(b"world")
    
    sig1 = sign_message(io, "hello")
    sig2 = sign_message(io, "world")
    
    print(f"    sig1 bits: {sig1.bit_length()}")
    print(f"    sig2 bits: {sig2.bit_length()}")
    
    # p divide a (sig^e - h)
    # Usar gmpy2 para eficiencia
    print("[*] Calculando sig^e (esto toma tiempo)...")
    val1 = gmpy2.mpz(sig1) ** e - h1
    val2 = gmpy2.mpz(sig2) ** e - h2
    
    print("[*] Calculando GCD...")
    p = int(gmpy2.gcd(val1, val2))
    
    # Limpiar factores pequeños
    for small_prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        while p % small_prime == 0 and p.bit_length() > 500:
            p //= small_prime
    
    print(f"[+] p extraído (bits): {p.bit_length()}")
    return p

def forge_signature(p: int, q: int, msg: bytes) -> int:
    """Forja una firma válida mod n para el mensaje dado"""
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d_n = pow(e, -1, phi_n)
    
    h = bytes_to_long_hash(msg)
    sig = pow(h, d_n, n)
    
    print(f"[+] Firma forjada para '{msg.decode()}'")
    print(f"    n bits = {n.bit_length()}")
    
    # Verificar localmente
    check = pow(sig, e, n)
    print(f"    Verificación local: {check == h}")
    
    return sig, n

def main():
    print("=" * 60)
    print("Solver para 'nobody' - RSA Module Mismatch Attack")
    print("=" * 60)
    
    context.log_level = 'info'
    
    # Conectar al servidor
    io = remote(HOST, PORT)
    
    try:
        # Paso 1: Extraer q usando cifrado
        q = extract_q(io)
        
        # Paso 2: Extraer p usando firma
        p = extract_p(io)
        
        # Verificar validez
        if p.bit_length() < 500:
            print(f"[!] p tiene pocos bits: {p.bit_length()}")
        if q.bit_length() < 500:
            print(f"[!] q tiene pocos bits: {q.bit_length()}")
        
        # Paso 3: Forjar firma para "give_me_flag"
        target_msg = b"give_me_flag"
        forged_sig, n = forge_signature(p, q, target_msg)
        
        # Paso 4: Verificar la firma forjada
        print("\n[*] Enviando firma forjada...")
        
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"Message: ", b"give_me_flag")
        io.sendlineafter(b"Signature: ", str(forged_sig).encode())
        
        # Leer respuesta línea por línea
        print("[+] Respuesta del servidor:")
        for _ in range(5):
            try:
                line = io.recvline(timeout=2).decode().strip()
                print(f"    {line}")
                if "FlagY" in line or "flag" in line.lower():
                    print("\n" + "=" * 60)
                    print(f"[!] FLAG: {line}")
                    print("=" * 60)
            except:
                break
        
    except Exception as ex:
        print(f"[!] Error: {ex}")
        import traceback
        traceback.print_exc()
    finally:
        io.close()

if __name__ == "__main__":
    main()
