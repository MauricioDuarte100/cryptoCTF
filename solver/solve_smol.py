#!/usr/bin/env python3
"""
Solver SMOL - Version con conexion persistente
Mantiene una sola conexion y pide multiples firmas
"""

import socket
import ssl
import time
from hashlib import sha256
from math import gcd
import re

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NONCE_BITS = 200
NONCE_BOUND = 2**NONCE_BITS

def get_signatures_persistent(count=6, timeout_per_sig=120):
    """Obtener firmas con una sola conexion persistente"""
    context = ssl.create_default_context()
    raw = socket.create_connection(("smol.chals.nitectf25.live", 1337), timeout=300)
    sock = context.wrap_socket(raw, server_hostname="smol.chals.nitectf25.live")
    
    # Menu
    time.sleep(0.5)
    sock.recv(4096)
    print("[+] Conectado")
    
    sigs = []
    msg = b"test"
    z = int.from_bytes(sha256(msg).digest(), "big") % n
    
    for i in range(count * 2):
        if len(sigs) >= count:
            break
        
        print(f"\n[*] Solicitando firma {len(sigs)+1}/{count}...")
        
        # Enviar comando de firma
        sock.send(b"2\n")
        time.sleep(0.5)
        
        try:
            sock.settimeout(5)
            sock.recv(4096)  # "Enter message as hex:"
        except:
            pass
        
        # Enviar mensaje
        sock.send(b"74657374\n")  # "test" en hex
        
        # Esperar firma (hasta timeout_per_sig segundos)
        start = time.time()
        data = b""
        
        while time.time() - start < timeout_per_sig:
            try:
                sock.settimeout(2)
                chunk = sock.recv(8192)
                if chunk:
                    data += chunk
                    if b"> " in data:  # Prompt recibido, firma completa
                        break
            except socket.timeout:
                pass
            except Exception as e:
                print(f"[!] Error recv: {e}")
                break
        
        elapsed = time.time() - start
        
        if not data:
            print(f"[!] Sin respuesta ({elapsed:.1f}s)")
            continue
        
        text = data.decode()
        
        # Parse m, a, b
        m_match = re.search(r'm = (\d+)', text)
        a_match = re.search(r'a = (\d+)', text)
        b_match = re.search(r'b = (\d+)', text)
        
        if not (m_match and a_match and b_match):
            print(f"[!] Respuesta incompleta ({elapsed:.1f}s)")
            continue
        
        m_val = int(m_match.group(1))
        a_val = int(a_match.group(1))
        
        print(f"[+] Firma recibida en {elapsed:.1f}s")
        
        # Extraer r, s
        diff = a_val - pow(10, 11)
        if diff <= 0:
            print("[!] a - 10^11 <= 0")
            continue
        
        g = gcd(diff, m_val)
        if g <= 1 or g >= m_val:
            print("[!] GCD no funciono")
            continue
        
        r, s = g, m_val // g
        if pow(10 + r, 11, m_val) != a_val:
            r, s = s, r
        
        if pow(10 + r, 11, m_val) != a_val:
            print("[!] Verificacion fallida")
            continue
        
        print(f"    r = {r} ({r.bit_length()} bits)")
        print(f"    s = {s} ({s.bit_length()} bits)")
        sigs.append((r, s, z))
    
    sock.close()
    return sigs

def lattice_attack(sigs):
    """HNP lattice attack"""
    from fpylll import IntegerMatrix, LLL, BKZ
    
    num = len(sigs)
    print(f"\n[*] Lattice attack ({num} firmas)...")
    
    t_vals = [(z * pow(s, -1, n)) % n for r, s, z in sigs]
    u_vals = [(r * pow(s, -1, n)) % n for r, s, z in sigs]
    
    dim = num + 2
    M = [[0] * dim for _ in range(dim)]
    for i in range(num):
        M[i][i] = n
    for i in range(num):
        M[num][i] = u_vals[i]
    M[num][num] = 1
    for i in range(num):
        M[num + 1][i] = t_vals[i]
    M[num + 1][num + 1] = NONCE_BOUND
    
    mat = IntegerMatrix.from_matrix(M)
    LLL.reduction(mat)
    
    for i in range(mat.nrows):
        row = [mat[i, j] for j in range(mat.ncols)]
        for sign in [1, -1]:
            d = (sign * row[num]) % n
            if 1 < d < n - 1:
                ok = all(
                    (pow(s, -1, n) * (z + r * d)) % n < NONCE_BOUND or
                    (n - (pow(s, -1, n) * (z + r * d)) % n) < NONCE_BOUND
                    for r, s, z in sigs
                )
                if ok:
                    print(f"[+] d = {d}")
                    return d
    
    for bs in [20, 30]:
        mat = IntegerMatrix.from_matrix(M)
        BKZ.reduction(mat, BKZ.Param(block_size=bs))
        for i in range(mat.nrows):
            row = [mat[i, j] for j in range(mat.ncols)]
            for sign in [1, -1]:
                d = (sign * row[num]) % n
                if 1 < d < n - 1:
                    ok = all(
                        (pow(s, -1, n) * (z + r * d)) % n < NONCE_BOUND or
                        (n - (pow(s, -1, n) * (z + r * d)) % n) < NONCE_BOUND
                        for r, s, z in sigs
                    )
                    if ok:
                        print(f"[+] d = {d} (BKZ-{bs})")
                        return d
    
    return None

def forge_and_submit(d):
    from ecdsa import SECP256k1
    import secrets
    
    msg = b"gimme_flag"
    z = int.from_bytes(sha256(msg).digest(), "big") % n
    G = SECP256k1.generator
    
    while True:
        k = secrets.randbelow(n - 1) + 1
        R = k * G
        r = int(R.x()) % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (z + r * d)) % n
        if s:
            break
    
    print(f"\n[*] Firma: r={r}, s={s}")
    
    context = ssl.create_default_context()
    raw = socket.create_connection(("smol.chals.nitectf25.live", 1337), timeout=60)
    sock = context.wrap_socket(raw, server_hostname="smol.chals.nitectf25.live")
    
    time.sleep(0.5)
    sock.recv(4096)
    sock.send(b"3\n")
    time.sleep(0.5)
    sock.recv(4096)
    sock.send(str(r).encode() + b"\n")
    time.sleep(0.5)
    sock.recv(4096)
    sock.send(str(s).encode() + b"\n")
    time.sleep(1)
    result = sock.recv(4096).decode()
    sock.close()
    
    return result

def main():
    print("=" * 50)
    print("  SMOL - ECDSA Biased Nonce Attack (Persistent)")
    print("=" * 50)
    
    sigs = get_signatures_persistent(count=6, timeout_per_sig=120)
    
    if len(sigs) < 4:
        print(f"\n[!] Solo {len(sigs)} firmas")
        return
    
    d = lattice_attack(sigs)
    if not d:
        print("[!] Lattice fallo")
        return
    
    result = forge_and_submit(d)
    
    print("\n" + "=" * 50)
    print(f"  {result}")
    print("=" * 50)

if __name__ == "__main__":
    main()
