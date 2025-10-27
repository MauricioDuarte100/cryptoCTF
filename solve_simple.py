#!/usr/bin/env python3
"""
Simple CTF Solver - Version simplificada que funciona
Ejecuta el challenge y extrae la flag directamente
"""

import sys
import os
import subprocess
import re
from pathlib import Path

def extract_flag_from_output(output):
    """Extrae flags del output usando patrones comunes mejorados"""
    
    # Patrones de flags comunes (mejorados)
    flag_patterns = [
        r'flag\{[^}]+\}',           # flag{...}
        r'FLAG\{[^}]+\}',           # FLAG{...}
        r'ctf\{[^}]+\}',            # ctf{...}
        r'CTF\{[^}]+\}',            # CTF{...}
        r'picoCTF\{[^}]+\}',        # picoCTF{...}
        r'hackthebox\{[^}]+\}',     # hackthebox{...}
        r'\{[^}]*flag[^}]*\}',      # {something_flag_something}
        r'[a-zA-Z0-9_]+\{[^}]+\}',  # generic{...}
        r'\b[0-9a-f]{32}\b',        # MD5 hash
        r'\b[0-9a-f]{40}\b',        # SHA1 hash
        r'\b[0-9a-f]{64}\b',        # SHA256 hash
    ]
    
    for pattern in flag_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            # Retornar el match más probable (el que contiene 'flag')
            for match in matches:
                if 'flag' in match.lower():
                    return match
            return matches[0]  # Si ninguno contiene 'flag', retornar el primero
    
    return None

def decode_base64_recursive(text, max_depth=10):
    """Decodifica Base64 recursivamente hasta encontrar flag o texto legible"""
    import base64
    import re
    
    if not text:
        return None
    
    current = text.strip()
    
    for depth in range(max_depth):
        try:
            # Intentar decodificar Base64
            decoded_bytes = base64.b64decode(current)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            
            print(f"  Layer {depth + 1}: {decoded[:50]}...")
            
            # ¿Encontramos flag?
            if 'flag{' in decoded.lower() or 'ctf{' in decoded.lower():
                print(f"  🎯 Found flag at layer {depth + 1}!")
                return decoded
            
            # Intentar hex decode si parece hex
            if re.match(r'^[0-9a-fA-F]+$', decoded.strip()) and len(decoded.strip()) % 2 == 0:
                try:
                    hex_decoded = bytes.fromhex(decoded.strip()).decode('utf-8', errors='ignore')
                    print(f"  Layer {depth + 1} (hex): {hex_decoded[:50]}...")
                    if 'flag{' in hex_decoded.lower() or 'ctf{' in hex_decoded.lower():
                        print(f"  🎯 Found flag in hex at layer {depth + 1}!")
                        return hex_decoded
                    # Continuar con el resultado hex decodificado
                    current = hex_decoded.strip()
                    continue
                except Exception as e:
                    print(f"  Hex decode failed: {e}")
            
            # ¿Parece que hay más Base64 para decodificar?
            if re.match(r'^[A-Za-z0-9+/=]+$', decoded.strip()) and len(decoded.strip()) > 10:
                current = decoded.strip()
            else:
                # No parece más Base64, pero podría contener flag
                if any(keyword in decoded.lower() for keyword in ['flag', 'ctf', 'picoctf']):
                    return decoded
                return decoded
            
        except Exception as e:
            print(f"  Layer {depth + 1}: Failed to decode - {e}")
            # Si falla la decodificación, retornar lo que tenemos hasta ahora
            return current if depth > 0 else None
    
    return current

def detect_aes_ecb(ciphertext_hex):
    """Detecta si un ciphertext usa AES ECB mode"""
    try:
        if len(ciphertext_hex) % 32 != 0:  # AES blocks are 16 bytes = 32 hex chars
            return False
        
        # Dividir en bloques de 16 bytes (32 hex chars)
        blocks = [ciphertext_hex[i:i+32] for i in range(0, len(ciphertext_hex), 32)]
        
        # Si hay bloques repetidos, probablemente es ECB
        return len(blocks) != len(set(blocks))
    except:
        return False

def decrypt_aes_ecb(ciphertext_hex, key):
    """Intenta descifrar AES ECB con una clave dada"""
    try:
        from Crypto.Cipher import AES
        
        ciphertext = bytes.fromhex(ciphertext_hex)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        
        # Remover padding PKCS7
        padding_length = plaintext[-1]
        if padding_length <= 16:
            plaintext = plaintext[:-padding_length]
        
        return plaintext.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  AES ECB decrypt error: {e}")
        return None

def solve_aes_challenge(file_path):
    """Resuelve challenges AES/DES"""
    
    print("🔐 Detected AES/DES challenge, trying symmetric attacks...")
    
    try:
        # Ejecutar el archivo
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Buscar ciphertext hex
        hex_matches = re.findall(r'([0-9a-fA-F]{32,})', output)
        
        for hex_data in hex_matches:
            print(f"🔢 Found hex data: {hex_data[:64]}...")
            
            # Intentar claves comunes para AES
            common_keys = [
                b'YELLOW SUBMARINE',  # Común en challenges
                b'1234567890123456',
                b'abcdefghijklmnop',
                b'0123456789abcdef',
                b'secretkey123456',
                b'thisisasecretkey',
                b'mysecretpassword'[:16],
                b'password1234567'[:16]
            ]
            
            print("🎯 Trying AES decryption with common keys...")
            for key in common_keys:
                if len(key) == 16:  # AES-128
                    plaintext = decrypt_aes_ecb(hex_data, key)
                    if plaintext and 'flag{' in plaintext.lower():
                        print(f"✅ Found flag with AES ECB key {key}: {plaintext}")
                        return plaintext
            
            # Detectar AES ECB para información
            if detect_aes_ecb(hex_data):
                print("📊 Note: This appears to be AES ECB mode (repeated blocks detected)")
            
            # Intentar como simple hex decode
            try:
                hex_decoded = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')
                if 'flag{' in hex_decoded.lower():
                    print(f"✅ Found flag in hex decode: {hex_decoded}")
                    return hex_decoded
            except:
                pass
        
        # Buscar flag directamente
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving AES challenge: {e}")
    
    return None

def solve_rsa_challenge(file_path):
    """Resuelve challenges RSA específicamente"""
    
    print("🔐 Detected RSA challenge, trying RSA attacks...")
    
    try:
        # Ejecutar el archivo para obtener los valores
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Extraer n, e, c del output
        n_match = re.search(r'n = (\d+)', output)
        e_match = re.search(r'e = (\d+)', output)
        c_match = re.search(r'c = (\d+)', output)
        
        if n_match and e_match and c_match:
            n = int(n_match.group(1))
            e = int(e_match.group(1))
            c = int(c_match.group(1))
            
            print(f"🔢 Extracted: n={n}, e={e}, c={c}")
            
            # Intentar ataque de exponente pequeño
            if e == 3:
                print("🎯 Trying small exponent attack (e=3)...")
                try:
                    import gmpy2
                    from Crypto.Util.number import long_to_bytes
                    
                    # Cube root attack
                    m, exact = gmpy2.iroot(c, 3)
                    if exact:
                        flag_bytes = long_to_bytes(m)
                        flag = flag_bytes.decode('ascii', errors='ignore')
                        if 'flag{' in flag.lower():
                            print(f"✅ Found flag with cube root: {flag}")
                            return flag
                except Exception as e:
                    print(f"⚠️ Cube root attack failed: {e}")
            
            # Intentar factorización simple
            print("🔧 Trying simple factorization...")
            try:
                import gmpy2
                from Crypto.Util.number import long_to_bytes
                
                # Intentar factorizar n (método básico)
                for i in range(2, min(1000000, int(n**0.5) + 1)):
                    if n % i == 0:
                        p = i
                        q = n // i
                        print(f"🎯 Found factors: p={p}, q={q}")
                        
                        phi = (p - 1) * (q - 1)
                        d = gmpy2.invert(e, phi)
                        m = pow(c, d, n)
                        
                        flag_bytes = long_to_bytes(m)
                        flag = flag_bytes.decode('ascii', errors='ignore')
                        if 'flag{' in flag.lower():
                            print(f"✅ Found flag with factorization: {flag}")
                            return flag
                        break
            except Exception as e:
                print(f"⚠️ Simple factorization failed: {e}")
            
            # Intentar Fermat factorization (para p ≈ q)
            print("🔧 Trying Fermat factorization...")
            try:
                import gmpy2
                from Crypto.Util.number import long_to_bytes
                
                # Fermat factorization
                a = gmpy2.isqrt(n) + 1
                for _ in range(1000000):  # Límite de iteraciones
                    b_squared = a * a - n
                    b = gmpy2.isqrt(b_squared)
                    
                    if b * b == b_squared:
                        p = a + b
                        q = a - b
                        if p * q == n and p > 1 and q > 1:
                            print(f"🎯 Fermat found factors: p={p}, q={q}")
                            
                            phi = (p - 1) * (q - 1)
                            d = gmpy2.invert(e, phi)
                            m = pow(c, d, n)
                            
                            flag_bytes = long_to_bytes(m)
                            flag = flag_bytes.decode('ascii', errors='ignore')
                            if 'flag{' in flag.lower():
                                print(f"✅ Found flag with Fermat: {flag}")
                                return flag
                            break
                    a += 1
            except Exception as e:
                print(f"⚠️ Fermat factorization failed: {e}")
        
        # Buscar flag directamente en el output
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving RSA challenge: {e}")
    
    return None

def solve_classical_challenge(file_path):
    """Resuelve challenges de cifrado clásico"""
    
    print("📜 Detected classical cipher, trying common attacks...")
    
    try:
        # Ejecutar el archivo
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Buscar texto cifrado
        encrypted_match = re.search(r'Encrypted[^:]*:\s*([A-Za-z0-9+/=\{\}_\s]+)', output)
        if encrypted_match:
            encrypted = encrypted_match.group(1).strip()
            print(f"🔤 Found encrypted text: {encrypted}")
            
            # Intentar Caesar cipher (ROT13 y otros)
            print("🎯 Trying Caesar cipher attacks...")
            for shift in range(26):
                decrypted = ""
                for char in encrypted:
                    if char.isalpha():
                        ascii_offset = 65 if char.isupper() else 97
                        decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                    else:
                        decrypted += char
                
                if 'flag{' in decrypted.lower():
                    print(f"✅ Found flag with Caesar shift {shift}: {decrypted}")
                    return decrypted
        
        # Buscar flag directamente
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving classical challenge: {e}")
    
    return None

def solve_xor_challenge(file_path):
    """Resuelve challenges XOR"""
    
    print("⚡ Detected XOR challenge, trying XOR attacks...")
    
    try:
        # Ejecutar el archivo
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Buscar datos hex
        hex_match = re.search(r'([0-9a-fA-F]{20,})', output)
        if hex_match:
            hex_data = hex_match.group(1)
            print(f"🔢 Found hex data: {hex_data}")
            
            try:
                encrypted_bytes = bytes.fromhex(hex_data)
                
                # Intentar single-byte XOR
                print("🎯 Trying single-byte XOR...")
                for key in range(256):
                    decrypted = bytes([b ^ key for b in encrypted_bytes])
                    try:
                        text = decrypted.decode('ascii')
                        if 'flag{' in text.lower():
                            print(f"✅ Found flag with XOR key {key}: {text}")
                            return text
                    except:
                        pass
            except Exception as e:
                print(f"⚠️ XOR attack failed: {e}")
        
        # Buscar flag directamente
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving XOR challenge: {e}")
    
    return None

def solve_encoding_challenge(file_path):
    """Resuelve challenges de encoding"""
    
    print("🔤 Detected encoding challenge, trying decoding attacks...")
    
    try:
        # Ejecutar el archivo
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Buscar datos encoded (mejorado para evitar líneas de =)
        encoded_matches = re.findall(r'([A-Za-z0-9+/]{10,}[A-Za-z0-9+/=]*)', output)
        for encoded_data in encoded_matches:
            # Filtrar líneas que son solo símbolos de separación
            if len(set(encoded_data)) > 3:  # Debe tener variedad de caracteres
                print(f"🔤 Found encoded data: {encoded_data[:50]}...")
                
                # Intentar Base64 múltiples capas
                print("🎯 Trying Base64 decoding...")
                try:
                    result = decode_base64_recursive(encoded_data)
                    if result and ('flag{' in result.lower() or 'ctf{' in result.lower()):
                        print(f"✅ Found flag with Base64 decoding: {result}")
                        return result
                except Exception as e:
                    print(f"⚠️ Base64 recursive decoding failed: {e}")
                    continue
        
        # Buscar flag directamente
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving encoding challenge: {e}")
    
    return None

def solve_hash_challenge(file_path):
    """Resuelve challenges de hash"""
    
    print("🔐 Detected hash challenge, trying hash attacks...")
    
    try:
        # Ejecutar el archivo
        result = subprocess.run([sys.executable, file_path], 
                              capture_output=True, text=True, timeout=30)
        
        output = result.stdout + result.stderr
        print(f"📄 Challenge output:\n{output}")
        
        # Buscar hash MD5/SHA
        hash_match = re.search(r'([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', output)
        if hash_match:
            hash_value = hash_match.group(1)
            print(f"🔢 Found hash: {hash_value}")
            
            # Diccionario común
            common_words = [
                "password", "123456", "password123", "admin", "letmein",
                "welcome", "monkey", "1234567890", "qwerty", "abc123",
                "password1", "123123", "000000", "iloveyou", "1234567",
                "rockyou", "12345678", "abc123", "123456789", "welcome123"
            ]
            
            import hashlib
            
            print("🎯 Trying dictionary attack...")
            for word in common_words:
                # MD5
                if len(hash_value) == 32:
                    if hashlib.md5(word.encode()).hexdigest() == hash_value.lower():
                        flag = f"flag{{{word}}}"
                        print(f"✅ Found flag with MD5: {flag}")
                        return flag
                
                # SHA1
                elif len(hash_value) == 40:
                    if hashlib.sha1(word.encode()).hexdigest() == hash_value.lower():
                        flag = f"flag{{{word}}}"
                        print(f"✅ Found flag with SHA1: {flag}")
                        return flag
        
        # Buscar flag directamente
        flag = extract_flag_from_output(output)
        if flag:
            print(f"✅ Found flag in output: {flag}")
            return flag
            
    except Exception as e:
        print(f"❌ Error solving hash challenge: {e}")
    
    return None

def detect_challenge_type(file_path):
    """Detecta el tipo de challenge por el contenido"""
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
        
        # Detectar por palabras clave (orden importa - más específico primero)
        if any(word in content for word in ['caesar', 'shift', 'rot13', 'chr(', 'ord(']):
            return 'classical'
        elif any(word in content for word in ['aes', 'des', 'crypto.cipher', 'mode_ecb', 'mode_cbc', 'yellow submarine']):
            return 'aes'
        elif any(word in content for word in ['hashlib', 'md5', 'sha', 'hash']):
            return 'hash'
        elif any(word in content for word in ['rsa', 'pow(', 'getprime', 'crypto.util']):
            return 'rsa'
        elif any(word in content for word in ['xor', '^', 'bytes([']):
            return 'xor'
        elif any(word in content for word in ['base64', 'b64encode', 'b64decode']):
            return 'encoding'
        elif any(word in content for word in ['cipher']):
            return 'classical'
        else:
            return 'unknown'
            
    except Exception as e:
        print(f"⚠️ Error detecting challenge type: {e}")
        return 'unknown'

def solve_ctf_challenge(file_path):
    """Función principal para resolver challenges"""
    
    print(f"🎯 SOLVING: {file_path}")
    print("=" * 50)
    
    # Detectar tipo
    challenge_type = detect_challenge_type(file_path)
    print(f"🔍 Detected type: {challenge_type.upper()}")
    
    # Resolver según el tipo
    solvers = {
        'rsa': solve_rsa_challenge,
        'classical': solve_classical_challenge,
        'xor': solve_xor_challenge,
        'encoding': solve_encoding_challenge,
        'hash': solve_hash_challenge,
        'aes': solve_aes_challenge
    }
    
    solver = solvers.get(challenge_type)
    if solver:
        flag = solver(file_path)
        if flag:
            return flag
    
    # Fallback: intentar todos los solvers
    print("🔄 Trying all solvers as fallback...")
    for solver_name, solver_func in solvers.items():
        if solver_name != challenge_type:  # Skip ya intentado
            print(f"🎯 Trying {solver_name} solver...")
            flag = solver_func(file_path)
            if flag:
                return flag
    
    return None

def main():
    """Función principal"""
    
    if len(sys.argv) < 2:
        print("Usage: python solve_simple.py <challenge.py>")
        sys.exit(1)
    
    challenge_file = sys.argv[1]
    
    if not os.path.exists(challenge_file):
        print(f"❌ File not found: {challenge_file}")
        sys.exit(1)
    
    print("SIMPLE CTF SOLVER")
    print("Direct challenge execution and analysis")
    print()
    
    flag = solve_ctf_challenge(challenge_file)
    
    print("\n" + "=" * 50)
    if flag:
        print("SUCCESS!")
        print(f"FLAG: {flag}")
        sys.exit(0)
    else:
        print("FAILED")
        print("No flag found with current methods")
        sys.exit(1)

if __name__ == "__main__":
    main()