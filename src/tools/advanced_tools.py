"""
Herramientas avanzadas adicionales para CTF Crypto
"""

import re
import hashlib
import itertools
from typing import Dict, List, Any, Optional
from langchain_core.tools import tool
import subprocess
import tempfile
import os

# ============ HERRAMIENTA 9: ANÁLISIS DE FRECUENCIAS ============

@tool
def frequency_analysis(text: str, language: str = "english") -> Dict[str, Any]:
    """
    Realiza análisis de frecuencias para criptoanálisis.
    
    Args:
        text: Texto a analizar
        language: Idioma para comparar frecuencias
        
    Returns:
        Dict con análisis de frecuencias y sugerencias
    """
    # Frecuencias esperadas en inglés
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
        'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
        'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
        'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
        'Q': 0.10, 'Z': 0.07
    }
    
    # Contar frecuencias en el texto
    text_upper = text.upper()
    letter_counts = {}
    total_letters = 0
    
    for char in text_upper:
        if char.isalpha():
            letter_counts[char] = letter_counts.get(char, 0) + 1
            total_letters += 1
    
    if total_letters == 0:
        return {"success": False, "error": "No letters found in text"}
    
    # Calcular frecuencias porcentuales
    text_freq = {}
    for letter, count in letter_counts.items():
        text_freq[letter] = (count / total_letters) * 100
    
    # Calcular chi-cuadrado para medir similitud con inglés
    chi_squared = 0
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        expected = english_freq.get(letter, 0)
        observed = text_freq.get(letter, 0)
        if expected > 0:
            chi_squared += ((observed - expected) ** 2) / expected
    
    # Sugerir posibles shifts para Caesar
    suggestions = []
    most_common = max(letter_counts.items(), key=lambda x: x[1])[0] if letter_counts else 'A'
    
    # Asumir que la letra más común es 'E'
    shift_to_e = (ord(most_common) - ord('E')) % 26
    suggestions.append({
        "type": "caesar",
        "shift": shift_to_e,
        "reason": f"Most common letter '{most_common}' mapped to 'E'"
    })
    
    return {
        "success": True,
        "letter_frequencies": text_freq,
        "chi_squared": chi_squared,
        "most_common_letter": most_common,
        "total_letters": total_letters,
        "suggestions": suggestions,
        "likely_language": "english" if chi_squared < 50 else "unknown"
    }

# ============ HERRAMIENTA 10: ATAQUES DE DICCIONARIO ============

@tool
def dictionary_attack(hash_value: str, hash_type: str = "auto", 
                     wordlist: str = "common") -> Dict[str, Any]:
    """
    Realiza ataque de diccionario contra hashes.
    
    Args:
        hash_value: Hash a crackear
        hash_type: Tipo de hash (md5, sha1, sha256, auto)
        wordlist: Wordlist a usar (common, rockyou)
        
    Returns:
        Dict con resultado del ataque
    """
    # Wordlists comunes
    common_passwords = [
        "password", "123456", "password123", "admin", "letmein",
        "welcome", "monkey", "1234567890", "qwerty", "abc123",
        "Password1", "password1", "root", "toor", "pass",
        "test", "guest", "user", "login", "secret"
    ]
    
    # Detectar tipo de hash automáticamente
    if hash_type == "auto":
        hash_len = len(hash_value)
        if hash_len == 32:
            hash_type = "md5"
        elif hash_len == 40:
            hash_type = "sha1"
        elif hash_len == 64:
            hash_type = "sha256"
        else:
            return {"success": False, "error": f"Unknown hash length: {hash_len}"}
    
    # Función de hash
    hash_functions = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256
    }
    
    if hash_type not in hash_functions:
        return {"success": False, "error": f"Unsupported hash type: {hash_type}"}
    
    hash_func = hash_functions[hash_type]
    target_hash = hash_value.lower()
    
    # Probar passwords comunes
    for password in common_passwords:
        computed_hash = hash_func(password.encode()).hexdigest()
        if computed_hash == target_hash:
            return {
                "success": True,
                "password": password,
                "hash_type": hash_type,
                "method": "common_passwords"
            }
    
    # Probar variaciones comunes
    for base_password in ["password", "admin", "test"]:
        for suffix in ["", "1", "123", "!", "@", "2023", "2024"]:
            for prefix in ["", "1", "@"]:
                candidate = prefix + base_password + suffix
                computed_hash = hash_func(candidate.encode()).hexdigest()
                if computed_hash == target_hash:
                    return {
                        "success": True,
                        "password": candidate,
                        "hash_type": hash_type,
                        "method": "variations"
                    }
    
    return {
        "success": False,
        "attempts": len(common_passwords) + 30,  # Aproximado
        "hash_type": hash_type
    }

# ============ HERRAMIENTA 11: ANÁLISIS DE ENTROPÍA ============

@tool
def entropy_analysis(data: str, encoding: str = "auto") -> Dict[str, Any]:
    """
    Analiza entropía de datos para detectar cifrado/compresión.
    
    Args:
        data: Datos a analizar
        encoding: Encoding de los datos (auto, hex, base64, raw)
        
    Returns:
        Dict con análisis de entropía
    """
    import math
    from collections import Counter
    
    # Detectar encoding automáticamente
    if encoding == "auto":
        if all(c in '0123456789abcdefABCDEF' for c in data.replace(' ', '')):
            encoding = "hex"
            try:
                data_bytes = bytes.fromhex(data.replace(' ', ''))
            except:
                data_bytes = data.encode()
        else:
            try:
                import base64
                decoded = base64.b64decode(data)
                if all(32 <= b <= 126 or b in [9, 10, 13] for b in decoded):
                    encoding = "base64"
                    data_bytes = decoded
                else:
                    encoding = "raw"
                    data_bytes = data.encode()
            except:
                encoding = "raw"
                data_bytes = data.encode()
    else:
        if encoding == "hex":
            data_bytes = bytes.fromhex(data.replace(' ', ''))
        elif encoding == "base64":
            import base64
            data_bytes = base64.b64decode(data)
        else:
            data_bytes = data.encode()
    
    # Calcular entropía de Shannon
    byte_counts = Counter(data_bytes)
    total_bytes = len(data_bytes)
    
    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    
    # Análisis de patrones
    max_entropy = 8.0  # Para bytes (2^8 = 256 posibilidades)
    entropy_ratio = entropy / max_entropy
    
    # Clasificación basada en entropía
    if entropy_ratio > 0.95:
        classification = "highly_random"  # Probablemente cifrado fuerte
    elif entropy_ratio > 0.8:
        classification = "random"  # Cifrado o compresión
    elif entropy_ratio > 0.6:
        classification = "mixed"  # Texto con algunos patrones
    else:
        classification = "structured"  # Texto plano o cifrado débil
    
    # Detectar patrones repetitivos
    patterns = {}
    for i in range(len(data_bytes) - 1):
        bigram = data_bytes[i:i+2]
        patterns[bigram] = patterns.get(bigram, 0) + 1
    
    most_common_pattern = max(patterns.items(), key=lambda x: x[1]) if patterns else None
    
    return {
        "entropy": entropy,
        "max_entropy": max_entropy,
        "entropy_ratio": entropy_ratio,
        "classification": classification,
        "total_bytes": total_bytes,
        "unique_bytes": len(byte_counts),
        "most_common_byte": max(byte_counts.items(), key=lambda x: x[1])[0],
        "most_common_pattern": most_common_pattern[0].hex() if most_common_pattern else None,
        "pattern_frequency": most_common_pattern[1] if most_common_pattern else 0,
        "detected_encoding": encoding
    }

# ============ HERRAMIENTA 12: GENERADOR DE EXPLOITS ============

@tool
def generate_exploit(attack_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Genera exploits personalizados para ataques específicos.
    
    Args:
        attack_type: Tipo de ataque (rsa_common_modulus, wiener, etc.)
        parameters: Parámetros del ataque
        
    Returns:
        Dict con código del exploit generado
    """
    exploits = {
        "rsa_common_modulus": """
# RSA Common Modulus Attack
from math import gcd
from Crypto.Util.number import inverse, long_to_bytes

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def common_modulus_attack(n, e1, e2, c1, c2):
    gcd_val, s, t = extended_gcd(e1, e2)
    if gcd_val != 1:
        return None
    
    if s < 0:
        s = -s
        c1 = inverse(c1, n)
    if t < 0:
        t = -t
        c2 = inverse(c2, n)
    
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return long_to_bytes(m)

# Parámetros
n = {n}
e1 = {e1}
e2 = {e2}
c1 = {c1}
c2 = {c2}

result = common_modulus_attack(n, e1, e2, c1, c2)
if result:
    print("Flag:", result.decode())
""",
        
        "rsa_wiener": """
# RSA Wiener Attack
import math
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

def continued_fractions(n, e):
    fractions = []
    while e != 0:
        fractions.append(n // e)
        n, e = e, n % e
    return fractions

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

def wiener_attack(n, e, c):
    cf = continued_fractions(e, n)
    convs = convergents(cf)
    
    for frac in convs:
        k, d = frac.numerator, frac.denominator
        if k == 0:
            continue
            
        phi = (e * d - 1) // k
        s = n - phi + 1
        discriminant = s * s - 4 * n
        
        if discriminant >= 0:
            sqrt_discriminant = int(math.sqrt(discriminant))
            if sqrt_discriminant * sqrt_discriminant == discriminant:
                p = (s + sqrt_discriminant) // 2
                q = (s - sqrt_discriminant) // 2
                if p * q == n:
                    m = pow(c, d, n)
                    return long_to_bytes(m)
    return None

# Parámetros
n = {n}
e = {e}
c = {c}

result = wiener_attack(n, e, c)
if result:
    print("Flag:", result.decode())
"""
    }
    
    if attack_type not in exploits:
        return {
            "success": False,
            "error": f"Unknown attack type: {attack_type}"
        }
    
    # Formatear exploit con parámetros
    try:
        exploit_code = exploits[attack_type].format(**parameters)
        return {
            "success": True,
            "exploit_code": exploit_code,
            "attack_type": attack_type,
            "parameters_used": list(parameters.keys())
        }
    except KeyError as e:
        return {
            "success": False,
            "error": f"Missing parameter: {e}"
        }

# ============ HERRAMIENTA 13: ANÁLISIS DE PADDING ============

@tool
def padding_oracle_analysis(ciphertext: str, block_size: int = 16) -> Dict[str, Any]:
    """
    Analiza padding para detectar vulnerabilidades de padding oracle.
    
    Args:
        ciphertext: Texto cifrado (hex)
        block_size: Tamaño de bloque en bytes
        
    Returns:
        Dict con análisis de padding
    """
    try:
        # Convertir hex a bytes
        ct_bytes = bytes.fromhex(ciphertext.replace(' ', ''))
        
        if len(ct_bytes) % block_size != 0:
            return {
                "success": False,
                "error": f"Ciphertext length not multiple of block size {block_size}"
            }
        
        num_blocks = len(ct_bytes) // block_size
        blocks = [ct_bytes[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
        
        # Análisis de patrones en bloques
        unique_blocks = set(blocks)
        repeated_blocks = []
        
        for i, block in enumerate(blocks):
            if blocks.count(block) > 1:
                repeated_blocks.append(i)
        
        # Detectar posible ECB mode
        ecb_detected = len(unique_blocks) < len(blocks)
        
        # Análisis del último bloque (posible padding)
        last_block = blocks[-1]
        possible_padding = []
        
        for pad_len in range(1, block_size + 1):
            if all(b == pad_len for b in last_block[-pad_len:]):
                possible_padding.append(pad_len)
        
        return {
            "success": True,
            "total_blocks": num_blocks,
            "unique_blocks": len(unique_blocks),
            "repeated_blocks": repeated_blocks,
            "ecb_mode_detected": ecb_detected,
            "possible_padding_lengths": possible_padding,
            "last_block_hex": last_block.hex(),
            "block_size": block_size
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# Lista actualizada de herramientas
ADVANCED_TOOLS = [
    frequency_analysis,
    dictionary_attack,
    entropy_analysis,
    generate_exploit,
    padding_oracle_analysis
]