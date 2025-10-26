"""
Herramientas especializadas para resolver CTF Crypto
Optimizadas para uso con Gemini function calling
"""

import re
import subprocess
import tempfile
import os
from typing import Dict, List, Any
from langchain_core.tools import tool

# ============ HERRAMIENTA 1: ANALIZAR ARCHIVOS ============

@tool
def analyze_files(files: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Analiza archivos de desafío CTF (.py, .sage, .txt) para extraer 
    parámetros criptográficos, imports, y estructura.
    
    Args:
        files: Lista de dicts con 'name' y 'content'
        
    Returns:
        Dict con imports, variables, funciones, e indicadores crypto
    """
    result = {
        "imports": [],
        "variables": {},
        "functions": [],
        "crypto_indicators": [],
        "file_summary": []
    }
    
    for file in files:
        name = file.get("name", "unknown")
        content = file.get("content", "")
        
        # Detectar imports
        imports = re.findall(r'^(?:from|import)\s+(\S+)', content, re.MULTILINE)
        result["imports"].extend(imports)
        
        # Extraer variables numéricas grandes (RSA params, etc.)
        # Soporta decimal y hex
        var_pattern = r'(\w+)\s*=\s*(\d{10,}|0x[0-9a-fA-F]{10,})'
        matches = re.findall(var_pattern, content)
        for var_name, var_value in matches:
            try:
                # Convertir a int (soporta hex con 0x)
                result["variables"][var_name] = int(var_value, 0)
            except:
                result["variables"][var_name] = var_value
        
        # Detectar funciones definidas
        functions = re.findall(r'def\s+(\w+)\s*\(', content)
        result["functions"].extend(functions)
        
        # Detectar indicadores de tipo de crypto
        content_lower = content.lower()
        
        # RSA
        if 'rsa' in content_lower or \
           any(v in result["variables"] for v in ['n', 'e', 'c', 'p', 'q']):
            result["crypto_indicators"].append("RSA")
        
        # AES/DES
        if 'aes' in content_lower or 'des' in content_lower or \
           'Crypto.Cipher.AES' in content:
            result["crypto_indicators"].append("AES/DES")
        
        # Cifrados clásicos
        if any(word in content_lower for word in ['caesar', 'rot', 'vigenere', 'substitution']):
            result["crypto_indicators"].append("Classical")
        
        # XOR
        if 'xor' in content_lower or '^' in content:
            result["crypto_indicators"].append("XOR")
        
        # Hash
        if any(word in content_lower for word in ['md5', 'sha', 'hash']):
            result["crypto_indicators"].append("Hash")
        
        # Lattice
        if any(word in content_lower for word in ['lattice', 'lll', 'matrix']):
            result["crypto_indicators"].append("Lattice")
        
        # ECC
        if 'elliptic' in content_lower or 'ecc' in content_lower:
            result["crypto_indicators"].append("ECC")
        
        result["file_summary"].append({
            "name": name,
            "lines": len(content.split('\n')),
            "size_bytes": len(content)
        })
    
    return result

# ============ HERRAMIENTA 2: CLASIFICAR CRYPTO ============

@tool
def classify_crypto(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clasifica el tipo de criptografía basándose en análisis de archivos.
    
    Args:
        analysis: Resultado de analyze_files()
        
    Returns:
        Dict con 'type' y 'confidence' (0.0 - 1.0)
    """
    indicators = analysis.get("crypto_indicators", [])
    variables = analysis.get("variables", {})
    imports = analysis.get("imports", [])
    
    # Sistema de scoring
    scores = {}
    
    # RSA detection
    rsa_score = 0.0
    if "RSA" in indicators:
        rsa_score += 0.3
    if all(v in variables for v in ['n', 'e', 'c']):
        rsa_score += 0.5
    if 'Crypto.PublicKey.RSA' in imports:
        rsa_score += 0.2
    scores["RSA"] = min(rsa_score, 1.0)
    
    # AES/DES detection
    aes_score = 0.0
    if "AES/DES" in indicators:
        aes_score += 0.5
    if any('Crypto.Cipher' in imp for imp in imports):
        aes_score += 0.4
    scores["AES"] = min(aes_score, 1.0)
    
    # Classical cipher detection
    classical_score = 0.0
    if "Classical" in indicators:
        classical_score += 0.6
    if any(func in analysis.get("functions", []) for func in ['encrypt', 'decrypt', 'caesar', 'vigenere']):
        classical_score += 0.3
    scores["Classical"] = min(classical_score, 1.0)
    
    # XOR detection
    xor_score = 0.0
    if "XOR" in indicators:
        xor_score += 0.7
    scores["XOR"] = min(xor_score, 1.0)
    
    # Hash detection
    hash_score = 0.0
    if "Hash" in indicators:
        hash_score += 0.6
    scores["Hash"] = min(hash_score, 1.0)
    
    # Lattice detection
    lattice_score = 0.0
    if "Lattice" in indicators:
        lattice_score += 0.5
    if any('sage' in imp.lower() or 'fpylll' in imp for imp in imports):
        lattice_score += 0.4
    scores["Lattice"] = min(lattice_score, 1.0)
    
    # Seleccionar el tipo con mayor score
    if not scores or max(scores.values()) < 0.3:
        return {"type": "Unknown", "confidence": 0.1, "all_scores": scores}
    
    best_type = max(scores, key=scores.get)
    confidence = scores[best_type]
    
    return {
        "type": best_type,
        "confidence": confidence,
        "all_scores": scores
    }

# ============ HERRAMIENTA 3: CONECTAR NETCAT ============

@tool
def connect_netcat(host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
    """
    Conecta a servidor netcat del desafío y captura output.
    
    Args:
        host: Hostname o IP
        port: Puerto
        timeout: Timeout en segundos
        
    Returns:
        Dict con 'success', 'output', 'error'
    """
    try:
        from pwn import remote
        import time
        
        conn = remote(host, port, timeout=timeout)
        time.sleep(0.5)  # Esperar banner
        
        # Capturar todo el output disponible
        output = conn.recvall(timeout=timeout).decode(errors='ignore')
        conn.close()
        
        return {
            "success": True,
            "output": output,
            "error": None
        }
    
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e)
        }

# ============ HERRAMIENTA 4: ATACAR RSA ============

@tool
def attack_rsa(n: str, e: str, c: str = "", timeout: int = 60) -> Dict[str, Any]:
    """
    Ejecuta batería de ataques RSA usando RsaCtfTool.
    
    Args:
        n: Módulo RSA (string decimal o hex)
        e: Exponente público (string decimal)
        c: Ciphertext (opcional, string decimal o hex)
        timeout: Timeout en segundos
        
    Returns:
        Dict con 'success', 'flag', 'output', 'attack_used'
    """
    try:
        # Verificar que RsaCtfTool existe
        rsactftool_path = "./RsaCtfTool/RsaCtfTool.py"
        if not os.path.exists(rsactftool_path):
            # Intentar path alternativo
            rsactftool_path = "RsaCtfTool.py"
            if not os.path.exists(rsactftool_path):
                return {
                    "success": False,
                    "output": "RsaCtfTool not found. Please install: git clone https://github.com/RsaCtfTool/RsaCtfTool.git",
                    "flag": None
                }
        
        # Construir comando
        cmd = ["python3", rsactftool_path, "-n", str(n), "-e", str(e)]
        
        if c:
            cmd.extend(["--uncipher", str(c)])
        
        # Ejecutar con timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Buscar flag en output
        flag_match = re.search(r'flag\{[^}]+\}', output, re.IGNORECASE)
        
        # Detectar qué ataque funcionó
        attack_used = "unknown"
        if "wiener" in output.lower():
            attack_used = "Wiener's Attack"
        elif "fermat" in output.lower():
            attack_used = "Fermat Factorization"
        elif "hastad" in output.lower():
            attack_used = "Hastad's Attack"
        elif "boneh" in output.lower():
            attack_used = "Boneh-Durfee Attack"
        
        return {
            "success": flag_match is not None,
            "flag": flag_match.group(0) if flag_match else None,
            "output": output[:500],  # Limitar output
            "attack_used": attack_used
        }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": f"Timeout after {timeout}s",
            "flag": None
        }
    except Exception as e:
        return {
            "success": False,
            "output": str(e),
            "flag": None
        }

# ============ HERRAMIENTA 5: ATACAR CIFRADOS CLÁSICOS ============

@tool
def attack_classical(ciphertext: str, max_attempts: int = 50) -> Dict[str, Any]:
    """
    Ataca cifrados clásicos (Caesar, XOR, etc.).
    
    Args:
        ciphertext: Texto cifrado
        max_attempts: Máximo de intentos
        
    Returns:
        Dict con 'success', 'plaintext', 'cipher_type', 'key'
    """
    results = []
    
    # ATAQUE 1: Caesar / ROT-N
    for shift in range(26):
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                plaintext += chr((ord(char) - base + shift) % 26 + base)
            else:
                plaintext += char
        
        # Buscar flag
        if "flag{" in plaintext.lower():
            return {
                "success": True,
                "plaintext": plaintext,
                "cipher_type": "Caesar",
                "key": shift
            }
        
        results.append({"type": "caesar", "shift": shift, "preview": plaintext[:50]})
    
    # ATAQUE 2: XOR single-byte
    try:
        # Intentar interpretar como hex
        if all(c in '0123456789abcdefABCDEF ' for c in ciphertext.replace(' ', '')):
            ciphertext_bytes = bytes.fromhex(ciphertext.replace(' ', ''))
        else:
            ciphertext_bytes = ciphertext.encode()
        
        for key in range(256):
            plaintext_bytes = bytes([b ^ key for b in ciphertext_bytes])
            try:
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore')
                if "flag{" in plaintext.lower():
                    return {
                        "success": True,
                        "plaintext": plaintext,
                        "cipher_type": "XOR single-byte",
                        "key": key
                    }
                
                if len(results) < max_attempts:
                    results.append({"type": "xor", "key": key, "preview": plaintext[:50]})
            except:
                pass
    except:
        pass
    
    return {
        "success": False,
        "attempts": len(results),
        "sample_results": results[:10]
    }

# ============ HERRAMIENTA 6: EJECUTAR SAGEMATH ============

@tool
def execute_sage(script: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Ejecuta script de SageMath para ataques avanzados.
    
    Args:
        script: Código SageMath completo
        timeout: Timeout en segundos
        
    Returns:
        Dict con 'success', 'output', 'error'
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False) as f:
        f.write(script)
        temp_file = f.name
    
    try:
        result = subprocess.run(
            ["sage", temp_file],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": f"Timeout after {timeout}s"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": "SageMath not installed. Install with: sudo apt install sagemath"
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e)
        }
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

# ============ HERRAMIENTA 7: FACTORIZAR NÚMEROS ============

@tool
def factorize_number(n: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Factoriza números usando múltiples métodos.
    
    Args:
        n: Número a factorizar (string)
        timeout: Timeout en segundos
        
    Returns:
        Dict con factores encontrados
    """
    try:
        n_int = int(n)
        factors = []
        
        # Método 1: Factores pequeños
        for i in range(2, min(10000, int(n_int**0.5) + 1)):
            if n_int % i == 0:
                factors.append(i)
                factors.append(n_int // i)
                break
        
        # Método 2: Fermat (para números cercanos a cuadrados perfectos)
        if not factors:
            import math
            a = int(math.ceil(math.sqrt(n_int)))
            for _ in range(1000):
                b_squared = a * a - n_int
                if b_squared >= 0:
                    b = int(math.sqrt(b_squared))
                    if b * b == b_squared:
                        p = a + b
                        q = a - b
                        if p * q == n_int and p > 1 and q > 1:
                            factors = [p, q]
                            break
                a += 1
        
        return {
            "success": len(factors) > 0,
            "factors": factors,
            "original": n
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "factors": []
        }

# ============ HERRAMIENTA 8: DECODIFICAR TEXTO ============

@tool
def decode_text(text: str, encodings: List[str] = None) -> Dict[str, Any]:
    """
    Intenta decodificar texto con múltiples encodings.
    
    Args:
        text: Texto a decodificar
        encodings: Lista de encodings a probar
        
    Returns:
        Dict con resultados de decodificación
    """
    if encodings is None:
        encodings = ['base64', 'hex', 'url', 'rot13']
    
    results = {}
    
    # Base64
    if 'base64' in encodings:
        try:
            import base64
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            results['base64'] = decoded
            if 'flag{' in decoded.lower():
                results['flag_found'] = {'encoding': 'base64', 'text': decoded}
        except:
            results['base64'] = "Error decoding"
    
    # Hex
    if 'hex' in encodings:
        try:
            decoded = bytes.fromhex(text.replace(' ', '')).decode('utf-8', errors='ignore')
            results['hex'] = decoded
            if 'flag{' in decoded.lower():
                results['flag_found'] = {'encoding': 'hex', 'text': decoded}
        except:
            results['hex'] = "Error decoding"
    
    # URL encoding
    if 'url' in encodings:
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(text)
            results['url'] = decoded
            if 'flag{' in decoded.lower():
                results['flag_found'] = {'encoding': 'url', 'text': decoded}
        except:
            results['url'] = "Error decoding"
    
    # ROT13
    if 'rot13' in encodings:
        try:
            decoded = text.encode().decode('rot13')
            results['rot13'] = decoded
            if 'flag{' in decoded.lower():
                results['flag_found'] = {'encoding': 'rot13', 'text': decoded}
        except:
            results['rot13'] = "Error decoding"
    
    return {
        "success": 'flag_found' in results,
        "results": results
    }

# Importar herramientas avanzadas
try:
    from .advanced_tools import ADVANCED_TOOLS
    EXTRA_TOOLS = ADVANCED_TOOLS
except ImportError:
    EXTRA_TOOLS = []

# Importar ataques RSA especializados
try:
    from .rsa_attacks import RSA_ATTACK_TOOLS
    RSA_TOOLS = RSA_ATTACK_TOOLS
except ImportError:
    RSA_TOOLS = []

# Lista de todas las herramientas para bind al LLM
ALL_TOOLS = [
    analyze_files,
    classify_crypto,
    connect_netcat,
    attack_rsa,
    attack_classical,
    execute_sage,
    factorize_number,
    decode_text
] + EXTRA_TOOLS + RSA_TOOLS