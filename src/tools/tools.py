"""
Herramientas especializadas para resolver CTF Crypto
Optimizadas para uso con Gemini function calling
Incluye RAG (Retrieval-Augmented Generation) para contexto histórico
"""

import re
import subprocess
import tempfile
import os
from typing import Dict, List, Any
from langchain_core.tools import tool

# Importar RAG tools
try:
    import sys
    from pathlib import Path
    rag_path = str(Path(__file__).parent.parent.parent / "rag")
    if rag_path not in sys.path:
        sys.path.insert(0, rag_path)
    
    from rag_agent_tools import retrieve_similar_writeups, analyze_with_context
    RAG_TOOLS = [retrieve_similar_writeups, analyze_with_context]
    RAG_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  RAG tools not available: {e}")
    RAG_TOOLS = []
    RAG_AVAILABLE = False

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
        
        # Extraer variables numéricas (RSA params, etc.)
        # Patrón 1: Números grandes directos
        var_pattern1 = r'(\w+)\s*=\s*(\d{10,}|0x[0-9a-fA-F]{10,})'
        matches1 = re.findall(var_pattern1, content)
        for var_name, var_value in matches1:
            try:
                result["variables"][var_name] = int(var_value, 0)
            except:
                result["variables"][var_name] = var_value
        
        # Patrón 2: Variables RSA comunes (números más pequeños también)
        var_pattern2 = r'(\b[nec]\b)\s*=\s*(\d+)'
        matches2 = re.findall(var_pattern2, content, re.IGNORECASE)
        for var_name, var_value in matches2:
            try:
                result["variables"][var_name.lower()] = int(var_value)
            except:
                result["variables"][var_name.lower()] = var_value
        
        # Patrón 3: Variables p, q, d, m, c (factores RSA y mensaje)
        var_pattern3 = r'\b([pqdmc])\s*=\s*(\d+)'
        matches3 = re.findall(var_pattern3, content)
        for var_name, var_value in matches3:
            try:
                result["variables"][var_name] = int(var_value)
            except:
                result["variables"][var_name] = var_value
        
        # Patrón 4: Expresiones calculadas (como n = p * q)
        calc_pattern = r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)'
        calc_matches = re.findall(calc_pattern, content)
        for var_name, var1, var2 in calc_matches:
            # Si tenemos los valores de var1 y var2, calcular
            if var1 in result["variables"] and var2 in result["variables"]:
                try:
                    result["variables"][var_name] = result["variables"][var1] * result["variables"][var2]
                except:
                    pass
        
        # Patrón 5: Variables message (mensaje)
        var_pattern5 = r'\b(message)\s*=\s*(\d+)'
        matches5 = re.findall(var_pattern5, content)
        for var_name, var_value in matches5:
            try:
                result["variables"][var_name] = int(var_value)
            except:
                result["variables"][var_name] = var_value
        
        # Patrón 6: Expresiones pow() (como c = pow(m, e, n))
        pow_pattern = r'(\w+)\s*=\s*pow\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)'
        pow_matches = re.findall(pow_pattern, content)
        for var_name, base, exp, mod in pow_matches:
            # Si tenemos todos los valores, calcular
            if base in result["variables"] and exp in result["variables"] and mod in result["variables"]:
                try:
                    result["variables"][var_name] = pow(
                        result["variables"][base], 
                        result["variables"][exp], 
                        result["variables"][mod]
                    )
                except:
                    pass
        
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
        
        # Encoding (Base64, Hex, etc.)
        if 'base64' in content_lower or 'b64encode' in content_lower or 'decode' in content_lower:
            result["crypto_indicators"].append("Encoding")
        
        result["file_summary"].append({
            "name": name,
            "lines": len(content.split('\n')),
            "size_bytes": len(content)
        })
    
    return result

# ============ HERRAMIENTA 2: CLASIFICAR CRYPTO ============

@tool
def classify_crypto(analysis: Dict[str, Any], use_ml: bool = True) -> Dict[str, Any]:
    """
    Clasifica el tipo de criptografía usando ML o heurística.
    
    Args:
        analysis: Resultado de analyze_files()
        use_ml: Si intentar usar modelo BERT primero
    
    Returns:
        {"type": "RSA", "confidence": 0.95, "method": "BERT"}
        o
        {"type": "RSA", "confidence": 0.85, "method": "heuristic"}
    """
    
    # INTENTO 1: ML (si disponible y use_ml=True)
    if use_ml:
        try:
            import sys
            from pathlib import Path
            
            # Añadir ml_phase2 al path si no está
            ml_path = str(Path(__file__).parent.parent.parent / "ml_phase2")
            if ml_path not in sys.path:
                sys.path.insert(0, ml_path)
            
            from bert_classifier import BERT_AVAILABLE, bert_classifier
            
            if BERT_AVAILABLE:
                # Preparar texto para BERT
                text_parts = []
                
                # Agregar imports
                imports = analysis.get('imports', [])
                if imports:
                    text_parts.append(f"Imports: {', '.join(imports)}")
                
                # Agregar variables
                variables = analysis.get('variables', {})
                if variables:
                    var_info = ', '.join([f"{k}={v}" for k, v in list(variables.items())[:10]])  # Limitar
                    text_parts.append(f"Variables: {var_info}")
                
                # Agregar indicadores
                indicators = analysis.get('crypto_indicators', [])
                if indicators:
                    text_parts.append(f"Indicators: {', '.join(indicators)}")
                
                # Agregar contenido de archivos (muestra)
                file_summary = analysis.get('file_summary', [])
                if file_summary:
                    text_parts.append(f"Files: {len(file_summary)} files analyzed")
                
                text = '\n'.join(text_parts)
                
                # Clasificar con BERT
                ml_result = bert_classifier.classify(text, return_all_scores=True)
                
                # Si confianza alta (>70%), usar resultado ML
                if ml_result.get('confidence', 0) > 0.70:
                    return {
                        "type": ml_result['type'],
                        "confidence": ml_result['confidence'],
                        "all_scores": ml_result.get('all_scores', {}),
                        "method": "BERT"
                    }
                else:
                    print(f"⚠️  BERT confidence low ({ml_result.get('confidence', 0):.2f}), falling back to heuristic")
        
        except Exception as e:
            print(f"⚠️  BERT classification failed: {e}, using heuristic")
    
    # INTENTO 2: Heurística (fallback o si use_ml=False)
    indicators = analysis.get("crypto_indicators", [])
    variables = analysis.get("variables", {})
    imports = analysis.get("imports", [])
    
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
    
    # Encoding detection
    encoding_score = 0.0
    if "Encoding" in indicators:
        encoding_score += 0.7
    if any('base64' in imp.lower() for imp in imports):
        encoding_score += 0.3
    scores["Encoding"] = min(encoding_score, 1.0)
    
    # ECC detection
    ecc_score = 0.0
    if "ECC" in indicators:
        ecc_score += 0.4
    scores["ECC"] = min(ecc_score, 1.0)
    
    # Seleccionar el mejor
    if not scores or max(scores.values()) < 0.3:
        return {
            "type": "Unknown",
            "confidence": 0.1,
            "all_scores": scores,
            "method": "heuristic"
        }
    
    best_type = max(scores, key=scores.get)
    confidence = scores[best_type]
    
    return {
        "type": best_type,
        "confidence": confidence,
        "all_scores": scores,
        "method": "heuristic"
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
def attack_rsa(n: str, e: str, c: str = "", timeout: int = 120) -> Dict[str, Any]:
    """
    Ejecuta batería de ataques RSA con múltiples estrategias.
    
    Args:
        n: Módulo RSA (string decimal o hex)
        e: Exponente público (string decimal)
        c: Ciphertext opcional (string decimal o hex)
        timeout: Timeout en segundos
        
    Returns:
        Dict con resultado del ataque
    """
    try:
        # Convertir parámetros
        n_int = int(n, 0)  # Soporta decimal y hex
        e_int = int(e, 0)
        c_int = int(c, 0) if c else None
        
        # Intentar ataques en orden de probabilidad
        attacks_tried = []
        
        # 1. Ataque Fermat (factores cercanos)
        if n_int < 10**20:  # Solo para números pequeños
            attacks_tried.append("Fermat Factorization")
            fermat_result = _fermat_attack(n_int, c_int, e_int)
            if fermat_result["success"]:
                return fermat_result
        
        # 2. Ataque de factores pequeños
        attacks_tried.append("Small Factors")
        small_factors_result = _small_factors_attack(n_int, c_int, e_int)
        if small_factors_result["success"]:
            return small_factors_result
        
        # 3. Si e es pequeño, intentar Hastad
        if e_int <= 17 and c_int:
            attacks_tried.append("Hastad's Attack (single)")
            hastad_result = _hastad_single_attack(n_int, e_int, c_int)
            if hastad_result["success"]:
                return hastad_result
        
        # 4. Intentar RsaCtfTool como fallback
        attacks_tried.append("RsaCtfTool")
        rsactf_result = _try_rsactftool(n, e, c, timeout)
        if rsactf_result["success"]:
            return rsactf_result
        
        return {
            "success": False,
            "output": f"All attacks failed. Tried: {', '.join(attacks_tried)}",
            "flag": None,
            "attacks_tried": attacks_tried,
            "debug_info": {
                "n_bits": n_int.bit_length(),
                "e_value": e_int,
                "has_ciphertext": bool(c_int)
            }
        }
    
    except Exception as e:
        return {
            "success": False,
            "output": f"Error in attack_rsa: {str(e)}",
            "flag": None,
            "debug_info": {"n": n, "e": e, "c": c}
        }

def _fermat_attack(n: int, c: int = None, e: int = None) -> Dict[str, Any]:
    """Ataque de factorización de Fermat"""
    
    if n % 2 == 0:
        p, q = 2, n // 2
    else:
        # Usar integer square root para números grandes
        def isqrt(n):
            if n < 0:
                raise ValueError("Square root not defined for negative numbers")
            if n == 0:
                return 0
            x = n
            y = (x + 1) // 2
            while y < x:
                x = y
                y = (x + n // x) // 2
            return x
        
        a = isqrt(n) + 1
        for i in range(10000):  # Límite de iteraciones
            b_squared = a * a - n
            if b_squared >= 0:
                b = isqrt(b_squared)
                if b * b == b_squared:
                    p = a + b
                    q = a - b
                    if p * q == n and p > 1 and q > 1:
                        break
            a += 1
        else:
            return {"success": False, "attack_type": "Fermat"}
    
    # Si tenemos ciphertext, descifrar
    if c and e and p > 1 and q > 1:
        try:
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            
            # Convertir a texto usando long_to_bytes
            try:
                if m > 0:
                    # Intentar con Crypto.Util.number.long_to_bytes
                    try:
                        from Crypto.Util.number import long_to_bytes
                        flag_bytes = long_to_bytes(m)
                        flag_text = flag_bytes.decode('utf-8', errors='ignore')
                    except:
                        # Fallback a método manual
                        flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                        flag_text = flag_bytes.decode('utf-8', errors='ignore')
                    
                    if 'flag{' in flag_text.lower():
                        return {
                            "success": True,
                            "flag": flag_text,
                            "attack_type": "Fermat Factorization",
                            "factors": {"p": p, "q": q}
                        }
                    
                    # Si no encontramos flag, devolver el mensaje descifrado para debug
                    return {
                        "success": True,
                        "flag": flag_text if flag_text.isprintable() else f"Decrypted (hex): {m:x}",
                        "attack_type": "Fermat Factorization",
                        "factors": {"p": p, "q": q},
                        "decrypted_message": m
                    }
            except Exception as ex:
                # Devolver información de debug
                return {
                    "success": True,
                    "flag": f"Decrypted number: {m}",
                    "attack_type": "Fermat Factorization", 
                    "factors": {"p": p, "q": q},
                    "decrypted_message": m,
                    "decode_error": str(ex)
                }
        except:
            pass
    
    return {
        "success": True if p > 1 and q > 1 else False,
        "attack_type": "Fermat Factorization",
        "factors": {"p": p, "q": q} if p > 1 and q > 1 else None,
        "flag": None
    }

def _small_factors_attack(n: int, c: int = None, e: int = None) -> Dict[str, Any]:
    """Ataque de factores pequeños"""
    # Probar factores pequeños hasta 10000 (evitar overflow)
    limit = min(10000, n // 2 + 1)
    for i in range(2, limit):
        if n % i == 0:
            p = i
            q = n // i
            
            # Si tenemos ciphertext, descifrar
            if c and e:
                try:
                    phi = (p - 1) * (q - 1)
                    d = pow(e, -1, phi)
                    m = pow(c, d, n)
                    
                    # Convertir a texto usando long_to_bytes
                    try:
                        if m > 0:
                            # Intentar con Crypto.Util.number.long_to_bytes
                            try:
                                from Crypto.Util.number import long_to_bytes
                                flag_bytes = long_to_bytes(m)
                                flag_text = flag_bytes.decode('utf-8', errors='ignore')
                            except:
                                # Fallback a método manual
                                flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                                flag_text = flag_bytes.decode('utf-8', errors='ignore')
                            
                            if 'flag{' in flag_text.lower():
                                return {
                                    "success": True,
                                    "flag": flag_text,
                                    "attack_type": "Small Factors",
                                    "factors": {"p": p, "q": q}
                                }
                            
                            # Si no encontramos flag, devolver el mensaje descifrado
                            return {
                                "success": True,
                                "flag": flag_text if flag_text.isprintable() else f"Decrypted (hex): {m:x}",
                                "attack_type": "Small Factors",
                                "factors": {"p": p, "q": q},
                                "decrypted_message": m
                            }
                    except Exception as ex:
                        return {
                            "success": True,
                            "flag": f"Decrypted number: {m}",
                            "attack_type": "Small Factors",
                            "factors": {"p": p, "q": q},
                            "decrypted_message": m,
                            "decode_error": str(ex)
                        }
                except:
                    pass
            
            return {
                "success": True,
                "attack_type": "Small Factors",
                "factors": {"p": p, "q": q},
                "flag": None
            }
    
    return {"success": False, "attack_type": "Small Factors"}

def _hastad_single_attack(n: int, e: int, c: int) -> Dict[str, Any]:
    """Ataque Hastad para un solo mensaje (e pequeño)"""
    if e > 17:
        return {"success": False, "attack_type": "Hastad"}
    
    # Intentar raíz e-ésima directa
    def nth_root(x, n):
        if x == 0:
            return 0
        
        # Método de Newton
        root = x
        for _ in range(100):  # Máximo 100 iteraciones
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
    
    m = nth_root(c, e)
    
    if m is not None:
        try:
            flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            flag_text = flag_bytes.decode('utf-8', errors='ignore')
            
            if 'flag{' in flag_text.lower():
                return {
                    "success": True,
                    "flag": flag_text,
                    "attack_type": "Hastad's Attack",
                    "message": m
                }
        except:
            pass
    
    return {"success": False, "attack_type": "Hastad"}

def _try_rsactftool(n: str, e: str, c: str, timeout: int) -> Dict[str, Any]:
    """Intenta usar RsaCtfTool como fallback"""
    try:
        # Crear script temporal que use RsaCtfTool correctamente
        script_content = f'''
import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), "RsaCtfTool", "src"))

from RsaCtfTool.main import main
import sys

# Simular argumentos de línea de comandos
sys.argv = ["main.py", "-n", "{n}", "-e", "{e}"]
if "{c}":
    sys.argv.extend(["--decrypt", "{c}"])

try:
    main()
except SystemExit:
    pass
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            temp_script = f.name
        
        print(f"🔧 Executing RsaCtfTool via temp script...")  # Debug
        
        result = subprocess.run(
            ["python", temp_script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        print(f"🔧 RsaCtfTool output preview: {output[:100]}...")  # Debug
        
        # Limpiar archivo temporal
        os.unlink(temp_script)
        
        # Buscar flag en output
        flag_match = re.search(r'flag\{[^}]+\}', output, re.IGNORECASE)
        
        # También buscar texto descifrado que pueda contener flag
        if not flag_match:
            # Buscar líneas que contengan "flag" (case insensitive)
            lines = output.split('\n')
            for line in lines:
                if 'flag' in line.lower() and '{' in line and '}' in line:
                    flag_match = re.search(r'flag\{[^}]*\}', line, re.IGNORECASE)
                    if flag_match:
                        break
        
        # Si no encontramos flag, buscar texto descifrado
        decrypted_text = None
        if "utf-8 :" in output:
            try:
                utf8_line = [line for line in output.split('\n') if 'utf-8 :' in line][0]
                decrypted_text = utf8_line.split('utf-8 :')[1].strip()
            except:
                pass
        
        return {
            "success": flag_match is not None,
            "flag": flag_match.group(0) if flag_match else decrypted_text,
            "attack_type": "RsaCtfTool",
            "output": output[:300],
            "return_code": result.returncode
        }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "attack_type": "RsaCtfTool",
            "error": f"Timeout after {timeout}s"
        }
    except Exception as e:
        return {
            "success": False,
            "attack_type": "RsaCtfTool",
            "error": str(e)
        }

# ============ HERRAMIENTA 5: ATACAR CIFRADOS CLÁSICOS ============

@tool
def attack_classical(ciphertext: str, max_attempts: int = 500) -> Dict[str, Any]:
    """
    Ataca cifrados clásicos mejorado (Caesar, XOR, etc.).
    
    Args:
        ciphertext: Texto cifrado
        max_attempts: Máximo de intentos
        
    Returns:
        Dict con 'success', 'plaintext', 'cipher_type', 'key'
    """
    results = {
        "caesar": [],
        "xor": [],
        "found": None
    }
    
    # ATAQUE 1: Caesar / ROT-N (mejorado)
    for shift in range(26):
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                plaintext += chr((ord(char) - base + shift) % 26 + base)
            else:
                plaintext += char
        
        if "flag{" in plaintext.lower():
            return {
                "success": True,
                "plaintext": plaintext,
                "cipher_type": "Caesar",
                "key": shift
            }
        results["caesar"].append((shift, plaintext[:50]))
    
    # ATAQUE 2: XOR - MEJORADO
    # Intentar interpretar como hex, base64, o raw bytes
    import base64
    
    cipher_bytes_options = []
    
    # Opción 1: Hex
    try:
        if all(c in '0123456789abcdefABCDEF ' for c in ciphertext):
            cipher_bytes_options.append(("hex", bytes.fromhex(ciphertext.replace(' ', ''))))
    except:
        pass
    
    # Opción 2: Base64
    try:
        cipher_bytes_options.append(("base64", base64.b64decode(ciphertext)))
    except:
        pass
    
    # Opción 3: Raw bytes
    try:
        cipher_bytes_options.append(("raw", ciphertext.encode()))
    except:
        pass
    
    for encoding_type, cipher_bytes in cipher_bytes_options:
        for key in range(256):
            try:
                plaintext_bytes = bytes([b ^ key for b in cipher_bytes])
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore')
                
                if "flag{" in plaintext.lower():
                    return {
                        "success": True,
                        "plaintext": plaintext,
                        "cipher_type": f"XOR single-byte ({encoding_type})",
                        "key": hex(key),
                        "key_decimal": key
                    }
                
                results["xor"].append((key, plaintext[:50]))
            except:
                pass
    
    # ATAQUE 3: ROT13 específico
    try:
        rot13_text = ciphertext.encode().decode('rot13')
        if "flag{" in rot13_text.lower():
            return {
                "success": True,
                "plaintext": rot13_text,
                "cipher_type": "ROT13",
                "key": 13
            }
    except:
        pass
    
    # ATAQUE 4: Vigenère con claves comunes
    common_keys = ["KEY", "SECRET", "PASSWORD", "CRYPTO", "FLAG", "CTF"]
    for key in common_keys:
        try:
            plaintext = _vigenere_decrypt(ciphertext, key)
            if "flag{" in plaintext.lower():
                return {
                    "success": True,
                    "plaintext": plaintext,
                    "cipher_type": "Vigenère",
                    "key": key
                }
        except:
            pass
    
    return {
        "success": False,
        "attempts": {
            "caesar": len(results["caesar"]),
            "xor": len(results["xor"])
        },
        "sample_results": {
            "caesar": results["caesar"][:5],
            "xor": results["xor"][:5]
        }
    }

def _vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Descifra texto usando Vigenère"""
    plaintext = ""
    key = key.upper()
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            plaintext += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            plaintext += char
    
    return plaintext

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
] + EXTRA_TOOLS + RSA_TOOLS + RAG_TOOLS