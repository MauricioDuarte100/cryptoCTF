"""
Agente CTF Crypto simplificado sin LangGraph
Para usar mientras solucionamos la integración completa
"""

import time
from typing import Dict, List, Any
from langchain_google_genai import ChatGoogleGenerativeAI
from ..tools.tools import ALL_TOOLS
from .prompts import MASTER_SYSTEM_PROMPT
from ..config.config import config
from ..database.database import get_database

class SimpleCTFAgent:
    """Agente CTF simplificado"""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            temperature=config.GEMINI_TEMPERATURE,
            google_api_key=config.GOOGLE_API_KEY
        )
        self.tools = {tool.name: tool for tool in ALL_TOOLS}
    
    def solve_challenge(self, description: str, files: List[Dict] = None, 
                       max_steps: int = 10) -> Dict[str, Any]:
        """
        Resuelve un desafío usando lógica simplificada
        """
        files = files or []
        solution_steps = []
        
        try:
            # Paso 1: Analizar archivos
            if files:
                analyze_result = self.tools["analyze_files"].invoke({"files": files})
                solution_steps.append("analyze_files")
                
                # Paso 2: Clasificar crypto
                classify_result = self.tools["classify_crypto"].invoke({"analysis": analyze_result})
                solution_steps.append("classify_crypto")
                
                challenge_type = classify_result.get("type", "Unknown")
                confidence = classify_result.get("confidence", 0.0)
                
                # Paso 3: Seleccionar estrategia basada en clasificación
                if challenge_type == "Classical" or confidence < 0.5:
                    # Buscar texto cifrado en archivos
                    ciphertext = self._extract_ciphertext(files)
                    if ciphertext:
                        attack_result = self.tools["attack_classical"].invoke({"ciphertext": ciphertext})
                        solution_steps.append("attack_classical")
                        
                        if attack_result.get("success"):
                            return {
                                "success": True,
                                "flag": attack_result.get("plaintext", ""),
                                "challenge_type": attack_result.get("cipher_type", challenge_type),
                                "confidence": 0.9,
                                "solution_steps": solution_steps,
                                "steps_used": len(solution_steps)
                            }
                
                elif challenge_type == "RSA":
                    # Extraer parámetros RSA
                    variables = analyze_result.get("variables", {})
                    n = str(variables.get("n", ""))
                    e = str(variables.get("e", ""))
                    c = str(variables.get("c", ""))
                    
                    if n and e:
                        attack_result = self.tools["attack_rsa"].invoke({
                            "n": n, "e": e, "c": c
                        })
                        solution_steps.append("attack_rsa")
                        
                        if attack_result.get("success"):
                            return {
                                "success": True,
                                "flag": attack_result.get("flag", ""),
                                "challenge_type": "RSA",
                                "confidence": 0.95,
                                "solution_steps": solution_steps,
                                "steps_used": len(solution_steps)
                            }
                
                elif challenge_type == "XOR":
                    # Buscar datos hex para XOR
                    hex_data = self._extract_hex_data(files)
                    if hex_data:
                        attack_result = self.tools["attack_classical"].invoke({"ciphertext": hex_data})
                        solution_steps.append("attack_classical")
                        
                        if attack_result.get("success"):
                            return {
                                "success": True,
                                "flag": attack_result.get("plaintext", ""),
                                "challenge_type": "XOR",
                                "confidence": 0.85,
                                "solution_steps": solution_steps,
                                "steps_used": len(solution_steps)
                            }
            
            # Si no se encontró nada específico, probar decodificación
            for file in files:
                content = file.get("content", "")
                
                # Buscar patrones de encoding
                decode_result = self.tools["decode_text"].invoke({
                    "text": content,
                    "encodings": ["base64", "hex", "url", "rot13"]
                })
                solution_steps.append("decode_text")
                
                if decode_result.get("success"):
                    flag_info = decode_result.get("results", {}).get("flag_found")
                    if flag_info:
                        return {
                            "success": True,
                            "flag": flag_info.get("text", ""),
                            "challenge_type": "Encoding",
                            "confidence": 0.8,
                            "solution_steps": solution_steps,
                            "steps_used": len(solution_steps)
                        }
            
            # Si nada funcionó
            return {
                "success": False,
                "flag": "",
                "challenge_type": challenge_type if 'challenge_type' in locals() else "Unknown",
                "confidence": confidence if 'confidence' in locals() else 0.0,
                "solution_steps": solution_steps,
                "steps_used": len(solution_steps),
                "error": "No se pudo resolver el desafío"
            }
            
        except Exception as e:
            return {
                "success": False,
                "flag": "",
                "challenge_type": "Error",
                "confidence": 0.0,
                "solution_steps": solution_steps,
                "steps_used": len(solution_steps),
                "error": str(e)
            }
    
    def _extract_ciphertext(self, files: List[Dict]) -> str:
        """Extrae texto cifrado de archivos"""
        for file in files:
            content = file.get("content", "")
            
            # Buscar patrones comunes
            import re
            
            # Buscar strings entre comillas
            quotes_match = re.search(r'["\']([^"\']{10,})["\']', content)
            if quotes_match:
                return quotes_match.group(1)
            
            # Buscar variables de ciphertext
            cipher_match = re.search(r'(?:ciphertext|cipher|encrypted)\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
            if cipher_match:
                return cipher_match.group(1)
        
        return ""
    
    def _extract_hex_data(self, files: List[Dict]) -> str:
        """Extrae datos hexadecimales de archivos"""
        for file in files:
            content = file.get("content", "")
            
            import re
            
            # Buscar patrones hex
            hex_match = re.search(r'["\']([0-9a-fA-F]{20,})["\']', content)
            if hex_match:
                return hex_match.group(1)
            
            # Buscar variables hex específicas
            hex_var_match = re.search(r'(?:hex|encrypted_hex)\s*=\s*["\']([0-9a-fA-F]+)["\']', content, re.IGNORECASE)
            if hex_var_match:
                return hex_var_match.group(1)
        
        return ""

def solve_ctf_challenge_simple(
    description: str,
    files: list[dict] = None,
    nc_host: str = "",
    nc_port: int = 0,
    max_steps: int = 15,
    challenge_name: str = None,
    expected_flag: str = None,
    log_to_db: bool = True
) -> dict:
    """
    Versión simplificada de solve_ctf_challenge
    """
    import time
    
    start_time = time.time()
    db = get_database() if log_to_db else None
    challenge_id = None
    
    # Registrar desafío en DB
    if db:
        challenge_name = challenge_name or f"Challenge_{int(time.time())}"
        challenge_id = db.log_challenge(
            name=challenge_name,
            description=description,
            challenge_type="Unknown",
            files=files or [],
            expected_flag=expected_flag
        )
    
    # Crear y ejecutar agente
    agent = SimpleCTFAgent()
    result = agent.solve_challenge(description, files, max_steps)
    
    end_time = time.time()
    total_time = end_time - start_time
    result["total_time"] = total_time
    
    # Validar flag si se proporcionó expected_flag
    if expected_flag and result.get("flag"):
        result["flag_correct"] = result["flag"].lower().strip() == expected_flag.lower().strip()
    
    # Registrar en DB
    if db and challenge_id:
        attempt_id = db.log_attempt(
            challenge_id=challenge_id,
            success=result.get("success", False),
            flag_found=result.get("flag", ""),
            confidence=result.get("confidence", 0.0),
            steps_used=result.get("steps_used", 0),
            total_time=total_time,
            error_message=result.get("error"),
            solution_steps=result.get("solution_steps", []),
            agent_version="2.1-simple",
            gemini_model=config.GEMINI_MODEL
        )
        
        result["challenge_id"] = challenge_id
        result["attempt_id"] = attempt_id
    
    return result