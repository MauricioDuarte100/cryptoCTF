#!/usr/bin/env python3
"""
Enhanced Multi-Agent Coordinator
Coordinador mejorado con integración BERT + RAG + fallbacks
"""

import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Añadir paths
sys.path.append('.')
sys.path.append('..')

@dataclass
class SolveResult:
    success: bool
    flag: Optional[str] = None
    classification: Optional[str] = None
    confidence: float = 0.0
    time_taken: float = 0.0
    strategy: Optional[str] = None
    agents_used: List[str] = None
    rag_context: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class EnhancedCoordinator:
    """Coordinador mejorado con múltiples estrategias"""
    
    def __init__(self):
        self.bert_classifier = None
        self.rag_engine = None
        self.simple_solver = None
        self.multi_agent_coordinator = None
        
        # Inicializar componentes
        self._initialize_components()
    
    def _initialize_components(self):
        """Inicializa todos los componentes disponibles"""
        
        # BERT Classifier
        try:
            from ml_phase2.bert_classifier_enhanced import get_bert_classifier
            self.bert_classifier = get_bert_classifier()
            print("✅ Enhanced BERT Classifier loaded")
        except Exception as e:
            print(f"⚠️ BERT not available: {e}")
        
        # RAG Engine
        try:
            from rag.rag_engine_enhanced import get_enhanced_rag_engine
            self.rag_engine = get_enhanced_rag_engine()
            print("✅ Enhanced RAG Engine loaded")
        except Exception as e:
            print(f"⚠️ RAG not available: {e}")
        
        # Simple Solver (fallback)
        try:
            from solve_simple import solve_ctf_challenge
            self.simple_solver = solve_ctf_challenge
            print("✅ Simple Solver fallback loaded")
        except Exception as e:
            print(f"⚠️ Simple solver not available: {e}")
        
        # Multi-Agent Coordinator
        try:
            from multi_agent.coordination.coordinator import get_coordinator
            self.multi_agent_coordinator = get_coordinator()
            print("✅ Multi-Agent Coordinator loaded")
        except Exception as e:
            print(f"⚠️ Multi-Agent not available: {e}")
    
    def solve_challenge(self, description: str, files: List[Dict[str, str]]) -> SolveResult:
        """Resuelve un challenge usando múltiples estrategias"""
        start_time = time.time()
        
        print(f"🎯 Enhanced Coordinator solving: {description[:50]}...")
        
        # Paso 1: Clasificación con BERT
        challenge_type = "Unknown"
        confidence = 0.0
        
        if self.bert_classifier:
            try:
                challenge_data = {
                    'description': description,
                    'files': files
                }
                challenge_type, confidence = self.bert_classifier.classify(challenge_data)
                print(f"🧠 BERT Classification: {challenge_type} ({confidence:.2f})")
            except Exception as e:
                print(f"⚠️ BERT classification failed: {e}")
        
        # Paso 2: Obtener contexto RAG
        rag_context = None
        if self.rag_engine:
            try:
                rag_results = self.rag_engine.retrieve_similar_writeups(
                    query=f"{challenge_type} {description}",
                    n_results=3,
                    attack_type=challenge_type.lower() if challenge_type != "Unknown" else None
                )
                rag_context = {
                    "similar_writeups": rag_results,
                    "context_used": len(rag_results) > 0
                }
                print(f"📚 RAG Context: {len(rag_results)} similar writeups found")
            except Exception as e:
                print(f"⚠️ RAG context failed: {e}")
        
        # Paso 3: Intentar resolución con Multi-Agent
        if self.multi_agent_coordinator:
            try:
                print("🤖 Trying Multi-Agent approach...")
                result = self.multi_agent_coordinator.solve_challenge(description, files)
                
                if result and hasattr(result, 'success') and result.success:
                    return SolveResult(
                        success=True,
                        flag=result.flag,
                        classification=challenge_type,
                        confidence=confidence,
                        time_taken=time.time() - start_time,
                        strategy="Multi-Agent Enhanced",
                        agents_used=getattr(result, 'agents_used', ['planner', 'executor', 'validator']),
                        rag_context=rag_context
                    )
            except Exception as e:
                print(f"⚠️ Multi-Agent failed: {e}")
        
        # Paso 4: Fallback al Simple Solver
        if self.simple_solver and files:
            try:
                print("🔧 Trying Simple Solver fallback...")
                
                # Crear archivo temporal
                temp_file = Path("temp_challenge_enhanced.py")
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(files[0]['content'])
                
                flag = self.simple_solver(str(temp_file))
                
                # Limpiar archivo temporal
                if temp_file.exists():
                    temp_file.unlink()
                
                if flag:
                    return SolveResult(
                        success=True,
                        flag=flag,
                        classification=challenge_type,
                        confidence=max(confidence, 0.7),
                        time_taken=time.time() - start_time,
                        strategy="Simple Solver Enhanced",
                        agents_used=['simple_solver'],
                        rag_context=rag_context
                    )
            except Exception as e:
                print(f"⚠️ Simple solver failed: {e}")
        
        # Paso 5: Estrategias específicas por tipo
        if challenge_type != "Unknown":
            try:
                print(f"🎯 Trying type-specific strategy for {challenge_type}...")
                flag = self._try_type_specific_strategy(challenge_type, files, description)
                
                if flag:
                    return SolveResult(
                        success=True,
                        flag=flag,
                        classification=challenge_type,
                        confidence=confidence,
                        time_taken=time.time() - start_time,
                        strategy=f"Type-Specific ({challenge_type})",
                        agents_used=['type_specific_solver'],
                        rag_context=rag_context
                    )
            except Exception as e:
                print(f"⚠️ Type-specific strategy failed: {e}")
        
        # Si todo falla
        return SolveResult(
            success=False,
            classification=challenge_type,
            confidence=confidence,
            time_taken=time.time() - start_time,
            strategy="All strategies failed",
            agents_used=[],
            rag_context=rag_context,
            error="No strategy succeeded"
        )
    
    def _try_type_specific_strategy(self, challenge_type: str, files: List[Dict], description: str) -> Optional[str]:
        """Intenta estrategias específicas por tipo de challenge"""
        
        if not files:
            return None
        
        content = files[0]['content']
        
        # RSA específico
        if 'rsa' in challenge_type.lower():
            return self._try_rsa_specific(content)
        
        # Classical cipher específico
        if 'classical' in challenge_type.lower() or 'cipher' in challenge_type.lower():
            return self._try_classical_specific(content)
        
        # Hash específico
        if 'hash' in challenge_type.lower():
            return self._try_hash_specific(content)
        
        # Encoding específico
        if 'encoding' in challenge_type.lower() or 'base64' in challenge_type.lower():
            return self._try_encoding_specific(content)
        
        return None
    
    def _try_rsa_specific(self, content: str) -> Optional[str]:
        """Estrategias específicas para RSA"""
        try:
            # Buscar parámetros RSA
            import re
            
            n_match = re.search(r'n\s*=\s*(\d+)', content)
            e_match = re.search(r'e\s*=\s*(\d+)', content)
            c_match = re.search(r'c\s*=\s*(\d+)', content)
            
            if n_match and e_match and c_match:
                n = int(n_match.group(1))
                e = int(e_match.group(1))
                c = int(c_match.group(1))
                
                # Intentar factorización simple
                if n < 10**20:  # Modulus pequeño
                    from src.tools.rsa_attacks import factorize_small_n, decrypt_rsa
                    factors = factorize_small_n(n)
                    if factors:
                        p, q = factors
                        flag = decrypt_rsa(n, e, c, p, q)
                        if flag and 'flag' in flag.lower():
                            return flag
                
                # Intentar ataque de exponente pequeño
                if e == 3:
                    import gmpy2
                    m = gmpy2.iroot(c, 3)[0]
                    try:
                        flag = bytes.fromhex(hex(m)[2:]).decode()
                        if 'flag' in flag.lower():
                            return flag
                    except:
                        pass
        except Exception as e:
            print(f"RSA specific strategy error: {e}")
        
        return None
    
    def _try_classical_specific(self, content: str) -> Optional[str]:
        """Estrategias específicas para cifrados clásicos"""
        try:
            import re
            
            # Buscar texto cifrado
            cipher_patterns = [
                r'encrypted[^:]*:\s*([a-zA-Z\{\}_]+)',
                r'ciphertext[^:]*:\s*([a-zA-Z\{\}_]+)',
                r'cipher[^:]*:\s*([a-zA-Z\{\}_]+)',
                r'message[^:]*:\s*([a-zA-Z\{\}_]+)'
            ]
            
            for pattern in cipher_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    ciphertext = match.group(1)
                    
                    # Intentar Caesar
                    for shift in range(26):
                        decrypted = ""
                        for char in ciphertext:
                            if char.isalpha():
                                base = ord('A') if char.isupper() else ord('a')
                                decrypted += chr((ord(char) - base - shift) % 26 + base)
                            else:
                                decrypted += char
                        
                        if 'flag' in decrypted.lower():
                            return decrypted
        except Exception as e:
            print(f"Classical specific strategy error: {e}")
        
        return None
    
    def _try_hash_specific(self, content: str) -> Optional[str]:
        """Estrategias específicas para hashes"""
        try:
            import hashlib
            import re
            
            # Buscar hash
            hash_patterns = [
                r'hash[^:]*:\s*([a-fA-F0-9]+)',
                r'md5[^:]*:\s*([a-fA-F0-9]+)',
                r'sha[^:]*:\s*([a-fA-F0-9]+)'
            ]
            
            for pattern in hash_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    target_hash = match.group(1).lower()
                    
                    # Intentar passwords comunes
                    common_passwords = [
                        'password', 'admin', 'root', 'user', 'test',
                        'hello', 'world', 'flag', 'ctf', '123456',
                        'qwerty', 'abc123', 'password123'
                    ]
                    
                    for pwd in common_passwords:
                        # MD5
                        if len(target_hash) == 32:
                            if hashlib.md5(pwd.encode()).hexdigest() == target_hash:
                                return f"flag{{{pwd}}}"
                        
                        # SHA1
                        elif len(target_hash) == 40:
                            if hashlib.sha1(pwd.encode()).hexdigest() == target_hash:
                                return f"flag{{{pwd}}}"
        except Exception as e:
            print(f"Hash specific strategy error: {e}")
        
        return None
    
    def _try_encoding_specific(self, content: str) -> Optional[str]:
        """Estrategias específicas para encoding"""
        try:
            import base64
            import re
            
            # Buscar datos codificados
            b64_patterns = [
                r'data[^:]*:\s*([A-Za-z0-9+/=]+)',
                r'encoded[^:]*:\s*([A-Za-z0-9+/=]+)',
                r'base64[^:]*:\s*([A-Za-z0-9+/=]+)'
            ]
            
            for pattern in b64_patterns:
                match = re.search(pattern, content)
                if match:
                    encoded_data = match.group(1)
                    
                    # Decodificación recursiva
                    current = encoded_data
                    for _ in range(5):  # Máximo 5 capas
                        try:
                            decoded = base64.b64decode(current).decode('utf-8')
                            if 'flag' in decoded.lower():
                                return decoded
                            current = decoded
                        except:
                            break
                    
                    # Intentar hex después de base64
                    try:
                        decoded_bytes = base64.b64decode(encoded_data)
                        hex_str = decoded_bytes.hex()
                        final = bytes.fromhex(hex_str).decode('utf-8')
                        if 'flag' in final.lower():
                            return final
                    except:
                        pass
        except Exception as e:
            print(f"Encoding specific strategy error: {e}")
        
        return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Obtiene el estado del sistema"""
        return {
            "status": "operational",
            "components": {
                "bert_classifier": self.bert_classifier is not None,
                "rag_engine": self.rag_engine is not None,
                "simple_solver": self.simple_solver is not None,
                "multi_agent": self.multi_agent_coordinator is not None
            },
            "capabilities": [
                "Enhanced BERT Classification",
                "RAG Context Retrieval", 
                "Multi-Agent Coordination",
                "Simple Solver Fallback",
                "Type-Specific Strategies"
            ]
        }

# Función de conveniencia
def get_enhanced_coordinator() -> EnhancedCoordinator:
    """Obtiene una instancia del coordinador mejorado"""
    return EnhancedCoordinator()

if __name__ == "__main__":
    # Test básico
    coordinator = get_enhanced_coordinator()
    
    # Test con challenge simple
    test_files = [{
        'name': 'test.py',
        'content': 'encrypted = "synt{pnrfne_pvcure_vf_rnfl_gb_oernx}"'
    }]
    
    result = coordinator.solve_challenge("Caesar cipher test", test_files)
    print(f"Result: {result}")