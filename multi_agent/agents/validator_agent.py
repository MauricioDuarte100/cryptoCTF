"""
Validator Agent - Phase 2.4
Agente especializado en validación de resultados y verificación de flags.
Valida la calidad y corrección de las soluciones encontradas.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib

@dataclass
class ValidationResult:
    """Resultado de validación"""
    is_valid: bool
    confidence: float
    flag_format: str
    validation_checks: Dict[str, bool]
    recommendations: List[str]
    quality_score: float

class ValidatorAgent:
    """
    Agente Validador - Verifica y valida resultados de ejecución
    """
    
    def __init__(self):
        self.name = "ValidatorAgent"
        self.capabilities = [
            "flag_validation",
            "format_checking",
            "quality_assessment",
            "result_verification"
        ]
        
        # Patrones comunes de flags CTF
        self.flag_patterns = [
            r'flag\{[^}]+\}',           # flag{...}
            r'ctf\{[^}]+\}',            # ctf{...}
            r'[a-zA-Z0-9_]+\{[^}]+\}',  # cualquier{...}
            r'[A-Z0-9]{20,}',           # Hash/código largo
            r'[a-f0-9]{32}',            # MD5
            r'[a-f0-9]{40}',            # SHA1
            r'[a-f0-9]{64}',            # SHA256
        ]
    
    def validate_flag(self, flag: str, challenge_type: str = "Unknown") -> ValidationResult:
        """
        Valida un flag encontrado
        """
        print(f"🔍 {self.name}: Validating flag '{flag}'...")
        
        if not flag or not isinstance(flag, str):
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                flag_format="invalid",
                validation_checks={"non_empty": False},
                recommendations=["Flag is empty or not a string"],
                quality_score=0.0
            )
        
        checks = {}
        recommendations = []
        
        # Check 1: Formato básico
        checks["has_flag_format"] = any(re.search(pattern, flag, re.IGNORECASE) for pattern in self.flag_patterns)
        
        # Check 2: Longitud razonable
        checks["reasonable_length"] = 5 <= len(flag) <= 200
        if not checks["reasonable_length"]:
            recommendations.append(f"Flag length ({len(flag)}) seems unusual")
        
        # Check 3: Caracteres válidos
        checks["valid_characters"] = bool(re.match(r'^[a-zA-Z0-9_{}()\-\s!@#$%^&*+=.,;:]+$', flag))
        if not checks["valid_characters"]:
            recommendations.append("Flag contains unusual characters")
        
        # Check 4: No es placeholder
        placeholder_patterns = [
            r'flag\{.*test.*\}',
            r'flag\{.*example.*\}',
            r'flag\{.*placeholder.*\}',
            r'flag\{.*xxx.*\}',
            r'flag\{.*dummy.*\}',
        ]
        checks["not_placeholder"] = not any(re.search(pattern, flag, re.IGNORECASE) for pattern in placeholder_patterns)
        if not checks["not_placeholder"]:
            recommendations.append("Flag appears to be a placeholder")
        
        # Check 5: Específico por tipo de challenge
        checks.update(self._validate_by_challenge_type(flag, challenge_type))
        
        # Check 6: Entropía (complejidad)
        entropy = self._calculate_entropy(flag)
        checks["sufficient_entropy"] = entropy > 2.0  # Umbral mínimo
        if not checks["sufficient_entropy"]:
            recommendations.append(f"Flag has low entropy ({entropy:.2f}), might be too simple")
        
        # Calcular confianza y calidad
        passed_checks = sum(1 for check in checks.values() if check)
        total_checks = len(checks)
        confidence = passed_checks / total_checks
        
        # Bonus por formato flag{...}
        if re.search(r'flag\{[^}]+\}', flag, re.IGNORECASE):
            confidence += 0.1
        
        # Penalty por recomendaciones
        confidence -= len(recommendations) * 0.05
        confidence = max(0.0, min(1.0, confidence))
        
        # Determinar formato
        flag_format = self._determine_format(flag)
        
        # Quality score (más estricto que confidence)
        quality_score = confidence
        if not checks.get("has_flag_format", False):
            quality_score *= 0.5
        if not checks.get("not_placeholder", False):
            quality_score *= 0.3
        
        is_valid = confidence >= 0.7 and checks.get("has_flag_format", False)
        
        result = ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            flag_format=flag_format,
            validation_checks=checks,
            recommendations=recommendations,
            quality_score=quality_score
        )
        
        print(f"   {'✅' if is_valid else '❌'} Validation: {confidence:.2f} confidence")
        if recommendations:
            print(f"   ⚠️  Recommendations: {len(recommendations)}")
            for rec in recommendations[:2]:  # Show first 2
                print(f"      - {rec}")
        
        return result
    
    def _validate_by_challenge_type(self, flag: str, challenge_type: str) -> Dict[str, bool]:
        """
        Validaciones específicas por tipo de challenge
        """
        checks = {}
        
        if challenge_type == "RSA":
            # RSA flags suelen ser texto plano decodificado
            checks["rsa_format"] = not flag.isdigit()  # No debería ser solo números
            checks["rsa_readable"] = any(c.isalpha() for c in flag)  # Debería tener letras
        
        elif challenge_type == "Classical":
            # Cifrados clásicos suelen dar texto legible
            checks["classical_readable"] = self._is_readable_text(flag)
            checks["classical_english"] = self._contains_english_words(flag)
        
        elif challenge_type == "XOR":
            # XOR puede dar texto o binario
            checks["xor_format"] = True  # XOR es flexible
        
        elif challenge_type == "Hash":
            # Hash cracking suele dar la palabra original
            checks["hash_format"] = len(flag) < 50  # No debería ser muy largo
            checks["hash_readable"] = flag.isascii()
        
        elif challenge_type == "Encoding":
            # Encoding suele dar texto claro
            checks["encoding_readable"] = self._is_readable_text(flag)
        
        else:
            # Tipo desconocido - checks genéricos
            checks["generic_format"] = True
        
        return checks
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calcula entropía de Shannon del texto
        """
        if not text:
            return 0.0
        
        # Contar frecuencias
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calcular entropía
        import math
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _determine_format(self, flag: str) -> str:
        """
        Determina el formato del flag
        """
        if re.search(r'flag\{[^}]+\}', flag, re.IGNORECASE):
            return "standard_flag"
        elif re.search(r'[a-zA-Z0-9_]+\{[^}]+\}', flag):
            return "custom_flag"
        elif re.match(r'^[a-f0-9]{32}$', flag):
            return "md5_hash"
        elif re.match(r'^[a-f0-9]{40}$', flag):
            return "sha1_hash"
        elif re.match(r'^[a-f0-9]{64}$', flag):
            return "sha256_hash"
        elif flag.isalnum():
            return "alphanumeric"
        else:
            return "mixed_format"
    
    def _is_readable_text(self, text: str) -> bool:
        """
        Verifica si el texto es legible (principalmente ASCII imprimible)
        """
        if not text:
            return False
        
        printable_chars = sum(1 for c in text if c.isprintable())
        return printable_chars / len(text) > 0.8
    
    def _contains_english_words(self, text: str) -> bool:
        """
        Verifica si contiene palabras en inglés comunes
        """
        common_words = [
            'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
            'flag', 'ctf', 'crypto', 'key', 'cipher', 'code', 'secret', 'password',
            'hello', 'world', 'test', 'admin', 'user', 'data', 'info', 'message'
        ]
        
        text_lower = text.lower()
        return any(word in text_lower for word in common_words)
    
    def validate_execution_result(self, execution_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Valida resultado completo de ejecución
        """
        print(f"\n🔍 {self.name}: Validating execution result...")
        
        flag_found = execution_result.get('flag_found', False)
        final_flag = execution_result.get('final_flag', '')
        winning_strategy = execution_result.get('winning_strategy', '')
        
        validation_summary = {
            'validator': self.name,
            'execution_success': flag_found,
            'flag_validation': None,
            'overall_quality': 0.0,
            'recommendations': [],
            'confidence': 0.0
        }
        
        if flag_found and final_flag:
            # Validar el flag encontrado
            flag_validation = self.validate_flag(final_flag)
            validation_summary['flag_validation'] = {
                'is_valid': flag_validation.is_valid,
                'confidence': flag_validation.confidence,
                'format': flag_validation.flag_format,
                'quality_score': flag_validation.quality_score,
                'checks_passed': sum(1 for check in flag_validation.validation_checks.values() if check),
                'total_checks': len(flag_validation.validation_checks),
                'recommendations': flag_validation.recommendations
            }
            
            validation_summary['overall_quality'] = flag_validation.quality_score
            validation_summary['confidence'] = flag_validation.confidence
            validation_summary['recommendations'].extend(flag_validation.recommendations)
            
            if flag_validation.is_valid:
                print(f"   ✅ Flag validation: PASSED ({flag_validation.confidence:.2f})")
            else:
                print(f"   ⚠️  Flag validation: QUESTIONABLE ({flag_validation.confidence:.2f})")
        
        else:
            print(f"   ❌ No flag found to validate")
            validation_summary['confidence'] = 0.0
            validation_summary['recommendations'].append("No flag was found during execution")
        
        # Validar estrategia ganadora
        if winning_strategy:
            print(f"   🎯 Winning strategy: {winning_strategy}")
            validation_summary['winning_strategy_valid'] = True
        else:
            validation_summary['winning_strategy_valid'] = False
            validation_summary['recommendations'].append("No winning strategy identified")
        
        # Calcular calidad general
        if flag_found and validation_summary.get('flag_validation', {}).get('is_valid', False):
            validation_summary['overall_quality'] = min(validation_summary['overall_quality'] + 0.1, 1.0)
        
        print(f"   📊 Overall quality: {validation_summary['overall_quality']:.2f}")
        
        return validation_summary

# Instancia global
validator_agent = ValidatorAgent()