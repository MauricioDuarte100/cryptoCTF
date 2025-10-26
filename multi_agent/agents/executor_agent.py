"""
Executor Agent - Phase 2.4
Agente especializado en ejecución de herramientas y ataques.
Ejecuta el plan generado por el Planner Agent.
"""

import time
from typing import Dict, List, Any
from dataclasses import dataclass
import sys
from pathlib import Path

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from tools.tools import attack_rsa, attack_classical, decode_text, factorize_number

@dataclass
class ExecutionResult:
    """Resultado de ejecución de una estrategia"""
    strategy_name: str
    success: bool
    flag: str
    execution_time: float
    error_message: str
    tool_used: str
    parameters_used: Dict[str, Any]

class ExecutorAgent:
    """
    Agente Ejecutor - Ejecuta herramientas y ataques según el plan
    """
    
    def __init__(self):
        self.name = "ExecutorAgent"
        self.capabilities = [
            "tool_execution",
            "attack_implementation", 
            "error_handling",
            "result_extraction"
        ]
        self.execution_history = []
    
    def execute_strategy(self, strategy: Dict[str, Any], max_retries: int = 2) -> ExecutionResult:
        """
        Ejecuta una estrategia específica
        """
        strategy_name = strategy['name']
        tools = strategy['tools']
        parameters = strategy['parameters']
        
        print(f"⚡ {self.name}: Executing strategy '{strategy_name}'...")
        
        start_time = time.time()
        
        for attempt in range(max_retries + 1):
            try:
                # Seleccionar herramienta principal
                primary_tool = tools[0] if tools else None
                
                if not primary_tool:
                    return ExecutionResult(
                        strategy_name=strategy_name,
                        success=False,
                        flag="",
                        execution_time=time.time() - start_time,
                        error_message="No tools specified for strategy",
                        tool_used="none",
                        parameters_used=parameters
                    )
                
                # Ejecutar según el tipo de herramienta
                result = self._execute_tool(primary_tool, parameters)
                
                execution_time = time.time() - start_time
                
                # Verificar si encontramos flag
                flag_found = self._extract_flag(result)
                
                if flag_found:
                    print(f"   ✅ Success! Flag found: {flag_found}")
                    return ExecutionResult(
                        strategy_name=strategy_name,
                        success=True,
                        flag=flag_found,
                        execution_time=execution_time,
                        error_message="",
                        tool_used=primary_tool,
                        parameters_used=parameters
                    )
                else:
                    print(f"   ⚠️  Attempt {attempt + 1}: No flag found")
                    if attempt < max_retries:
                        print(f"   🔄 Retrying with modified parameters...")
                        parameters = self._modify_parameters(parameters, attempt + 1)
            
            except Exception as e:
                print(f"   ❌ Attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries:
                    return ExecutionResult(
                        strategy_name=strategy_name,
                        success=False,
                        flag="",
                        execution_time=time.time() - start_time,
                        error_message=str(e),
                        tool_used=primary_tool,
                        parameters_used=parameters
                    )
        
        # Si llegamos aquí, todos los intentos fallaron
        return ExecutionResult(
            strategy_name=strategy_name,
            success=False,
            flag="",
            execution_time=time.time() - start_time,
            error_message="All retry attempts failed",
            tool_used=primary_tool,
            parameters_used=parameters
        )
    
    def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """
        Ejecuta una herramienta específica con parámetros
        """
        print(f"   🔧 Using tool: {tool_name}")
        
        if tool_name == 'attack_rsa':
            return attack_rsa.invoke({
                'n': str(parameters.get('n', '')),
                'e': str(parameters.get('e', '')),
                'c': str(parameters.get('c', ''))
            })
        
        elif tool_name == 'attack_classical':
            ciphertext = parameters.get('ciphertext', parameters.get('encrypted_data', ''))
            return attack_classical.invoke({
                'ciphertext': str(ciphertext)
            })
        
        elif tool_name == 'decode_text':
            text = parameters.get('encoded_text', parameters.get('ciphertext', ''))
            return decode_text.invoke({
                'text': str(text)
            })
        
        elif tool_name == 'factorize_number':
            n = parameters.get('n', '')
            return factorize_number.invoke({
                'number': str(n)
            })
        
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    def _extract_flag(self, result: Any) -> str:
        """
        Extrae flag del resultado de la herramienta
        """
        if not result:
            return ""
        
        # Si es string, buscar flag directamente
        if isinstance(result, str):
            if 'flag{' in result.lower():
                # Extraer flag
                start = result.lower().find('flag{')
                if start != -1:
                    end = result.find('}', start) + 1
                    if end > start:
                        return result[start:end]
        
        # Si es dict, buscar en campos comunes
        elif isinstance(result, dict):
            for key in ['flag', 'result', 'output', 'plaintext', 'decrypted']:
                if key in result and result[key]:
                    flag = self._extract_flag(result[key])
                    if flag:
                        return flag
        
        return ""
    
    def _modify_parameters(self, parameters: Dict[str, Any], attempt: int) -> Dict[str, Any]:
        """
        Modifica parámetros para reintentos
        """
        modified = parameters.copy()
        
        # Para RSA, intentar convertir números si son strings
        if 'n' in modified and isinstance(modified['n'], str):
            try:
                modified['n'] = int(modified['n'])
            except:
                pass
        
        if 'e' in modified and isinstance(modified['e'], str):
            try:
                modified['e'] = int(modified['e'])
            except:
                pass
        
        if 'c' in modified and isinstance(modified['c'], str):
            try:
                modified['c'] = int(modified['c'])
            except:
                pass
        
        return modified
    
    def execute_plan(self, execution_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta plan completo de estrategias
        """
        print(f"\n🚀 {self.name}: Executing plan with {len(execution_plan['strategies'])} strategies...")
        
        strategies = execution_plan['strategies']
        results = []
        
        for i, strategy in enumerate(strategies):
            print(f"\n📋 Strategy {i+1}/{len(strategies)}: {strategy['name']}")
            print(f"   Priority: {strategy['priority']}")
            print(f"   Success Probability: {strategy['success_probability']:.2f}")
            
            result = self.execute_strategy(strategy)
            results.append(result)
            
            # Si encontramos flag, parar ejecución
            if result.success and result.flag:
                print(f"\n🎉 {self.name}: FLAG FOUND! Stopping execution.")
                break
            
            # Si no es la última estrategia, continuar
            if i < len(strategies) - 1:
                print(f"   ➡️  Moving to next strategy...")
        
        # Compilar resultados
        successful_results = [r for r in results if r.success]
        total_time = sum(r.execution_time for r in results)
        
        execution_summary = {
            'executor': self.name,
            'total_strategies_tried': len(results),
            'successful_strategies': len(successful_results),
            'total_execution_time': total_time,
            'flag_found': len(successful_results) > 0,
            'final_flag': successful_results[0].flag if successful_results else "",
            'winning_strategy': successful_results[0].strategy_name if successful_results else "",
            'results': [
                {
                    'strategy': r.strategy_name,
                    'success': r.success,
                    'flag': r.flag,
                    'time': r.execution_time,
                    'tool': r.tool_used,
                    'error': r.error_message
                }
                for r in results
            ]
        }
        
        print(f"\n📊 {self.name}: Execution Summary:")
        print(f"   Strategies tried: {execution_summary['total_strategies_tried']}")
        print(f"   Success: {execution_summary['flag_found']}")
        if execution_summary['flag_found']:
            print(f"   Winning strategy: {execution_summary['winning_strategy']}")
            print(f"   Flag: {execution_summary['final_flag']}")
        print(f"   Total time: {execution_summary['total_execution_time']:.2f}s")
        
        return execution_summary

# Instancia global
executor_agent = ExecutorAgent()