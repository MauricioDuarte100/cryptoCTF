"""
Planner Agent - Phase 2.4
Agente especializado en planificación estratégica y toma de decisiones.
Usa RAG para contexto histórico y genera planes de ataque detallados.
"""

import json
from typing import Dict, List, Any
from dataclasses import dataclass
import sys
from pathlib import Path

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "rag"))

from tools.tools import analyze_files, classify_crypto
from rag_agent_tools import retrieve_similar_writeups, analyze_with_context

@dataclass
class AttackPlan:
    """Plan de ataque estructurado"""
    challenge_type: str
    confidence: float
    primary_strategy: str
    fallback_strategies: List[str]
    tools_needed: List[str]
    parameters: Dict[str, Any]
    rag_context: Dict[str, Any]
    estimated_difficulty: str
    success_probability: float

class PlannerAgent:
    """
    Agente Planificador - Decide estrategia y genera planes de ataque
    """
    
    def __init__(self):
        self.name = "PlannerAgent"
        self.capabilities = [
            "strategic_planning",
            "rag_context_analysis", 
            "attack_prioritization",
            "risk_assessment"
        ]
    
    def analyze_challenge(self, challenge_description: str, files: List[Dict]) -> Dict[str, Any]:
        """
        Análisis inicial del challenge usando todas las herramientas disponibles
        """
        print(f"🧠 {self.name}: Analyzing challenge...")
        
        # 1. Análisis de archivos
        analysis = analyze_files.invoke({'files': files})
        print(f"   📊 File analysis: {len(analysis.get('variables', {}))} variables, {len(analysis.get('imports', []))} imports")
        
        # 2. Clasificación con BERT+Heuristic
        classification = classify_crypto.invoke({'analysis': analysis, 'use_ml': True})
        print(f"   🎯 Classification: {classification['type']} ({classification['confidence']:.2f}) via {classification.get('method', 'unknown')}")
        
        # 3. RAG Context retrieval
        challenge_content = f"{challenge_description}\n\n"
        for file in files:
            challenge_content += f"File: {file['name']}\n{file.get('content', '')}\n\n"
        
        rag_result = retrieve_similar_writeups.invoke({
            'challenge_text': challenge_content,
            'challenge_type': classification['type']
        })
        
        if rag_result['status'] == 'success':
            print(f"   🧠 RAG Context: {rag_result['count']} similar writeups retrieved")
        else:
            print(f"   ⚠️  RAG Context: {rag_result['message']}")
        
        return {
            'analysis': analysis,
            'classification': classification,
            'rag_context': rag_result,
            'challenge_content': challenge_content
        }
    
    def generate_attack_plan(self, challenge_analysis: Dict[str, Any]) -> AttackPlan:
        """
        Genera plan de ataque detallado basado en análisis
        """
        print(f"📋 {self.name}: Generating attack plan...")
        
        classification = challenge_analysis['classification']
        analysis = challenge_analysis['analysis']
        rag_context = challenge_analysis['rag_context']
        
        challenge_type = classification['type']
        confidence = classification['confidence']
        
        # Estrategias por tipo
        strategy_map = {
            'RSA': {
                'primary': 'rsa_factorization_attacks',
                'fallbacks': ['wiener_attack', 'fermat_factorization', 'common_modulus'],
                'tools': ['attack_rsa', 'factorize_number'],
                'difficulty': 'medium'
            },
            'Classical': {
                'primary': 'frequency_analysis',
                'fallbacks': ['brute_force_rotation', 'dictionary_attack'],
                'tools': ['attack_classical', 'decode_text'],
                'difficulty': 'easy'
            },
            'XOR': {
                'primary': 'single_byte_bruteforce',
                'fallbacks': ['multi_byte_analysis', 'key_reuse_attack'],
                'tools': ['attack_classical'],  # XOR handled by classical
                'difficulty': 'easy'
            },
            'Encoding': {
                'primary': 'base64_decode',
                'fallbacks': ['hex_decode', 'url_decode'],
                'tools': ['decode_text'],
                'difficulty': 'trivial'
            },
            'Hash': {
                'primary': 'dictionary_attack',
                'fallbacks': ['rainbow_table', 'brute_force'],
                'tools': ['attack_classical'],
                'difficulty': 'hard'
            }
        }
        
        strategy = strategy_map.get(challenge_type, {
            'primary': 'generic_analysis',
            'fallbacks': ['manual_inspection'],
            'tools': ['analyze_files'],
            'difficulty': 'unknown'
        })
        
        # Extraer parámetros del análisis
        parameters = {}
        variables = analysis.get('variables', {})
        
        if challenge_type == 'RSA':
            parameters = {
                'n': variables.get('n', 'unknown'),
                'e': variables.get('e', 'unknown'), 
                'c': variables.get('c', 'unknown')
            }
        elif challenge_type == 'Classical':
            parameters = {
                'ciphertext': variables.get('ciphertext', variables.get('encrypted', 'unknown'))
            }
        elif challenge_type == 'XOR':
            parameters = {
                'encrypted_data': variables.get('encrypted', variables.get('ciphertext', 'unknown'))
            }
        
        # Calcular probabilidad de éxito basada en contexto RAG
        success_probability = confidence
        if rag_context.get('status') == 'success' and rag_context.get('count', 0) > 0:
            success_probability = min(success_probability + 0.2, 1.0)  # Boost por contexto RAG
        
        plan = AttackPlan(
            challenge_type=challenge_type,
            confidence=confidence,
            primary_strategy=strategy['primary'],
            fallback_strategies=strategy['fallbacks'],
            tools_needed=strategy['tools'],
            parameters=parameters,
            rag_context=rag_context,
            estimated_difficulty=strategy['difficulty'],
            success_probability=success_probability
        )
        
        print(f"   ✅ Plan generated: {plan.primary_strategy} (success prob: {plan.success_probability:.2f})")
        return plan
    
    def prioritize_strategies(self, plan: AttackPlan) -> List[Dict[str, Any]]:
        """
        Prioriza estrategias basado en contexto RAG y probabilidades
        """
        print(f"🎯 {self.name}: Prioritizing attack strategies...")
        
        strategies = []
        
        # Estrategia principal
        strategies.append({
            'name': plan.primary_strategy,
            'priority': 1,
            'tools': plan.tools_needed,
            'parameters': plan.parameters,
            'success_probability': plan.success_probability,
            'reason': f'Primary strategy for {plan.challenge_type} with {plan.confidence:.2f} confidence'
        })
        
        # Estrategias de fallback
        for i, fallback in enumerate(plan.fallback_strategies):
            strategies.append({
                'name': fallback,
                'priority': i + 2,
                'tools': plan.tools_needed,
                'parameters': plan.parameters,
                'success_probability': max(plan.success_probability - 0.1 * (i + 1), 0.1),
                'reason': f'Fallback strategy #{i+1} for {plan.challenge_type}'
            })
        
        # Si hay contexto RAG, ajustar prioridades
        if plan.rag_context.get('status') == 'success':
            writeups = plan.rag_context.get('writeups', [])
            for writeup in writeups:
                # Analizar writeup para extraer estrategias exitosas
                content = writeup.get('content', '').lower()
                if 'wiener' in content and plan.challenge_type == 'RSA':
                    # Boost Wiener attack priority
                    for strategy in strategies:
                        if 'wiener' in strategy['name']:
                            strategy['priority'] = max(strategy['priority'] - 1, 1)
                            strategy['success_probability'] += 0.1
                            strategy['reason'] += ' (RAG boost: Wiener mentioned in similar writeup)'
        
        # Ordenar por prioridad
        strategies.sort(key=lambda x: x['priority'])
        
        print(f"   📊 Prioritized {len(strategies)} strategies")
        for i, strategy in enumerate(strategies[:3]):  # Show top 3
            print(f"      {i+1}. {strategy['name']} (prob: {strategy['success_probability']:.2f})")
        
        return strategies
    
    def create_execution_plan(self, challenge_description: str, files: List[Dict]) -> Dict[str, Any]:
        """
        Crea plan de ejecución completo para el challenge
        """
        print(f"\n🚀 {self.name}: Creating execution plan...")
        
        # 1. Análisis completo
        analysis = self.analyze_challenge(challenge_description, files)
        
        # 2. Generar plan de ataque
        attack_plan = self.generate_attack_plan(analysis)
        
        # 3. Priorizar estrategias
        prioritized_strategies = self.prioritize_strategies(attack_plan)
        
        # 4. Crear plan de ejecución
        execution_plan = {
            'planner': self.name,
            'challenge_type': attack_plan.challenge_type,
            'confidence': attack_plan.confidence,
            'estimated_difficulty': attack_plan.estimated_difficulty,
            'success_probability': attack_plan.success_probability,
            'strategies': prioritized_strategies,
            'parameters': attack_plan.parameters,
            'rag_context_used': attack_plan.rag_context.get('status') == 'success',
            'rag_patterns_count': attack_plan.rag_context.get('count', 0),
            'analysis_summary': {
                'variables_found': len(analysis['analysis'].get('variables', {})),
                'imports_found': len(analysis['analysis'].get('imports', [])),
                'crypto_indicators': analysis['analysis'].get('crypto_indicators', [])
            }
        }
        
        print(f"✅ {self.name}: Execution plan ready!")
        print(f"   Type: {execution_plan['challenge_type']}")
        print(f"   Strategies: {len(execution_plan['strategies'])}")
        print(f"   RAG Context: {execution_plan['rag_patterns_count']} patterns")
        print(f"   Success Probability: {execution_plan['success_probability']:.2f}")
        
        return execution_plan

# Instancia global
planner_agent = PlannerAgent()