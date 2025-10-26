#!/usr/bin/env python3
"""
TEST SISTEMA INTEGRADO COMPLETO
Prueba todos los componentes trabajando juntos
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime

# Añadir paths
sys.path.append('.')
sys.path.append('multi_agent')
sys.path.append('ml_phase2')
sys.path.append('rag')

def test_enhanced_bert():
    """Test del clasificador BERT mejorado"""
    print("🧠 Testing Enhanced BERT Classifier")
    print("-" * 40)
    
    try:
        from ml_phase2.bert_classifier_enhanced import get_bert_classifier
        
        classifier = get_bert_classifier()
        if classifier is None:
            print("❌ BERT classifier not available")
            return False
        
        # Test con challenge de ejemplo
        test_challenge = {
            'description': 'RSA challenge with small exponent e=3',
            'files': [{'content': 'n = 12345\ne = 3\nc = 67890'}]
        }
        
        predicted_type, confidence = classifier.classify(test_challenge)
        print(f"✅ Classification: {predicted_type} (confidence: {confidence:.4f})")
        
        # Info del modelo
        model_info = classifier.get_model_info()
        print(f"📊 Model info: {model_info}")
        
        return True
        
    except Exception as e:
        print(f"❌ BERT test failed: {e}")
        return False

def test_enhanced_rag():
    """Test del motor RAG mejorado"""
    print("\n📚 Testing Enhanced RAG Engine")
    print("-" * 40)
    
    try:
        from rag.rag_engine_enhanced import get_enhanced_rag_engine
        
        rag_engine = get_enhanced_rag_engine()
        if rag_engine is None:
            print("❌ RAG engine not available")
            return False
        
        # Test de estadísticas
        stats = rag_engine.get_statistics()
        print(f"📊 RAG Statistics: {stats}")
        
        if not stats.get('available'):
            print("⚠️ RAG data not available")
            return False
        
        # Test de búsqueda
        test_query = "RSA small exponent attack"
        results = rag_engine.retrieve_similar_writeups(test_query, n_results=3)
        print(f"🔍 Search results for '{test_query}': {len(results)} found")
        
        # Test de contexto para challenge
        test_challenge = {
            'description': 'RSA challenge with small exponent',
            'files': [{'content': 'n = 12345\ne = 3\nc = 67890'}]
        }
        
        context = rag_engine.get_context_for_challenge(test_challenge)
        print(f"🎯 Challenge context: {context.get('available', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ RAG test failed: {e}")
        return False

def test_multi_agent_coordinator():
    """Test del coordinador multi-agente mejorado"""
    print("\n🤖 Testing Enhanced Multi-Agent Coordinator")
    print("-" * 40)
    
    try:
        from multi_agent.coordination.coordinator_enhanced import get_enhanced_coordinator
        
        coordinator = get_enhanced_coordinator()
        if coordinator is None:
            print("❌ Enhanced coordinator not available")
            return False
        
        # Estado del sistema
        status = coordinator.get_system_status()
        print(f"📊 System Status:")
        print(f"   Ready: {status['coordinator_ready']}")
        print(f"   Agents: {list(status['agents'].keys())}")
        print(f"   Enhanced BERT: {status['enhanced_components']['bert_classifier']}")
        print(f"   Enhanced RAG: {status['enhanced_components']['rag_engine']}")
        print(f"   Capabilities: {', '.join(status['capabilities'])}")
        
        if not status['coordinator_ready']:
            print("⚠️ Coordinator not ready")
            return False
        
        # Test con challenge simple
        test_challenge = {
            'description': 'Simple XOR cipher challenge',
            'files': [{
                'name': 'challenge.py',
                'content': '''
# XOR Challenge
ciphertext = "1a2b3c4d5e6f"
key = "secret"
# Find the flag
'''
            }]
        }
        
        print(f"\n🧪 Testing with challenge: {test_challenge['description']}")
        result = coordinator.solve_challenge(
            test_challenge['description'],
            test_challenge['files']
        )
        
        print(f"\n📊 Test Result:")
        print(f"   Success: {result.success}")
        print(f"   Classification: {result.classification}")
        print(f"   Time: {result.time_taken:.2f}s")
        print(f"   Agents Used: {', '.join(result.agents_used)}")
        print(f"   Strategy: {result.strategy}")
        
        if result.error:
            print(f"   Error: {result.error}")
        
        return True
        
    except Exception as e:
        print(f"❌ Multi-agent test failed: {e}")
        return False

def test_backend_api():
    """Test del backend FastAPI (sin servidor)"""
    print("\n🌐 Testing Backend API Components")
    print("-" * 40)
    
    try:
        # Importar componentes del backend
        import backend_fastapi_enhanced
        
        print("✅ Backend imports successful")
        
        # Verificar disponibilidad de componentes
        components = {
            "Enhanced Coordinator": backend_fastapi_enhanced.ENHANCED_COORDINATOR_AVAILABLE,
            "Enhanced BERT": backend_fastapi_enhanced.BERT_ENHANCED_AVAILABLE,
            "Enhanced RAG": backend_fastapi_enhanced.RAG_ENHANCED_AVAILABLE,
            "Simple Solver": backend_fastapi_enhanced.SIMPLE_SOLVER_AVAILABLE
        }
        
        print("📊 Backend Components:")
        for component, available in components.items():
            status = "✅" if available else "❌"
            print(f"   {status} {component}")
        
        return any(components.values())
        
    except Exception as e:
        print(f"❌ Backend test failed: {e}")
        return False

def test_integration_scenarios():
    """Test de escenarios de integración completos"""
    print("\n🎯 Testing Integration Scenarios")
    print("-" * 40)
    
    scenarios = [
        {
            'name': 'RSA Small Exponent',
            'description': 'RSA challenge with e=3',
            'files': [{
                'name': 'rsa_challenge.py',
                'content': '''
n = 12345678901234567890123456789
e = 3
c = 98765432109876543210987654321
# Find the plaintext
'''
            }]
        },
        {
            'name': 'Caesar Cipher',
            'description': 'Classical substitution cipher',
            'files': [{
                'name': 'caesar.py',
                'content': '''
ciphertext = "WKLV LV D WHVW"
# Caesar cipher with unknown shift
# Find the flag
'''
            }]
        },
        {
            'name': 'XOR Challenge',
            'description': 'XOR encryption with repeating key',
            'files': [{
                'name': 'xor.py',
                'content': '''
import binascii
ciphertext = binascii.unhexlify("1a2b3c4d5e6f")
# XOR with repeating key
# Find the original message
'''
            }]
        }
    ]
    
    results = []
    
    try:
        from multi_agent.coordination.coordinator_enhanced import get_enhanced_coordinator
        coordinator = get_enhanced_coordinator()
        
        if not coordinator or not coordinator.is_ready:
            print("⚠️ Enhanced coordinator not ready, skipping integration tests")
            return False
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n🧪 Scenario {i}: {scenario['name']}")
            print(f"   Description: {scenario['description']}")
            
            start_time = time.time()
            result = coordinator.solve_challenge(
                scenario['description'],
                scenario['files']
            )
            end_time = time.time()
            
            scenario_result = {
                'name': scenario['name'],
                'success': result.success,
                'time_taken': end_time - start_time,
                'classification': result.classification,
                'strategy': result.strategy,
                'agents_used': result.agents_used,
                'error': result.error
            }
            
            results.append(scenario_result)
            
            status = "✅" if result.success else "❌"
            print(f"   {status} Result: {result.success}")
            print(f"   ⏱️ Time: {scenario_result['time_taken']:.2f}s")
            
            if result.classification:
                print(f"   🏷️ Type: {result.classification}")
            
            if result.strategy:
                print(f"   🎯 Strategy: {result.strategy}")
            
            if result.error:
                print(f"   ❌ Error: {result.error}")
        
        # Resumen de resultados
        print(f"\n📊 Integration Test Summary:")
        print(f"   Total scenarios: {len(scenarios)}")
        print(f"   Successful: {len([r for r in results if r['success']])}")
        print(f"   Failed: {len([r for r in results if not r['success']])}")
        print(f"   Average time: {sum(r['time_taken'] for r in results) / len(results):.2f}s")
        
        return len([r for r in results if r['success']]) > 0
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def generate_integration_report(test_results):
    """Genera reporte de integración"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "integration_test_results": test_results,
        "summary": {
            "total_tests": len(test_results),
            "passed": len([r for r in test_results.values() if r]),
            "failed": len([r for r in test_results.values() if not r]),
            "success_rate": len([r for r in test_results.values() if r]) / len(test_results)
        },
        "recommendations": []
    }
    
    # Añadir recomendaciones basadas en resultados
    if not test_results.get('enhanced_bert'):
        report["recommendations"].append("Install and configure Enhanced BERT classifier")
    
    if not test_results.get('enhanced_rag'):
        report["recommendations"].append("Prepare RAG embeddings and data")
    
    if not test_results.get('multi_agent'):
        report["recommendations"].append("Fix multi-agent system configuration")
    
    if not test_results.get('backend_api'):
        report["recommendations"].append("Resolve backend API dependencies")
    
    # Guardar reporte
    report_file = f"integration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return report_file

def main():
    """Función principal de test de integración"""
    print("🚀 ENHANCED CTF SOLVER - INTEGRATION TEST")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    # Ejecutar tests
    test_results = {
        'enhanced_bert': test_enhanced_bert(),
        'enhanced_rag': test_enhanced_rag(),
        'multi_agent': test_multi_agent_coordinator(),
        'backend_api': test_backend_api(),
        'integration_scenarios': test_integration_scenarios()
    }
    
    # Resumen final
    print("\n" + "=" * 60)
    print("🎯 INTEGRATION TEST FINAL SUMMARY")
    print("=" * 60)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name.replace('_', ' ').title()}")
    
    total_tests = len(test_results)
    passed_tests = len([r for r in test_results.values() if r])
    success_rate = passed_tests / total_tests
    
    print(f"\n📊 Overall Results:")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {passed_tests}")
    print(f"   Failed: {total_tests - passed_tests}")
    print(f"   Success Rate: {success_rate:.1%}")
    
    # Generar reporte
    report_file = generate_integration_report(test_results)
    print(f"\n📄 Report saved: {report_file}")
    
    # Estado final
    if success_rate >= 0.8:
        print("\n🎉 INTEGRATION TEST: SUCCESS")
        print("   System is ready for production use!")
    elif success_rate >= 0.6:
        print("\n⚠️ INTEGRATION TEST: PARTIAL SUCCESS")
        print("   System has some issues but core functionality works")
    else:
        print("\n❌ INTEGRATION TEST: FAILED")
        print("   System needs significant fixes before use")
    
    print("=" * 60)
    
    return success_rate >= 0.6

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)