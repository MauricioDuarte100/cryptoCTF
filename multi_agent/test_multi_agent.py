"""
Test Multi-Agent System - Phase 2.4
Prueba completa del sistema multi-agente con challenges reales.
"""

import sys
from pathlib import Path

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent))

from coordination.coordinator import multi_agent_coordinator

def test_multi_agent_system():
    """
    Test completo del sistema multi-agente
    """
    print("🧪 TESTING MULTI-AGENT SYSTEM")
    print("=" * 60)
    
    # Challenge de prueba - RSA simple
    test_challenge = {
        "description": "RSA challenge with small exponent",
        "files": [{
            "name": "chall.py",
            "content": """
# RSA Challenge - Small Exponent Attack
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Public key parameters
n = 12345678901234567890123456789012345678901234567890123456789012345678901234567890
e = 3
c = 9876543210987654321098765432109876543210987654321098765432109876543210987654321

print(f"n = {n}")
print(f"e = {e}")  
print(f"c = {c}")
print("Hint: Small exponent vulnerability!")

# The flag is encrypted with RSA
# Try cube root attack since e=3
"""
        }]
    }
    
    # Ejecutar sistema multi-agente
    result = multi_agent_coordinator.solve_challenge(
        challenge_description=test_challenge["description"],
        files=test_challenge["files"]
    )
    
    # Verificar resultado
    print(f"\n🔍 TEST RESULTS:")
    print(f"   Success: {result.success}")
    print(f"   Flag: {result.flag}")
    print(f"   Total Time: {result.total_time:.2f}s")
    print(f"   Confidence: {result.confidence:.2f}")
    print(f"   Quality: {result.quality_score:.2f}")
    
    # Estadísticas de rendimiento
    stats = multi_agent_coordinator.get_performance_stats()
    print(f"\n📊 PERFORMANCE STATS:")
    print(f"   Success Rate: {stats['success_rate']:.2%}")
    print(f"   Avg Total Time: {stats['average_times']['total']:.2f}s")
    print(f"   Avg Planner Time: {stats['average_times']['planner']:.2f}s")
    print(f"   Avg Executor Time: {stats['average_times']['executor']:.2f}s")
    print(f"   Avg Validator Time: {stats['average_times']['validator']:.2f}s")
    
    # Evaluación
    if result.success and result.confidence > 0.7:
        print(f"\n✅ MULTI-AGENT TEST: PASSED")
        print(f"   System is working correctly")
        return True
    else:
        print(f"\n⚠️  MULTI-AGENT TEST: NEEDS REVIEW")
        print(f"   Success: {result.success}, Confidence: {result.confidence:.2f}")
        return False

def test_individual_agents():
    """
    Test individual de cada agente
    """
    print(f"\n🔧 TESTING INDIVIDUAL AGENTS")
    print("-" * 40)
    
    test_files = [{
        "name": "test.py",
        "content": "n = 123\ne = 3\nc = 456\nprint('RSA test')"
    }]
    
    # Test Planner Agent
    print(f"🧠 Testing Planner Agent...")
    try:
        from agents.planner_agent import planner_agent
        plan = planner_agent.create_execution_plan("RSA test", test_files)
        print(f"   ✅ Planner: Generated plan with {len(plan.get('strategies', []))} strategies")
    except Exception as e:
        print(f"   ❌ Planner failed: {e}")
        return False
    
    # Test Executor Agent
    print(f"⚡ Testing Executor Agent...")
    try:
        from agents.executor_agent import executor_agent
        # Crear plan simple para test
        simple_plan = {
            'strategies': [{
                'name': 'test_strategy',
                'tools': ['decode_text'],
                'parameters': {'encoded_text': 'hello'},
                'priority': 1,
                'success_probability': 0.5
            }]
        }
        exec_result = executor_agent.execute_plan(simple_plan)
        print(f"   ✅ Executor: Executed {exec_result.get('total_strategies_tried', 0)} strategies")
    except Exception as e:
        print(f"   ❌ Executor failed: {e}")
        return False
    
    # Test Validator Agent
    print(f"🔍 Testing Validator Agent...")
    try:
        from agents.validator_agent import validator_agent
        validation = validator_agent.validate_flag("flag{test_flag}", "RSA")
        print(f"   ✅ Validator: Confidence {validation.confidence:.2f}")
    except Exception as e:
        print(f"   ❌ Validator failed: {e}")
        return False
    
    print(f"✅ All individual agents working correctly")
    return True

def main():
    """
    Test principal del sistema multi-agente
    """
    print("🚀 MULTI-AGENT SYSTEM TEST SUITE")
    print("=" * 60)
    
    # Test 1: Agentes individuales
    individual_test = test_individual_agents()
    
    # Test 2: Sistema completo
    if individual_test:
        system_test = test_multi_agent_system()
    else:
        print("❌ Skipping system test due to individual agent failures")
        system_test = False
    
    # Resultado final
    print(f"\n" + "=" * 60)
    print(f"🎯 FINAL TEST RESULTS")
    print(f"=" * 60)
    print(f"Individual Agents: {'✅ PASS' if individual_test else '❌ FAIL'}")
    print(f"Multi-Agent System: {'✅ PASS' if system_test else '❌ FAIL'}")
    
    overall_success = individual_test and system_test
    
    if overall_success:
        print(f"\n🎉 MULTI-AGENT SYSTEM: READY FOR PRODUCTION")
        print(f"   All tests passed successfully")
        print(f"   Phase 2.4 implementation: COMPLETE")
    else:
        print(f"\n⚠️  MULTI-AGENT SYSTEM: NEEDS WORK")
        print(f"   Some tests failed - review implementation")
    
    return overall_success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)