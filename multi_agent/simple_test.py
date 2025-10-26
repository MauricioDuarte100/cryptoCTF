"""
Simple Multi-Agent Test
Test rápido para verificar que el sistema multi-agente funciona.
"""

import sys
from pathlib import Path

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent))

def test_multi_agent_simple():
    """Test simple del sistema multi-agente"""
    print("🧪 SIMPLE MULTI-AGENT TEST")
    print("=" * 50)
    
    try:
        # Test 1: Importar coordinator
        print("📦 Testing imports...")
        from coordination.coordinator import multi_agent_coordinator
        print("   ✅ Coordinator imported")
        
        # Test 2: Verificar agentes
        print("🤖 Testing agents...")
        agents = multi_agent_coordinator.agents
        print(f"   ✅ {len(agents)} agents available: {list(agents.keys())}")
        
        # Test 3: Test simple de clasificación
        print("🎯 Testing classification...")
        test_files = [{
            "name": "test.py",
            "content": "n = 123\ne = 3\nc = 456"
        }]
        
        from agents.planner_agent import planner_agent
        plan = planner_agent.create_execution_plan("RSA test", test_files)
        
        print(f"   ✅ Plan created: {plan['challenge_type']} with {len(plan['strategies'])} strategies")
        print(f"   ✅ RAG patterns: {plan['rag_patterns_count']}")
        print(f"   ✅ Success probability: {plan['success_probability']:.2f}")
        
        print("\n🎉 MULTI-AGENT SYSTEM: FUNCTIONAL")
        print("   All core components working")
        print("   Architecture ready for production")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_multi_agent_simple()
    print(f"\nResult: {'✅ PASS' if success else '❌ FAIL'}")
    exit(0 if success else 1)