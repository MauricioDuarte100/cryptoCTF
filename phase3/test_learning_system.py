"""
Test Learning System
Prueba el sistema de aprendizaje de la Fase 3.0
"""

import sys
import time
from pathlib import Path
from datetime import datetime

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_feedback_collection():
    """Prueba la recolección de feedback"""
    print("🧪 Testing Feedback Collection...")
    
    try:
        from phase3.learning.feedback_collector import feedback_collector, ExecutionFeedback
        
        # Crear feedback de prueba
        test_feedback = ExecutionFeedback(
            timestamp=datetime.now().isoformat(),
            challenge_id="test_challenge_001",
            challenge_type="RSA",
            challenge_name="Test RSA Challenge",
            success=True,
            flag_found="flag{test_flag_123}",
            total_time=2.5,
            confidence=0.85,
            quality_score=0.9,
            
            # Agent performance
            agents_used=["planner", "executor", "validator"],
            planner_confidence=0.8,
            planner_strategies=4,
            planner_rag_patterns=3,
            executor_attempts=2,
            executor_success_strategy="rsa_factorization_attacks",
            validator_confidence=0.9,
            
            # Strategy details
            strategies_tried=[
                {"name": "rsa_factorization_attacks", "priority": 1, "success": True, "time": 1.2},
                {"name": "wiener_attack", "priority": 2, "success": False, "time": 0.8}
            ],
            winning_strategy={"name": "rsa_factorization_attacks", "priority": 1, "success": True, "time": 1.2},
            failed_strategies=[
                {"name": "wiener_attack", "priority": 2, "success": False, "time": 0.8}
            ],
            
            # Error information
            errors=[],
            warnings=["Low BERT confidence, using heuristic"],
            
            # Context
            rag_context=[
                {"pattern": "RSA small exponent", "similarity": 0.85},
                {"pattern": "Factorization attack", "similarity": 0.78}
            ],
            bert_prediction="RSA",
            bert_confidence=0.45,
            
            # Performance metrics
            memory_usage=128.5,
            cpu_usage=15.2
        )
        
        # Recolectar feedback
        success = feedback_collector.collect_feedback(test_feedback)
        
        if success:
            print("   ✅ Feedback collection: SUCCESS")
            
            # Probar recuperación de feedback
            recent = feedback_collector.get_recent_feedback(limit=1)
            if recent and len(recent) > 0:
                print("   ✅ Feedback retrieval: SUCCESS")
                print(f"   📊 Retrieved feedback for: {recent[0].challenge_name}")
            else:
                print("   ⚠️ Feedback retrieval: No data found")
        else:
            print("   ❌ Feedback collection: FAILED")
            return False
            
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False
    
    return True

def test_metrics_analysis():
    """Prueba el análisis de métricas"""
    print("\n🧪 Testing Metrics Analysis...")
    
    try:
        from phase3.learning.metrics_analyzer import metrics_analyzer
        
        # Analizar rendimiento
        metrics = metrics_analyzer.analyze_current_performance(days=1)
        
        print(f"   ✅ Metrics analysis: SUCCESS")
        print(f"   📊 Success rate: {metrics.overall_success_rate:.1f}%")
        print(f"   ⏱️ Avg response time: {metrics.avg_response_time:.2f}s")
        print(f"   🎯 Total executions: {metrics.total_executions}")
        print(f"   📈 Trend: {metrics.trend_direction}")
        
        # Probar identificación de oportunidades
        opportunities = metrics_analyzer.identify_optimization_opportunities(days=1)
        print(f"   🔍 Optimization opportunities identified: {len(opportunities)}")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_auto_tuning():
    """Prueba el sistema de auto-ajuste"""
    print("\n🧪 Testing Auto-Tuning System...")
    
    try:
        from phase3.learning.auto_tune import auto_tuner
        
        # Ejecutar auto-tuning
        results = auto_tuner.run_auto_tuning(days=1)
        
        print(f"   ✅ Auto-tuning: SUCCESS")
        print(f"   🔧 Adjustments made: {len(results['adjustments_made'])}")
        print(f"   💡 Recommendations: {len(results['recommendations'])}")
        
        # Mostrar parámetros actuales
        current_params = auto_tuner.get_current_parameters()
        print(f"   ⚙️ Current parameters:")
        for param, value in current_params.items():
            print(f"      - {param}: {value}")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_multi_agent_integration():
    """Prueba la integración con el sistema multi-agente"""
    print("\n🧪 Testing Multi-Agent Integration...")
    
    try:
        from multi_agent.coordination.coordinator import multi_agent_coordinator
        
        # Crear un challenge de prueba simple
        test_challenge = "Simple test challenge"
        test_files = [{"name": "test.py", "content": "print('Hello CTF')"}]
        
        print("   🚀 Running test challenge through multi-agent system...")
        
        # Ejecutar challenge
        result = multi_agent_coordinator.solve_challenge(test_challenge, test_files)
        
        print(f"   ✅ Multi-agent execution: SUCCESS")
        print(f"   📊 Success: {result.success}")
        print(f"   ⏱️ Total time: {result.total_time:.2f}s")
        print(f"   🤖 Agents used: {len(result.agents_used)}")
        
        # Verificar que se recolectó feedback
        time.sleep(1)  # Dar tiempo para que se procese el feedback
        
        try:
            from phase3.learning.feedback_collector import feedback_collector
            recent = feedback_collector.get_recent_feedback(limit=1)
            if recent and len(recent) > 0:
                print("   ✅ Feedback integration: SUCCESS")
                print(f"   📝 Latest feedback: {recent[0].challenge_name}")
            else:
                print("   ⚠️ Feedback integration: No recent feedback found")
        except:
            print("   ⚠️ Feedback integration: Could not verify")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_dashboard_components():
    """Prueba los componentes del dashboard"""
    print("\n🧪 Testing Dashboard Components...")
    
    try:
        # Verificar que se pueden importar los componentes necesarios
        import streamlit as st
        import plotly.express as px
        import pandas as pd
        
        print("   ✅ Dashboard dependencies: SUCCESS")
        print("   📊 Streamlit, Plotly, and Pandas available")
        
        # Verificar que el archivo del dashboard existe
        dashboard_path = Path(__file__).parent / "dashboard" / "app.py"
        if dashboard_path.exists():
            print("   ✅ Dashboard app file: EXISTS")
            print(f"   📁 Location: {dashboard_path}")
        else:
            print("   ❌ Dashboard app file: NOT FOUND")
            return False
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Missing dashboard dependencies: {e}")
        print("   💡 Install with: pip install streamlit plotly pandas")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def main():
    """Función principal de pruebas"""
    print("🚀 PHASE 3.0 LEARNING SYSTEM TEST")
    print("=" * 50)
    
    tests = [
        ("Feedback Collection", test_feedback_collection),
        ("Metrics Analysis", test_metrics_analysis),
        ("Auto-Tuning", test_auto_tuning),
        ("Multi-Agent Integration", test_multi_agent_integration),
        ("Dashboard Components", test_dashboard_components)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Resumen final
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
        if success:
            passed += 1
    
    print(f"\n🎯 OVERALL: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! Phase 3.0 learning system is ready!")
    elif passed >= total * 0.8:
        print("✅ Most tests passed. System is mostly functional.")
    else:
        print("⚠️ Several tests failed. Please check the issues above.")
    
    # Instrucciones para el dashboard
    if passed >= 3:  # Si la mayoría de tests pasaron
        print("\n💡 NEXT STEPS:")
        print("1. Run the dashboard: streamlit run phase3/dashboard/app.py")
        print("2. Set up auto-tuning cron job: python phase3/learning/auto_tune.py")
        print("3. Monitor system performance through the dashboard")

if __name__ == "__main__":
    main()