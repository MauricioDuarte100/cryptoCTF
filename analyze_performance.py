#!/usr/bin/env python3
"""
Análisis detallado del rendimiento del agente
Identifica fortalezas y debilidades para mejorar
"""

import sys
from pathlib import Path
import json

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def analyze_benchmark_results():
    """Analiza los resultados del último benchmark"""
    
    print("🔍 Análisis de Rendimiento del Agente")
    print("="*60)
    
    # Buscar el reporte más reciente
    reports = list(Path(".").glob("benchmark_report_*.json"))
    if not reports:
        print("❌ No se encontraron reportes de benchmark")
        print("   Ejecuta: python benchmark.py")
        return False
    
    latest_report = max(reports, key=lambda p: p.stat().st_mtime)
    
    try:
        with open(latest_report, 'r') as f:
            report = json.load(f)
        
        print(f"📄 Analizando: {latest_report.name}")
        print(f"🕐 Timestamp: {report.get('timestamp', 'Unknown')}")
        
        # Análisis general
        total = report.get('total_challenges', 0)
        successful = report.get('successful_challenges', 0)
        success_rate = report.get('success_rate', 0)
        
        print(f"\n🎯 Rendimiento General:")
        print(f"   Desafíos totales: {total}")
        print(f"   Éxitos: {successful}")
        print(f"   Tasa de éxito: {success_rate:.1%}")
        
        # Clasificar rendimiento
        if success_rate >= 0.8:
            grade = "🏆 EXCELENTE"
        elif success_rate >= 0.6:
            grade = "✅ BUENO"
        elif success_rate >= 0.4:
            grade = "⚠️  REGULAR"
        elif success_rate >= 0.2:
            grade = "❌ MALO"
        else:
            grade = "💥 CRÍTICO"
        
        print(f"   Calificación: {grade}")
        
        # Análisis por tipo
        print(f"\n📊 Análisis por Tipo:")
        by_type = report.get('by_type', {})
        
        strengths = []
        weaknesses = []
        
        for crypto_type, stats in by_type.items():
            rate = stats.get('success_rate', 0)
            total_type = stats.get('total', 0)
            successful_type = stats.get('successful', 0)
            
            print(f"   {crypto_type}:")
            print(f"      Tasa: {rate:.1%} ({successful_type}/{total_type})")
            print(f"      Tiempo promedio: {stats.get('avg_time', 0):.2f}s")
            
            if rate >= 0.8:
                strengths.append(crypto_type)
            elif rate <= 0.2:
                weaknesses.append(crypto_type)
        
        # Análisis por dificultad
        print(f"\n🎚️  Análisis por Dificultad:")
        by_difficulty = report.get('by_difficulty', {})
        
        for difficulty, stats in by_difficulty.items():
            rate = stats.get('success_rate', 0)
            total_diff = stats.get('total', 0)
            successful_diff = stats.get('successful', 0)
            
            print(f"   {difficulty}: {rate:.1%} ({successful_diff}/{total_diff})")
        
        # Recomendaciones
        print(f"\n💡 Recomendaciones:")
        
        if strengths:
            print(f"   🏆 Fortalezas (mantener):")
            for strength in strengths:
                print(f"      - {strength}: El agente funciona bien aquí")
        
        if weaknesses:
            print(f"   🔧 Debilidades (mejorar):")
            for weakness in weaknesses:
                print(f"      - {weakness}: Necesita trabajo urgente")
                
                # Sugerencias específicas
                if weakness == "RSA":
                    print(f"         * Verificar integración con RsaCtfTool")
                    print(f"         * Mejorar extracción de parámetros n, e, c")
                    print(f"         * Añadir más ataques RSA especializados")
                elif weakness == "XOR":
                    print(f"         * Mejorar detección de datos hex")
                    print(f"         * Añadir ataques XOR multi-byte")
                    print(f"         * Mejorar análisis de frecuencias")
                elif weakness == "Classical":
                    print(f"         * Añadir más cifrados clásicos")
                    print(f"         * Mejorar detección de patrones")
        
        # Próximos pasos
        print(f"\n🚀 Próximos Pasos para Fase 2.2:")
        
        if success_rate < 0.5:
            print(f"   1. 🔧 PRIORIDAD ALTA: Arreglar herramientas básicas")
            print(f"      - Debuggear por qué fallan los ataques")
            print(f"      - Verificar integración con RsaCtfTool")
            print(f"      - Mejorar extracción de parámetros")
        
        print(f"   2. 📊 Recopilar más datos:")
        print(f"      - Ejecutar benchmark con más desafíos")
        print(f"      - Añadir challenges de diferentes fuentes")
        print(f"      - Objetivo: 50+ desafíos para entrenar ML")
        
        print(f"   3. 🤖 Preparar para ML:")
        print(f"      - Implementar clasificador BERT")
        print(f"      - Entrenar con datos actuales")
        print(f"      - Comparar rendimiento pre/post ML")
        
        # Análisis detallado de fallos
        print(f"\n🔍 Análisis de Fallos:")
        failed_challenges = [
            result for result in report.get('detailed_results', [])
            if not result.get('success', False)
        ]
        
        if failed_challenges:
            print(f"   Desafíos fallidos: {len(failed_challenges)}")
            
            # Agrupar por tipo de error
            error_types = {}
            for challenge in failed_challenges:
                error = challenge.get('error', 'Sin error específico')
                error_short = error[:50] + "..." if len(error) > 50 else error
                
                if error_short not in error_types:
                    error_types[error_short] = []
                error_types[error_short].append(challenge['name'])
            
            for error, challenges in error_types.items():
                print(f"   '{error}': {len(challenges)} desafíos")
                for challenge in challenges[:3]:  # Mostrar solo primeros 3
                    print(f"      - {challenge}")
                if len(challenges) > 3:
                    print(f"      - ... y {len(challenges) - 3} más")
        
        return True
        
    except Exception as e:
        print(f"❌ Error analizando reporte: {e}")
        return False

def main():
    """Función principal"""
    success = analyze_benchmark_results()
    
    if success:
        print(f"\n✅ Análisis completado")
        print(f"💡 Usa estos insights para mejorar el agente en Fase 2.2")
    else:
        print(f"\n❌ Análisis falló")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)