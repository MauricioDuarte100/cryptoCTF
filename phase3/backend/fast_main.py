"""
Fast Backend for Multi-Agent CTF System
Backend ultra-optimizado para desarrollo rápido
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uvicorn
import time
from datetime import datetime
import logging

# Configurar logging básico
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear aplicación FastAPI
app = FastAPI(
    title="Multi-Agent CTF System API (Fast)",
    description="API ultra-rápida para desarrollo",
    version="3.0.0-fast",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS optimizado
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Modelos básicos
class ChallengeRequest(BaseModel):
    description: str
    files: List[Dict[str, str]]
    max_execution_time: Optional[int] = 60

class ChallengeResponse(BaseModel):
    success: bool
    flag: Optional[str]
    total_time: float
    agents_used: List[str]
    confidence: float
    quality_score: float
    execution_id: str

# Mock data para desarrollo rápido
MOCK_METRICS = {
    "overall_success_rate": 85.5,
    "avg_response_time": 2.3,
    "avg_confidence": 0.78,
    "total_executions": 42,
    "successful_executions": 36,
    "failed_executions": 6,
    "success_by_type": {
        "RSA": 90.0,
        "Classical": 85.0,
        "XOR": 80.0,
        "Encoding": 95.0
    },
    "time_by_type": {
        "RSA": 3.2,
        "Classical": 1.8,
        "XOR": 2.1,
        "Encoding": 1.2
    },
    "agent_performance": {
        "planner": {"avg_confidence": 0.75, "avg_strategies": 3.2},
        "executor": {"avg_attempts": 2.1, "success_rate": 85.5},
        "validator": {"avg_confidence": 0.82}
    },
    "trend_direction": "improving",
    "trend_strength": 0.15,
    "recommendations": [
        "✅ System performance is stable",
        "📈 Success rate trending upward",
        "🎯 Consider optimizing RSA strategies"
    ]
}

MOCK_RECENT_FEEDBACK = [
    {
        "timestamp": datetime.now().isoformat(),
        "challenge_name": "RSA Small Exponent",
        "challenge_type": "RSA",
        "success": True,
        "total_time": 2.5,
        "confidence": 0.85,
        "agents_used": ["planner", "executor", "validator"]
    },
    {
        "timestamp": datetime.now().isoformat(),
        "challenge_name": "Caesar Cipher",
        "challenge_type": "Classical",
        "success": True,
        "total_time": 1.2,
        "confidence": 0.92,
        "agents_used": ["planner", "executor", "validator"]
    },
    {
        "timestamp": datetime.now().isoformat(),
        "challenge_name": "XOR Challenge",
        "challenge_type": "XOR",
        "success": False,
        "total_time": 3.8,
        "confidence": 0.45,
        "agents_used": ["planner", "executor", "validator"]
    }
]

# Endpoints ultra-rápidos
@app.get("/api/health")
async def health_check():
    """Health check instantáneo"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "learning_system": True,
        "version": "3.0.0-fast",
        "mode": "development"
    }

@app.get("/api/status")
async def system_status():
    """Estado del sistema - Mock rápido"""
    return {
        "system_status": "operational",
        "recent_executions": len(MOCK_RECENT_FEEDBACK),
        "current_success_rate": MOCK_METRICS["overall_success_rate"],
        "avg_response_time": MOCK_METRICS["avg_response_time"],
        "last_execution": MOCK_RECENT_FEEDBACK[0]["timestamp"],
        "agents_status": {
            "planner": "active",
            "executor": "active",
            "validator": "active",
            "coordinator": "active"
        }
    }

@app.post("/api/challenges/solve", response_model=ChallengeResponse)
async def solve_challenge(request: ChallengeRequest):
    """Resolver challenge - Mock rápido"""
    # Simular procesamiento
    await asyncio.sleep(0.1)  # 100ms de "procesamiento"
    
    # Mock response basado en el tipo de challenge
    challenge_type = "Unknown"
    if "rsa" in request.description.lower():
        challenge_type = "RSA"
    elif "caesar" in request.description.lower() or "cipher" in request.description.lower():
        challenge_type = "Classical"
    elif "xor" in request.description.lower():
        challenge_type = "XOR"
    elif "base64" in request.description.lower() or "encode" in request.description.lower():
        challenge_type = "Encoding"
    
    # Simular éxito/fallo
    success = len(request.description) % 3 != 0  # 66% success rate
    
    return ChallengeResponse(
        success=success,
        flag=f"flag{{mock_{challenge_type.lower()}_{int(time.time())}}}" if success else None,
        total_time=round(0.5 + (len(request.description) % 10) * 0.3, 2),
        agents_used=["planner", "executor", "validator"],
        confidence=0.85 if success else 0.45,
        quality_score=0.9 if success else 0.3,
        execution_id=f"exec_{int(time.time())}"
    )

@app.get("/api/metrics")
async def get_metrics(days: int = 7):
    """Métricas - Mock instantáneo"""
    return MOCK_METRICS

@app.get("/api/metrics/trends")
async def get_performance_trends(days: int = 30):
    """Tendencias - Mock"""
    trends = []
    for i in range(min(days, 7)):  # Últimos 7 días
        date = datetime.now().date()
        trends.append({
            "date": str(date),
            "total_executions": 5 + i,
            "successful_executions": 4 + (i % 2),
            "success_rate": 80 + (i * 2),
            "avg_time": 2.0 + (i * 0.1),
            "avg_confidence": 0.75 + (i * 0.02),
            "avg_quality": 0.8 + (i * 0.01)
        })
    
    return {"daily_trends": trends}

@app.get("/api/metrics/errors")
async def get_error_analysis(days: int = 7):
    """Análisis de errores - Mock"""
    return {
        "error_patterns": [
            {
                "errors": ["Tool not found", "Timeout error"],
                "warnings": ["Low confidence"],
                "challenge_type": "RSA",
                "frequency": 3
            },
            {
                "errors": ["Invalid input"],
                "warnings": [],
                "challenge_type": "XOR",
                "frequency": 2
            }
        ]
    }

@app.get("/api/feedback/recent")
async def get_recent_feedback(limit: int = 50):
    """Feedback reciente - Mock"""
    return MOCK_RECENT_FEEDBACK[:limit]

@app.get("/api/feedback/success-rates")
async def get_success_rates(days: int = 7):
    """Tasas de éxito - Mock"""
    return MOCK_METRICS["success_by_type"]

@app.get("/api/feedback/strategy-effectiveness")
async def get_strategy_effectiveness(days: int = 7):
    """Efectividad de estrategias - Mock"""
    return {
        "rsa_factorization_attacks": {
            "RSA": {"usage_count": 15, "avg_time": 2.5, "avg_confidence": 0.85}
        },
        "frequency_analysis": {
            "Classical": {"usage_count": 12, "avg_time": 1.2, "avg_confidence": 0.90}
        },
        "single_byte_bruteforce": {
            "XOR": {"usage_count": 8, "avg_time": 1.8, "avg_confidence": 0.75}
        }
    }

@app.post("/api/tuning/run")
async def run_auto_tuning(days: int = 7):
    """Auto-tuning - Mock"""
    return {
        "timestamp": datetime.now().isoformat(),
        "adjustments_made": [
            {
                "parameter": "rag_threshold",
                "old_value": 0.4,
                "new_value": 0.35,
                "reason": "Improve RAG recall"
            }
        ],
        "recommendations": [
            "🔧 RAG threshold adjusted for better performance",
            "📊 Monitor success rate over next 24 hours"
        ],
        "performance_impact": {
            "expected_success_rate_change": 2.5,
            "expected_response_time_change": 0.1,
            "confidence_level": "medium"
        }
    }

@app.get("/api/tuning/parameters")
async def get_current_parameters():
    """Parámetros actuales - Mock"""
    return {
        "rag_threshold": 0.35,
        "bert_confidence_threshold": 0.5,
        "max_strategies": 5,
        "max_attempts_per_strategy": 3
    }

@app.get("/api/tuning/opportunities")
async def get_optimization_opportunities(days: int = 14):
    """Oportunidades de optimización - Mock"""
    return {
        "threshold_adjustments": [
            {
                "type": "rag_threshold",
                "current": "0.4",
                "recommended": "lower",
                "reason": "High success rate with low patterns"
            }
        ],
        "strategy_improvements": [
            {
                "challenge_type": "RSA",
                "strategies": [{"name": "wiener_attack"}],
                "failure_frequency": 5,
                "recommendation": "Review Wiener attack parameters"
            }
        ],
        "model_retraining": [],
        "performance_issues": []
    }

@app.get("/api/admin/stats")
async def get_admin_stats():
    """Stats administrativas - Mock"""
    return {
        "coordinator_stats": {
            "total_executions": 42,
            "success_rate": 85.5,
            "average_times": {
                "total": 2.3,
                "planner": 0.8,
                "executor": 1.2,
                "validator": 0.3
            },
            "average_confidence": 0.78,
            "average_quality": 0.82,
            "agent_usage": {
                "planner": 42,
                "executor": 42,
                "validator": 42
            }
        },
        "total_challenges_processed": 42,
        "unique_challenge_types": 4,
        "avg_strategies_per_challenge": 3.2,
        "system_uptime": "operational",
        "database_status": "connected"
    }

# Importar asyncio para sleep
import asyncio

if __name__ == "__main__":
    print("🚀 Starting FAST Multi-Agent CTF System Backend...")
    print("⚡ Ultra-optimized for development speed")
    print("🌐 API: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/api/docs")
    
    uvicorn.run(
        "fast_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )