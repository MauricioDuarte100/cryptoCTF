"""
FastAPI Backend for Multi-Agent CTF System
Backend profesional para el sistema multi-agente con APIs REST
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uvicorn
import sys
from pathlib import Path
from datetime import datetime, timedelta
import logging
import asyncio
from functools import lru_cache
import time

# Añadir paths necesarios
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Lazy loading de sistemas pesados
_feedback_collector = None
_metrics_analyzer = None
_auto_tuner = None
_multi_agent_coordinator = None
LEARNING_AVAILABLE = None

def get_feedback_collector():
    """Lazy loading del feedback collector"""
    global _feedback_collector
    if _feedback_collector is None:
        try:
            from phase3.learning.feedback_collector import feedback_collector
            _feedback_collector = feedback_collector
        except ImportError as e:
            logger.error(f"Failed to load feedback collector: {e}")
            raise HTTPException(status_code=503, detail="Feedback system not available")
    return _feedback_collector

def get_metrics_analyzer():
    """Lazy loading del metrics analyzer"""
    global _metrics_analyzer
    if _metrics_analyzer is None:
        try:
            from phase3.learning.metrics_analyzer import metrics_analyzer
            _metrics_analyzer = metrics_analyzer
        except ImportError as e:
            logger.error(f"Failed to load metrics analyzer: {e}")
            raise HTTPException(status_code=503, detail="Metrics system not available")
    return _metrics_analyzer

def get_auto_tuner():
    """Lazy loading del auto tuner"""
    global _auto_tuner
    if _auto_tuner is None:
        try:
            from phase3.learning.auto_tune import auto_tuner
            _auto_tuner = auto_tuner
        except ImportError as e:
            logger.error(f"Failed to load auto tuner: {e}")
            raise HTTPException(status_code=503, detail="Auto-tuning system not available")
    return _auto_tuner

def get_multi_agent_coordinator():
    """Lazy loading del coordinador multi-agente"""
    global _multi_agent_coordinator
    if _multi_agent_coordinator is None:
        try:
            from multi_agent.coordination.coordinator import multi_agent_coordinator
            _multi_agent_coordinator = multi_agent_coordinator
        except ImportError as e:
            logger.error(f"Failed to load multi-agent coordinator: {e}")
            raise HTTPException(status_code=503, detail="Multi-agent system not available")
    return _multi_agent_coordinator

def check_learning_availability():
    """Verifica disponibilidad del sistema de aprendizaje"""
    global LEARNING_AVAILABLE
    if LEARNING_AVAILABLE is None:
        try:
            get_feedback_collector()
            get_metrics_analyzer()
            LEARNING_AVAILABLE = True
        except:
            LEARNING_AVAILABLE = False
    return LEARNING_AVAILABLE

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear aplicación FastAPI
app = FastAPI(
    title="Multi-Agent CTF System API",
    description="API profesional para el sistema multi-agente de resolución de CTFs",
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configurar CORS para el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Específico en lugar de "*"
    allow_headers=["*"],
)

# Cache para respuestas frecuentes
@lru_cache(maxsize=128)
def cached_health_check():
    """Health check cacheado"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "learning_system": check_learning_availability(),
        "version": "3.0.0"
    }

# Modelos Pydantic para requests/responses
class ChallengeRequest(BaseModel):
    description: str
    files: List[Dict[str, str]]
    max_execution_time: Optional[int] = 300

class ChallengeResponse(BaseModel):
    success: bool
    flag: Optional[str]
    total_time: float
    agents_used: List[str]
    confidence: float
    quality_score: float
    execution_id: str

class MetricsResponse(BaseModel):
    overall_success_rate: float
    avg_response_time: float
    avg_confidence: float
    total_executions: int
    successful_executions: int
    failed_executions: int
    success_by_type: Dict[str, float]
    time_by_type: Dict[str, float]
    agent_performance: Dict[str, Dict[str, float]]
    trend_direction: str
    trend_strength: float
    recommendations: List[str]

class TuningResponse(BaseModel):
    timestamp: str
    adjustments_made: List[Dict[str, Any]]
    recommendations: List[str]
    performance_impact: Dict[str, Any]

# Endpoints de salud y estado
@app.get("/api/health")
async def health_check():
    """Endpoint de salud del sistema - Ultra rápido"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "learning_system": check_learning_availability(),
        "version": "3.0.0"
    }

@app.get("/api/status")
async def system_status():
    """Estado detallado del sistema - Optimizado"""
    if not check_learning_availability():
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        # Usar lazy loading y límites pequeños para velocidad
        feedback_collector = get_feedback_collector()
        
        # Solo obtener datos mínimos necesarios
        recent_feedback = feedback_collector.get_recent_feedback(limit=5)  # Reducido de 10 a 5
        
        return {
            "system_status": "operational",
            "recent_executions": len(recent_feedback),
            "last_execution": recent_feedback[0].timestamp if recent_feedback else None,
            "agents_status": {
                "planner": "active",
                "executor": "active", 
                "validator": "active",
                "coordinator": "active"
            },
            "quick_stats": True  # Indica que son stats rápidas
        }
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        # Retornar estado básico en caso de error
        return {
            "system_status": "degraded",
            "recent_executions": 0,
            "agents_status": {
                "planner": "unknown",
                "executor": "unknown", 
                "validator": "unknown",
                "coordinator": "unknown"
            },
            "error": str(e)
        }

# Endpoints de ejecución de challenges
@app.post("/api/challenges/solve", response_model=ChallengeResponse)
async def solve_challenge(request: ChallengeRequest, background_tasks: BackgroundTasks):
    """Resuelve un challenge CTF usando el sistema multi-agente"""
    if not check_learning_availability():
        raise HTTPException(status_code=503, detail="Multi-agent system not available")
    
    try:
        logger.info(f"Solving challenge: {request.description[:100]}...")
        
        # Lazy load del coordinador
        coordinator = get_multi_agent_coordinator()
        
        # Ejecutar challenge en background si es muy largo
        if request.max_execution_time and request.max_execution_time > 60:
            # Para challenges largos, ejecutar en background
            execution_id = f"exec_{int(datetime.now().timestamp())}"
            background_tasks.add_task(
                execute_challenge_background,
                coordinator,
                request.description,
                request.files,
                request.max_execution_time,
                execution_id
            )
            
            return ChallengeResponse(
                success=False,
                flag=None,
                total_time=0.0,
                agents_used=[],
                confidence=0.0,
                quality_score=0.0,
                execution_id=execution_id
            )
        else:
            # Ejecutar directamente para challenges rápidos
            result = coordinator.solve_challenge(
                request.description,
                request.files,
                request.max_execution_time or 60  # Límite por defecto
            )
            
            execution_id = f"exec_{int(datetime.now().timestamp())}"
            
            return ChallengeResponse(
                success=result.success,
                flag=result.flag if result.success else None,
                total_time=result.total_time,
                agents_used=result.agents_used,
                confidence=result.confidence,
                quality_score=result.quality_score,
                execution_id=execution_id
            )
        
    except Exception as e:
        logger.error(f"Error solving challenge: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def execute_challenge_background(coordinator, description, files, max_time, execution_id):
    """Ejecuta challenge en background"""
    try:
        result = coordinator.solve_challenge(description, files, max_time)
        logger.info(f"Background challenge {execution_id} completed: {result.success}")
    except Exception as e:
        logger.error(f"Background challenge {execution_id} failed: {e}")

# Endpoints de métricas y análisis
# Cache para métricas (5 minutos)
_metrics_cache = {}
_metrics_cache_time = {}

@app.get("/api/metrics", response_model=MetricsResponse)
async def get_metrics(days: int = 7):
    """Obtiene métricas de rendimiento del sistema - Con cache"""
    if not check_learning_availability():
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    # Verificar cache
    cache_key = f"metrics_{days}"
    current_time = time.time()
    
    if (cache_key in _metrics_cache and 
        cache_key in _metrics_cache_time and 
        current_time - _metrics_cache_time[cache_key] < 300):  # 5 minutos
        return _metrics_cache[cache_key]
    
    try:
        analyzer = get_metrics_analyzer()
        metrics = analyzer.analyze_current_performance(days=days)
        
        response = MetricsResponse(
            overall_success_rate=metrics.overall_success_rate,
            avg_response_time=metrics.avg_response_time,
            avg_confidence=metrics.avg_confidence,
            total_executions=metrics.total_executions,
            successful_executions=metrics.successful_executions,
            failed_executions=metrics.failed_executions,
            success_by_type=metrics.success_by_type,
            time_by_type=metrics.time_by_type,
            agent_performance=metrics.agent_performance,
            trend_direction=metrics.trend_direction,
            trend_strength=metrics.trend_strength,
            recommendations=metrics.recommendations
        )
        
        # Guardar en cache
        _metrics_cache[cache_key] = response
        _metrics_cache_time[cache_key] = current_time
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics/trends")
async def get_performance_trends(days: int = 30):
    """Obtiene tendencias de rendimiento"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        trends = feedback_collector.get_performance_trends(days=days)
        return trends
    except Exception as e:
        logger.error(f"Error getting trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics/errors")
async def get_error_analysis(days: int = 7):
    """Obtiene análisis de errores"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        errors = feedback_collector.get_error_analysis(days=days)
        return errors
    except Exception as e:
        logger.error(f"Error getting error analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de feedback y historial
@app.get("/api/feedback/recent")
async def get_recent_feedback(limit: int = 50):
    """Obtiene feedback reciente"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        feedback = feedback_collector.get_recent_feedback(limit=limit)
        return [f.to_dict() for f in feedback]
    except Exception as e:
        logger.error(f"Error getting recent feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/feedback/success-rates")
async def get_success_rates(days: int = 7):
    """Obtiene tasas de éxito por tipo"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        rates = feedback_collector.get_success_rate_by_type(days=days)
        return rates
    except Exception as e:
        logger.error(f"Error getting success rates: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/feedback/strategy-effectiveness")
async def get_strategy_effectiveness(days: int = 7):
    """Obtiene efectividad de estrategias"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        effectiveness = feedback_collector.get_strategy_effectiveness(days=days)
        return effectiveness
    except Exception as e:
        logger.error(f"Error getting strategy effectiveness: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de auto-tuning
@app.post("/api/tuning/run", response_model=TuningResponse)
async def run_auto_tuning(days: int = 7):
    """Ejecuta el proceso de auto-ajuste"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        results = auto_tuner.run_auto_tuning(days=days)
        
        return TuningResponse(
            timestamp=results['timestamp'],
            adjustments_made=results['adjustments_made'],
            recommendations=results['recommendations'],
            performance_impact=results['performance_impact']
        )
        
    except Exception as e:
        logger.error(f"Error running auto-tuning: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tuning/parameters")
async def get_current_parameters():
    """Obtiene parámetros actuales del sistema"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        parameters = auto_tuner.get_current_parameters()
        return parameters
    except Exception as e:
        logger.error(f"Error getting parameters: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tuning/opportunities")
async def get_optimization_opportunities(days: int = 14):
    """Obtiene oportunidades de optimización"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        opportunities = metrics_analyzer.identify_optimization_opportunities(days=days)
        return opportunities
    except Exception as e:
        logger.error(f"Error getting optimization opportunities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoints de administración
@app.get("/api/admin/stats")
async def get_admin_stats():
    """Estadísticas administrativas del sistema"""
    if not LEARNING_AVAILABLE:
        raise HTTPException(status_code=503, detail="Learning system not available")
    
    try:
        # Obtener estadísticas del coordinador
        coordinator_stats = multi_agent_coordinator.get_performance_stats()
        
        # Obtener métricas recientes
        recent_feedback = feedback_collector.get_recent_feedback(limit=100)
        
        # Calcular estadísticas adicionales
        total_challenges = len(recent_feedback)
        unique_types = len(set(f.challenge_type for f in recent_feedback))
        avg_strategies = sum(f.planner_strategies for f in recent_feedback) / total_challenges if total_challenges > 0 else 0
        
        return {
            "coordinator_stats": coordinator_stats,
            "total_challenges_processed": total_challenges,
            "unique_challenge_types": unique_types,
            "avg_strategies_per_challenge": avg_strategies,
            "system_uptime": "operational",
            "database_status": "connected"
        }
        
    except Exception as e:
        logger.error(f"Error getting admin stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket para updates en tiempo real (futuro)
@app.get("/api/ws/info")
async def websocket_info():
    """Información sobre WebSocket endpoints (para implementación futura)"""
    return {
        "websocket_available": False,
        "planned_endpoints": [
            "/ws/metrics",
            "/ws/executions",
            "/ws/system-status"
        ],
        "note": "WebSocket endpoints will be implemented in future versions"
    }

# Manejo de errores global
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )