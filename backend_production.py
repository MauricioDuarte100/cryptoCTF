#!/usr/bin/env python3
"""
Production FastAPI Backend
Backend simplificado pero robusto para producción
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import time
import asyncio
from datetime import datetime
from pathlib import Path
import sys
import logging
import traceback

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Añadir paths
sys.path.append('.')

# Modelos Pydantic
class ChallengeFile(BaseModel):
    name: str
    content: str

class SolveRequest(BaseModel):
    description: str
    files: List[ChallengeFile]
    host: Optional[str] = None
    port: Optional[int] = None
    timeout: int = 30

class SolveResponse(BaseModel):
    success: bool
    flag: Optional[str] = None
    challenge_type: Optional[str] = None
    confidence: float = 0.0
    time_taken: float = 0.0
    strategy: Optional[str] = None
    error: Optional[str] = None
    timestamp: str

class SystemStatus(BaseModel):
    status: str
    uptime: str
    total_requests: int
    successful_solves: int
    success_rate: float
    average_time: float
    available_solvers: List[str]

# Inicializar FastAPI
app = FastAPI(
    title="CTF Solver Production API",
    description="Production-ready CTF Challenge Solver",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Variables globales
start_time = datetime.now()
solve_history = []
active_solvers = {}

# Inicializar solvers
def initialize_solvers():
    """Inicializa los solvers disponibles"""
    global active_solvers
    
    logger.info("🚀 Initializing solvers...")
    
    # Simple Solver (siempre disponible)
    try:
        from solve_simple import solve_ctf_challenge
        active_solvers['simple'] = solve_ctf_challenge
        logger.info("✅ Simple Solver loaded")
    except Exception as e:
        logger.error(f"❌ Simple Solver failed: {e}")
    
    # Enhanced Coordinator
    try:
        from multi_agent.coordination.coordinator_enhanced import get_enhanced_coordinator
        active_solvers['enhanced'] = get_enhanced_coordinator()
        logger.info("✅ Enhanced Coordinator loaded")
    except Exception as e:
        logger.warning(f"⚠️ Enhanced Coordinator not available: {e}")
    
    # Multi-Agent
    try:
        from multi_agent.coordination.coordinator import get_coordinator
        active_solvers['multi_agent'] = get_coordinator()
        logger.info("✅ Multi-Agent Coordinator loaded")
    except Exception as e:
        logger.warning(f"⚠️ Multi-Agent not available: {e}")
    
    logger.info(f"🎯 {len(active_solvers)} solvers initialized")

@app.on_event("startup")
async def startup_event():
    """Inicializa el sistema al arrancar"""
    logger.info("🚀 Starting CTF Solver Production API")
    initialize_solvers()
    logger.info("✅ API ready for requests")

@app.get("/")
async def root():
    """Endpoint raíz"""
    return {
        "message": "CTF Solver Production API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "solvers": list(active_solvers.keys())
    }

@app.get("/health")
async def health_check():
    """Health check para load balancers"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime": str(datetime.now() - start_time),
        "solvers": len(active_solvers)
    }

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Obtiene el estado detallado del sistema"""
    uptime = str(datetime.now() - start_time)
    total_requests = len(solve_history)
    successful_solves = len([h for h in solve_history if h.get('success')])
    success_rate = successful_solves / max(total_requests, 1)
    average_time = sum(h.get('time_taken', 0) for h in solve_history) / max(total_requests, 1)
    
    return SystemStatus(
        status="operational" if active_solvers else "degraded",
        uptime=uptime,
        total_requests=total_requests,
        successful_solves=successful_solves,
        success_rate=success_rate,
        average_time=average_time,
        available_solvers=list(active_solvers.keys())
    )

async def solve_with_timeout(solver_func, *args, timeout: int = 30):
    """Ejecuta un solver con timeout"""
    try:
        # Crear una tarea que se puede cancelar
        task = asyncio.create_task(asyncio.to_thread(solver_func, *args))
        result = await asyncio.wait_for(task, timeout=timeout)
        return result, None
    except asyncio.TimeoutError:
        return None, f"Solver timed out after {timeout}s"
    except Exception as e:
        return None, str(e)

@app.post("/api/solve", response_model=SolveResponse)
async def solve_challenge(request: SolveRequest):
    """Resuelve un challenge CTF"""
    start_time_solve = time.time()
    
    logger.info(f"🎯 New solve request: {request.description[:50]}...")
    
    try:
        # Preparar archivos
        files = [{
            'name': f.name,
            'content': f.content
        } for f in request.files]
        
        result = None
        strategy_used = None
        error_msg = None
        
        # Intentar con Enhanced Coordinator primero
        if 'enhanced' in active_solvers:
            logger.info("🚀 Trying Enhanced Coordinator...")
            try:
                coordinator = active_solvers['enhanced']
                result_obj = coordinator.solve_challenge(request.description, files)
                
                if result_obj.success:
                    result = result_obj.flag
                    strategy_used = "Enhanced Coordinator"
                    
                    response = SolveResponse(
                        success=True,
                        flag=result,
                        challenge_type=result_obj.classification,
                        confidence=result_obj.confidence,
                        time_taken=result_obj.time_taken,
                        strategy=strategy_used,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    # Guardar en historial
                    solve_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "description": request.description,
                        "success": True,
                        "flag": result,
                        "strategy": strategy_used,
                        "time_taken": result_obj.time_taken
                    })
                    
                    logger.info(f"✅ Enhanced Coordinator success: {result}")
                    return response
                    
            except Exception as e:
                logger.warning(f"⚠️ Enhanced Coordinator failed: {e}")
                error_msg = str(e)
        
        # Fallback a Simple Solver
        if 'simple' in active_solvers and files:
            logger.info("🔧 Trying Simple Solver...")
            try:
                # Crear archivo temporal
                temp_file = Path(f"temp_challenge_{int(time.time())}.py")
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(files[0]['content'])
                
                # Resolver con timeout
                solver_func = active_solvers['simple']
                result, solve_error = await solve_with_timeout(
                    solver_func, str(temp_file), timeout=request.timeout
                )
                
                # Limpiar archivo temporal
                if temp_file.exists():
                    temp_file.unlink()
                
                if result:
                    strategy_used = "Simple Solver"
                    time_taken = time.time() - start_time_solve
                    
                    response = SolveResponse(
                        success=True,
                        flag=result,
                        challenge_type="Auto-detected",
                        confidence=0.8,
                        time_taken=time_taken,
                        strategy=strategy_used,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    # Guardar en historial
                    solve_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "description": request.description,
                        "success": True,
                        "flag": result,
                        "strategy": strategy_used,
                        "time_taken": time_taken
                    })
                    
                    logger.info(f"✅ Simple Solver success: {result}")
                    return response
                else:
                    error_msg = solve_error or "Simple solver returned no result"
                    
            except Exception as e:
                logger.warning(f"⚠️ Simple Solver failed: {e}")
                error_msg = str(e)
        
        # Si todo falla
        time_taken = time.time() - start_time_solve
        
        response = SolveResponse(
            success=False,
            error=error_msg or "All solvers failed",
            time_taken=time_taken,
            strategy="None (all failed)",
            timestamp=datetime.now().isoformat()
        )
        
        # Guardar en historial
        solve_history.append({
            "timestamp": datetime.now().isoformat(),
            "description": request.description,
            "success": False,
            "error": error_msg,
            "time_taken": time_taken
        })
        
        logger.warning(f"❌ All solvers failed for: {request.description[:50]}")
        return response
        
    except Exception as e:
        time_taken = time.time() - start_time_solve
        error_msg = f"Critical error: {str(e)}"
        
        logger.error(f"💥 Critical error: {e}")
        logger.error(traceback.format_exc())
        
        return SolveResponse(
            success=False,
            error=error_msg,
            time_taken=time_taken,
            strategy="Error",
            timestamp=datetime.now().isoformat()
        )

@app.post("/api/solve/batch")
async def solve_batch_challenges(requests: List[SolveRequest]):
    """Resuelve múltiples challenges en paralelo"""
    logger.info(f"📦 Batch solve request: {len(requests)} challenges")
    
    # Limitar a 10 challenges por batch
    if len(requests) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 challenges per batch")
    
    # Resolver en paralelo
    tasks = [solve_challenge(req) for req in requests]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Procesar resultados
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append({
                "index": i,
                "success": False,
                "error": str(result),
                "timestamp": datetime.now().isoformat()
            })
        else:
            processed_results.append({
                "index": i,
                **result.dict()
            })
    
    successful = len([r for r in processed_results if r.get('success')])
    
    return {
        "success": True,
        "total": len(requests),
        "successful": successful,
        "success_rate": successful / len(requests),
        "results": processed_results,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/history")
async def get_solve_history(limit: int = 20):
    """Obtiene el historial de challenges resueltos"""
    recent_history = solve_history[-limit:] if len(solve_history) > limit else solve_history
    return {
        "success": True,
        "history": recent_history,
        "total": len(solve_history)
    }

@app.get("/api/statistics")
async def get_detailed_statistics():
    """Obtiene estadísticas detalladas"""
    if not solve_history:
        return {
            "success": True,
            "statistics": {
                "total_requests": 0,
                "successful_solves": 0,
                "success_rate": 0.0,
                "average_time": 0.0
            }
        }
    
    total = len(solve_history)
    successful = len([h for h in solve_history if h.get('success')])
    success_rate = successful / total
    avg_time = sum(h.get('time_taken', 0) for h in solve_history) / total
    
    # Estadísticas por estrategia
    strategies = {}
    for entry in solve_history:
        strategy = entry.get('strategy', 'Unknown')
        if strategy not in strategies:
            strategies[strategy] = {"total": 0, "successful": 0}
        strategies[strategy]["total"] += 1
        if entry.get('success'):
            strategies[strategy]["successful"] += 1
    
    # Performance reciente
    recent = solve_history[-10:] if len(solve_history) > 10 else solve_history
    recent_success_rate = len([h for h in recent if h.get('success')]) / len(recent)
    
    return {
        "success": True,
        "statistics": {
            "total_requests": total,
            "successful_solves": successful,
            "success_rate": success_rate,
            "average_time": avg_time,
            "strategies": strategies,
            "recent_success_rate": recent_success_rate,
            "uptime": str(datetime.now() - start_time)
        }
    }

@app.post("/api/upload")
async def upload_challenge_file(file: UploadFile = File(...)):
    """Sube un archivo de challenge"""
    try:
        content = await file.read()
        
        # Intentar decodificar como texto
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            # Si no es texto, convertir a base64
            import base64
            text_content = base64.b64encode(content).decode('utf-8')
        
        return {
            "success": True,
            "filename": file.filename,
            "content": text_content,
            "size": len(content),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )

# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.2f}s")
    
    return response

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting CTF Solver Production API")
    print("=" * 50)
    print("📍 URL: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🔧 Health: http://localhost:8000/health")
    print("=" * 50)
    
    uvicorn.run(
        "backend_production:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disabled for production
        log_level="info",
        access_log=True
    )