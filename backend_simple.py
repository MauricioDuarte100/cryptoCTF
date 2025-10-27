#!/usr/bin/env python3
"""
Simple Production Backend
Backend simplificado que funciona inmediatamente
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import time
import asyncio
from datetime import datetime
from pathlib import Path
import sys
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Añadir paths
sys.path.append('.')

# Modelos
class ChallengeFile(BaseModel):
    name: str
    content: str

class SolveRequest(BaseModel):
    description: str
    files: List[ChallengeFile]
    timeout: int = 30

class SolveResponse(BaseModel):
    success: bool
    flag: Optional[str] = None
    challenge_type: Optional[str] = None
    time_taken: float = 0.0
    strategy: Optional[str] = None
    error: Optional[str] = None
    timestamp: str

# FastAPI app
app = FastAPI(
    title="CTF Solver Simple API",
    description="Simple CTF Challenge Solver API",
    version="1.0.0"
)

# CORS
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
simple_solver = None

# Inicializar solver
def initialize_solver():
    """Inicializa el solver simple"""
    global simple_solver
    
    try:
        from solve_simple import solve_ctf_challenge
        simple_solver = solve_ctf_challenge
        logger.info("✅ Simple Solver loaded")
        return True
    except Exception as e:
        logger.error(f"❌ Simple Solver failed: {e}")
        return False

@app.on_event("startup")
async def startup_event():
    """Inicializa el sistema"""
    logger.info("🚀 Starting Simple CTF Solver API")
    success = initialize_solver()
    if success:
        logger.info("✅ API ready for requests")
    else:
        logger.warning("⚠️ API started but solver not available")

@app.get("/")
async def root():
    """Endpoint raíz"""
    return {
        "message": "CTF Solver Simple API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "solver_available": simple_solver is not None
    }

@app.get("/health")
async def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime": str(datetime.now() - start_time),
        "solver_available": simple_solver is not None
    }

@app.get("/api/status")
async def get_system_status():
    """Estado del sistema"""
    total_requests = len(solve_history)
    successful_solves = len([h for h in solve_history if h.get('success')])
    success_rate = successful_solves / max(total_requests, 1)
    average_time = sum(h.get('time_taken', 0) for h in solve_history) / max(total_requests, 1)
    
    return {
        "status": "operational" if simple_solver else "degraded",
        "uptime": str(datetime.now() - start_time),
        "total_requests": total_requests,
        "successful_solves": successful_solves,
        "success_rate": success_rate,
        "average_time": average_time,
        "solver_available": simple_solver is not None
    }

async def solve_with_timeout(solver_func, file_path: str, timeout: int = 30):
    """Ejecuta solver con timeout"""
    try:
        task = asyncio.create_task(asyncio.to_thread(solver_func, file_path))
        result = await asyncio.wait_for(task, timeout=timeout)
        return result, None
    except asyncio.TimeoutError:
        return None, f"Solver timed out after {timeout}s"
    except Exception as e:
        return None, str(e)

@app.post("/api/solve", response_model=SolveResponse)
async def solve_challenge(request: SolveRequest):
    """Resuelve un challenge"""
    start_time_solve = time.time()
    
    logger.info(f"🎯 Solving: {request.description[:50]}...")
    
    if not simple_solver:
        return SolveResponse(
            success=False,
            error="Solver not available",
            time_taken=0.0,
            strategy="None",
            timestamp=datetime.now().isoformat()
        )
    
    if not request.files:
        return SolveResponse(
            success=False,
            error="No files provided",
            time_taken=0.0,
            strategy="None",
            timestamp=datetime.now().isoformat()
        )
    
    try:
        # Crear archivo temporal
        temp_file = Path(f"temp_challenge_{int(time.time())}.py")
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(request.files[0].content)
        
        # Resolver con timeout
        result, error = await solve_with_timeout(
            simple_solver, str(temp_file), timeout=request.timeout
        )
        
        # Limpiar archivo temporal
        if temp_file.exists():
            temp_file.unlink()
        
        time_taken = time.time() - start_time_solve
        
        if result:
            response = SolveResponse(
                success=True,
                flag=result,
                challenge_type="Auto-detected",
                time_taken=time_taken,
                strategy="Simple Solver",
                timestamp=datetime.now().isoformat()
            )
            
            # Guardar en historial
            solve_history.append({
                "timestamp": datetime.now().isoformat(),
                "description": request.description,
                "success": True,
                "flag": result,
                "time_taken": time_taken
            })
            
            logger.info(f"✅ Success: {result}")
            return response
        else:
            response = SolveResponse(
                success=False,
                error=error or "Solver returned no result",
                time_taken=time_taken,
                strategy="Simple Solver",
                timestamp=datetime.now().isoformat()
            )
            
            # Guardar en historial
            solve_history.append({
                "timestamp": datetime.now().isoformat(),
                "description": request.description,
                "success": False,
                "error": error,
                "time_taken": time_taken
            })
            
            logger.warning(f"❌ Failed: {error}")
            return response
            
    except Exception as e:
        time_taken = time.time() - start_time_solve
        error_msg = str(e)
        
        logger.error(f"💥 Error: {e}")
        
        return SolveResponse(
            success=False,
            error=error_msg,
            time_taken=time_taken,
            strategy="Error",
            timestamp=datetime.now().isoformat()
        )

@app.get("/api/history")
async def get_solve_history(limit: int = 20):
    """Historial de soluciones"""
    recent_history = solve_history[-limit:] if len(solve_history) > limit else solve_history
    return {
        "success": True,
        "history": recent_history,
        "total": len(solve_history)
    }

@app.get("/api/statistics")
async def get_statistics():
    """Estadísticas del sistema"""
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
    
    return {
        "success": True,
        "statistics": {
            "total_requests": total,
            "successful_solves": successful,
            "success_rate": success_rate,
            "average_time": avg_time,
            "uptime": str(datetime.now() - start_time)
        }
    }

# Test endpoint
@app.post("/api/test")
async def test_solver():
    """Test del solver con challenge simple"""
    test_request = SolveRequest(
        description="Test Caesar cipher",
        files=[ChallengeFile(
            name="test.py",
            content='encrypted = "synt{pnrfne_pvcure_vf_rnfl_gb_oernx}"'
        )]
    )
    
    return await solve_challenge(test_request)

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting Simple CTF Solver API")
    print("=" * 40)
    print("📍 URL: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🧪 Test: http://localhost:8000/api/test")
    print("=" * 40)
    
    uvicorn.run(
        "backend_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )