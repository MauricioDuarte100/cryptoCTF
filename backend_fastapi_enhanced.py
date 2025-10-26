#!/usr/bin/env python3
"""
ENHANCED FastAPI Backend
Backend integrado con BERT y RAG mejorados + sistema multi-agente
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import time
from datetime import datetime
from pathlib import Path
import sys

# Añadir paths necesarios
sys.path.append('.')
sys.path.append('multi_agent')
sys.path.append('ml_phase2')
sys.path.append('rag')

# Importar componentes mejorados
try:
    from multi_agent.coordination.coordinator_enhanced import get_enhanced_coordinator
    ENHANCED_COORDINATOR_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Enhanced coordinator not available: {e}")
    ENHANCED_COORDINATOR_AVAILABLE = False
    # Fallback al solver simple
    try:
        from solve_simple import solve_ctf_challenge
        SIMPLE_SOLVER_AVAILABLE = True
    except ImportError:
        SIMPLE_SOLVER_AVAILABLE = False

try:
    from ml_phase2.bert_classifier_enhanced import get_bert_classifier
    BERT_ENHANCED_AVAILABLE = True
except ImportError:
    BERT_ENHANCED_AVAILABLE = False

try:
    from rag.rag_engine_enhanced import get_enhanced_rag_engine
    RAG_ENHANCED_AVAILABLE = True
except ImportError:
    RAG_ENHANCED_AVAILABLE = False

# Modelos Pydantic
class ChallengeFile(BaseModel):
    name: str
    content: str

class SolveRequest(BaseModel):
    description: str
    files: List[ChallengeFile]
    host: Optional[str] = None
    port: Optional[int] = None
    use_enhanced: bool = True

class SolveResponse(BaseModel):
    success: bool
    flag: Optional[str] = None
    challenge_type: Optional[str] = None
    confidence: float = 0.0
    time_taken: float = 0.0
    strategy: Optional[str] = None
    agents_used: List[str] = []
    rag_context: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    enhanced_features: Dict[str, bool] = {}

class SystemStatus(BaseModel):
    status: str
    components: Dict[str, bool]
    capabilities: List[str]
    statistics: Dict[str, Any]

# Inicializar FastAPI
app = FastAPI(
    title="Enhanced CTF Solver API",
    description="Advanced Multi-Agent CTF Challenge Solver with BERT + RAG",
    version="3.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Variables globales
enhanced_coordinator = None
bert_classifier = None
rag_engine = None
solve_history = []

@app.on_event("startup")
async def startup_event():
    """Inicializa componentes al arrancar"""
    global enhanced_coordinator, bert_classifier, rag_engine
    
    print("🚀 Starting Enhanced CTF Solver API")
    print("=" * 50)
    
    # Inicializar coordinador mejorado
    if ENHANCED_COORDINATOR_AVAILABLE:
        try:
            enhanced_coordinator = get_enhanced_coordinator()
            print("✅ Enhanced Multi-Agent Coordinator loaded")
        except Exception as e:
            print(f"⚠️ Could not load enhanced coordinator: {e}")
    
    # Inicializar BERT mejorado
    if BERT_ENHANCED_AVAILABLE:
        try:
            bert_classifier = get_bert_classifier()
            print("✅ Enhanced BERT Classifier loaded")
        except Exception as e:
            print(f"⚠️ Could not load enhanced BERT: {e}")
    
    # Inicializar RAG mejorado
    if RAG_ENHANCED_AVAILABLE:
        try:
            rag_engine = get_enhanced_rag_engine()
            print("✅ Enhanced RAG Engine loaded")
        except Exception as e:
            print(f"⚠️ Could not load enhanced RAG: {e}")
    
    print("=" * 50)
    print("🎯 Enhanced API ready for requests")

@app.get("/", response_model=Dict[str, str])
async def root():
    """Endpoint raíz"""
    return {
        "message": "Enhanced CTF Solver API v3.0",
        "status": "operational",
        "features": "Multi-Agent + Enhanced BERT + RAG",
        "docs": "/docs"
    }

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Obtiene el estado del sistema"""
    components = {
        "enhanced_coordinator": enhanced_coordinator is not None,
        "bert_classifier": bert_classifier is not None,
        "rag_engine": rag_engine is not None,
        "simple_solver_fallback": SIMPLE_SOLVER_AVAILABLE
    }
    
    capabilities = []
    if enhanced_coordinator:
        coordinator_status = enhanced_coordinator.get_system_status()
        capabilities.extend(coordinator_status.get('capabilities', []))
    
    if bert_classifier:
        capabilities.append("Enhanced BERT Classification")
    
    if rag_engine:
        capabilities.append("Enhanced RAG Context")
    
    if SIMPLE_SOLVER_AVAILABLE:
        capabilities.append("Simple Solver Fallback")
    
    # Estadísticas
    statistics = {
        "total_requests": len(solve_history),
        "successful_solves": len([h for h in solve_history if h.get('success')]),
        "average_time": sum(h.get('time_taken', 0) for h in solve_history) / max(len(solve_history), 1),
        "uptime": "running"
    }
    
    if rag_engine:
        rag_stats = rag_engine.get_statistics()
        if rag_stats.get('available'):
            statistics['rag_writeups'] = rag_stats.get('writeups_count', 0)
    
    status = "operational" if any(components.values()) else "degraded"
    
    return SystemStatus(
        status=status,
        components=components,
        capabilities=capabilities,
        statistics=statistics
    )

@app.post("/api/solve", response_model=SolveResponse)
async def solve_challenge(request: SolveRequest):
    """Resuelve un challenge CTF"""
    start_time = time.time()
    
    print(f"\n🎯 New solve request: {request.description[:50]}...")
    print(f"   Files: {len(request.files)}")
    print(f"   Enhanced mode: {request.use_enhanced}")
    
    try:
        # Preparar archivos
        files = [{
            'name': f.name,
            'content': f.content
        } for f in request.files]
        
        result = None
        
        # Intentar con sistema mejorado primero
        if request.use_enhanced and enhanced_coordinator:
            print("🚀 Using Enhanced Multi-Agent System")
            try:
                result = enhanced_coordinator.solve_challenge(request.description, files)
                
                response = SolveResponse(
                    success=result.success,
                    flag=result.flag,
                    challenge_type=result.classification,
                    confidence=result.confidence,
                    time_taken=result.time_taken,
                    strategy=result.strategy,
                    agents_used=result.agents_used,
                    rag_context=result.rag_context,
                    error=result.error,
                    enhanced_features={
                        "multi_agent": True,
                        "enhanced_bert": bert_classifier is not None,
                        "enhanced_rag": rag_engine is not None
                    }
                )
                
            except Exception as e:
                print(f"⚠️ Enhanced system error: {e}")
                result = None
        
        # Fallback al solver simple
        if result is None and SIMPLE_SOLVER_AVAILABLE:
            print("🔧 Using Simple Solver Fallback")
            try:
                # Crear archivo temporal para el solver simple
                temp_file = Path("temp_challenge.py")
                if files:
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        f.write(files[0]['content'])
                    
                    flag = solve_ctf_challenge(str(temp_file))
                    
                    # Limpiar archivo temporal
                    if temp_file.exists():
                        temp_file.unlink()
                    
                    end_time = time.time()
                    
                    response = SolveResponse(
                        success=bool(flag),
                        flag=flag,
                        challenge_type="Unknown",
                        confidence=0.8 if flag else 0.0,
                        time_taken=end_time - start_time,
                        strategy="Simple Solver",
                        agents_used=["simple_solver"],
                        enhanced_features={
                            "multi_agent": False,
                            "enhanced_bert": False,
                            "enhanced_rag": False,
                            "simple_fallback": True
                        }
                    )
                    
                else:
                    raise ValueError("No files provided for simple solver")
                    
            except Exception as e:
                print(f"⚠️ Simple solver error: {e}")
                response = SolveResponse(
                    success=False,
                    error=f"All solvers failed: {str(e)}",
                    time_taken=time.time() - start_time,
                    enhanced_features={"error": True}
                )
        
        elif result is None:
            response = SolveResponse(
                success=False,
                error="No solvers available",
                time_taken=time.time() - start_time,
                enhanced_features={"no_solvers": True}
            )
        
        # Guardar en historial
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "description": request.description,
            "success": response.success,
            "flag": response.flag,
            "challenge_type": response.challenge_type,
            "time_taken": response.time_taken,
            "strategy": response.strategy,
            "enhanced_used": request.use_enhanced
        }
        solve_history.append(history_entry)
        
        # Limitar historial a últimas 100 entradas
        if len(solve_history) > 100:
            solve_history.pop(0)
        
        print(f"✅ Request completed: {response.success} in {response.time_taken:.2f}s")
        return response
        
    except Exception as e:
        error_response = SolveResponse(
            success=False,
            error=str(e),
            time_taken=time.time() - start_time,
            enhanced_features={"critical_error": True}
        )
        
        print(f"❌ Critical error: {e}")
        return error_response

@app.post("/api/classify")
async def classify_challenge(request: SolveRequest):
    """Clasifica un challenge sin resolverlo"""
    try:
        if bert_classifier:
            challenge_data = {
                'description': request.description,
                'files': [{'content': f.content} for f in request.files]
            }
            
            predicted_type, confidence = bert_classifier.classify(challenge_data)
            
            return {
                "success": True,
                "challenge_type": predicted_type,
                "confidence": confidence,
                "method": "Enhanced BERT"
            }
        else:
            return {
                "success": False,
                "error": "BERT classifier not available",
                "method": "None"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/api/rag/search")
async def search_writeups(query: str, n_results: int = 5, attack_type: Optional[str] = None):
    """Busca writeups similares usando RAG"""
    try:
        if rag_engine:
            results = rag_engine.retrieve_similar_writeups(
                query=query,
                n_results=n_results,
                attack_type=attack_type
            )
            
            return {
                "success": True,
                "results": results,
                "total": len(results)
            }
        else:
            return {
                "success": False,
                "error": "RAG engine not available"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/api/history")
async def get_solve_history(limit: int = 20):
    """Obtiene el historial de challenges resueltos"""
    try:
        recent_history = solve_history[-limit:] if len(solve_history) > limit else solve_history
        return {
            "success": True,
            "history": recent_history,
            "total": len(solve_history)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/api/statistics")
async def get_statistics():
    """Obtiene estadísticas detalladas del sistema"""
    try:
        stats = {
            "total_requests": len(solve_history),
            "successful_solves": len([h for h in solve_history if h.get('success')]),
            "success_rate": 0.0,
            "average_time": 0.0,
            "challenge_types": {},
            "strategies_used": {},
            "recent_performance": []
        }
        
        if stats["total_requests"] > 0:
            stats["success_rate"] = stats["successful_solves"] / stats["total_requests"]
            stats["average_time"] = sum(h.get('time_taken', 0) for h in solve_history) / stats["total_requests"]
        
        # Análisis por tipo de challenge
        for entry in solve_history:
            challenge_type = entry.get('challenge_type', 'Unknown')
            if challenge_type not in stats["challenge_types"]:
                stats["challenge_types"][challenge_type] = {"total": 0, "successful": 0}
            
            stats["challenge_types"][challenge_type]["total"] += 1
            if entry.get('success'):
                stats["challenge_types"][challenge_type]["successful"] += 1
        
        # Análisis por estrategia
        for entry in solve_history:
            strategy = entry.get('strategy', 'Unknown')
            if strategy not in stats["strategies_used"]:
                stats["strategies_used"][strategy] = {"total": 0, "successful": 0}
            
            stats["strategies_used"][strategy]["total"] += 1
            if entry.get('success'):
                stats["strategies_used"][strategy]["successful"] += 1
        
        # Performance reciente (últimos 10)
        recent = solve_history[-10:] if len(solve_history) > 10 else solve_history
        stats["recent_performance"] = [
            {
                "timestamp": entry.get('timestamp'),
                "success": entry.get('success'),
                "time_taken": entry.get('time_taken', 0),
                "challenge_type": entry.get('challenge_type')
            }
            for entry in recent
        ]
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
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
            "size": len(content)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting Enhanced CTF Solver API Server")
    print("=" * 50)
    print("📍 URL: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🔧 Admin: http://localhost:8000/redoc")
    print("=" * 50)
    
    uvicorn.run(
        "backend_fastapi_enhanced:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )