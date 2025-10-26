#!/usr/bin/env python3
"""
Backend Startup Script
Script de inicio para el backend FastAPI
"""

import uvicorn
import sys
import os
from pathlib import Path

# Añadir el directorio raíz al path
root_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(root_dir))

# Configurar variables de entorno
os.environ.setdefault('PYTHONPATH', str(root_dir))

def main():
    """Función principal de inicio"""
    print("🚀 Starting Multi-Agent CTF System Backend...")
    print(f"📁 Root directory: {root_dir}")
    print(f"🌐 API will be available at: http://localhost:8000")
    print(f"📚 API documentation: http://localhost:8000/api/docs")
    print("=" * 60)
    
    # Verificar que el sistema de aprendizaje esté disponible
    try:
        from phase3.learning.feedback_collector import feedback_collector
        print("✅ Learning system: AVAILABLE")
    except ImportError as e:
        print(f"⚠️ Learning system: NOT AVAILABLE ({e})")
    
    try:
        from multi_agent.coordination.coordinator import multi_agent_coordinator
        print("✅ Multi-agent system: AVAILABLE")
    except ImportError as e:
        print(f"⚠️ Multi-agent system: NOT AVAILABLE ({e})")
    
    print("=" * 60)
    
    # Iniciar servidor
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        app_dir=str(Path(__file__).parent)
    )

if __name__ == "__main__":
    main()