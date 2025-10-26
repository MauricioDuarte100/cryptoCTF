"""
Agente CTF Crypto usando Gemini 2.5 Flash + LangGraph
100% GRATIS - Sin necesidad de Claude/OpenAI
"""

import os
from typing import TypedDict, Annotated, Sequence
from operator import add
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from ..tools.tools import ALL_TOOLS
from .prompts import MASTER_SYSTEM_PROMPT
from ..config.config import config

# Cargar variables de entorno
load_dotenv()

# ============ DEFINIR ESTADO DEL AGENTE ============

class CTFAgentState(TypedDict):
    """Estado del agente CTF"""
    messages: Annotated[Sequence[BaseMessage], add]
    challenge_description: str
    files: list[dict]
    nc_host: str
    nc_port: int
    challenge_type: str
    confidence: float
    parameters_extracted: dict
    flag: str
    solution_steps: list[str]
    remaining_steps: int

# ============ CONFIGURAR GEMINI ============

def create_gemini_model():
    """Crea instancia de Gemini 2.5 Flash con tools"""
    
    # Verificar API key
    if not config.GOOGLE_API_KEY:
        raise ValueError(
            "GOOGLE_API_KEY not found! "
            "Get your free key at: https://aistudio.google.com/apikey"
        )
    
    # Crear modelo Gemini
    llm = ChatGoogleGenerativeAI(
        model=config.GEMINI_MODEL,
        temperature=config.GEMINI_TEMPERATURE,
        google_api_key=config.GOOGLE_API_KEY,
        convert_system_message_to_human=True,  # Gemini maneja system messages así
    )
    
    # Bind tools al modelo
    llm_with_tools = llm.bind_tools(ALL_TOOLS)
    
    return llm_with_tools

# ============ NODOS DEL GRAFO ============

def agent_node(state: CTFAgentState) -> dict:
    """
    Nodo principal: Gemini decide qué hacer
    """
    llm = create_gemini_model()
    
    # Si es la primera iteración, crear mensaje inicial
    if not state["messages"]:
        initial_message = HumanMessage(
            content=f"""{MASTER_SYSTEM_PROMPT}

---

NUEVO DESAFÍO CTF:

Descripción: {state['challenge_description']}

Archivos proporcionados: {len(state['files'])} archivo(s)
{chr(10).join(f"  - {f['name']}" for f in state['files'])}

Conexión Netcat: {state['nc_host']}:{state['nc_port'] if state['nc_port'] else 'N/A'}

---

Procede con la Metodología Sistemática. Comienza con PASO 1: RECONOCIMIENTO INICIAL.
"""
        )
        
        messages = [initial_message]
    else:
        messages = state["messages"]
    
    # Gemini procesa y decide
    response = llm.invoke(messages)
    
    # Decrementar steps restantes
    remaining = state.get("remaining_steps", config.MAX_ITERATIONS) - 1
    
    return {
        "messages": [response],
        "remaining_steps": remaining
    }

def tool_node(state: CTFAgentState) -> dict:
    """
    Nodo de ejecución de herramientas
    """
    last_message = state["messages"][-1]
    
    # Ejecutar todos los tool calls
    tool_messages = []
    new_steps = list(state.get("solution_steps", []))
    
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            try:
                # Buscar la herramienta por nombre
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                
                # Encontrar la función de herramienta
                tool_func = None
                for tool in ALL_TOOLS:
                    if hasattr(tool, 'name') and tool.name == tool_name:
                        tool_func = tool
                        break
                    elif hasattr(tool, '__name__') and tool.__name__ == tool_name:
                        tool_func = tool
                        break
                
                if tool_func:
                    tool_result = tool_func.invoke(tool_args) if hasattr(tool_func, 'invoke') else tool_func(**tool_args)
                else:
                    tool_result = {"error": f"Tool {tool_name} not found", "success": False}
                
            except Exception as e:
                tool_result = {"error": str(e), "success": False}
            
            # Crear mensaje de resultado
            tool_messages.append(
                ToolMessage(
                    content=str(tool_result),
                    tool_call_id=tool_call.get("id", "unknown")
                )
            )
            
            # Documentar paso
            new_steps.append(f"Executed: {tool_name} with args: {tool_args}")
            
            # Actualizar estado según herramienta
            if tool_name == "classify_crypto" and isinstance(tool_result, dict):
                state["challenge_type"] = tool_result.get("type", "Unknown")
                state["confidence"] = tool_result.get("confidence", 0.0)
            
            # Buscar flag en resultados
            if isinstance(tool_result, dict) and "flag" in tool_result and tool_result["flag"]:
                state["flag"] = tool_result["flag"]
    
    return {
        "messages": tool_messages,
        "solution_steps": new_steps
    }

def should_continue(state: CTFAgentState) -> str:
    """
    Decide si continuar iterando o terminar
    """
    last_message = state["messages"][-1]
    
    # Si encontramos la flag, terminar
    if state.get("flag"):
        return "end"
    
    # Si no quedan steps, terminar (anti-loop)
    if state.get("remaining_steps", 0) <= 0:
        return "end"
    
    # Si el último mensaje tiene tool calls, ejecutar tools
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        return "continue"
    
    # Si no hay tool calls, terminar
    return "end"

# ============ CONSTRUIR GRAFO ============

def create_ctf_agent():
    """Construye el grafo del agente"""
    
    workflow = StateGraph(CTFAgentState)
    
    # Añadir nodos
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", tool_node)
    
    # Definir flujo
    workflow.set_entry_point("agent")
    
    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "continue": "tools",
            "end": END
        }
    )
    
    workflow.add_edge("tools", "agent")
    
    return workflow.compile()

# ============ FUNCIÓN PRINCIPAL ============

def solve_ctf_challenge(
    description: str,
    files: list[dict] = None,
    nc_host: str = "",
    nc_port: int = 0,
    max_steps: int = 15
) -> dict:
    """
    Resuelve un desafío CTF crypto
    
    Args:
        description: Descripción del desafío
        files: Lista de archivos [{name: str, content: str}]
        nc_host: Host para netcat (opcional)
        nc_port: Puerto para netcat (opcional)
        max_steps: Máximo de iteraciones
    
    Returns:
        Dict con resultado final
    """
    
    # Crear agente
    agent = create_ctf_agent()
    
    # Estado inicial
    initial_state = {
        "messages": [],
        "challenge_description": description,
        "files": files or [],
        "nc_host": nc_host,
        "nc_port": nc_port,
        "challenge_type": "Unknown",
        "confidence": 0.0,
        "parameters_extracted": {},
        "flag": "",
        "solution_steps": [],
        "remaining_steps": max_steps
    }
    
    # Ejecutar agente
    try:
        final_state = agent.invoke(initial_state)
        
        return {
            "success": bool(final_state.get("flag")),
            "flag": final_state.get("flag", ""),
            "challenge_type": final_state.get("challenge_type", "Unknown"),
            "confidence": final_state.get("confidence", 0.0),
            "solution_steps": final_state.get("solution_steps", []),
            "total_messages": len(final_state.get("messages", [])),
            "steps_used": max_steps - final_state.get("remaining_steps", 0)
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "flag": "",
            "challenge_type": "Error",
            "confidence": 0.0
        }

# ============ CLI INTERFACE ============

if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="CTF Crypto Solver with Gemini AI")
    parser.add_argument("--description", "-d", required=True, help="Challenge description")
    parser.add_argument("--files", "-f", nargs="+", help="Challenge files to analyze")
    parser.add_argument("--host", help="Netcat host")
    parser.add_argument("--port", type=int, help="Netcat port")
    parser.add_argument("--max-steps", type=int, default=15, help="Max iterations")
    parser.add_argument("--output", "-o", help="Output JSON file")
    
    args = parser.parse_args()
    
    # Cargar archivos
    files = []
    if args.files:
        for file_path in args.files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    files.append({
                        "name": os.path.basename(file_path),
                        "content": f.read()
                    })
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
    
    # Resolver desafío
    print(f"🚀 Solving CTF challenge with Gemini AI...")
    print(f"📝 Description: {args.description}")
    print(f"📁 Files: {len(files)} file(s)")
    
    result = solve_ctf_challenge(
        description=args.description,
        files=files,
        nc_host=args.host or "",
        nc_port=args.port or 0,
        max_steps=args.max_steps
    )
    
    # Mostrar resultado
    print("\n" + "="*50)
    print("🎯 RESULTADO FINAL")
    print("="*50)
    
    if result["success"]:
        print(f"✅ FLAG ENCONTRADA: {result['flag']}")
        print(f"🔍 Tipo: {result['challenge_type']}")
        print(f"📊 Confianza: {result['confidence']:.2f}")
        print(f"⚡ Pasos usados: {result['steps_used']}")
    else:
        print(f"❌ No se pudo resolver")
        if "error" in result:
            print(f"💥 Error: {result['error']}")
    
    print(f"\n📋 Pasos ejecutados:")
    for i, step in enumerate(result.get("solution_steps", []), 1):
        print(f"  {i}. {step}")
    
    # Guardar resultado
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n💾 Resultado guardado en: {args.output}")