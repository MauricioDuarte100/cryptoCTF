"""
Enhanced CTF Agent with Deep Learning Integration
Combines LangGraph agents with neural classifiers, predictors, and RAG.
"""

import os
import time
from typing import TypedDict, Annotated, Sequence, Dict, Any, List
from operator import add
from pathlib import Path

from dotenv import load_dotenv

try:
    from langgraph.graph import StateGraph, END
    from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage
    from langchain_google_genai import ChatGoogleGenerativeAI
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

# Import Deep Learning components
try:
    from ..dl_models.challenge_classifier import get_classifier, RuleBasedClassifier
    from ..dl_models.attack_predictor import get_attack_predictor, RuleBasedAttackPredictor
    HAS_DL_MODELS = True
except ImportError:
    HAS_DL_MODELS = False

try:
    from ..rag.experience_retriever import get_experience_retriever
    from ..rag.challenge_embeddings import ChallengeEmbedder
    HAS_RAG = True
except ImportError:
    HAS_RAG = False

try:
    from ..learning.experience_storage import get_experience_storage, SolvedChallengeExperience
    HAS_EXPERIENCE = True
except ImportError:
    HAS_EXPERIENCE = False

from ..tools.tools import ALL_TOOLS
from ..config.config import config
from ..database.database import get_database

load_dotenv()


class EnhancedCTFAgentState(TypedDict):
    """Enhanced state with Deep Learning context."""
    messages: Annotated[Sequence[BaseMessage], add]
    challenge_description: str
    files: list[dict]
    nc_host: str
    nc_port: int
    
    # Deep Learning enhanced fields
    challenge_type: str
    type_confidence: float
    predicted_attacks: list[str]
    attack_confidence: float
    similar_experiences: list[dict]
    
    # Standard fields
    parameters_extracted: dict
    flag: str
    solution_steps: list[str]
    remaining_steps: int
    
    # New tracking fields
    dl_classification_done: bool
    rag_retrieval_done: bool


class DeepLearningEnhancer:
    """
    Enhances CTF solving with Deep Learning predictions.
    Integrates classifier, predictor, and RAG retrieval.
    """
    
    def __init__(self, 
                 classifier_path: str = None,
                 predictor_path: str = None,
                 retriever_path: str = None):
        """Initialize DL components."""
        self.classifier = None
        self.predictor = None
        self.retriever = None
        self.experience_storage = None
        
        # Initialize classifier
        if HAS_DL_MODELS:
            try:
                self.classifier = get_classifier(classifier_path)
                print("✅ Loaded DL classifier")
            except Exception as e:
                print(f"⚠️ Classifier not available: {e}")
                self.classifier = RuleBasedClassifier()
        else:
            print("⚠️ DL models not available, using rule-based")
            self.classifier = RuleBasedClassifier() if 'RuleBasedClassifier' in dir() else None
        
        # Initialize predictor
        if HAS_DL_MODELS:
            try:
                self.predictor = get_attack_predictor(predictor_path)
                print("✅ Loaded attack predictor")
            except Exception as e:
                print(f"⚠️ Predictor not available: {e}")
                self.predictor = RuleBasedAttackPredictor()
        
        # Initialize RAG retriever
        if HAS_RAG:
            try:
                self.retriever = get_experience_retriever(index_path=retriever_path)
                print("✅ Loaded experience retriever")
            except Exception as e:
                print(f"⚠️ Retriever not available: {e}")
        
        # Initialize experience storage
        if HAS_EXPERIENCE:
            try:
                self.experience_storage = get_experience_storage()
                print("✅ Loaded experience storage")
            except Exception as e:
                print(f"⚠️ Experience storage not available: {e}")
    
    def analyze_challenge(self, description: str, files: List[Dict]) -> Dict[str, Any]:
        """
        Comprehensive challenge analysis using DL.
        
        Returns:
            Dictionary with type, attacks, and similar experiences
        """
        result = {
            "challenge_type": "Unknown",
            "type_confidence": 0.0,
            "predicted_attacks": [],
            "attack_confidence": 0.0,
            "similar_experiences": [],
            "recommendations": []
        }
        
        # 1. Classify challenge
        if self.classifier:
            try:
                classification = self.classifier.classify(description, files)
                result["challenge_type"] = classification.get("challenge_type", "Unknown")
                result["type_confidence"] = classification.get("type_confidence", 0.0)
                result["attack_patterns_from_classifier"] = classification.get("attack_patterns", [])
            except Exception as e:
                print(f"⚠️ Classification failed: {e}")
        
        # 2. Predict attack sequence
        if self.predictor:
            try:
                prediction = self.predictor.predict(
                    description, files, 
                    challenge_type=result["challenge_type"]
                )
                result["predicted_attacks"] = prediction.get("predicted_attacks", [])
                result["attack_confidence"] = prediction.get("total_confidence", 0.0)
            except Exception as e:
                print(f"⚠️ Attack prediction failed: {e}")
        
        # 3. Retrieve similar experiences
        if self.retriever:
            try:
                similar = self.retriever.retrieve_similar(
                    description, files, 
                    challenge_type=result["challenge_type"],
                    k=3
                )
                result["similar_experiences"] = [
                    {
                        "name": s.challenge_name,
                        "type": s.challenge_type,
                        "attack": s.attack_pattern,
                        "similarity": s.similarity_score,
                        "solution_steps": s.solution_steps[:5],
                        "solution_code": s.solution_code[:500] if s.solution_code else ""
                    }
                    for s in similar
                ]
            except Exception as e:
                print(f"⚠️ RAG retrieval failed: {e}")
        
        # 4. Generate recommendations
        result["recommendations"] = self._generate_recommendations(result)
        
        return result
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate solving recommendations based on analysis."""
        recs = []
        
        ctype = analysis.get("challenge_type", "Unknown")
        attacks = analysis.get("predicted_attacks", [])
        similar = analysis.get("similar_experiences", [])
        
        # Type-based recommendations
        type_recs = {
            "RSA": "Try RsaCtfTool or manual factorization attacks",
            "AES": "Check for padding oracle or ECB mode vulnerabilities",
            "XOR": "Try single-byte and repeating key XOR attacks",
            "Classical": "Use frequency analysis or brute-force shifts",
            "Hash": "Check for length extension or collision attacks",
            "Encoding": "Try common encodings (base64, hex, rot13)"
        }
        if ctype in type_recs:
            recs.append(type_recs[ctype])
        
        # Attack-based recommendations
        if attacks:
            recs.append(f"Suggested attack sequence: {' → '.join(attacks[:3])}")
        
        # Similar experience recommendations
        if similar:
            best = similar[0]
            if best["similarity"] > 0.7:
                recs.append(f"Very similar to '{best['name']}' - consider adapting its solution")
            elif best["similarity"] > 0.5:
                recs.append(f"Somewhat similar to '{best['name']}' ({best['attack']})")
        
        return recs
    
    def store_solution(self, 
                      description: str,
                      files: List[Dict],
                      challenge_type: str,
                      flag: str,
                      attack_pattern: str,
                      solution_steps: List[str],
                      solution_code: str = "",
                      solve_time: float = 0.0) -> str:
        """
        Store a successful solution as a new experience.
        This enables continuous learning.
        
        Returns:
            experience_id
        """
        if not self.experience_storage:
            print("⚠️ Experience storage not available")
            return ""
        
        experience = SolvedChallengeExperience(
            challenge_id="",  # Will be generated
            challenge_name=description[:50],
            challenge_description=description,
            challenge_type=challenge_type,
            difficulty="Medium",  # Could be predicted
            source_files=files,
            solution_successful=True,
            flag_found=flag,
            solution_steps=solution_steps,
            attack_pattern=attack_pattern,
            solution_code=solution_code,
            solve_time_seconds=solve_time,
            confidence_score=1.0
        )
        
        exp_id = self.experience_storage.store_experience(experience)
        print(f"✅ Stored experience: {exp_id}")
        
        return exp_id


def create_enhanced_agent():
    """Create LangGraph agent with DL enhancement."""
    if not HAS_LANGGRAPH:
        raise ImportError("LangGraph required for enhanced agent")
    
    # Initialize DL enhancer
    enhancer = DeepLearningEnhancer()
    
    def dl_analysis_node(state: EnhancedCTFAgentState) -> dict:
        """Deep Learning analysis node."""
        if state.get("dl_classification_done"):
            return {}
        
        analysis = enhancer.analyze_challenge(
            state["challenge_description"],
            state["files"]
        )
        
        return {
            "challenge_type": analysis["challenge_type"],
            "type_confidence": analysis["type_confidence"],
            "predicted_attacks": analysis["predicted_attacks"],
            "attack_confidence": analysis["attack_confidence"],
            "similar_experiences": analysis["similar_experiences"],
            "dl_classification_done": True
        }
    
    def create_gemini_model():
        """Create Gemini model with tools."""
        if not config.GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY required")
        
        llm = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            temperature=config.GEMINI_TEMPERATURE,
            google_api_key=config.GOOGLE_API_KEY,
            convert_system_message_to_human=True
        )
        
        return llm.bind_tools(ALL_TOOLS)
    
    def agent_node(state: EnhancedCTFAgentState) -> dict:
        """Main agent node with DL-enhanced context."""
        llm = create_gemini_model()
        
        if not state["messages"]:
            # Build enhanced prompt with DL analysis
            dl_context = ""
            
            if state.get("challenge_type") and state.get("type_confidence", 0) > 0.5:
                dl_context += f"\n🧠 DL Analysis:\n"
                dl_context += f"  - Type: {state['challenge_type']} ({state['type_confidence']:.0%} confidence)\n"
            
            if state.get("predicted_attacks"):
                dl_context += f"  - Suggested attacks: {', '.join(state['predicted_attacks'][:3])}\n"
            
            if state.get("similar_experiences"):
                dl_context += f"  - Similar solved challenges:\n"
                for exp in state["similar_experiences"][:2]:
                    dl_context += f"    * {exp['name']} ({exp['attack']}, {exp['similarity']:.0%} similar)\n"
            
            initial_message = HumanMessage(
                content=f"""You are an expert CTF solver with access to Deep Learning analysis.

{dl_context}

---

NEW CTF CHALLENGE:

Description: {state['challenge_description']}

Files: {len(state['files'])} file(s)
{chr(10).join(f"  - {f['name']}: {f.get('content', '')[:200]}..." for f in state['files'])}

Connection: {state['nc_host']}:{state['nc_port'] if state['nc_port'] else 'N/A'}

---

Use the DL suggestions above as guidance. Start by analyzing the challenge.
"""
            )
            messages = [initial_message]
        else:
            messages = state["messages"]
        
        response = llm.invoke(messages)
        remaining = state.get("remaining_steps", config.MAX_ITERATIONS) - 1
        
        return {
            "messages": [response],
            "remaining_steps": remaining
        }
    
    def tool_node(state: EnhancedCTFAgentState) -> dict:
        """Execute tools."""
        last_message = state["messages"][-1]
        tool_messages = []
        new_steps = list(state.get("solution_steps", []))
        
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            for tool_call in last_message.tool_calls:
                try:
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    
                    tool_func = None
                    for tool in ALL_TOOLS:
                        if hasattr(tool, 'name') and tool.name == tool_name:
                            tool_func = tool
                            break
                    
                    if tool_func:
                        tool_result = tool_func.invoke(tool_args)
                    else:
                        tool_result = {"error": f"Tool {tool_name} not found"}
                    
                except Exception as e:
                    tool_result = {"error": str(e)}
                
                tool_messages.append(
                    ToolMessage(
                        content=str(tool_result),
                        tool_call_id=tool_call.get("id", "unknown")
                    )
                )
                
                new_steps.append(f"Executed: {tool_name}")
                
                # Check for flag
                if isinstance(tool_result, dict) and tool_result.get("flag"):
                    state["flag"] = tool_result["flag"]
        
        return {
            "messages": tool_messages,
            "solution_steps": new_steps
        }
    
    def should_continue(state: EnhancedCTFAgentState) -> str:
        """Decide next step."""
        if state.get("flag"):
            return "store_experience"
        if state.get("remaining_steps", 0) <= 0:
            return "end"
        
        last_message = state["messages"][-1] if state["messages"] else None
        if last_message and hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            return "tools"
        
        return "end"
    
    def store_experience_node(state: EnhancedCTFAgentState) -> dict:
        """Store successful solution as experience."""
        if state.get("flag") and enhancer.experience_storage:
            enhancer.store_solution(
                description=state["challenge_description"],
                files=state["files"],
                challenge_type=state.get("challenge_type", "Unknown"),
                flag=state["flag"],
                attack_pattern=state.get("predicted_attacks", ["unknown"])[0] if state.get("predicted_attacks") else "unknown",
                solution_steps=state.get("solution_steps", []),
                solve_time=0.0
            )
        return {}
    
    # Build graph
    workflow = StateGraph(EnhancedCTFAgentState)
    
    # Add nodes
    workflow.add_node("dl_analysis", dl_analysis_node)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", tool_node)
    workflow.add_node("store_experience", store_experience_node)
    
    # Define flow
    workflow.set_entry_point("dl_analysis")
    workflow.add_edge("dl_analysis", "agent")
    
    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            "store_experience": "store_experience",
            "end": END
        }
    )
    
    workflow.add_edge("tools", "agent")
    workflow.add_edge("store_experience", END)
    
    return workflow.compile()


def solve_with_dl(
    description: str,
    files: list = None,
    nc_host: str = "",
    nc_port: int = 0,
    max_steps: int = 15
) -> Dict[str, Any]:
    """
    Solve CTF challenge with Deep Learning enhancement.
    
    Main entry point for the enhanced solver.
    """
    start_time = time.time()
    
    agent = create_enhanced_agent()
    
    initial_state = {
        "messages": [],
        "challenge_description": description,
        "files": files or [],
        "nc_host": nc_host,
        "nc_port": nc_port,
        "challenge_type": "Unknown",
        "type_confidence": 0.0,
        "predicted_attacks": [],
        "attack_confidence": 0.0,
        "similar_experiences": [],
        "parameters_extracted": {},
        "flag": "",
        "solution_steps": [],
        "remaining_steps": max_steps,
        "dl_classification_done": False,
        "rag_retrieval_done": False
    }
    
    try:
        final_state = agent.invoke(initial_state)
        
        return {
            "success": bool(final_state.get("flag")),
            "flag": final_state.get("flag", ""),
            "challenge_type": final_state.get("challenge_type", "Unknown"),
            "type_confidence": final_state.get("type_confidence", 0.0),
            "predicted_attacks": final_state.get("predicted_attacks", []),
            "similar_experiences": final_state.get("similar_experiences", []),
            "solution_steps": final_state.get("solution_steps", []),
            "total_time": time.time() - start_time,
            "method": "deep_learning_enhanced"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "total_time": time.time() - start_time,
            "method": "deep_learning_enhanced"
        }


if __name__ == "__main__":
    print("🧪 Testing Enhanced DL Agent...")
    
    # Quick test of DL enhancer
    enhancer = DeepLearningEnhancer()
    
    analysis = enhancer.analyze_challenge(
        "RSA challenge with small exponent e=3. Decrypt the ciphertext.",
        [{"name": "chall.py", "content": "n = 12345\ne = 3\nc = 67890"}]
    )
    
    print(f"✅ Challenge Type: {analysis['challenge_type']}")
    print(f"📊 Confidence: {analysis['type_confidence']:.1%}")
    print(f"⚔️ Predicted Attacks: {analysis['predicted_attacks']}")
    print(f"📚 Similar Experiences: {len(analysis['similar_experiences'])}")
    print(f"💡 Recommendations: {analysis['recommendations']}")
