"""
CTF Crypto Agent - Gemini AI
Agente especializado en resolver desafíos CTF de criptografía
"""

__version__ = "1.0.0"
__author__ = "CTF Crypto Agent Team"
__description__ = "AI-powered CTF crypto challenge solver using Gemini 2.5 Flash"

from .core.agent import solve_ctf_challenge
from .config.config import config

__all__ = ['solve_ctf_challenge', 'config']