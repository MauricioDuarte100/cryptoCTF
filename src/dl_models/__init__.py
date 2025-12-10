"""
Deep Learning Models for CTF Solver
"""

from .challenge_classifier import ChallengeClassifier, ClassifierConfig
from .attack_predictor import AttackPredictor, PredictorConfig

__all__ = [
    'ChallengeClassifier', 
    'ClassifierConfig',
    'AttackPredictor', 
    'PredictorConfig'
]
