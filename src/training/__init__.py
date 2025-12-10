"""
Training module for CTF Solver Deep Learning models
"""

from .train_classifier import train_classifier
from .train_predictor import train_predictor

__all__ = ['train_classifier', 'train_predictor']
