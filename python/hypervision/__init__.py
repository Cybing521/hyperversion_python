"""
HyperVision - Flow Interaction Graph based Attack Traffic Detection System

This is a Python implementation of HyperVision, originally published in NDSS'23:
"Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis"

Original C++ implementation: https://github.com/fuchuanpu/HyperVision
Authors: Chuanpu Fu, Qi Li, Ke Xu (Tsinghua University)
"""

__version__ = "1.0.0"
__author__ = "Python port by cyibin"
__original_author__ = "Chuanpu Fu, Qi Li, Ke Xu"

from .detector import HypervisionDetector

__all__ = ['HypervisionDetector']
