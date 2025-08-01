"""
BinFreak - Advanced Binary Analysis Tool
"""

from .analysis.binary_engine import BinaryAnalysisEngine
from .core.license_manager import SimpleLicenseManager
from .gui.main_window import SimplifiedMainWindow

__version__ = "2.0.0"
__author__ = "BinFreak Team"

__all__ = [
    'BinaryAnalysisEngine',
    'SimpleLicenseManager', 
    'SimplifiedMainWindow'
]
