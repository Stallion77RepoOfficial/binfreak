"""
BinFreak - Advanced Binary Analysis Tool
"""

from .core.license_manager import LicenseManager
from .analysis.binary_engine import BinaryAnalysisEngine
from .analysis.disassembly_engine import AdvancedDisassemblyEngine
from .analysis.fuzzing_engine import FuzzingEngine
from .analysis.decompiler_engine import DecompilerEngine
from .gui.main_window import BinFreakMainWindow
from .gui.visualization import AdvancedVisualizationWidget, VisualizationManager
from .utils import FileUtils, BinaryUtils, FormatUtils

__version__ = "1.0.0"
__author__ = "BinFreak Team"

__all__ = [
    'LicenseManager',
    'BinaryAnalysisEngine', 
    'AdvancedDisassemblyEngine',
    'FuzzingEngine',
    'DecompilerEngine',
    'BinFreakMainWindow',
    'AdvancedVisualizationWidget',
    'VisualizationManager',
    'FileUtils',
    'BinaryUtils', 
    'FormatUtils'
]
