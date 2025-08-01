"""
GUI module initialization
"""

from .main_window import SimplifiedMainWindow
from .visualization import AdvancedVisualizationWidget, VisualizationManager
from .ui_components import UIComponents
from .menu_manager import MenuManager
# TabManager imported directly in main_window to avoid circular imports

__all__ = [
    'SimplifiedMainWindow',
    'AdvancedVisualizationWidget',
    'VisualizationManager',
    'UIComponents',
    'MenuManager', 
    'TabManager'
]
