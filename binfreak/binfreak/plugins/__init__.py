"""
BinFreak Plugin System - Extensible analyzer framework
"""

from .plugin_manager import PluginManager
from .base_plugin import BasePlugin, AnalysisPlugin, VisualizationPlugin

__all__ = [
    'PluginManager',
    'BasePlugin', 
    'AnalysisPlugin',
    'VisualizationPlugin'
]