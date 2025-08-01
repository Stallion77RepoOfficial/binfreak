"""
Base plugin classes for BinFreak extension system
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime


class BasePlugin(ABC):
    """Base class for all BinFreak plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = "A BinFreak plugin"
        self.enabled = True
        self.dependencies = []
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'enabled': self.enabled,
            'dependencies': self.dependencies
        }
    
    def enable(self):
        """Enable the plugin"""
        self.enabled = True
    
    def disable(self):
        """Disable the plugin"""
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled


class AnalysisPlugin(BasePlugin):
    """Base class for analysis plugins"""
    
    @abstractmethod
    def analyze(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze binary data and return results
        
        Args:
            binary_data: Raw binary data
            file_info: Basic file information (path, size, format, etc.)
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported binary formats"""
        pass
    
    def can_analyze(self, file_info: Dict[str, Any]) -> bool:
        """Check if this plugin can analyze the given file"""
        file_format = file_info.get('format', {}).get('type', 'Unknown')
        supported = self.get_supported_formats()
        return any(fmt.lower() in file_format.lower() for fmt in supported) if supported else True


class VisualizationPlugin(BasePlugin):
    """Base class for visualization plugins"""
    
    @abstractmethod
    def visualize(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create visualization from analysis results
        
        Args:
            analysis_results: Results from binary analysis
            
        Returns:
            Dictionary containing visualization data
        """
        pass
    
    @abstractmethod
    def get_visualization_type(self) -> str:
        """Get the type of visualization this plugin provides"""
        pass


class CustomAnalyzer(AnalysisPlugin):
    """Example custom analyzer plugin"""
    
    def __init__(self):
        super().__init__()
        self.name = "Custom Binary Analyzer"
        self.version = "1.0.0"
        self.author = "BinFreak Team"
        self.description = "Custom binary analysis plugin"
    
    def get_info(self) -> Dict[str, Any]:
        return super().get_info()
    
    def analyze(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Example analysis implementation"""
        return {
            'plugin_name': self.name,
            'analysis_time': datetime.now().isoformat(),
            'file_size': len(binary_data),
            'sample_analysis': 'Custom analysis completed'
        }
    
    def get_supported_formats(self) -> List[str]:
        return ['PE', 'ELF', 'Mach-O', 'Raw']