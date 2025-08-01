"""
Plugin Manager for BinFreak - Handles plugin loading and execution
"""

import os
import sys
import importlib
import importlib.util
from typing import Dict, Any, List, Optional
from pathlib import Path

from .base_plugin import BasePlugin, AnalysisPlugin, VisualizationPlugin


class PluginManager:
    """Manages loading and execution of BinFreak plugins"""
    
    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.plugin_dirs = plugin_dirs or []
        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.analysis_plugins: Dict[str, AnalysisPlugin] = {}
        self.visualization_plugins: Dict[str, VisualizationPlugin] = {}
        
        # Add default plugin directories
        self._add_default_plugin_dirs()
    
    def _add_default_plugin_dirs(self):
        """Add default plugin directories"""
        # Built-in plugins directory
        builtin_dir = Path(__file__).parent / "builtin"
        if builtin_dir.exists():
            self.plugin_dirs.append(str(builtin_dir))
        
        # User plugins directory
        user_dir = Path.home() / ".binfreak" / "plugins"
        if user_dir.exists():
            self.plugin_dirs.append(str(user_dir))
    
    def discover_plugins(self) -> List[str]:
        """Discover available plugins in plugin directories"""
        discovered = []
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                continue
                
            for file_path in Path(plugin_dir).rglob("*.py"):
                if file_path.name.startswith("__"):
                    continue
                    
                discovered.append(str(file_path))
        
        return discovered
    
    def load_plugin(self, plugin_path: str) -> Optional[BasePlugin]:
        """Load a single plugin from file path"""
        try:
            # Add the plugin directory to sys.path temporarily
            plugin_dir = str(Path(plugin_path).parent)
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)
            
            # Also add the plugins directory for base_plugin imports
            plugins_dir = str(Path(__file__).parent)
            if plugins_dir not in sys.path:
                sys.path.insert(0, plugins_dir)
            
            # Create module spec
            module_name = Path(plugin_path).stem
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            
            if spec is None or spec.loader is None:
                return None
            
            # Load module
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find plugin classes in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr != BasePlugin and
                    attr != AnalysisPlugin and
                    attr != VisualizationPlugin):
                    
                    # Instantiate plugin
                    plugin_instance = attr()
                    plugin_name = plugin_instance.name
                    
                    self.loaded_plugins[plugin_name] = plugin_instance
                    
                    # Categorize plugin
                    if isinstance(plugin_instance, AnalysisPlugin):
                        self.analysis_plugins[plugin_name] = plugin_instance
                    elif isinstance(plugin_instance, VisualizationPlugin):
                        self.visualization_plugins[plugin_name] = plugin_instance
                    
                    return plugin_instance
            
        except Exception as e:
            print(f"Failed to load plugin {plugin_path}: {e}")
            return None
        
        return None
    
    def load_all_plugins(self) -> Dict[str, BasePlugin]:
        """Load all discoverable plugins"""
        discovered = self.discover_plugins()
        
        for plugin_path in discovered:
            self.load_plugin(plugin_path)
        
        return self.loaded_plugins
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a loaded plugin by name"""
        return self.loaded_plugins.get(name)
    
    def get_analysis_plugins(self) -> Dict[str, AnalysisPlugin]:
        """Get all loaded analysis plugins"""
        return self.analysis_plugins
    
    def get_visualization_plugins(self) -> Dict[str, VisualizationPlugin]:
        """Get all loaded visualization plugins"""
        return self.visualization_plugins
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enable()
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.disable()
            return True
        return False
    
    def run_analysis_plugins(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Run all enabled analysis plugins on binary data"""
        results = {}
        
        for name, plugin in self.analysis_plugins.items():
            if not plugin.is_enabled():
                continue
                
            if not plugin.can_analyze(file_info):
                continue
            
            try:
                result = plugin.analyze(binary_data, file_info)
                results[name] = result
            except Exception as e:
                results[name] = {'error': str(e)}
        
        return results
    
    def get_plugin_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all loaded plugins"""
        info = {}
        for name, plugin in self.loaded_plugins.items():
            info[name] = plugin.get_info()
        return info
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin"""
        if name in self.loaded_plugins:
            del self.loaded_plugins[name]
            
            if name in self.analysis_plugins:
                del self.analysis_plugins[name]
            
            if name in self.visualization_plugins:
                del self.visualization_plugins[name]
            
            return True
        
        return False