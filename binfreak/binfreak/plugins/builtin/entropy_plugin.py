"""
Entropy Analysis Plugin - Analyzes binary entropy for packed/encrypted sections
"""

import math
from collections import Counter
from typing import Dict, Any, List
from abc import ABC, abstractmethod


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


class EntropyAnalysisPlugin(AnalysisPlugin):
    """Analyzes binary entropy to detect packed or encrypted sections"""
    
    def __init__(self):
        super().__init__()
        self.name = "Entropy Analyzer"
        self.version = "1.0.0"
        self.author = "BinFreak Team"
        self.description = "Analyzes binary entropy to detect packed/encrypted sections"
    
    def get_info(self) -> Dict[str, Any]:
        return super().get_info()
    
    def analyze(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform entropy analysis on binary data"""
        try:
            # Calculate overall entropy
            overall_entropy = self._calculate_entropy(binary_data)
            
            # Analyze entropy in blocks
            block_size = 1024
            block_entropies = []
            high_entropy_blocks = []
            
            for i in range(0, len(binary_data), block_size):
                block = binary_data[i:i + block_size]
                if len(block) < block_size // 2:  # Skip small blocks at end
                    break
                    
                block_entropy = self._calculate_entropy(block)
                block_entropies.append({
                    'offset': i,
                    'size': len(block),
                    'entropy': block_entropy
                })
                
                # High entropy indicates possible packing/encryption
                if block_entropy > 7.5:
                    high_entropy_blocks.append({
                        'offset': i,
                        'size': len(block),
                        'entropy': block_entropy
                    })
            
            # Analysis results
            avg_entropy = sum(b['entropy'] for b in block_entropies) / len(block_entropies) if block_entropies else 0
            max_entropy = max(b['entropy'] for b in block_entropies) if block_entropies else 0
            
            # Determine if binary is likely packed/encrypted
            is_packed = (overall_entropy > 7.0 or 
                        len(high_entropy_blocks) > len(block_entropies) * 0.3 or
                        avg_entropy > 6.5)
            
            return {
                'plugin_name': self.name,
                'overall_entropy': overall_entropy,
                'average_entropy': avg_entropy,
                'max_entropy': max_entropy,
                'total_blocks': len(block_entropies),
                'high_entropy_blocks': len(high_entropy_blocks),
                'is_likely_packed': is_packed,
                'high_entropy_regions': high_entropy_blocks[:10],  # Limit to first 10
                'entropy_distribution': self._get_entropy_distribution(block_entropies)
            }
            
        except Exception as e:
            return {'error': f"Entropy analysis failed: {str(e)}"}
    
    def get_supported_formats(self) -> List[str]:
        return ['PE', 'ELF', 'Mach-O', 'Raw']  # Works on any binary format
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        counts = Counter(data)
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _get_entropy_distribution(self, block_entropies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of entropy ranges"""
        distribution = {
            'very_low': 0,    # 0-2
            'low': 0,         # 2-4
            'medium': 0,      # 4-6
            'high': 0,        # 6-7.5
            'very_high': 0    # 7.5-8
        }
        
        for block in block_entropies:
            entropy = block['entropy']
            if entropy < 2:
                distribution['very_low'] += 1
            elif entropy < 4:
                distribution['low'] += 1
            elif entropy < 6:
                distribution['medium'] += 1
            elif entropy < 7.5:
                distribution['high'] += 1
            else:
                distribution['very_high'] += 1
        
        return distribution