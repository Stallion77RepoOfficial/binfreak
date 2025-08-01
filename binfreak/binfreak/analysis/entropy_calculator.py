"""
Entropy calculation module for binary analysis
"""

import math
from typing import List


class EntropyCalculator:
    """Calculates Shannon entropy for binary data"""
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(data)
        for count in frequencies.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def calculate_entropy_blocks(self, data: bytes, block_size: int = 256) -> List[float]:
        """Calculate entropy for blocks of binary data"""
        entropy_values = []
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if block:
                entropy_values.append(self.calculate_entropy(block))
        return entropy_values
    
    def calculate_entropy_chunks(self, data: bytes, chunk_size: int = 1024) -> List[float]:
        """Calculate entropy for data chunks"""
        entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            entropies.append(self.calculate_entropy(chunk))
        return entropies
    
    def get_entropy_classification(self, entropy: float) -> str:
        """Classify entropy level"""
        if entropy < 1.0:
            return "Very Low (likely text/data)"
        elif entropy < 3.0:
            return "Low (structured data)"
        elif entropy < 5.0:
            return "Medium (mixed content)"
        elif entropy < 7.0:
            return "High (compressed/encrypted)"
        else:
            return "Very High (likely packed/encrypted)"
