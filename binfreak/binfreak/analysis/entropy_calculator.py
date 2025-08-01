"""
Enhanced entropy calculation module for binary analysis with visualization
"""

import math
from typing import List, Dict, Any, Tuple
import json


class EntropyCalculator:
    """Enhanced entropy calculator with visualization and analysis features"""
    
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
    
    def calculate_sliding_window_entropy(self, data: bytes, window_size: int = 256, step_size: int = 64) -> List[Dict[str, Any]]:
        """Calculate entropy using sliding window approach"""
        results = []
        
        for i in range(0, len(data) - window_size + 1, step_size):
            window = data[i:i + window_size]
            entropy = self.calculate_entropy(window)
            
            results.append({
                'offset': i,
                'entropy': entropy,
                'classification': self.get_entropy_classification(entropy),
                'byte_distribution': self._analyze_byte_distribution(window)
            })
        
        return results
    
    def analyze_entropy_pattern(self, data: bytes) -> Dict[str, Any]:
        """Comprehensive entropy pattern analysis"""
        if not data:
            return {'error': 'No data provided'}
        
        # Overall entropy
        overall_entropy = self.calculate_entropy(data)
        
        # Block-based analysis
        block_entropies = self.calculate_entropy_blocks(data, 1024)
        
        # Sliding window analysis
        sliding_entropies = self.calculate_sliding_window_entropy(data, 512, 128)
        
        # Statistical analysis
        entropy_stats = self._calculate_entropy_statistics(block_entropies)
        
        # Pattern detection
        patterns = self._detect_entropy_patterns(sliding_entropies)
        
        # Anomaly detection
        anomalies = self._detect_entropy_anomalies(sliding_entropies, entropy_stats['mean'])
        
        return {
            'overall_entropy': overall_entropy,
            'overall_classification': self.get_entropy_classification(overall_entropy),
            'block_analysis': {
                'block_count': len(block_entropies),
                'block_entropies': block_entropies,
                'statistics': entropy_stats
            },
            'sliding_window_analysis': {
                'window_count': len(sliding_entropies),
                'windows': sliding_entropies[:100],  # Limit for UI
                'patterns': patterns,
                'anomalies': anomalies
            },
            'visualization_data': self._prepare_visualization_data(sliding_entropies),
            'recommendations': self._generate_entropy_recommendations(overall_entropy, patterns, anomalies)
        }
    
    def get_entropy_classification(self, entropy: float) -> str:
        """Enhanced entropy classification with more detailed categories"""
        if entropy < 0.5:
            return "Very Low (likely null/repeated data)"
        elif entropy < 1.0:
            return "Low (highly structured data)"
        elif entropy < 2.0:
            return "Low-Medium (structured text/code)"
        elif entropy < 4.0:
            return "Medium (mixed binary data)"
        elif entropy < 6.0:
            return "Medium-High (complex data structures)"
        elif entropy < 7.0:
            return "High (compressed/encrypted data)"
        elif entropy < 7.5:
            return "Very High (strong encryption/compression)"
        else:
            return "Maximum (cryptographic data/random)"
    
    def detect_packed_sections(self, data: bytes, threshold: float = 7.0) -> List[Dict[str, Any]]:
        """Detect potentially packed or encrypted sections based on entropy"""
        sections = []
        sliding_analysis = self.calculate_sliding_window_entropy(data, 1024, 256)
        
        in_high_entropy_section = False
        section_start = 0
        
        for window in sliding_analysis:
            if window['entropy'] >= threshold:
                if not in_high_entropy_section:
                    section_start = window['offset']
                    in_high_entropy_section = True
            else:
                if in_high_entropy_section:
                    sections.append({
                        'start_offset': section_start,
                        'end_offset': window['offset'],
                        'length': window['offset'] - section_start,
                        'average_entropy': self._calculate_average_entropy_in_range(
                            sliding_analysis, section_start, window['offset']
                        ),
                        'classification': 'Likely packed/encrypted',
                        'confidence': self._calculate_packing_confidence(
                            sliding_analysis, section_start, window['offset']
                        )
                    })
                    in_high_entropy_section = False
        
        # Handle section that goes to end of file
        if in_high_entropy_section:
            sections.append({
                'start_offset': section_start,
                'end_offset': len(data),
                'length': len(data) - section_start,
                'classification': 'Likely packed/encrypted (end of file)',
                'confidence': 0.8
            })
        
        return sections
    
    def compare_entropy_profiles(self, data1: bytes, data2: bytes) -> Dict[str, Any]:
        """Compare entropy profiles between two binaries"""
        analysis1 = self.analyze_entropy_pattern(data1)
        analysis2 = self.analyze_entropy_pattern(data2)
        
        # Calculate correlation between entropy patterns
        entropies1 = [w['entropy'] for w in analysis1['sliding_window_analysis']['windows']]
        entropies2 = [w['entropy'] for w in analysis2['sliding_window_analysis']['windows']]
        
        correlation = self._calculate_entropy_correlation(entropies1, entropies2)
        
        return {
            'file1_analysis': analysis1,
            'file2_analysis': analysis2,
            'comparison': {
                'overall_entropy_difference': abs(analysis1['overall_entropy'] - analysis2['overall_entropy']),
                'entropy_correlation': correlation,
                'similar_patterns': correlation > 0.7,
                'classification_match': analysis1['overall_classification'] == analysis2['overall_classification']
            }
        }
    
    def _analyze_byte_distribution(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte value distribution in data"""
        if not data:
            return {}
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        total_bytes = len(data)
        
        # Calculate statistics
        non_zero_bytes = sum(1 for count in byte_counts if count > 0)
        max_count = max(byte_counts)
        min_count = min(count for count in byte_counts if count > 0) if non_zero_bytes > 0 else 0
        
        # Find most and least common bytes
        most_common_byte = byte_counts.index(max_count)
        
        return {
            'unique_bytes': non_zero_bytes,
            'most_common_byte': {
                'value': most_common_byte,
                'count': max_count,
                'percentage': (max_count / total_bytes) * 100
            },
            'distribution_uniformity': non_zero_bytes / 256.0,
            'byte_frequency_variance': self._calculate_variance(byte_counts)
        }
    
    def _calculate_entropy_statistics(self, entropies: List[float]) -> Dict[str, float]:
        """Calculate statistical measures for entropy values"""
        if not entropies:
            return {}
        
        mean_entropy = sum(entropies) / len(entropies)
        variance = sum((e - mean_entropy) ** 2 for e in entropies) / len(entropies)
        std_dev = math.sqrt(variance)
        
        sorted_entropies = sorted(entropies)
        median = sorted_entropies[len(sorted_entropies) // 2]
        
        return {
            'mean': mean_entropy,
            'median': median,
            'min': min(entropies),
            'max': max(entropies),
            'variance': variance,
            'std_deviation': std_dev,
            'range': max(entropies) - min(entropies)
        }
    
    def _detect_entropy_patterns(self, sliding_entropies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect patterns in entropy distribution"""
        patterns = []
        
        # Detect sudden entropy changes
        for i in range(1, len(sliding_entropies)):
            current = sliding_entropies[i]['entropy']
            previous = sliding_entropies[i-1]['entropy']
            
            change = abs(current - previous)
            if change > 2.0:  # Significant entropy change
                patterns.append({
                    'type': 'entropy_jump',
                    'offset': sliding_entropies[i]['offset'],
                    'from_entropy': previous,
                    'to_entropy': current,
                    'change_magnitude': change,
                    'description': f"Entropy jump from {previous:.2f} to {current:.2f}"
                })
        
        # Detect consistent high entropy regions
        high_entropy_regions = []
        in_high_region = False
        region_start = 0
        
        for window in sliding_entropies:
            if window['entropy'] > 6.5:  # High entropy threshold
                if not in_high_region:
                    region_start = window['offset']
                    in_high_region = True
            else:
                if in_high_region:
                    high_entropy_regions.append({
                        'type': 'high_entropy_region',
                        'start_offset': region_start,
                        'end_offset': window['offset'],
                        'length': window['offset'] - region_start,
                        'description': f"High entropy region from {region_start:x} to {window['offset']:x}"
                    })
                    in_high_region = False
        
        patterns.extend(high_entropy_regions)
        
        return patterns
    
    def _detect_entropy_anomalies(self, sliding_entropies: List[Dict[str, Any]], mean_entropy: float) -> List[Dict[str, Any]]:
        """Detect entropy anomalies (outliers)"""
        anomalies = []
        
        # Calculate threshold for anomaly detection (2 standard deviations)
        entropies = [w['entropy'] for w in sliding_entropies]
        std_dev = math.sqrt(sum((e - mean_entropy) ** 2 for e in entropies) / len(entropies))
        threshold = 2 * std_dev
        
        for window in sliding_entropies:
            deviation = abs(window['entropy'] - mean_entropy)
            if deviation > threshold:
                anomaly_type = 'high_entropy_anomaly' if window['entropy'] > mean_entropy else 'low_entropy_anomaly'
                
                anomalies.append({
                    'type': anomaly_type,
                    'offset': window['offset'],
                    'entropy': window['entropy'],
                    'deviation': deviation,
                    'significance': deviation / threshold,
                    'description': f"Entropy anomaly at offset {window['offset']:x}: {window['entropy']:.2f}"
                })
        
        return anomalies
    
    def _prepare_visualization_data(self, sliding_entropies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare data for entropy visualization"""
        return {
            'entropy_over_offset': [
                {'offset': w['offset'], 'entropy': w['entropy']} 
                for w in sliding_entropies
            ],
            'entropy_histogram': self._create_entropy_histogram([w['entropy'] for w in sliding_entropies]),
            'classification_distribution': self._create_classification_distribution(sliding_entropies)
        }
    
    def _create_entropy_histogram(self, entropies: List[float], bins: int = 20) -> List[Dict[str, Any]]:
        """Create histogram data for entropy values"""
        if not entropies:
            return []
        
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        bin_width = (max_entropy - min_entropy) / bins
        
        histogram = []
        for i in range(bins):
            bin_start = min_entropy + i * bin_width
            bin_end = bin_start + bin_width
            
            count = sum(1 for e in entropies if bin_start <= e < bin_end)
            
            histogram.append({
                'bin_start': bin_start,
                'bin_end': bin_end,
                'count': count,
                'percentage': (count / len(entropies)) * 100
            })
        
        return histogram
    
    def _create_classification_distribution(self, sliding_entropies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Create distribution of entropy classifications"""
        distribution = {}
        
        for window in sliding_entropies:
            classification = window['classification']
            distribution[classification] = distribution.get(classification, 0) + 1
        
        return distribution
    
    def _generate_entropy_recommendations(self, overall_entropy: float, 
                                        patterns: List[Dict[str, Any]], 
                                        anomalies: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on entropy analysis"""
        recommendations = []
        
        # Overall entropy recommendations
        if overall_entropy > 7.5:
            recommendations.append("File has very high entropy - likely packed, encrypted, or compressed")
            recommendations.append("Consider using unpacking tools or entropy-based analysis")
        elif overall_entropy < 2.0:
            recommendations.append("File has low entropy - likely contains structured data or many repeated patterns")
            recommendations.append("May contain large amounts of null bytes or text data")
        
        # Pattern-based recommendations
        if any(p['type'] == 'high_entropy_region' for p in patterns):
            recommendations.append("High entropy regions detected - investigate for packed/encrypted sections")
        
        if any(p['type'] == 'entropy_jump' for p in patterns):
            recommendations.append("Sudden entropy changes detected - may indicate section boundaries or data type changes")
        
        # Anomaly-based recommendations
        if len(anomalies) > 5:
            recommendations.append("Multiple entropy anomalies detected - file may have unusual structure")
        
        return recommendations
    
    def _calculate_average_entropy_in_range(self, sliding_analysis: List[Dict[str, Any]], 
                                          start_offset: int, end_offset: int) -> float:
        """Calculate average entropy in a specific range"""
        relevant_windows = [
            w for w in sliding_analysis 
            if start_offset <= w['offset'] <= end_offset
        ]
        
        if not relevant_windows:
            return 0.0
        
        return sum(w['entropy'] for w in relevant_windows) / len(relevant_windows)
    
    def _calculate_packing_confidence(self, sliding_analysis: List[Dict[str, Any]], 
                                    start_offset: int, end_offset: int) -> float:
        """Calculate confidence that a region is packed/encrypted"""
        relevant_windows = [
            w for w in sliding_analysis 
            if start_offset <= w['offset'] <= end_offset
        ]
        
        if not relevant_windows:
            return 0.0
        
        high_entropy_count = sum(1 for w in relevant_windows if w['entropy'] > 7.0)
        confidence = high_entropy_count / len(relevant_windows)
        
        return min(confidence, 1.0)
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)
    
    def _calculate_entropy_correlation(self, entropies1: List[float], entropies2: List[float]) -> float:
        """Calculate correlation between two entropy sequences"""
        if not entropies1 or not entropies2:
            return 0.0
        
        min_len = min(len(entropies1), len(entropies2))
        if min_len == 0:
            return 0.0
        
        # Truncate to same length
        e1 = entropies1[:min_len]
        e2 = entropies2[:min_len]
        
        # Calculate correlation coefficient
        mean1 = sum(e1) / len(e1)
        mean2 = sum(e2) / len(e2)
        
        numerator = sum((e1[i] - mean1) * (e2[i] - mean2) for i in range(min_len))
        
        sum_sq1 = sum((e1[i] - mean1) ** 2 for i in range(min_len))
        sum_sq2 = sum((e2[i] - mean2) ** 2 for i in range(min_len))
        
        denominator = math.sqrt(sum_sq1 * sum_sq2)
        
        return numerator / denominator if denominator > 0 else 0.0
