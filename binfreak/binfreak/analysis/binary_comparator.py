"""
Binary Comparison Engine - Compare and diff binary files
"""

import os
import hashlib
import difflib
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime


class BinaryComparator:
    """Binary file comparison and diffing engine"""
    
    def __init__(self):
        self.comparison_cache = {}
    
    def compare_files(self, file1_path: str, file2_path: str) -> Dict[str, Any]:
        """Compare two binary files and return detailed comparison results"""
        try:
            # Create comparison key for caching
            comparison_key = f"{file1_path}::{file2_path}"
            if comparison_key in self.comparison_cache:
                return self.comparison_cache[comparison_key]
            
            start_time = datetime.now()
            
            # Load both files
            with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
                data1 = f1.read()
                data2 = f2.read()
            
            # Basic file information
            file1_info = self._get_file_info(file1_path, data1)
            file2_info = self._get_file_info(file2_path, data2)
            
            # Perform various comparison analyses
            hash_comparison = self._compare_hashes(data1, data2)
            size_comparison = self._compare_sizes(data1, data2)
            byte_differences = self._find_byte_differences(data1, data2)
            structural_comparison = self._compare_structure(data1, data2)
            similarity_score = self._calculate_similarity(data1, data2)
            
            # Function-level comparison (if available)
            function_comparison = self._compare_functions(data1, data2, file1_info, file2_info)
            
            # String comparison
            string_comparison = self._compare_strings(data1, data2)
            
            end_time = datetime.now()
            comparison_time = (end_time - start_time).total_seconds()
            
            result = {
                'file1': file1_info,
                'file2': file2_info,
                'hash_comparison': hash_comparison,
                'size_comparison': size_comparison,
                'similarity_score': similarity_score,
                'byte_differences': byte_differences,
                'structural_comparison': structural_comparison,
                'function_comparison': function_comparison,
                'string_comparison': string_comparison,
                'comparison_time': comparison_time,
                'timestamp': end_time.isoformat()
            }
            
            self.comparison_cache[comparison_key] = result
            return result
            
        except FileNotFoundError as e:
            return {'error': f'File not found: {str(e)}'}
        except PermissionError as e:
            return {'error': f'Permission denied: {str(e)}'}
        except Exception as e:
            return {'error': f'Comparison failed: {str(e)}'}
    
    def compare_multiple(self, file_paths: List[str]) -> Dict[str, Any]:
        """Compare multiple files and create a comparison matrix"""
        if len(file_paths) < 2:
            return {'error': 'At least 2 files required for comparison'}
        
        results = {}
        comparison_matrix = {}
        
        # Load all files
        file_data = {}
        for path in file_paths:
            try:
                with open(path, 'rb') as f:
                    file_data[path] = f.read()
            except Exception as e:
                return {'error': f'Failed to load {path}: {str(e)}'}
        
        # Compare each pair
        for i, file1 in enumerate(file_paths):
            comparison_matrix[file1] = {}
            for j, file2 in enumerate(file_paths):
                if i == j:
                    comparison_matrix[file1][file2] = 1.0  # Same file
                elif j > i:  # Avoid duplicate comparisons
                    similarity = self._calculate_similarity(file_data[file1], file_data[file2])
                    comparison_matrix[file1][file2] = similarity
                    comparison_matrix.setdefault(file2, {})[file1] = similarity
        
        # Find most similar and most different pairs
        similarities = []
        for file1 in file_paths:
            for file2 in file_paths:
                if file1 != file2 and file2 in comparison_matrix[file1]:
                    similarities.append((file1, file2, comparison_matrix[file1][file2]))
        
        similarities.sort(key=lambda x: x[2], reverse=True)
        
        return {
            'comparison_matrix': comparison_matrix,
            'most_similar': similarities[:5],  # Top 5 most similar
            'most_different': similarities[-5:],  # Top 5 most different
            'file_count': len(file_paths),
            'total_comparisons': len(similarities),
            'average_similarity': sum(s[2] for s in similarities) / len(similarities) if similarities else 0
        }
    
    def _get_file_info(self, file_path: str, data: bytes) -> Dict[str, Any]:
        """Get basic file information"""
        return {
            'path': file_path,
            'name': os.path.basename(file_path),
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
    
    def _compare_hashes(self, data1: bytes, data2: bytes) -> Dict[str, Any]:
        """Compare file hashes"""
        md5_1 = hashlib.md5(data1).hexdigest()
        md5_2 = hashlib.md5(data2).hexdigest()
        sha256_1 = hashlib.sha256(data1).hexdigest()
        sha256_2 = hashlib.sha256(data2).hexdigest()
        
        return {
            'md5_match': md5_1 == md5_2,
            'sha256_match': sha256_1 == sha256_2,
            'identical': md5_1 == md5_2 and sha256_1 == sha256_2
        }
    
    def _compare_sizes(self, data1: bytes, data2: bytes) -> Dict[str, Any]:
        """Compare file sizes"""
        size1, size2 = len(data1), len(data2)
        size_diff = abs(size1 - size2)
        size_ratio = min(size1, size2) / max(size1, size2) if max(size1, size2) > 0 else 1.0
        
        return {
            'size1': size1,
            'size2': size2,
            'size_difference': size_diff,
            'size_ratio': size_ratio,
            'size_change_percent': (size_diff / max(size1, size2)) * 100 if max(size1, size2) > 0 else 0
        }
    
    def _find_byte_differences(self, data1: bytes, data2: bytes, max_diffs: int = 100) -> List[Dict[str, Any]]:
        """Find byte-level differences between files"""
        differences = []
        min_len = min(len(data1), len(data2))
        
        # Compare overlapping bytes
        for i in range(min_len):
            if data1[i] != data2[i] and len(differences) < max_diffs:
                differences.append({
                    'offset': i,
                    'byte1': data1[i],
                    'byte2': data2[i],
                    'type': 'modified'
                })
        
        # Handle size differences
        if len(data1) > len(data2):
            differences.append({
                'offset': len(data2),
                'size': len(data1) - len(data2),
                'type': 'added_to_file1'
            })
        elif len(data2) > len(data1):
            differences.append({
                'offset': len(data1),
                'size': len(data2) - len(data1),
                'type': 'added_to_file2'
            })
        
        return differences
    
    def _calculate_similarity(self, data1: bytes, data2: bytes) -> float:
        """Calculate similarity score between two binary files"""
        if not data1 and not data2:
            return 1.0
        if not data1 or not data2:
            return 0.0
        
        # Use byte-level similarity for small files
        if len(data1) < 10000 and len(data2) < 10000:
            return self._byte_similarity(data1, data2)
        
        # Use sampling for large files
        return self._sampled_similarity(data1, data2)
    
    def _byte_similarity(self, data1: bytes, data2: bytes) -> float:
        """Calculate exact byte similarity"""
        min_len = min(len(data1), len(data2))
        max_len = max(len(data1), len(data2))
        
        if max_len == 0:
            return 1.0
        
        matches = sum(1 for i in range(min_len) if data1[i] == data2[i])
        similarity = matches / max_len
        
        return similarity
    
    def _sampled_similarity(self, data1: bytes, data2: bytes, sample_size: int = 1000) -> float:
        """Calculate similarity using sampling for large files"""
        # Sample bytes from both files
        step1 = max(1, len(data1) // sample_size)
        step2 = max(1, len(data2) // sample_size)
        
        sample1 = data1[::step1][:sample_size]
        sample2 = data2[::step2][:sample_size]
        
        return self._byte_similarity(sample1, sample2)
    
    def _compare_structure(self, data1: bytes, data2: bytes) -> Dict[str, Any]:
        """Compare structural aspects of the binaries"""
        # Basic structural comparison
        entropy1 = self._calculate_entropy(data1)
        entropy2 = self._calculate_entropy(data2)
        
        # Null byte distribution
        nulls1 = data1.count(0)
        nulls2 = data2.count(0)
        
        return {
            'entropy_similarity': 1.0 - abs(entropy1 - entropy2) / 8.0,  # Entropy is 0-8
            'null_bytes_ratio': min(nulls1, nulls2) / max(nulls1, nulls2) if max(nulls1, nulls2) > 0 else 1.0,
            'entropy_file1': entropy1,
            'entropy_file2': entropy2
        }
    
    def _compare_functions(self, data1: bytes, data2: bytes, file1_info: Dict, file2_info: Dict) -> Dict[str, Any]:
        """Compare function-level differences (simplified)"""
        # This is a placeholder - in a full implementation, this would
        # use the function detector to find and compare functions
        return {
            'function_analysis': 'Basic function comparison (placeholder)',
            'note': 'Full function comparison requires integration with disassembly engine'
        }
    
    def _compare_strings(self, data1: bytes, data2: bytes) -> Dict[str, Any]:
        """Compare strings found in both binaries"""
        # Extract basic ASCII strings
        strings1 = set(self._extract_basic_strings(data1))
        strings2 = set(self._extract_basic_strings(data2))
        
        common_strings = strings1.intersection(strings2)
        unique_to_1 = strings1 - strings2
        unique_to_2 = strings2 - strings1
        
        return {
            'total_strings_file1': len(strings1),
            'total_strings_file2': len(strings2),
            'common_strings': len(common_strings),
            'unique_to_file1': len(unique_to_1),
            'unique_to_file2': len(unique_to_2),
            'string_similarity': len(common_strings) / max(len(strings1), len(strings2)) if max(len(strings1), len(strings2)) > 0 else 1.0,
            'sample_common': list(common_strings)[:10],
            'sample_unique_1': list(unique_to_1)[:10],
            'sample_unique_2': list(unique_to_2)[:10]
        }
    
    def _extract_basic_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract basic ASCII strings from binary data"""
        import re
        pattern = rb'[!-~]{%d,}' % min_length
        matches = re.findall(pattern, data)
        return [match.decode('ascii', errors='ignore') for match in matches]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(data)
        entropy = 0.0
        length = len(data)
        
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy