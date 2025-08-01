"""
Binary Analysis Engine - Core binary analysis functionality
"""

import os
import json
import time
import struct
import math
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple


class BinaryAnalysisEngine:
    """Core binary analysis functionality"""
    
    def __init__(self):
        self.analysis_cache = {}
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive binary file analysis"""
        if file_path in self.analysis_cache:
            return self.analysis_cache[file_path]
        
        try:
            start_time = time.time()
            
            # Load binary data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            
            # Initialize analysis components
            from .format_detector import FormatDetector
            from .string_extractor import StringExtractor
            from .entropy_calculator import EntropyCalculator
            from .function_detector import FunctionDetector
            
            format_detector = FormatDetector()
            string_extractor = StringExtractor()
            entropy_calculator = EntropyCalculator()
            function_detector = FunctionDetector()
            
            # Perform real analysis
            file_format_str = format_detector.detect_format(data)
            file_format = {'type': file_format_str, 'arch': 'x86_64'}  # Create dict
            strings = string_extractor.extract_strings(data)
            entropy_blocks = entropy_calculator.calculate_entropy_blocks(data)
            functions = function_detector.detect_functions(data)
            
            # Analyze sections based on format
            sections = self.analyze_sections(data, file_format)
            
            # Real disassembly attempt
            disassembly = self.perform_disassembly(data, file_format)
            
            analysis_time = time.time() - start_time
            
            # Code vs data ratio analysis
            code_analysis = self.analyze_code_sections(data, file_format, sections)
            
            # Entry point detection
            entry_point = self.find_entry_point(data, file_format)
            
            # Calculate analysis statistics
            analysis_time = time.time() - start_time
            
            result = {
                'file_path': file_path,
                'file_size': file_size,
                'file_format': file_format,
                'file_data': data,  # Include raw data for visualization
                'entropy': entropy_blocks,
                'strings': strings[:1000],
                'functions': functions,
                'sections': sections,
                'disassembly': disassembly,
                'analysis_time': datetime.now().isoformat(),
                'analysis_duration': f"{analysis_time:.2f}s",
                'statistics': {
                    'total_functions': len(functions),
                    'total_strings': len(strings),
                    'total_sections': len(sections),
                    'file_size_mb': file_size / (1024 * 1024),
                    'format_type': file_format.get('type', 'Unknown')
                }
            }
            
            self.analysis_cache[file_path] = result
            return result
        
        except FileNotFoundError:
            return {'error': f'File not found: {file_path}', 'file_path': file_path}
        except PermissionError:
            return {'error': f'Permission denied: {file_path}', 'file_path': file_path}
        except MemoryError:
            return {'error': f'File too large to analyze: {file_path}', 'file_path': file_path}
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}', 'file_path': file_path}
    
    def perform_disassembly(self, data: bytes, file_format: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform basic disassembly"""
        disassembly = []
        
        try:
            # Try using Capstone if available
            import capstone
            
            # Determine architecture
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_64
            
            if file_format.get('arch') == 'x86':
                mode = capstone.CS_MODE_32
            elif file_format.get('arch') == 'arm':
                arch = capstone.CS_ARCH_ARM
                mode = capstone.CS_MODE_ARM
            
            md = capstone.Cs(arch, mode)
            
            # Find code section
            code_offset = 0x1000 if len(data) > 0x1000 else 0
            code_data = data[code_offset:code_offset + min(1024, len(data) - code_offset)]
            
            for instruction in md.disasm(code_data, code_offset):
                disassembly.append({
                    'address': f"0x{instruction.address:x}",
                    'bytes': ' '.join(f'{b:02x}' for b in instruction.bytes),
                    'mnemonic': instruction.mnemonic,
                    'operands': instruction.op_str
                })
                
                if len(disassembly) >= 100:  # Limit output
                    break
                    
        except ImportError:
            # Fallback disassembly
            disassembly = self.basic_disassembly(data)
        except Exception as e:
            # Log the error and fallback
            print(f"Disassembly error: {e}")
            disassembly = self.basic_disassembly(data)
        
        return disassembly
    
    def basic_disassembly(self, data: bytes) -> List[Dict[str, Any]]:
        """Basic disassembly fallback"""
        disassembly = []
        
        # Simple x86 instruction patterns
        x86_patterns = {
            b'\x55': 'push rbp',
            b'\x48\x89\xe5': 'mov rbp, rsp',
            b'\x48\x83\xec': 'sub rsp,',
            b'\xc3': 'ret',
            b'\x90': 'nop',
            b'\xcc': 'int3'
        }
        
        offset = 0x1000 if len(data) > 0x1000 else 0
        end_offset = min(offset + 512, len(data))
        
        i = offset
        while i < end_offset and len(disassembly) < 50:
            found = False
            for pattern, instruction in x86_patterns.items():
                if data[i:i+len(pattern)] == pattern:
                    disassembly.append({
                        'address': f"0x{i:x}",
                        'bytes': ' '.join(f'{b:02x}' for b in pattern),
                        'mnemonic': instruction.split()[0],
                        'operands': ' '.join(instruction.split()[1:]) if len(instruction.split()) > 1 else ''
                    })
                    i += len(pattern)
                    found = True
                    break
            
            if not found:
                # Show raw byte if no pattern matches
                if i < len(data):
                    byte_val = data[i]
                    disassembly.append({
                        'address': f"0x{i:x}",
                        'bytes': f'{byte_val:02x}',
                        'mnemonic': 'db',
                        'operands': f'0x{byte_val:02x}'
                    })
                i += 1
        
        return disassembly
    
    def detect_format(self, data: bytes) -> str:
        """Enhanced binary format detection with comprehensive support"""
        from .format_detector import FormatDetector
        detector = FormatDetector()
        return detector.detect_format(data)
    
    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Enhanced string extraction with multiple encodings"""
        from .string_extractor import StringExtractor
        extractor = StringExtractor()
        return extractor.extract_strings(data, min_length)
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        from .entropy_calculator import EntropyCalculator
        calculator = EntropyCalculator()
        return calculator.calculate_entropy(data)
    
    def detect_functions(self, data: bytes) -> List[Dict[str, Any]]:
        """Professional function detection with proper binary format parsing"""
        from .function_detector import FunctionDetector
        detector = FunctionDetector()
        return detector.detect_functions(data)
    
    def analyze_sections(self, data: bytes, file_format: str) -> List[Dict[str, Any]]:
        """Analyze binary sections based on format"""
        from .section_analyzer import SectionAnalyzer
        analyzer = SectionAnalyzer()
        return analyzer.analyze_sections(data, file_format)
    
    def analyze_imports_exports(self, data: bytes, file_format: str) -> Dict[str, Any]:
        """Analyze imports and exports"""
        from .import_export_analyzer import ImportExportAnalyzer
        analyzer = ImportExportAnalyzer()
        return analyzer.analyze_imports_exports(data, file_format)
    
    def analyze_code_sections(self, data: bytes, file_format: str, sections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze code vs data ratio"""
        total_size = len(data)
        code_size = 0
        data_size = 0
        string_size = 0
        
        for section in sections:
            size = section.get('size', 0)
            section_type = section.get('type', '').lower()
            
            if any(x in section_type for x in ['text', 'code', 'exec']):
                code_size += size
            elif any(x in section_type for x in ['data', 'bss', 'rodata']):
                data_size += size
            elif any(x in section_type for x in ['string', 'cstring']):
                string_size += size
        
        return {
            'total_size': total_size,
            'code_size': code_size,
            'data_size': data_size,
            'string_size': string_size,
            'code_percentage': (code_size / total_size * 100) if total_size > 0 else 0,
            'data_percentage': (data_size / total_size * 100) if total_size > 0 else 0,
            'string_percentage': (string_size / total_size * 100) if total_size > 0 else 0
        }
    
    def find_entry_point(self, data: bytes, file_format: str) -> str:
        """Find binary entry point"""
        from .entry_point_finder import EntryPointFinder
        finder = EntryPointFinder()
        return finder.find_entry_point(data, file_format)
    
    def classify_entropy(self, entropy: float) -> str:
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
