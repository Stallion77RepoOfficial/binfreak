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
        self.plugin_manager = None
        self._initialize_plugins()
    
    def _initialize_plugins(self):
        """Initialize the plugin system"""
        try:
            from ..plugins.plugin_manager import PluginManager
            self.plugin_manager = PluginManager()
            self.plugin_manager.load_all_plugins()
        except Exception as e:
            print(f"Plugin system initialization failed: {e}")
            self.plugin_manager = None
    
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
            
            # Run plugin analysis if available
            if self.plugin_manager:
                try:
                    plugin_results = self.plugin_manager.run_analysis_plugins(data, {
                        'path': file_path,
                        'size': file_size,
                        'format': file_format
                    })
                    result['plugin_analysis'] = plugin_results
                except Exception as e:
                    result['plugin_analysis'] = {'error': f'Plugin analysis failed: {str(e)}'}
            
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
        """Perform disassembly with proper code section detection"""
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
            
            # Find the actual code section for different formats
            code_sections = self._find_code_sections(data, file_format)
            
            if code_sections:
                # Use the first code section found
                code_section = code_sections[0]
                code_offset = code_section.get('file_offset', 0)
                code_size = code_section.get('size', 1024)
                code_addr = code_section.get('virtual_address', code_offset)
                
                # Ensure we don't read beyond file boundaries
                if code_offset < len(data):
                    end_offset = min(code_offset + code_size, len(data))
                    code_data = data[code_offset:end_offset]
                    
                    print(f"Disassembling code section at file offset 0x{code_offset:x}, size {len(code_data)} bytes")
                    
                    for instruction in md.disasm(code_data, code_addr):
                        disassembly.append({
                            'address': f"0x{instruction.address:x}",
                            'bytes': ' '.join(f'{b:02x}' for b in instruction.bytes),
                            'mnemonic': instruction.mnemonic,
                            'operands': instruction.op_str
                        })
                        
                        if len(disassembly) >= 100:  # Limit output
                            break
            else:
                # Fallback: try to find code heuristically
                print("No code sections found, using heuristic search")
                code_offset, code_data = self._find_code_heuristic(data)
                
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
    
    def _find_code_sections(self, data: bytes, file_format: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find code sections in the binary"""
        code_sections = []
        
        try:
            file_type = file_format.get('type', '')
            
            if 'Mach-O' in file_type:
                code_sections = self._find_macho_text_section(data)
            elif 'ELF' in file_type:
                code_sections = self._find_elf_text_section(data)
            elif 'PE' in file_type:
                code_sections = self._find_pe_text_section(data)
                
        except Exception as e:
            print(f"Error finding code sections: {e}")
            
        return code_sections
    
    def _find_macho_text_section(self, data: bytes) -> List[Dict[str, Any]]:
        """Find __TEXT.__text section in Mach-O binary"""
        import struct
        
        try:
            # Check Mach-O magic
            magic = struct.unpack('<I', data[0:4])[0]
            is_64bit = magic in [0xfeedfacf, 0xcffaedfe]
            
            if is_64bit:
                # 64-bit Mach-O
                ncmds = struct.unpack('<I', data[16:20])[0]
                load_cmd_offset = 32
            else:
                # 32-bit Mach-O
                ncmds = struct.unpack('<I', data[12:16])[0]
                load_cmd_offset = 28
            
            # Parse load commands to find __TEXT segment
            current_offset = load_cmd_offset
            
            for _ in range(ncmds):
                if current_offset + 8 > len(data):
                    break
                    
                cmd = struct.unpack('<I', data[current_offset:current_offset+4])[0]
                cmdsize = struct.unpack('<I', data[current_offset+4:current_offset+8])[0]
                
                # LC_SEGMENT_64 = 0x19, LC_SEGMENT = 0x1
                if cmd in [0x19, 0x1]:
                    # Found a segment load command
                    if is_64bit and cmd == 0x19:
                        # 64-bit segment
                        if current_offset + 72 <= len(data):
                            segname = data[current_offset+8:current_offset+24].rstrip(b'\x00')
                            vmaddr = struct.unpack('<Q', data[current_offset+24:current_offset+32])[0]
                            vmsize = struct.unpack('<Q', data[current_offset+32:current_offset+40])[0]
                            fileoff = struct.unpack('<Q', data[current_offset+40:current_offset+48])[0]
                            filesize = struct.unpack('<Q', data[current_offset+48:current_offset+56])[0]
                            nsects = struct.unpack('<I', data[current_offset+64:current_offset+68])[0]
                            
                            if segname == b'__TEXT':
                                # Found __TEXT segment, now look for __text section
                                section_offset = current_offset + 72
                                for i in range(nsects):
                                    if section_offset + 80 <= len(data):
                                        sectname = data[section_offset:section_offset+16].rstrip(b'\x00')
                                        segname = data[section_offset+16:section_offset+32].rstrip(b'\x00')
                                        addr = struct.unpack('<Q', data[section_offset+32:section_offset+40])[0]
                                        size = struct.unpack('<Q', data[section_offset+40:section_offset+48])[0]
                                        offset = struct.unpack('<I', data[section_offset+48:section_offset+52])[0]
                                        
                                        if sectname == b'__text' and segname == b'__TEXT':
                                            return [{
                                                'name': '__TEXT.__text',
                                                'virtual_address': addr,
                                                'file_offset': offset,
                                                'size': size,
                                                'type': 'code'
                                            }]
                                        section_offset += 80
                    elif not is_64bit and cmd == 0x1:
                        # 32-bit segment (simplified)
                        if current_offset + 56 <= len(data):
                            segname = data[current_offset+8:current_offset+24].rstrip(b'\x00')
                            if segname == b'__TEXT':
                                # For simplicity, estimate text section location
                                return [{
                                    'name': '__TEXT.__text',
                                    'virtual_address': 0x1000,
                                    'file_offset': 0x1000,
                                    'size': 0x1000,
                                    'type': 'code'
                                }]
                
                current_offset += cmdsize
                
        except Exception as e:
            print(f"Error parsing Mach-O: {e}")
            
        return []
    
    def _find_elf_text_section(self, data: bytes) -> List[Dict[str, Any]]:
        """Find .text section in ELF binary (simplified)"""
        # Basic ELF parsing would go here
        # For now, return a reasonable default
        return [{
            'name': '.text',
            'virtual_address': 0x401000,
            'file_offset': 0x1000,
            'size': 0x1000,
            'type': 'code'
        }]
    
    def _find_pe_text_section(self, data: bytes) -> List[Dict[str, Any]]:
        """Find .text section in PE binary (simplified)"""
        # Basic PE parsing would go here
        # For now, return a reasonable default
        return [{
            'name': '.text',
            'virtual_address': 0x401000,
            'file_offset': 0x1000,
            'size': 0x1000,
            'type': 'code'
        }]
    
    def _find_code_heuristic(self, data: bytes) -> tuple:
        """Find code using heuristics when format parsing fails"""
        # Look for common instruction patterns starting from different offsets
        potential_offsets = [0x1000, 0x4000, 0x460, 0x800, 0x2000]
        
        for offset in potential_offsets:
            if offset < len(data):
                chunk = data[offset:offset + 512]
                if self._looks_like_code(chunk):
                    return offset, chunk
        
        # If nothing found, default to beginning after headers
        offset = min(0x1000, len(data) // 2)
        return offset, data[offset:offset + 512]
    
    def _looks_like_code(self, data: bytes) -> bool:
        """Heuristic to determine if bytes look like executable code"""
        if len(data) < 16:
            return False
        
        # Count instruction-like patterns
        instruction_bytes = 0
        null_bytes = 0
        
        for i in range(min(len(data), 64)):
            byte = data[i]
            if byte == 0:
                null_bytes += 1
            elif byte in [0x48, 0x49, 0x4a, 0x4b, 0x55, 0x56, 0x57, 0x89, 0x8b, 0xe8, 0xe9, 0x83, 0x81, 0xc3, 0xc2]:
                instruction_bytes += 1
        
        # If more than 30% nulls, probably not code
        if null_bytes > len(data) * 0.3:
            return False
            
        # If we have some instruction-like bytes, it might be code
        return instruction_bytes >= 3

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
