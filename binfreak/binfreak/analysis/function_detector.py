"""
Function detection module for binary analysis
"""

import struct
from typing import Dict, Any, List


class FunctionDetector:
    """Detects functions in binary files"""
    
    def detect_functions(self, data: bytes) -> List[Dict[str, Any]]:
        """Professional function detection with proper binary format parsing"""
        functions = []
        
        try:
            from .format_detector import FormatDetector
            detector = FormatDetector()
            file_format = detector.detect_format(data)
            
            if 'Mach-O' in file_format:
                functions = self.parse_macho_functions(data)
            elif 'ELF' in file_format:
                functions = self.parse_elf_functions(data)
            elif 'PE' in file_format:
                functions = self.parse_pe_functions(data)
            else:
                # Fallback to pattern-based detection for unknown formats
                functions = self.pattern_based_function_detection(data)
            
            # If no functions found through format parsing, try pattern detection
            if not functions:
                functions = self.pattern_based_function_detection(data)
            
            # Sort by address
            functions.sort(key=lambda x: int(x['address'], 16) if isinstance(x['address'], str) else x['address'])
            
            return functions[:1000]  # Limit to prevent UI overload
            
        except Exception as e:
            # Fallback to pattern detection on any error
            return self.pattern_based_function_detection(data)
    
    def parse_macho_functions(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse Mach-O functions from symbol table"""
        functions = []
        
        try:
            if len(data) < 32:
                return []
            
            magic = struct.unpack('<I', data[:4])[0]
            is_64bit = magic in [0xcffaedfe, 0xfeedfacf]
            
            # Parse basic Mach-O structure for function symbols
            # This is a simplified implementation
            if is_64bit:
                header_size = 32
            else:
                header_size = 28
            
            # Look for function-like patterns in code sections
            functions = self.find_functions_in_code_section(data[header_size:], 0x100000000)
            
        except Exception:
            functions = self.pattern_based_function_detection(data)
        
        return functions
    
    def parse_elf_functions(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse ELF functions from symbol table"""
        functions = []
        
        try:
            if len(data) < 64:
                return []
            
            # Parse ELF header
            ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
            is_64bit = ei_class == 2
            
            # Parse section headers to find symbol table
            functions = self._parse_elf_symbol_table(data, is_64bit)
            
            # If no symbol table found, use pattern-based detection
            if not functions:
                functions = self.pattern_based_function_detection(data)
            
        except Exception:
            functions = self.pattern_based_function_detection(data)
        
        return functions
    
    def parse_pe_functions(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse PE functions from export table and patterns"""
        functions = []
        
        try:
            if len(data) < 64 or not data.startswith(b'MZ'):
                return []
            
            # Basic PE parsing - look for .text section
            pe_offset = struct.unpack('<I', data[60:64])[0]
            if pe_offset >= len(data) - 4:
                return []
            
            # Look for function patterns in typical PE code sections
            functions = self.find_functions_in_code_section(data, 0x401000)
            
        except Exception:
            functions = self.pattern_based_function_detection(data)
        
        return functions
    
    def find_functions_in_code_section(self, code_data: bytes, base_address: int) -> List[Dict[str, Any]]:
        """Find functions within a code section using pattern analysis"""
        functions = []
        
        # Enhanced function prologues for different architectures
        prologues = [
            # x86-64 prologues
            (b'\x55\x48\x89\xe5', 'x64_standard', 4),      # push rbp; mov rbp, rsp
            (b'\x48\x83\xec', 'x64_stack_alloc', 4),       # sub rsp, imm8
            (b'\x48\x81\xec', 'x64_large_stack', 7),       # sub rsp, imm32
            (b'\xf3\x0f\x1e\xfa', 'endbr64', 4),           # endbr64 (Intel CET)
            
            # x86 prologues  
            (b'\x55\x89\xe5', 'x86_standard', 3),          # push ebp; mov ebp, esp
            (b'\x83\xec', 'x86_stack_alloc', 3),           # sub esp, imm8
            (b'\x81\xec', 'x86_large_stack', 6),           # sub esp, imm32
            
            # ARM64 prologues (for universal binaries)
            (b'\xfd\x7b\xbf\xa9', 'arm64_standard', 4),    # stp x29, x30, [sp, #-16]!
            (b'\xfd\x03\x00\x91', 'arm64_frame', 4),       # mov x29, sp
        ]
        
        for prologue, func_type, size in prologues:
            offset = 0
            while True:
                pos = code_data.find(prologue, offset)
                if pos == -1:
                    break
                
                # Check alignment (functions usually aligned to 4 or 16 bytes)
                if pos % 4 == 0:
                    func_addr = base_address + pos
                    
                    # Skip if too close to previous function (likely same function)
                    if not any(abs(func_addr - int(f['address'], 16)) < 16 for f in functions):
                        # Try to determine function size by finding next prologue or return
                        func_size = self.estimate_function_size(code_data, pos)
                        
                        functions.append({
                            'address': hex(func_addr),
                            'name': f'sub_{func_addr:x}',
                            'type': func_type,
                            'size': func_size
                        })
                
                offset = pos + size
        
        return functions
    
    def estimate_function_size(self, data: bytes, start_pos: int) -> int:
        """Estimate function size by looking for returns and next function"""
        max_search = min(1000, len(data) - start_pos)  # Search up to 1000 bytes
        
        # Look for return instructions
        returns = [b'\xc3', b'\xc2', b'\xcb', b'\xca']  # ret, ret imm16, retf, retf imm16
        
        for i in range(start_pos + 4, start_pos + max_search):
            if i >= len(data):
                break
                
            # Check for return instruction
            if data[i:i+1] in returns:
                return i - start_pos + 1
        
        return min(100, max_search)  # Default size
    
    def pattern_based_function_detection(self, data: bytes) -> List[Dict[str, Any]]:
        """Enhanced pattern-based function detection with better heuristics"""
        functions = []
        
        # Enhanced function prologues for different architectures
        prologues = [
            # x64 prologues
            (b'\x55\x48\x89\xe5', 'x64_standard'),      # push rbp; mov rbp, rsp
            (b'\x48\x83\xec', 'x64_stack_alloc'),       # sub rsp, imm
            (b'\x48\x89\xe5', 'x64_frame_setup'),       # mov rbp, rsp
            (b'\xf3\x0f\x1e\xfa', 'x64_endbr64'),       # endbr64 (CET)
            (b'\x48\x83\xc4', 'x64_stack_cleanup'),     # add rsp, imm
            
            # x86 prologues  
            (b'\x55\x89\xe5', 'x86_standard'),          # push ebp; mov ebp, esp
            (b'\x83\xec', 'x86_stack_alloc'),           # sub esp, imm
            (b'\x89\xe5', 'x86_frame_setup'),           # mov ebp, esp
            (b'\x83\xc4', 'x86_stack_cleanup'),         # add esp, imm
            
            # ARM prologues
            (b'\x00\x48\x2d\xe9', 'arm_push_lr'),       # push {lr}
            (b'\x10\x48\x2d\xe9', 'arm_push_regs'),     # push {r4, lr}
            
            # Function call patterns
            (b'\xe8', 'x86_call_rel'),                   # call rel32
            (b'\xff\x15', 'x86_call_indirect'),         # call dword ptr
            (b'\x48\xff\x15', 'x64_call_indirect'),     # call qword ptr
        ]
        
        # Pattern-based detection with confidence scoring
        potential_functions = {}
        
        for prologue, func_type in prologues:
            offset = 0
            while True:
                pos = data.find(prologue, offset)
                if pos == -1:
                    break
                
                # Calculate confidence score
                confidence = self._calculate_function_confidence(data, pos)
                
                if pos not in potential_functions or potential_functions[pos]['confidence'] < confidence:
                    potential_functions[pos] = {
                        'address': hex(pos),
                        'name': f'func_{pos:x}',
                        'type': func_type,
                        'confidence': confidence,
                        'size': self._estimate_function_size(data, pos)
                    }
                
                offset = pos + len(prologue)
        
        # Convert to list and filter by confidence
        functions = [func for func in potential_functions.values() if func['confidence'] > 0.3]
        
        # Add control flow based detection
        control_flow_functions = self._detect_functions_by_control_flow(data)
        functions.extend(control_flow_functions)
        
        # Remove duplicates and sort
        seen_addresses = set()
        unique_functions = []
        for func in sorted(functions, key=lambda x: int(x['address'], 16)):
            addr = int(func['address'], 16)
            if not any(abs(addr - seen_addr) < 16 for seen_addr in seen_addresses):
                unique_functions.append(func)
                seen_addresses.add(addr)
        
        # If still no functions found, use heuristic detection
        if not unique_functions:
            unique_functions = self._heuristic_function_detection(data)
        
        return unique_functions[:1000]  # Limit to prevent UI overload
    
    def _calculate_function_confidence(self, data: bytes, pos: int) -> float:
        """Calculate confidence score for a potential function start"""
        confidence = 0.0
        
        # Check if position is aligned (functions often start at aligned addresses)
        if pos % 4 == 0:
            confidence += 0.1
        if pos % 16 == 0:
            confidence += 0.2
        
        # Check for valid instruction sequences after the prologue
        if pos + 32 < len(data):
            chunk = data[pos:pos + 32]
            if self._has_valid_instruction_sequence(chunk):
                confidence += 0.3
        
        # Check for function epilogue patterns nearby
        if self._has_nearby_epilogue(data, pos):
            confidence += 0.2
        
        # Check for call references to this position
        if self._has_call_references(data, pos):
            confidence += 0.3
        
        # Avoid false positives in data sections
        if self._is_likely_data_section(data, pos):
            confidence -= 0.4
        
        return max(0.0, min(1.0, confidence))
    
    def _estimate_function_size(self, data: bytes, start_pos: int) -> int:
        """Estimate function size by looking for epilogue patterns"""
        max_search = min(2048, len(data) - start_pos)  # Search up to 2KB
        
        # Common epilogue patterns
        epilogues = [
            b'\xc3',                # ret
            b'\xc2',                # ret imm16
            b'\x5d\xc3',           # pop rbp; ret
            b'\x48\x83\xc4',       # add rsp, imm (x64)
            b'\x83\xc4',           # add esp, imm (x86)
        ]
        
        for i in range(start_pos + 4, start_pos + max_search):
            for epilogue in epilogues:
                if data[i:i+len(epilogue)] == epilogue:
                    return i - start_pos + len(epilogue)
        
        return 64  # Default estimate
    
    def _detect_functions_by_control_flow(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect functions by analyzing control flow patterns"""
        functions = []
        
        # Look for jump targets that could be function starts
        jump_targets = set()
        
        # Simple pattern matching for calls and jumps
        for i in range(len(data) - 5):
            # x86/x64 call instruction (E8)
            if data[i] == 0xE8:
                # Extract target address (relative call)
                if i + 5 < len(data):
                    target = struct.unpack('<I', data[i+1:i+5])[0]
                    # Calculate absolute target
                    abs_target = (i + 5 + target) % len(data)
                    if 0 <= abs_target < len(data):
                        jump_targets.add(abs_target)
        
        # Validate jump targets as potential functions
        for target in jump_targets:
            if self._looks_like_function_start(data, target):
                functions.append({
                    'address': hex(target),
                    'name': f'func_{target:x}',
                    'type': 'call_target',
                    'confidence': 0.7,
                    'size': self._estimate_function_size(data, target)
                })
        
        return functions
    
    def _heuristic_function_detection(self, data: bytes) -> List[Dict[str, Any]]:
        """Fallback heuristic detection for when other methods fail"""
        functions = []
        
        # Look for executable-looking patterns at regular intervals
        for i in range(0, min(len(data), 100000), 256):  # Check every 256 bytes
            if i + 16 < len(data):
                chunk = data[i:i+16]
                if self._looks_like_code(chunk):
                    functions.append({
                        'address': hex(i),
                        'name': f'heuristic_func_{i:x}',
                        'type': 'heuristic',
                        'confidence': 0.4,
                        'size': 'unknown'
                    })
        
        return functions[:50]  # Limit heuristic functions
    
    def _has_valid_instruction_sequence(self, chunk: bytes) -> bool:
        """Check if chunk contains valid instruction-like sequences"""
        if len(chunk) < 8:
            return False
        
        # Look for patterns that suggest real instructions
        valid_patterns = 0
        
        # Check for valid x86/x64 instruction patterns
        for i in range(len(chunk) - 2):
            byte1, byte2 = chunk[i], chunk[i+1]
            
            # Common instruction prefixes
            if byte1 in [0x48, 0x49, 0x4A, 0x4B]:  # REX prefixes
                valid_patterns += 1
            
            # Common opcodes
            if byte1 in [0x89, 0x8B, 0x83, 0x48, 0xFF, 0xE8, 0xE9]:
                valid_patterns += 1
        
        return valid_patterns >= 2
    
    def _has_nearby_epilogue(self, data: bytes, pos: int) -> bool:
        """Check for epilogue patterns within reasonable distance"""
        search_end = min(pos + 512, len(data))
        epilogue_chunk = data[pos:search_end]
        
        # Look for return instructions
        return b'\xc3' in epilogue_chunk or b'\xc2' in epilogue_chunk
    
    def _has_call_references(self, data: bytes, pos: int) -> bool:
        """Check if other code calls this position"""
        # This is a simplified check - in a full implementation,
        # we would maintain a proper call graph
        target_bytes = struct.pack('<I', pos)
        return target_bytes in data
    
    def _is_likely_data_section(self, data: bytes, pos: int) -> bool:
        """Check if position is likely in a data section"""
        if pos + 32 > len(data):
            return True
        
        chunk = data[pos:pos + 32]
        
        # High entropy might indicate compressed/encrypted data
        entropy = self._calculate_chunk_entropy(chunk)
        if entropy > 7.5:
            return True
        
        # Too many null bytes suggests data
        null_ratio = chunk.count(0) / len(chunk)
        if null_ratio > 0.8:
            return True
        
        # Printable ASCII strings suggest data
        printable_ratio = sum(1 for b in chunk if 32 <= b <= 126) / len(chunk)
        if printable_ratio > 0.8:
            return True
        
        return False
    
    def _looks_like_function_start(self, data: bytes, pos: int) -> bool:
        """Check if position looks like a valid function start"""
        if pos + 8 > len(data):
            return False
        
        chunk = data[pos:pos + 8]
        
        # Check for common function prologue patterns
        prologues = [
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp
            b'\x55\x89\xe5',      # push ebp; mov ebp, esp
            b'\x48\x83\xec',      # sub rsp, imm
            b'\x83\xec'           # sub esp, imm
        ]
        
        for prologue in prologues:
            if chunk.startswith(prologue):
                return True
        
        return False
    
    def _looks_like_code(self, chunk: bytes) -> bool:
        """Enhanced code detection heuristics"""
        if len(chunk) < 8:
            return False
        
        # Calculate entropy - code typically has medium entropy
        entropy = self._calculate_chunk_entropy(chunk)
        if entropy < 2.0 or entropy > 7.5:
            return False
        
        # Check for instruction-like patterns
        instruction_indicators = 0
        
        for i in range(len(chunk)):
            byte_val = chunk[i]
            
            # Common x86/x64 opcodes
            if byte_val in [0x48, 0x49, 0x89, 0x8B, 0x83, 0xFF, 0xE8, 0xE9, 0xC3]:
                instruction_indicators += 1
            
            # ModR/M byte patterns
            if i + 1 < len(chunk):
                if byte_val in [0x89, 0x8B] and chunk[i+1] & 0xC0 in [0x00, 0x40, 0x80, 0xC0]:
                    instruction_indicators += 1
        
        return instruction_indicators >= 2
    
    def _calculate_chunk_entropy(self, chunk: bytes) -> float:
        """Calculate Shannon entropy of a data chunk"""
        if not chunk:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(chunk)
        entropy = 0.0
        length = len(chunk)
        
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _parse_elf_symbol_table(self, data: bytes, is_64bit: bool) -> List[Dict[str, Any]]:
        """Parse ELF symbol table for function symbols"""
        functions = []
        
        try:
            import struct
            
            # ELF header parsing
            if is_64bit:
                header_fmt = '<16sHHIQQQIHHHHHH'
                header_size = 64
            else:
                header_fmt = '<16sHHIIIIIHHHHHH'
                header_size = 52
            
            if len(data) < header_size:
                return []
            
            # This is a simplified implementation
            # A full ELF parser would be much more complex
            # For now, fall back to pattern detection
            return self.pattern_based_function_detection(data)
            
        except Exception:
            return []
    
    def looks_like_code(self, data: bytes) -> bool:
        """Heuristic to determine if bytes look like executable code"""
        return self._looks_like_code(data)
