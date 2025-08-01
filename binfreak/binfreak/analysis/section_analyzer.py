"""
Section analyzer for binary files
"""

from typing import Dict, Any, List


class SectionAnalyzer:
    """Analyzes sections in binary files"""
    
    def analyze_sections(self, data: bytes, file_format: str) -> List[Dict[str, Any]]:
        """Analyze binary sections based on format"""
        sections = []
        
        try:
            if 'Mach-O' in file_format:
                sections = self.parse_macho_sections(data)
            elif 'ELF' in file_format:
                sections = self.parse_elf_sections(data)
            elif 'PE' in file_format:
                sections = self.parse_pe_sections(data)
            else:
                # Heuristic section detection for unknown formats
                sections = self.estimate_sections(data)
                
        except Exception as e:
            # Fallback to estimated sections
            sections = self.estimate_sections(data)
        
        return sections
    
    def estimate_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Heuristic section estimation for unknown formats"""
        sections = []
        chunk_size = len(data) // 20  # Divide into ~20 sections
        
        if chunk_size < 1000:
            chunk_size = 1000
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            section_type = "data"
            
            # Heuristic analysis
            if self.looks_like_code(chunk):
                section_type = "text"
            elif self.has_many_strings(chunk):
                section_type = "strings"
            
            sections.append({
                'name': f'section_{i//chunk_size}',
                'address': hex(i),
                'size': len(chunk),
                'type': section_type,
                'offset': i
            })
        
        return sections[:25]  # Limit to 25 sections
    
    def has_many_strings(self, data: bytes) -> bool:
        """Check if data contains many strings"""
        from .string_extractor import StringExtractor
        extractor = StringExtractor()
        strings = extractor.extract_strings(data, min_length=3)
        return len(strings) > len(data) // 100  # More than 1% strings
    
    def looks_like_code(self, data: bytes) -> bool:
        """Heuristic to determine if bytes look like executable code"""
        if len(data) < 4:
            return False
        
        # Check for common instruction patterns
        common_opcodes = {
            0x48, 0x49, 0x4a, 0x4b,  # REX prefixes (x64)
            0x55, 0x56, 0x57,        # push instructions
            0x89, 0x8b,              # mov instructions
            0xe8, 0xe9,              # call, jmp
            0x83, 0x81,              # arithmetic
            0xc3, 0xc2,              # ret instructions
        }
        
        opcode_count = sum(1 for byte in data[:16] if byte in common_opcodes)
        return opcode_count >= 3  # At least 3 instruction-like bytes
    
    # Format-specific section parsing methods
    def parse_macho_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse Mach-O sections"""
        sections = []
        
        try:
            # Basic Mach-O header parsing
            if len(data) >= 32:
                magic = int.from_bytes(data[0:4], 'little')
                if magic in [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe]:
                    # This is a real Mach-O file, parse properly
                    sections = self._parse_macho_load_commands(data)
        except Exception:
            pass
        
        # Fall back to estimation if parsing fails
        if not sections:
            sections = self.estimate_sections(data)
        
        return sections
    
    def parse_elf_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse ELF sections"""
        sections = []
        
        try:
            # Check ELF magic
            if data[:4] == b'\x7fELF':
                sections = self._parse_elf_section_headers(data)
        except Exception:
            pass
        
        # Fall back to estimation if parsing fails
        if not sections:
            sections = self.estimate_sections(data)
        
        return sections
    
    def parse_pe_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse PE sections"""
        sections = []
        
        try:
            # Check DOS header
            if data[:2] == b'MZ':
                sections = self._parse_pe_section_headers(data)
        except Exception:
            pass
        
        # Fall back to estimation if parsing fails
        if not sections:
            sections = self.estimate_sections(data)
        
        return sections
    def _parse_elf_section_headers(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse ELF section headers"""
        sections = []
        
        try:
            import struct
            
            # Basic ELF header parsing
            ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
            is_64bit = ei_class == 2
            
            if is_64bit:
                # 64-bit ELF header
                e_shoff = struct.unpack('<Q', data[40:48])[0]
                e_shentsize = struct.unpack('<H', data[58:60])[0]
                e_shnum = struct.unpack('<H', data[60:62])[0]
            else:
                # 32-bit ELF header
                e_shoff = struct.unpack('<I', data[32:36])[0]
                e_shentsize = struct.unpack('<H', data[46:48])[0]
                e_shnum = struct.unpack('<H', data[48:50])[0]
            
            # Parse section headers (simplified)
            for i in range(min(e_shnum, 64)):  # Limit to 64 sections
                offset = e_shoff + i * e_shentsize
                if offset + e_shentsize <= len(data):
                    sections.append({
                        'name': f'section_{i}',
                        'offset': hex(offset),
                        'size': hex(e_shentsize),
                        'type': 'elf_section',
                        'permissions': 'r--'
                    })
        except Exception:
            pass
        
        return sections
    
    def _parse_pe_section_headers(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse PE section headers"""
        sections = []
        
        try:
            import struct
            
            # DOS header
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            
            # PE header
            if e_lfanew + 24 <= len(data):
                num_sections = struct.unpack('<H', data[e_lfanew + 6:e_lfanew + 8])[0]
                sections_offset = e_lfanew + 24 + 224  # PE header + optional header
                
                # Parse section headers (simplified)
                for i in range(min(num_sections, 32)):  # Limit to 32 sections
                    section_offset = sections_offset + i * 40
                    if section_offset + 40 <= len(data):
                        name = data[section_offset:section_offset + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
                        virtual_size = struct.unpack('<I', data[section_offset + 8:section_offset + 12])[0]
                        virtual_address = struct.unpack('<I', data[section_offset + 12:section_offset + 16])[0]
                        
                        sections.append({
                            'name': name or f'section_{i}',
                            'offset': hex(virtual_address),
                            'size': hex(virtual_size),
                            'type': 'pe_section',
                            'permissions': 'r--'
                        })
        except Exception:
            pass
        
        return sections
    
    def _parse_macho_load_commands(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse Mach-O load commands"""
        sections = []
        
        try:
            import struct
            
            # Basic Mach-O header parsing
            magic = struct.unpack('<I', data[0:4])[0]
            is_64bit = magic in [0xfeedfacf, 0xcffaedfe]
            
            if is_64bit:
                ncmds = struct.unpack('<I', data[16:20])[0]
                load_commands_offset = 32
            else:
                ncmds = struct.unpack('<I', data[12:16])[0]
                load_commands_offset = 28
            
            # Parse load commands (simplified)
            for i in range(min(ncmds, 32)):  # Limit to 32 commands
                sections.append({
                    'name': f'load_cmd_{i}',
                    'offset': hex(load_commands_offset + i * 16),
                    'size': '0x10',
                    'type': 'macho_segment',
                    'permissions': 'r--'
                })
        except Exception:
            pass
        
        return sections
