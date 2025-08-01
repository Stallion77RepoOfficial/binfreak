"""
Binary format detection module
"""

import struct
from typing import Dict, Any


class FormatDetector:
    """Detects binary file formats with comprehensive support"""
    
    def detect_format(self, data: bytes) -> str:
        """Enhanced binary format detection with comprehensive support"""
        if len(data) < 4:
            return 'Unknown (too small)'
        
        # ELF (Linux, Android, BSD)
        if data.startswith(b'\x7fELF'):
            return self._analyze_elf(data)
        
        # PE/COFF (Windows)
        if data.startswith(b'MZ'):
            return self._analyze_pe(data)
        
        # Mach-O (macOS, iOS)
        mach_o_result = self._analyze_macho(data)
        if mach_o_result:
            return mach_o_result
        
        # Java Class files
        if data.startswith(b'\xca\xfe\xba\xbe') and len(data) > 8:
            major_version = struct.unpack('>H', data[6:8])[0]
            return f'Java Class (version {major_version})'
        
        # A.OUT (old Unix)
        aout_result = self._analyze_aout(data)
        if aout_result:
            return aout_result
        
        # Archive formats
        archive_result = self._analyze_archives(data)
        if archive_result:
            return archive_result
        
        # Script files
        if data.startswith(b'#!'):
            shebang_line = data.split(b'\n')[0][:50]
            return f'Script ({shebang_line.decode("utf-8", errors="ignore")})'
        
        # Other formats
        other_result = self._analyze_other_formats(data)
        if other_result:
            return other_result
        
        # Fallback analysis
        return self._fallback_analysis(data)
    
    def _analyze_elf(self, data: bytes) -> str:
        """Analyze ELF format"""
        ei_class = data[4] if len(data) > 4 else 0
        ei_data = data[5] if len(data) > 5 else 0
        arch = "32-bit" if ei_class == 1 else "64-bit" if ei_class == 2 else "unknown"
        endian = "little-endian" if ei_data == 1 else "big-endian" if ei_data == 2 else "unknown"
        return f'ELF ({arch}, {endian})'
    
    def _analyze_pe(self, data: bytes) -> str:
        """Analyze PE format"""
        if len(data) > 60:
            pe_offset = struct.unpack('<I', data[60:64])[0] if len(data) >= 64 else 0
            if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+2] == b'PE':
                # Get machine type
                if pe_offset + 6 < len(data):
                    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                    arch_map = {
                        0x014c: "i386",
                        0x0200: "ia64", 
                        0x8664: "x86-64",
                        0x01c0: "ARM",
                        0xaa64: "ARM64"
                    }
                    arch = arch_map.get(machine, f"unknown-{machine:04x}")
                    return f'PE ({arch})'
                return 'PE (unknown arch)'
        return 'MZ (DOS executable)'
    
    def _analyze_macho(self, data: bytes) -> str:
        """Analyze Mach-O format"""
        mach_o_signatures = [
            (b'\xfe\xed\xfa\xce', 'Mach-O 32-bit (big-endian)'),
            (b'\xce\xfa\xed\xfe', 'Mach-O 32-bit (little-endian)'),
            (b'\xfe\xed\xfa\xcf', 'Mach-O 64-bit (big-endian)'),
            (b'\xcf\xfa\xed\xfe', 'Mach-O 64-bit (little-endian)'),
            (b'\xca\xfe\xba\xbe', 'Mach-O Fat Binary (big-endian)'),
            (b'\xbe\xba\xfe\xca', 'Mach-O Fat Binary (little-endian)')
        ]
        
        for signature, description in mach_o_signatures:
            if data.startswith(signature):
                return description
        return None
    
    def _analyze_aout(self, data: bytes) -> str:
        """Analyze A.OUT format"""
        if len(data) >= 4:
            magic = struct.unpack('<I', data[:4])[0]
            aout_magics = {
                0x010b: 'A.OUT (OMAGIC)',
                0x020b: 'A.OUT (NMAGIC)', 
                0x030b: 'A.OUT (ZMAGIC)',
                0x040b: 'A.OUT (QMAGIC)'
            }
            return aout_magics.get(magic)
        return None
    
    def _analyze_archives(self, data: bytes) -> str:
        """Analyze archive formats"""
        if data.startswith(b'!<arch>\n'):
            return 'AR Archive'
        if data.startswith(b'PK\x03\x04') or data.startswith(b'PK\x05\x06'):
            return 'ZIP Archive'
        if data.startswith(b'\x1f\x8b'):
            return 'GZIP Archive'
        if data.startswith(b'BZ'):
            return 'BZIP2 Archive'
        return None
    
    def _analyze_other_formats(self, data: bytes) -> str:
        """Analyze other common formats"""
        signatures = {
            b'\x50\x4b': 'ZIP-based',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89\x50\x4e\x47': 'PNG Image',
            b'GIF8': 'GIF Image',
            b'\x00\x00\x01\x00': 'ICO Image',
            b'RIFF': 'RIFF (AVI/WAV)',
            b'\x1f\x9d': 'LZW Compressed',
            b'\x1f\xa0': 'LZH Compressed',
        }
        
        for sig, desc in signatures.items():
            if data.startswith(sig):
                return desc
        return None
    
    def _fallback_analysis(self, data: bytes) -> str:
        """Fallback analysis for unknown formats"""
        from .entropy_calculator import EntropyCalculator
        calculator = EntropyCalculator()
        entropy = calculator.calculate_entropy(data[:1024])  # Check first 1KB
        
        if entropy > 7.5:
            return 'Unknown (possibly packed/encrypted)'
        elif entropy < 1.0:
            return 'Unknown (possibly sparse/zero-filled)'
        
        # Check if it looks like text
        try:
            sample = data[:512].decode('utf-8')
            if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in sample):
                return 'Text file'
        except:
            pass
        
        return f'Unknown binary (entropy: {entropy:.2f})'
