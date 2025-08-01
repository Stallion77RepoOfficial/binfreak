"""
Architecture analysis for disassembly
"""

import struct
from typing import Dict, Any


class ArchitectureAnalyzer:
    """Analyzes binary architecture and format"""
    
    def analyze_architecture(self, binary_data: bytes) -> Dict[str, Any]:
        """Determine binary architecture and format"""
        if len(binary_data) < 64:
            return {'arch': 'unknown', 'format': 'unknown', 'bits': 32}
        
        # ELF detection
        if binary_data[:4] == b'\x7fELF':
            return self._analyze_elf(binary_data)
        
        # PE detection
        elif binary_data[:2] == b'MZ':
            return self._analyze_pe_format(binary_data)
        
        # Mach-O detection
        elif binary_data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                                b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return self._analyze_macho_format(binary_data)
        
        # Raw binary - attempt to detect by instruction patterns
        return self._detect_raw_architecture(binary_data)
    
    def _analyze_elf(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze ELF format"""
        ei_class = binary_data[4]
        ei_data = binary_data[5]
        e_machine = struct.unpack('<H' if ei_data == 1 else '>H', binary_data[18:20])[0]
        
        bits = 64 if ei_class == 2 else 32
        endian = 'little' if ei_data == 1 else 'big'
        
        # Determine architecture
        arch_map = {
            0x3E: 'x86_64',  # AMD64
            0x03: 'x86',     # i386
            0xB7: 'aarch64', # ARM64
            0x28: 'arm',     # ARM
            0xF3: 'riscv',   # RISC-V
        }
        
        arch = arch_map.get(e_machine, 'unknown')
        
        return {
            'format': 'elf',
            'arch': arch,
            'bits': bits,
            'endian': endian,
            'entry_point': self._read_elf_entry_point(binary_data, bits, endian)
        }
    
    def _read_elf_entry_point(self, data: bytes, bits: int, endian: str) -> int:
        """Read ELF entry point"""
        try:
            fmt = '<Q' if endian == 'little' else '>Q' if bits == 64 else '<I' if endian == 'little' else '>I'
            offset = 24 if bits == 64 else 20
            return struct.unpack(fmt, data[offset:offset + (8 if bits == 64 else 4)])[0]
        except:
            return 0x401000  # Default
    
    def _analyze_pe_format(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE format"""
        try:
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            if e_lfanew + 4 < len(data) and data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                machine = struct.unpack('<H', data[e_lfanew+4:e_lfanew+6])[0]
                
                arch_map = {
                    0x014c: 'x86',      # IMAGE_FILE_MACHINE_I386
                    0x8664: 'x86_64',   # IMAGE_FILE_MACHINE_AMD64
                    0x01c0: 'arm',      # IMAGE_FILE_MACHINE_ARM
                    0xaa64: 'aarch64',  # IMAGE_FILE_MACHINE_ARM64
                }
                
                arch = arch_map.get(machine, 'x86')
                bits = 64 if arch in ['x86_64', 'aarch64'] else 32
                
                return {
                    'format': 'pe',
                    'arch': arch,
                    'bits': bits,
                    'endian': 'little'
                }
        except:
            pass
        
        return {'format': 'pe', 'arch': 'x86', 'bits': 32, 'endian': 'little'}
    
    def _analyze_macho_format(self, data: bytes) -> Dict[str, Any]:
        """Analyze Mach-O format"""
        magic = struct.unpack('<I', data[:4])[0]
        
        if magic in [0xfeedface, 0xcefaedfe]:  # 32-bit
            bits = 32
        elif magic in [0xfeedfacf, 0xcffaedfe]:  # 64-bit
            bits = 64
        else:
            bits = 64
        
        # CPU type is at offset 4
        try:
            cpu_type = struct.unpack('<I', data[4:8])[0]
            if cpu_type == 0x01000007:  # CPU_TYPE_X86_64
                arch = 'x86_64'
            elif cpu_type == 0x00000007:  # CPU_TYPE_X86
                arch = 'x86'
            elif cpu_type == 0x0100000c:  # CPU_TYPE_ARM64
                arch = 'aarch64'
            elif cpu_type == 0x0000000c:  # CPU_TYPE_ARM
                arch = 'arm'
            else:
                arch = 'x86_64'
        except:
            arch = 'x86_64'
        
        return {
            'format': 'macho',
            'arch': arch,
            'bits': bits,
            'endian': 'little'
        }
    
    def _detect_raw_architecture(self, data: bytes) -> Dict[str, Any]:
        """Detect architecture from raw binary by instruction patterns"""
        # Look for common x86-64 instruction patterns
        x64_patterns = [
            b'\x48\x89\xe5',  # mov rbp, rsp
            b'\x48\x83\xec',  # sub rsp, imm8
            b'\x48\x8b',      # mov reg, r/m64
            b'\x48\x89',      # mov r/m64, reg
        ]
        
        x86_patterns = [
            b'\x55',          # push ebp
            b'\x89\xe5',      # mov ebp, esp
            b'\x83\xec',      # sub esp, imm8
            b'\x8b\x45',      # mov eax, [ebp+offset]
        ]
        
        arm64_patterns = [
            b'\xfd\x7b\xbf\xa9',  # stp x29, x30, [sp, #-16]!
            b'\xfd\x03\x00\x91',  # mov x29, sp
        ]
        
        # Count pattern matches
        x64_score = sum(data.count(pattern) for pattern in x64_patterns)
        x86_score = sum(data.count(pattern) for pattern in x86_patterns)
        arm64_score = sum(data.count(pattern) for pattern in arm64_patterns)
        
        if x64_score > max(x86_score, arm64_score):
            return {'format': 'raw', 'arch': 'x86_64', 'bits': 64, 'endian': 'little'}
        elif arm64_score > x86_score:
            return {'format': 'raw', 'arch': 'aarch64', 'bits': 64, 'endian': 'little'}
        else:
            return {'format': 'raw', 'arch': 'x86', 'bits': 32, 'endian': 'little'}
