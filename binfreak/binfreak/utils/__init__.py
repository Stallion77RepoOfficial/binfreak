"""
Utility functions and helper classes
"""

import os
import hashlib
import struct
import time
from typing import List, Dict, Any, Optional, Union, Tuple


class FileUtils:
    """File handling utilities"""
    
    @staticmethod
    def read_file_chunks(file_path: str, chunk_size: int = 8192) -> bytes:
        """Read file in chunks"""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return b''
    
    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return ""
    
    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get comprehensive file information"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'modified': time.ctime(stat.st_mtime),
                'created': time.ctime(stat.st_ctime),
                'permissions': oct(stat.st_mode)[-3:],
                'is_executable': os.access(file_path, os.X_OK)
            }
        except Exception as e:
            print(f"Error getting file info: {e}")
            return {}


class BinaryUtils:
    """Binary data manipulation utilities"""
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate entropy of binary data"""
        if not data:
            return 0.0
        
        # Count frequency of each byte value
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_length = len(data)
        
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_length
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    @staticmethod
    def find_patterns(data: bytes, pattern: bytes) -> List[int]:
        """Find all occurrences of a pattern in binary data"""
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions
    
    @staticmethod
    def unpack_data(data: bytes, format_string: str, offset: int = 0) -> Tuple:
        """Safely unpack binary data"""
        try:
            struct_size = struct.calcsize(format_string)
            if offset + struct_size > len(data):
                return None
            return struct.unpack(format_string, data[offset:offset + struct_size])
        except struct.error:
            return None


class FormatUtils:
    """Data formatting utilities"""
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """Format byte size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    @staticmethod
    def format_hex_dump(data: bytes, start_offset: int = 0, bytes_per_line: int = 16) -> str:
        """Format binary data as hex dump"""
        lines = []
        
        for i in range(0, len(data), bytes_per_line):
            # Offset
            offset = start_offset + i
            offset_str = f"{offset:08x}"
            
            # Hex bytes
            chunk = data[i:i + bytes_per_line]
            hex_str = ' '.join(f"{b:02x}" for b in chunk)
            hex_str = hex_str.ljust(bytes_per_line * 3 - 1)
            
            # ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            lines.append(f"{offset_str}  {hex_str}  |{ascii_str}|")
        
        return '\n'.join(lines)
    
    @staticmethod
    def format_address(address: int, bits: int = 64) -> str:
        """Format memory address"""
        if bits == 64:
            return f"0x{address:016x}"
        else:
            return f"0x{address:08x}"


class ValidationUtils:
    """Data validation utilities"""
    
    @staticmethod
    def is_valid_pe_file(data: bytes) -> bool:
        """Check if data is a valid PE file"""
        if len(data) < 64:
            return False
        
        # Check DOS header
        if data[:2] != b'MZ':
            return False
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', data[60:64])[0]
        if pe_offset >= len(data) - 4:
            return False
        
        # Check PE signature
        return data[pe_offset:pe_offset + 4] == b'PE\x00\x00'
    
    @staticmethod
    def is_valid_elf_file(data: bytes) -> bool:
        """Check if data is a valid ELF file"""
        if len(data) < 16:
            return False
        
        # Check ELF magic
        return data[:4] == b'\x7fELF'
    
    @staticmethod
    def is_valid_macho_file(data: bytes) -> bool:
        """Check if data is a valid Mach-O file"""
        if len(data) < 4:
            return False
        
        # Check Mach-O magic numbers
        magic = struct.unpack('<I', data[:4])[0]
        return magic in [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe]


class PerformanceUtils:
    """Performance monitoring utilities"""
    
    @staticmethod
    def time_operation(func, *args, **kwargs):
        """Time a function execution"""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        return result, end_time - start_time
    
    @staticmethod
    def memory_usage():
        """Get current memory usage (simplified)"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0


class ConfigUtils:
    """Configuration management utilities"""
    
    @staticmethod
    def load_config(config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            import json
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    @staticmethod
    def save_config(config: Dict[str, Any], config_path: str) -> bool:
        """Save configuration to file"""
        try:
            import json
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_default_config() -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'analysis': {
                'max_strings': 10000,
                'min_string_length': 4,
                'entropy_block_size': 256,
                'function_detection_threshold': 0.8
            },
            'gui': {
                'theme': 'dark',
                'font_size': 10,
                'auto_save': True,
                'max_tabs': 10
            },
            'fuzzing': {
                'timeout': 60,
                'max_iterations': 100000,
                'corpus_size': 100
            }
        }
