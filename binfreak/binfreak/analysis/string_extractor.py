"""
String extraction module for binary analysis
"""

from typing import List


class StringExtractor:
    """Extracts strings from binary data with multiple encoding support"""
    
    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Enhanced string extraction with multiple encodings"""
        strings = []
        
        # ASCII strings
        ascii_strings = self._extract_ascii_strings(data, min_length)
        strings.extend(ascii_strings)
        
        # UTF-16 strings (Windows)
        utf16_strings = self._extract_utf16_strings(data, min_length)
        strings.extend(utf16_strings)
        
        # UTF-8 strings
        utf8_strings = self._extract_utf8_strings(data, min_length)
        strings.extend(utf8_strings)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen and len(s.strip()) >= min_length:
                seen.add(s)
                unique_strings.append(s)
        
        return unique_strings
    
    def _extract_ascii_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract ASCII strings"""
        strings = []
        current = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += chr(byte)
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""
        
        if len(current) >= min_length:
            strings.append(current)
        
        return strings
    
    def _extract_utf16_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract UTF-16 strings (common in Windows binaries)"""
        strings = []
        
        # Try both little-endian and big-endian
        for encoding in ['utf-16le', 'utf-16be']:
            try:
                # Decode in chunks
                i = 0
                current = ""
                
                while i < len(data) - 1:
                    try:
                        char_bytes = data[i:i+2]
                        char = char_bytes.decode(encoding)
                        
                        if char.isprintable() and not char.isspace():
                            current += char
                        elif char.isspace() and current:
                            current += char
                        else:
                            if len(current.strip()) >= min_length:
                                strings.append(current.strip())
                            current = ""
                        
                        i += 2
                    except UnicodeDecodeError:
                        if len(current.strip()) >= min_length:
                            strings.append(current.strip())
                        current = ""
                        i += 1
                
                if len(current.strip()) >= min_length:
                    strings.append(current.strip())
                    
            except Exception:
                continue
        
        return strings
    
    def _extract_utf8_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract UTF-8 strings"""
        strings = []
        
        try:
            # Try to decode as UTF-8
            text = data.decode('utf-8', errors='ignore')
            current = ""
            
            for char in text:
                if char.isprintable():
                    current += char
                else:
                    if len(current.strip()) >= min_length:
                        strings.append(current.strip())
                    current = ""
            
            if len(current.strip()) >= min_length:
                strings.append(current.strip())
                
        except Exception:
            pass
        
        return strings
    
    def extract_printable_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings with position information"""
        strings_with_pos = []
        current = ""
        start_pos = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current:
                    start_pos = i
                current += chr(byte)
            else:
                if len(current) >= min_length:
                    strings_with_pos.append({
                        'string': current,
                        'offset': start_pos,
                        'length': len(current)
                    })
                current = ""
        
        if len(current) >= min_length:
            strings_with_pos.append({
                'string': current,
                'offset': start_pos,
                'length': len(current)
            })
        
        return [item['string'] for item in strings_with_pos]
