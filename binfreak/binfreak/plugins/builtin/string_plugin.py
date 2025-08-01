"""
String Analysis Plugin - Advanced string extraction and analysis
"""

import re
from typing import Dict, Any, List
from abc import ABC, abstractmethod


class BasePlugin(ABC):
    """Base class for all BinFreak plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = "A BinFreak plugin"
        self.enabled = True
        self.dependencies = []
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'enabled': self.enabled,
            'dependencies': self.dependencies
        }
    
    def enable(self):
        """Enable the plugin"""
        self.enabled = True
    
    def disable(self):
        """Disable the plugin"""
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled


class AnalysisPlugin(BasePlugin):
    """Base class for analysis plugins"""
    
    @abstractmethod
    def analyze(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze binary data and return results
        
        Args:
            binary_data: Raw binary data
            file_info: Basic file information (path, size, format, etc.)
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported binary formats"""
        pass
    
    def can_analyze(self, file_info: Dict[str, Any]) -> bool:
        """Check if this plugin can analyze the given file"""
        file_format = file_info.get('format', {}).get('type', 'Unknown')
        supported = self.get_supported_formats()
        return any(fmt.lower() in file_format.lower() for fmt in supported) if supported else True


class StringAnalysisPlugin(AnalysisPlugin):
    """Advanced string extraction and analysis plugin"""
    
    def __init__(self):
        super().__init__()
        self.name = "String Analyzer"
        self.version = "1.0.0"
        self.author = "BinFreak Team"
        self.description = "Advanced string extraction and analysis with pattern detection"
    
    def get_info(self) -> Dict[str, Any]:
        return super().get_info()
    
    def analyze(self, binary_data: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform advanced string analysis"""
        try:
            # Extract different types of strings
            ascii_strings = self._extract_ascii_strings(binary_data)
            unicode_strings = self._extract_unicode_strings(binary_data)
            url_patterns = self._find_urls(ascii_strings + unicode_strings)
            ip_patterns = self._find_ip_addresses(ascii_strings + unicode_strings)
            file_paths = self._find_file_paths(ascii_strings + unicode_strings)
            registry_keys = self._find_registry_keys(ascii_strings + unicode_strings)
            crypto_indicators = self._find_crypto_indicators(ascii_strings + unicode_strings)
            
            # Interesting string patterns
            interesting_strings = self._find_interesting_patterns(ascii_strings + unicode_strings)
            
            return {
                'plugin_name': self.name,
                'total_ascii_strings': len(ascii_strings),
                'total_unicode_strings': len(unicode_strings),
                'urls_found': len(url_patterns),
                'ip_addresses_found': len(ip_patterns),
                'file_paths_found': len(file_paths),
                'registry_keys_found': len(registry_keys),
                'crypto_indicators_found': len(crypto_indicators),
                'ascii_strings': ascii_strings[:100],  # Limit output
                'unicode_strings': unicode_strings[:50],
                'urls': url_patterns,
                'ip_addresses': ip_patterns,
                'file_paths': file_paths[:20],
                'registry_keys': registry_keys[:20],
                'crypto_indicators': crypto_indicators,
                'interesting_strings': interesting_strings
            }
            
        except Exception as e:
            return {'error': f"String analysis failed: {str(e)}"}
    
    def get_supported_formats(self) -> List[str]:
        return ['PE', 'ELF', 'Mach-O', 'Raw']
    
    def _extract_ascii_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII strings from binary data"""
        strings = []
        pattern = re.compile(rb'[!-~]{%d,}' % min_length)
        
        for match in pattern.finditer(data):
            string_data = match.group().decode('ascii', errors='ignore')
            strings.append({
                'offset': match.start(),
                'length': len(string_data),
                'value': string_data,
                'type': 'ascii'
            })
        
        return strings
    
    def _extract_unicode_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract Unicode strings from binary data"""
        strings = []
        
        # Look for UTF-16 strings (common in Windows binaries)
        try:
            pattern = re.compile(rb'(?:[!-~]\x00){%d,}' % min_length)
            for match in pattern.finditer(data):
                try:
                    string_data = match.group().decode('utf-16le', errors='ignore')
                    if len(string_data) >= min_length:
                        strings.append({
                            'offset': match.start(),
                            'length': len(string_data),
                            'value': string_data,
                            'type': 'unicode'
                        })
                except:
                    continue
        except:
            pass
        
        return strings
    
    def _find_urls(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find URL patterns in strings"""
        urls = []
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        
        for string_obj in strings:
            string_val = string_obj['value']
            matches = url_pattern.findall(string_val)
            urls.extend(matches)
        
        return list(set(urls))  # Remove duplicates
    
    def _find_ip_addresses(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find IP address patterns in strings"""
        ips = []
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        for string_obj in strings:
            string_val = string_obj['value']
            matches = ip_pattern.findall(string_val)
            ips.extend(matches)
        
        return list(set(ips))
    
    def _find_file_paths(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find file path patterns in strings"""
        paths = []
        
        # Windows paths
        win_pattern = re.compile(r'[A-Z]:\\[^<>:"|?*\n\r]+', re.IGNORECASE)
        # Unix paths
        unix_pattern = re.compile(r'/[a-zA-Z0-9._/-]+')
        
        for string_obj in strings:
            string_val = string_obj['value']
            win_matches = win_pattern.findall(string_val)
            unix_matches = unix_pattern.findall(string_val)
            paths.extend(win_matches + unix_matches)
        
        return list(set(paths))
    
    def _find_registry_keys(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find Windows registry key patterns"""
        keys = []
        reg_pattern = re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]+', re.IGNORECASE)
        
        for string_obj in strings:
            string_val = string_obj['value']
            matches = reg_pattern.findall(string_val)
            keys.extend(matches)
        
        return list(set(keys))
    
    def _find_crypto_indicators(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find cryptographic indicators"""
        indicators = []
        crypto_keywords = [
            'aes', 'des', 'rsa', 'md5', 'sha1', 'sha256', 'sha512',
            'encrypt', 'decrypt', 'cipher', 'crypto', 'hash', 'hmac',
            'certificate', 'private key', 'public key'
        ]
        
        for string_obj in strings:
            string_val = string_obj['value'].lower()
            for keyword in crypto_keywords:
                if keyword in string_val and len(string_obj['value']) > 8:
                    indicators.append(string_obj['value'])
                    break
        
        return list(set(indicators))
    
    def _find_interesting_patterns(self, strings: List[Dict[str, Any]]) -> List[str]:
        """Find interesting string patterns that might indicate malware or specific functionality"""
        interesting = []
        
        suspicious_keywords = [
            'keylog', 'password', 'admin', 'root', 'backdoor',
            'exploit', 'payload', 'shellcode', 'inject', 'hook',
            'debug', 'anti', 'virus', 'bypass', 'stealth'
        ]
        
        for string_obj in strings:
            string_val = string_obj['value'].lower()
            for keyword in suspicious_keywords:
                if keyword in string_val and len(string_obj['value']) > 6:
                    interesting.append(string_obj['value'])
                    break
        
        return list(set(interesting))[:20]  # Limit to 20 most interesting