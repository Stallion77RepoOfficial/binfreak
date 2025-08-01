"""
LibFuzzer Integration Module for Professional Fuzzing
Provides integration with libFuzzer for coverage-guided fuzzing
"""

import os
import subprocess
import tempfile
import shutil
import json
import time
import signal
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import logging


class LibFuzzerIntegration:
    """Professional fuzzing integration with libFuzzer"""
    
    def __init__(self, libfuzzer_path: Optional[str] = None):
        self.logger = logging.getLogger('LibFuzzer')
        self.libfuzzer_path = libfuzzer_path or self._find_libfuzzer()
        self.current_session = None
        self.is_running = False
        
    def _find_libfuzzer(self) -> Optional[str]:
        """Find libFuzzer installation"""
        # Common locations where libFuzzer might be installed
        possible_paths = [
            '/usr/bin/clang++',
            '/usr/local/bin/clang++',
            shutil.which('clang++'),
            shutil.which('clang'),
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                # Check if this clang supports libFuzzer
                if self._check_libfuzzer_support(path):
                    self.logger.info(f"Found libFuzzer support in: {path}")
                    return path
        
        self.logger.warning("libFuzzer not found. Install clang with fuzzing support.")
        return None
    
    def _check_libfuzzer_support(self, clang_path: str) -> bool:
        """Check if clang installation supports libFuzzer"""
        try:
            result = subprocess.run(
                [clang_path, '-fsanitize=fuzzer', '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return 'fsanitize=fuzzer' in result.stderr or result.returncode == 0
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if libFuzzer is available"""
        return self.libfuzzer_path is not None
    
    def prepare_target_for_fuzzing(self, source_files: List[str], 
                                 output_binary: str,
                                 compile_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Prepare a target binary for libFuzzer"""
        if not self.is_available():
            return {'error': 'libFuzzer not available', 'success': False}
        
        compile_options = compile_options or {}
        
        try:
            # Build command
            cmd = [self.libfuzzer_path]
            
            # Add fuzzing flags
            cmd.extend([
                '-fsanitize=fuzzer',
                '-fsanitize=address',  # AddressSanitizer for better crash detection
                '-fsanitize-coverage=trace-pc-guard',
                '-g',  # Debug info
                '-O1'  # Some optimization
            ])
            
            # Add custom compile options
            if compile_options.get('extra_flags'):
                cmd.extend(compile_options['extra_flags'])
            
            # Add source files
            cmd.extend(source_files)
            
            # Output binary
            cmd.extend(['-o', output_binary])
            
            # Compile
            self.logger.info(f"Compiling fuzzing target: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'binary_path': output_binary,
                    'compile_output': result.stdout + result.stderr
                }
            else:
                return {
                    'success': False,
                    'error': 'Compilation failed',
                    'compile_output': result.stdout + result.stderr
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def start_fuzzing_session(self, target_binary: str, 
                            corpus_dir: str,
                            options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Start a libFuzzer fuzzing session"""
        if not self.is_available():
            return {'error': 'libFuzzer not available', 'success': False}
        
        if not os.path.exists(target_binary):
            return {'error': f'Target binary not found: {target_binary}', 'success': False}
        
        options = options or {}
        
        try:
            # Create corpus directory if it doesn't exist
            os.makedirs(corpus_dir, exist_ok=True)
            
            # Create artifacts directory
            artifacts_dir = options.get('artifacts_dir', 'fuzzing_artifacts')
            os.makedirs(artifacts_dir, exist_ok=True)
            
            # Build libFuzzer command
            cmd = [target_binary, corpus_dir]
            
            # Add libFuzzer options
            fuzzer_options = {
                'max_total_time': options.get('max_time', 3600),  # 1 hour default
                'max_len': options.get('max_input_length', 1024),
                'timeout': options.get('timeout', 20),
                'rss_limit_mb': options.get('memory_limit_mb', 2048),
                'artifact_prefix': os.path.join(artifacts_dir, 'crash-'),
                'exact_artifact_path': os.path.join(artifacts_dir, 'exact-crash'),
                'dict': options.get('dictionary_file'),
                'only_ascii': options.get('only_ascii', 0),
                'shrink': options.get('shrink', 1),
                'reduce_inputs': options.get('reduce_inputs', 1),
                'jobs': options.get('parallel_jobs', 1),
                'workers': options.get('workers', 1),
                'reload': options.get('reload', 1),
                'print_final_stats': 1,
                'close_fd_mask': options.get('close_fd_mask', 3)
            }
            
            # Add non-None options to command
            for key, value in fuzzer_options.items():
                if value is not None:
                    cmd.append(f'-{key}={value}')
            
            # Start fuzzing session
            session = FuzzingSession(
                cmd=cmd,
                corpus_dir=corpus_dir,
                artifacts_dir=artifacts_dir,
                options=options
            )
            
            success = session.start()
            
            if success:
                self.current_session = session
                self.is_running = True
                
                return {
                    'success': True,
                    'session_id': session.session_id,
                    'corpus_dir': corpus_dir,
                    'artifacts_dir': artifacts_dir,
                    'command': ' '.join(cmd)
                }
            else:
                return {'success': False, 'error': 'Failed to start fuzzing session'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_fuzzing_stats(self) -> Dict[str, Any]:
        """Get current fuzzing statistics"""
        if not self.current_session:
            return {'error': 'No active fuzzing session'}
        
        return self.current_session.get_stats()
    
    def stop_fuzzing_session(self) -> Dict[str, Any]:
        """Stop current fuzzing session"""
        if not self.current_session:
            return {'error': 'No active fuzzing session'}
        
        result = self.current_session.stop()
        self.is_running = False
        
        return result
    
    def create_fuzzing_harness(self, template_type: str, 
                             output_file: str,
                             target_function: str = None) -> Dict[str, Any]:
        """Create a fuzzing harness for a target"""
        templates = {
            'basic_file': self._get_basic_file_harness_template(),
            'function_fuzzer': self._get_function_fuzzer_template(target_function),
            'network_fuzzer': self._get_network_fuzzer_template(),
            'parser_fuzzer': self._get_parser_fuzzer_template()
        }
        
        if template_type not in templates:
            return {
                'error': f'Unknown template type: {template_type}',
                'available_templates': list(templates.keys())
            }
        
        try:
            with open(output_file, 'w') as f:
                f.write(templates[template_type])
            
            return {
                'success': True,
                'harness_file': output_file,
                'template_type': template_type
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_basic_file_harness_template(self) -> str:
        """Get basic file fuzzing harness template"""
        return '''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// Include your target headers here
// #include "target_library.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Basic fuzzing harness for file-based input
    if (size == 0) return 0;
    
    // TODO: Replace this with your target function
    // Example: parse_input_data(data, size);
    
    // Write data to temporary file if needed
    FILE *temp_file = tmpfile();
    if (temp_file) {
        fwrite(data, 1, size, temp_file);
        rewind(temp_file);
        
        // TODO: Call your target function with the file
        // Example: process_file(temp_file);
        
        fclose(temp_file);
    }
    
    return 0;  // Always return 0
}
'''
    
    def _get_function_fuzzer_template(self, target_function: str) -> str:
        """Get function-specific fuzzing harness template"""
        func_name = target_function or "target_function"
        
        return f'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include headers for your target function
// #include "target.h"

// Declare your target function if not in headers
// extern int {func_name}(const char* input, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    
    // Ensure null termination for string functions
    char *input = (char*)malloc(size + 1);
    if (!input) return 0;
    
    memcpy(input, data, size);
    input[size] = '\\0';
    
    // Call your target function
    // TODO: Replace with actual function call
    // {func_name}(input, size);
    
    free(input);
    return 0;
}}
'''
    
    def _get_network_fuzzer_template(self) -> str:
        """Get network protocol fuzzing harness template"""
        return '''
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// Include your network protocol headers
// #include "protocol_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;  // Minimum packet size
    
    // Create a mock network packet structure
    struct network_packet {
        uint32_t length;
        uint8_t *payload;
    } packet;
    
    packet.length = size - 4;
    packet.payload = (uint8_t*)(data + 4);
    
    // TODO: Call your network protocol parser
    // Example: parse_network_packet(&packet);
    
    return 0;
}
'''
    
    def _get_parser_fuzzer_template(self) -> str:
        """Get parser fuzzing harness template"""
        return '''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include your parser headers
// #include "parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Create parser input structure
    struct parser_input {
        const uint8_t *data;
        size_t size;
        size_t offset;
    } input;
    
    input.data = data;
    input.size = size;
    input.offset = 0;
    
    // TODO: Call your parser function
    // Example: parse_data(&input);
    
    return 0;
}
'''
    
    def create_fuzzing_dictionary(self, target_type: str, output_file: str) -> Dict[str, Any]:
        """Create a fuzzing dictionary for specific target types"""
        dictionaries = {
            'http': self._get_http_dictionary(),
            'xml': self._get_xml_dictionary(),
            'json': self._get_json_dictionary(),
            'binary': self._get_binary_dictionary(),
            'sql': self._get_sql_dictionary()
        }
        
        if target_type not in dictionaries:
            return {
                'error': f'Unknown dictionary type: {target_type}',
                'available_types': list(dictionaries.keys())
            }
        
        try:
            with open(output_file, 'w') as f:
                for entry in dictionaries[target_type]:
                    f.write(f'"{entry}"\\n')
            
            return {
                'success': True,
                'dictionary_file': output_file,
                'entries': len(dictionaries[target_type])
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_http_dictionary(self) -> List[str]:
        """Get HTTP protocol fuzzing dictionary"""
        return [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
            "HTTP/1.0", "HTTP/1.1", "HTTP/2.0",
            "Host:", "User-Agent:", "Accept:", "Content-Type:", "Content-Length:",
            "Authorization:", "Cookie:", "Set-Cookie:", "Location:", "Referer:",
            "application/json", "application/xml", "text/html", "text/plain",
            "multipart/form-data", "application/x-www-form-urlencoded",
            "gzip", "deflate", "chunked", "keep-alive", "close",
            "200 OK", "404 Not Found", "500 Internal Server Error",
            "../", "..\\\\", "%2e%2e%2f", "%2e%2e%5c", "?", "&", "=",
            "<script>", "</script>", "javascript:", "data:", "file:"
        ]
    
    def _get_xml_dictionary(self) -> List[str]:
        """Get XML fuzzing dictionary"""
        return [
            "<?xml", "version=", "encoding=", "standalone=",
            "<!DOCTYPE", "<!ENTITY", "SYSTEM", "PUBLIC",
            "<![CDATA[", "]]>", "<!--", "-->",
            "&lt;", "&gt;", "&amp;", "&quot;", "&apos;",
            "xmlns:", "xsi:", "schemaLocation=",
            "&xxe;", "file:///", "http://", "ftp://",
            "]>&xxe;", "%xxe;", "<!ENTITY xxe"
        ]
    
    def _get_json_dictionary(self) -> List[str]:
        """Get JSON fuzzing dictionary"""
        return [
            "{", "}", "[", "]", ":", ",", '"',
            "null", "true", "false",
            "\\n", "\\r", "\\t", "\\\\", '\\"',
            "\\u0000", "\\u001f", "\\uffff",
            "Infinity", "-Infinity", "NaN",
            "__proto__", "constructor", "prototype"
        ]
    
    def _get_binary_dictionary(self) -> List[str]:
        """Get binary format fuzzing dictionary"""
        return [
            "\\x00\\x00\\x00\\x00", "\\xff\\xff\\xff\\xff",
            "\\x7f\\x45\\x4c\\x46",  # ELF magic
            "\\x4d\\x5a",            # PE magic  
            "\\xfe\\xed\\xfa\\xce",  # Mach-O magic
            "\\x50\\x4b\\x03\\x04",  # ZIP magic
            "\\x89\\x50\\x4e\\x47",  # PNG magic
            "\\xff\\xd8\\xff",       # JPEG magic
            "\\x1f\\x8b\\x08",       # GZIP magic
            "RIFF", "WAVE", "fmt ", "data"
        ]
    
    def _get_sql_dictionary(self) -> List[str]:
        """Get SQL injection fuzzing dictionary"""
        return [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "UNION", "WHERE", "ORDER BY", "GROUP BY", "HAVING",
            "AND", "OR", "NOT", "IN", "LIKE", "BETWEEN",
            "'", '"', ";", "--", "/*", "*/", "\\n", "\\r",
            "' OR '1'='1", "' UNION SELECT", "'; DROP TABLE",
            "admin'--", "' OR 1=1#", "\\x00", "\\x1a"
        ]


class FuzzingSession:
    """Manages a libFuzzer fuzzing session"""
    
    def __init__(self, cmd: List[str], corpus_dir: str, artifacts_dir: str, options: Dict[str, Any]):
        self.cmd = cmd
        self.corpus_dir = corpus_dir
        self.artifacts_dir = artifacts_dir
        self.options = options
        self.session_id = f"fuzz_{int(time.time())}"
        self.process = None
        self.start_time = None
        self.stats = {
            'executions': 0,
            'crashes': 0,
            'hangs': 0,
            'features': 0,
            'corpus_size': 0,
            'exec_per_sec': 0,
            'coverage': 0
        }
        self.logger = logging.getLogger('FuzzingSession')
        self.stats_thread = None
        self.is_running = False
    
    def start(self) -> bool:
        """Start the fuzzing session"""
        try:
            self.logger.info(f"Starting fuzzing session: {' '.join(self.cmd)}")
            
            self.process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.start_time = time.time()
            self.is_running = True
            
            # Start stats monitoring thread
            self.stats_thread = threading.Thread(target=self._monitor_output)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to start fuzzing session: {e}")
            return False
    
    def stop(self) -> Dict[str, Any]:
        """Stop the fuzzing session"""
        if not self.process:
            return {'error': 'No active process'}
        
        try:
            # Send SIGINT to stop gracefully
            self.process.send_signal(signal.SIGINT)
            
            # Wait for process to terminate
            self.process.wait(timeout=30)
            
            self.is_running = False
            runtime = time.time() - self.start_time if self.start_time else 0
            
            # Collect final artifacts
            artifacts = self._collect_artifacts()
            
            return {
                'success': True,
                'runtime_seconds': runtime,
                'final_stats': self.stats,
                'artifacts': artifacts
            }
        
        except subprocess.TimeoutExpired:
            # Force kill if graceful shutdown fails
            self.process.kill()
            self.process.wait()
            self.is_running = False
            
            return {
                'success': True,
                'forced_termination': True,
                'final_stats': self.stats
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current fuzzing statistics"""
        runtime = time.time() - self.start_time if self.start_time else 0
        
        # Update corpus size
        try:
            corpus_files = list(Path(self.corpus_dir).glob('*'))
            self.stats['corpus_size'] = len([f for f in corpus_files if f.is_file()])
        except:
            pass
        
        return {
            'session_id': self.session_id,
            'runtime_seconds': runtime,
            'is_running': self.is_running,
            'stats': self.stats.copy(),
            'artifacts_found': len(self._collect_artifacts())
        }
    
    def _monitor_output(self):
        """Monitor libFuzzer output and update statistics"""
        if not self.process:
            return
        
        try:
            for line in iter(self.process.stdout.readline, ''):
                if not self.is_running:
                    break
                
                line = line.strip()
                if line:
                    self._parse_libfuzzer_output(line)
        
        except Exception as e:
            self.logger.warning(f"Output monitoring error: {e}")
    
    def _parse_libfuzzer_output(self, line: str):
        """Parse libFuzzer output line and update statistics"""
        try:
            # Parse libFuzzer stats line
            # Format: #1234  INITED cov: 567 ft: 890 corp: 12/345Kb exec/s: 123 rss: 456Mb
            if line.startswith('#') and 'cov:' in line:
                parts = line.split()
                
                for i, part in enumerate(parts):
                    if part.startswith('#'):
                        self.stats['executions'] = int(part[1:])
                    elif part == 'cov:' and i + 1 < len(parts):
                        self.stats['coverage'] = int(parts[i + 1])
                    elif part == 'ft:' and i + 1 < len(parts):
                        self.stats['features'] = int(parts[i + 1])
                    elif part == 'corp:' and i + 1 < len(parts):
                        corp_info = parts[i + 1].split('/')
                        if corp_info:
                            self.stats['corpus_size'] = int(corp_info[0])
                    elif part == 'exec/s:' and i + 1 < len(parts):
                        self.stats['exec_per_sec'] = int(parts[i + 1])
            
            # Check for crashes and hangs
            if 'ERROR: AddressSanitizer' in line or 'SEGV' in line:
                self.stats['crashes'] += 1
            elif 'timeout' in line.lower() or 'hang' in line.lower():
                self.stats['hangs'] += 1
        
        except Exception as e:
            # Ignore parsing errors
            pass
    
    def _collect_artifacts(self) -> List[Dict[str, Any]]:
        """Collect fuzzing artifacts (crashes, hangs, etc.)"""
        artifacts = []
        
        try:
            artifacts_path = Path(self.artifacts_dir)
            if artifacts_path.exists():
                for artifact_file in artifacts_path.glob('*'):
                    if artifact_file.is_file():
                        stat = artifact_file.stat()
                        artifacts.append({
                            'file': str(artifact_file),
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'type': self._classify_artifact(artifact_file.name)
                        })
        
        except Exception as e:
            self.logger.warning(f"Failed to collect artifacts: {e}")
        
        return artifacts
    
    def _classify_artifact(self, filename: str) -> str:
        """Classify artifact type based on filename"""
        if 'crash' in filename.lower():
            return 'crash'
        elif 'hang' in filename.lower() or 'timeout' in filename.lower():
            return 'hang'
        elif 'leak' in filename.lower():
            return 'memory_leak'
        else:
            return 'unknown'


# Factory function
def get_libfuzzer_integration(libfuzzer_path: Optional[str] = None) -> LibFuzzerIntegration:
    """Get libFuzzer integration instance"""
    return LibFuzzerIntegration(libfuzzer_path)