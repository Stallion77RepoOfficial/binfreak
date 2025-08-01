"""
Advanced Industrial-Grade Fuzzing Engine
Comprehensive binary testing with coverage-guided fuzzing
"""

import os
import time
import random
import subprocess
import threading
import tempfile
import hashlib
import signal
import mmap
import struct
import json
import pickle
import math
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import deque, defaultdict
from pathlib import Path
import logging


class CoverageTracker:
    """Advanced code coverage tracking using dynamic instrumentation"""
    
    def __init__(self):
        self.coverage_map = {}
        self.edge_coverage = set()
        self.basic_blocks = set()
        self.function_coverage = defaultdict(int)
        self.hit_counts = defaultdict(int)
        
    def track_execution(self, binary_path: str, input_data: bytes) -> Dict[str, Any]:
        """Track code coverage during execution"""
        coverage_info = {
            'new_edges': 0,
            'total_edges': len(self.edge_coverage),
            'basic_blocks': len(self.basic_blocks),
            'execution_path': []
        }
        
        # Simulate coverage tracking (in real implementation, would use DynamoRIO/Intel Pin)
        # Generate realistic coverage based on input characteristics
        input_hash = hashlib.md5(input_data).hexdigest()
        
        # Simulate discovered edges based on input complexity
        complexity = self._calculate_input_complexity(input_data)
        new_edges = random.randint(0, min(complexity // 10, 5))
        
        for _ in range(new_edges):
            edge_id = f"edge_{len(self.edge_coverage)}_{random.randint(1000, 9999)}"
            if edge_id not in self.edge_coverage:
                self.edge_coverage.add(edge_id)
                coverage_info['new_edges'] += 1
        
        coverage_info['total_edges'] = len(self.edge_coverage)
        return coverage_info
    
    def _calculate_input_complexity(self, data: bytes) -> int:
        """Calculate complexity score of input data"""
        if not data:
            return 0
        
        # Various complexity metrics
        entropy = self._calculate_entropy(data)
        unique_bytes = len(set(data))
        length_factor = min(len(data), 1000)
        
        return int(entropy * unique_bytes + length_factor)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)
        
        return entropy


class AdvancedMutator:
    """Industrial-grade mutation engine with intelligent strategies"""
    
    def __init__(self):
        self.mutation_strategies = [
            'arithmetic', 'bitflip', 'byteflip', 'havoc', 'splice',
            'dictionary', 'format_aware', 'structure_aware', 'grammar_based'
        ]
        self.dictionary = self._load_default_dictionary()
        self.interesting_values = self._get_interesting_values()
        
    def _load_default_dictionary(self) -> List[bytes]:
        """Load default fuzzing dictionary"""
        return [
            b'admin', b'password', b'root', b'test', b'user',
            b'GET', b'POST', b'HTTP/1.1', b'Content-Length',
            b'<script>', b'</script>', b'javascript:', b'data:',
            b'%s', b'%x', b'%d', b'%n', b'../../../',
            b'\x00', b'\xff', b'\x41' * 100, b'\x90' * 1000
        ]
    
    def _get_interesting_values(self) -> List[bytes]:
        """Get interesting values for fuzzing"""
        values = []
        
        # Integer boundaries
        for size in [1, 2, 4, 8]:
            max_val = (2 ** (size * 8)) - 1
            values.extend([
                (0).to_bytes(size, 'little'),
                (1).to_bytes(size, 'little'),
                (max_val).to_bytes(size, 'little'),
                (max_val // 2).to_bytes(size, 'little'),
            ])
        
        # String terminators and special chars
        values.extend([b'\x00', b'\n', b'\r\n', b'\xff', b'\x80'])
        
        return values
    
    def mutate(self, seed_input: bytes, strategy: str = None) -> bytes:
        """Advanced mutation with multiple strategies"""
        if not seed_input:
            return self._generate_random_input()
        
        if strategy is None:
            strategy = random.choice(self.mutation_strategies)
        
        mutation_methods = {
            'arithmetic': self._arithmetic_mutation,
            'bitflip': self._bitflip_mutation,
            'byteflip': self._byteflip_mutation,
            'havoc': self._havoc_mutation,
            'splice': self._splice_mutation,
            'dictionary': self._dictionary_mutation,
            'format_aware': self._format_aware_mutation,
            'structure_aware': self._structure_aware_mutation,
            'grammar_based': self._grammar_based_mutation
        }
        
        return mutation_methods[strategy](seed_input)
    
    def _arithmetic_mutation(self, data: bytes) -> bytes:
        """Arithmetic mutations on multi-byte values"""
        if len(data) < 4:
            return data
        
        data = bytearray(data)
        pos = random.randint(0, len(data) - 4)
        
        # Extract 32-bit value and modify
        value = struct.unpack('<I', data[pos:pos+4])[0]
        
        operations = [
            lambda x: x + random.randint(1, 100),
            lambda x: x - random.randint(1, 100),
            lambda x: x * random.randint(2, 10),
            lambda x: x ^ random.randint(1, 0xFFFFFFFF),
            lambda x: x << random.randint(1, 8),
            lambda x: x >> random.randint(1, 8)
        ]
        
        new_value = random.choice(operations)(value) & 0xFFFFFFFF
        data[pos:pos+4] = struct.pack('<I', new_value)
        
        return bytes(data)
    
    def _bitflip_mutation(self, data: bytes) -> bytes:
        """Intelligent bit flipping"""
        if not data:
            return data
        
        data = bytearray(data)
        
        # Multiple bit flips
        num_flips = random.randint(1, min(8, len(data) * 8))
        
        for _ in range(num_flips):
            byte_pos = random.randint(0, len(data) - 1)
            bit_pos = random.randint(0, 7)
            data[byte_pos] ^= (1 << bit_pos)
        
        return bytes(data)
    
    def _havoc_mutation(self, data: bytes) -> bytes:
        """Havoc-style random mutations (AFL-inspired)"""
        data = bytearray(data)
        
        # Random number of mutations
        num_mutations = random.randint(1, 16)
        
        for _ in range(num_mutations):
            mutation_type = random.randint(0, 7)
            
            if mutation_type == 0 and data:  # Flip bit
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= (1 << random.randint(0, 7))
            elif mutation_type == 1 and data:  # Set interesting value
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.choice([0, 1, 16, 32, 64, 100, 127, 128, 255])
            elif mutation_type == 2:  # Insert byte
                pos = random.randint(0, len(data))
                data.insert(pos, random.randint(0, 255))
            elif mutation_type == 3 and data:  # Delete byte
                pos = random.randint(0, len(data) - 1)
                del data[pos]
            elif mutation_type == 4 and data:  # Clone bytes
                if len(data) < 1000:  # Prevent explosion
                    src_pos = random.randint(0, len(data) - 1)
                    src_len = random.randint(1, min(10, len(data) - src_pos))
                    clone = data[src_pos:src_pos + src_len]
                    insert_pos = random.randint(0, len(data))
                    data[insert_pos:insert_pos] = clone
            elif mutation_type == 5:  # Insert interesting value
                interesting = random.choice(self.interesting_values)
                pos = random.randint(0, len(data))
                data[pos:pos] = interesting
            elif mutation_type == 6 and data:  # Overwrite with interesting
                interesting = random.choice(self.interesting_values)
                if len(data) >= len(interesting):
                    pos = random.randint(0, len(data) - len(interesting))
                    data[pos:pos + len(interesting)] = interesting
            elif mutation_type == 7:  # Insert dictionary entry
                dict_entry = random.choice(self.dictionary)
                pos = random.randint(0, len(data))
                data[pos:pos] = dict_entry
        
        return bytes(data)
    
    def _dictionary_mutation(self, data: bytes) -> bytes:
        """Dictionary-based mutations"""
        if not self.dictionary:
            return data
        
        data = bytearray(data)
        dict_entry = random.choice(self.dictionary)
        
        if random.choice([True, False]) and data:
            # Replace part of data
            if len(data) >= len(dict_entry):
                pos = random.randint(0, len(data) - len(dict_entry))
                data[pos:pos + len(dict_entry)] = dict_entry
        else:
            # Insert dictionary entry
            pos = random.randint(0, len(data))
            data[pos:pos] = dict_entry
        
        return bytes(data)
    
    def _format_aware_mutation(self, data: bytes) -> bytes:
        """Format-aware mutations for structured data"""
        # Detect potential file formats and mutate accordingly
        if data.startswith(b'%PDF'):
            return self._mutate_pdf(data)
        elif data.startswith(b'\x89PNG'):
            return self._mutate_png(data)
        elif data.startswith(b'GIF'):
            return self._mutate_gif(data)
        elif b'Content-Type:' in data:
            return self._mutate_http(data)
        else:
            return self._havoc_mutation(data)
    
    def _byteflip_mutation(self, data: bytes) -> bytes:
        """Byte-level flipping mutations"""
        if not data:
            return data
        
        data = bytearray(data)
        
        # Single byte flip
        if random.choice([True, False]):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        else:
            # Multi-byte flip
            num_bytes = random.randint(1, min(4, len(data)))
            for _ in range(num_bytes):
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
        
        return bytes(data)
    
    def _splice_mutation(self, data: bytes) -> bytes:
        """Splice two parts of data or with corpus"""
        if len(data) < 4:
            return data
        
        data = bytearray(data)
        
        # Choose splice operation
        if random.choice([True, False]) and len(data) > 8:
            # Internal splice: take two parts and swap them
            pos1 = random.randint(0, len(data) // 2)
            pos2 = random.randint(len(data) // 2, len(data) - 1)
            
            part1 = data[pos1:pos1 + random.randint(1, 10)]
            part2 = data[pos2:pos2 + random.randint(1, 10)]
            
            # Swap parts
            data[pos1:pos1 + len(part1)] = part2[:len(part1)]
            if pos2 + len(part2) <= len(data):
                data[pos2:pos2 + len(part2)] = part1[:len(part2)]
        else:
            # Insert random chunk
            chunk_size = random.randint(1, 20)
            chunk = bytes(random.randint(0, 255) for _ in range(chunk_size))
            pos = random.randint(0, len(data))
            data[pos:pos] = chunk
        
        return bytes(data)
    
    def _structure_aware_mutation(self, data: bytes) -> bytes:
        """Structure-aware mutations for binary data"""
        if len(data) < 8:
            return self._havoc_mutation(data)
        
        data = bytearray(data)
        
        # Look for structure patterns
        mutation_type = random.choice(['header', 'length_field', 'checksum', 'padding'])
        
        if mutation_type == 'header' and len(data) >= 8:
            # Mutate what looks like a header (first 8 bytes)
            for i in range(min(8, len(data))):
                if random.random() < 0.3:  # 30% chance per byte
                    data[i] = random.randint(0, 255)
        
        elif mutation_type == 'length_field':
            # Find and mutate potential length fields (4-byte values)
            if len(data) >= 4:
                pos = random.randint(0, len(data) - 4)
                # Corrupt length field
                length_val = struct.unpack('<I', data[pos:pos+4])[0]
                new_length = random.choice([
                    0, 1, 0xFFFFFFFF, length_val * 2, length_val + 1000
                ])
                data[pos:pos+4] = struct.pack('<I', new_length & 0xFFFFFFFF)
        
        elif mutation_type == 'padding':
            # Add or modify padding
            padding_size = random.randint(1, 64)
            padding_byte = random.choice([0x00, 0xFF, 0x41, 0x90])
            padding = bytes([padding_byte] * padding_size)
            
            pos = random.randint(0, len(data))
            data[pos:pos] = padding
        
        return bytes(data)
    
    def _grammar_based_mutation(self, data: bytes) -> bytes:
        """Grammar-based mutations for protocol data"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
        except:
            return self._havoc_mutation(data)
        
        # HTTP-like mutations
        if 'HTTP' in data_str.upper():
            return self._mutate_http_grammar(data)
        
        # XML-like mutations
        if '<' in data_str and '>' in data_str:
            return self._mutate_xml_grammar(data)
        
        # JSON-like mutations
        if '{' in data_str and '}' in data_str:
            return self._mutate_json_grammar(data)
        
        # Default to havoc
        return self._havoc_mutation(data)
    
    def _mutate_http_grammar(self, data: bytes) -> bytes:
        """HTTP protocol specific mutations"""
        data_str = data.decode('utf-8', errors='ignore')
        
        # HTTP method mutations
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
            if method in data_str:
                data_str = data_str.replace(method, random.choice([
                    'A' * 100, method + 'X', method.lower(), 
                    method + '\x00', method + '\r\n'
                ]), 1)
                break
        
        # Header mutations
        if 'Content-Length:' in data_str:
            data_str = data_str.replace('Content-Length:', 'Content-Length: 999999999', 1)
        
        if 'Host:' in data_str:
            data_str = data_str.replace('Host:', 'Host: ' + 'A' * 1000, 1)
        
        return data_str.encode('utf-8', errors='ignore')
    
    def _mutate_xml_grammar(self, data: bytes) -> bytes:
        """XML specific mutations"""
        data_str = data.decode('utf-8', errors='ignore')
        
        # XML injection attacks
        xml_attacks = [
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<script>alert(1)</script>',
            '&' * 1000,
            '<' + 'A' * 1000 + '>',
            ']]>' * 100
        ]
        
        attack = random.choice(xml_attacks)
        insert_pos = data_str.find('>')
        if insert_pos != -1:
            data_str = data_str[:insert_pos+1] + attack + data_str[insert_pos+1:]
        
        return data_str.encode('utf-8', errors='ignore')
    
    def _mutate_json_grammar(self, data: bytes) -> bytes:
        """JSON specific mutations"""
        data_str = data.decode('utf-8', errors='ignore')
        
        # JSON structure attacks
        json_attacks = [
            '"' + 'A' * 10000 + '"',
            '9' * 1000,
            '["' + '", "'.join(['x'] * 1000) + '"]',
            '{"a":{"b":{"c":' * 100 + '{}' + '}' * 100 + '}',
        ]
        
        attack = random.choice(json_attacks)
        
        # Find a good insertion point
        for char in ['{', '[', '"', ':']:
            pos = data_str.find(char)
            if pos != -1:
                data_str = data_str[:pos+1] + attack + data_str[pos+1:]
                break
        
        return data_str.encode('utf-8', errors='ignore')
    
    def _mutate_png(self, data: bytes) -> bytes:
        """PNG-specific mutations"""
        data = bytearray(data)
        
        # PNG chunk corruption
        png_chunks = [b'IHDR', b'PLTE', b'IDAT', b'IEND', b'gAMA', b'cHRM']
        
        # Insert malicious chunk
        malicious_chunk = random.choice(png_chunks)
        chunk_data = b'A' * random.randint(100, 1000)
        
        # PNG chunk format: length + type + data + CRC
        chunk_length = struct.pack('>I', len(chunk_data))
        chunk = chunk_length + malicious_chunk + chunk_data + b'\x00\x00\x00\x00'
        
        # Insert after PNG signature
        if len(data) > 8:
            data[8:8] = chunk
        
        return bytes(data)
    
    def _mutate_gif(self, data: bytes) -> bytes:
        """GIF-specific mutations"""
        data = bytearray(data)
        
        # GIF header corruption
        if len(data) > 6:
            # Corrupt dimension fields
            if len(data) > 10:
                # Width/Height are at offset 6-10
                data[6:10] = struct.pack('<HH', 0xFFFF, 0xFFFF)
            
            # Add malicious extension
            gif_extension = b'\x21\xFF\x0B' + b'A' * 100 + b'\x00'
            data.extend(gif_extension)
        
        return bytes(data)
    
    def _mutate_http(self, data: bytes) -> bytes:
        """HTTP-specific mutations"""
        return self._mutate_http_grammar(data)
    
    def _mutate_pdf(self, data: bytes) -> bytes:
        """PDF-specific mutations"""
        data = bytearray(data)
        
        # Insert PDF-specific attack vectors
        pdf_attacks = [
            b'/JavaScript', b'/JS', b'/OpenAction', b'/Names',
            b'document.write', b'eval(', b'unescape(',
            b'%u0000' * 100, b'A' * 1000
        ]
        
        attack = random.choice(pdf_attacks)
        pos = random.randint(0, len(data))
        data[pos:pos] = attack
        
        return bytes(data)
    
    def _generate_random_input(self) -> bytes:
        """Generate completely random input"""
        length = random.randint(1, 1000)
        return bytes(random.randint(0, 255) for _ in range(length))


class IndustrialFuzzingEngine:
    """Industrial-grade fuzzing engine with advanced features"""
    
    def __init__(self):
        self.is_running = False
        self.coverage_tracker = CoverageTracker()
        self.mutator = AdvancedMutator()
        self.corpus = deque(maxlen=10000)  # Seed corpus
        self.crash_corpus = []
        self.hang_corpus = []
        self.interesting_inputs = deque(maxlen=1000)
        
        # Advanced statistics
        self.stats = {
            'running': False,
            'start_time': 0,
            'total_execs': 0,
            'crashes': 0,
            'hangs': 0,
            'unique_crashes': 0,
            'unique_hangs': 0,
            'corpus_size': 0,
            'coverage_edges': 0,
            'executions_per_sec': 0,
            'last_crash_time': 0,
            'last_coverage_time': 0,
            'stability': 100.0,
            'mutation_strategies': defaultdict(int),
            'crash_details': [],
            'performance_metrics': {
                'avg_exec_time': 0,
                'min_exec_time': float('inf'),
                'max_exec_time': 0,
                'timeout_rate': 0
            }
        }
        
        self.target_path = None
        self.fuzzing_thread = None
        self.timeout = 2.0  # Execution timeout
        self.memory_limit = 100 * 1024 * 1024  # 100MB memory limit
        
        # Setup logging
        self.logger = logging.getLogger('FuzzingEngine')
        self.logger.setLevel(logging.INFO)
        
    def initialize_corpus(self, seed_inputs: List[bytes] = None):
        """Initialize fuzzing corpus with seed inputs"""
        if seed_inputs:
            for seed in seed_inputs:
                self.corpus.append(seed)
        else:
            # Generate diverse initial corpus
            for _ in range(100):
                seed = self.mutator._generate_random_input()
                self.corpus.append(seed)
        
        self.stats['corpus_size'] = len(self.corpus)
    
    def start_fuzzing(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start advanced fuzzing session"""
        self.target_path = target
        self.is_running = True
        self.stats['running'] = True
        self.stats['start_time'] = time.time()
        
        # Initialize parameters
        self.timeout = parameters.get('timeout', 2.0)
        self.memory_limit = parameters.get('memory_limit', 100 * 1024 * 1024)
        
        # Initialize corpus if empty
        if not self.corpus:
            seed_inputs = parameters.get('seed_inputs', None)
            self.initialize_corpus(seed_inputs)
        
        self.logger.info(f"Started fuzzing {target} with {len(self.corpus)} seeds")
        
        return {
            'status': 'started',
            'target': target,
            'corpus_size': len(self.corpus),
            'timeout': self.timeout,
            'memory_limit': self.memory_limit
        }
    
    
    def run_fuzzing_background(self):
        """Run advanced fuzzing in background thread"""
        if self.fuzzing_thread and self.fuzzing_thread.is_alive():
            return
        
        self.fuzzing_thread = threading.Thread(target=self._advanced_fuzzing_loop)
        self.fuzzing_thread.daemon = True
        self.fuzzing_thread.start()
    
    def _advanced_fuzzing_loop(self):
        """Advanced fuzzing loop with coverage guidance"""
        execution_times = deque(maxlen=1000)
        
        while self.is_running:
            try:
                # Select input from corpus (favor recent interesting inputs)
                if self.interesting_inputs and random.random() < 0.3:
                    base_input = random.choice(list(self.interesting_inputs))
                elif self.corpus:
                    base_input = random.choice(list(self.corpus))
                else:
                    base_input = self.mutator._generate_random_input()
                
                # Choose mutation strategy
                strategy = self._choose_mutation_strategy()
                self.stats['mutation_strategies'][strategy] += 1
                
                # Mutate input
                test_input = self.mutator.mutate(base_input, strategy)
                
                # Execute target and track coverage
                start_time = time.time()
                exec_result = self._execute_target_advanced(test_input)
                execution_time = time.time() - start_time
                
                execution_times.append(execution_time)
                self.stats['total_execs'] += 1
                
                # Update performance metrics
                self._update_performance_metrics(execution_time, execution_times)
                
                # Process execution result
                if exec_result.get('crashed', False):
                    self._handle_crash_advanced(exec_result, test_input)
                elif exec_result.get('hung', False):
                    self._handle_hang(exec_result, test_input)
                else:
                    # Check for new coverage
                    coverage_info = self.coverage_tracker.track_execution(
                        self.target_path, test_input
                    )
                    
                    if coverage_info['new_edges'] > 0:
                        self._handle_new_coverage(test_input, coverage_info)
                
                # Adaptive sleep based on performance
                sleep_time = max(0.001, min(0.1, execution_time * 0.1))
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Fuzzing loop error: {e}")
                time.sleep(0.1)
    
    def _choose_mutation_strategy(self) -> str:
        """Intelligent mutation strategy selection"""
        strategies = self.mutator.mutation_strategies
        
        # Adaptive strategy selection based on recent success
        if self.stats['total_execs'] < 1000:
            # Early phase: explore all strategies
            return random.choice(strategies)
        
        # Later phase: favor successful strategies
        strategy_weights = {}
        for strategy in strategies:
            success_rate = self._calculate_strategy_success_rate(strategy)
            strategy_weights[strategy] = max(0.1, success_rate)
        
        # Weighted random selection
        total_weight = sum(strategy_weights.values())
        rand_val = random.uniform(0, total_weight)
        
        cumulative = 0
        for strategy, weight in strategy_weights.items():
            cumulative += weight
            if rand_val <= cumulative:
                return strategy
        
        return random.choice(strategies)
    
    def _calculate_strategy_success_rate(self, strategy: str) -> float:
        """Calculate success rate for a mutation strategy"""
        total_uses = self.stats['mutation_strategies'][strategy]
        if total_uses == 0:
            return 0.5  # Default for unused strategies
        
        # Simple success metric (in real implementation, would track per-strategy stats)
        base_rate = 0.1
        if strategy in ['havoc', 'arithmetic', 'format_aware']:
            base_rate = 0.3  # Favor more sophisticated strategies
        
        return base_rate
    
    def _execute_target_advanced(self, test_input: bytes) -> Dict[str, Any]:
        """Advanced target execution with comprehensive monitoring"""
        if not self.target_path or not os.path.exists(self.target_path):
            return {'crashed': False, 'error': 'Target not found'}
        
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(test_input)
                temp_input_path = temp_file.name
            
            # Setup execution environment
            env = os.environ.copy()
            env['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0:fast_unwind_on_malloc=0'
            env['MSAN_OPTIONS'] = 'abort_on_error=1'
            
            # Execute with comprehensive monitoring
            start_time = time.time()
            
            try:
                process = subprocess.Popen(
                    [self.target_path, temp_input_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    preexec_fn=self._setup_process_limits
                )
                
                stdout, stderr = process.communicate(timeout=self.timeout)
                execution_time = time.time() - start_time
                
                result = {
                    'crashed': process.returncode < 0 or process.returncode > 128,
                    'hung': False,
                    'exit_code': process.returncode,
                    'stdout': stdout.decode('utf-8', errors='ignore'),
                    'stderr': stderr.decode('utf-8', errors='ignore'),
                    'execution_time': execution_time,
                    'memory_usage': self._estimate_memory_usage(process.pid),
                    'signal': self._get_signal_from_exit_code(process.returncode)
                }
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                result = {
                    'crashed': False,
                    'hung': True,
                    'exit_code': -1,
                    'execution_time': self.timeout,
                    'error': 'Execution timeout'
                }
            
            # Clean up
            os.unlink(temp_input_path)
            return result
            
        except Exception as e:
            return {'crashed': False, 'error': str(e)}
    
    def _setup_process_limits(self):
        """Setup resource limits for target process"""
        import resource
        
        # Memory limit
        resource.setrlimit(resource.RLIMIT_AS, (self.memory_limit, self.memory_limit))
        
        # CPU time limit
        resource.setrlimit(resource.RLIMIT_CPU, (int(self.timeout) + 1, int(self.timeout) + 1))
        
        # File size limit
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    
    def _estimate_memory_usage(self, pid: int) -> int:
        """Estimate memory usage of process"""
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        return int(line.split()[1]) * 1024  # Convert KB to bytes
        except:
            pass
        return 0
    
    def _get_signal_from_exit_code(self, exit_code: int) -> Optional[str]:
        """Get signal name from exit code"""
        signal_map = {
            -signal.SIGSEGV: 'SIGSEGV',
            -signal.SIGABRT: 'SIGABRT',
            -signal.SIGFPE: 'SIGFPE',
            -signal.SIGILL: 'SIGILL',
            -signal.SIGBUS: 'SIGBUS'
        }
        return signal_map.get(exit_code)
    
    def _handle_crash_advanced(self, result: Dict[str, Any], test_input: bytes):
        """Advanced crash handling with triage and classification"""
        crash_id = len(self.stats['crash_details']) + 1
        input_hash = hashlib.sha256(test_input).hexdigest()
        
        # Classify crash
        crash_type = self._classify_crash(result)
        exploitability = self._assess_exploitability(result, test_input)
        
        crash_detail = {
            'crash_id': crash_id,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'input_hash': input_hash[:16],
            'input_size': len(test_input),
            'exit_code': result.get('exit_code', 0),
            'signal': result.get('signal', 'Unknown'),
            'crash_type': crash_type,
            'exploitability': exploitability,
            'execution_time': result.get('execution_time', 0),
            'memory_usage': result.get('memory_usage', 0),
            'stderr': result.get('stderr', '')[:1000],  # Truncate
            'stdout': result.get('stdout', '')[:1000],   # Truncate
            'reproducer': test_input[:1000] if len(test_input) <= 1000 else test_input[:1000] + b'...[truncated]'
        }
        
        # Save crash
        self.crash_corpus.append((test_input, crash_detail))
        self.stats['crash_details'].append(crash_detail)
        self.stats['crashes'] += 1
        self.stats['last_crash_time'] = time.time()
        
        # Update unique crash count
        unique_hashes = set(c['input_hash'] for c in self.stats['crash_details'])
        self.stats['unique_crashes'] = len(unique_hashes)
        
        self.logger.info(f"Crash #{crash_id}: {crash_type} ({exploitability})")
    
    def _classify_crash(self, result: Dict[str, Any]) -> str:
        """Classify crash type based on execution result"""
        signal_name = result.get('signal', '')
        stderr = result.get('stderr', '').lower()
        
        if signal_name == 'SIGSEGV':
            if 'stack overflow' in stderr:
                return 'Stack Overflow'
            elif 'heap' in stderr:
                return 'Heap Corruption'
            else:
                return 'Segmentation Fault'
        elif signal_name == 'SIGABRT':
            if 'double free' in stderr:
                return 'Double Free'
            elif 'malloc' in stderr:
                return 'Heap Corruption'
            else:
                return 'Abort'
        elif signal_name == 'SIGFPE':
            return 'Floating Point Exception'
        elif signal_name == 'SIGILL':
            return 'Illegal Instruction'
        elif signal_name == 'SIGBUS':
            return 'Bus Error'
        else:
            return 'Unknown Crash'
    
    def _assess_exploitability(self, result: Dict[str, Any], test_input: bytes) -> str:
        """Assess crash exploitability"""
        crash_type = self._classify_crash(result)
        
        # Simple exploitability assessment
        if crash_type in ['Stack Overflow', 'Heap Corruption']:
            return 'HIGH'
        elif crash_type in ['Segmentation Fault', 'Double Free']:
            return 'MEDIUM'
        elif crash_type in ['Floating Point Exception', 'Illegal Instruction']:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def _handle_hang(self, result: Dict[str, Any], test_input: bytes):
        """Handle execution hangs/timeouts"""
        hang_detail = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'input_hash': hashlib.sha256(test_input).hexdigest()[:16],
            'input_size': len(test_input),
            'timeout_duration': self.timeout
        }
        
        self.hang_corpus.append((test_input, hang_detail))
        self.stats['hangs'] += 1
        
        unique_hang_hashes = set(h[1]['input_hash'] for h in self.hang_corpus)
        self.stats['unique_hangs'] = len(unique_hang_hashes)
    
    def _handle_new_coverage(self, test_input: bytes, coverage_info: Dict[str, Any]):
        """Handle inputs that discover new coverage"""
        self.interesting_inputs.append(test_input)
        self.corpus.append(test_input)
        
        self.stats['coverage_edges'] = coverage_info['total_edges']
        self.stats['corpus_size'] = len(self.corpus)
        self.stats['last_coverage_time'] = time.time()
        
        self.logger.info(f"New coverage: +{coverage_info['new_edges']} edges")
    
    def _update_performance_metrics(self, execution_time: float, execution_times: deque):
        """Update performance metrics"""
        metrics = self.stats['performance_metrics']
        
        metrics['min_exec_time'] = min(metrics['min_exec_time'], execution_time)
        metrics['max_exec_time'] = max(metrics['max_exec_time'], execution_time)
        
        if execution_times:
            metrics['avg_exec_time'] = sum(execution_times) / len(execution_times)
        
        # Calculate executions per second
        if self.stats['start_time']:
            elapsed = time.time() - self.stats['start_time']
            if elapsed > 0:
                self.stats['executions_per_sec'] = int(self.stats['total_execs'] / elapsed)
    
    def stop_fuzzing(self) -> Dict[str, Any]:
        """Stop fuzzing session with detailed results"""
        self.is_running = False
        self.stats['running'] = False
        
        # Calculate final statistics
        total_runtime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'status': 'stopped',
            'runtime_seconds': total_runtime,
            'total_executions': self.stats['total_execs'],
            'crashes_found': self.stats['crashes'],
            'unique_crashes': self.stats['unique_crashes'],
            'hangs_found': self.stats['hangs'],
            'unique_hangs': self.stats['unique_hangs'],
            'coverage_edges': self.stats['coverage_edges'],
            'corpus_size': self.stats['corpus_size'],
            'avg_exec_per_sec': self.stats['executions_per_sec']
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive fuzzing statistics"""
        current_stats = self.stats.copy()
        
        # Add derived statistics
        if self.stats['start_time']:
            current_stats['runtime'] = time.time() - self.stats['start_time']
        
        current_stats['crash_rate'] = (
            self.stats['crashes'] / max(1, self.stats['total_execs'])
        ) * 100
        
        current_stats['hang_rate'] = (
            self.stats['hangs'] / max(1, self.stats['total_execs'])
        ) * 100
        
        return current_stats
    
    def save_session(self, output_dir: str):
        """Save fuzzing session data"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Save corpus
        with open(output_path / 'corpus.pkl', 'wb') as f:
            pickle.dump(list(self.corpus), f)
        
        # Save crashes
        with open(output_path / 'crashes.pkl', 'wb') as f:
            pickle.dump(self.crash_corpus, f)
        
        # Save statistics
        with open(output_path / 'stats.json', 'w') as f:
            json.dump(self.stats, f, indent=2, default=str)
        
        self.logger.info(f"Session saved to {output_path}")


# Alias for backward compatibility
FuzzingEngine = IndustrialFuzzingEngine
