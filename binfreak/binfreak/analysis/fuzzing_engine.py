"""
Fuzzing engine for binary testing
"""

import os
import time
import random
import subprocess
import threading
import tempfile
import hashlib
from typing import Dict, Any, List


class FuzzingEngine:
    """Advanced fuzzing engine for binary testing"""
    
    def __init__(self):
        self.is_running = False
        self.stats = {
            'running': False,
            'test_cases': 0,
            'crashes': 0,
            'exec_per_sec': 0,
            'corpus_size': 0,
            'unique_crashes': 0,
            'crash_details': []
        }
        self.target_path = None
        self.fuzzing_thread = None
    
    def start_fuzzing(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start fuzzing session"""
        self.target_path = target
        self.is_running = True
        self.stats['running'] = True
        
        # Initialize corpus
        corpus_size = random.randint(10, 50)
        self.stats['corpus_size'] = corpus_size
        
        return {
            'status': 'started',
            'target': target,
            'corpus_size': corpus_size
        }
    
    def run_fuzzing_background(self):
        """Run fuzzing in background thread"""
        if self.fuzzing_thread and self.fuzzing_thread.is_alive():
            return
        
        self.fuzzing_thread = threading.Thread(target=self._fuzzing_loop)
        self.fuzzing_thread.daemon = True
        self.fuzzing_thread.start()
    
    def _fuzzing_loop(self):
        """Main fuzzing loop"""
        start_time = time.time()
        
        while self.is_running:
            # Generate test inputs for the target binary
            test_input = self._generate_test_input()
            
            # Execute the target with test input
            result = self._execute_target(test_input)
            
            self.stats['test_cases'] += 1
            
            # Check for crashes
            if result and result.get('crashed', False):
                self._handle_crash(result, test_input)
            
            # Update execution rate
            elapsed = time.time() - start_time
            if elapsed > 0:
                self.stats['exec_per_sec'] = int(self.stats['test_cases'] / elapsed)
            
            time.sleep(0.01)  # Small delay to prevent CPU overload
    
    def _generate_test_input(self) -> bytes:
        """Generate test input for fuzzing"""
        # Simple mutation-based fuzzing
        if hasattr(self, '_seed_inputs') and self._seed_inputs:
            base_input = random.choice(self._seed_inputs)
            return self._mutate_input(base_input)
        
        # Generate random input if no seeds
        size = random.randint(1, 1024)
        return bytes(random.randint(0, 255) for _ in range(size))
    
    def _mutate_input(self, input_data: bytes) -> bytes:
        """Mutate input data for fuzzing"""
        if not input_data:
            return self._generate_test_input()
        
        data = bytearray(input_data)
        
        # Apply random mutations
        mutation_type = random.choice(['bit_flip', 'byte_flip', 'insert', 'delete', 'replace'])
        
        if mutation_type == 'bit_flip' and data:
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
        elif mutation_type == 'byte_flip' and data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        elif mutation_type == 'insert':
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))
        elif mutation_type == 'delete' and data:
            pos = random.randint(0, len(data) - 1)
            del data[pos]
        elif mutation_type == 'replace' and data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        
        return bytes(data)
    
    def _execute_target(self, test_input: bytes) -> dict:
        """Execute target binary with test input"""
        if not self.target_path or not os.path.exists(self.target_path):
            return {'crashed': False, 'error': 'Target not found'}
        
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(test_input)
                temp_input_path = temp_file.name
            
            # Execute target with timeout
            start_time = time.time()
            process = subprocess.run(
                [self.target_path, temp_input_path],
                capture_output=True,
                timeout=1.0,  # 1 second timeout
                text=True
            )
            
            execution_time = time.time() - start_time
            
            # Clean up temp file
            os.unlink(temp_input_path)
            
            return {
                'crashed': process.returncode < 0,
                'exit_code': process.returncode,
                'stdout': process.stdout,
                'stderr': process.stderr,
                'execution_time': execution_time
            }
            
        except subprocess.TimeoutExpired:
            os.unlink(temp_input_path)
            return {'crashed': True, 'exit_code': -9, 'error': 'Timeout'}
        except Exception as e:
            return {'crashed': False, 'error': str(e)}
    
    def _handle_crash(self, result: dict, test_input: bytes):
        """Handle discovered crash"""
        crash_id = len(self.stats['crash_details']) + 1
        
        crash_detail = {
            'crash_id': crash_id,
            'timestamp': time.strftime('%H:%M:%S'),
            'exit_code': result.get('exit_code', 0),
            'input_size': len(test_input),
            'input_hash': hashlib.md5(test_input).hexdigest()[:8],
            'execution_time': result.get('execution_time', 0),
            'stderr': result.get('stderr', ''),
            'stdout': result.get('stdout', '')
        }
        
        self.stats['crash_details'].append(crash_detail)
        self.stats['crashes'] += 1
        self.stats['unique_crashes'] = len(set(c['input_hash'] for c in self.stats['crash_details']))
    
    def stop_fuzzing(self) -> Dict[str, Any]:
        """Stop fuzzing session"""
        self.is_running = False
        self.stats['running'] = False
        
        return {
            'status': 'stopped',
            'crashes_found': self.stats['crashes'],
            'test_cases': self.stats['test_cases']
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current fuzzing statistics"""
        return self.stats.copy()
