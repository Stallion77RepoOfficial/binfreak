"""
Advanced disassembly engine for binary analysis
"""

import struct
from typing import Dict, Any, List, Optional


class AdvancedDisassemblyEngine:
    """Professional disassembly engine with CFG analysis"""
    
    def __init__(self):
        self.architecture = None
        self.endian = 'little'
        self.word_size = 8  # 64-bit default
        self.instruction_cache = {}
        self.function_cache = {}
        self.cross_references = {}
        self.data_references = {}
        self.imported_functions = set()
        
        # Try to import capstone for professional disassembly
        try:
            import capstone as cs
            self.capstone = cs
            self.has_capstone = True
            self.cs = None  # Will be set per function based on architecture
            self.capstone_available = True
            print("Capstone disassembly engine loaded successfully")
        except ImportError as e:
            self.has_capstone = False
            self.capstone_available = False
            print(f"Capstone not available: {e}. Using fallback disassembler.")
    
    def analyze_architecture(self, binary_data: bytes) -> Dict[str, Any]:
        """Determine binary architecture and format"""
        from .architecture_analyzer import ArchitectureAnalyzer
        analyzer = ArchitectureAnalyzer()
        return analyzer.analyze_architecture(binary_data)
    
    def disassemble_function(self, data: bytes, start_addr: int, func_size: int = 200) -> Dict[str, Any]:
        """Disassemble function into basic blocks using real disassembler"""
        try:
            # Extract function data
            if start_addr >= len(data):
                # Use offset calculation for realistic analysis
                offset = start_addr % len(data) if data else 0
                func_data = data[offset:offset + min(func_size, len(data) - offset)]
            else:
                func_data = data[start_addr:start_addr + func_size]
            
            if not func_data:
                return {'error': 'No data to disassemble'}
            
            # Advanced disassembly
            instructions = self.disassemble_function_advanced(data, start_addr, 500)
            
            if 'error' in instructions:
                return instructions
                
            return instructions
            
        except Exception as e:
            return {'error': str(e)}
    
    def disassemble_function_advanced(self, binary_data: bytes, start_addr: int, 
                                    max_instructions: int = 500) -> Dict[str, Any]:
        """Advanced function disassembly with CFG analysis"""
        arch_info = self.analyze_architecture(binary_data)
        
        # Set up disassembler based on architecture
        if self.has_capstone:
            instructions = self._disassemble_with_capstone(binary_data, start_addr, 
                                                         arch_info, max_instructions)
        else:
            instructions = self._disassemble_fallback(binary_data, start_addr, max_instructions)
        
        if not instructions:
            return {'error': 'Failed to disassemble function'}
        
        # Advanced analysis
        basic_blocks = self._create_advanced_basic_blocks(instructions)
        control_flow = self._analyze_control_flow(instructions, basic_blocks)
        data_flow = self._analyze_data_flow(instructions)
        function_calls = self._extract_function_calls(instructions)
        
        return {
            'instructions': instructions,
            'basic_blocks': basic_blocks,
            'control_flow': control_flow,
            'data_flow': data_flow,
            'function_calls': function_calls,
            'architecture': arch_info,
            'metrics': self._calculate_function_metrics(instructions, basic_blocks)
        }
    
    def _disassemble_with_capstone(self, data: bytes, start_addr: int, 
                                  arch_info: Dict[str, Any], max_instructions: int) -> List[Dict[str, Any]]:
        """Professional disassembly using Capstone"""
        from .capstone_disassembler import CapstoneDisassembler
        disassembler = CapstoneDisassembler(self.capstone)
        return disassembler.disassemble(data, start_addr, arch_info, max_instructions)
    
    def _disassemble_fallback(self, data: bytes, base_addr: int, max_instructions: int) -> List[Dict[str, Any]]:
        """Simple fallback disassembler"""
        from .fallback_disassembler import FallbackDisassembler
        disassembler = FallbackDisassembler()
        return disassembler.disassemble(data, base_addr, max_instructions)
    
    def _create_advanced_basic_blocks(self, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create advanced basic blocks with detailed analysis"""
        from .basic_block_analyzer import BasicBlockAnalyzer
        analyzer = BasicBlockAnalyzer()
        return analyzer.create_basic_blocks(instructions)
    
    def _analyze_control_flow(self, instructions: List[Dict[str, Any]], 
                            basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        from .control_flow_analyzer import ControlFlowAnalyzer
        analyzer = ControlFlowAnalyzer()
        return analyzer.analyze_control_flow(instructions, basic_blocks)
    
    def _analyze_data_flow(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data flow patterns"""
        from .data_flow_analyzer import DataFlowAnalyzer
        analyzer = DataFlowAnalyzer()
        return analyzer.analyze_data_flow(instructions)
    
    def _extract_function_calls(self, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract and analyze function calls"""
        function_calls = []
        
        for instr in instructions:
            if instr.get('mnemonic') == 'call':
                call_info = {
                    'address': instr['address'],
                    'target': None,
                    'type': 'unknown'
                }
                
                # Determine call type and target
                if instr.get('immediate_values'):
                    call_info['target'] = f"0x{instr['immediate_values'][0]:x}"
                    call_info['type'] = 'direct'
                else:
                    call_info['type'] = 'indirect'
                    # Try to determine target from operands
                    for operand in instr.get('operands', []):
                        if operand.get('type') == 'register':
                            call_info['target'] = operand['name']
                        elif operand.get('type') == 'memory':
                            call_info['target'] = 'memory'
                
                function_calls.append(call_info)
        
        return function_calls
    
    def _calculate_function_metrics(self, instructions: List[Dict[str, Any]], 
                                  basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive function metrics"""
        from .metrics_calculator import MetricsCalculator
        calculator = MetricsCalculator()
        return calculator.calculate_function_metrics(instructions, basic_blocks)
    
    # Legacy methods for compatibility
    def disassemble_bytes_capstone(self, data: bytes, base_addr: int) -> List[Dict[str, Any]]:
        """Legacy method - redirect to advanced disassembly"""
        result = self.disassemble_function_advanced(data, base_addr)
        return result.get('instructions', [])
    
    def disassemble_bytes_fallback(self, data: bytes, base_addr: int) -> List[Dict[str, Any]]:
        """Fallback disassembly when Capstone is not available"""
        return self._disassemble_fallback(data, base_addr, 50)
    
    def create_basic_blocks(self, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Legacy method - redirect to advanced basic block creation"""
        return self._create_advanced_basic_blocks(instructions)


# Keep old class name for compatibility
class DisassemblyEngine(AdvancedDisassemblyEngine):
    """Compatibility alias for AdvancedDisassemblyEngine"""
    pass
