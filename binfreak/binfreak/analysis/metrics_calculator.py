"""
Metrics calculator for function analysis
"""

from typing import Dict, Any, List


class MetricsCalculator:
    """Calculates comprehensive function metrics"""
    
    def calculate_function_metrics(self, instructions: List[Dict[str, Any]], 
                                 basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive function metrics"""
        metrics = {
            'instruction_count': len(instructions),
            'basic_block_count': len(basic_blocks),
            'cyclomatic_complexity': 1,
            'code_size': sum(instr.get('size', 0) for instr in instructions),
            'instruction_types': {},
            'register_pressure': 0,
            'call_count': 0,
            'branch_count': 0
        }
        
        # Count instruction types
        for instr in instructions:
            instr_type = instr.get('type', 'unknown')
            metrics['instruction_types'][instr_type] = metrics['instruction_types'].get(instr_type, 0) + 1
        
        # Calculate cyclomatic complexity
        edges = sum(len(block.get('successors', [])) for block in basic_blocks)
        nodes = len(basic_blocks)
        metrics['cyclomatic_complexity'] = edges - nodes + 2 if nodes > 0 else 1
        
        # Count specific operations
        for instr in instructions:
            mnemonic = instr.get('mnemonic', '')
            if mnemonic == 'call':
                metrics['call_count'] += 1
            elif mnemonic.startswith('j'):
                metrics['branch_count'] += 1
        
        # Estimate register pressure (unique registers used)
        used_registers = set()
        for instr in instructions:
            used_registers.update(instr.get('regs_read', []))
            used_registers.update(instr.get('regs_write', []))
        metrics['register_pressure'] = len(used_registers)
        
        return metrics
