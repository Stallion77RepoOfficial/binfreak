"""
Data flow analyzer
"""

from typing import Dict, Any, List


class DataFlowAnalyzer:
    """Analyzes data flow patterns"""
    
    def analyze_data_flow(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data flow patterns"""
        data_flow = {
            'register_usage': {},
            'memory_accesses': [],
            'constants': [],
            'string_references': []
        }
        
        # Track register usage
        for instr in instructions:
            for reg in instr.get('regs_read', []):
                if reg not in data_flow['register_usage']:
                    data_flow['register_usage'][reg] = {'reads': 0, 'writes': 0}
                data_flow['register_usage'][reg]['reads'] += 1
            
            for reg in instr.get('regs_write', []):
                if reg not in data_flow['register_usage']:
                    data_flow['register_usage'][reg] = {'reads': 0, 'writes': 0}
                data_flow['register_usage'][reg]['writes'] += 1
        
        # Track memory accesses
        for instr in instructions:
            for mem_ref in instr.get('memory_refs', []):
                data_flow['memory_accesses'].append({
                    'address': instr['address'],
                    'type': 'read' if instr.get('mnemonic') in ['mov', 'cmp', 'test'] else 'write',
                    'reference': mem_ref
                })
        
        # Track constants
        for instr in instructions:
            for imm_val in instr.get('immediate_values', []):
                data_flow['constants'].append({
                    'address': instr['address'],
                    'value': imm_val,
                    'context': instr.get('mnemonic', '')
                })
        
        return data_flow
