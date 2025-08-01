"""
Control flow analyzer
"""

from typing import Dict, Any, List


class ControlFlowAnalyzer:
    """Analyzes control flow patterns"""
    
    def analyze_control_flow(self, instructions: List[Dict[str, Any]], 
                           basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        control_flow = {
            'type': 'linear',
            'has_loops': False,
            'has_recursion': False,
            'call_sites': [],
            'jump_tables': [],
            'complexity': 1  # Cyclomatic complexity
        }
        
        # Count decision points for cyclomatic complexity
        decision_points = 0
        
        for block in basic_blocks:
            successors = len(block.get('successors', []))
            if successors > 1:
                decision_points += successors - 1
        
        control_flow['complexity'] = decision_points + 1
        
        # Detect loops (back edges)
        for block in basic_blocks:
            for successor_id in block.get('successors', []):
                successor_block = next((b for b in basic_blocks if b['id'] == successor_id), None)
                if successor_block:
                    # Check if this is a back edge (successor has lower address)
                    block_addr = int(block['start_address'], 16)
                    succ_addr = int(successor_block['start_address'], 16)
                    if succ_addr <= block_addr:
                        control_flow['has_loops'] = True
                        break
        
        # Detect function calls
        for instr in instructions:
            if instr.get('mnemonic') == 'call':
                control_flow['call_sites'].append({
                    'address': instr['address'],
                    'target': instr.get('immediate_values', [None])[0]
                })
        
        # Classify control flow type
        if control_flow['has_loops']:
            control_flow['type'] = 'looping'
        elif len(basic_blocks) > 1:
            control_flow['type'] = 'branching'
        
        return control_flow
