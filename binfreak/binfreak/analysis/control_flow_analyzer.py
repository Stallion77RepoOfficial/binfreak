"""
Control flow analyzer with enhanced call graph functionality
"""

from typing import Dict, Any, List


class ControlFlowAnalyzer:
    """Analyzes control flow patterns and call graphs"""
    
    def analyze_control_flow(self, instructions: List[Dict[str, Any]], 
                           basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze control flow patterns with enhanced call graph"""
        control_flow = {
            'type': 'linear',
            'has_loops': False,
            'has_recursion': False,
            'call_sites': [],
            'jump_tables': [],
            'complexity': 1,  # Cyclomatic complexity
            'basic_blocks_count': len(basic_blocks),
            'branches': [],
            'calls_count': 0,
            'returns_count': 0,
            'branches_count': 0,
            'function_calls': []
        }
        
        # Count decision points for cyclomatic complexity
        decision_points = 0
        
        for block in basic_blocks:
            successors = len(block.get('successors', []))
            if successors > 1:
                decision_points += successors - 1
                control_flow['branches_count'] += 1
                
                # Add branch details
                control_flow['branches'].append({
                    'address': block.get('start_address', ''),
                    'type': 'conditional',
                    'target': block.get('successors', []),
                    'condition': 'branch'
                })
        
        control_flow['complexity'] = decision_points + 1
        
        # Detect loops (back edges)
        for block in basic_blocks:
            for successor_id in block.get('successors', []):
                successor_block = next((b for b in basic_blocks if b['id'] == successor_id), None)
                if successor_block:
                    # Check if this is a back edge (successor has lower address)
                    try:
                        block_addr = int(block['start_address'], 16)
                        succ_addr = int(successor_block['start_address'], 16)
                        if succ_addr <= block_addr:
                            control_flow['has_loops'] = True
                            break
                    except (ValueError, KeyError):
                        continue
        
        # Enhanced function call analysis
        for instr in instructions:
            mnemonic = instr.get('mnemonic', '').lower()
            
            if mnemonic == 'call':
                control_flow['calls_count'] += 1
                call_target = instr.get('operands', [{}])[0].get('imm', 'unknown')
                call_address = instr.get('address', '')
                
                # Basic call site info
                call_info = {
                    'address': call_address,
                    'target': call_target,
                    'type': 'direct' if isinstance(call_target, int) else 'indirect'
                }
                
                control_flow['call_sites'].append(call_info)
                
                # Enhanced call graph info
                enhanced_call = {
                    'target': hex(call_target) if isinstance(call_target, int) else str(call_target),
                    'address': call_address,
                    'type': 'direct' if isinstance(call_target, int) else 'indirect',
                    'target_analysis': {
                        'size': 'unknown',
                        'params': 'unknown'
                    }
                }
                
                # Analyze target if it's a direct call
                if isinstance(call_target, int):
                    enhanced_call['target_analysis'].update({
                        'size': 'estimated',
                        'params': self._estimate_parameters(instructions, call_address)
                    })
                
                control_flow['function_calls'].append(enhanced_call)
                
            elif mnemonic in ['ret', 'retn', 'retf']:
                control_flow['returns_count'] += 1
                
            elif mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge']:
                # Add unconditional/conditional jump info
                jump_target = instr.get('operands', [{}])[0].get('imm', 'unknown')
                jump_type = 'conditional' if mnemonic != 'jmp' else 'unconditional'
                
                control_flow['branches'].append({
                    'address': instr.get('address', ''),
                    'type': jump_type,
                    'target': hex(jump_target) if isinstance(jump_target, int) else str(jump_target),
                    'condition': mnemonic
                })
        
        # Classify control flow type
        if control_flow['has_loops']:
            control_flow['type'] = 'looping'
        elif len(basic_blocks) > 1:
            control_flow['type'] = 'branching'
        
        return control_flow
    
    def _estimate_parameters(self, instructions: List[Dict[str, Any]], call_address: str) -> str:
        """Estimate function parameters based on nearby instructions"""
        try:
            # Find instructions before the call
            call_idx = next(i for i, instr in enumerate(instructions) 
                          if instr.get('address') == call_address)
            
            param_count = 0
            stack_adjustments = 0
            
            # Look at previous 10 instructions
            for i in range(max(0, call_idx - 10), call_idx):
                instr = instructions[i]
                mnemonic = instr.get('mnemonic', '').lower()
                
                # Count push instructions (parameter passing)
                if mnemonic == 'push':
                    param_count += 1
                elif mnemonic == 'mov' and 'esp' in str(instr.get('operands', [])):
                    stack_adjustments += 1
            
            if param_count > 0:
                return f"{param_count} parameters (estimated)"
            elif stack_adjustments > 0:
                return f"stack-based parameters"
            else:
                return "no parameters detected"
                
        except (StopIteration, ValueError, IndexError):
            return "unknown"
