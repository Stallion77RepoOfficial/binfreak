"""
Basic block analyzer for control flow analysis
"""

from typing import Dict, Any, List


class BasicBlockAnalyzer:
    """Analyzes and creates basic blocks from instructions"""
    
    def create_basic_blocks(self, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create advanced basic blocks with detailed analysis"""
        if not instructions:
            return []
        
        # Find block boundaries
        block_starts = {0}  # First instruction is always a block start
        
        for i, instr in enumerate(instructions):
            instr_type = instr.get('type', '')
            
            # Block starts after control flow instructions
            if instr_type in ['control_flow', 'return'] and i + 1 < len(instructions):
                block_starts.add(i + 1)
            
            # Block starts at jump targets
            if instr_type == 'control_flow' and instr.get('immediate_values'):
                for target in instr['immediate_values']:
                    # Find instruction at target address
                    for j, target_instr in enumerate(instructions):
                        if int(target_instr['address'], 16) == target:
                            block_starts.add(j)
                            break
        
        # Create blocks
        block_starts = sorted(block_starts)
        blocks = []
        
        for i in range(len(block_starts)):
            start_idx = block_starts[i]
            end_idx = block_starts[i + 1] if i + 1 < len(block_starts) else len(instructions)
            
            block_instructions = instructions[start_idx:end_idx]
            if not block_instructions:
                continue
            
            # Analyze block characteristics
            block = {
                'id': f"bb_{i}",
                'start_address': block_instructions[0]['address'],
                'end_address': block_instructions[-1]['address'],
                'instructions': block_instructions,
                'instruction_count': len(block_instructions),
                'successors': [],
                'predecessors': [],
                'type': self._classify_basic_block(block_instructions),
                'complexity_score': self._calculate_block_complexity(block_instructions)
            }
            
            blocks.append(block)
        
        # Calculate block connections
        self._calculate_block_connections(blocks)
        
        return blocks
    
    def _classify_basic_block(self, instructions: List[Dict[str, Any]]) -> str:
        """Classify basic block type"""
        if not instructions:
            return 'empty'
        
        last_instr = instructions[-1]
        last_type = last_instr.get('type', '')
        
        if last_type == 'return':
            return 'exit'
        elif last_type == 'control_flow':
            if last_instr.get('mnemonic', '').startswith('j') and last_instr.get('mnemonic') != 'jmp':
                return 'conditional'
            elif last_instr.get('mnemonic') == 'jmp':
                return 'unconditional'
            elif last_instr.get('mnemonic') == 'call':
                return 'call'
        
        return 'sequential'
    
    def _calculate_block_complexity(self, instructions: List[Dict[str, Any]]) -> int:
        """Calculate basic block complexity score"""
        complexity = len(instructions)
        
        for instr in instructions:
            instr_type = instr.get('type', '')
            
            # Add complexity for different instruction types
            if instr_type == 'control_flow':
                complexity += 3
            elif instr_type == 'system':
                complexity += 2
            elif instr_type in ['arithmetic', 'logical']:
                complexity += 1
        
        return complexity
    
    def _calculate_block_connections(self, blocks: List[Dict[str, Any]]):
        """Calculate connections between basic blocks"""
        for i, block in enumerate(blocks):
            last_instr = block['instructions'][-1] if block['instructions'] else None
            if not last_instr:
                continue
            
            instr_type = last_instr.get('type', '')
            
            if instr_type == 'return':
                # Return block has no successors
                continue
            elif instr_type == 'control_flow':
                mnemonic = last_instr.get('mnemonic', '')
                
                if mnemonic == 'jmp':
                    # Unconditional jump - find target block
                    target_addr = self._extract_jump_target(last_instr)
                    if target_addr:
                        target_block = self._find_block_by_address(blocks, target_addr)
                        if target_block:
                            block['successors'].append(target_block['id'])
                            target_block['predecessors'].append(block['id'])
                
                elif mnemonic.startswith('j') and mnemonic != 'jmp':
                    # Conditional jump - two successors
                    # 1. Jump target
                    target_addr = self._extract_jump_target(last_instr)
                    if target_addr:
                        target_block = self._find_block_by_address(blocks, target_addr)
                        if target_block:
                            block['successors'].append(target_block['id'])
                            target_block['predecessors'].append(block['id'])
                    
                    # 2. Fall-through to next block
                    if i + 1 < len(blocks):
                        next_block = blocks[i + 1]
                        block['successors'].append(next_block['id'])
                        next_block['predecessors'].append(block['id'])
                
                elif mnemonic == 'call':
                    # Call instruction - continue to next block after call
                    if i + 1 < len(blocks):
                        next_block = blocks[i + 1]
                        block['successors'].append(next_block['id'])
                        next_block['predecessors'].append(block['id'])
            
            else:
                # Sequential block - continue to next block
                if i + 1 < len(blocks):
                    next_block = blocks[i + 1]
                    block['successors'].append(next_block['id'])
                    next_block['predecessors'].append(block['id'])
    
    def _extract_jump_target(self, instruction: Dict[str, Any]) -> int:
        """Extract jump target address from instruction"""
        immediate_values = instruction.get('immediate_values', [])
        if immediate_values:
            return immediate_values[0]
        return None
    
    def _find_block_by_address(self, blocks: List[Dict[str, Any]], address: int) -> Dict[str, Any]:
        """Find basic block containing given address"""
        for block in blocks:
            start_addr = int(block['start_address'], 16)
            end_addr = int(block['end_address'], 16)
            if start_addr <= address <= end_addr:
                return block
        return None
