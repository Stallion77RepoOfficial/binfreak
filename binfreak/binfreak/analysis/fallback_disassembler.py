"""
Fallback disassembler when Capstone is not available
"""

from typing import Dict, Any, List


class FallbackDisassembler:
    """Simple fallback disassembler"""
    
    def disassemble(self, data: bytes, base_addr: int, max_instructions: int) -> List[Dict[str, Any]]:
        """Simple fallback disassembly"""
        instructions = []
        offset = 0
        count = 0
        
        while offset < len(data) and count < max_instructions:
            # Simple x86-64 instruction patterns
            byte_val = data[offset] if offset < len(data) else 0
            
            instruction = {
                'address': f"0x{base_addr + offset:08x}",
                'bytes': f"{byte_val:02x}",
                'size': 1,
                'type': 'unknown',
                'operands': [],
                'regs_read': [],
                'regs_write': [],
                'immediate_values': [],
                'memory_refs': []
            }
            
            # Basic pattern recognition
            if byte_val == 0x55:  # push rbp
                instruction.update({
                    'mnemonic': 'push',
                    'op_str': 'rbp',
                    'type': 'stack',
                    'regs_read': ['rbp'],
                    'regs_write': ['rsp']
                })
            elif byte_val == 0x5d:  # pop rbp
                instruction.update({
                    'mnemonic': 'pop',
                    'op_str': 'rbp',
                    'type': 'stack',
                    'regs_write': ['rbp', 'rsp']
                })
            elif byte_val == 0xc3:  # ret
                instruction.update({
                    'mnemonic': 'ret',
                    'op_str': '',
                    'type': 'return'
                })
            elif byte_val == 0x90:  # nop
                instruction.update({
                    'mnemonic': 'nop',
                    'op_str': '',
                    'type': 'other'
                })
            else:
                instruction.update({
                    'mnemonic': 'unknown',
                    'op_str': f'0x{byte_val:02x}',
                    'type': 'unknown'
                })
            
            instructions.append(instruction)
            offset += instruction['size']
            count += 1
            
            # Stop at return instruction
            if instruction.get('mnemonic') == 'ret':
                break
        
        return instructions
