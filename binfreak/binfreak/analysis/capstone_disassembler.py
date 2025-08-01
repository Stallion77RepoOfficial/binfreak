"""
Capstone disassembler wrapper
"""

from typing import Dict, Any, List


class CapstoneDisassembler:
    """Professional disassembly using Capstone engine"""
    
    def __init__(self, capstone):
        self.capstone = capstone
    
    def disassemble(self, data: bytes, start_addr: int, arch_info: Dict[str, Any], 
                   max_instructions: int) -> List[Dict[str, Any]]:
        """Professional disassembly using Capstone"""
        if not self.capstone:
            return []
            
        try:
            # Configure Capstone based on architecture
            if arch_info['arch'] == 'x86_64':
                md = self.capstone.Cs(self.capstone.CS_ARCH_X86, self.capstone.CS_MODE_64)
            elif arch_info['arch'] == 'x86':
                md = self.capstone.Cs(self.capstone.CS_ARCH_X86, self.capstone.CS_MODE_32)
            elif arch_info['arch'] == 'aarch64':
                md = self.capstone.Cs(self.capstone.CS_ARCH_ARM64, self.capstone.CS_MODE_ARM)
            elif arch_info['arch'] == 'arm':
                md = self.capstone.Cs(self.capstone.CS_ARCH_ARM, self.capstone.CS_MODE_ARM)
            else:
                # Default to x86_64
                md = self.capstone.Cs(self.capstone.CS_ARCH_X86, self.capstone.CS_MODE_64)
            
            md.detail = True  # Enable detailed instruction info
            
            instructions = []
            
            # Calculate proper file offset
            file_offset = self._calculate_file_offset(start_addr, len(data))
            
            # Get data slice for disassembly
            max_size = min(max_instructions * 16, len(data) - file_offset)
            data_slice = data[file_offset:file_offset + max_size]
            
            if not data_slice:
                return []
            
            count = 0
            for insn in md.disasm(data_slice, start_addr):
                if count >= max_instructions:
                    break
                
                instruction = self._create_instruction_dict(insn)
                instructions.append(instruction)
                count += 1
                
                # Stop at function end markers
                if insn.mnemonic in ['ret', 'retn', 'retf']:
                    break
            
            return instructions
            
        except Exception as e:
            print(f"Capstone disassembly error: {e}")
            return []
    
    def _calculate_file_offset(self, start_addr: int, data_len: int) -> int:
        """Calculate file offset from virtual address"""
        # macOS ARM64/x64 binaries typically use 0x100000000 base
        if start_addr >= 0x100000000:  # macOS 64-bit base
            file_offset = start_addr - 0x100000000
        # Linux/Windows PE x64 binaries
        elif start_addr >= 0x400000:  # Typical x64 executable base
            file_offset = start_addr - 0x400000
        # Linux/Windows x86 binaries  
        elif start_addr >= 0x8048000:  # Typical x86 Linux base
            file_offset = start_addr - 0x8048000
        # Windows x86 PE binaries
        elif start_addr >= 0x10000000:  # Different base
            file_offset = start_addr - 0x10000000
        else:
            # Fallback: assume direct file offset or small offset from start
            file_offset = start_addr % data_len
        
        # Ensure offset is within bounds
        file_offset = min(max(file_offset, 0), data_len - 1)
        return file_offset
    
    def _create_instruction_dict(self, insn) -> Dict[str, Any]:
        """Create instruction dictionary from Capstone instruction"""
        instruction = {
            'address': f"0x{insn.address:08x}",
            'mnemonic': insn.mnemonic or 'unknown',
            'op_str': insn.op_str or '',
            'bytes': ' '.join([f'{b:02x}' for b in insn.bytes]) if insn.bytes else '',
            'size': insn.size,
            'type': self._classify_instruction(insn),
            'operands': [],
            'regs_read': [],
            'regs_write': [],
            'groups': [],
            'immediate_values': [],
            'memory_refs': []
        }
        
        # Safely extract register information
        try:
            instruction['regs_read'] = [insn.reg_name(reg) for reg in insn.regs_read if reg != 0]
            instruction['regs_write'] = [insn.reg_name(reg) for reg in insn.regs_write if reg != 0]
            instruction['groups'] = [insn.group_name(group) for group in insn.groups if group != 0]
        except:
            pass
        
        # Extract operand information
        self._extract_operands(insn, instruction)
        
        return instruction
    
    def _classify_instruction(self, insn) -> str:
        """Classify instruction type"""
        mnemonic = insn.mnemonic.lower()
        
        if mnemonic in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'ret']:
            return 'control_flow'
        elif mnemonic in ['mov', 'lea', 'xchg']:
            return 'data_movement'
        elif mnemonic in ['add', 'sub', 'mul', 'div']:
            return 'arithmetic'
        elif mnemonic in ['push', 'pop']:
            return 'stack'
        elif mnemonic in ['cmp', 'test']:
            return 'comparison'
        else:
            return 'other'
    
    def _extract_operands(self, insn, instruction: Dict[str, Any]):
        """Extract operand information"""
        if not hasattr(insn, 'operands') or not insn.operands:
            return
        
        try:
            for op in insn.operands:
                if hasattr(op, 'type'):
                    if op.type == self.capstone.CS_OP_IMM:
                        instruction['immediate_values'].append(op.imm)
                    elif op.type == self.capstone.CS_OP_MEM and hasattr(op, 'mem'):
                        mem_ref = {
                            'base': insn.reg_name(op.mem.base) if hasattr(op.mem, 'base') and op.mem.base != 0 else None,
                            'index': insn.reg_name(op.mem.index) if hasattr(op.mem, 'index') and op.mem.index != 0 else None,
                            'scale': getattr(op.mem, 'scale', 1),
                            'displacement': getattr(op.mem, 'disp', 0)
                        }
                        instruction['memory_refs'].append(mem_ref)
        except:
            pass
