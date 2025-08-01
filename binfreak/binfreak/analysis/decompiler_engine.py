"""
Decompiler engine for binary analysis
"""

from typing import Dict, Any, List


class DecompilerEngine:
    """Decompiler engine for converting assembly to C-like code"""
    
    def __init__(self):
        self.decompilation_cache = {}
    
    def decompile_function(self, function_info: Dict[str, Any], binary_data: bytes) -> Dict[str, Any]:
        """Decompile a function to advanced C-like code with assembly analysis"""
        function_addr = function_info.get('address', '0x0')
        
        if function_addr in self.decompilation_cache:
            return self.decompilation_cache[function_addr]
        
        try:
            # Get assembly instructions for analysis
            assembly_analysis = self._analyze_assembly_patterns(function_info, binary_data)
            
            # Generate advanced C code based on assembly analysis
            c_code = self._generate_advanced_c_code(function_info, assembly_analysis)
            
            result = {
                'c_code': c_code,
                'function_signature': self._analyze_function_signature_advanced(function_info, assembly_analysis),
                'variables': self._extract_variables_from_assembly(assembly_analysis),
                'basic_blocks': assembly_analysis.get('basic_blocks', []),
                'control_flow': assembly_analysis.get('control_flow', {}),
                'analysis': {
                    'complexity': self._calculate_complexity(assembly_analysis),
                    'optimization_level': self._detect_optimization_level(assembly_analysis),
                    'stack_frame_size': assembly_analysis.get('stack_size', 0),
                    'function_calls': assembly_analysis.get('function_calls', [])
                }
            }
            
            self.decompilation_cache[function_addr] = result
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_assembly_patterns(self, function_info: Dict[str, Any], binary_data: bytes) -> Dict[str, Any]:
        """Analyze assembly patterns to understand function behavior"""
        try:
            from .disassembly_engine import AdvancedDisassemblyEngine
            
            engine = AdvancedDisassemblyEngine()
            func_addr = function_info.get('address', 0)
            
            # Convert address if needed
            if isinstance(func_addr, str):
                if func_addr.startswith('0x'):
                    func_addr = int(func_addr, 16)
                else:
                    func_addr = int(func_addr)
            
            # Get detailed disassembly
            disasm_result = engine.disassemble_function_advanced(binary_data, func_addr, 300)
            
            if 'error' in disasm_result:
                return {'error': disasm_result['error']}
            
            instructions = disasm_result.get('instructions', [])
            
            # Analyze patterns
            analysis = {
                'instructions': instructions,
                'instruction_count': len(instructions),
                'stack_operations': self._analyze_stack_operations(instructions),
                'arithmetic_operations': self._analyze_arithmetic_operations(instructions),
                'memory_accesses': self._analyze_memory_accesses(instructions),
                'control_flow': self._analyze_control_flow_patterns(instructions),
                'function_calls': self._extract_function_calls(instructions),
                'register_usage': self._analyze_register_usage(instructions),
                'stack_size': self._calculate_stack_frame_size(instructions)
            }
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_stack_operations(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze stack operations (push, pop, stack allocation)"""
        stack_ops = {'pushes': 0, 'pops': 0, 'stack_alloc': 0, 'local_vars': []}
        
        for instr in instructions:
            mnemonic = instr.get('mnemonic', '').lower()
            if mnemonic == 'push':
                stack_ops['pushes'] += 1
            elif mnemonic == 'pop':
                stack_ops['pops'] += 1
            elif mnemonic == 'sub' and 'rsp' in instr.get('op_str', ''):
                # Stack allocation
                try:
                    # Extract allocation size
                    op_str = instr.get('op_str', '')
                    if 'rsp,' in op_str:
                        size_str = op_str.split(',')[-1].strip()
                        if size_str.startswith('0x'):
                            size = int(size_str, 16)
                        else:
                            size = int(size_str)
                        stack_ops['stack_alloc'] += size
                except:
                    pass
        
        return stack_ops
    
    def _analyze_arithmetic_operations(self, instructions: List[Dict[str, Any]]) -> List[str]:
        """Analyze arithmetic operations"""
        arithmetic = []
        for instr in instructions:
            mnemonic = instr.get('mnemonic', '').lower()
            if mnemonic in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'imul', 'idiv']:
                arithmetic.append(mnemonic)
        return arithmetic
    
    def _analyze_memory_accesses(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze memory access patterns"""
        memory = {'reads': 0, 'writes': 0, 'patterns': []}
        
        for instr in instructions:
            op_str = instr.get('op_str', '')
            if '[' in op_str and ']' in op_str:
                if instr.get('mnemonic', '').lower() in ['mov', 'lea']:
                    # Determine if read or write
                    parts = op_str.split(',')
                    if len(parts) == 2:
                        if '[' in parts[1]:  # Memory read
                            memory['reads'] += 1
                        elif '[' in parts[0]:  # Memory write
                            memory['writes'] += 1
        
        return memory
    
    def _analyze_control_flow_patterns(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        cf = {'branches': 0, 'loops': 0, 'conditions': 0}
        
        for instr in instructions:
            mnemonic = instr.get('mnemonic', '').lower()
            if mnemonic.startswith('j') and mnemonic != 'jmp':  # Conditional jumps
                cf['conditions'] += 1
            elif mnemonic == 'jmp':
                cf['branches'] += 1
            elif mnemonic in ['loop', 'loope', 'loopne']:
                cf['loops'] += 1
        
        return cf
    
    def _extract_function_calls(self, instructions: List[Dict[str, Any]]) -> List[str]:
        """Extract function calls"""
        calls = []
        for instr in instructions:
            if instr.get('mnemonic', '').lower() == 'call':
                target = instr.get('op_str', 'unknown')
                calls.append(target)
        return calls
    
    def _analyze_register_usage(self, instructions: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze register usage patterns"""
        reg_usage = {}
        
        for instr in instructions:
            regs_read = instr.get('regs_read', [])
            regs_write = instr.get('regs_write', [])
            
            for reg in regs_read + regs_write:
                reg_usage[reg] = reg_usage.get(reg, 0) + 1
        
        return reg_usage
    
    def _calculate_stack_frame_size(self, instructions: List[Dict[str, Any]]) -> int:
        """Calculate stack frame size from instructions"""
        max_stack_size = 0
        
        for instr in instructions:
            if instr.get('mnemonic', '').lower() == 'sub' and 'rsp' in instr.get('op_str', ''):
                try:
                    op_str = instr.get('op_str', '')
                    if 'rsp,' in op_str:
                        size_str = op_str.split(',')[-1].strip()
                        if size_str.startswith('0x'):
                            size = int(size_str, 16)
                        else:
                            size = int(size_str)
                        max_stack_size = max(max_stack_size, size)
                except:
                    pass
        
        return max_stack_size
    
    def _generate_c_code(self, function_info: Dict[str, Any]) -> str:
        """Generate C-like code from function info"""
        func_name = function_info.get('name', 'unknown_function')
        func_type = function_info.get('type', 'void')
        
        # Simplified C code generation
        c_code = f"""// Decompiled function: {func_name}
{func_type} {func_name}()
{{
    // Function implementation
    int var1;
    int var2;
    
    var1 = 0;
    var2 = var1 + 1;
    
    return var2;
}}"""
        
        return c_code
    
    def _analyze_function_signature(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze function signature"""
        return {
            'return_type': 'int',
            'calling_convention': 'cdecl',
            'parameters': [
                {'name': 'param1', 'type': 'int'},
                {'name': 'param2', 'type': 'char*'}
            ]
        }
    
    def _analyze_function_signature_advanced(self, function_info: Dict[str, Any], assembly_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced function signature analysis based on assembly patterns"""
        reg_usage = assembly_analysis.get('register_usage', {})
        stack_ops = assembly_analysis.get('stack_operations', {})
        
        # Detect calling convention
        calling_convention = 'stdcall'  # Default
        if 'rdi' in reg_usage or 'rsi' in reg_usage:
            calling_convention = 'x64_fastcall'  # System V AMD64 ABI
        elif 'rcx' in reg_usage or 'rdx' in reg_usage:
            calling_convention = 'ms_x64'  # Microsoft x64 calling convention
        
        # Detect return type
        return_type = self._deduce_return_type(assembly_analysis)
        
        # Detect parameters
        parameters = []
        param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        for i, reg in enumerate(param_regs):
            if reg in reg_usage and reg_usage[reg] > 1:
                parameters.append({
                    'name': f'arg{i+1}',
                    'type': 'int',
                    'register': reg
                })
                if len(parameters) >= 4:  # Limit parameters
                    break
        
        return {
            'return_type': return_type,
            'calling_convention': calling_convention,
            'parameters': parameters,
            'stack_frame_size': stack_ops.get('stack_alloc', 0)
        }
    
    def _extract_variables(self, function_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract local variables"""
        return [
            {'name': 'var1', 'type': 'int', 'scope': 'local'},
            {'name': 'var2', 'type': 'int', 'scope': 'local'}
        ]
    
    def _extract_variables_from_assembly(self, assembly_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract variables from assembly analysis"""
        variables = []
        stack_ops = assembly_analysis.get('stack_operations', {})
        
        # Estimate local variables from stack allocation
        stack_size = stack_ops.get('stack_alloc', 0)
        if stack_size > 0:
            var_count = min(stack_size // 8, 10)  # Estimate based on 8-byte slots
            for i in range(var_count):
                variables.append({
                    'name': f'local_var_{i}',
                    'type': 'int',
                    'scope': 'local',
                    'stack_offset': i * 8
                })
        
        return variables
    
    def _generate_advanced_c_code(self, function_info: Dict[str, Any], assembly_analysis: Dict[str, Any]) -> str:
        """Generate advanced C-like code based on assembly analysis"""
        func_name = function_info.get('name', 'unknown_function')
        func_addr = function_info.get('address', '0x0')
        func_size = function_info.get('size', 0)
        
        # Clean function name for C
        c_func_name = func_name.replace('.', '_').replace('@', '_').replace('-', '_')
        if c_func_name.startswith(('0x', 'sub_')):
            c_func_name = f"function_{func_addr.replace('0x', '')}"
        
        # Analyze function signature
        stack_ops = assembly_analysis.get('stack_operations', {})
        function_calls = assembly_analysis.get('function_calls', [])
        arithmetic_ops = assembly_analysis.get('arithmetic_operations', [])
        control_flow = assembly_analysis.get('control_flow', {})
        
        # Generate function signature
        return_type = self._deduce_return_type(assembly_analysis)
        parameters = self._deduce_parameters(assembly_analysis)
        
        # Start building C code
        c_code = f"""/*
 * Decompiled function: {func_name}
 * Original address: {func_addr}
 * Function size: {func_size} bytes
 * Stack frame size: {assembly_analysis.get('stack_size', 0)} bytes
 * Instruction count: {assembly_analysis.get('instruction_count', 0)}
 */
{return_type} {c_func_name}({parameters}) {{"""
        
        # Add local variables based on stack analysis
        if stack_ops.get('stack_alloc', 0) > 0:
            c_code += f"\n    // Local variables (stack frame: {stack_ops['stack_alloc']} bytes)"
            var_count = min(stack_ops['stack_alloc'] // 8, 10)  # Estimate variable count
            for i in range(var_count):
                c_code += f"\n    int local_var_{i};"
            c_code += "\n"
        
        # Add function body based on control flow
        if control_flow.get('conditions', 0) > 0:
            c_code += "\n    // Conditional logic detected"
            c_code += "\n    if (/* condition */) {"
            c_code += "\n        // Branch code"
            if arithmetic_ops:
                c_code += f"\n        // Arithmetic operations: {', '.join(set(arithmetic_ops[:5]))}"
            c_code += "\n    }"
            
        if control_flow.get('loops', 0) > 0:
            c_code += "\n\n    // Loop structure detected"
            c_code += "\n    for (int i = 0; i < /* limit */; i++) {"
            c_code += "\n        // Loop body"
            c_code += "\n    }"
        
        # Add function calls
        if function_calls:
            c_code += "\n\n    // Function calls detected:"
            for call in function_calls[:5]:  # Show first 5 calls
                clean_call = call.replace('0x', 'func_').replace('[', '').replace(']', '')
                c_code += f"\n    {clean_call}();"
        
        # Add arithmetic operations
        if arithmetic_ops:
            c_code += "\n\n    // Arithmetic operations:"
            unique_ops = list(set(arithmetic_ops))
            for op in unique_ops[:3]:
                if op == 'add':
                    c_code += "\n    result = operand1 + operand2;"
                elif op == 'sub':
                    c_code += "\n    result = operand1 - operand2;"
                elif op == 'mul' or op == 'imul':
                    c_code += "\n    result = operand1 * operand2;"
                elif op == 'div' or op == 'idiv':
                    c_code += "\n    result = operand1 / operand2;"
        
        # Add return statement
        if return_type != 'void':
            c_code += "\n\n    // Return value (simplified)"
            c_code += "\n    return result;"
        
        c_code += "\n}"
        
        return c_code
    
    def _deduce_return_type(self, assembly_analysis: Dict[str, Any]) -> str:
        """Deduce return type from assembly analysis"""
        # Simple heuristics based on register usage
        reg_usage = assembly_analysis.get('register_usage', {})
        
        # Check if EAX/RAX is used (common return register)
        if 'eax' in reg_usage or 'rax' in reg_usage:
            return 'int'
        elif 'xmm0' in reg_usage:  # Floating point return
            return 'float'
        else:
            return 'void'
    
    def _deduce_parameters(self, assembly_analysis: Dict[str, Any]) -> str:
        """Deduce function parameters from assembly analysis"""
        # Simple parameter detection based on common calling conventions
        reg_usage = assembly_analysis.get('register_usage', {})
        
        param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']  # x64 calling convention
        params = []
        
        for i, reg in enumerate(param_regs):
            if reg in reg_usage and reg_usage[reg] > 1:  # Used multiple times
                params.append(f"int param{i+1}")
                if len(params) >= 3:  # Limit to 3 parameters for simplicity
                    break
        
        return ', '.join(params) if params else 'void'
    
    def _calculate_complexity(self, assembly_analysis: Dict[str, Any]) -> str:
        """Calculate function complexity"""
        instr_count = assembly_analysis.get('instruction_count', 0)
        control_flow = assembly_analysis.get('control_flow', {})
        
        complexity_score = instr_count
        complexity_score += control_flow.get('conditions', 0) * 5
        complexity_score += control_flow.get('loops', 0) * 10
        complexity_score += len(assembly_analysis.get('function_calls', [])) * 3
        
        if complexity_score < 20:
            return 'low'
        elif complexity_score < 100:
            return 'medium'
        else:
            return 'high'
    
    def _detect_optimization_level(self, assembly_analysis: Dict[str, Any]) -> str:
        """Detect optimization level from assembly patterns"""
        instr_count = assembly_analysis.get('instruction_count', 0)
        
        # Simple heuristics
        if instr_count < 10:
            return 'high'  # Highly optimized, very compact
        elif instr_count < 50:
            return 'medium'
        else:
            return 'low'  # Verbose, likely unoptimized
