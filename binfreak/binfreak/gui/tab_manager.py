"""
Tab Manager for BinFreak - Enhanced with realistic decompiler and professional analysis
"""

from typing import Dict, Any, List
from PyQt6.QtWidgets import (QWidget, QTextEdit, QVBoxLayout, QHBoxLayout, 
                            QTreeWidget, QTreeWidgetItem, QSplitter, QPushButton)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class TabManager:
    """Manages analysis result tabs with enhanced decompiler"""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.selected_function = None
        
    def update_disassembly_tab(self, result: Dict[str, Any]):
        """Update disassembly tab with comprehensive analysis"""
        try:
            disasm_widget = self.main_window.tabs['Disassembly']
            
            if isinstance(disasm_widget, QTextEdit):
                # Clear and set content
                content = self._generate_comprehensive_disassembly(result)
                disasm_widget.clear()
                disasm_widget.setPlainText(content)
                
                # Set monospace font for better readability
                font = QFont("Courier New", 10)
                disasm_widget.setFont(font)
                
        except Exception as e:
            print(f"Error updating disassembly tab: {e}")
    
    def _generate_comprehensive_disassembly(self, result: Dict[str, Any]) -> str:
        """Generate comprehensive disassembly with enhanced analysis"""
        disasm_lines = ["=== BINARY DISASSEMBLY ANALYSIS ===\n"]
        
        # File information
        file_path = result.get('file_path', 'Unknown file')
        file_name = file_path.split('/')[-1] if '/' in file_path else file_path
        file_format = result.get('file_format', {})
        file_format_type = file_format.get('type', 'Unknown') if isinstance(file_format, dict) else str(file_format)
        file_arch = file_format.get('arch', 'Unknown') if isinstance(file_format, dict) else 'Unknown'
        
        disasm_lines.append(f"File: {file_name}")
        disasm_lines.append(f"Architecture: {file_arch}")
        disasm_lines.append(f"Format: {file_format_type}")
        disasm_lines.append(f"Entry Point: {result.get('entry_point', 'Unknown')}")
        disasm_lines.append("\n" + "="*80 + "\n")
        
        # Show actual disassembly with proper formatting
        if 'disassembly' in result:
            disasm_data = result['disassembly']
            disasm_lines.append("=== MAIN DISASSEMBLY ===\n")
            
            if isinstance(disasm_data, list) and disasm_data:
                # Format real disassembly data
                for i, item in enumerate(disasm_data[:50]):  # Show first 50 instructions
                    if isinstance(item, dict):
                        addr = item.get('address', f'0x{1000 + i*4:x}')
                        mnemonic = item.get('mnemonic', 'unknown')
                        operands = item.get('operands', '')
                        bytes_hex = item.get('bytes', '00 00 00 00')
                        
                        # Format instruction line
                        disasm_lines.append(f"{addr:>12}: {bytes_hex:<12} {mnemonic:<8} {operands}")
                    elif isinstance(item, str) and item.strip():
                        disasm_lines.append(f"      {item}")
            else:
                disasm_lines.append("No disassembly data available or disassembly failed")
            
            disasm_lines.append("\n" + "="*80 + "\n")
        
        # Function analysis with real data
        functions = result.get('functions', [])
        if functions:
            disasm_lines.append(f"=== FUNCTION ANALYSIS ({len(functions)} functions) ===\n")
            
            for func in functions[:8]:  # Show first 8 functions
                func_analysis = self._get_real_function_disassembly(func, result)
                disasm_lines.append(func_analysis)
                disasm_lines.append("="*80 + "\n")
        
        return "\n".join(disasm_lines)
    
    def _get_real_function_disassembly(self, function_info: Dict[str, Any], result: Dict[str, Any]) -> str:
        """Get real disassembly for a specific function from actual analysis"""
        try:
            func_name = function_info.get('name', f"func_{function_info.get('address', 'unknown')}")
            func_addr = function_info.get('address', '0x0')
            func_size = function_info.get('size', 0)
            
            disasm_lines = [f"Function: {func_name}"]
            disasm_lines.append(f"Address: {func_addr}")
            disasm_lines.append(f"Size: {func_size} bytes")
            disasm_lines.append("-" * 60)
            
            # Use real disassembly data if available
            if 'disassembly' in function_info and function_info['disassembly']:
                func_disasm = function_info['disassembly']
                if isinstance(func_disasm, list):
                    for instruction in func_disasm:
                        if isinstance(instruction, dict):
                            addr = instruction.get('address', '0x0')
                            mnemonic = instruction.get('mnemonic', 'unknown')
                            operands = instruction.get('operands', '')
                            bytes_hex = instruction.get('bytes', '00')
                            disasm_lines.append(f"{addr:>12}: {bytes_hex:<12} {mnemonic:<8} {operands}")
                        else:
                            disasm_lines.append(f"      {instruction}")
                else:
                    disasm_lines.append(f"  ; Disassembly: {func_disasm}")
            else:
                # If no function-specific disassembly, show basic info
                disasm_lines.append(f"  ; Function at {func_addr} (size: {func_size} bytes)")
                disasm_lines.append(f"  ; No detailed disassembly available")
                
                # Try to show some relevant info from function
                if 'instructions' in function_info:
                    instr_count = function_info['instructions']
                    disasm_lines.append(f"  ; Estimated instructions: {instr_count}")
                    
                if 'complexity' in function_info:
                    complexity = function_info['complexity']
                    disasm_lines.append(f"  ; Complexity: {complexity}")
            
            return "\n".join(disasm_lines) + "\n"
            
        except Exception as e:
            return f"  ; Error analyzing function: {str(e)}\n"
    
    def update_tabs_with_results(self, result: Dict[str, Any]):
        """Update all tabs with analysis results"""
        try:
            # Store all functions for potential future use
            self.all_functions = result.get('functions', [])
            
            # Update disassembly tab
            self.update_disassembly_tab(result)
            
            # Update other tabs if they exist
            if hasattr(self.main_window, 'tabs'):
                # Update visualization tab if it exists
                if 'Visualization' in self.main_window.tabs:
                    viz_widget = self.main_window.tabs['Visualization']
                    if hasattr(viz_widget, 'update_data'):
                        viz_widget.update_data(result)
                    elif hasattr(viz_widget, 'call_graph_widget'):
                        # Update call graph with all functions
                        viz_widget.call_graph_widget.update_call_graph(self.all_functions[:15], result)
                        
                # Update other analysis tabs
                for tab_name in ['Strings', 'Entropy Analysis', 'Dependencies']:
                    if tab_name in self.main_window.tabs:
                        tab_widget = self.main_window.tabs[tab_name]
                        if hasattr(tab_widget, 'update_data'):
                            tab_widget.update_data(result)
                        elif hasattr(tab_widget, 'setPlainText'):
                            # For text widgets, show relevant data
                            if tab_name == 'Strings' and 'strings' in result:
                                strings_data = result['strings']
                                if isinstance(strings_data, list):
                                    content = "\n".join([str(s) for s in strings_data[:100]])
                                else:
                                    content = str(strings_data)
                                tab_widget.setPlainText(content)
                            elif tab_name == 'Dependencies' and 'imports' in result:
                                imports_data = result['imports']
                                if isinstance(imports_data, list):
                                    content = "\n".join([str(imp) for imp in imports_data])
                                else:
                                    content = str(imports_data)
                                tab_widget.setPlainText(content)
                
        except Exception as e:
            print(f"Error updating tabs: {e}")
