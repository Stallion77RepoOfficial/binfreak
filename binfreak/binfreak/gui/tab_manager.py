"""
Tab manager for handling different analysis tabs
"""

from typing import Dict, Any

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from PyQt6.QtGui import QFont


class TabManager:
    """Manages tabs in the main window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
    
    def update_tabs_with_results(self, result: Dict[str, Any]):
        """Update tabs with analysis results"""
        # Update disassembly tab
        if hasattr(self.main_window, 'disassembly_tab'):
            self.update_disassembly_tab(result)
        
        # Update functions tab
        if hasattr(self.main_window, 'functions_tab'):
            self.update_functions_tab(result)
    
    def update_disassembly_tab(self, result: Dict[str, Any]):
        """Update disassembly tab with real analysis results"""
        disasm_text = ""
        
        # Get disassembly from analysis result
        if 'disassembly' in result and result['disassembly']:
            disasm_data = result['disassembly']
            disasm_text += "=== DISASSEMBLY ===\n\n"
            
            for instruction in disasm_data:
                if isinstance(instruction, dict):
                    addr = instruction.get('address', '0x0')
                    bytes_str = instruction.get('bytes', '')
                    mnemonic = instruction.get('mnemonic', '')
                    operands = instruction.get('operands', '')
                    disasm_text += f"{addr:>12}: {bytes_str:<20} {mnemonic:<8} {operands}\n"
        
        # Add function analysis if available
        if 'functions' in result and result['functions']:
            functions = result['functions']
            disasm_text += f"\n\n=== DETECTED FUNCTIONS ({len(functions)}) ===\n\n"
            
            for func in functions[:20]:  # Show first 20 functions
                name = func.get('name', 'unknown')
                address = func.get('address', '0x0')
                size = func.get('size', 0)
                disasm_text += f"Function: {name:<20} @ {address:<12} (size: {size:>6} bytes)\n"
        
        if not disasm_text:
            disasm_text = "Disassembly analysis in progress...\n\n"
            disasm_text += "This tab will show:\n"
            disasm_text += "• Assembly instructions with addresses\n"
            disasm_text += "• Detected functions and their locations\n"
            disasm_text += "• Code analysis and control flow\n\n"
            disasm_text += "Load a supported binary format (PE, ELF, Mach-O) to see detailed disassembly."
        
        self.main_window.disassembly_tab.setText(disasm_text)
    
    def update_functions_tab(self, result: Dict[str, Any]):
        """Update functions tab with results"""
        functions = result.get('functions', [])
        
        self.main_window.functions_tab.setRowCount(len(functions))
        
        for i, func in enumerate(functions):
            from PyQt6.QtWidgets import QTableWidgetItem
            
            address = func.get('address', '0x0')
            name = func.get('name', f'sub_{address}')
            size = func.get('size', 0)
            func_type = func.get('type', 'Unknown')
            
            self.main_window.functions_tab.setItem(i, 0, QTableWidgetItem(str(address)))
            self.main_window.functions_tab.setItem(i, 1, QTableWidgetItem(name))
            self.main_window.functions_tab.setItem(i, 2, QTableWidgetItem(str(size)))
            self.main_window.functions_tab.setItem(i, 3, QTableWidgetItem(func_type))
    
    def create_disassembly_tab(self) -> QWidget:
        """Create disassembly tab (placeholder)"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        disasm_output = QTextEdit()
        disasm_output.setFont(QFont("Monaco", 10))
        disasm_output.setReadOnly(True)
        disasm_output.setPlaceholderText("Disassembly will appear here...")
        layout.addWidget(disasm_output)
        
        return widget
    
    def create_visualization_tab(self) -> QWidget:
        """Create visualization tab (placeholder)"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        vis_placeholder = QTextEdit()
        vis_placeholder.setPlaceholderText("Binary visualization will appear here...")
        vis_placeholder.setReadOnly(True)
        layout.addWidget(vis_placeholder)
        
        return widget
