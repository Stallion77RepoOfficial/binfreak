"""
Simplified Main Window for BinFreak - Clean GUI Implementation
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QSplitter,
    QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem, QStatusBar,
    QMenuBar, QFileDialog, QProgressBar, QLabel, QPushButton,
    QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QFont

from ..analysis.binary_engine import BinaryAnalysisEngine
from ..core.license_manager import SimpleLicenseManager


class AnalysisWorker(QThread):
    """Background worker for binary analysis"""
    progress_updated = pyqtSignal(int)
    analysis_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.analysis_engine = BinaryAnalysisEngine()
    
    def run(self):
        """Run analysis in background"""
        try:
            self.progress_updated.emit(10)
            result = self.analysis_engine.analyze_file(self.file_path)
            self.progress_updated.emit(90)
            
            if 'error' in result:
                self.error_occurred.emit(result['error'])
            else:
                self.analysis_completed.emit(result)
                
            self.progress_updated.emit(100)
        except Exception as e:
            self.error_occurred.emit(str(e))


class SimplifiedMainWindow(QMainWindow):
    """Simplified main window focusing on core binary analysis"""
    
    def __init__(self):
        super().__init__()
        self.current_analysis: Optional[Dict[str, Any]] = None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.license_manager = SimpleLicenseManager()
        
        self.init_ui()
        self.setup_menus()
        self.setup_status_bar()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("BinFreak - Binary Analysis Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget with splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(main_splitter)
        
        # Left panel - File info and controls
        self.create_left_panel(main_splitter)
        
        # Right panel - Analysis results
        self.create_right_panel(main_splitter)
        
        # Set splitter proportions
        main_splitter.setSizes([300, 900])
    
    def create_left_panel(self, parent):
        """Create left control panel"""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # File selection
        file_layout = QHBoxLayout()
        self.open_button = QPushButton("Open Binary")
        self.open_button.clicked.connect(self.open_file)
        file_layout.addWidget(self.open_button)
        
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.start_analysis)
        self.analyze_button.setEnabled(False)
        file_layout.addWidget(self.analyze_button)
        
        left_layout.addLayout(file_layout)
        
        # File info
        self.file_info = QTextEdit()
        self.file_info.setMaximumHeight(200)
        self.file_info.setPlaceholderText("No file loaded")
        left_layout.addWidget(QLabel("File Information:"))
        left_layout.addWidget(self.file_info)
        
        # Analysis summary
        self.analysis_summary = QTextEdit()
        self.analysis_summary.setMaximumHeight(300)
        self.analysis_summary.setPlaceholderText("No analysis performed")
        left_layout.addWidget(QLabel("Analysis Summary:"))
        left_layout.addWidget(self.analysis_summary)
        
        left_layout.addStretch()
        parent.addWidget(left_widget)
    
    def create_right_panel(self, parent):
        """Create right results panel"""
        self.tab_widget = QTabWidget()
        
        # Enhanced tabs for professional analysis
        
        # Disassembly tab with advanced features
        self.disassembly_widget = self.create_disassembly_tab()
        self.tab_widget.addTab(self.disassembly_widget, "Disassembly")
        
        # Hexadecimal viewer
        self.hex_viewer = self.create_hex_viewer_tab()
        self.tab_widget.addTab(self.hex_viewer, "Hex Viewer")
        
        # Control Flow Graph tab
        self.cfg_widget = self.create_cfg_tab()
        self.tab_widget.addTab(self.cfg_widget, "Control Flow")
        
        # Fuzzing tab
        self.fuzzing_widget = self.create_fuzzing_tab()
        self.tab_widget.addTab(self.fuzzing_widget, "Fuzzing")
        
        # Strings tab
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(3)
        self.strings_table.setHorizontalHeaderLabels(["Address", "Length", "String"])
        self.strings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tab_widget.addTab(self.strings_table, "Strings")
        
        # Functions tab
        self.functions_tree = QTreeWidget()
        self.functions_tree.setHeaderLabels(["Address", "Name", "Type", "Size", "Confidence"])
        self.tab_widget.addTab(self.functions_tree, "Functions")
        
        # Sections tab
        self.sections_tree = QTreeWidget()
        self.sections_tree.setHeaderLabels(["Name", "Address", "Size", "Type", "Permissions"])
        self.tab_widget.addTab(self.sections_tree, "Sections")
        
        # Advanced Analysis tab (Ghidra results)
        self.advanced_analysis = QTextEdit()
        self.advanced_analysis.setFont(QFont("Courier", 10))
        self.advanced_analysis.setReadOnly(True)
        self.tab_widget.addTab(self.advanced_analysis, "Advanced Analysis")
        
        # Raw analysis tab
        self.raw_analysis = QTextEdit()
        self.raw_analysis.setFont(QFont("Courier", 10))
        self.raw_analysis.setReadOnly(True)
        self.tab_widget.addTab(self.raw_analysis, "Raw Analysis")
        
        parent.addWidget(self.tab_widget)
    
    def create_disassembly_tab(self) -> QWidget:
        """Create enhanced disassembly tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.disasm_address_input = QTextEdit()
        self.disasm_address_input.setMaximumHeight(30)
        self.disasm_address_input.setPlaceholderText("Enter address (e.g., 0x1000)")
        controls_layout.addWidget(QLabel("Address:"))
        controls_layout.addWidget(self.disasm_address_input)
        
        self.disasm_button = QPushButton("Disassemble")
        self.disasm_button.clicked.connect(self.disassemble_at_address)
        controls_layout.addWidget(self.disasm_button)
        
        layout.addLayout(controls_layout)
        
        # Disassembly display
        self.disassembly_table = QTableWidget()
        self.disassembly_table.setColumnCount(4)
        self.disassembly_table.setHorizontalHeaderLabels(["Address", "Bytes", "Instruction", "Operands"])
        layout.addWidget(self.disassembly_table)
        
        return widget
    
    def create_hex_viewer_tab(self) -> QWidget:
        """Create professional hex viewer"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.hex_offset_input = QTextEdit()
        self.hex_offset_input.setMaximumHeight(30)
        self.hex_offset_input.setPlaceholderText("Offset (e.g., 0x1000)")
        controls_layout.addWidget(QLabel("Offset:"))
        controls_layout.addWidget(self.hex_offset_input)
        
        self.hex_goto_button = QPushButton("Go To")
        self.hex_goto_button.clicked.connect(self.goto_hex_offset)
        controls_layout.addWidget(self.hex_goto_button)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Hex display
        self.hex_display = QTextEdit()
        self.hex_display.setFont(QFont("Courier", 10))
        self.hex_display.setReadOnly(True)
        layout.addWidget(self.hex_display)
        
        return widget
    
    def create_cfg_tab(self) -> QWidget:
        """Create control flow graph tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.cfg_function_input = QTextEdit()
        self.cfg_function_input.setMaximumHeight(30)
        self.cfg_function_input.setPlaceholderText("Function address")
        controls_layout.addWidget(QLabel("Function:"))
        controls_layout.addWidget(self.cfg_function_input)
        
        self.cfg_generate_button = QPushButton("Generate CFG")
        self.cfg_generate_button.clicked.connect(self.generate_cfg)
        controls_layout.addWidget(self.cfg_generate_button)
        
        layout.addLayout(controls_layout)
        
        # CFG display
        self.cfg_display = QTextEdit()
        self.cfg_display.setFont(QFont("Courier", 10))
        self.cfg_display.setReadOnly(True)
        self.cfg_display.setPlaceholderText("Control flow graph will appear here...")
        layout.addWidget(self.cfg_display)
        
        return widget
    
    def create_fuzzing_tab(self) -> QWidget:
        """Create fuzzing interface"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Fuzzing controls
        controls_layout = QVBoxLayout()
        
        # Fuzzing options
        options_layout = QHBoxLayout()
        
        self.fuzz_timeout_input = QTextEdit()
        self.fuzz_timeout_input.setMaximumHeight(30)
        self.fuzz_timeout_input.setPlaceholderText("300")
        options_layout.addWidget(QLabel("Timeout (s):"))
        options_layout.addWidget(self.fuzz_timeout_input)
        
        self.fuzz_memory_input = QTextEdit()
        self.fuzz_memory_input.setMaximumHeight(30)
        self.fuzz_memory_input.setPlaceholderText("2048")
        options_layout.addWidget(QLabel("Memory (MB):"))
        options_layout.addWidget(self.fuzz_memory_input)
        
        controls_layout.addLayout(options_layout)
        
        # Fuzzing buttons
        buttons_layout = QHBoxLayout()
        
        self.start_fuzz_button = QPushButton("Start Fuzzing")
        self.start_fuzz_button.clicked.connect(self.start_fuzzing)
        buttons_layout.addWidget(self.start_fuzz_button)
        
        self.stop_fuzz_button = QPushButton("Stop Fuzzing")
        self.stop_fuzz_button.clicked.connect(self.stop_fuzzing)
        self.stop_fuzz_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_fuzz_button)
        
        self.fuzz_stats_button = QPushButton("Show Stats")
        self.fuzz_stats_button.clicked.connect(self.show_fuzz_stats)
        buttons_layout.addWidget(self.fuzz_stats_button)
        
        controls_layout.addLayout(buttons_layout)
        layout.addLayout(controls_layout)
        
        # Fuzzing results
        self.fuzzing_results = QTextEdit()
        self.fuzzing_results.setFont(QFont("Courier", 10))
        self.fuzzing_results.setReadOnly(True)
        self.fuzzing_results.setPlaceholderText("Fuzzing results will appear here...")
        layout.addWidget(self.fuzzing_results)
        
        return widget
    
    def setup_menus(self):
        # Enhanced menus for professional features
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open Binary...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        # Export options
        export_menu = file_menu.addMenu("Export")
        
        export_analysis_action = QAction("Export Analysis...", self)
        export_analysis_action.triggered.connect(self.export_analysis)
        export_menu.addAction(export_analysis_action)
        
        export_disassembly_action = QAction("Export Disassembly...", self)
        export_disassembly_action.triggered.connect(self.export_disassembly)
        export_menu.addAction(export_disassembly_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")
        
        advanced_analysis_action = QAction("Run Advanced Analysis", self)
        advanced_analysis_action.setShortcut("Ctrl+A")
        advanced_analysis_action.triggered.connect(self.run_advanced_analysis)
        analysis_menu.addAction(advanced_analysis_action)
        
        cfg_action = QAction("Generate Control Flow Graph", self)
        cfg_action.triggered.connect(self.show_cfg_dialog)
        analysis_menu.addAction(cfg_action)
        
        analysis_menu.addSeparator()
        
        fuzzing_action = QAction("Open Fuzzing Interface", self)
        fuzzing_action.triggered.connect(self.open_fuzzing_interface)
        analysis_menu.addAction(fuzzing_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        hex_viewer_action = QAction("Hex Viewer", self)
        hex_viewer_action.setShortcut("Ctrl+H")
        hex_viewer_action.triggered.connect(self.open_hex_viewer)
        tools_menu.addAction(hex_viewer_action)
        
        compare_action = QAction("Binary Comparison", self)
        compare_action.triggered.connect(self.open_binary_comparison)
        tools_menu.addAction(compare_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        keyboard_shortcuts_action = QAction("Keyboard Shortcuts", self)
        keyboard_shortcuts_action.triggered.connect(self.show_shortcuts)
        help_menu.addAction(keyboard_shortcuts_action)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def open_file(self):
        """Open binary file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary File", "", "All Files (*)"
        )
        
        if file_path:
            self.load_file_info(file_path)
            self.analyze_button.setEnabled(True)
            self.status_bar.showMessage(f"Loaded: {os.path.basename(file_path)}")
    
    def load_file_info(self, file_path: str):
        """Load basic file information"""
        try:
            file_stats = os.stat(file_path)
            size_mb = file_stats.st_size / (1024 * 1024)
            
            info_text = f"""Path: {file_path}
Name: {os.path.basename(file_path)}
Size: {file_stats.st_size:,} bytes ({size_mb:.2f} MB)
Modified: {datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
Permissions: {oct(file_stats.st_mode)[-3:]}"""
            
            self.file_info.setPlainText(info_text)
            self.current_file_path = file_path
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file info: {str(e)}")
    
    def start_analysis(self):
        """Start binary analysis"""
        if not hasattr(self, 'current_file_path'):
            QMessageBox.warning(self, "Warning", "No file selected")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_button.setEnabled(False)
        
        # Start analysis worker
        self.analysis_worker = AnalysisWorker(self.current_file_path)
        self.analysis_worker.progress_updated.connect(self.progress_bar.setValue)
        self.analysis_worker.analysis_completed.connect(self.analysis_completed)
        self.analysis_worker.error_occurred.connect(self.analysis_error)
        self.analysis_worker.start()
        
        self.status_bar.showMessage("Analyzing...")
    
    def analysis_completed(self, result: Dict[str, Any]):
        """Handle completed analysis"""
        self.progress_bar.setVisible(False)
        self.analyze_button.setEnabled(True)
        self.current_analysis = result
        
        # Update summary
        summary = self.create_analysis_summary(result)
        self.analysis_summary.setPlainText(summary)
        
        # Update enhanced strings table
        self.update_strings_table_enhanced(result.get('strings', []))
        
        # Update enhanced functions tree
        self.update_functions_tree_enhanced(result.get('functions', []))
        
        # Update sections tree
        self.update_sections_tree(result.get('sections', []))
        
        # Update disassembly display
        self.update_disassembly_display(result.get('disassembly', []))
        
        # Update hex viewer
        self.update_hex_viewer(result.get('file_data', b''))
        
        # Update advanced analysis
        self.update_advanced_analysis(result.get('ghidra_analysis', {}))
        
        # Update raw analysis
        self.raw_analysis.setPlainText(json.dumps(result, indent=2, default=str))
        
        self.status_bar.showMessage("Analysis completed")
    
    def update_strings_table_enhanced(self, strings: list):
        """Update enhanced strings table with address and length"""
        self.strings_table.setRowCount(len(strings))
        for i, string in enumerate(strings):
            if isinstance(string, dict):
                # Enhanced string data with address
                self.strings_table.setItem(i, 0, QTableWidgetItem(string.get('address', f'0x{i*4:08x}')))
                self.strings_table.setItem(i, 1, QTableWidgetItem(str(string.get('length', len(str(string.get('value', '')))))))
                self.strings_table.setItem(i, 2, QTableWidgetItem(str(string.get('value', ''))))
            else:
                # Legacy string format
                self.strings_table.setItem(i, 0, QTableWidgetItem(f'0x{i*4:08x}'))
                self.strings_table.setItem(i, 1, QTableWidgetItem(str(len(str(string)))))
                self.strings_table.setItem(i, 2, QTableWidgetItem(str(string)))
    
    def update_functions_tree_enhanced(self, functions: list):
        """Update enhanced functions tree with confidence"""
        self.functions_tree.clear()
        for func in functions:
            item = QTreeWidgetItem([
                func.get('address', 'Unknown'),
                func.get('name', 'Unknown'),
                func.get('type', 'Unknown'),
                str(func.get('size', 'Unknown')),
                str(func.get('confidence', 'N/A'))
            ])
            self.functions_tree.addTopLevelItem(item)
    
    def update_disassembly_display(self, disassembly: list):
        """Update disassembly display"""
        self.disassembly_table.setRowCount(len(disassembly))
        for i, instr in enumerate(disassembly):
            self.disassembly_table.setItem(i, 0, QTableWidgetItem(str(instr.get('address', ''))))
            self.disassembly_table.setItem(i, 1, QTableWidgetItem(str(instr.get('bytes', ''))))
            self.disassembly_table.setItem(i, 2, QTableWidgetItem(str(instr.get('mnemonic', ''))))
            self.disassembly_table.setItem(i, 3, QTableWidgetItem(str(instr.get('operands', ''))))
    
    def update_hex_viewer(self, data: bytes):
        """Update hex viewer with binary data"""
        if not data:
            self.hex_display.setPlainText("No data available")
            return
        
        hex_text = self.format_hex_display(data[:4096])  # Show first 4KB
        self.hex_display.setPlainText(hex_text)
    
    def format_hex_display(self, data: bytes) -> str:
        """Format binary data for hex display"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:08x}"
            hex_part = ' '.join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(47)  # Pad to align ASCII
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{offset}  {hex_part}  |{ascii_part}|")
        return '\n'.join(lines)
    
    def update_advanced_analysis(self, ghidra_analysis: dict):
        """Update advanced analysis tab with Ghidra results"""
        if not ghidra_analysis or not ghidra_analysis.get('available', False):
            self.advanced_analysis.setPlainText(
                "Advanced analysis not available.\n"
                "Install Ghidra for professional-grade analysis features."
            )
            return
        
        if 'error' in ghidra_analysis:
            self.advanced_analysis.setPlainText(f"Advanced analysis error: {ghidra_analysis['error']}")
            return
        
        # Format Ghidra analysis results
        analysis_text = "=== ADVANCED ANALYSIS RESULTS (Ghidra) ===\n\n"
        
        # Functions
        functions = ghidra_analysis.get('functions', [])
        analysis_text += f"Functions Found: {len(functions)}\n"
        analysis_text += "-" * 50 + "\n"
        for func in functions[:20]:  # Show first 20
            analysis_text += f"Function: {func.get('name', 'unknown')}\n"
            analysis_text += f"  Address: {func.get('address', 'unknown')}\n"
            analysis_text += f"  Size: {func.get('size', 'unknown')}\n"
            analysis_text += f"  Calling Convention: {func.get('calling_convention', 'unknown')}\n"
            if func.get('signature'):
                analysis_text += f"  Signature: {func['signature']}\n"
            analysis_text += "\n"
        
        # Symbols
        symbols = ghidra_analysis.get('symbols', [])
        if symbols:
            analysis_text += f"\nSymbols Found: {len(symbols)}\n"
            analysis_text += "-" * 50 + "\n"
            for sym in symbols[:10]:  # Show first 10
                analysis_text += f"Symbol: {sym.get('name', 'unknown')}\n"
                analysis_text += f"  Address: {sym.get('address', 'unknown')}\n"
                analysis_text += f"  Type: {sym.get('type', 'unknown')}\n\n"
        
        # Memory Layout
        memory_layout = ghidra_analysis.get('memory_layout', {})
        if memory_layout:
            analysis_text += "\nMemory Layout:\n"
            analysis_text += "-" * 50 + "\n"
            segments = memory_layout.get('segments', [])
            for seg in segments:
                analysis_text += f"Segment: {seg.get('name', 'unknown')}\n"
                analysis_text += f"  Start: {seg.get('start', 'unknown')}\n"
                analysis_text += f"  End: {seg.get('end', 'unknown')}\n"
                analysis_text += f"  Permissions: {seg.get('permissions', 'unknown')}\n\n"
        
        self.advanced_analysis.setPlainText(analysis_text)
    
    def analysis_error(self, error: str):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.analyze_button.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed: {error}")
        self.status_bar.showMessage("Analysis failed")
    
    def create_analysis_summary(self, result: Dict[str, Any]) -> str:
        """Create analysis summary text"""
        stats = result.get('statistics', {})
        
        summary = f"""File Format: {result.get('file_format', {}).get('type', 'Unknown')}
File Size: {result.get('file_size', 0):,} bytes
Functions: {stats.get('total_functions', 0)}
Strings: {stats.get('total_strings', 0)}
Sections: {stats.get('total_sections', 0)}
Analysis Time: {result.get('analysis_duration', 'Unknown')}

File Type Details:
{self.get_format_details(result.get('file_format', {}))}

Entropy Analysis:
{self.get_entropy_summary(result.get('entropy', {}))}"""
        
        return summary
    
    def get_format_details(self, file_format: Dict[str, Any]) -> str:
        """Get detailed format information"""
        format_type = file_format.get('type', 'Unknown')
        if 'ELF' in format_type:
            return f"Linux/Unix executable ({format_type})"
        elif 'PE' in format_type:
            return f"Windows executable ({format_type})"
        elif 'Mach-O' in format_type:
            return f"macOS executable ({format_type})"
        else:
            return format_type
    
    def get_entropy_summary(self, entropy_data) -> str:
        """Get entropy analysis summary"""
        if isinstance(entropy_data, dict):
            avg_entropy = entropy_data.get('average', 0)
        else:
            avg_entropy = entropy_data if isinstance(entropy_data, (int, float)) else 0
        
        if avg_entropy > 7.5:
            return f"{avg_entropy:.2f} - Very high (likely packed/encrypted)"
        elif avg_entropy > 6.0:
            return f"{avg_entropy:.2f} - High (compressed content)"
        elif avg_entropy > 4.0:
            return f"{avg_entropy:.2f} - Medium (mixed content)"
        else:
            return f"{avg_entropy:.2f} - Low (structured data)"
    
    def update_sections_tree(self, sections: list):
        """Update sections tree with enhanced information"""
        self.sections_tree.clear()
        for section in sections:
            item = QTreeWidgetItem([
                section.get('name', 'Unknown'),
                section.get('address', 'Unknown'),
                str(section.get('size', 'Unknown')),
                section.get('type', 'Unknown'),
                section.get('permissions', 'r--')
            ])
            self.sections_tree.addTopLevelItem(item)
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self, 
            "About BinFreak",
            "BinFreak v2.0 - Professional Binary Analysis Tool\n\n"
            "Enhanced with professional-grade features:\n\n"
            "Core Features:\n"
            "• Dynamic binary format detection\n"
            "• Intelligent function detection\n"
            "• Advanced string extraction\n"
            "• Professional disassembly engine\n"
            "• Section analysis\n"
            "• Entropy analysis\n\n"
            "Professional Features:\n"
            "• Ghidra integration for IDA Pro-level analysis\n"
            "• LibFuzzer integration for coverage-guided fuzzing\n"
            "• Control flow graph generation\n"
            "• Professional hex viewer\n"
            "• Advanced visualization\n"
            "• Export capabilities\n\n"
            "This tool provides professional binary analysis capabilities\n"
            "comparable to commercial tools using open-source components."
        )
    
    def disassemble_at_address(self):
        """Disassemble at specific address"""
        if not hasattr(self, 'current_analysis') or not self.current_analysis:
            QMessageBox.warning(self, "Warning", "Please analyze a file first")
            return
        
        address_text = self.disasm_address_input.toPlainText().strip()
        if not address_text:
            QMessageBox.warning(self, "Warning", "Please enter an address")
            return
        
        try:
            # Parse address
            if address_text.startswith('0x'):
                address = int(address_text, 16)
            else:
                address = int(address_text)
            
            # Get disassembly data
            disassembly = self.current_analysis.get('disassembly', [])
            
            # Find instructions near the address
            relevant_instructions = []
            for instr in disassembly:
                try:
                    instr_addr = int(instr.get('address', '0x0'), 16)
                    if abs(instr_addr - address) < 1000:  # Within 1000 bytes
                        relevant_instructions.append(instr)
                except:
                    continue
            
            # Update disassembly display
            self.update_disassembly_display(relevant_instructions)
            
            # Switch to disassembly tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Disassembly":
                    self.tab_widget.setCurrentIndex(i)
                    break
        
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid address format")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Disassembly failed: {str(e)}")
    
    def goto_hex_offset(self):
        """Go to specific offset in hex viewer"""
        if not hasattr(self, 'current_analysis') or not self.current_analysis:
            QMessageBox.warning(self, "Warning", "Please analyze a file first")
            return
        
        offset_text = self.hex_offset_input.toPlainText().strip()
        if not offset_text:
            return
        
        try:
            if offset_text.startswith('0x'):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
            
            data = self.current_analysis.get('file_data', b'')
            if offset >= len(data):
                QMessageBox.warning(self, "Warning", "Offset beyond file size")
                return
            
            # Show data from offset
            hex_text = self.format_hex_display(data[offset:offset+1024])
            self.hex_display.setPlainText(hex_text)
            
            # Switch to hex viewer tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Hex Viewer":
                    self.tab_widget.setCurrentIndex(i)
                    break
        
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid offset format")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hex viewer error: {str(e)}")
    
    def generate_cfg(self):
        """Generate control flow graph"""
        if not hasattr(self, 'current_analysis') or not self.current_analysis:
            QMessageBox.warning(self, "Warning", "Please analyze a file first")
            return
        
        function_text = self.cfg_function_input.toPlainText().strip()
        if not function_text:
            QMessageBox.warning(self, "Warning", "Please enter a function address")
            return
        
        try:
            # Get analysis engine
            from ..analysis.binary_engine import BinaryAnalysisEngine
            engine = BinaryAnalysisEngine()
            
            # Generate CFG
            result = engine.generate_control_flow_graph(
                self.current_file_path,
                function_text
            )
            
            if 'error' in result:
                self.cfg_display.setPlainText(f"CFG generation failed: {result['error']}")
            else:
                # Format CFG result
                cfg_text = json.dumps(result, indent=2)
                self.cfg_display.setPlainText(cfg_text)
            
            # Switch to CFG tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Control Flow":
                    self.tab_widget.setCurrentIndex(i)
                    break
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"CFG generation failed: {str(e)}")
    
    def start_fuzzing(self):
        """Start fuzzing session"""
        if not hasattr(self, 'current_file_path'):
            QMessageBox.warning(self, "Warning", "Please load a file first")
            return
        
        try:
            # Get fuzzing options
            timeout = int(self.fuzz_timeout_input.toPlainText() or "300")
            memory_mb = int(self.fuzz_memory_input.toPlainText() or "2048")
            
            # Get analysis engine
            from ..analysis.binary_engine import BinaryAnalysisEngine
            engine = BinaryAnalysisEngine()
            
            # Start fuzzing
            options = {
                'fuzzing_options': {
                    'max_time': timeout,
                    'memory_limit_mb': memory_mb
                },
                'harness_type': 'basic_file'
            }
            
            result = engine.start_fuzzing_session(self.current_file_path, options)
            
            if result.get('success'):
                self.fuzzing_results.append(f"Fuzzing started successfully!")
                self.fuzzing_results.append(f"Session ID: {result.get('session_id', 'unknown')}")
                self.fuzzing_results.append(f"Command: {result.get('command', 'unknown')}")
                
                self.start_fuzz_button.setEnabled(False)
                self.stop_fuzz_button.setEnabled(True)
            else:
                error = result.get('error', 'Unknown error')
                self.fuzzing_results.append(f"Fuzzing failed: {error}")
                QMessageBox.critical(self, "Fuzzing Error", f"Failed to start fuzzing: {error}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Fuzzing error: {str(e)}")
    
    def stop_fuzzing(self):
        """Stop fuzzing session"""
        try:
            from ..analysis.binary_engine import BinaryAnalysisEngine
            engine = BinaryAnalysisEngine()
            
            result = engine.stop_fuzzing()
            
            if result.get('success'):
                self.fuzzing_results.append(f"Fuzzing stopped.")
                self.fuzzing_results.append(f"Runtime: {result.get('runtime_seconds', 0):.1f} seconds")
                self.fuzzing_results.append(f"Final stats: {result.get('final_stats', {})}")
            else:
                self.fuzzing_results.append(f"Stop failed: {result.get('error', 'Unknown error')}")
            
            self.start_fuzz_button.setEnabled(True)
            self.stop_fuzz_button.setEnabled(False)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Stop fuzzing error: {str(e)}")
    
    def show_fuzz_stats(self):
        """Show fuzzing statistics"""
        try:
            from ..analysis.binary_engine import BinaryAnalysisEngine
            engine = BinaryAnalysisEngine()
            
            stats = engine.get_fuzzing_stats()
            
            if 'error' in stats:
                self.fuzzing_results.append(f"Stats error: {stats['error']}")
            else:
                self.fuzzing_results.append("=== FUZZING STATISTICS ===")
                self.fuzzing_results.append(json.dumps(stats, indent=2))
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Stats error: {str(e)}")
    
    def run_advanced_analysis(self):
        """Run advanced analysis with Ghidra"""
        if not hasattr(self, 'current_file_path'):
            QMessageBox.warning(self, "Warning", "Please load a file first")
            return
        
        try:
            from ..analysis.binary_engine import BinaryAnalysisEngine
            engine = BinaryAnalysisEngine()
            
            if not engine.ghidra_analyzer or not engine.ghidra_analyzer.is_available():
                QMessageBox.information(
                    self, 
                    "Ghidra Not Available", 
                    "Ghidra is not installed or configured.\n"
                    "Please install Ghidra to use advanced analysis features."
                )
                return
            
            # Show progress
            progress = QProgressBar()
            progress.setRange(0, 0)  # Indeterminate
            self.status_bar.addWidget(progress)
            
            self.status_bar.showMessage("Running advanced analysis with Ghidra...")
            
            # Run analysis
            result = engine.perform_ghidra_analysis(self.current_file_path)
            
            # Remove progress bar
            self.status_bar.removeWidget(progress)
            
            # Update analysis display
            self.update_advanced_analysis(result)
            
            # Switch to advanced analysis tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Advanced Analysis":
                    self.tab_widget.setCurrentIndex(i)
                    break
            
            self.status_bar.showMessage("Advanced analysis completed")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Advanced analysis failed: {str(e)}")
    
    def export_analysis(self):
        """Export analysis results"""
        if not hasattr(self, 'current_analysis'):
            QMessageBox.warning(self, "Warning", "No analysis to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Analysis", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_analysis, f, indent=2, default=str)
                QMessageBox.information(self, "Success", f"Analysis exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def export_disassembly(self):
        """Export disassembly"""
        if not hasattr(self, 'current_analysis'):
            QMessageBox.warning(self, "Warning", "No analysis to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Disassembly", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                disassembly = self.current_analysis.get('disassembly', [])
                with open(file_path, 'w') as f:
                    f.write("BinFreak Disassembly Export\n")
                    f.write("=" * 50 + "\n\n")
                    for instr in disassembly:
                        f.write(f"{instr.get('address', '')} {instr.get('bytes', '')} "
                               f"{instr.get('mnemonic', '')} {instr.get('operands', '')}\n")
                QMessageBox.information(self, "Success", f"Disassembly exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def show_cfg_dialog(self):
        """Show CFG generation dialog"""
        # Switch to CFG tab
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == "Control Flow":
                self.tab_widget.setCurrentIndex(i)
                break
    
    def open_fuzzing_interface(self):
        """Open fuzzing interface"""
        # Switch to fuzzing tab
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == "Fuzzing":
                self.tab_widget.setCurrentIndex(i)
                break
    
    def open_hex_viewer(self):
        """Open hex viewer"""
        # Switch to hex viewer tab
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == "Hex Viewer":
                self.tab_widget.setCurrentIndex(i)
                break
    
    def open_binary_comparison(self):
        """Open binary comparison tool"""
        QMessageBox.information(
            self, 
            "Binary Comparison", 
            "Binary comparison feature coming soon!\n"
            "This will allow comparing two binaries side-by-side."
        )
    
    def show_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts = """
Keyboard Shortcuts:

File Operations:
Ctrl+O - Open Binary File
Ctrl+Q - Exit Application

Analysis:
Ctrl+A - Run Advanced Analysis
Ctrl+H - Open Hex Viewer

Navigation:
Tab - Switch between analysis tabs
Ctrl+Tab - Navigate tabs
"""
        QMessageBox.information(self, "Keyboard Shortcuts", shortcuts)