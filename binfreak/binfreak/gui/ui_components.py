"""
UI Components manager for the main window
"""

import os
from datetime import datetime
from typing import Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QTextEdit, QTreeWidget, QTreeWidgetItem, QLabel, QLineEdit,
    QGroupBox, QProgressBar, QTableWidget, QTableWidgetItem,
    QToolBar, QPushButton, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont


class UIComponents:
    """Manages UI components for the main window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
    
    def setup_main_layout(self):
        """Setup main UI layout"""
        central_widget = QWidget()
        self.main_window.setCentralWidget(central_widget)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - File info, functions, and symbols with search
        left_panel = self._create_left_panel()
        
        # Center panel - Tabbed interface
        center_panel = self._create_center_panel()
        
        # Right panel - Properties and logs
        right_panel = self._create_right_panel()
        
        # Add panels to splitter
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(center_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([300, 800, 300])
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        
        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # Progress bar (hidden by default)
        progress_bar = QProgressBar()
        progress_bar.setVisible(False)
        layout.addWidget(progress_bar)
        self.main_window.set_progress_bar(progress_bar)
        
        layout.addWidget(main_splitter)
    
    def _create_left_panel(self) -> QWidget:
        """Create left panel with file info and analysis trees"""
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # File info
        self.main_window.file_info = QTextEdit()
        self.main_window.file_info.setMaximumHeight(100)
        self.main_window.file_info.setPlaceholderText("No file loaded")
        left_layout.addWidget(QLabel("File Information:"))
        left_layout.addWidget(self.main_window.file_info)
        
        # Search/Filter section
        filter_group = QGroupBox("Search & Filter")
        filter_layout = QVBoxLayout(filter_group)
        
        self.main_window.search_input = QLineEdit()
        self.main_window.search_input.setPlaceholderText("Search functions, symbols...")
        self.main_window.search_input.textChanged.connect(self._filter_items)
        filter_layout.addWidget(self.main_window.search_input)
        
        left_layout.addWidget(filter_group)
        
        # Detailed tabbed view for functions, symbols, etc.
        self.main_window.left_tabs = QTabWidget()
        
        # Enable keyboard navigation for tabs
        self.main_window.left_tabs.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        # Connect mouse click to focus
        self.main_window.left_tabs.currentChanged.connect(self._on_tab_changed)
        
        # Functions tab
        self._create_functions_tab()
        
        # Symbols tab
        self._create_symbols_tab()
        
        # Imports tab
        self._create_imports_tab()
        
        # Exports tab
        self._create_exports_tab()
        
        left_layout.addWidget(self.main_window.left_tabs)
        
        # Set initial focus to allow keyboard navigation
        self.main_window.left_tabs.setFocus()
        
        return left_panel
    
    def _create_functions_tab(self):
        """Create functions tab"""
        function_tab = QWidget()
        func_layout = QVBoxLayout(function_tab)
        
        self.main_window.function_list = QTreeWidget()
        self.main_window.function_list.setHeaderLabels(["Address", "Name", "Type", "Size"])
        self.main_window.function_list.itemDoubleClicked.connect(self._on_function_double_click)
        func_layout.addWidget(self.main_window.function_list)
        
        self.main_window.left_tabs.addTab(function_tab, "Functions")
    
    def _create_symbols_tab(self):
        """Create symbols tab"""
        symbols_tab = QWidget()
        symbols_layout = QVBoxLayout(symbols_tab)
        
        self.main_window.symbols_list = QTreeWidget()
        self.main_window.symbols_list.setHeaderLabels(["Address", "Symbol", "Type", "Module"])
        self.main_window.symbols_list.itemDoubleClicked.connect(self._on_symbol_double_click)
        symbols_layout.addWidget(self.main_window.symbols_list)
        
        self.main_window.left_tabs.addTab(symbols_tab, "Symbols")
    
    def _create_imports_tab(self):
        """Create imports tab"""
        imports_tab = QWidget()
        imports_layout = QVBoxLayout(imports_tab)
        
        self.main_window.imports_list = QTreeWidget()
        self.main_window.imports_list.setHeaderLabels(["Function", "Library", "Address"])
        imports_layout.addWidget(self.main_window.imports_list)
        
        self.main_window.left_tabs.addTab(imports_tab, "Imports")
    
    def _create_exports_tab(self):
        """Create exports tab"""
        exports_tab = QWidget()
        exports_layout = QVBoxLayout(exports_tab)
        
        self.main_window.exports_list = QTreeWidget()
        self.main_window.exports_list.setHeaderLabels(["Function", "Address", "Ordinal"])
        exports_layout.addWidget(self.main_window.exports_list)
        
        self.main_window.left_tabs.addTab(exports_tab, "Exports")
    
    def _create_center_panel(self) -> QWidget:
        """Create center panel with tabs"""
        self.main_window.tab_widget = QTabWidget()
        
        # Analysis tab
        self.main_window.analysis_tab = QTextEdit()
        self.main_window.analysis_tab.setFont(QFont("Monaco", 10))
        self.main_window.tab_widget.addTab(self.main_window.analysis_tab, "Analysis")
        
        # Strings tab
        self.main_window.strings_tab = QTableWidget()
        self.main_window.strings_tab.setColumnCount(2)
        self.main_window.strings_tab.setHorizontalHeaderLabels(["Offset", "String"])
        self.main_window.tab_widget.addTab(self.main_window.strings_tab, "Strings")
        
        # Disassembly tab
        self.main_window.disassembly_tab = QTextEdit()
        self.main_window.disassembly_tab.setFont(QFont("Monaco", 9))
        self.main_window.disassembly_tab.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        self.main_window.tab_widget.addTab(self.main_window.disassembly_tab, "Disassembly")
        
        # Functions tab
        self.main_window.functions_tab = QTableWidget()
        self.main_window.functions_tab.setColumnCount(4)
        self.main_window.functions_tab.setHorizontalHeaderLabels(["Address", "Name", "Size", "Type"])
        self.main_window.tab_widget.addTab(self.main_window.functions_tab, "Functions")
        
        # Fuzzing tab
        self.main_window.fuzzing_tab = self._create_fuzzing_tab()
        self.main_window.tab_widget.addTab(self.main_window.fuzzing_tab, "Fuzzing")
        
        # Visualization tab
        try:
            from ..gui.visualization import AdvancedVisualizationWidget
            self.main_window.visualization_tab = AdvancedVisualizationWidget()
            self.main_window.tab_widget.addTab(self.main_window.visualization_tab, "Visualization")
        except ImportError:
            pass
        
        return self.main_window.tab_widget
    
    def _create_right_panel(self) -> QWidget:
        """Create right panel with properties and logs"""
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Properties
        self.main_window.properties_text = QTextEdit()
        self.main_window.properties_text.setMaximumHeight(200)
        right_layout.addWidget(QLabel("Properties:"))
        right_layout.addWidget(self.main_window.properties_text)
        
        # Logs
        self.main_window.log_text = QTextEdit()
        right_layout.addWidget(QLabel("Logs:"))
        right_layout.addWidget(self.main_window.log_text)
        
        # Set log text reference
        self.main_window.set_log_text(self.main_window.log_text)
        
        return right_panel
    
    def _create_toolbar(self) -> QToolBar:
        """Create main toolbar"""
        toolbar = QToolBar()
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        
        # Open file - bigger and more prominent
        open_action = QAction("📁 Open Binary File", self.main_window)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.main_window.open_file)
        toolbar.addAction(open_action)
        
        return toolbar
    
    def update_analysis_results(self, result: Dict[str, Any]):
        """Update UI with analysis results"""
        try:
            # Update file info safely
            file_path = result.get('file_path', 'Unknown')
            if file_path and os.path.exists(file_path):
                file_stats = os.stat(file_path)
                creation_time = datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                modification_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                file_name = os.path.basename(file_path)
            else:
                creation_time = modification_time = 'Unknown'
                file_name = 'Unknown'
            
            # Get safe values for display
            file_size = result.get('file_size', 0)
            file_format = result.get('file_format', {})
            format_text = file_format.get('type', 'Unknown') if isinstance(file_format, dict) else str(file_format)
            
            info_text = f"""Name: {file_name}
Size: {file_size:,} bytes
Format: {format_text}
Architecture: {self._get_architecture_info(result)}
Created: {creation_time}
Modified: {modification_time}"""
            
            self.main_window.file_info.setPlainText(info_text)
            
            # Update analysis tab
            import json
            analysis_text = json.dumps(result, indent=2, default=str)
            self.main_window.analysis_tab.setPlainText(analysis_text[:5000])  # Limit size
            
            # Update strings
            self._update_strings_tab(result)
            
            # Update function and symbol lists
            self._update_function_list(result)
            self._update_symbol_list(result)
            
            # Update properties
            self._update_properties(result)
            
        except Exception as e:
            error_text = f"Error updating UI: {str(e)}"
            self.main_window.file_info.setPlainText(error_text)
            if hasattr(self.main_window, 'log'):
                self.main_window.log(f"UI update error: {e}")
        self.main_window.analysis_tab.setPlainText(analysis_text)
        
        # Update strings tab
        self.main_window.strings_tab.setRowCount(len(result['strings']))
        for i, string in enumerate(result['strings']):
            self.main_window.strings_tab.setItem(i, 0, QTableWidgetItem(str(i)))
            self.main_window.strings_tab.setItem(i, 1, QTableWidgetItem(string))
        
        # Update function list
        self.main_window.function_list.clear()
        for func in result['functions']:
            func_size = "~100 bytes"  # Simplified estimation
            
            item = QTreeWidgetItem([
                func.get('address', ''),
                func.get('name', ''),
                func.get('type', ''),
                func_size
            ])
            self.main_window.function_list.addTopLevelItem(item)
        
        # Update symbols, imports, exports lists
        self._update_symbols_list(result)
        self._update_imports_list(result)
        self._update_exports_list(result)
        
        # Update properties
        self._update_properties(result)
    
    def _get_architecture_info(self, result: Dict[str, Any]) -> str:
        """Get architecture information from format"""
        format_str = result.get('file_format', 'Unknown')
        if 'ELF' in format_str:
            if '64-bit' in format_str:
                return 'x86-64'
            elif '32-bit' in format_str:
                return 'x86'
        elif 'PE' in format_str:
            if 'x86-64' in format_str:
                return 'x86-64'
            elif 'i386' in format_str:
                return 'x86'
        elif 'Mach-O' in format_str:
            if '64-bit' in format_str:
                return 'x86-64/ARM64'
            else:
                return 'x86/ARM'
        return 'Unknown'
    
    def _update_symbols_list(self, result: Dict[str, Any]):
        """Update symbols list"""
        self.main_window.symbols_list.clear()
        symbols = self._extract_symbols(result)
        for symbol in symbols:
            item = QTreeWidgetItem([
                symbol.get('address', ''),
                symbol.get('name', ''),
                symbol.get('type', ''),
                symbol.get('module', '')
            ])
            self.main_window.symbols_list.addTopLevelItem(item)
    
    def _update_imports_list(self, result: Dict[str, Any]):
        """Update imports list"""
        self.main_window.imports_list.clear()
        imports = self._extract_imports(result)
        for imp in imports:
            item = QTreeWidgetItem([
                imp.get('function', ''),
                imp.get('library', ''),
                imp.get('address', '')
            ])
            self.main_window.imports_list.addTopLevelItem(item)
    
    def _update_exports_list(self, result: Dict[str, Any]):
        """Update exports list"""
        self.main_window.exports_list.clear()
        exports = self._extract_exports(result)
        for exp in exports:
            item = QTreeWidgetItem([
                exp.get('function', ''),
                exp.get('address', ''),
                str(exp.get('ordinal', ''))
            ])
            self.main_window.exports_list.addTopLevelItem(item)
    
    def _update_properties(self, result: Dict[str, Any]):
        """Update properties panel"""
        # Calculate average entropy if it's a list
        entropy_data = result.get('entropy', [])
        if isinstance(entropy_data, list) and entropy_data:
            avg_entropy = sum(entropy_data) / len(entropy_data)
            entropy_text = f"{avg_entropy:.3f} (avg of {len(entropy_data)} blocks)"
        elif isinstance(entropy_data, (int, float)):
            entropy_text = f"{entropy_data:.3f}"
        else:
            entropy_text = "N/A"
        
        props_text = f"""Functions: {len(result.get('functions', []))}
Strings: {len(result.get('strings', []))}
Entropy: {entropy_text}
Entry Point: {self._get_entry_point(result)}
Sections: {len(result.get('sections', []))}
File Format: {result.get('file_format', {}).get('type', 'Unknown')}
File Size: {result.get('file_size', 0):,} bytes"""
        
        self.main_window.properties_text.setPlainText(props_text)
    
    def _extract_symbols(self, result: Dict[str, Any]) -> list:
        """Extract symbols from analysis result"""
        symbols = []
        
        # Add function symbols
        for func in result.get('functions', []):
            symbols.append({
                'address': func.get('address', ''),
                'name': func.get('name', ''),
                'type': 'Function',
                'module': 'main'
            })
        
        return symbols
    
    def _extract_imports(self, result: Dict[str, Any]) -> list:
        """Extract imports from analysis result"""
        return result.get('imports', [])
    
    def _extract_exports(self, result: Dict[str, Any]) -> list:
        """Extract exports from analysis result"""
        return result.get('exports', [])
    
    def _get_entry_point(self, result: Dict[str, Any]) -> str:
        """Get entry point from analysis result"""
        entry_point = result.get('entry_point', 'Unknown')
        if entry_point and entry_point != 'Unknown':
            return str(entry_point)
        return 'Not detected'
    
    def _filter_items(self):
        """Filter functions and symbols based on search text"""
        search_text = self.main_window.search_input.text().lower()
        
        # Filter functions
        for i in range(self.main_window.function_list.topLevelItemCount()):
            item = self.main_window.function_list.topLevelItem(i)
            function_name = item.text(1).lower()
            function_addr = item.text(0).lower()
            visible = search_text in function_name or search_text in function_addr
            item.setHidden(not visible)
        
        # Filter symbols
        for i in range(self.main_window.symbols_list.topLevelItemCount()):
            item = self.main_window.symbols_list.topLevelItem(i)
            symbol_name = item.text(1).lower()
            symbol_addr = item.text(0).lower()
            visible = search_text in symbol_name or search_text in symbol_addr
            item.setHidden(not visible)
    
    def _on_function_double_click(self, item, column):
        """Handle function double click"""
        function_addr = item.text(0)
        function_name = item.text(1)
        self.main_window.log(f"Function selected: {function_name} at {function_addr}")
    
    def _on_symbol_double_click(self, item, column):
        """Handle symbol double click"""
        symbol_addr = item.text(0)
        symbol_name = item.text(1)
        self.main_window.log(f"Symbol selected: {symbol_name} at {symbol_addr}")
    
    def _create_fuzzing_tab(self) -> QWidget:
        """Create fuzzing tab with controls and results"""
        fuzzing_widget = QWidget()
        layout = QVBoxLayout(fuzzing_widget)
        
        # Fuzzing controls
        controls_group = QGroupBox("Fuzzing Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Target display
        target_label = QLabel("Target:")
        self.main_window.target_display = QLabel("No file loaded")
        self.main_window.target_display.setStyleSheet("color: #666; padding: 5px; border: 1px solid #ccc;")
        
        # Fuzzing buttons
        self.main_window.start_fuzz_btn = QPushButton("Start Fuzzing")
        self.main_window.stop_fuzz_btn = QPushButton("Stop Fuzzing")
        self.main_window.stop_fuzz_btn.setEnabled(False)
        
        # Connect buttons
        self.main_window.start_fuzz_btn.clicked.connect(self.main_window.start_fuzzing)
        self.main_window.stop_fuzz_btn.clicked.connect(self.main_window.stop_fuzzing)
        
        controls_layout.addWidget(target_label)
        controls_layout.addWidget(self.main_window.target_display)
        controls_layout.addStretch()
        controls_layout.addWidget(self.main_window.start_fuzz_btn)
        controls_layout.addWidget(self.main_window.stop_fuzz_btn)
        
        layout.addWidget(controls_group)
        
        # Results
        results_group = QGroupBox("Fuzzing Results")
        results_layout = QVBoxLayout(results_group)
        
        self.main_window.fuzz_results = QTextEdit()
        self.main_window.fuzz_results.setReadOnly(True)
        results_layout.addWidget(self.main_window.fuzz_results)
        
        layout.addWidget(results_group)
        
        return fuzzing_widget
    
    def _on_tab_changed(self, index):
        """Handle tab change to maintain focus"""
        if hasattr(self.main_window, 'left_tabs'):
            self.main_window.left_tabs.setFocus()
            tab_name = self.main_window.left_tabs.tabText(index)
            self.main_window.log(f"Tab changed to: {tab_name} (Use ← → arrows to navigate)")
