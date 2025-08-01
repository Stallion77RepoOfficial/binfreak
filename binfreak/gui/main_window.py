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
        
        # Strings tab
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(2)
        self.strings_table.setHorizontalHeaderLabels(["Index", "String"])
        self.strings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tab_widget.addTab(self.strings_table, "Strings")
        
        # Functions tab
        self.functions_tree = QTreeWidget()
        self.functions_tree.setHeaderLabels(["Address", "Name", "Type", "Size"])
        self.tab_widget.addTab(self.functions_tree, "Functions")
        
        # Sections tab
        self.sections_tree = QTreeWidget()
        self.sections_tree.setHeaderLabels(["Name", "Address", "Size", "Type"])
        self.tab_widget.addTab(self.sections_tree, "Sections")
        
        # Raw analysis tab
        self.raw_analysis = QTextEdit()
        self.raw_analysis.setFont(QFont("Courier", 10))
        self.raw_analysis.setReadOnly(True)
        self.tab_widget.addTab(self.raw_analysis, "Raw Analysis")
        
        parent.addWidget(self.tab_widget)
    
    def setup_menus(self):
        """Setup application menus"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open Binary...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
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
        
        # Update strings table
        self.update_strings_table(result.get('strings', []))
        
        # Update functions tree
        self.update_functions_tree(result.get('functions', []))
        
        # Update sections tree
        self.update_sections_tree(result.get('sections', []))
        
        # Update raw analysis
        self.raw_analysis.setPlainText(json.dumps(result, indent=2, default=str))
        
        self.status_bar.showMessage("Analysis completed")
    
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
    
    def update_strings_table(self, strings: list):
        """Update strings table"""
        self.strings_table.setRowCount(len(strings))
        for i, string in enumerate(strings):
            self.strings_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.strings_table.setItem(i, 1, QTableWidgetItem(str(string)))
    
    def update_functions_tree(self, functions: list):
        """Update functions tree"""
        self.functions_tree.clear()
        for func in functions:
            item = QTreeWidgetItem([
                func.get('address', 'Unknown'),
                func.get('name', 'Unknown'),
                func.get('type', 'Unknown'),
                str(func.get('size', 'Unknown'))
            ])
            self.functions_tree.addTopLevelItem(item)
    
    def update_sections_tree(self, sections: list):
        """Update sections tree"""
        self.sections_tree.clear()
        for section in sections:
            item = QTreeWidgetItem([
                section.get('name', 'Unknown'),
                section.get('address', 'Unknown'),
                str(section.get('size', 'Unknown')),
                section.get('type', 'Unknown')
            ])
            self.sections_tree.addTopLevelItem(item)
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self, 
            "About BinFreak",
            "BinFreak v2.0 - Simplified Binary Analysis Tool\n\n"
            "A clean, modular binary analysis tool focused on core functionality.\n\n"
            "Features:\n"
            "• Binary format detection\n"
            "• String extraction\n"
            "• Function detection\n"
            "• Section analysis\n"
            "• Entropy analysis"
        )