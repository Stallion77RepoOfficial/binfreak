"""
Main application window for BinFreak
"""

import sys
import os
from datetime import datetime
from typing import Dict, Any

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem, 
    QStatusBar, QMenuBar, QFileDialog, QProgressBar, QLabel,
    QToolBar, QPushButton, QMessageBox, QComboBox, QLineEdit,
    QGroupBox, QCheckBox, QSpinBox, QTableWidget, QTableWidgetItem,
    QFormLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QFont

from ..core.license_manager import SimpleLicenseManager
from ..analysis.binary_engine import BinaryAnalysisEngine
from .ui_components import UIComponents
from .menu_manager import MenuManager
from .tab_manager import TabManager


class AnalysisWorker(QThread):
    """Background analysis worker"""
    
    progress_updated = pyqtSignal(int)
    analysis_completed = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.engine = BinaryAnalysisEngine()
    
    def run(self):
        """Run analysis in background"""
        try:
            self.progress_updated.emit(25)
            result = self.engine.analyze_file(self.file_path)
            self.progress_updated.emit(75)
            result['success'] = True
            self.progress_updated.emit(100)
            self.analysis_completed.emit(result)
        except Exception as e:
            self.error_occurred.emit(str(e))


class SimplifiedMainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.license_manager = SimpleLicenseManager()
        self.analysis_engine = BinaryAnalysisEngine()
        self.current_analysis = None
        
        self.setWindowTitle("BinFreak - Advanced Binary Analysis Tool")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Initialize UI components
        self.ui_components = UIComponents(self)
        self.menu_manager = MenuManager(self)
        self.tab_manager = TabManager(self)
        
        self.setup_ui()
        self.setup_menus()
        self.setup_status_bar()
        self.setup_keyboard_shortcuts()
        
        # Check license on startup
        if not self.license_manager.is_licensed:
            self.show_registration_dialog()
    
    def setup_ui(self):
        """Setup main UI layout"""
        self.ui_components.setup_main_layout()
    
    def setup_menus(self):
        """Setup application menus"""
        self.menu_manager.setup_menus()
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # License status
        license_info = self.license_manager.get_license_info()
        status_text = f"License: {license_info['status']}"
        if license_info['status'] == 'Licensed':
            status_text += f" (expires: {license_info.get('expiry', 'unknown')})"
        
        status_text += " | Navigation: ← → arrows, Ctrl+← Ctrl+→, Tab/Shift+Tab"
        
        self.status_bar.showMessage(status_text)
    
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts"""
        from PyQt6.QtGui import QShortcut, QKeySequence
        from PyQt6.QtCore import Qt
        
        # Global shortcuts that work regardless of focus
        self.right_shortcut = QShortcut(QKeySequence("Ctrl+Right"), self)
        self.right_shortcut.activated.connect(self.next_left_tab)
        
        self.left_shortcut = QShortcut(QKeySequence("Ctrl+Left"), self)
        self.left_shortcut.activated.connect(self.prev_left_tab)
        
        # Alternative shortcuts
        self.tab_shortcut = QShortcut(QKeySequence("Tab"), self)
        self.tab_shortcut.activated.connect(self.next_left_tab)
        
        self.shift_tab_shortcut = QShortcut(QKeySequence("Shift+Tab"), self)
        self.shift_tab_shortcut.activated.connect(self.prev_left_tab)
    
    def keyPressEvent(self, event):
        """Handle key press events"""
        from PyQt6.QtCore import Qt
        
        # Only handle arrows when left panel has focus or no other widget is focused
        if event.key() == Qt.Key.Key_Right:
            self.next_left_tab()
            event.accept()
            return
        elif event.key() == Qt.Key.Key_Left:
            self.prev_left_tab()
            event.accept()
            return
        
        # Pass other keys to parent
        super().keyPressEvent(event)
    
    def next_left_tab(self):
        """Move to next tab in left panel"""
        try:
            if hasattr(self, 'left_tabs') and self.left_tabs:
                current = self.left_tabs.currentIndex()
                next_index = (current + 1) % self.left_tabs.count()
                self.left_tabs.setCurrentIndex(next_index)
                tab_name = self.left_tabs.tabText(next_index)
                self.log(f"→ Switched to: {tab_name}")
            else:
                self.log("Left tabs not available yet")
        except Exception as e:
            self.log(f"Error switching tab: {e}")
    
    def prev_left_tab(self):
        """Move to previous tab in left panel"""
        try:
            if hasattr(self, 'left_tabs') and self.left_tabs:
                current = self.left_tabs.currentIndex()
                prev_index = (current - 1) % self.left_tabs.count()
                self.left_tabs.setCurrentIndex(prev_index)
                tab_name = self.left_tabs.tabText(prev_index)
                self.log(f"← Switched to: {tab_name}")
            else:
                self.log("Left tabs not available yet")
        except Exception as e:
            self.log(f"Error switching tab: {e}")
    
    def show_registration_dialog(self):
        """Show license information for open source version"""
        QMessageBox.information(self, "BinFreak Open Source", 
                               "This is the open source version of BinFreak.\n\n"
                               "All features are available without registration.\n"
                               "Thank you for using BinFreak!")

    def show_license_status(self):
        """Show license status for open source version"""
        try:
            license_info = self.license_manager.get_license_info()
            status_text = f"License Status: {license_info['status']}\n"
            status_text += f"Version: {license_info['version']}\n"
            status_text += f"Features: {', '.join(license_info['features'])}"
            
            QMessageBox.information(self, "License Status", status_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to get license status: {str(e)}")
            self.log(f"License status error: {str(e)}")

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About BinFreak", 
                         "BinFreak v1.0\nAdvanced Binary Analysis Tool\n\n"
                         "Features:\n"
                         "• Binary format detection\n"
                         "• String extraction\n" 
                         "• Function analysis\n"
                         "• Disassembly engine\n"
                         "• Entropy visualization\n"
                         "• Fuzzing capabilities")
    
    def open_file(self):
        """Open binary file for analysis"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary File", "", "All Files (*)")
        
        if file_path:
            self.log(f"Loading file: {file_path}")
            self.start_analysis_worker(file_path)
    
    def start_analysis_worker(self, file_path: str):
        """Start analysis in background thread"""
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.analysis_worker = AnalysisWorker(file_path)
        self.analysis_worker.progress_updated.connect(self.progress_bar.setValue)
        self.analysis_worker.analysis_completed.connect(self.analysis_completed)
        self.analysis_worker.error_occurred.connect(self.analysis_error)
        self.analysis_worker.start()
    
    def analysis_completed(self, result: Dict[str, Any]):
        """Handle completed analysis"""
        self.progress_bar.setVisible(False)
        self.current_analysis = result
        
        if 'error' in result:
            self.log(f"Analysis error: {result['error']}")
            return
        
        # Update UI with analysis results
        self.ui_components.update_analysis_results(result)
        self.tab_manager.update_tabs_with_results(result)
        
        # Update visualization if available
        if hasattr(self, 'visualization_tab'):
            self.visualization_tab.update_visualization(result)
            # Also set binary data for entropy calculation
            if 'file_data' in result:
                self.visualization_tab.entropy_widget.set_binary_data(result['file_data'])
        
        # Update fuzzing target display
        if hasattr(self, 'target_display'):
            file_path = result.get('file_path', 'Unknown')
            self.target_display.setText(os.path.basename(file_path))
        
        self.log("Analysis completed successfully")
    
    def analysis_error(self, error: str):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.log(f"Analysis failed: {error}")
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n{error}")
    
    def log(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if hasattr(self, 'log_text'):
            self.log_text.append(f"[{timestamp}] {message}")
        else:
            print(f"[{timestamp}] {message}")
    
    def set_progress_bar(self, progress_bar):
        """Set progress bar reference"""
        self.progress_bar = progress_bar
    
    def set_log_text(self, log_text):
        """Set log text widget reference"""
        self.log_text = log_text
    
    def start_fuzzing(self):
        """Start fuzzing session"""
        # Use currently loaded file as target
        if not self.current_analysis or 'file_path' not in self.current_analysis:
            QMessageBox.warning(self, "Warning", "Please load a binary file first")
            return
        
        target_path = self.current_analysis['file_path']
        
        if not os.path.exists(target_path):
            QMessageBox.warning(self, "Warning", "Target binary no longer exists")
            return
        
        # Initialize fuzzing engine
        from ..analysis.fuzzing_engine import FuzzingEngine
        self.fuzzing_engine = FuzzingEngine()
        
        # Start fuzzing
        parameters = {
            'timeout': 60,
            'max_iterations': 100000
        }
        
        result = self.fuzzing_engine.start_fuzzing(target_path, parameters)
        self.log(f"Fuzzing started on {os.path.basename(target_path)}: {result}")
        
        # Start background fuzzing
        self.fuzzing_engine.run_fuzzing_background()
        
        # Update UI
        self.start_fuzz_btn.setEnabled(False)
        self.stop_fuzz_btn.setEnabled(True)
        
        # Start stats timer
        self.fuzz_timer = QTimer()
        self.fuzz_timer.timeout.connect(self.update_fuzzing_stats)
        self.fuzz_timer.start(1000)  # Update every second
    
    def stop_fuzzing(self):
        """Stop fuzzing session"""
        if hasattr(self, 'fuzzing_engine'):
            result = self.fuzzing_engine.stop_fuzzing()
            self.log(f"Fuzzing stopped: {result}")
        
        # Update UI
        self.start_fuzz_btn.setEnabled(True)
        self.stop_fuzz_btn.setEnabled(False)
        
        # Stop timer
        if hasattr(self, 'fuzz_timer'):
            self.fuzz_timer.stop()
    
    def update_fuzzing_stats(self):
        """Update fuzzing statistics display"""
        if hasattr(self, 'fuzzing_engine'):
            stats = self.fuzzing_engine.get_stats()
            
            # Update stats text
            stats_text = f"""
Running: {stats['running']}
Test Cases: {stats['test_cases']:,}
Crashes Found: {stats['crashes']}
Unique Crashes: {stats['unique_crashes']}
Executions/sec: {stats['exec_per_sec']:,}
Corpus Size: {stats['corpus_size']}
            """.strip()
            
            self.fuzz_stats.setText(stats_text)
            
            # Update crash table
            self.update_crash_table(stats['crash_details'])
    
    def update_crash_table(self, crashes):
        """Update crash results table"""
        self.crash_table.setRowCount(len(crashes))
        
        for i, crash in enumerate(crashes):
            self.crash_table.setItem(i, 0, QTableWidgetItem(str(crash['crash_id'])))
            self.crash_table.setItem(i, 1, QTableWidgetItem(crash['timestamp']))
            self.crash_table.setItem(i, 2, QTableWidgetItem(str(crash['signal'])))
            self.crash_table.setItem(i, 3, QTableWidgetItem(str(crash['input_size'])))
            self.crash_table.setItem(i, 4, QTableWidgetItem(crash['input_hash']))
            
            # Determine if exploitable
            exploitable = "Likely" if crash['signal'] in [11, 6, 4] else "Unknown"
            self.crash_table.setItem(i, 5, QTableWidgetItem(exploitable))
