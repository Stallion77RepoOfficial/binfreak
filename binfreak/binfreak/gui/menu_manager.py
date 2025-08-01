"""
Menu manager for the main window
"""

from PyQt6.QtWidgets import QMenuBar, QMessageBox
from PyQt6.QtGui import QAction


class MenuManager:
    """Manages menus for the main window"""
    
    def __init__(self, main_window):
        self.main_window = main_window
    
    def setup_menus(self):
        """Setup application menus"""
        menubar = self.main_window.menuBar()
        
        # File menu (simplified)
        self._create_file_menu(menubar)
        
        # License menu
        self._create_license_menu(menubar)
        
        # Help menu
        self._create_help_menu(menubar)
    
    def _create_file_menu(self, menubar):
        """Create simplified file menu"""
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open Binary File", self.main_window)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.main_window.open_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self.main_window)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.main_window.close)
        file_menu.addAction(exit_action)
    
    def _create_license_menu(self, menubar):
        """Create license menu"""
        license_menu = menubar.addMenu("License")
        
        register_action = QAction("Register License", self.main_window)
        register_action.triggered.connect(self.main_window.show_registration_dialog)
        license_menu.addAction(register_action)
        
        status_action = QAction("License Status", self.main_window)
        status_action.triggered.connect(self.main_window.show_license_status)
        license_menu.addAction(status_action)
    
    def _create_help_menu(self, menubar):
        """Create help menu"""
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self.main_window)
        about_action.triggered.connect(self.main_window.show_about)
        help_menu.addAction(about_action)
