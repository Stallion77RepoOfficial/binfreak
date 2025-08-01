#!/usr/bin/env python3
"""
BinFreak - Advanced Binary Analysis Tool
Main entry point for the application
"""

import sys
import os

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from binfreak import BinFreakMainWindow, LicenseManager

try:
    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtCore import Qt
except ImportError:
    print("Error: PyQt6 is required to run BinFreak")
    print("Install with: pip install PyQt6")
    sys.exit(1)


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("BinFreak")
    app.setApplicationVersion("1.0.0")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Initialize license manager
    license_manager = LicenseManager()
    
    # Check license (open-source version - always valid)
    if not license_manager.check_license():
        # Auto-activate open source license if needed
        license_manager.register_license("opensource@binfreak.local", "opensource123")
    
    # Create and show main window
    try:
        main_window = BinFreakMainWindow()
        main_window.show()
        
        return app.exec()
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to start BinFreak: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
