#!/usr/bin/env python3
"""
BinFreak - Simplified Binary Analysis Tool
Clean, modular implementation focusing on core functionality
"""

import sys
import os
from pathlib import Path

# Ensure sys.path is clean and correctly configured
sys.path = list(dict.fromkeys(sys.path))
sys.path.insert(0, str(Path(__file__).parent))

print("sys.path:", sys.path)

def main():
    """Main application entry point"""
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("Error: PyQt6 is required to run BinFreak")
        print("Install with: pip install PyQt6")
        sys.exit(1)

    from binfreak.binfreak.gui.main_window import SimplifiedMainWindow
    
    app = QApplication(sys.argv)
    app.setApplicationName("BinFreak")
    app.setApplicationVersion("2.0.0")
    app.setStyle('Fusion')
    
    # Create simplified main window
    window = SimplifiedMainWindow()
    window.show()
    
    return app.exec()


def test_analysis(file_path: str):
    """Test the analysis engine without GUI"""
    sys.path.insert(0, str(Path(__file__).parent))
    
    # Import only what we need for testing
    from binfreak.binfreak.analysis.binary_engine import BinaryAnalysisEngine
    
    engine = BinaryAnalysisEngine()
    result = engine.analyze_file(file_path)
    
    if 'error' in result:
        print(f"Analysis failed: {result['error']}")
        return False
    
    print(f"Analysis successful!")
    print(f"File: {result['file_path']}")
    print(f"Size: {result['file_size']} bytes")
    print(f"Format: {result['file_format'].get('type', 'Unknown')}")
    print(f"Functions found: {len(result.get('functions', []))}")
    print(f"Strings found: {len(result.get('strings', []))}")
    print(f"Analysis time: {result.get('analysis_duration', 'Unknown')}")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Test mode without GUI
        if len(sys.argv) > 2:
            test_file = sys.argv[2]
        else:
            test_file = "binfreak/test_binary"
        
        if os.path.exists(test_file):
            test_analysis(test_file)
        else:
            print(f"Test file not found: {test_file}")
            sys.exit(1)
    else:
        # Normal GUI mode
        sys.exit(main())