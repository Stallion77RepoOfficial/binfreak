#!/usr/bin/env python3
"""
FuzzPro Build Script - Embeds FuzzPro binary into GUI and creates standalone executable
New system: fuzzpro_gui.py -> app.py -> FuzzPro.app
"""

import os
import sys
import subprocess
import base64
import re

def embed_binary_in_gui():
    """Embed FuzzPro binary into the GUI script to create app.py"""
    print("Building FuzzPro binary...")
    
    # Build FuzzPro
    result = subprocess.run(["make", "clean"], cwd=".")
    if result.returncode != 0:
        print("Failed to clean")
        return False
        
    result = subprocess.run(["make"], cwd=".")
    if result.returncode != 0:
        print("Failed to build FuzzPro")
        return False
    
    # Read binary data
    if not os.path.exists("fuzzpro"):
        print("FuzzPro binary not found!")
        return False
        
    print("Embedding FuzzPro binary into GUI...")
    with open("fuzzpro", "rb") as f:
        binary_data = f.read()
    
    # Encode binary as base64
    encoded_data = base64.b64encode(binary_data).decode('utf-8')
    print(f"Binary size: {len(binary_data)} bytes, encoded: {len(encoded_data)} chars")
    
    # Read original GUI script
    if not os.path.exists("fuzzpro_gui.py"):
        print("Original GUI file not found: fuzzpro_gui.py")
        return False
        
    with open("fuzzpro_gui.py", "r") as f:
        gui_content = f.read()
    
    # Ensure base64 import is present
    if "import base64" not in gui_content:
        gui_content = gui_content.replace(
            "import tempfile",
            "import tempfile\nimport base64"
        )
    
    # Find insertion point after imports but before class definitions
    insert_position = gui_content.find("class FuzzingWorker")
    if insert_position == -1:
        print("Could not find FuzzingWorker class in GUI file")
        return False
    
    # Insert the embedded binary with proper formatting (always fresh start)
    binary_line = f"\n# Embedded FuzzPro binary data (base64 encoded)\nEMBEDDED_FUZZPRO_BINARY = base64.b64decode('{encoded_data}')\n\n"
    gui_content = gui_content[:insert_position] + binary_line + gui_content[insert_position:]
    print("Embedded binary data inserted into GUI code")
    
    # Add binary extraction method (always add fresh)
    print("Adding binary extraction method...")
    
    # Find FuzzingWorker class __init__ method and add extraction method after it
    init_method_end = gui_content.find("        self.is_running = True")
    if init_method_end != -1:
        # Find the next method definition or end of class
        next_method = gui_content.find("\n    def ", init_method_end)
        if next_method != -1:
            extraction_method = '''
        
    def extract_fuzzpro_binary(self):
        """Extract embedded FuzzPro binary to temporary file"""
        import tempfile
        import os
        
        try:
            # Create temporary file
            fd, temp_path = tempfile.mkstemp(suffix='_fuzzpro', prefix='tmp_')
            
            with os.fdopen(fd, 'wb') as f:
                f.write(EMBEDDED_FUZZPRO_BINARY)
            
            os.chmod(temp_path, 0o755)  # Make executable
            return temp_path
        except Exception as e:
            # Fallback to local binary if extraction fails
            print(f"Failed to extract embedded binary: {e}")
            return "./fuzzpro"
'''
            gui_content = gui_content[:next_method] + extraction_method + gui_content[next_method:]
            print("Binary extraction method added")
    
    # Write the final app.py
    with open("app.py", "w") as f:
        f.write(gui_content)
    
    print("Successfully created app.py with embedded binary!")
    return True

def create_macos_app():
    """Create standalone macOS app from app.py"""
    print("Creating standalone macOS application...")
    
    if not os.path.exists("app.py"):
        print("app.py not found! Run 'python3 build.py embed' first.")
        return False
    
    # Install PyInstaller if needed
    try:
        import PyInstaller
        print("PyInstaller found")
    except ImportError:
        print("Installing PyInstaller...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        if result.returncode != 0:
            print("Failed to install PyInstaller")
            return False
        print("PyInstaller installed successfully")
    
    # Clean previous builds
    import shutil
    if os.path.exists("dist"):
        shutil.rmtree("dist")
        print("Cleaned previous build")
    if os.path.exists("build"):
        shutil.rmtree("build")
    if os.path.exists("FuzzPro.spec"):
        os.remove("FuzzPro.spec")
    
    # Create app bundle with PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onedir",           # Create one directory with dependencies
        "--windowed",         # No console window (GUI app)
        "--clean",            # Clean PyInstaller cache
        "--name", "FuzzPro",  # App name
        "--add-data", "vulnerable_test:.",  # Include test binary if exists
        "app.py"
    ]
    
    print("Running PyInstaller...")
    print(f"Command: {' '.join(cmd)}")
    
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("Failed to create app bundle")
        return False
    
    print("Successfully created FuzzPro.app in dist/")
    print("You can run it from: ./dist/FuzzPro.app/Contents/MacOS/FuzzPro")
    print("Or double-click: dist/FuzzPro.app")
    return True

def main():
    """Main build function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "embed":
            # Create embedded version (app.py)
            success = embed_binary_in_gui()
            if success:
                print("\nEmbedded GUI created as app.py")
                print("Run 'python3 build.py app' to create standalone .app")
            return success
        elif sys.argv[1] == "app":
            # Create .app from app.py
            success = create_macos_app()
            return success
        elif sys.argv[1] == "all":
            # Do both steps
            print("Step 1: Creating embedded version...")
            if not embed_binary_in_gui():
                return False
            print("\nStep 2: Creating standalone app...")
            if not create_macos_app():
                return False
            print("\nBuild complete! FuzzPro.app is ready in dist/")
            return True
    
    # Default: show usage
    print("FuzzPro Build System")
    print("Usage:")
    print("  python3 build.py embed  - Create app.py with embedded binary")
    print("  python3 build.py app    - Create FuzzPro.app from app.py")
    print("  python3 build.py all    - Do both steps")
    print("")
    print("Files:")
    print("  fuzzpro_gui.py    - Original GUI (uses system ./fuzzpro)")
    print("  app.py            - Embedded GUI (created by 'embed')")
    print("  FuzzPro.app       - Standalone app (created by 'app')")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
