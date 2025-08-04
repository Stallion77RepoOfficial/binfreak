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
    
    # Read original GUI script
    if not os.path.exists("fuzzpro_gui.py"):
        print("Original GUI file not found: fuzzpro_gui.py")
        return False
        
    with open("fuzzpro_gui.py", "r") as f:
        gui_content = f.read()
    
    # Add base64 import if not present
    if "import base64" not in gui_content:
        gui_content = gui_content.replace(
            "import tempfile",
            "import tempfile\nimport base64"
        )
    
    # Add embedded binary data after imports
    if "EMBEDDED_FUZZPRO_BINARY" not in gui_content:
        # Find the right place to insert - after imports but before class definitions
        insert_position = gui_content.find("class FuzzingWorker")
        if insert_position == -1:
            print("Could not find insertion point in GUI file")
            return False
        
        # Insert the embedded binary
        binary_line = f"\n# Embedded FuzzPro binary data\nEMBEDDED_FUZZPRO_BINARY = base64.b64decode('{encoded_data}')\n\n"
        gui_content = gui_content[:insert_position] + binary_line + gui_content[insert_position:]
    
    # Update FuzzingWorker to use embedded binary instead of system binary
    # Replace "./fuzzpro" with extracted binary path
    gui_content = gui_content.replace(
        'cmd = ["./fuzzpro", "-i", str(self.iterations), self.target_binary]',
        '''# Extract embedded binary to temp file
        fuzzpro_path = self.extract_fuzzpro_binary()
        cmd = [fuzzpro_path, "-i", str(self.iterations), self.target_binary]'''
    )
    
    # Add binary extraction method to FuzzingWorker class
    extraction_method = '''
    def extract_fuzzpro_binary(self):
        """Extract embedded FuzzPro binary to temporary file"""
        import tempfile
        import os
        
        # Create temporary file
        fd, temp_path = tempfile.mkstemp(suffix='_fuzzpro', prefix='tmp_')
        
        with os.fdopen(fd, 'wb') as f:
            f.write(EMBEDDED_FUZZPRO_BINARY)
        
        os.chmod(temp_path, 0o755)  # Make executable
        return temp_path
        '''
    
    # Find FuzzingWorker class and add the method
    class_start = gui_content.find("class FuzzingWorker")
    if class_start != -1:
        # Find the run method
        run_method_start = gui_content.find("def run(self):", class_start)
        if run_method_start != -1:
            # Insert extraction method before run method
            gui_content = gui_content[:run_method_start] + extraction_method + "\n    " + gui_content[run_method_start:]
    
    # Write the final app.py
    with open("app.py", "w") as f:
        f.write(gui_content)
    
    print("Created app.py with embedded binary")
    return True

def create_macos_app():
    """Create standalone macOS app from app.py"""
    print("Creating standalone macOS application...")
    
    if not os.path.exists("app.py"):
        print("app.py not found! Run embed_binary_in_gui() first.")
        return False
    
    # Install PyInstaller if needed
    try:
        import PyInstaller
    except ImportError:
        print("Installing PyInstaller...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        if result.returncode != 0:
            print("Failed to install PyInstaller")
            return False
    
    # Create app bundle with PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onedir",
        "--windowed",
        "--clean",
        "--name", "FuzzPro",
        "app.py"
    ]
    
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("Failed to create app bundle")
        return False
    
    print("Successfully created FuzzPro.app in dist/")
    print("You can run it from dist/FuzzPro.app")
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
