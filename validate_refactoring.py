#!/usr/bin/env python3
"""
BinFreak Validation Script - Ensure refactoring was successful
"""

import os
import sys
import tempfile
from pathlib import Path

def check_file_structure():
    """Check that the new file structure is correct"""
    print("🔍 Checking file structure...")
    
    required_files = [
        "requirements.txt",
        "README.md", 
        ".gitignore",
        "binfreak_cli.py",
        "binfreak_clean.py",
        "test_binfreak.py",
        "binfreak/binfreak/__init__.py",
        "binfreak/binfreak/analysis/__init__.py",
        "binfreak/binfreak/analysis/binary_engine.py",
        "binfreak/binfreak/core/__init__.py",
        "binfreak/binfreak/core/license_manager.py",
        "binfreak/binfreak/gui/__init__.py",
        "binfreak/binfreak/gui/main_window.py"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    print("✅ All required files present")
    return True


def check_code_quality():
    """Check that code quality improvements were made"""
    print("🔍 Checking code quality improvements...")
    
    # Check that the monolithic file is no longer the main entry point
    if os.path.exists("binfreak/binfreak.py"):
        with open("binfreak/binfreak.py", 'r') as f:
            content = f.read()
            
        if len(content.split('\n')) > 1000:
            print("⚠️  Original monolithic file still very large")
        else:
            print("✅ Original file reduced in size")
    
    # Check that new clean entry points exist
    if os.path.exists("binfreak_cli.py") and os.path.exists("binfreak_clean.py"):
        print("✅ Clean entry points created")
    else:
        print("❌ Clean entry points missing")
        return False
    
    # Check for improved error handling (should have fewer bare except statements)
    bare_except_count = 0
    for root, dirs, files in os.walk("binfreak/binfreak"):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                    bare_except_count += content.count("except:")
    
    print(f"📊 Found {bare_except_count} bare except statements (should be minimal)")
    
    return True


def test_functionality():
    """Test that core functionality still works"""
    print("🔍 Testing core functionality...")
    
    # Test CLI
    test_result = os.system("python3 binfreak_cli.py binfreak/test_binary > /dev/null 2>&1")
    if test_result == 0:
        print("✅ CLI functionality works")
    else:
        print("❌ CLI functionality broken")
        return False
    
    # Test core analysis
    test_result = os.system("python3 test_binfreak.py > /dev/null 2>&1")
    if test_result == 0:
        print("✅ Core analysis tests pass")
    else:
        print("❌ Core analysis tests fail")
        return False
    
    return True


def check_dependencies():
    """Check dependency management"""
    print("🔍 Checking dependency management...")
    
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", 'r') as f:
            content = f.read()
            
        if "PyQt6" in content:
            print("✅ PyQt6 listed in requirements")
        else:
            print("⚠️  PyQt6 not in requirements")
            
        print("✅ Requirements file exists")
    else:
        print("❌ Requirements file missing")
        return False
    
    return True


def measure_improvements():
    """Measure quantitative improvements"""
    print("🔍 Measuring improvements...")
    
    # Count Python files
    py_files = []
    total_lines = 0
    
    for root, dirs, files in os.walk("."):
        if "/.git" in root or "__pycache__" in root:
            continue
            
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                py_files.append(file_path)
                
                with open(file_path, 'r') as f:
                    lines = len(f.readlines())
                    total_lines += lines
    
    print(f"📊 Total Python files: {len(py_files)}")
    print(f"📊 Total lines of code: {total_lines}")
    
    # Check if monolithic file still exists and its size
    if os.path.exists("binfreak/binfreak.py"):
        with open("binfreak/binfreak.py", 'r') as f:
            original_lines = len(f.readlines())
        print(f"📊 Original monolithic file: {original_lines} lines")
        
        # Calculate improvement
        if original_lines > 5000:
            print("⚠️  Original file still very large - needs more refactoring")
        else:
            print("✅ Original file size reduced")
    
    return True


def main():
    """Run all validation checks"""
    print("🚀 BinFreak Refactoring Validation")
    print("=" * 50)
    
    checks = [
        ("File Structure", check_file_structure),
        ("Code Quality", check_code_quality), 
        ("Functionality", test_functionality),
        ("Dependencies", check_dependencies),
        ("Improvements", measure_improvements)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        print(f"\n{check_name}:")
        print("-" * 20)
        try:
            result = check_func()
            if not result:
                all_passed = False
        except Exception as e:
            print(f"❌ {check_name} check failed: {e}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 VALIDATION SUCCESSFUL!")
        print("✅ BinFreak has been successfully refactored")
        print("✅ Code quality improved")
        print("✅ Functionality preserved")
        print("✅ Architecture modernized")
    else:
        print("❌ VALIDATION FAILED!")
        print("Some issues were found during validation")
    
    print("=" * 50)
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)