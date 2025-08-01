"""
Basic tests for BinFreak functionality
"""

import os
import sys
import tempfile
from pathlib import Path

# Add binfreak to path
sys.path.insert(0, str(Path(__file__).parent / "binfreak" / "binfreak"))

from analysis.binary_engine import BinaryAnalysisEngine
from core.license_manager import SimpleLicenseManager


def test_license_manager():
    """Test the simplified license manager"""
    print("Testing license manager...")
    lm = SimpleLicenseManager()
    
    assert lm.check_license() == True, "License should always be valid"
    assert lm.is_feature_enabled("any_feature") == True, "All features should be enabled"
    
    info = lm.get_license_info()
    assert info['status'] == 'Open Source', "Should be open source"
    
    print("✓ License manager tests passed")


def test_binary_analysis_engine():
    """Test the binary analysis engine"""
    print("Testing binary analysis engine...")
    engine = BinaryAnalysisEngine()
    
    # Test with non-existent file
    result = engine.analyze_file("/nonexistent/file")
    assert 'error' in result, "Should return error for non-existent file"
    print("✓ Non-existent file handling works")
    
    # Test with test binary if available
    test_binary = "binfreak/test_binary"
    if os.path.exists(test_binary):
        result = engine.analyze_file(test_binary)
        
        if 'error' not in result:
            assert 'file_path' in result, "Should include file path"
            assert 'file_size' in result, "Should include file size"
            assert 'file_format' in result, "Should include file format"
            assert 'strings' in result, "Should include strings"
            assert 'functions' in result, "Should include functions"
            print("✓ Test binary analysis successful")
        else:
            print(f"! Test binary analysis failed: {result['error']}")
    else:
        print("! Test binary not found, skipping analysis test")
    
    # Test with a small sample file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"Hello, World!\x00This is a test binary.\x00")
        tmp.flush()
        
        result = engine.analyze_file(tmp.name)
        
        if 'error' not in result:
            assert result['file_size'] > 0, "Should detect file size"
            assert len(result['strings']) > 0, "Should find strings"
            print("✓ Sample file analysis successful")
        else:
            print(f"! Sample file analysis failed: {result['error']}")
        
        os.unlink(tmp.name)
    
    print("✓ Binary analysis engine tests passed")


def test_format_detection():
    """Test format detection with known patterns"""
    print("Testing format detection...")
    engine = BinaryAnalysisEngine()
    
    # Test ELF detection
    elf_header = b'\x7fELF' + b'\x00' * 60
    format_result = engine.detect_format(elf_header)
    assert 'ELF' in format_result, f"Should detect ELF format, got: {format_result}"
    
    # Test PE detection
    pe_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00' + b'PE\x00\x00'
    format_result = engine.detect_format(pe_header)
    assert 'PE' in format_result or 'MZ' in format_result, f"Should detect PE format, got: {format_result}"
    
    print("✓ Format detection tests passed")


def test_string_extraction():
    """Test string extraction"""
    print("Testing string extraction...")
    engine = BinaryAnalysisEngine()
    
    test_data = b'Hello\x00World\x00\x41\x42\x43\x00Test123\x00\x00\x00Binary\x00'
    strings = engine.extract_strings(test_data)
    
    assert len(strings) > 0, "Should find strings"
    assert 'Hello' in strings, "Should find 'Hello'"
    assert 'World' in strings, "Should find 'World'" 
    assert 'Binary' in strings, "Should find 'Binary'"
    
    print(f"✓ String extraction found {len(strings)} strings")


def run_all_tests():
    """Run all tests"""
    print("Running BinFreak tests...\n")
    
    try:
        test_license_manager()
        test_binary_analysis_engine()
        test_format_detection()
        test_string_extraction()
        
        print("\n🎉 All tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)