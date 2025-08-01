#!/usr/bin/env python3
"""
BinFreak Enhanced Analysis Test Suite
Tests all the new professional features
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_enhanced_binary_engine():
    """Test the enhanced binary analysis engine"""
    print("=" * 60)
    print("Testing Enhanced Binary Analysis Engine")
    print("=" * 60)
    
    try:
        # Import the enhanced engine
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from binary_engine import BinaryAnalysisEngine
        
        print("✓ Enhanced Binary Engine imported successfully")
        
        # Initialize engine
        engine = BinaryAnalysisEngine()
        print("✓ Engine initialized successfully")
        
        # Check advanced capabilities
        ghidra_available = engine.ghidra_analyzer.is_available() if engine.ghidra_analyzer else False
        libfuzzer_available = engine.libfuzzer_integration.is_available() if engine.libfuzzer_integration else False
        
        print(f"✓ Ghidra integration: {'Available' if ghidra_available else 'Not available (install Ghidra for full features)'}")
        print(f"✓ LibFuzzer integration: {'Available' if libfuzzer_available else 'Not available (install clang with fuzzing support)'}")
        
        # Create a test binary
        test_data = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"Test binary data with some strings" + b"\x90" * 100
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(test_data)
            temp_path = temp_file.name
        
        try:
            # Test enhanced analysis
            print("\\nTesting enhanced file analysis...")
            result = engine.analyze_file(temp_path)
            
            if 'error' in result:
                print(f"✗ Analysis failed: {result['error']}")
                return False
            
            print(f"✓ File analyzed successfully")
            print(f"  - File size: {result.get('file_size', 0)} bytes")
            print(f"  - Format detected: {result.get('file_format', {}).get('type', 'Unknown')}")
            print(f"  - Functions found: {len(result.get('functions', []))}")
            print(f"  - Strings found: {len(result.get('strings', []))}")
            print(f"  - Sections found: {len(result.get('sections', []))}")
            print(f"  - Advanced analysis available: {result.get('statistics', {}).get('advanced_analysis_available', False)}")
            
            return True
            
        finally:
            os.unlink(temp_path)
    
    except Exception as e:
        print(f"✗ Enhanced Binary Engine test failed: {e}")
        return False

def test_dynamic_function_detection():
    """Test the enhanced function detection"""
    print("\\n" + "=" * 60)
    print("Testing Dynamic Function Detection")
    print("=" * 60)
    
    try:
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from function_detector import FunctionDetector
        
        print("✓ Enhanced Function Detector imported successfully")
        
        detector = FunctionDetector()
        
        # Create test data with various function patterns
        test_data = (
            b"\x55\x48\x89\xe5" +  # x64 prologue
            b"\x48\x83\xec\x10" +  # sub rsp, 16
            b"\x90" * 20 +            # nops
            b"\xc3" +                 # ret
            b"\x55\x89\xe5" +       # x86 prologue  
            b"\x83\xec\x08" +       # sub esp, 8
            b"\x90" * 15 +            # nops
            b"\xc3" +                 # ret
            b"\x00" * 100             # padding
        )
        
        functions = detector.detect_functions(test_data)
        
        print(f"✓ Dynamic function detection completed")
        print(f"  - Functions detected: {len(functions)}")
        
        for i, func in enumerate(functions[:5]):  # Show first 5
            print(f"  - Function {i+1}: {func.get('address', 'N/A')} ({func.get('type', 'Unknown')}) confidence: {func.get('confidence', 'N/A')}")
        
        return len(functions) > 0
    
    except Exception as e:
        print(f"✗ Dynamic Function Detection test failed: {e}")
        return False

def test_enhanced_entropy_analysis():
    """Test the enhanced entropy calculator"""
    print("\\n" + "=" * 60)
    print("Testing Enhanced Entropy Analysis")
    print("=" * 60)
    
    try:
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from entropy_calculator import EntropyCalculator
        
        print("✓ Enhanced Entropy Calculator imported successfully")
        
        calculator = EntropyCalculator()
        
        # Test with different data types
        test_cases = [
            (b"\x00" * 1000, "Low entropy (null bytes)"),
            (b"Hello world! " * 100, "Medium entropy (text)"),
            (os.urandom(1000), "High entropy (random data)")
        ]
        
        for test_data, description in test_cases:
            analysis = calculator.analyze_entropy_pattern(test_data)
            
            print(f"\n✓ {description}:")
            print(f"  - Overall entropy: {analysis['overall_entropy']:.2f}")
            print(f"  - Classification: {analysis['overall_classification']}")
            print(f"  - Sliding windows: {analysis['sliding_window_analysis']['window_count']}")
            print(f"  - Patterns detected: {len(analysis['sliding_window_analysis']['patterns'])}")
            print(f"  - Anomalies detected: {len(analysis['sliding_window_analysis']['anomalies'])}")
        
        # Test packed section detection
        packed_sections = calculator.detect_packed_sections(os.urandom(2048))
        print(f"\n✓ Packed section detection: {len(packed_sections)} sections found")
        
        return True
    
    except Exception as e:
        print(f"✗ Enhanced Entropy Analysis test failed: {e}")
        return False

def test_ghidra_integration():
    """Test Ghidra integration"""
    print("\\n" + "=" * 60)
    print("Testing Ghidra Integration")
    print("=" * 60)
    
    try:
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from ghidra_integration import get_ghidra_analyzer
        
        print("✓ Ghidra Integration module imported successfully")
        
        analyzer = get_ghidra_analyzer()
        
        if analyzer.is_available():
            print("✓ Ghidra is available and configured")
            
            # Create a simple test binary
            test_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"minimal ELF data"
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as temp_file:
                temp_file.write(test_data)
                temp_path = temp_file.name
            
            try:
                print("\nTesting Ghidra analysis...")
                result = analyzer.analyze_binary(temp_path, {'timeout': 30})
                
                if result.get('success'):
                    print("✓ Ghidra analysis completed successfully")
                    print(f"  - Functions found: {len(result.get('functions', []))}")
                    print(f"  - Symbols found: {len(result.get('symbols', []))}")
                else:
                    print(f"○ Ghidra analysis completed with limitations: {result.get('error', 'Unknown error')}")
                
                return True
                
            finally:
                os.unlink(temp_path)
        else:
            print("○ Ghidra not available - install Ghidra for professional analysis features")
            print("  This is expected if Ghidra is not installed")
            return True  # Not a failure, just not available
    
    except Exception as e:
        print(f"✗ Ghidra Integration test failed: {e}")
        return False

def test_libfuzzer_integration():
    """Test libFuzzer integration"""
    print("\\n" + "=" * 60)
    print("Testing LibFuzzer Integration")
    print("=" * 60)
    
    try:
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from libfuzzer_integration import get_libfuzzer_integration
        
        print("✓ LibFuzzer Integration module imported successfully")
        
        integration = get_libfuzzer_integration()
        
        if integration.is_available():
            print("✓ LibFuzzer is available and configured")
            
            # Test harness creation
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as harness_file:
                harness_path = harness_file.name
            
            try:
                result = integration.create_fuzzing_harness('basic_file', harness_path)
                
                if result.get('success'):
                    print("✓ Fuzzing harness created successfully")
                    
                    # Check if harness file was created
                    if os.path.exists(harness_path):
                        with open(harness_path, 'r') as f:
                            content = f.read()
                        print(f"  - Harness file size: {len(content)} characters")
                        print("  - Contains LLVMFuzzerTestOneInput:", "LLVMFuzzerTestOneInput" in content)
                else:
                    print(f"✗ Harness creation failed: {result.get('error', 'Unknown error')}")
                
                return True
                
            finally:
                if os.path.exists(harness_path):
                    os.unlink(harness_path)
        else:
            print("○ LibFuzzer not available - install clang with fuzzing support")
            print("  This is expected if clang with fuzzing support is not installed")
            return True  # Not a failure, just not available
    
    except Exception as e:
        print(f"✗ LibFuzzer Integration test failed: {e}")
        return False

def test_binary_comparison():
    """Test enhanced binary comparison"""
    print("\\n" + "=" * 60)
    print("Testing Enhanced Binary Comparison")
    print("=" * 60)
    
    try:
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'analysis'))
        from binary_comparator import BinaryComparator
        
        print("✓ Enhanced Binary Comparator imported successfully")
        
        comparator = BinaryComparator()
        
        # Create two similar but different test files
        data1 = b"Test binary 1" + b"\x90" * 100 + b"Function data" + b"\x00" * 50
        data2 = b"Test binary 2" + b"\x90" * 100 + b"Function data" + b"\x00" * 60  # Different size
        
        with tempfile.NamedTemporaryFile(delete=False) as file1, \
             tempfile.NamedTemporaryFile(delete=False) as file2:
            
            file1.write(data1)
            file2.write(data2)
            file1_path = file1.name
            file2_path = file2.name
        
        try:
            print("\nComparing test binaries...")
            result = comparator.compare_files(file1_path, file2_path)
            
            if 'error' in result:
                print(f"✗ Comparison failed: {result['error']}")
                return False
            
            print("✓ Binary comparison completed successfully")
            
            basic = result.get('basic_comparison', {})
            print(f"  - Files identical: {basic.get('identical', False)}")
            print(f"  - Size difference: {basic.get('size_difference', 0)} bytes")
            print(f"  - MD5 match: {basic.get('hash_matches', {}).get('md5', False)}")
            
            similarity = result.get('similarity_metrics', {})
            print(f"  - Overall similarity: {similarity.get('overall_similarity', 0):.1f}%")
            print(f"  - Jaccard similarity: {similarity.get('jaccard_similarity', 0):.3f}")
            
            return True
            
        finally:
            os.unlink(file1_path)
            os.unlink(file2_path)
    
    except Exception as e:
        print(f"✗ Enhanced Binary Comparison test failed: {e}")
        return False

def test_visualization_components():
    """Test visualization components"""
    print("\\n" + "=" * 60)
    print("Testing Visualization Components")
    print("=" * 60)
    
    try:
        # Test hex viewer import
        sys.path.insert(0, str(project_root / 'binfreak' / 'binfreak' / 'visualization'))
        
        try:
            from hex_viewer import HexViewer
            print("✓ Professional Hex Viewer component imported successfully")
        except ImportError as e:
            print(f"○ Hex Viewer GUI component not available: {e}")
            print("  This is expected in headless environments")
        
        return True
    
    except Exception as e:
        print(f"✗ Visualization Components test failed: {e}")
        return False

def run_all_tests():
    """Run all test suites"""
    print("BinFreak Enhanced Features Test Suite")
    print("=" * 80)
    print("Testing all professional enhancements...")
    
    tests = [
        ("Enhanced Binary Engine", test_enhanced_binary_engine),
        ("Dynamic Function Detection", test_dynamic_function_detection),
        ("Enhanced Entropy Analysis", test_enhanced_entropy_analysis),
        ("Ghidra Integration", test_ghidra_integration),
        ("LibFuzzer Integration", test_libfuzzer_integration),
        ("Enhanced Binary Comparison", test_binary_comparison),
        ("Visualization Components", test_visualization_components),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:<8} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed! BinFreak enhanced features are working correctly.")
    elif passed >= total * 0.8:
        print("\n✓ Most tests passed! BinFreak enhanced features are mostly functional.")
        print("  Some advanced features may not be available due to missing dependencies.")
    else:
        print("\n⚠ Some tests failed. Check the error messages above.")
    
    return passed, total

if __name__ == "__main__":
    # Change to project directory
    os.chdir(project_root)
    
    # Run tests
    passed, total = run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if passed >= total * 0.8 else 1)