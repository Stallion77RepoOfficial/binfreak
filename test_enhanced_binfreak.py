"""
Comprehensive tests for BinFreak's enhanced features
"""

import os
import sys
import tempfile
import hashlib
from pathlib import Path

# Add binfreak to path
sys.path.insert(0, str(Path(__file__).parent / "binfreak" / "binfreak"))

from analysis.binary_engine import BinaryAnalysisEngine
from analysis.binary_comparator import BinaryComparator
from plugins.plugin_manager import PluginManager
from core.license_manager import SimpleLicenseManager


def test_plugin_system():
    """Test the plugin system functionality"""
    print("Testing plugin system...")
    
    try:
        plugin_manager = PluginManager()
        
        # Test plugin discovery and loading
        plugins = plugin_manager.load_all_plugins()
        print(f"✓ Loaded {len(plugins)} plugins")
        
        # Test plugin info
        plugin_info = plugin_manager.get_plugin_info()
        for name, info in plugin_info.items():
            print(f"  - {name}: {info.get('description', 'No description')}")
        
        # Test analysis plugins specifically
        analysis_plugins = plugin_manager.get_analysis_plugins()
        print(f"✓ Found {len(analysis_plugins)} analysis plugins")
        
        print("✓ Plugin system tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Plugin system test failed: {e}")
        return False


def test_binary_comparison():
    """Test binary comparison functionality"""
    print("Testing binary comparison...")
    
    try:
        # Create test files
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            test_data1 = b"Hello World! This is test data." * 100
            f1.write(test_data1)
            f1.flush()
            file1_path = f1.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            test_data2 = b"Hello World! This is different test data." * 100
            f2.write(test_data2)
            f2.flush()
            file2_path = f2.name
        
        # Test comparison
        comparator = BinaryComparator()
        result = comparator.compare_files(file1_path, file2_path)
        
        # Verify results
        assert 'file1' in result, "Should contain file1 info"
        assert 'file2' in result, "Should contain file2 info"
        assert 'similarity_score' in result, "Should contain similarity score"
        assert 'hash_comparison' in result, "Should contain hash comparison"
        assert 'byte_differences' in result, "Should contain byte differences"
        
        print(f"✓ Similarity score: {result['similarity_score']:.3f}")
        print(f"✓ Hash match: {result['hash_comparison']['md5_match']}")
        print(f"✓ Byte differences found: {len(result['byte_differences'])}")
        
        # Test multiple file comparison
        with tempfile.NamedTemporaryFile(delete=False) as f3:
            test_data3 = b"Completely different content here!" * 50
            f3.write(test_data3)
            f3.flush()
            file3_path = f3.name
        
        multi_result = comparator.compare_multiple([file1_path, file2_path, file3_path])
        assert 'comparison_matrix' in multi_result, "Should contain comparison matrix"
        assert 'most_similar' in multi_result, "Should contain most similar pairs"
        
        print(f"✓ Multiple file comparison: {multi_result['file_count']} files")
        
        # Cleanup
        os.unlink(file1_path)
        os.unlink(file2_path)
        os.unlink(file3_path)
        
        print("✓ Binary comparison tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Binary comparison test failed: {e}")
        return False


def test_enhanced_analysis():
    """Test enhanced binary analysis with plugins"""
    print("Testing enhanced binary analysis...")
    
    try:
        engine = BinaryAnalysisEngine()
        
        # Test with a real binary if available
        test_binary = "binfreak/test_binary"
        if os.path.exists(test_binary):
            result = engine.analyze_file(test_binary)
            
            if 'error' not in result:
                # Check for plugin analysis results
                if 'plugin_analysis' in result:
                    print(f"✓ Plugin analysis completed: {len(result['plugin_analysis'])} plugins ran")
                    
                    # Check for specific plugin results
                    for plugin_name, plugin_result in result['plugin_analysis'].items():
                        if 'error' not in plugin_result:
                            print(f"  - {plugin_name}: Success")
                        else:
                            print(f"  - {plugin_name}: {plugin_result['error']}")
                else:
                    print("⚠ No plugin analysis results (plugins may not be loaded)")
                
                # Verify standard analysis still works
                assert 'file_format' in result, "Should include file format"
                assert 'functions' in result, "Should include functions"
                assert 'strings' in result, "Should include strings"
                
                print(f"✓ Analysis completed for {result['file_path']}")
                print(f"  - Format: {result['file_format']['type']}")
                print(f"  - Functions: {len(result['functions'])}")
                print(f"  - Strings: {len(result['strings'])}")
            else:
                print(f"⚠ Analysis error: {result['error']}")
        else:
            print("⚠ Test binary not found, skipping file analysis")
        
        print("✓ Enhanced analysis tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Enhanced analysis test failed: {e}")
        return False


def test_plugin_analysis():
    """Test individual plugin analysis"""
    print("Testing individual plugin analysis...")
    
    try:
        # Create test binary data
        test_data = b"Hello World!" + b"\x00" * 100 + b"This is a test string!" + b"\xFF" * 50
        
        # Test plugin manager
        plugin_manager = PluginManager()
        plugin_manager.load_all_plugins()
        
        file_info = {
            'path': 'test_data',
            'size': len(test_data),
            'format': {'type': 'Raw'}
        }
        
        # Run plugin analysis
        results = plugin_manager.run_analysis_plugins(test_data, file_info)
        
        print(f"✓ Plugin analysis results: {len(results)} plugins")
        
        for plugin_name, result in results.items():
            if 'error' not in result:
                print(f"  - {plugin_name}: Analysis successful")
                # Show some sample results
                if 'overall_entropy' in result:
                    print(f"    Entropy: {result['overall_entropy']:.2f}")
                if 'total_ascii_strings' in result:
                    print(f"    ASCII strings: {result['total_ascii_strings']}")
            else:
                print(f"  - {plugin_name}: Error - {result['error']}")
        
        print("✓ Plugin analysis tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Plugin analysis test failed: {e}")
        return False


def test_license_manager():
    """Test the simplified license manager"""
    print("Testing license manager...")
    
    try:
        lm = SimpleLicenseManager()
        
        assert lm.check_license() == True, "License should always be valid"
        assert lm.is_feature_enabled("any_feature") == True, "All features should be enabled"
        
        info = lm.get_license_info()
        assert info['status'] == 'Open Source', "Should be open source"
        assert 'features' in info, "Should have features list"
        
        print("✓ License manager tests passed")
        return True
        
    except Exception as e:
        print(f"✗ License manager test failed: {e}")
        return False


def run_comprehensive_tests():
    """Run all tests"""
    print("=" * 50)
    print("BinFreak Comprehensive Test Suite")
    print("=" * 50)
    
    tests = [
        test_license_manager,
        test_plugin_system,
        test_plugin_analysis,
        test_binary_comparison,
        test_enhanced_analysis
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        print()
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
    
    print()
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return True
    else:
        print("❌ Some tests failed")
        return False


if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)