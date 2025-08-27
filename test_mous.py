#!/usr/bin/env python3
"""
Test script for Mous Security Scanner
Author: SayerLinux
"""

import sys
import os

# Add src to path for testing
current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
sys.path.insert(0, os.path.join(current_dir, 'src'))

def test_imports():
    """Test that all modules can be imported correctly"""
    print("Testing imports...")
    
    try:
        from src.core.config import Config
        print("✓ Config imported successfully")
        
        from src.core.scanner import MousScanner
        print("✓ MousScanner imported successfully")
        
        from src.reports.report_generator import ReportGenerator
        print("✓ ReportGenerator imported successfully")
        
        from src.database.updater import VulnDBUpdater
        print("✓ VulnDBUpdater imported successfully")
        
        from src.core.plugin_manager import PluginManager
        print("✓ PluginManager imported successfully")
        
        from src.modules.xss_scanner import XSSScanner
        print("✓ XSSScanner imported successfully")
        
        from src.modules.sql_scanner import SQLScanner
        print("✓ SQLScanner imported successfully")
        
        from src.modules.lfi_scanner import LFIScanner
        print("✓ LFIScanner imported successfully")
        
        from src.modules.rce_scanner import RCEScanner
        print("✓ RCEScanner imported successfully")
        
        from src.modules.info_scanner import InfoScanner
        print("✓ InfoScanner imported successfully")
        
        from src.modules.discovery_scanner import DiscoveryScanner
        print("✓ DiscoveryScanner imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def test_config():
    """Test configuration loading"""
    print("\nTesting configuration...")
    
    try:
        from src.core.config import Config
        config = Config()
        print("✓ Default configuration loaded")
        
        # Test getting configuration values
        threads = config.get('threads', 10)
        print(f"✓ Default threads: {threads}")
        
        return True
        
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality"""
    print("\nTesting basic functionality...")
    
    try:
        from src.core.config import Config
        from src.core.scanner import MousScanner
        
        # Create minimal config
        config = Config()
        config.set('threads', 1)  # Use single thread for testing
        config.set('timeout', 5)   # Short timeout for testing
        
        # Initialize scanner
        scanner = MousScanner(config)
        print("✓ Scanner initialized successfully")
        
        # Test target normalization
        normalized = scanner._normalize_target("http://httpbin.org")
        print(f"✓ Target normalization: {normalized}")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Mous Security Scanner - Test Suite")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Config Tests", test_config),
        ("Basic Functionality", test_basic_functionality)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        if test_func():
            passed += 1
            print(f"✅ {test_name} PASSED")
        else:
            print(f"❌ {test_name} FAILED")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Mous is ready to use.")
    else:
        print("⚠️  Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()