# BinFreak - Binary Analysis Tool

A clean, modular binary analysis tool focused on core functionality without the bloat.

## Overview

BinFreak has been completely refactored from a 7400+ line monolithic codebase into a clean, modular architecture. The tool now focuses on essential binary analysis features with improved code quality and maintainability.

## Key Improvements Made

### 🔧 **Code Quality Fixes**
- **Removed 7400+ line monolithic file** - Split into logical modules
- **Eliminated code duplication** - Single implementation per feature
- **Improved error handling** - Replaced bare `except:` with specific exceptions
- **Separated concerns** - GUI, analysis, and core logic properly isolated
- **Added type hints** - Better code documentation and IDE support

### 🏗️ **Architecture Refactoring**
- **Modular structure** - Clear separation between analysis, GUI, and core
- **Dependency management** - Proper requirements.txt
- **Clean imports** - No circular dependencies
- **Plugin architecture** - Easy to extend with new analysis engines

### ✨ **Features**
- **Binary format detection** - ELF, PE, Mach-O, and more
- **String extraction** - ASCII, UTF-8, UTF-16 support
- **Function detection** - Pattern-based and format-specific
- **Section analysis** - Detailed binary structure analysis
- **Entropy analysis** - Detect packed/encrypted content
- **Multiple interfaces** - CLI, GUI, and programmatic API

## Installation

```bash
# Clone the repository
git clone https://github.com/Stallion77RepoOfficial/binfreak.git
cd binfreak

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command Line Interface (Recommended)

```bash
# Basic analysis
python3 binfreak_cli.py binary_file

# Show strings
python3 binfreak_cli.py binary_file --strings

# Show functions and sections
python3 binfreak_cli.py binary_file --functions --sections

# Full analysis with limited results
python3 binfreak_cli.py binary_file --all --limit 50

# JSON output for automation
python3 binfreak_cli.py binary_file --json
```

### GUI Interface

```bash
# Launch GUI (requires PyQt6 and display)
python3 binfreak_clean.py
```

### Programmatic API

```python
from binfreak.analysis.binary_engine import BinaryAnalysisEngine

engine = BinaryAnalysisEngine()
result = engine.analyze_file("path/to/binary")

print(f"Format: {result['file_format']['type']}")
print(f"Functions: {len(result['functions'])}")
print(f"Strings: {len(result['strings'])}")
```

## Project Structure

```
binfreak/
├── binfreak/              # Main package
│   ├── analysis/          # Analysis engines
│   │   ├── binary_engine.py
│   │   ├── format_detector.py
│   │   ├── string_extractor.py
│   │   └── ...
│   ├── core/              # Core functionality
│   │   └── license_manager.py
│   └── gui/               # GUI components
│       └── main_window.py
├── binfreak_cli.py        # Command line interface
├── binfreak_clean.py      # GUI entry point
├── test_binfreak.py       # Basic tests
├── requirements.txt       # Dependencies
└── README.md
```

## Testing

```bash
# Run basic tests
python3 test_binfreak.py

# Test CLI functionality
python3 binfreak_cli.py binfreak/test_binary --all
```

## Supported Formats

- **ELF** (Linux/Unix executables and libraries)
- **PE** (Windows executables and DLLs) 
- **Mach-O** (macOS executables and frameworks)
- **Raw binaries** (with heuristic analysis)

## Dependencies

### Required
- **Python 3.8+**

### Optional
- **PyQt6** - For GUI interface
- **python-capstone** - Enhanced disassembly (advanced features)

## What Was Fixed

### Before (Problems)
- ❌ 7400+ line monolithic file
- ❌ Massive code duplication
- ❌ Poor error handling (`except:`)
- ❌ Mixed GUI and business logic
- ❌ Inconsistent module usage
- ❌ Over-engineered features
- ❌ No proper testing

### After (Solutions)
- ✅ Clean modular architecture
- ✅ Single responsibility principle
- ✅ Proper exception handling
- ✅ Separated concerns
- ✅ Consistent API design
- ✅ Focus on core functionality
- ✅ Basic test coverage

## Contributing

The codebase is now clean and modular, making contributions much easier:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Roadmap

- [ ] Add more binary format support
- [ ] Implement advanced disassembly with Capstone
- [ ] Add plugin system for custom analyzers
- [ ] Improve function detection algorithms
- [ ] Add binary comparison features
- [ ] Create comprehensive test suite