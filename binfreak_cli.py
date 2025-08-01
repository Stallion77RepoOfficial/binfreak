#!/usr/bin/env python3
"""
BinFreak CLI - Command Line Interface for Binary Analysis
Simple, focused tool for analyzing binaries without GUI overhead
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import Dict, Any

# Add binfreak to path
sys.path.insert(0, str(Path(__file__).parent / "binfreak" / "binfreak"))

from analysis.binary_engine import BinaryAnalysisEngine


def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def print_analysis_summary(result: Dict[str, Any]) -> None:
    """Print a summary of the analysis results"""
    if 'error' in result:
        print(f"❌ Analysis failed: {result['error']}")
        return
    
    print(f"📁 File: {os.path.basename(result['file_path'])}")
    print(f"📏 Size: {format_size(result['file_size'])}")
    print(f"🔍 Format: {result['file_format'].get('type', 'Unknown')}")
    
    # Entropy analysis
    entropy_data = result.get('entropy', {})
    if isinstance(entropy_data, dict):
        avg_entropy = entropy_data.get('average', 0)
    else:
        avg_entropy = entropy_data if isinstance(entropy_data, (int, float)) else 0
    
    if avg_entropy > 7.5:
        entropy_desc = "Very high (likely packed/encrypted)"
    elif avg_entropy > 6.0:
        entropy_desc = "High (compressed content)"
    elif avg_entropy > 4.0:
        entropy_desc = "Medium (mixed content)"
    else:
        entropy_desc = "Low (structured data)"
    
    print(f"🎲 Entropy: {avg_entropy:.2f} - {entropy_desc}")
    
    # Statistics
    functions = result.get('functions', [])
    strings = result.get('strings', [])
    sections = result.get('sections', [])
    
    print(f"🔧 Functions: {len(functions)}")
    print(f"📝 Strings: {len(strings)}")
    print(f"📚 Sections: {len(sections)}")
    print(f"⏱️  Analysis time: {result.get('analysis_duration', 'Unknown')}")


def print_detailed_analysis(result: Dict[str, Any], args: argparse.Namespace) -> None:
    """Print detailed analysis based on requested options"""
    
    if args.strings:
        print("\n" + "="*50)
        print("STRINGS ANALYSIS")
        print("="*50)
        strings = result.get('strings', [])
        
        if args.limit:
            strings = strings[:args.limit]
        
        for i, string in enumerate(strings, 1):
            print(f"{i:4d}: {string}")
        
        if len(result.get('strings', [])) > len(strings):
            print(f"... and {len(result.get('strings', [])) - len(strings)} more strings")
    
    if args.functions:
        print("\n" + "="*50)
        print("FUNCTIONS ANALYSIS")
        print("="*50)
        functions = result.get('functions', [])
        
        if args.limit:
            functions = functions[:args.limit]
        
        if not functions:
            print("No functions detected")
        else:
            print(f"{'Address':<12} {'Name':<20} {'Type':<15} {'Size'}")
            print("-" * 60)
            for func in functions:
                print(f"{func.get('address', 'Unknown'):<12} "
                      f"{func.get('name', 'Unknown'):<20} "
                      f"{func.get('type', 'Unknown'):<15} "
                      f"{func.get('size', 'Unknown')}")
    
    if args.sections:
        print("\n" + "="*50)
        print("SECTIONS ANALYSIS")
        print("="*50)
        sections = result.get('sections', [])
        
        if not sections:
            print("No sections detected")
        else:
            print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Type'}")
            print("-" * 60)
            for section in sections:
                print(f"{section.get('name', 'Unknown'):<15} "
                      f"{section.get('address', 'Unknown'):<12} "
                      f"{str(section.get('size', 'Unknown')):<12} "
                      f"{section.get('type', 'Unknown')}")
    
    if args.entropy:
        print("\n" + "="*50)
        print("ENTROPY ANALYSIS")
        print("="*50)
        entropy_data = result.get('entropy', {})
        
        if isinstance(entropy_data, list):
            # Calculate average from list
            avg_entropy = sum(entropy_data) / len(entropy_data) if entropy_data else 0
            print(f"Average entropy: {avg_entropy:.3f}")
            print(f"Block count: {len(entropy_data)}")
            
            if args.verbose and entropy_data:
                print("\nEntropy by blocks:")
                for i, block_entropy in enumerate(entropy_data[:20]):  # Show first 20 blocks
                    offset = i * 1024  # Assuming 1KB blocks
                    print(f"  Block {i:3d} (offset 0x{offset:06x}): {block_entropy:.3f}")
        elif isinstance(entropy_data, dict):
            print(f"Average entropy: {entropy_data.get('average', 0):.3f}")
            print(f"Block count: {entropy_data.get('block_count', 0)}")
            
            blocks = entropy_data.get('blocks', [])
            if blocks and args.verbose:
                print("\nEntropy by blocks:")
                for i, block in enumerate(blocks[:20]):  # Show first 20 blocks
                    offset = i * 1024  # Assuming 1KB blocks
                    print(f"  Block {i:3d} (offset 0x{offset:06x}): {block:.3f}")
        else:
            print(f"Overall entropy: {entropy_data:.3f}")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="BinFreak - Binary Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  binfreak_cli.py binary.exe                    # Basic analysis
  binfreak_cli.py binary.exe --strings          # Show strings
  binfreak_cli.py binary.exe --functions        # Show functions  
  binfreak_cli.py binary.exe --all             # Full analysis
  binfreak_cli.py binary.exe --json            # JSON output
  binfreak_cli.py binary.exe --limit 50        # Limit results
        """
    )
    
    parser.add_argument('file', help='Binary file to analyze')
    parser.add_argument('--strings', action='store_true', help='Show extracted strings')
    parser.add_argument('--functions', action='store_true', help='Show detected functions')
    parser.add_argument('--sections', action='store_true', help='Show file sections')
    parser.add_argument('--entropy', action='store_true', help='Show entropy analysis')
    parser.add_argument('--all', action='store_true', help='Show all analysis details')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--limit', type=int, default=100, help='Limit number of results (default: 100)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate file
    if not os.path.exists(args.file):
        print(f"❌ Error: File '{args.file}' not found")
        sys.exit(1)
    
    if not os.path.isfile(args.file):
        print(f"❌ Error: '{args.file}' is not a file")
        sys.exit(1)
    
    # Perform analysis
    print(f"🔍 Analyzing '{args.file}'...")
    engine = BinaryAnalysisEngine()
    result = engine.analyze_file(args.file)
    
    if args.json:
        # JSON output
        print(json.dumps(result, indent=2, default=str))
        return
    
    # Text output
    print_analysis_summary(result)
    
    if 'error' in result:
        sys.exit(1)
    
    # Handle --all flag
    if args.all:
        args.strings = True
        args.functions = True
        args.sections = True
        args.entropy = True
    
    # Print detailed analysis if requested
    if any([args.strings, args.functions, args.sections, args.entropy]):
        print_detailed_analysis(result, args)
    
    print(f"\n✅ Analysis completed successfully")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)