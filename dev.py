#!/usr/bin/env python3
"""
BinFreak Development Helper - Common development tasks
"""

import os
import sys
import subprocess
from pathlib import Path


def run_command(cmd, description):
    """Run a command and print the result"""
    print(f"🔄 {description}...")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"✅ {description} completed")
        if result.stdout.strip():
            print(f"Output: {result.stdout.strip()}")
    else:
        print(f"❌ {description} failed")
        if result.stderr.strip():
            print(f"Error: {result.stderr.strip()}")
    
    return result.returncode == 0


def test():
    """Run all tests"""
    print("🧪 Running tests...")
    return run_command("python3 test_binfreak.py", "Basic tests")


def validate():
    """Run validation"""
    print("🔍 Running validation...")
    return run_command("python3 validate_refactoring.py", "Refactoring validation")


def demo():
    """Run a demo analysis"""
    print("🎬 Running demo analysis...")
    if os.path.exists("binfreak/test_binary"):
        return run_command("python3 binfreak_cli.py binfreak/test_binary --all --limit 5", "Demo analysis")
    else:
        print("❌ Test binary not found")
        return False


def clean():
    """Clean up temporary files"""
    print("🧹 Cleaning up...")
    commands = [
        "find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true",
        "find . -name '*.pyc' -delete 2>/dev/null || true",
        "find . -name '*.pyo' -delete 2>/dev/null || true",
        "find . -name '.DS_Store' -delete 2>/dev/null || true"
    ]
    
    for cmd in commands:
        subprocess.run(cmd, shell=True, capture_output=True)
    
    print("✅ Cleanup completed")
    return True


def install():
    """Install dependencies"""
    print("📦 Installing dependencies...")
    return run_command("pip install -r requirements.txt", "Dependency installation")


def help_text():
    """Show help"""
    print("""
🛠️  BinFreak Development Helper

Usage: python3 dev.py <command>

Commands:
  test        Run all tests
  validate    Run refactoring validation
  demo        Run demo analysis on test binary
  clean       Clean up temporary files
  install     Install dependencies
  help        Show this help

Examples:
  python3 dev.py test
  python3 dev.py demo
  python3 dev.py clean
    """)


def main():
    """Main function"""
    if len(sys.argv) != 2:
        help_text()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    commands = {
        'test': test,
        'validate': validate,
        'demo': demo,
        'clean': clean,
        'install': install,
        'help': help_text
    }
    
    if command not in commands:
        print(f"❌ Unknown command: {command}")
        help_text()
        sys.exit(1)
    
    success = commands[command]()
    
    if success is False:
        sys.exit(1)


if __name__ == "__main__":
    main()