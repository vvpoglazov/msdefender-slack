#!/usr/bin/env python
"""
Script to run the tests for MS Defender Slack integration.
Tests are run with mocked clients, so no real API keys are needed.
"""
import os
import sys
import pytest

def main():
    """Run the test suite."""
    print("\n=== Microsoft Defender Slack Notification Tests ===\n")
    print("Running tests with mocked APIs (no real credentials needed)...\n")
    
    # Ensure tests directory is in path
    test_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.dirname(test_dir))
    
    # Run pytest with appropriate args
    args = [
        "-v",                   # Verbose output
        "--color=yes",          # Colored output
        test_dir,               # Test directory
        "-xvs",                 # Exit on first failure, verbose, no capture
    ]
    
    exit_code = pytest.main(args)
    
    if exit_code == 0:
        print("\n✅ All tests passed successfully!")
        print("You can proceed without real API keys for Slack and Microsoft Defender")
    else:
        print("\n❌ Some tests failed. Please fix the issues before proceeding.")
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main()) 