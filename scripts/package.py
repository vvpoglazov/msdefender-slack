#!/usr/bin/env python3
"""
Package Lambda functions for deployment.
"""

import os
import shutil
import zipfile
import subprocess
import tempfile
import sys

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
DIST_DIR = os.path.join(PROJECT_ROOT, 'dist')
PACKAGE_PATH = os.path.join(DIST_DIR, 'lambda_package.zip')

# Ensure dist directory exists
if not os.path.exists(DIST_DIR):
    os.makedirs(DIST_DIR)

def create_lambda_package():
    """
    Create a Lambda deployment package containing all required code.
    """
    print("Creating Lambda deployment package...")
    
    # Create a temporary directory for the package contents
    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy the source code
        print("Copying source code...")
        shutil.copytree(SRC_DIR, os.path.join(temp_dir, 'src'))
        
        # Install dependencies
        print("Installing dependencies...")
        pip_command = [
            sys.executable, '-m', 'pip', 'install',
            '--target', temp_dir,
            '-r', os.path.join(PROJECT_ROOT, 'requirements.txt')
        ]
        
        # Execute pip install
        try:
            subprocess.check_call(pip_command)
        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies: {e}")
            sys.exit(1)
        
        # Create the zip file
        print(f"Creating zip file: {PACKAGE_PATH}")
        with zipfile.ZipFile(PACKAGE_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk the temporary directory and add all files
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip __pycache__ directories and .pyc files
                    if '__pycache__' in file_path or file.endswith('.pyc'):
                        continue
                    
                    # Get relative path
                    rel_path = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, rel_path)
    
    # Print the package size
    package_size_mb = os.path.getsize(PACKAGE_PATH) / (1024 * 1024)
    print(f"Package created successfully: {PACKAGE_PATH} ({package_size_mb:.2f} MB)")
    
    # Check if the package is under the Lambda size limit
    if package_size_mb > 50:
        print("WARNING: Package size exceeds AWS Lambda limit of 50 MB")
        
    return PACKAGE_PATH

if __name__ == "__main__":
    create_lambda_package() 