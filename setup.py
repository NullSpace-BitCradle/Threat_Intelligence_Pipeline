#!/usr/bin/env python3
"""
Setup script for Threat Intelligence Pipeline
This script helps users set up the project by creating necessary directories and files.
"""

import os
import sys
from pathlib import Path

def create_directories():
    """Create necessary directories for the project"""
    directories = [
        'logs',
        'database', 
        'resources',
        'results'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✓ Created directory: {directory}")

def create_placeholder_files():
    """Create placeholder files for generated data"""
    placeholder_files = {
        'lastUpdate.txt': '1970-01-01T00:00:00.000000',
        'resources/placeholder.txt': 'This directory will contain generated database files.',
        'database/placeholder.txt': 'This directory will contain CVE database files.',
        'results/placeholder.txt': 'This directory will contain processing results.',
        'logs/placeholder.txt': 'This directory will contain log files.'
    }
    
    for file_path, content in placeholder_files.items():
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"✓ Created placeholder: {file_path}")

def main():
    """Main setup function"""
    print("🚀 Setting up Threat Intelligence Pipeline...")
    print("=" * 50)
    
    try:
        create_directories()
        create_placeholder_files()
        
        print("\n✅ Setup complete!")
        print("\nNext steps:")
        print("1. Set your NVD API key: export NVD_API_KEY='your-api-key-here'")
        print("2. Run the pipeline: python tip.py")
        print("3. Open the web interface: python -m http.server 8000")
        print("4. Navigate to: http://localhost:8000/docs/index.html")
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
