#!/usr/bin/env python3
"""
Setup script for Threat Intelligence Pipeline
Creates necessary directories for pipeline operation.
"""

import sys
from pathlib import Path


def main():
    """Create required directories"""
    directories = [
        'docs/data',
        'docs/database',
        'logs',
        'results'
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

    # Create lastUpdate.txt if it doesn't exist
    last_update = Path('lastUpdate.txt')
    if not last_update.exists():
        last_update.write_text('1970-01-01T00:00:00.000000')

    print("Setup complete.")
    print("Next steps:")
    print("  1. Set NVD API key: export NVD_API_KEY='your-key'")
    print("  2. Run pipeline:    PYTHONPATH=src python run_pipeline.py")


if __name__ == "__main__":
    main()
