#!/usr/bin/env python3
"""Entry point: `python main.py <command> ...`"""

import sys

from password_manager.cli import main

if __name__ == "__main__":
    sys.exit(main())
