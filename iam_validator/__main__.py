"""Main entry point for iam_validator package.

Allows running as: python -m iam_validator
"""

import sys

from iam_validator.core.cli import main

if __name__ == "__main__":
    sys.exit(main())
