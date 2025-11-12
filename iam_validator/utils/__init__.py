"""Utility modules for IAM Policy Validator.

This package contains reusable utility classes and functions that have
NO dependencies on IAM-specific logic. These utilities are generic and
could be used in any Python project.

For IAM-specific utilities (that depend on CheckConfig, AWSServiceFetcher, etc.),
see iam_validator.checks.utils instead.

Organization:
    - cache.py: Generic caching implementations (LRUCache with TTL)
    - regex.py: Regex pattern caching and compilation utilities
    - terminal.py: Terminal width detection utilities
"""

from iam_validator.utils.cache import LRUCache
from iam_validator.utils.regex import (
    cached_pattern,
    clear_pattern_cache,
    compile_and_cache,
    get_cached_pattern,
)
from iam_validator.utils.terminal import get_terminal_width

__all__ = [
    # Cache utilities
    "LRUCache",
    # Regex utilities
    "cached_pattern",
    "compile_and_cache",
    "get_cached_pattern",
    "clear_pattern_cache",
    # Terminal utilities
    "get_terminal_width",
]
