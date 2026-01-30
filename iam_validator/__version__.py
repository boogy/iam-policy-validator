"""Version information for IAM Validator.

This file is the single source of truth for the package version.
"""

__version__ = "1.15.6"
# Parse version, handling pre-release suffixes like -rc, -alpha, -beta
_version_base = __version__.split("-", maxsplit=1)[0]  # Remove pre-release suffix if present
__version_info__ = tuple(int(part) for part in _version_base.split("."))
