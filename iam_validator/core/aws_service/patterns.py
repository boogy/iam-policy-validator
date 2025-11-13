"""Pre-compiled regex patterns for AWS service validation.

This module provides a singleton class containing pre-compiled regex patterns
used across the AWS service validation system for better performance.
"""

import re


class CompiledPatterns:
    """Pre-compiled regex patterns for validation.

    This class implements the Singleton pattern to ensure patterns are compiled only once
    and reused across all instances for better performance.
    """

    _instance: "CompiledPatterns | None" = None
    _initialized: bool = False

    def __new__(cls) -> "CompiledPatterns":
        """Create or return the singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize compiled patterns (only once due to Singleton pattern)."""
        # Only initialize once, even if __init__ is called multiple times
        if CompiledPatterns._initialized:
            return

        CompiledPatterns._initialized = True

        # ARN validation pattern
        self.arn_pattern = re.compile(
            r"^arn:(?P<partition>(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f)):"
            r"(?P<service>[a-z0-9\-]+):"
            r"(?P<region>[a-z0-9\-]*):"
            r"(?P<account>[0-9]*):"
            r"(?P<resource>.+)$",
            re.IGNORECASE,
        )

        # Action format pattern
        self.action_pattern = re.compile(
            r"^(?P<service>[a-zA-Z0-9_-]+):(?P<action>[a-zA-Z0-9*_-]+)$"
        )

        # Wildcard detection patterns
        self.wildcard_pattern = re.compile(r"\*")
        self.partial_wildcard_pattern = re.compile(r"^[^*]+\*$")
