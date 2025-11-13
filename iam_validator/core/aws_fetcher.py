"""AWS Service Fetcher - Backward compatibility facade.

DEPRECATED: This module is kept for backward compatibility.
New code should import from iam_validator.core.aws_service instead:

    from iam_validator.core.aws_service import AWSServiceFetcher

This facade will be removed in a future major version.
"""

import warnings

# Re-export classes from new location
from iam_validator.core.aws_service import (
    AWSServiceFetcher,
    CompiledPatterns,
    ConditionKeyValidationResult,
)

# Emit deprecation warning when this module is imported
warnings.warn(
    "Importing from iam_validator.core.aws_fetcher is deprecated. "
    "Use 'from iam_validator.core.aws_service import AWSServiceFetcher' instead. "
    "This compatibility layer will be removed in a future major version.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["AWSServiceFetcher", "ConditionKeyValidationResult", "CompiledPatterns"]
