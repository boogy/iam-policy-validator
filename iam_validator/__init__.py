"""IAM Policy Validator - Validate AWS IAM policies for correctness and security."""

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.cli import main
from iam_validator.core.models import (
    IAMPolicy,
    PolicyValidationResult,
    Statement,
    ValidationIssue,
    ValidationReport,
)
from iam_validator.integrations.github_integration import GitHubIntegration

from .__version__ import __version__, __version_info__

__all__ = [
    "__version__",
    "__version_info__",
    "IAMPolicy",
    "Statement",
    "ValidationIssue",
    "PolicyValidationResult",
    "ValidationReport",
    "AWSServiceFetcher",
    "GitHubIntegration",
    "main",
]
