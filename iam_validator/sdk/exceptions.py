"""
Public exception types for the IAM Policy Validator SDK.

This module defines user-facing exceptions that library users might want to catch
and handle in their code.
"""


class IAMValidatorError(Exception):
    """Base exception for all IAM Validator errors."""

    pass


class PolicyLoadError(IAMValidatorError):
    """Raised when a policy file cannot be loaded or parsed."""

    pass


class PolicyValidationError(IAMValidatorError):
    """Raised when policy validation fails critically."""

    pass


class ConfigurationError(IAMValidatorError):
    """Raised when configuration is invalid or cannot be loaded."""

    pass


class AWSServiceError(IAMValidatorError):
    """Raised when AWS service data cannot be fetched."""

    pass


class InvalidPolicyFormatError(PolicyLoadError):
    """Raised when policy format is invalid (not valid JSON/YAML or missing required fields)."""

    pass


class UnsupportedPolicyTypeError(PolicyLoadError):
    """Raised when policy type is not supported."""

    pass
