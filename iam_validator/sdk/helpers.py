"""
Helper utilities for custom check development.

This module provides high-level helper classes and functions that make it
easy to develop custom IAM policy checks.
"""

from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import ValidationIssue
from iam_validator.sdk.arn_matching import arn_matches, arn_strictly_valid


class CheckHelper:
    """
    All-in-one helper class for custom check development.

    This class provides convenient methods for common check operations like
    ARN matching, action expansion, and issue creation.

    Example:
        >>> helper = CheckHelper(fetcher)
        >>> actions = await helper.expand_actions(["s3:Get*"])
        >>> if helper.arn_matches("arn:*:s3:::secret-*", resource):
        ...     issue = helper.create_issue(
        ...         severity="high",
        ...         statement_idx=0,
        ...         message="Sensitive bucket access"
        ...     )
    """

    def __init__(self, fetcher: AWSServiceFetcher):
        """
        Initialize helper with AWS service fetcher.

        Args:
            fetcher: AWS service fetcher for retrieving service definitions
        """
        self.fetcher = fetcher

    async def expand_actions(
        self,
        actions: list[str],
    ) -> list[str]:
        """
        Expand action wildcards to concrete actions.

        Args:
            actions: List of actions that may contain wildcards (e.g., ["s3:Get*"])

        Returns:
            List of expanded action strings (e.g., ["s3:GetObject", "s3:GetObjectVersion"])

        Example:
            >>> actions = await helper.expand_actions(["s3:Get*"])
            >>> # Returns: ["s3:GetObject", "s3:GetObjectVersion", ...]
        """
        return await expand_wildcard_actions(actions, self.fetcher)

    def arn_matches(
        self,
        pattern: str,
        arn: str,
        resource_type: str | None = None,
    ) -> bool:
        """
        Check if ARN matches pattern with glob support.

        Args:
            pattern: ARN pattern (can have wildcards)
            arn: ARN to check (can have wildcards)
            resource_type: Optional resource type for special handling

        Returns:
            True if ARN matches pattern

        Example:
            >>> helper.arn_matches("arn:*:s3:::secret-*", "arn:aws:s3:::secret-bucket/key")
            True
        """
        return arn_matches(pattern, arn, resource_type)

    def arn_strictly_valid(
        self,
        pattern: str,
        arn: str,
        resource_type: str | None = None,
    ) -> bool:
        """
        Strictly validate ARN against pattern.

        Args:
            pattern: ARN pattern from AWS service definition
            arn: ARN to validate
            resource_type: Optional resource type

        Returns:
            True if ARN strictly matches pattern
        """
        return arn_strictly_valid(pattern, arn, resource_type)

    def create_issue(
        self,
        severity: str,
        statement_idx: int,
        message: str,
        statement_sid: str | None = None,
        issue_type: str = "custom",
        action: str | None = None,
        resource: str | None = None,
        condition_key: str | None = None,
        suggestion: str | None = None,
        line_number: int | None = None,
    ) -> ValidationIssue:
        """
        Create a validation issue with all necessary fields.

        Args:
            severity: Severity level (critical, high, medium, low, error, warning, info)
            statement_idx: Index of the statement in the policy
            message: Human-readable error message
            statement_sid: Optional statement ID
            issue_type: Type of issue (default: "custom")
            action: Optional action that caused the issue
            resource: Optional resource that caused the issue
            condition_key: Optional condition key that caused the issue
            suggestion: Optional suggestion for fixing the issue
            line_number: Optional line number in source file

        Returns:
            ValidationIssue object
        """
        return ValidationIssue(
            severity=severity,
            statement_sid=statement_sid,
            statement_index=statement_idx,
            issue_type=issue_type,
            message=message,
            action=action,
            resource=resource,
            condition_key=condition_key,
            suggestion=suggestion,
            line_number=line_number,
        )


async def expand_actions(
    actions: list[str],
    fetcher: AWSServiceFetcher | None = None,
) -> list[str]:
    """
    Expand action wildcards to concrete actions.

    This is a standalone function that can be used without CheckHelper.

    Args:
        actions: List of actions that may contain wildcards
        fetcher: Optional AWS service fetcher (created if not provided)

    Returns:
        List of expanded action strings (e.g., ["s3:GetObject", "s3:GetObjectVersion"])

    Example:
        >>> from iam_validator.sdk import expand_actions
        >>> actions = await expand_actions(["s3:Get*"])
        >>> # Returns: ["s3:GetObject", "s3:GetObjectVersion", ...]

    Note:
        If no fetcher is provided, a temporary one will be created.
        For better performance when making multiple calls, create a
        fetcher once and pass it to this function or use CheckHelper.
    """
    if fetcher is None:
        # Create temporary fetcher
        fetcher = AWSServiceFetcher()

    return await expand_wildcard_actions(actions, fetcher)
