"""
Service principals utilities for resource policy validation.

This module provides:
- Default list of common AWS service principals
- Utility to check if a principal is any AWS service principal
- Functions to categorize service principals by type

Configuration:
- Use "*" in allowed_service_principals to allow ALL AWS service principals
- Use explicit list to restrict to specific services only
- AWS service principals end with .amazonaws.com or .amazonaws.com.cn
"""

from typing import Final

# ============================================================================
# Allowed Service Principals
# ============================================================================
# These AWS service principals are commonly used in resource policies
# and are generally considered safe to allow

DEFAULT_SERVICE_PRINCIPALS: Final[tuple[str, ...]] = (
    "cloudfront.amazonaws.com",
    "s3.amazonaws.com",
    "sns.amazonaws.com",
    "lambda.amazonaws.com",
    "logs.amazonaws.com",
    "events.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "backup.amazonaws.com",
    "cloudwatch.amazonaws.com",
    "monitoring.amazonaws.com",
    "ec2.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "eks.amazonaws.com",
    "apigateway.amazonaws.com",
)


def get_service_principals() -> tuple[str, ...]:
    """
    Get tuple of allowed service principals.

    Returns:
        Tuple of AWS service principal names
    """
    return DEFAULT_SERVICE_PRINCIPALS


def is_allowed_service_principal(principal: str) -> bool:
    """
    Check if a principal is an allowed service principal.

    Args:
        principal: Principal to check (e.g., "lambda.amazonaws.com")

    Returns:
        True if principal is in allowed list

    Performance: O(n) but small list (~16 items)
    """
    return principal in DEFAULT_SERVICE_PRINCIPALS


def is_aws_service_principal(principal: str) -> bool:
    """
    Check if a principal is an AWS service principal (any AWS service).

    This checks if the principal matches the AWS service principal pattern.
    AWS service principals typically end with ".amazonaws.com" or ".amazonaws.com.cn"

    Args:
        principal: Principal to check (e.g., "lambda.amazonaws.com", "s3.amazonaws.com.cn")

    Returns:
        True if principal matches AWS service principal pattern

    Examples:
        >>> is_aws_service_principal("lambda.amazonaws.com")
        True
        >>> is_aws_service_principal("s3.amazonaws.com.cn")
        True
        >>> is_aws_service_principal("arn:aws:iam::123456789012:root")
        False
        >>> is_aws_service_principal("*")
        False
    """
    if not isinstance(principal, str):
        return False

    # AWS service principals end with .amazonaws.com or .amazonaws.com.cn
    return principal.endswith(".amazonaws.com") or principal.endswith(".amazonaws.com.cn")


def get_service_principals_by_category() -> dict[str, tuple[str, ...]]:
    """
    Get service principals organized by service category.

    Returns:
        Dictionary mapping categories to service principal tuples
    """
    return {
        "storage": (
            "s3.amazonaws.com",
            "backup.amazonaws.com",
        ),
        "compute": (
            "lambda.amazonaws.com",
            "ec2.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "eks.amazonaws.com",
        ),
        "networking": (
            "cloudfront.amazonaws.com",
            "elasticloadbalancing.amazonaws.com",
            "apigateway.amazonaws.com",
        ),
        "monitoring": (
            "logs.amazonaws.com",
            "cloudwatch.amazonaws.com",
            "monitoring.amazonaws.com",
            "cloudtrail.amazonaws.com",
        ),
        "messaging": (
            "sns.amazonaws.com",
            "events.amazonaws.com",
        ),
        "management": ("config.amazonaws.com",),
    }
