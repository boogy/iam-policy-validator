"""
Default service principals for resource policy validation.

These are AWS service principals that are commonly used and considered safe
in resource-based policies (S3 bucket policies, SNS topic policies, etc.).
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
