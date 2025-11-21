"""
Default wildcard configurations for security best practices checks.

These wildcards define which actions are considered "safe" to use with
Resource: "*" (e.g., read-only describe operations).

Using Python tuples instead of YAML lists provides:
- Zero parsing overhead
- Immutable by default (tuples)
- Better performance
- Easy PyPI packaging
"""

from typing import Final

# ============================================================================
# Allowed Wildcards for Resource: "*"
# ============================================================================
# These action patterns are considered safe to use with wildcard resources
# They are typically read-only operations that need broad resource access

DEFAULT_ALLOWED_WILDCARDS: Final[tuple[str, ...]] = (
    # Auto Scaling
    "autoscaling:Describe*",
    # CloudWatch
    "cloudwatch:Describe*",
    "cloudwatch:Get*",
    "cloudwatch:List*",
    # DynamoDB
    "dynamodb:Describe*",
    "dynamodb:Get*",
    "dynamodb:List*",
    # EC2
    "ec2:Describe*",
    "ec2:List*",
    # Elastic Load Balancing
    "elasticloadbalancing:Describe*",
    # IAM (non-sensitive read operations)
    "iam:Get*",
    "iam:List*",
    # KMS
    "kms:Describe*",
    # Lambda
    "lambda:Get*",
    "lambda:List*",
    # CloudWatch Logs
    "logs:Describe*",
    "logs:Filter*",
    "logs:Get*",
    # RDS
    "rds:Describe*",
    # Route53
    "route53:Get*",
    "route53:List*",
    # S3 (safe read operations only)
    "s3:Describe*",
    "s3:GetBucket*",
    "s3:GetM*",
    "s3:List*",
    # SQS
    "sqs:Get*",
    "sqs:List*",
    # API Gateway
    "apigateway:GET",
)

# ============================================================================
# Service-Level Wildcards (Allowed Services)
# ============================================================================
# Services that are allowed to use service-level wildcards like "logs:*"
# These are typically low-risk monitoring/logging services

DEFAULT_SERVICE_WILDCARDS: Final[tuple[str, ...]] = (
    "logs",
    "cloudwatch",
    "xray",
)


def get_allowed_wildcards() -> tuple[str, ...]:
    """
    Get tuple of allowed wildcard action patterns.

    Returns:
        Tuple of action patterns that are safe to use with Resource: "*"
    """
    return DEFAULT_ALLOWED_WILDCARDS


def get_allowed_service_wildcards() -> tuple[str, ...]:
    """
    Get tuple of services allowed to use service-level wildcards.

    Returns:
        Tuple of service names (e.g., "logs", "cloudwatch")
    """
    return DEFAULT_SERVICE_WILDCARDS


def is_allowed_wildcard(pattern: str) -> bool:
    """
    Check if a wildcard pattern is in the allowed list.

    Args:
        pattern: Action pattern to check (e.g., "s3:List*")

    Returns:
        True if pattern is in allowed wildcards

    Performance: O(n) but typically small list (~25 items)
    """
    return pattern in DEFAULT_ALLOWED_WILDCARDS


def is_allowed_service_wildcard(service: str) -> bool:
    """
    Check if a service is allowed to use service-level wildcards.

    Args:
        service: Service name (e.g., "logs", "s3")

    Returns:
        True if service is in allowed list

    Performance: O(n) but very small list (~3 items)
    """
    return service in DEFAULT_SERVICE_WILDCARDS
