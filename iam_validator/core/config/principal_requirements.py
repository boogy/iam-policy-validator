"""
Principal condition requirement configurations for principal_validation check.

This module defines default condition requirements for principals in resource-based
policies, making it easy to manage complex principal condition enforcement rules
without deeply nested YAML/dict structures.

Using Python provides:
- Better readability and maintainability
- Type hints and IDE support
- Easy to add/modify requirements
- No parsing overhead
- Compiled to .pyc

Configuration Fields Reference:
- principals: List of principal patterns to match (supports wildcards)
- severity: Override default severity for this requirement
- required_conditions: Conditions that must be present (supports all_of/any_of/none_of)
- condition_key: The IAM condition key to validate
- expected_value: (Optional) Expected value for the condition key
- operator: (Optional) Specific operator to validate (e.g., "StringEquals", "IpAddress")
- description: Technical description of what the requirement does
- example: Concrete code example showing proper condition usage

Field Progression: detect (condition_key) → explain (description) → demonstrate (example)

For detailed explanation of these fields and how to customize requirements,
see: docs/configuration.md#principal-validation
"""

from typing import Any, Final

# ============================================================================
# Principal Condition Requirement Definitions
# ============================================================================

# Public Access (*) - CRITICAL: Must have source restrictions
PUBLIC_ACCESS_REQUIREMENT: Final[dict[str, Any]] = {
    "principals": ["*"],
    "severity": "critical",
    "required_conditions": {
        "any_of": [
            {
                "condition_key": "aws:SourceArn",
                "description": (
                    "Public access must be scoped to a specific source ARN "
                    "(e.g., SNS topic, EventBridge rule, CloudFront distribution)"
                ),
                "example": (
                    "# Example: S3 bucket policy allowing access from SNS topic\n"
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"\n'
                    "  }\n"
                    "}"
                ),
            },
            {
                "condition_key": "aws:SourceAccount",
                "description": (
                    "Public access must be limited to a specific AWS account to prevent "
                    "unauthorized access from other accounts"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:SourceAccount": "123456789012"\n'
                    "  }\n"
                    "}"
                ),
            },
            {
                "condition_key": "aws:SourceVpce",
                "description": (
                    "Or limit public access to a specific VPC endpoint for network-level isolation"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:SourceVpce": "vpce-1a2b3c4d"\n'
                    "  }\n"
                    "}"
                ),
            },
            {
                "condition_key": "aws:SourceIp",
                "description": ("Or limit public access to specific IP addresses or CIDR ranges"),
                "example": (
                    '"Condition": {\n'
                    '  "IpAddress": {\n'
                    '    "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]\n'
                    "  }\n"
                    "}"
                ),
            },
        ]
    },
}

# Cross-Account Root Access - HIGH: Must be from same organization
CROSS_ACCOUNT_ORG_REQUIREMENT: Final[dict[str, Any]] = {
    "principals": ["arn:aws:iam::*:root"],
    "severity": "high",
    "required_conditions": {
        "any_of": [
            {
                "condition_key": "aws:PrincipalOrgID",
                "operator": "StringEquals",
                "description": (
                    "Cross-account root access must be from principals in the same AWS Organization "
                    "to prevent unauthorized third-party access"
                ),
                "example": (
                    "# Replace with your organization ID\n"
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:PrincipalOrgID": "o-123456789"\n'
                    "  }\n"
                    "}"
                ),
            },
            {
                "condition_key": "aws:PrincipalOrgPaths",
                "operator": "StringEquals",
                "description": (
                    "Cross-account root access must be from principals in the same AWS Organization "
                    "to prevent unauthorized third-party access"
                ),
                "example": (
                    "# Replace with your organization ID\n"
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:PrincipalOrgPaths": "o-123456789/*"\n'
                    "  }\n"
                    "}"
                ),
            },
        ],
    },
}

# IAM Roles - HIGH: Must have MFA or VPC endpoint
IAM_ROLE_MFA_OR_VPC: Final[dict[str, Any]] = {
    "principals": ["arn:aws:iam::*:role/*"],
    "severity": "high",
    "required_conditions": {
        "any_of": [
            {
                "condition_key": "aws:MultiFactorAuthPresent",
                "expected_value": True,
                "description": "Require MFA authentication for IAM role access",
                "example": (
                    '"Condition": {\n  "Bool": {\n    "aws:MultiFactorAuthPresent": "true"\n  }\n}'
                ),
            },
            {
                "condition_key": "aws:SourceVpce",
                "description": (
                    "Or require access from a specific VPC endpoint to ensure network-level isolation"
                ),
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:SourceVpce": "vpce-12345678"\n'
                    "  }\n"
                    "}"
                ),
            },
        ]
    },
}

# IAM Users - MEDIUM: Must have MFA and IP restrictions
IAM_USER_MFA_AND_IP: Final[dict[str, Any]] = {
    "principals": ["arn:aws:iam::*:user/*"],
    "severity": "medium",
    "required_conditions": {
        "all_of": [
            {
                "condition_key": "aws:MultiFactorAuthPresent",
                "expected_value": True,
                "severity": "high",  # Override for this specific condition
                "description": "IAM users must have MFA enabled for security",
                "example": (
                    '"Condition": {\n  "Bool": {\n    "aws:MultiFactorAuthPresent": "true"\n  }\n}'
                ),
            },
            {
                "condition_key": "aws:SourceIp",
                "operator": "IpAddress",
                "description": "IAM users must access from approved corporate IP ranges",
                "example": (
                    '"Condition": {\n'
                    '  "IpAddress": {\n'
                    '    "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]\n'
                    "  }\n"
                    "}"
                ),
            },
        ]
    },
}

# Federated Users - HIGH: Tag-based access control (ABAC)
FEDERATED_USER_ABAC: Final[dict[str, Any]] = {
    "principals": ["arn:aws:iam::*:federated-user/*"],
    "severity": "high",
    "required_conditions": {
        "all_of": [
            {
                "condition_key": "aws:PrincipalTag/Department",
                "description": "Federated users must have Department tag for access control",
                "example": (
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:PrincipalTag/Department": "Engineering"\n'
                    "  }\n"
                    "}"
                ),
            },
            {
                "condition_key": "aws:RequestTag/Owner",
                "operator": "StringEquals",
                "expected_value": "${aws:PrincipalTag/Owner}",
                "description": (
                    "Resource owner must match principal's owner tag (Attribute-Based Access Control)"
                ),
                "example": (
                    "# ABAC: Principal tag must match resource tag\n"
                    '"Condition": {\n'
                    '  "StringEquals": {\n'
                    '    "aws:RequestTag/Owner": "${aws:PrincipalTag/Owner}"\n'
                    "  }\n"
                    "}"
                ),
            },
        ]
    },
}

# Prevent Insecure Transport - CRITICAL: Never allow HTTP
PREVENT_INSECURE_TRANSPORT: Final[dict[str, Any]] = {
    "principals": ["*", "arn:aws:iam::*:*"],
    "severity": "critical",
    "required_conditions": {
        "none_of": [
            {
                "condition_key": "aws:SecureTransport",
                "expected_value": False,
                "description": (
                    "Insecure transport (HTTP) must never be explicitly allowed. "
                    "This prevents man-in-the-middle attacks and data interception"
                ),
                "example": (
                    "# INCORRECT - Never allow this:\n"
                    '"Condition": {\n'
                    '  "Bool": {\n'
                    '    "aws:SecureTransport": "false"  # ❌ This is forbidden\n'
                    "  }\n"
                    "}\n\n"
                    "# CORRECT - Require HTTPS:\n"
                    '"Condition": {\n'
                    '  "Bool": {\n'
                    '    "aws:SecureTransport": "true"  # ✅ Always use this\n'
                    "  }\n"
                    "}"
                ),
            }
        ]
    },
}

# Assumed Role Sessions - MEDIUM: Require session tags
ASSUMED_ROLE_SESSION_TAGS: Final[dict[str, Any]] = {
    "principals": ["arn:aws:sts::*:assumed-role/*"],
    "severity": "medium",
    "required_conditions": [
        {
            "condition_key": "aws:PrincipalTag/SessionName",
            "description": (
                "Assumed role sessions should be tagged with session name for audit trails "
                "and access attribution"
            ),
            "example": (
                '"Condition": {\n  "StringLike": {\n    "aws:PrincipalTag/SessionName": "*"\n  }\n}'
            ),
        }
    ],
}

# ============================================================================
# Registry and Helper Functions
# ============================================================================

# All available requirement definitions
ALL_PRINCIPAL_REQUIREMENTS: Final[dict[str, dict[str, Any]]] = {
    "public_access": PUBLIC_ACCESS_REQUIREMENT,
    "cross_account_org": CROSS_ACCOUNT_ORG_REQUIREMENT,
    "iam_role_mfa_or_vpc": IAM_ROLE_MFA_OR_VPC,
    "iam_user_mfa_and_ip": IAM_USER_MFA_AND_IP,
    "federated_user_abac": FEDERATED_USER_ABAC,
    "prevent_insecure_transport": PREVENT_INSECURE_TRANSPORT,
    "assumed_role_session_tags": ASSUMED_ROLE_SESSION_TAGS,
}

# Default requirements enabled by default (most critical ones)
DEFAULT_ENABLED_REQUIREMENTS: Final[list[str]] = [
    "public_access",  # CRITICAL: Public access must have restrictions
    "prevent_insecure_transport",  # CRITICAL: Never allow insecure transport
]


def get_default_principal_requirements() -> list[dict[str, Any]]:
    """Get default principal condition requirements (most critical ones enabled by default).

    Returns:
        List of default principal condition requirements
    """
    return [ALL_PRINCIPAL_REQUIREMENTS[name] for name in DEFAULT_ENABLED_REQUIREMENTS]


def get_principal_requirement(name: str) -> dict[str, Any] | None:
    """Get a single principal condition requirement by name.

    Args:
        name: The requirement name

    Returns:
        The principal condition requirement or None if not found
    """
    return ALL_PRINCIPAL_REQUIREMENTS.get(name)


def get_principal_requirements_by_names(names: list[str]) -> list[dict[str, Any]]:
    """Get multiple principal condition requirements by name.

    Args:
        names: List of requirement names

    Returns:
        List of principal condition requirements
    """
    return [
        ALL_PRINCIPAL_REQUIREMENTS[name] for name in names if name in ALL_PRINCIPAL_REQUIREMENTS
    ]


def get_principal_requirements_by_severity(severity: str) -> list[dict[str, Any]]:
    """Get principal condition requirements filtered by severity.

    Args:
        severity: The severity level (critical, high, medium, low)

    Returns:
        List of principal condition requirements with matching severity
    """
    return [req for req in ALL_PRINCIPAL_REQUIREMENTS.values() if req.get("severity") == severity]


def get_all_principal_requirement_names() -> list[str]:
    """Get all available principal condition requirement names.

    Returns:
        List of all requirement names
    """
    return list(ALL_PRINCIPAL_REQUIREMENTS.keys())


# ============================================================================
# Usage Examples
# ============================================================================

"""
# Example 1: Use default requirements (public_access + prevent_insecure_transport)
from iam_validator.core.config import get_default_principal_requirements

config = {
    "principal_validation": {
        "enabled": True,
        "principal_condition_requirements": get_default_principal_requirements(),
    }
}

# Example 2: Use specific requirements by name
from iam_validator.core.config import get_principal_requirements_by_names

config = {
    "principal_validation": {
        "enabled": True,
        "principal_condition_requirements": get_principal_requirements_by_names([
            "public_access",
            "cross_account_org",
            "iam_role_mfa_or_vpc",
        ]),
    }
}

# Example 3: Get all critical severity requirements
from iam_validator.core.config import get_principal_requirements_by_severity

config = {
    "principal_validation": {
        "enabled": True,
        "principal_condition_requirements": get_principal_requirements_by_severity("critical"),
    }
}

# Example 4: Get all available requirement names
from iam_validator.core.config import get_all_principal_requirement_names

print(get_all_principal_requirement_names())
# Output: ['public_access', 'cross_account_org', 'iam_role_mfa_or_vpc', ...]

# Example 5: Get a single requirement
from iam_validator.core.config import get_principal_requirement

req = get_principal_requirement("public_access")
if req:
    print(req["principals"])  # ["*"]
    print(req["severity"])    # "critical"
"""
