"""
Condition requirement configurations for action_condition_enforcement check.

This module defines default condition requirements for sensitive actions,
making it easy to manage complex condition enforcement rules without
deeply nested YAML/dict structures.

Using Python provides:
- Better readability and maintainability
- Type hints and IDE support
- Easy to add/modify requirements
- No parsing overhead
- Compiled to .pyc

Configuration Fields Reference:
- description: Technical description of what the requirement does (shown in output)
- example: Concrete code example showing proper condition usage
- condition_key: The IAM condition key to validate
- expected_value: (Optional) Expected value for the condition key
- severity: (Optional) Override default severity for this requirement

Field Progression: detect (condition_key) → explain (description) → demonstrate (example)

For detailed explanation of these fields and how to customize requirements,
see: docs/condition-requirements.md and docs/configuration.md#customizing-messages
"""

from typing import Any, Final

# ============================================================================
# Condition Requirement Definitions
# ============================================================================

# IAM PassRole - CRITICAL: Prevent privilege escalation
IAM_PASS_ROLE_REQUIREMENT: Final[dict[str, Any]] = {
    "actions": ["iam:PassRole"],
    "severity": "high",
    "required_conditions": [
        {
            "condition_key": "iam:PassedToService",
            "description": (
                "Restrict which AWS services can assume the passed role to prevent privilege escalation"
            ),
            "example": (
                '"Condition": {\n'
                '  "StringEquals": {\n'
                '    "iam:PassedToService": [\n'
                '      "lambda.amazonaws.com",\n'
                '      "ecs-tasks.amazonaws.com",\n'
                '      "ec2.amazonaws.com",\n'
                '      "glue.amazonaws.com"\n'
                "    ]\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# IAM Write Operations - Require permissions boundary
IAM_WRITE_PERMISSIONS_BOUNDARY: Final[dict[str, Any]] = {
    "actions": [
        "iam:CreateRole",
        "iam:PutRolePolicy*",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:Attach*Policy*",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
    ],
    "severity": "high",
    "required_conditions": [
        {
            "condition_key": "iam:PermissionsBoundary",
            "description": (
                "Require permissions boundary for sensitive IAM operations to prevent privilege escalation"
            ),
            "expected_value": "arn:aws:iam::*:policy/DeveloperBoundary",
            "example": (
                "# See: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html\n"
                "{\n"
                '  "Condition": {\n'
                '    "StringEquals": {\n'
                '      "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/XCompanyBoundaries"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# S3 Write Operations - Require organization ID
S3_WRITE_ORG_ID: Final[dict[str, Any]] = {
    "actions": ["s3:PutObject"],
    "severity": "medium",
    "required_conditions": [
        {
            "condition_key": "aws:ResourceOrgId",
            "description": (
                "Require aws:ResourceOrgId condition for S3 write actions to enforce organization-level access control"
            ),
            "example": (
                "{\n"
                '  "Condition": {\n'
                '    "StringEquals": {\n'
                '      "aws:ResourceOrgId": "${aws:PrincipalOrgID}"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# IP Restrictions - Source IP requirements
SOURCE_IP_RESTRICTIONS: Final[dict[str, Any]] = {
    "action_patterns": [
        "^ssm:StartSession$",
        "^ssm:Run.*$",
        "^s3:GetObject$",
        "^rds-db:Connect$",
    ],
    "severity": "low",
    "required_conditions": [
        {
            "condition_key": "aws:SourceIp",
            "description": "Restrict access to corporate IP ranges",
            "example": (
                "{\n"
                '  "Condition": {\n'
                '    "IpAddress": {\n'
                '      "aws:SourceIp": [\n'
                '        "10.0.0.0/8",\n'
                '        "172.16.0.0/12"\n'
                "      ]\n"
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# S3 Secure Transport - Never allow insecure transport
S3_SECURE_TRANSPORT: Final[dict[str, Any]] = {
    "actions": ["s3:GetObject", "s3:PutObject"],
    "required_conditions": {
        "none_of": [
            {
                "condition_key": "aws:SecureTransport",
                "expected_value": False,
                "description": "Never allow insecure transport to be explicitly permitted",
                "example": (
                    "# Set this condition to true to enforce secure transport or remove it entirely\n"
                    "{\n"
                    '  "Condition": {\n'
                    '    "Bool": {\n'
                    '      "aws:SecureTransport": "true"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
        ],
    },
}

# ============================================================================
# Optional Requirements (Commented Examples for Users)
# ============================================================================
# These are disabled by default but can be enabled by users

# S3 Destructive Operations - Require MFA
S3_DESTRUCTIVE_MFA: Final[dict[str, Any]] = {
    "actions": [
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPolicy",
    ],
    "severity": "high",
    "required_conditions": [
        {
            "condition_key": "aws:MultiFactorAuthPresent",
            "description": "Require MFA for S3 destructive operations",
            "expected_value": "true",
            "example": (
                "{\n"
                '  "Condition": {\n'
                '    "Bool": {\n'
                '      "aws:MultiFactorAuthPresent": "true"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# All S3 Operations - Require HTTPS
S3_REQUIRE_HTTPS: Final[dict[str, Any]] = {
    "action_patterns": ["^s3:.*"],
    "severity": "medium",
    "required_conditions": [
        {
            "condition_key": "aws:SecureTransport",
            "description": "Require HTTPS for all S3 operations",
            "expected_value": True,
            "example": (
                "{\n"
                '  "Condition": {\n'
                '    "Bool": {\n'
                '      "aws:SecureTransport": "true"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# EC2 Instances - Must be in specific VPCs
EC2_VPC_RESTRICTION: Final[dict[str, Any]] = {
    "actions": ["ec2:RunInstances"],
    "severity": "high",
    "required_conditions": [
        {
            "condition_key": "ec2:Vpc",
            "description": "EC2 instances must be launched in approved VPCs",
            "example": (
                "{\n"
                '  "Condition": {\n'
                '    "StringEquals": {\n'
                '      "ec2:Vpc": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        },
    ],
}

# EC2 Instances - Tag requirements (ABAC)
EC2_TAG_REQUIREMENTS: Final[dict[str, Any]] = {
    "actions": ["ec2:RunInstances"],
    "severity": "high",
    "required_conditions": {
        "all_of": [
            {
                "condition_key": "aws:RequestTag/env",
                "operator": "StringEquals",
                "expected_value": ["prod", "pre", "dev", "sandbox"],
                "description": "Must specify a valid Environment tag",
            },
        ],
        "any_of": [
            {
                "condition_key": "aws:ResourceTag/owner",
                "operator": "StringEquals",
                "expected_value": "${aws:PrincipalTag/owner}",
                "description": "Resource owner must match the principal's owner tag",
            },
            {
                "condition_key": "aws:RequestTag/owner",
                "description": "Must specify resource owner",
                "expected_value": "${aws:PrincipalTag/owner}",
            },
        ],
    },
}

# RDS - Database tag requirements
RDS_TAG_REQUIREMENTS: Final[dict[str, Any]] = {
    "action_patterns": [
        "^rds:Create.*",
        "^rds:Modify.*",
    ],
    "severity": "medium",
    "required_conditions": {
        "all_of": [
            {
                "condition_key": "aws:RequestTag/DataClassification",
                "description": "Must specify data classification",
            },
            {
                "condition_key": "aws:RequestTag/BackupPolicy",
                "description": "Must specify backup policy",
            },
            {
                "condition_key": "aws:RequestTag/Owner",
                "description": "Must specify resource owner",
            },
        ],
    },
}

# S3 Bucket Operations - Data classification matching
S3_BUCKET_TAG_REQUIREMENTS: Final[dict[str, Any]] = {
    "actions": ["s3:CreateBucket", "s3:PutObject"],
    "severity": "medium",
    "required_conditions": {
        "all_of": [
            {
                "condition_key": "aws:ResourceTag/DataClassification",
                "operator": "StringEquals",
                "expected_value": "${aws:PrincipalTag/DataClassification}",
                "description": "Data classification must match principal's tag",
            },
            {
                "condition_key": "aws:RequestTag/Owner",
                "description": "Must specify owner",
            },
            {
                "condition_key": "aws:RequestTag/CostCenter",
                "description": "Must specify cost center",
            },
        ],
    },
}

# Forbidden Actions - Flag if these dangerous actions appear
FORBIDDEN_ACTIONS: Final[dict[str, Any]] = {
    "actions": {
        "none_of": [
            "iam:*",
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
        ],
    },
    "severity": "critical",
    "description": "These highly sensitive actions are forbidden in this policy",
}

# Prevent overly permissive IP ranges
PREVENT_PUBLIC_IP: Final[dict[str, Any]] = {
    "action_patterns": ["^s3:.*"],
    "severity": "high",
    "required_conditions": {
        "none_of": [
            {
                "condition_key": "aws:SourceIp",
                "expected_value": "0.0.0.0/0",
                "description": "Do not allow access from any IP address",
            },
        ],
    },
}

# ============================================================================
# Default Requirements List
# ============================================================================

# Requirements enabled by default
DEFAULT_CONDITION_REQUIREMENTS: Final[list[dict[str, Any]]] = [
    IAM_PASS_ROLE_REQUIREMENT,
    IAM_WRITE_PERMISSIONS_BOUNDARY,
    S3_WRITE_ORG_ID,
    SOURCE_IP_RESTRICTIONS,
    S3_SECURE_TRANSPORT,
]

# All available requirements (including optional ones)
ALL_CONDITION_REQUIREMENTS: Final[dict[str, dict[str, Any]]] = {
    # Default (enabled)
    "iam_pass_role": IAM_PASS_ROLE_REQUIREMENT,
    "iam_permissions_boundary": IAM_WRITE_PERMISSIONS_BOUNDARY,
    "s3_org_id": S3_WRITE_ORG_ID,
    "source_ip_restrictions": SOURCE_IP_RESTRICTIONS,
    "s3_secure_transport": S3_SECURE_TRANSPORT,
    # Optional (disabled by default)
    "s3_destructive_mfa": S3_DESTRUCTIVE_MFA,
    "s3_require_https": S3_REQUIRE_HTTPS,
    "ec2_vpc_restriction": EC2_VPC_RESTRICTION,
    "ec2_tag_requirements": EC2_TAG_REQUIREMENTS,
    "rds_tag_requirements": RDS_TAG_REQUIREMENTS,
    "s3_bucket_tag_requirements": S3_BUCKET_TAG_REQUIREMENTS,
    "forbidden_actions": FORBIDDEN_ACTIONS,
    "prevent_public_ip": PREVENT_PUBLIC_IP,
}


# ============================================================================
# Helper Functions
# ============================================================================


def get_default_requirements() -> list[dict[str, Any]]:
    """
    Get the default condition requirements.

    Returns:
        List of default condition requirement configurations
    """
    # Return a copy to prevent modification
    import copy

    return copy.deepcopy(DEFAULT_CONDITION_REQUIREMENTS)


def get_requirement(name: str) -> dict[str, Any] | None:
    """
    Get a specific requirement by name.

    Args:
        name: Requirement name (e.g., "iam_pass_role", "s3_destructive_mfa")

    Returns:
        Requirement configuration dict, or None if not found
    """
    import copy

    req = ALL_CONDITION_REQUIREMENTS.get(name)
    return copy.deepcopy(req) if req else None


def get_all_requirement_names() -> list[str]:
    """
    Get list of all available requirement names.

    Returns:
        List of requirement names
    """
    return list(ALL_CONDITION_REQUIREMENTS.keys())


def get_requirements_by_names(names: list[str]) -> list[dict[str, Any]]:
    """
    Get multiple requirements by name.

    Args:
        names: List of requirement names

    Returns:
        List of requirement configurations
    """
    import copy

    requirements = []
    for name in names:
        req = ALL_CONDITION_REQUIREMENTS.get(name)
        if req:
            requirements.append(copy.deepcopy(req))
    return requirements


def get_requirements_by_severity(
    min_severity: str = "low",
) -> list[dict[str, Any]]:
    """
    Get requirements filtered by minimum severity.

    Args:
        min_severity: Minimum severity level (low, medium, high, critical)

    Returns:
        List of requirements matching severity criteria
    """
    import copy

    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_level = severity_order.get(min_severity, 0)

    requirements = []
    for req in ALL_CONDITION_REQUIREMENTS.values():
        req_severity = req.get("severity", "low")
        req_level = severity_order.get(req_severity, 0)
        if req_level >= min_level:
            requirements.append(copy.deepcopy(req))

    return requirements


def describe_requirement(name: str) -> dict[str, Any]:
    """
    Get description and metadata for a requirement.

    Args:
        name: Requirement name

    Returns:
        Dictionary with requirement metadata
    """
    descriptions = {
        "iam_pass_role": {
            "name": "IAM PassRole Restriction",
            "category": "privilege_escalation",
            "severity": "high",
            "description": "Prevents privilege escalation by requiring iam:PassedToService condition",
            "required": True,
        },
        "iam_permissions_boundary": {
            "name": "IAM Permissions Boundary",
            "category": "privilege_escalation",
            "severity": "high",
            "description": "Requires permissions boundary for IAM write operations",
            "required": True,
        },
        "s3_org_id": {
            "name": "S3 Organization ID",
            "category": "data_exfiltration",
            "severity": "medium",
            "description": "Ensures S3 operations stay within organization",
            "required": True,
        },
        "source_ip_restrictions": {
            "name": "Source IP Restrictions",
            "category": "network_security",
            "severity": "low",
            "description": "Restricts access to corporate IP ranges",
            "required": False,
        },
        "s3_secure_transport": {
            "name": "S3 Secure Transport",
            "category": "encryption",
            "severity": "medium",
            "description": "Prevents explicitly allowing insecure transport",
            "required": True,
        },
        "s3_destructive_mfa": {
            "name": "S3 Destructive MFA",
            "category": "data_protection",
            "severity": "high",
            "description": "Requires MFA for destructive S3 operations",
            "required": False,
        },
        "ec2_tag_requirements": {
            "name": "EC2 Tag Requirements (ABAC)",
            "category": "abac",
            "severity": "high",
            "description": "Enforces tag-based access control for EC2 instances",
            "required": False,
        },
    }

    return descriptions.get(name, {"name": "Unknown", "description": "Unknown requirement"})
