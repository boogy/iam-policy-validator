"""
Condition requirement configurations for action_condition_enforcement check.

This module defines default condition requirements for sensitive actions,
making it easy to manage complex condition enforcement rules without
deeply nested YAML/dict structures.

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
    "suggestion_text": (
        "This action allows passing IAM roles to AWS services, which can lead to privilege escalation. "
        "Always restrict which services can receive roles:\n"
        "• Use `iam:PassedToService` to limit specific AWS services (e.g., lambda.amazonaws.com, ecs-tasks.amazonaws.com)\n"
        "• Consider adding `iam:AssociatedResourceArn` to restrict which resources can use the role\n"
        "• Require MFA for sensitive role passing (`aws:MultiFactorAuthPresent` = `true`)"
    ),
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

# S3 Organization Boundary - Prevent data exfiltration for both reads and writes
# Enforces that S3 operations only access resources within organizational boundaries
S3_ORG_BOUNDARY: Final[dict[str, Any]] = {
    "actions": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
    "severity": "medium",
    "suggestion_text": (
        "These S3 actions can read or write data. Prevent data exfiltration by ensuring operations only access organization-owned buckets:\n"
        "• Use organization ID (`aws:ResourceOrgID` = `${aws:PrincipalOrgID}`)\n"
        "• OR use organization paths (`aws:ResourceOrgPaths` = `${aws:PrincipalOrgPaths}`)\n"
        "• OR restrict by network boundary (IP/VPC/VPCe) + same account (`aws:ResourceAccount` = `${aws:PrincipalAccount}`)"
    ),
    "required_conditions": {
        "any_of": [
            # Option 1: Restrict to organization resources (strongest)
            {
                "condition_key": "aws:ResourceOrgID",
                "description": "Restrict S3 operations to resources within your AWS Organization",
                "expected_value": "${aws:PrincipalOrgID}",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:ResourceOrgID": "${aws:PrincipalOrgID}"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
            # Option 2: Restrict to organization paths
            {
                "condition_key": "aws:ResourceOrgPaths",
                "description": "Restrict S3 operations to resources within your AWS Organization path",
                "expected_value": "${aws:PrincipalOrgPaths}",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:ResourceOrgPaths": "${aws:PrincipalOrgPaths}"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
            # Option 3: Network boundary - Source IP + same account
            {
                "condition_key": "aws:SourceIp",
                "description": "Restrict S3 operations by source IP address and same account",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},\n'
                    '    "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}\n'
                    "  }\n"
                    "}"
                ),
            },
            # Option 4: Network boundary - Source VPC + same account
            {
                "condition_key": "aws:SourceVpc",
                "description": "Restrict S3 operations by source VPC and same account",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:SourceVpc": "vpc-12345678",\n'
                    '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
            # Option 5: Network boundary - VPC Endpoint + same account
            {
                "condition_key": "aws:SourceVpce",
                "description": "Restrict S3 operations by VPC endpoint and same account",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:SourceVpce": "vpce-12345678",\n'
                    '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
            # Option 6: Minimum - at least require same account
            {
                "condition_key": "aws:ResourceAccount",
                "description": "Restrict S3 operations to resources within the same AWS account",
                "expected_value": "${aws:PrincipalAccount}",
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
            },
        ],
    },
}

# IP Restrictions - Source IP requirements
SOURCE_IP_RESTRICTIONS: Final[dict[str, Any]] = {
    "action_patterns": [
        "^ssm:StartSession$",
        "^ssm:Run.*$",
        "^rds-db:Connect$",
    ],
    "severity": "low",
    "suggestion_text": (
        "This action accesses sensitive resources or data. Restrict network access to trusted locations:\n"
        "• Use `aws:SourceIp` to limit to corporate IP ranges (e.g., office networks, VPN endpoints)\n"
        "• Alternative: Use `aws:SourceVpc` or `aws:SourceVpce` for VPC-based restrictions\n"
        "• Consider combining with secure transport requirements\n"
        "• For S3: Ensure account ownership (`aws:ResourceAccount` = `${aws:PrincipalAccount}`)"
    ),
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
                "    },\n"
                '    "Bool": {"aws:SecureTransport": "true"},\n'
                '    "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}\n'
                "  }\n"
                "}"
            ),
        },
    ],
}

# S3 Secure Transport - Never allow insecure transport
S3_SECURE_TRANSPORT: Final[dict[str, Any]] = {
    "actions": ["s3:GetObject", "s3:PutObject"],
    "severity": "critical",
    "suggestion_text": (
        "CRITICAL: This S3 action must enforce encrypted connections. Unencrypted HTTP connections expose data in transit:\n"
        "• Set `aws:SecureTransport` to `true` to enforce HTTPS/TLS\n"
        "• NEVER set `aws:SecureTransport` to `false` (this explicitly allows unencrypted connections)\n"
        "• Combine with other controls (IP restrictions, account boundaries) for defense in depth"
    ),
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
# Condition Requirements
# ============================================================================

CONDITION_REQUIREMENTS: Final[list[dict[str, Any]]] = [
    IAM_PASS_ROLE_REQUIREMENT,
    S3_ORG_BOUNDARY,  # Unified S3 read/write organization boundary enforcement
    SOURCE_IP_RESTRICTIONS,
    S3_SECURE_TRANSPORT,
    PREVENT_PUBLIC_IP,
]
