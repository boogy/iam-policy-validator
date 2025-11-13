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

# S3 Write Operations - Require organization ID
S3_WRITE_ORG_ID: Final[dict[str, Any]] = {
    "actions": ["s3:PutObject"],
    "severity": "medium",
    "required_conditions": {
        "any_of": [
            # Option 1: Use organization-level control with ResourceOrgID
            {
                "all_of": [
                    {
                        "condition_key": "aws:ResourceOrgID",
                        "description": "Restrict S3 write actions to resources within your AWS Organization",
                        "example": (
                            "{\n"
                            '  "Condition": {\n'
                            '    "StringEquals": {\n'
                            '      "aws:ResourceOrgID": "${aws:PrincipalOrgID}",\n'
                            '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                            "    }\n"
                            "  }\n"
                            "}"
                        ),
                    },
                    {
                        "condition_key": "aws:ResourceAccount",
                        "description": "Ensure the S3 resource belongs to the same AWS account as the principal",
                    },
                ]
            },
            # Option 2: Use organization path-based control
            {
                "all_of": [
                    {
                        "condition_key": "aws:ResourceOrgPaths",
                        "description": "Restrict S3 write actions to resources within your AWS Organization path",
                        "example": (
                            "{\n"
                            '  "Condition": {\n'
                            '    "StringEquals": {\n'
                            '      "aws:ResourceOrgPaths": "${aws:PrincipalOrgPaths}",\n'
                            '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                            "    }\n"
                            "  }\n"
                            "}"
                        ),
                    },
                    {
                        "condition_key": "aws:ResourceAccount",
                        "description": "Ensure the S3 resource belongs to the same AWS account as the principal",
                    },
                ]
            },
            # Option 3: Account-only control (less restrictive, but still secure)
            {
                "condition_key": "aws:ResourceAccount",
                "description": "Restrict S3 write actions to resources within the same AWS account",
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
    "severity": "critical",
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
    S3_WRITE_ORG_ID,
    SOURCE_IP_RESTRICTIONS,
    S3_SECURE_TRANSPORT,
    PREVENT_PUBLIC_IP,
]
