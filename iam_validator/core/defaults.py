"""
Default configuration for IAM Policy Validator.

This module contains the default configuration that is used when no user
configuration file is provided. User configuration files will override
these defaults.

This configuration is synced with the example-config.yaml file.
"""

# ============================================================================
# SEVERITY LEVELS
# ============================================================================
# The validator uses two types of severity levels:
#
# 1. IAM VALIDITY SEVERITIES (for AWS IAM policy correctness):
#    - error:   Policy violates AWS IAM rules (invalid actions, ARNs, etc.)
#    - warning: Policy may have IAM-related issues but is technically valid
#    - info:    Informational messages about the policy structure
#
# 2. SECURITY SEVERITIES (for security best practices):
#    - critical: Critical security risk (e.g., wildcard action + resource)
#    - high:     High security risk (e.g., missing required conditions)
#    - medium:   Medium security risk (e.g., overly permissive wildcards)
#    - low:      Low security risk (e.g., minor best practice violations)
#
# Use 'error' for policy validity issues, and 'critical/high/medium/low' for
# security best practices. This distinction helps separate "broken policies"
# from "insecure but valid policies".
# ============================================================================

# Default configuration dictionary
DEFAULT_CONFIG = {
    "settings": {
        "fail_fast": False,
        "max_concurrent": 10,
        "enable_builtin_checks": True,
        "parallel_execution": True,
        "cache_enabled": True,
        "cache_directory": ".cache/aws_services",
        "cache_ttl_hours": 24,
        "fail_on_severity": ["error", "critical"],
    },
    "sid_uniqueness_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates that Statement IDs (Sids) are unique within the policy",
    },
    "policy_size_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates that IAM policies don't exceed AWS size limits",
        "policy_type": "managed",
    },
    "action_validation_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates that actions exist in AWS services",
        "disable_wildcard_warnings": True,
    },
    "condition_key_validation_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates condition keys against AWS service definitions",
        "validate_aws_global_keys": True,
    },
    "resource_validation_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates ARN format for resources",
        "arn_pattern": "^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\\-]+:[a-z0-9\\-*]*:[0-9*]*:.+$",
    },
    "security_best_practices_check": {
        "enabled": True,
        "description": "Checks for common security anti-patterns",
        "wildcard_action_check": {
            "enabled": True,
            "severity": "medium",
            "message": "Statement allows all actions (*)",
            "suggestion": "Replace wildcard with specific actions needed for your use case",
            "example": """Replace:
  "Action": ["*"]

With specific actions:
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket"
  ]
""",
        },
        "wildcard_resource_check": {
            "enabled": True,
            "severity": "medium",
            "message": "Statement applies to all resources (*)",
            "suggestion": "Replace wildcard with specific resource ARNs",
            "example": """Replace:
  "Resource": "*"

With specific ARNs:
  "Resource": [
    "arn:aws:service:region:account-id:resource-type/resource-id",
    "arn:aws:service:region:account-id:resource-type/*"
  ]
""",
        },
        "full_wildcard_check": {
            "enabled": True,
            "severity": "critical",
            "message": "Statement allows all actions on all resources - CRITICAL SECURITY RISK",
            "suggestion": "This grants full administrative access. Replace both wildcards with specific actions and resources to follow least-privilege principle",
            "example": """Replace:
  "Action": "*",
  "Resource": "*"

With specific values:
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": [
    "arn:aws:s3:::my-bucket/*"
  ]
""",
        },
        "service_wildcard_check": {
            "enabled": True,
            "severity": "high",
            "allowed_services": ["logs", "cloudwatch"],
        },
        "sensitive_action_check": {
            "enabled": True,
            "severity": "medium",
            "sensitive_actions": [
                "iam:CreateUser",
                "iam:CreateRole",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:CreateAccessKey",
                "iam:DeleteUser",
                "iam:DeleteRole",
                "s3:DeleteBucket",
                "s3:PutBucketPolicy",
                "s3:DeleteBucketPolicy",
                "ec2:TerminateInstances",
                "ec2:DeleteVolume",
                "rds:DeleteDBInstance",
                "lambda:DeleteFunction",
                "eks:DeleteCluster",
            ],
            "sensitive_action_patterns": ["^iam:Delete.*"],
        },
    },
    "action_condition_enforcement_check": {
        "enabled": True,
        "severity": "high",
        "description": "Enforce specific IAM condition requirements (unified: MFA, IP, tags, etc.)",
        "action_condition_requirements": [
            {
                "actions": ["iam:PassRole"],
                "action_patterns": ["^iam:Pas?.*$"],
                "severity": "high",
                "required_conditions": [
                    {
                        "condition_key": "iam:PassedToService",
                        "description": "Specify which AWS services are allowed to use the passed role to prevent privilege escalation",
                        "example": """"Condition": {
  "StringEquals": {
    "iam:PassedToService": [
      "lambda.amazonaws.com",
      "ecs-tasks.amazonaws.com",
      "ec2.amazonaws.com",
      "glue.amazonaws.com",
      "lambda.amazonaws.com"
    ]
  }
}
""",
                    },
                ],
            },
            {
                "actions": [
                    "iam:Create*",
                    "iam:CreateRole",
                    "iam:Put*Policy*",
                    "iam:PutUserPolicy",
                    "iam:PutRolePolicy",
                    "iam:Attach*Policy*",
                    "iam:AttachUserPolicy",
                    "iam:AttachRolePolicy",
                ],
                "action_patterns": ["^iam:Create", "^iam:Put.*Policy", "^iam:Attach.*Policy"],
                "severity": "high",
                "required_conditions": [
                    {
                        "condition_key": "iam:PermissionsBoundary",
                        "description": "Require permissions boundary for sensitive IAM operations to prevent privilege escalation",
                        "expected_value": "arn:aws:iam::*:policy/DeveloperBoundary",
                        "example": """# See: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
"Condition": {
  "StringEquals": {
    "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/XCompanyBoundaries"
  }
}
""",
                    },
                ],
            },
            {
                "actions": ["s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy"],
                "severity": "high",
                "required_conditions": [
                    {
                        "condition_key": "aws:MultiFactorAuthPresent",
                        "description": "Require MFA for S3 destructive operations",
                        "expected_value": True,
                    },
                ],
            },
            {
                "action_patterns": [
                    "^ssm:StartSession$",
                    "^ssm:Run.*$",
                    "^s3:GetObject$",
                    "^rds:.*$",
                ],
                "severity": "medium",
                "required_conditions": [
                    {
                        "condition_key": "aws:SourceIp",
                        "description": "Restrict access to corporate IP ranges",
                        "example": """"Condition": {
  "IpAddress": {
    "aws:SourceIp": [
      "10.0.0.0/8",
      "172.16.0.0/12"
    ]
  }
}
""",
                    },
                ],
            },
            {
                "actions": ["ec2:RunInstances"],
                "required_conditions": {
                    "all_of": [
                        {
                            "condition_key": "aws:ResourceTag/owner",
                            "operator": "StringEquals",
                            "expected_value": "${aws:PrincipalTag/owner}",
                            "description": "Resource owner must match the principal's owner tag",
                        },
                        {
                            "condition_key": "aws:RequestTag/env",
                            "operator": "StringEquals",
                            "expected_value": [
                                "prod",
                                "pre",
                                "dev",
                                "sandbox",
                            ],
                            "description": "Must specify a valid Environment tag",
                        },
                    ],
                },
            },
            {
                "action_patterns": ["^rds:Create.*", "^rds:Modify.*"],
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
            },
        ],
    },
}


def get_default_config() -> dict:
    """
    Get a deep copy of the default configuration.

    Returns:
        A deep copy of the default configuration dictionary
    """
    import copy

    return copy.deepcopy(DEFAULT_CONFIG)
