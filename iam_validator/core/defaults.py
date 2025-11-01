"""
Default configuration for IAM Policy Validator.

This module contains the default configuration that is used when no user
configuration file is provided. User configuration files will override
these defaults.

This configuration is synced with the default-config.yaml file.
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
        "aws_services_dir": None,
        "cache_enabled": True,
        "cache_ttl_hours": 168,
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
    },
    "condition_key_validation_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates condition keys against AWS service definitions for specified actions",
        "validate_aws_global_keys": True,
    },
    "resource_validation_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates ARN format for resources",
        "arn_pattern": "^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\\-]+:[a-z0-9\\-*]*:[0-9*]*:.+$",
    },
    "action_resource_constraint_check": {
        "enabled": True,
        "severity": "error",
        "description": "Validates that actions without required resource types use Resource: '*'",
    },
    "security_best_practices_check": {
        "enabled": True,
        "description": "Checks for common security anti-patterns",
        "allowed_wildcards": [
            "autoscaling:Describe*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            "dynamodb:Describe*",
            "ec2:Describe*",
            "elasticloadbalancing:Describe*",
            "iam:Get*",
            "iam:List*",
            "kms:Describe*",
            "lambda:Get*",
            "lambda:List*",
            "logs:Describe*",
            "logs:Filter*",
            "logs:Get*",
            "rds:Describe*",
            "route53:Get*",
            "route53:List*",
            "s3:Describe*",
            "s3:GetBucket*",
            "s3:GetM*",
            "s3:List*",
            "sqs:Get*",
            "sqs:List*",
            "apigateway:GET",
        ],
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
            "allowed_services": ["logs", "cloudwatch", "xray"],
        },
        "sensitive_action_check": {
            "enabled": True,
            "severity": "medium",
            "message_single": "Sensitive action '{action}' should have conditions to limit when it can be used",
            "message_multiple": "Sensitive actions '{actions}' should have conditions to limit when they can be used",
            "suggestion": "Add IAM conditions to limit when this action can be used. Consider: ABAC (ResourceTag OR RequestTag must match PrincipalTag), IP restrictions (aws:SourceIp), MFA requirements (aws:MultiFactorAuthPresent), or time-based restrictions (aws:CurrentTime)",
            "example": """"Condition": {
  "StringEquals": {
    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"
  }
}
""",
            "sensitive_actions": [
                "iam:AddClientIDToOpenIDConnectProvider",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:CreateAccessKey",
                "iam:CreateOpenIDConnectProvider",
                "iam:CreatePolicyVersion",
                "iam:CreateRole",
                "iam:CreateSAMLProvider",
                "iam:CreateUser",
                "iam:DeleteAccessKey",
                "iam:DeleteLoginProfile",
                "iam:DeleteOpenIDConnectProvider",
                "iam:DeleteRole",
                "iam:DeleteRolePolicy",
                "iam:DeleteSAMLProvider",
                "iam:DeleteUser",
                "iam:DeleteUserPolicy",
                "iam:DetachRolePolicy",
                "iam:DetachUserPolicy",
                "iam:PutRolePolicy",
                "iam:PutUserPolicy",
                "iam:SetDefaultPolicyVersion",
                "iam:UpdateAccessKey",
                "iam:UpdateAssumeRolePolicy",
                "kms:DisableKey",
                "kms:PutKeyPolicy",
                "kms:ScheduleKeyDeletion",
                "secretsmanager:DeleteSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:PutSecretValue",
                "ssm:DeleteParameter",
                "ssm:PutParameter",
                "ec2:DeleteSnapshot",
                "ec2:DeleteVolume",
                "ec2:DeleteVpc",
                "ec2:ModifyInstanceAttribute",
                "ec2:TerminateInstances",
                "ecr:DeleteRepository",
                "ecs:DeleteCluster",
                "ecs:DeleteService",
                "eks:DeleteCluster",
                "lambda:DeleteFunction",
                "lambda:DeleteFunctionConcurrency",
                "lambda:PutFunctionConcurrency",
                "dynamodb:DeleteTable",
                "efs:DeleteFileSystem",
                "elasticache:DeleteCacheCluster",
                "fsx:DeleteFileSystem",
                "rds:DeleteDBCluster",
                "rds:DeleteDBInstance",
                "redshift:DeleteCluster",
                "backup:DeleteBackupVault",
                "glacier:DeleteArchive",
                "s3:DeleteBucket",
                "s3:DeleteBucketPolicy",
                "s3:DeleteObject",
                "s3:PutBucketPolicy",
                "s3:PutLifecycleConfiguration",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup",
                "ec2:DisassociateRouteTable",
                "ec2:RevokeSecurityGroupEgress",
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
                "cloudwatch:DeleteLogGroup",
                "config:DeleteConfigurationRecorder",
                "guardduty:DeleteDetector",
                "account:CloseAccount",
                "account:CreateAccount",
                "organizations:LeaveOrganization",
                "organizations:RemoveAccountFromOrganization",
            ],
        },
    },
    "action_condition_enforcement_check": {
        "enabled": True,
        "severity": "high",
        "description": "Enforce specific IAM condition requirements (unified: MFA, IP, tags, etc.)",
        "action_condition_requirements": [
            {
                "actions": ["iam:PassRole"],
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
                    "iam:CreateRole",
                    "iam:Put*Policy*",
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
                "actions": ["s3:PutObject"],
                "severity": "medium",
                "required_conditions": [
                    {
                        "condition_key": "aws:ResourceOrgId",
                        "description": "Require aws:ResourceOrgId condition for S3 write actions to enforce organization-level access control",
                        "example": """"Condition": {
  "StringEquals": {
    "aws:ResourceOrgId": "${aws:PrincipalOrgID}"
  }
}
""",
                    },
                ],
            },
            {
                "action_patterns": ["^s3:.*"],
                "required_conditions": [
                    {
                        "condition_key": "aws:SecureTransport",
                        "description": "Require HTTPS for all S3 operations",
                        "expected_value": True,
                    },
                ],
            },
            {
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
