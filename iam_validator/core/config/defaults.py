"""
Default configuration for IAM Policy Validator.

This module contains the default configuration that is used when no user
configuration file is provided. User configuration files will override
these defaults.

This configuration uses Python-native data structures (imported from
iam_validator.core.config) for optimal performance and PyPI packaging.

Benefits of code-first approach:
- Zero parsing overhead (no YAML/JSON parsing)
- Compiled to .pyc for faster imports
- Better IDE support and type hints
- No data files to manage in PyPI package
- 5-10x faster than YAML parsing
"""

from iam_validator.core.config.condition_requirements import get_default_requirements
from iam_validator.core.config.principal_requirements import (
    get_default_principal_requirements,
)
from iam_validator.core.config.service_principals import DEFAULT_SERVICE_PRINCIPALS
from iam_validator.core.config.wildcards import (
    DEFAULT_ALLOWED_WILDCARDS,
    DEFAULT_SERVICE_WILDCARDS,
)

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

# ============================================================================
# DEFAULT CONFIGURATION
# ============================================================================
DEFAULT_CONFIG = {
    # ========================================================================
    # Global Settings
    # ========================================================================
    "settings": {
        # Stop validation on first error
        "fail_fast": False,
        # Maximum number of concurrent policy validations
        "max_concurrent": 10,
        # Enable/disable ALL built-in checks (set to False when using AWS Access Analyzer)
        "enable_builtin_checks": True,
        # Enable parallel execution of checks for better performance
        "parallel_execution": True,
        # Path to directory containing pre-downloaded AWS service definitions
        # Set to a directory path to use offline validation, or None to use AWS API
        "aws_services_dir": None,
        # Cache AWS service definitions locally (persists between runs)
        "cache_enabled": True,
        # Cache TTL in hours (default: 168 = 7 days)
        "cache_ttl_hours": 168,
        # Severity levels that cause validation to fail
        # IAM Validity: error, warning, info
        # Security: critical, high, medium, low
        "fail_on_severity": ["error", "critical", "high"],
    },
    # ========================================================================
    # AWS IAM Validation Checks
    # These validate that policies conform to AWS IAM requirements
    # ========================================================================
    # Validate Statement ID (Sid) uniqueness as per AWS IAM requirements
    # AWS requires:
    # - Sids must be unique within the policy (duplicate_sid error)
    # - Sids must contain only alphanumeric characters, hyphens, and underscores
    # - No spaces or special characters allowed
    "sid_uniqueness": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that Statement IDs (Sids) are unique and follow AWS naming requirements",
    },
    # Validate policy size against AWS limits
    # Policy type determines which AWS limit to enforce:
    #   - managed: 6144 characters (excluding whitespace)
    #   - inline_user: 2048 characters
    #   - inline_group: 5120 characters
    #   - inline_role: 10240 characters
    "policy_size": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that IAM policies don't exceed AWS size limits",
        "policy_type": "managed",  # Change based on your policy type
    },
    # Validate IAM actions against AWS service definitions
    # Uses AWS Service Authorization Reference to validate action names
    # Catches typos like "s3:GetObjekt" or non-existent actions
    "action_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that actions exist in AWS services",
    },
    # Validate condition keys for actions against AWS service definitions
    # Ensures condition keys are valid for the specified actions
    # Examples:
    #   ✅ s3:GetObject with s3:prefix condition
    #   ❌ s3:GetObject with ec2:InstanceType condition (invalid)
    "condition_key_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates condition keys against AWS service definitions for specified actions",
        # Validate aws:* global condition keys against known list
        "validate_aws_global_keys": True,
        # Warn when global condition keys (aws:*) are used with actions that have action-specific keys
        # While global condition keys can be used across all AWS services, they may not be available
        # in every request context. This warning helps ensure proper validation.
        # Set to False to disable warnings for global condition keys
        "warn_on_global_condition_keys": True,
    },
    # Validate resource ARN formats
    # Ensures ARNs follow the correct format:
    #   arn:partition:service:region:account-id:resource-type/resource-id
    # Pattern allows wildcards (*) in region and account fields
    "resource_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates ARN format for resources",
        "arn_pattern": "^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\\-]+:[a-z0-9\\-*]*:[0-9*]*:.+$",
    },
    # ========================================================================
    # Principal Validation (Resource Policies)
    # ========================================================================
    # Validates Principal elements in resource-based policies
    # (S3 buckets, SNS topics, SQS queues, etc.)
    # Only runs when --policy-type RESOURCE_POLICY is specified
    #
    # See: iam_validator/core/config/service_principals.py for defaults
    "principal_validation": {
        "enabled": True,
        "severity": "high",  # Security issue, not IAM validity error
        "description": "Validates Principal elements in resource policies for security best practices",
        # blocked_principals: Principals that should NEVER be allowed (deny list)
        # Default: ["*"] blocks public access to everyone
        # Examples:
        #   ["*"]  - Block public access
        #   ["*", "arn:aws:iam::*:root"]  - Block public + all AWS accounts
        "blocked_principals": ["*"],
        # allowed_principals: When set, ONLY these principals are allowed (whitelist mode)
        # Leave empty to allow all except blocked principals
        # Examples:
        #   []  - Allow all (except blocked)
        #   ["arn:aws:iam::123456789012:root"]  - Only allow specific account
        #   ["arn:aws:iam::*:role/OrgAccessRole"]  - Allow specific role in any account
        "allowed_principals": [],
        # require_conditions_for: Principals that MUST have specific IAM conditions
        # Format: {principal_pattern: [required_condition_keys]}
        # Default: Public access (*) must specify source to limit scope
        # Examples:
        #   "*": ["aws:SourceArn"]  - Public access must specify source ARN
        #   "arn:aws:iam::*:root": ["aws:PrincipalOrgID"]  - Cross-account must be from org
        "require_conditions_for": {
            "*": [
                "aws:SourceArn",
                "aws:SourceAccount",
                "aws:SourceVpce",
                "aws:SourceIp",
                "aws:SourceOrgID",
                "aws:SourceOrgPaths",
            ],
        },
        # principal_condition_requirements: Advanced condition requirements for principals
        # Similar to action_condition_enforcement but for principals
        # Supports all_of/any_of/none_of logic with rich metadata
        # Default: 2 critical requirements enabled (public_access, prevent_insecure_transport)
        # See: iam_validator/core/config/principal_requirements.py
        # To customize requirements, use Python API:
        #   from iam_validator.core.config import get_principal_requirements_by_names
        #   requirements = get_principal_requirements_by_names(['public_access', 'cross_account_org'])
        # To disable: set to empty list []
        "principal_condition_requirements": get_default_principal_requirements(),
        # allowed_service_principals: AWS service principals that are always allowed
        # Default: 16 common AWS services (cloudfront, s3, lambda, logs, etc.)
        # These are typically safe as AWS services need access to resources
        # See: iam_validator/core/config/service_principals.py
        "allowed_service_principals": list(DEFAULT_SERVICE_PRINCIPALS),
    },
    # Validate resource constraints for actions
    # Ensures that actions without required resource types (account-level operations)
    # use Resource: "*" as they cannot target specific resources
    # Example: iam:ListUsers cannot target a specific user, must use "*"
    "action_resource_constraint": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that actions without required resource types use Resource: '*'",
    },
    # ========================================================================
    # Security Best Practices Checks
    # ========================================================================
    # Individual checks for security anti-patterns
    #
    # Configuration Fields Reference:
    # - description: Technical description of what the check does (internal/docs)
    # - message: Error/warning shown to users when issue is detected
    # - suggestion: Guidance on how to fix or mitigate the issue
    # - example: Concrete code example showing before/after or proper usage
    #
    # Field Progression: detect (description) → alert (message) → advise (suggestion) → demonstrate (example)
    #
    # For detailed explanation of these fields and how to customize them,
    # see: docs/configuration.md#customizing-messages
    #
    # See: iam_validator/core/config/wildcards.py for allowed wildcards
    # See: iam_validator/core/config/sensitive_actions.py for sensitive actions
    # ========================================================================
    # Check for wildcard actions (Action: "*")
    # Flags statements that allow all actions
    "wildcard_action": {
        "enabled": True,
        "severity": "medium",  # Security issue
        "description": "Checks for wildcard actions (*)",
        "message": "Statement allows all actions (*)",
        "suggestion": "Replace wildcard with specific actions needed for your use case",
        "example": (
            "Replace:\n"
            '  "Action": ["*"]\n'
            "\n"
            "With specific actions:\n"
            '  "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]\n'
        ),
    },
    # Check for wildcard resources (Resource: "*")
    # Flags statements that apply to all resources
    # Exception: Allowed if ALL actions are in allowed_wildcards list
    "wildcard_resource": {
        "enabled": True,
        "severity": "medium",  # Security issue
        "description": "Checks for wildcard resources (*)",
        # Allowed wildcard patterns for actions that can be used with Resource: "*"
        # Default: 25 read-only patterns (Describe*, List*, Get*)
        # See: iam_validator/core/config/wildcards.py
        "allowed_wildcards": list(DEFAULT_ALLOWED_WILDCARDS),
        "message": "Statement applies to all resources (*)",
        "suggestion": "Replace wildcard with specific resource ARNs",
        "example": (
            "Replace:\n"
            '  "Resource": "*"\n'
            "\n"
            "With specific ARNs:\n"
            '  "Resource": [\n'
            '    "arn:aws:service:region:account-id:resource-type/resource-id",\n'
            '    "arn:aws:service:region:account-id:resource-type/*"\n'
            "  ]\n"
        ),
    },
    # Check for BOTH Action: "*" AND Resource: "*" (CRITICAL)
    # This grants full administrative access (AdministratorAccess equivalent)
    "full_wildcard": {
        "enabled": True,
        "severity": "critical",  # CRITICAL security risk
        "description": "Checks for both action and resource wildcards together (critical risk)",
        "message": "Statement allows all actions on all resources - CRITICAL SECURITY RISK",
        "suggestion": (
            "This grants full administrative access. Replace both wildcards with specific actions "
            "and resources to follow least-privilege principle"
        ),
        "example": (
            "Replace:\n"
            '  "Action": "*",\n'
            '  "Resource": "*"\n'
            "\n"
            "With specific values:\n"
            '  "Action": [\n'
            '    "s3:GetObject",\n'
            '    "s3:PutObject"\n'
            "  ],\n"
            '  "Resource": [\n'
            '    "arn:aws:s3:::my-bucket/*"\n'
            "  ]\n"
        ),
    },
    # Check for service-level wildcards (e.g., "iam:*", "s3:*", "ec2:*")
    # These grant ALL permissions for a service (often too permissive)
    # Exception: Some services like logs, cloudwatch are typically safe
    #
    # Template placeholders supported in message/suggestion/example:
    # - {action}: The wildcard action found (e.g., "s3:*")
    # - {service}: The service name (e.g., "s3")
    "service_wildcard": {
        "enabled": True,
        "severity": "high",  # Security issue
        "description": "Checks for service-level wildcards (e.g., 'iam:*', 's3:*')",
        # Services that are allowed to use wildcards (default: logs, cloudwatch, xray)
        # See: iam_validator/core/config/wildcards.py
        "allowed_services": list(DEFAULT_SERVICE_WILDCARDS),
    },
    # Check for sensitive actions without IAM conditions
    # Sensitive actions: IAM changes, secrets access, destructive operations
    # Default: 79 actions across 8 categories
    # Categories: iam_identity, secrets_credentials, compute_containers,
    #             database_storage, s3_backup, network_security,
    #             access_logging, account_organization
    #
    # Scans at BOTH statement-level AND policy-level for security patterns
    # See: iam_validator/core/config/sensitive_actions.py
    # Python API: get_actions_by_categories(['iam_identity', 'secrets_credentials'])
    #
    # Template placeholders supported:
    # - message_single uses {action}: Single action name (e.g., "iam:CreateRole")
    # - message_multiple uses {actions}: Comma-separated list (e.g., "iam:CreateRole', 'iam:PutUserPolicy")
    # - suggestion and example support both {action} and {actions}
    "sensitive_action": {
        "enabled": True,
        "severity": "medium",  # Security issue
        "description": "Checks for sensitive actions without conditions",
        # Custom message templates (support {action} and {actions} placeholders)
        "message_single": "Sensitive action '{action}' should have conditions to limit when it can be used",
        "message_multiple": "Sensitive actions '{actions}' should have conditions to limit when they can be used",
        "suggestion": (
            "Add IAM conditions to limit when this action can be used.\n"
            "Consider: ABAC (ResourceTag OR RequestTag matching ${aws:PrincipalTag}), "
            "IP restrictions (aws:SourceIp), MFA requirements (aws:MultiFactorAuthPresent), "
            "or time-based restrictions (aws:CurrentTime)\n"
        ),
        "example": (
            '"Condition": {\n'
            '  "StringEquals": {\n'
            '    "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"\n'
            "  }\n"
            "}\n"
        ),
    },
    # ========================================================================
    # Action Condition Enforcement
    # ========================================================================
    # Enforce specific IAM condition requirements for actions
    # Examples: iam:PassRole must specify iam:PassedToService,
    #           S3 writes must require MFA, EC2 launches must use tags
    #
    # Default: 5 enabled requirements out of 13 available
    # Available requirements:
    #   Default (enabled):
    #     - iam_pass_role: Requires iam:PassedToService
    #     - iam_permissions_boundary: Requires permissions boundary
    #     - s3_org_id: Requires organization ID for S3 writes
    #     - source_ip_restrictions: Restricts to corporate IPs
    #     - s3_secure_transport: Prevents insecure transport
    #   Optional (disabled by default):
    #     - s3_destructive_mfa: Requires MFA for S3 deletes
    #     - s3_require_https: Requires HTTPS for all S3 operations
    #     - ec2_vpc_restriction: Restricts EC2 to specific VPCs
    #     - ec2_tag_requirements: ABAC tag requirements for EC2
    #     - rds_tag_requirements: Tag requirements for RDS
    #     - s3_bucket_tag_requirements: Tag requirements for S3 buckets
    #     - forbidden_actions: Flags forbidden actions
    #     - prevent_public_ip: Prevents 0.0.0.0/0 IP ranges
    #
    # See: iam_validator/core/config/condition_requirements.py
    # Python API:
    #   from iam_validator.core.config import get_requirements_by_names
    #   requirements = get_requirements_by_names(['iam_pass_role', 's3_destructive_mfa'])
    "action_condition_enforcement": {
        "enabled": True,
        "severity": "high",  # Default severity (can be overridden per-requirement)
        "description": "Enforces conditions (MFA, IP, tags, etc.) for specific actions (supports all_of/any_of)",
        # Load 5 default requirements from Python module
        # Returns a deep copy to prevent mutation of the originals
        "action_condition_requirements": get_default_requirements(),
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
