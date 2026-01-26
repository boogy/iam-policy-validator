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

from iam_validator.core import constants
from iam_validator.core.config.category_suggestions import get_category_suggestions
from iam_validator.core.config.condition_requirements import CONDITION_REQUIREMENTS
from iam_validator.core.config.principal_requirements import (
    get_default_principal_requirements,
)
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
        "cache_ttl_hours": constants.DEFAULT_CACHE_TTL_HOURS,
        # Severity levels that cause validation to fail
        # IAM Validity: error, warning, info
        # Security: critical, high, medium, low
        "fail_on_severity": list(constants.HIGH_SEVERITY_LEVELS),
        # GitHub PR label mapping based on severity findings
        # When issues with these severities are found, apply the corresponding labels
        # If no issues with these severities exist, remove the labels if present
        # Supports both single labels and lists of labels per severity
        # Examples:
        #   Single label per severity: {"error": "iam-validity-error", "critical": "security-critical"}
        #   Multiple labels per severity: {"error": ["iam-error", "needs-fix"], "critical": ["security-critical", "needs-review"]}
        #   Mixed: {"error": "iam-validity-error", "critical": ["security-critical", "needs-review"]}
        # Default: {} (disabled)
        "severity_labels": {},
        # CODEOWNERS-based finding ignore settings
        # Allows CODEOWNERS to ignore validation findings by replying "ignore" to PR comments
        # Ignored findings won't cause the action to fail and won't be posted as comments
        "ignore_settings": {
            # Enable/disable the CODEOWNERS ignore feature
            "enabled": True,
            # Fallback list of users who can ignore findings when no CODEOWNERS file exists
            # If empty and no CODEOWNERS, all ignore requests are denied (fail secure)
            # Example: ["security-team-lead", "platform-admin"]
            "allowed_users": [],
            # Whether to post visible replies when ignore requests are denied
            # When False (default), denials are only logged
            # When True, a reply is posted explaining why the ignore was denied
            "post_denial_feedback": False,
        },
        # Organization-specific documentation URL configuration
        # Allows overriding default AWS documentation links with org-specific runbooks
        "documentation": {
            # Base URL for org-specific runbooks (null = use AWS docs)
            # Example: "https://wiki.mycompany.com/security/iam-checks"
            # When set, check documentation URLs will be: {base_url}/{check_id}
            "base_url": None,
            # Include AWS documentation links alongside org docs
            "include_aws_docs": True,
        },
        # Severity filtering - hide specific severity levels from output
        # When set, issues with these severities will be filtered out globally
        # Can be overridden per-check using check-level hide_severities
        # Valid values: "error", "warning", "info", "critical", "high", "medium", "low"
        # Example: ["low", "info"] - hide low and info severity findings
        "hide_severities": None,
    },
    # ========================================================================
    # AWS IAM Validation Checks (17 checks total)
    # These validate that policies conform to AWS IAM requirements
    # ========================================================================
    # ========================================================================
    # 1. SID UNIQUENESS
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
    # ========================================================================
    # 2. POLICY SIZE
    # ========================================================================
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
    # ========================================================================
    # 3. ACTION VALIDATION
    # ========================================================================
    # Validate IAM actions against AWS service definitions
    # Uses AWS Service Authorization Reference to validate action names
    # Catches typos like "s3:GetObjekt" or non-existent actions
    "action_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that actions exist in AWS services",
    },
    # ========================================================================
    # 4. CONDITION KEY VALIDATION
    # ========================================================================
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
        "warn_on_global_condition_keys": False,
    },
    # ========================================================================
    # 5. CONDITION TYPE MISMATCH
    # ========================================================================
    # Validate condition type matching
    # Ensures condition operators match the expected types for condition keys
    # Examples:
    #   ✅ StringEquals with string condition key
    #   ❌ NumericEquals with string condition key (type mismatch)
    #   ✅ DateGreaterThan with date condition key
    #   ❌ StringLike with date condition key (type mismatch)
    "condition_type_mismatch": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that condition operators match the expected types for condition keys",
    },
    # ========================================================================
    # 6. SET OPERATOR VALIDATION
    # ========================================================================
    # Validate set operator usage (ForAllValues/ForAnyValue)
    # Ensures set operators are only used with multi-value condition keys
    # Using them with single-value keys can cause unexpected behavior
    "set_operator_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that set operators are used with multi-value condition keys",
    },
    # ========================================================================
    # 7. MFA CONDITION ANTIPATTERN
    # ========================================================================
    # Detect MFA condition anti-patterns
    # Identifies dangerous MFA-related patterns that may not enforce MFA as intended:
    #  1. Bool with aws:MultiFactorAuthPresent = false (key may not exist)
    #  2. Null with aws:MultiFactorAuthPresent = false (only checks existence)
    "mfa_condition_antipattern": {
        "enabled": True,
        "severity": "warning",  # Security concern, not an IAM validity error
        "description": "Detects dangerous MFA-related condition patterns",
    },
    # ========================================================================
    # 8. RESOURCE VALIDATION
    # ========================================================================
    # Validate resource ARN formats
    # Ensures ARNs follow the correct format:
    #   arn:partition:service:region:account-id:resource-type/resource-id
    # Pattern allows wildcards (*) in region and account fields
    "resource_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates ARN format for resources",
        "arn_pattern": constants.DEFAULT_ARN_VALIDATION_PATTERN,
    },
    # ========================================================================
    # 9. PRINCIPAL VALIDATION
    # ========================================================================
    # Validates Principal elements in resource-based policies
    # Applies to: S3 buckets, SNS topics, SQS queues, Lambda functions, etc.
    # Only runs when: --policy-type RESOURCE_POLICY
    #
    # Control mechanisms:
    #   1. block_wildcard_principal - Simple toggle for wildcard principal handling
    #   2. blocked_principals - Block specific principals (deny list)
    #   3. allowed_principals - Allow only specific principals (whitelist mode)
    #   4. principal_condition_requirements - Require conditions for principals
    #   5. allowed_service_principals - Always allow AWS service principals
    #   6. block_service_principal_wildcard - Block {"Service": "*"} patterns
    "principal_validation": {
        "enabled": True,
        "severity": "high",  # Security issue, not IAM validity error
        "description": "Validates Principal elements in resource policies for security best practices",
        # block_wildcard_principal: Strict mode toggle for Principal: "*"
        #   false (default): Allow wildcard principal but require conditions
        #   true: Block wildcard principal entirely - strictest option
        # When false, principal_condition_requirements for "*" are enforced,
        # allowing patterns like S3 bucket policies with aws:SourceArn conditions.
        "block_wildcard_principal": False,
        # blocked_principals: Deny list - additional principals to block
        # Note: When block_wildcard_principal is true, "*" is automatically blocked.
        "blocked_principals": [],
        # allowed_principals: Whitelist mode - when set, ONLY these are allowed
        # Default: [] allows all (except blocked)
        "allowed_principals": [],
        # principal_condition_requirements: Require conditions for specific principals
        # Supports all_of/any_of/none_of logic like action_condition_enforcement
        # Default: 2 enabled (public_access, prevent_insecure_transport)
        # See: iam_validator/core/config/principal_requirements.py
        "principal_condition_requirements": get_default_principal_requirements(),
        # allowed_service_principals: AWS service principals (*.amazonaws.com)
        # Default: ["aws:*"] allows ALL AWS service principals
        # Note: "aws:*" is different from "*" (public access)
        "allowed_service_principals": ["aws:*"],
        # block_service_principal_wildcard: Block {"Service": "*"} in Principal
        # This pattern allows ANY AWS service to access the resource, which is
        # extremely permissive. Without source verification conditions like
        # aws:SourceArn or aws:SourceAccount, this creates a security risk.
        # Default: True (always block this dangerous pattern)
        "block_service_principal_wildcard": True,
    },
    # ========================================================================
    # 10. TRUST POLICY VALIDATION
    # ========================================================================
    # Validate trust policies (role assumption policies) for security best practices
    # Ensures assume role actions have appropriate principals and conditions
    #
    # Key validations:
    #   - Action-Principal type matching (e.g., AssumeRoleWithSAML needs Federated)
    #   - Provider ARN format validation (SAML vs OIDC provider patterns)
    #   - Required conditions per assume method
    #
    # Complements principal_validation check (which validates principal allowlists/blocklists)
    # This check focuses on action-principal coupling specific to trust policies
    #
    # Auto-detection: Only runs on statements with assume role actions
    "trust_policy_validation": {
        "enabled": True,  # Enabled by default (auto-detects trust policies)
        "severity": "high",  # Security issue
        "description": "Validates trust policies for role assumption security and action-principal coupling",
        # validation_rules: Custom rules override defaults
        # Default rules validate:
        #   - sts:AssumeRole → AWS or Service principals
        #   - sts:AssumeRoleWithSAML → Federated (SAML provider) with SAML:aud
        #   - sts:AssumeRoleWithWebIdentity → Federated (OIDC provider)
        # Example custom rules:
        # "validation_rules": {
        #     "sts:AssumeRole": {
        #         "allowed_principal_types": ["AWS"],  # Only AWS, not Service
        #         "required_conditions": ["sts:ExternalId"],  # Always require ExternalId
        #     }
        # }
    },
    # ========================================================================
    # 11. POLICY TYPE VALIDATION
    # ========================================================================
    # Validate policy type requirements (new in v1.3.0)
    # Ensures policies conform to the declared type (IDENTITY vs RESOURCE_POLICY)
    # Also enforces RCP (Resource Control Policy) specific requirements
    # RCP validation includes:
    #  - Must have Effect: Deny (RCPs are deny-only)
    #  - Must target specific resource types (no wildcards)
    #  - Principal must be "*" (applies to all)
    "policy_type_validation": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates policies match declared type and enforces RCP requirements",
    },
    # ========================================================================
    # 12. ACTION-RESOURCE MATCHING
    # ========================================================================
    # Validate action-resource matching
    # Ensures resources match the required resource types for actions
    # Handles both:
    #   1. Account-level actions that require Resource: "*" (e.g., iam:ListUsers)
    #   2. Resource-specific actions with correct ARN types (e.g., s3:GetObject)
    # Inspired by Parliament's RESOURCE_MISMATCH check
    # Examples:
    #   ✅ iam:ListUsers with Resource: "*"
    #   ❌ iam:ListUsers with arn:aws:iam::123:user/foo (account-level action)
    #   ✅ s3:GetObject with arn:aws:s3:::bucket/*
    #   ❌ s3:GetObject with arn:aws:s3:::bucket (missing /*)
    #   ✅ s3:ListBucket with arn:aws:s3:::bucket
    #   ❌ s3:ListBucket with arn:aws:s3:::bucket/* (should be bucket, not object)
    "action_resource_matching": {
        "enabled": True,
        "severity": "error",  # IAM validity error
        "description": "Validates that resource ARNs match the required resource types for actions (including account-level actions)",
    },
    # ========================================================================
    # Security Best Practices Checks (6 checks)
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
    # ========================================================================
    # 13. WILDCARD ACTION
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
    # ========================================================================
    # 14. WILDCARD RESOURCE
    # ========================================================================
    # Check for wildcard resources (Resource: "*")
    # Flags statements that apply to all resources
    # Exception: Allowed if ALL actions are in allowed_wildcards list
    #
    # DUAL MATCHING STRATEGY:
    # The check uses two complementary matching strategies for maximum flexibility:
    #
    # 1. LITERAL MATCH (Fast Path - no AWS API calls):
    #    Policy actions match config patterns exactly as strings
    #    Example: Policy "iam:Get*" matches config "iam:Get*" → PASS
    #
    # 2. EXPANDED MATCH (Comprehensive Path - uses AWS API):
    #    Both policy actions and config patterns expand to actual AWS actions
    #    Example: Policy "iam:GetUser" matches config "iam:Get*" (expanded) → PASS
    #
    # SUPPORTED SCENARIOS:
    #   Policy Action         Config Pattern        Match Type   Result
    #   iam:Get*              iam:Get*              Literal      ✅ Pass
    #   iam:GetUser           iam:Get*              Expanded     ✅ Pass
    #   iam:Get*, iam:List*   iam:Get*, iam:List*   Literal      ✅ Pass
    #   iam:Get*, iam:GetUser iam:Get*              Literal      ✅ Pass
    #   iam:Delete*           iam:Get*              None         ❌ Fail
    #
    # PERFORMANCE TIP: Literal matching is faster (no AWS API expansion)
    "wildcard_resource": {
        "enabled": True,
        "severity": "medium",  # Security issue
        "description": "Checks for wildcard resources (*)",
        # Allowed wildcard patterns for actions that can be used with Resource: "*"
        # Supports BOTH literal matching and pattern expansion via AWS API
        #
        # Default: 25 read-only patterns (Describe*, List*, Get*)
        # See: iam_validator/core/config/wildcards.py
        #
        # Examples:
        #   ["ec2:Describe*"]  # Matches: ec2:Describe* (literal) OR ec2:DescribeInstances (expanded)
        #   ["iam:GetUser"]    # Matches: iam:GetUser only
        #   ["s3:List*"]       # Matches: s3:List* (literal) OR s3:ListBucket (expanded)
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
    # ========================================================================
    # 15. FULL WILDCARD (CRITICAL)
    # ========================================================================
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
            '  "Action": ["s3:GetObject", "s3:PutObject"],\n'
            '  "Resource": ["arn:aws:s3:::my-bucket/*"]\n'
        ),
    },
    # ========================================================================
    # 16. SERVICE WILDCARD
    # ========================================================================
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
        "message": "Service wildcard '{action}' grants all permissions for the {service} service",
        "suggestion": (
            "Replace '{action}' with specific actions needed for your use case to follow least-privilege principle.\n"
            "Find valid {service} actions: https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"
        ),
        "example": (
            "Replace:\n"
            '  "Action": ["{action}"]\n'
            "\n"
            "With specific actions:\n"
            '  "Action": ["{service}:Describe*", "{service}:List*"]\n'
        ),
    },
    # ========================================================================
    # 17. SENSITIVE ACTION
    # ========================================================================
    # Check for sensitive actions without IAM conditions
    # Sensitive actions: IAM changes, secrets access, destructive operations
    # Default: 490 actions across 4 security risk categories
    #
    # Categories (with action counts):
    #   - credential_exposure (46):  Actions exposing credentials, secrets, or tokens
    #   - data_access (109):         Actions retrieving sensitive data
    #   - priv_esc (27):             Actions enabling privilege escalation
    #   - resource_exposure (321):   Actions modifying resource policies/permissions
    #
    # Scans at BOTH statement-level AND policy-level for security patterns
    # See: iam_validator/core/config/sensitive_actions.py
    # Source: https://github.com/primeharbor/sensitive_iam_actions
    #
    # Python API:
    #   from iam_validator.core.config.sensitive_actions import get_sensitive_actions
    #   # Get all sensitive actions (default)
    #   all_actions = get_sensitive_actions()
    #   # Get only specific categories
    #   priv_esc_only = get_sensitive_actions(['priv_esc'])
    #   # Get multiple categories
    #   critical = get_sensitive_actions(['credential_exposure', 'priv_esc'])
    #
    # Avoiding Duplicate Alerts:
    #   If you configure specific actions in action_condition_enforcement,
    #   use ignore_patterns to prevent duplicate alerts from sensitive_action:
    #
    #   ignore_patterns:
    #     - action_matches: "^(iam:PassRole|iam:CreateUser|s3:PutObject)$"
    #
    # Template placeholders supported:
    # - message_single uses {action}: Single action name (e.g., "iam:CreateRole")
    # - message_multiple uses {actions}: Comma-separated list (e.g., "iam:CreateRole', 'iam:PutUserPolicy")
    # - suggestion and example support both {action} and {actions}
    "sensitive_action": {
        "enabled": True,
        "severity": "medium",  # Security issue (can be overridden per-category)
        "description": "Checks for sensitive actions without conditions",
        # Categories to check (default: all categories enabled)
        # Set to specific categories to limit scope:
        #   categories: ['credential_exposure', 'priv_esc']  # Only check critical actions
        #   categories: ['data_access']  # Only check data access actions
        # Set to empty list to disable: categories: []
        "categories": [
            "credential_exposure",  # Critical: Credential/secret exposure (46 actions)
            "data_access",  # High: Sensitive data retrieval (109 actions)
            "priv_esc",  # Critical: Privilege escalation (27 actions)
            "resource_exposure",  # High: Resource policy modifications (321 actions)
        ],
        # Per-category severity overrides (optional)
        # If not specified, uses the default severity above
        "category_severities": {
            "credential_exposure": "critical",  # Override: credential exposure is critical
            "priv_esc": "critical",  # Override: privilege escalation is critical
            "data_access": "high",  # Override: data access is high
            "resource_exposure": "high",  # Override: resource exposure is high
        },
        # Category-specific ABAC suggestions and examples
        # These provide tailored guidance for each security risk category
        # See: iam_validator/core/config/category_suggestions.py
        # Can be overridden to customize suggestions per category
        "category_suggestions": get_category_suggestions(),
        # Custom message templates (support {action} and {actions} placeholders)
        "message_single": "Sensitive action '{action}' should have conditions to limit when it can be used",
        "message_multiple": "Sensitive actions '{actions}' should have conditions to limit when they can be used",
        # Ignore patterns to prevent duplicate alerts
        # Useful when you have specific condition enforcement for certain actions
        # Example: Ignore iam:PassRole since it's checked by action_condition_enforcement
        "ignore_patterns": [
            {"action": "^iam:PassRole$"},
        ],
        # Cross-statement privilege escalation patterns (policy-wide detection)
        # These patterns detect dangerous action combinations across ANY statements in the policy
        # Uses all_of logic: ALL actions must exist somewhere in the policy
        "sensitive_actions": [
            # User privilege escalation: Create user + attach admin policy
            {
                "all_of": ["iam:CreateUser", "iam:AttachUserPolicy"],
                "severity": "critical",
                "message": "Policy grants {actions} across statements - enables privilege escalation. {statements}",
                "suggestion": (
                    "This combination allows an attacker to:\n"
                    "1. Create a new IAM user\n"
                    "2. Attach AdministratorAccess policy to that user\n"
                    "3. Escalate to full account access\n\n"
                    "Mitigation options:\n"
                    "• Remove both of these permissions\n"
                    "• Add strict IAM conditions (IP restrictions, tags, force a specific policy with `iam:PolicyARN` condition)\n"
                ),
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "iam:PolicyARN": "arn:aws:iam::*:policy/ReadOnlyAccess"\n'
                    "    },\n"
                    '    "IpAddress": {\n'
                    '      "aws:SourceIp": ["10.0.0.0/8"]\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                ),
            },
            # Role privilege escalation: Create role + attach admin policy
            {
                "all_of": ["iam:CreateRole", "iam:AttachRolePolicy"],
                "severity": "high",
                "message": "Policy grants {actions} across statements - enables privilege escalation. {statements}",
                "suggestion": (
                    "This combination allows creating privileged roles with admin policies.\n\n"
                    "Mitigation options:\n"
                    "• Remove both of these permissions\n"
                    "• Add strict IAM conditions with a Permissions Boundary and ABAC Tagging, force a specific policy with `iam:PolicyARN` condition\n"
                ),
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "iam:PermissionsBoundary": "arn:aws:iam::*:policy/MaxPermissions"\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                    "OR\n"
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "iam:PolicyARN": "arn:aws:iam::*:policy/MaxPermissions"\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                ),
            },
            # Lambda backdoor: Create/update function + invoke
            {
                "all_of": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                "severity": "medium",
                "message": "Policy grants {actions} across statements - enables code execution. {statements}",
                "suggestion": (
                    "This combination allows an attacker to:\n"
                    "1. Create a Lambda function with malicious code\n"
                    "2. Execute the function to perform operations with the Lambda's role\n\n"
                    "Mitigation options:\n"
                    "• Restrict Lambda creation to specific function names/paths\n"
                    "• Require resource tags on functions and tag-based invocation controls\n"
                    "• Require MFA for Lambda function creation\n"
                    "• Use separate policies for creation vs invocation"
                ),
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:PrincipalTag/team": "${aws:ResourceTag/team}"\n'
                    "    },\n"
                    '    "SourceIp": {\n'
                    '      "aws:SourceIp": ["10.0.0.0/8"]\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                ),
            },
            # Lambda code modification backdoor
            {
                "all_of": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                "severity": "medium",
                "message": "Policy grants {actions} across statements - enables code injection. {statements}",
                "suggestion": (
                    "This combination allows modifying existing Lambda functions and executing them.\n\n"
                    "Mitigation options:\n"
                    "• Use resource-based policies to restrict which functions can be modified\n"
                    "• Require MFA for code updates\n"
                    "• Use separate policies for code updates vs invocation\n"
                    "• Implement code signing for Lambda functions"
                ),
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "aws:ResourceAccount": "${aws:PrincipalAccount}"\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                ),
            },
            # EC2 instance privilege escalation
            {
                "all_of": ["ec2:RunInstances", "iam:PassRole"],
                "severity": "high",
                "message": "Policy grants {actions} across statements - enables privilege escalation via instance profile. {statements}",
                "suggestion": (
                    "This combination allows launching EC2 instances with privileged roles.\n\n"
                    "Mitigation options:\n"
                    "• Add iam:PassedToService condition requiring ec2.amazonaws.com\n"
                    "• Restrict instance creation to specific AMIs or instance types\n"
                    "• Limit PassRole to specific low-privilege roles\n"
                    "• Require tagging and ABAC controls"
                ),
                "example": (
                    "{\n"
                    '  "Condition": {\n'
                    '    "StringEquals": {\n'
                    '      "iam:PassedToService": "ec2.amazonaws.com"\n'
                    "    },\n"
                    '    "ArnLike": {\n'
                    '      "iam:AssociatedResourceArn": "arn:aws:ec2:*:*:instance/*"\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                ),
            },
        ],
    },
    # ========================================================================
    # 18. ACTION CONDITION ENFORCEMENT
    # ========================================================================
    # Enforce specific IAM condition requirements for actions
    # Examples: iam:PassRole must specify iam:PassedToService,
    #           S3 writes must require MFA, EC2 launches must use tags
    #
    # Default: 5 enabled requirements
    # Available requirements:
    #   Default (enabled):
    #     - iam_pass_role: Requires iam:PassedToService
    #     - s3_org_boundary: Prevents S3 data exfiltration (reads + writes)
    #     - source_ip_restrictions: Restricts to corporate IPs
    #     - s3_secure_transport: Prevents insecure transport
    #     - prevent_public_ip: Prevents 0.0.0.0/0 IP ranges
    #
    # See: iam_validator/core/config/condition_requirements.py
    "action_condition_enforcement": {
        "enabled": True,
        "severity": "high",  # Default severity (can be overridden per-requirement)
        "description": "Enforces conditions (MFA, IP, tags, etc.) for specific actions at both statement and policy level",
        # CRITICAL: This key is used by sensitive_action check for filtering
        # It must be named "requirements" (not "action_condition_requirements")
        # to enable automatic deduplication of warnings
        "requirements": __import__("copy").deepcopy(CONDITION_REQUIREMENTS),
        # POLICY-LEVEL: Scan entire policy and enforce conditions across ALL matching statements
        # Example: "If ANY statement grants iam:CreateUser, then ALL such statements must have MFA"
        # Default: Empty list (opt-in feature)
        # To enable, add requirements like:
        #   policy_level_requirements:
        #     - actions:
        #         any_of: ["iam:CreateUser", "iam:AttachUserPolicy"]
        #       scope: "policy"
        #       required_conditions:
        #         - condition_key: "aws:MultiFactorAuthPresent"
        #           expected_value: true
        #       severity: "critical"
        "policy_level_requirements": [],
    },
}


def get_default_config() -> dict:
    """
    Get a deep copy of the default configuration.

    Returns:
        A deep copy of the default configuration dictionary
    """
    import copy  # pylint: disable=import-outside-toplevel

    return copy.deepcopy(DEFAULT_CONFIG)
