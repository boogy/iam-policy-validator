"""
Core constants for IAM Policy Validator.

This module defines constants used across the validator to ensure consistency
and provide a single source of truth for shared values. These constants are
based on AWS service limits and documentation.

References:
- AWS IAM Policy Size Limits: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
- AWS ARN Format: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
"""

# ============================================================================
# ARN Validation
# ============================================================================

# ARN Validation Pattern
# This pattern is specifically designed for validation and allows wildcards (*) in region and account fields
# Unlike the parsing pattern in CompiledPatterns, this is more lenient for validation purposes
# Supports all AWS partitions: aws, aws-cn, aws-us-gov, aws-eusc, aws-iso*
DEFAULT_ARN_VALIDATION_PATTERN = r"^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\-]+:[a-z0-9\-*]*:[0-9*]*:.+$"

# Maximum allowed ARN length to prevent ReDoS attacks
# AWS maximum ARN length is approximately 2048 characters
MAX_ARN_LENGTH = 2048

# ============================================================================
# AWS IAM Policy Size Limits
# ============================================================================
# These limits are enforced by AWS and policies exceeding them will be rejected
# Note: AWS does not count whitespace when calculating policy size

# Managed policy maximum size (characters, excluding whitespace)
MAX_MANAGED_POLICY_SIZE = 6144

# Inline policy maximum size for IAM users (characters, excluding whitespace)
MAX_INLINE_USER_POLICY_SIZE = 2048

# Inline policy maximum size for IAM groups (characters, excluding whitespace)
MAX_INLINE_GROUP_POLICY_SIZE = 5120

# Inline policy maximum size for IAM roles (characters, excluding whitespace)
MAX_INLINE_ROLE_POLICY_SIZE = 10240

# Policy size limits dictionary (for backward compatibility and easy lookup)
AWS_POLICY_SIZE_LIMITS = {
    "managed": MAX_MANAGED_POLICY_SIZE,
    "inline_user": MAX_INLINE_USER_POLICY_SIZE,
    "inline_group": MAX_INLINE_GROUP_POLICY_SIZE,
    "inline_role": MAX_INLINE_ROLE_POLICY_SIZE,
}

# ============================================================================
# Configuration Defaults
# ============================================================================

# Default configuration file names (searched in order)
DEFAULT_CONFIG_FILENAMES = [
    "iam-validator.yaml",
    "iam-validator.yml",
    ".iam-validator.yaml",
    ".iam-validator.yml",
]

# ============================================================================
# GitHub Integration
# ============================================================================

# Bot identifier for GitHub comments and reviews
BOT_IDENTIFIER = "🤖 IAM Policy Validator"

# HTML comment markers for identifying bot-generated content (for cleanup/updates)
SUMMARY_IDENTIFIER = "<!-- iam-policy-validator-summary -->"
REVIEW_IDENTIFIER = "<!-- iam-policy-validator-review -->"
