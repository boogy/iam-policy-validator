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
# Severity Levels
# ============================================================================
# Severity level groupings for filtering and categorization
# Used across formatters and report generation

# High severity issues that typically fail validation
HIGH_SEVERITY_LEVELS = ("error", "critical", "high")

# Medium severity issues (warnings)
MEDIUM_SEVERITY_LEVELS = ("warning", "medium")

# Low severity issues (informational)
LOW_SEVERITY_LEVELS = ("info", "low")

# Severity configuration with emoji and action guidance for PR comments
SEVERITY_CONFIG = {
    "critical": {"emoji": "🔴", "action": "Block deployment"},
    "high": {"emoji": "🟠", "action": "Fix before merge"},
    "medium": {"emoji": "🟡", "action": "Address soon"},
    "low": {"emoji": "🔵", "action": "Consider fixing"},
    "error": {"emoji": "❌", "action": "Must fix - AWS will reject"},
    "warning": {"emoji": "⚠️", "action": "Review"},
    "info": {"emoji": "ℹ️", "action": "Optional"},
}

# ============================================================================
# GitHub Integration
# ============================================================================

# Bot identifier for GitHub comments and reviews
BOT_IDENTIFIER = "🤖 IAM Policy Validator"

# HTML comment markers for identifying bot-generated content (for cleanup/updates)
SUMMARY_IDENTIFIER = "<!-- iam-policy-validator-summary -->"
REVIEW_IDENTIFIER = "<!-- iam-policy-validator-review -->"
IGNORED_FINDINGS_IDENTIFIER = "<!-- iam-policy-validator-ignored-findings -->"

# GitHub comment size limits
# GitHub's actual limit is 65536 characters, but we use a smaller limit for safety
GITHUB_MAX_COMMENT_LENGTH = 65000  # Maximum single comment length
GITHUB_COMMENT_SPLIT_LIMIT = 60000  # Target size when splitting into multiple parts

# Comment size estimation parameters (used for multi-part comment splitting)
COMMENT_BASE_OVERHEAD_CHARS = 2000  # Base overhead for headers/footers
COMMENT_CHARS_PER_ISSUE_ESTIMATE = 500  # Average characters per issue
COMMENT_CONTINUATION_OVERHEAD_CHARS = 200  # Overhead for continuation markers
FORMATTING_SAFETY_BUFFER = 100  # Safety buffer for formatting calculations

# ============================================================================
# Console Display Settings
# ============================================================================

# Panel width for formatted console output
CONSOLE_PANEL_WIDTH = 100

# Rich console color styles
CONSOLE_HEADER_COLOR = "bright_blue"

# ============================================================================
# Cache and Timeout Settings
# ============================================================================

# Cache TTL (Time To Live) - 7 days
DEFAULT_CACHE_TTL_HOURS = 168  # 7 days in hours
DEFAULT_CACHE_TTL_SECONDS = 604800  # 7 days in seconds (168 * 3600)

# HTTP request timeout in seconds
DEFAULT_HTTP_TIMEOUT_SECONDS = 30.0

# Time conversion constants
SECONDS_PER_HOUR = 3600

# ============================================================================
# Policy Type Restrictions
# ============================================================================

# AWS services that support Resource Control Policies (RCP)
# These services can have wildcard actions in RCP policy statements
# Reference: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
RCP_SUPPORTED_SERVICES = frozenset(
    {
        "s3",
        "sts",
        "sqs",
        "secretsmanager",
        "kms",
    }
)

# ============================================================================
# AWS Documentation URLs
# ============================================================================

# AWS Service Authorization Reference (for finding valid actions, resources, and condition keys)
AWS_SERVICE_AUTH_REF_URL = "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"

# ============================================================================
# AWS Tag Constraints
# ============================================================================
# Reference: https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html

# --- Tag Key Constraints ---
# Allowed characters in AWS tag keys: letters, numbers, spaces, and + - = . _ : / @
# This is the character class for use in regex patterns
AWS_TAG_KEY_ALLOWED_CHARS = r"a-zA-Z0-9 +\-=._:/@"

# Maximum length for AWS tag keys (per AWS documentation)
AWS_TAG_KEY_MAX_LENGTH = 128

# --- Tag Value Constraints ---
# Allowed characters in AWS tag values: letters, numbers, spaces, and + - = . _ : / @
# Same character set as tag keys
AWS_TAG_VALUE_ALLOWED_CHARS = r"a-zA-Z0-9 +\-=._:/@"

# Maximum length for AWS tag values (per AWS documentation)
# Note: Tag values can be empty (minimum 0), unlike keys which must have at least 1 char
AWS_TAG_VALUE_MAX_LENGTH = 256

# Minimum length for AWS tag values (can be empty)
AWS_TAG_VALUE_MIN_LENGTH = 0
