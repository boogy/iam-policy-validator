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
# Every place that validates an ARN must source the partition alternation from
# ARN_PARTITION_REGEX so the supported partitions stay in lockstep. Adding a
# new partition (e.g., a future AWS region split) is then a one-line change.
# Covers commercial, China, GovCloud, Europe sovereign, and all ISO partitions.
ARN_PARTITION_REGEX = r"(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f)"

# Lenient ARN format used by `resource_validation` — allows wildcards (*) in
# region and account fields. Stricter than the structural parser in
# CompiledPatterns but tolerant enough for policy-author conveniences.
DEFAULT_ARN_VALIDATION_PATTERN = rf"^arn:{ARN_PARTITION_REGEX}:[a-z0-9\-]+:[a-z0-9\-*]*:[0-9*]*:.+$"

# Maximum allowed ARN length to prevent ReDoS attacks
# AWS maximum ARN length is approximately 2048 characters
MAX_ARN_LENGTH = 2048

# ============================================================================
# IAM Policy Version Literals
# ============================================================================
# Centralized so MCP, fix tools, and templates can't drift. AWS recognises two
# IAM policy language versions: "2012-10-17" (current) and "2008-10-17" (legacy).
# New policies should always use "2012-10-17".
IAM_POLICY_VERSION_CURRENT = "2012-10-17"
IAM_POLICY_VERSION_LEGACY = "2008-10-17"
IAM_POLICY_VERSIONS_VALID: frozenset[str] = frozenset({IAM_POLICY_VERSION_CURRENT, IAM_POLICY_VERSION_LEGACY})

# ============================================================================
# Default region per AWS partition
# ============================================================================
# AWS service endpoints are partition-specific. `us-east-1` is only valid in
# the commercial partition. Any tool calling boto3 with a partition other than
# `aws` MUST use a region that exists in that partition or the SDK rejects the
# request before it leaves the box. Centralized so MCP, CLI, and tests
# converge on the same defaults.
PARTITION_DEFAULT_REGION: dict[str, str] = {
    "aws": "us-east-1",
    "aws-cn": "cn-north-1",
    "aws-us-gov": "us-gov-west-1",
    "aws-eusc": "eusc-de-east-1",
    "aws-iso": "us-iso-east-1",
    "aws-iso-b": "us-isob-east-1",
    "aws-iso-e": "eu-isoe-west-1",
    "aws-iso-f": "us-isof-south-1",
}

# ============================================================================
# AWS IAM Policy Size Limits
# ============================================================================
# These limits are enforced by AWS and policies exceeding them will be rejected
# Note: AWS does not count whitespace when calculating policy size

# Managed policy maximum size (bytes, excluding whitespace)
MAX_MANAGED_POLICY_SIZE = 6144

# Inline policy maximum size for IAM users (bytes, excluding whitespace)
MAX_INLINE_USER_POLICY_SIZE = 2048

# Inline policy maximum size for IAM groups (bytes, excluding whitespace)
MAX_INLINE_GROUP_POLICY_SIZE = 5120

# Inline policy maximum size for IAM roles (bytes, excluding whitespace)
MAX_INLINE_ROLE_POLICY_SIZE = 10240

# Inline policy maximum size for IAM role trust policies (bytes, excluding whitespace).
# Trust policies are the assume-role policies attached to IAM roles.
MAX_INLINE_ROLE_TRUST_POLICY_SIZE = 2048

# Service Control Policy maximum size (bytes, excluding whitespace)
MAX_SCP_SIZE = 5120

# Resource Control Policy maximum size (bytes, excluding whitespace)
MAX_RCP_SIZE = 5120

# Policy size limits dictionary (for backward compatibility and easy lookup)
AWS_POLICY_SIZE_LIMITS = {
    "managed": MAX_MANAGED_POLICY_SIZE,
    "inline_user": MAX_INLINE_USER_POLICY_SIZE,
    "inline_group": MAX_INLINE_GROUP_POLICY_SIZE,
    "inline_role": MAX_INLINE_ROLE_POLICY_SIZE,
    "inline_role_trust": MAX_INLINE_ROLE_TRUST_POLICY_SIZE,
    "scp": MAX_SCP_SIZE,
    "rcp": MAX_RCP_SIZE,
}

# Default mapping from runtime policy type (the `--policy-type` argument or
# auto-detected type) to the size-limit key in AWS_POLICY_SIZE_LIMITS.
# Users can override the chosen limit on a per-check basis by setting
# `checks.policy_size.config.policy_type` in their YAML config (e.g. to use
# `inline_user` instead of `managed` for an IDENTITY_POLICY).
AWS_POLICY_TYPE_TO_SIZE_KEY = {
    "IDENTITY_POLICY": "managed",
    "RESOURCE_POLICY": "managed",  # conservative default; service-specific limits vary
    "TRUST_POLICY": "inline_role_trust",
    "SERVICE_CONTROL_POLICY": "scp",
    "RESOURCE_CONTROL_POLICY": "rcp",
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
ANALYZER_IDENTIFIER = "<!-- iam-access-analyzer-validator -->"

# Structural markers embedded inside review-comment bodies. Centralized so
# producers (body-builders in models.py) and consumers (parsers in
# github_integration.py / ignore_processor.py) cannot drift apart.
ISSUE_TYPE_MARKER_FORMAT = "<!-- issue-type: {issue_type} -->"
ISSUE_TYPE_MARKER_PATTERN = r"<!-- issue-type: (\w+) -->"
FINDING_ID_MARKER_FORMAT = "<!-- finding-id: {finding_id} -->"
# Strict pattern: the canonical 16-char hex hash produced by
# compute_finding_hash(). Used by the bot's own comment lifecycle.
FINDING_ID_STRICT_PATTERN = r"<!-- finding-id: ([a-f0-9]{16}) -->"
# Loose pattern: accepts any hex length. Used by extract_finding_id() when
# parsing user-authored ignore commands that may reference legacy ids.
FINDING_ID_LOOSE_PATTERN = r"<!-- finding-id: ([a-f0-9]+) -->"

# GitHub comment size limits
# GITHUB_COMMENT_HARD_LIMIT is GitHub's actual API ceiling — exceeding it
# returns a 422. The other two limits are our internal safety margins.
GITHUB_COMMENT_HARD_LIMIT = 65536  # GitHub-enforced absolute maximum
GITHUB_MAX_COMMENT_LENGTH = 65000  # Maximum single comment length (safety margin)
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

# AWS services that support Resource Control Policies (RCP).
# Sourced from the official AWS Organizations documentation. Expanded beyond
# the 2024 launch set; the current IAM service prefixes are:
#
#   - Amazon S3 (s3)
#   - AWS Security Token Service (sts)
#   - Amazon SQS (sqs)
#   - AWS Key Management Service (kms) — note: RCPs do NOT apply to
#     `kms:RetireGrant` or to AWS-managed keys
#   - AWS Secrets Manager (secretsmanager)
#   - Amazon Cognito: User Pools (cognito-idp) and Identity Pools (cognito-identity)
#   - Amazon DynamoDB (dynamodb)
#   - Amazon Elastic Container Registry (ecr)
#   - Amazon OpenSearch Serverless (aoss) — note: this is the serverless
#     product, not Amazon OpenSearch Service (`es`), which is NOT covered
#   - Amazon CloudWatch Logs (logs)
#
# Reference: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
RCP_SUPPORTED_SERVICES = frozenset(
    {
        "s3",
        "sts",
        "sqs",
        "kms",
        "secretsmanager",
        "cognito-idp",
        "cognito-identity",
        "dynamodb",
        "ecr",
        "aoss",
        "logs",
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
