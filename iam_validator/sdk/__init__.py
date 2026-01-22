"""IAM Policy Validator SDK - Public API for library usage.

This module provides the complete public API for using IAM Policy Validator
as a Python library. It exposes both high-level convenience functions and
low-level components for custom integrations.

Example:
    Basic validation::

        from iam_validator.sdk import validate_file

        result = await validate_file("policy.json")
        print(f"Valid: {result.is_valid}")

    With context manager::

        from iam_validator.sdk import validator

        async with validator() as v:
            result = await v.validate_file("policy.json")
            v.generate_report([result])

    Policy manipulation::

        from iam_validator.sdk import parse_policy, get_policy_summary

        policy = parse_policy(policy_json)
        summary = get_policy_summary(policy)
        print(f"Actions: {summary['action_count']}")

    Query AWS service definitions::

        from iam_validator.sdk import AWSServiceFetcher, query_actions

        async with AWSServiceFetcher() as fetcher:
            # Query all S3 write actions
            write_actions = await query_actions(fetcher, "s3", access_level="write")

    Custom check development::

        from iam_validator.sdk import PolicyCheck, CheckHelper

        class MyCheck(PolicyCheck):
            check_id = "my_check"
            description = "My custom check"
            default_severity = "medium"

            async def execute(self, statement, idx, fetcher, config):
                helper = CheckHelper(fetcher)
                # Use helper.arn_matches(), helper.create_issue(), etc.
                return []
"""

# ruff: noqa: E402
# Imports are organized by category with comments, which triggers E402.
# This is intentional for readability in this public API module.

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry, PolicyCheck
from iam_validator.core.config.config_loader import (
    ValidatorConfig,
    load_validator_config,
)
from iam_validator.core.formatters.csv import CSVFormatter
from iam_validator.core.formatters.html import HTMLFormatter
from iam_validator.core.formatters.json import JSONFormatter
from iam_validator.core.formatters.markdown import MarkdownFormatter
from iam_validator.core.formatters.sarif import SARIFFormatter
from iam_validator.core.models import (
    IAMPolicy,
    PolicyValidationResult,
    Statement,
    ValidationIssue,
)
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.report import ReportGenerator
from iam_validator.sdk.arn_matching import (
    arn_matches,
    arn_strictly_valid,
    convert_aws_pattern_to_wildcard,
    is_glob_match,
)
from iam_validator.sdk.context import (
    ValidationContext,
    validator,
    validator_from_config,
)
from iam_validator.sdk.exceptions import (
    AWSServiceError,
    ConfigurationError,
    IAMValidatorError,
    InvalidPolicyFormatError,
    PolicyLoadError,
    PolicyValidationError,
    UnsupportedPolicyTypeError,
)
from iam_validator.sdk.helpers import CheckHelper, expand_actions
from iam_validator.sdk.policy_utils import (
    extract_actions,
    extract_condition_keys,
    extract_condition_keys_from_statement,
    extract_resources,
    find_statements_with_action,
    find_statements_with_resource,
    get_policy_summary,
    has_public_access,
    is_resource_policy,
    merge_policies,
    normalize_policy,
    parse_policy,
    policy_to_dict,
    policy_to_json,
)
from iam_validator.sdk.query_utils import (
    get_actions_by_access_level,
    get_actions_supporting_condition,
    get_wildcard_only_actions,
    query_action_details,
    query_actions,
    query_arn_format,
    query_arn_formats,
    query_arn_types,
    query_condition_key,
    query_condition_keys,
)
from iam_validator.sdk.shortcuts import (
    count_issues_by_severity,
    get_issues,
    quick_validate,
    validate_directory,
    validate_file,
    validate_json,
)

# Alias for convenience (matches documentation)
Config = ValidatorConfig

__all__ = [
    # === High-level shortcuts ===
    "validate_file",
    "validate_directory",
    "validate_json",
    "quick_validate",
    "get_issues",
    "count_issues_by_severity",
    # === Context managers ===
    "validator",
    "validator_from_config",
    "ValidationContext",
    # === Policy utilities ===
    "parse_policy",
    "normalize_policy",
    "extract_actions",
    "extract_resources",
    "extract_condition_keys",
    "extract_condition_keys_from_statement",
    "find_statements_with_action",
    "find_statements_with_resource",
    "merge_policies",
    "get_policy_summary",
    "policy_to_json",
    "policy_to_dict",
    "is_resource_policy",
    "has_public_access",
    # === Query utilities ===
    "query_actions",
    "query_action_details",
    "query_arn_formats",
    "query_arn_types",
    "query_arn_format",
    "query_condition_keys",
    "query_condition_key",
    "get_actions_by_access_level",
    "get_wildcard_only_actions",
    "get_actions_supporting_condition",
    # === ARN utilities ===
    "arn_matches",
    "arn_strictly_valid",
    "is_glob_match",
    "convert_aws_pattern_to_wildcard",
    # === Custom check development ===
    "PolicyCheck",
    "CheckRegistry",
    "CheckHelper",
    "expand_actions",
    # === Core validation (advanced) ===
    "validate_policies",
    "PolicyLoader",
    # === Reporting ===
    "ReportGenerator",
    "JSONFormatter",
    "HTMLFormatter",
    "CSVFormatter",
    "MarkdownFormatter",
    "SARIFFormatter",
    # === Models ===
    "ValidationIssue",
    "PolicyValidationResult",
    "IAMPolicy",
    "Statement",
    # === ValidatorConfiguration ===
    "ValidatorConfig",
    "Config",  # Alias for ValidatorConfig
    "load_validator_config",
    # === AWS utilities ===
    "AWSServiceFetcher",
    # === Exceptions ===
    "IAMValidatorError",
    "PolicyLoadError",
    "PolicyValidationError",
    "ConfigurationError",
    "AWSServiceError",
    "InvalidPolicyFormatError",
    "UnsupportedPolicyTypeError",
    # Version
    "__version__",
]

# SDK version (same as main package)
from iam_validator.__version__ import __version__
