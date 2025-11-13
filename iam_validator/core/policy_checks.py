"""IAM Policy Validation Module.

This module provides comprehensive validation of IAM policies including:
- Action validation against AWS Service Reference API
- Condition key validation
- Resource ARN format validation
- Security best practices checks
"""

import asyncio
import logging
from pathlib import Path

from iam_validator.core import constants
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry, create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader
from iam_validator.core.models import (
    IAMPolicy,
    PolicyType,
    PolicyValidationResult,
    ValidationIssue,
)
from iam_validator.core.policy_loader import PolicyLoader

logger = logging.getLogger(__name__)


def _should_fail_on_issue(
    issue: ValidationIssue, fail_on_severities: list[str] | None = None
) -> bool:
    """Determine if an issue should cause validation to fail.

    Args:
        issue: Validation issue to check
        fail_on_severities: List of severity levels that should cause failure
                           Defaults to ["error"] if not specified

    Returns:
        True if the issue should cause validation to fail
    """
    if not fail_on_severities:
        fail_on_severities = ["error"]  # Default: only fail on errors

    # Check if issue severity is in the fail list
    return issue.severity in fail_on_severities


async def validate_policies(
    policies: list[tuple[str, IAMPolicy]] | list[tuple[str, IAMPolicy, dict]],
    config_path: str | None = None,
    custom_checks_dir: str | None = None,
    policy_type: PolicyType = "IDENTITY_POLICY",
    aws_services_dir: str | None = None,
) -> list[PolicyValidationResult]:
    """Validate multiple policies concurrently.

    Args:
        policies: List of (file_path, policy) or (file_path, policy, raw_dict) tuples
        config_path: Optional path to configuration file
        custom_checks_dir: Optional path to directory containing custom checks for auto-discovery
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)
        aws_services_dir: Optional path to directory containing pre-downloaded AWS service definitions
                         (enables offline mode, overrides config setting)

    Returns:
        List of validation results
    """
    # Load configuration
    config = ConfigLoader.load_config(explicit_path=config_path, allow_missing=True)

    # Create registry with or without built-in checks based on configuration
    enable_parallel = config.get_setting("parallel_execution", True)
    enable_builtin_checks = config.get_setting("enable_builtin_checks", True)

    registry = create_default_registry(
        enable_parallel=enable_parallel, include_builtin_checks=enable_builtin_checks
    )

    if not enable_builtin_checks:
        logger.info("Built-in checks disabled - using only custom checks")

    # Apply configuration to built-in checks (if they were registered)
    if enable_builtin_checks:
        ConfigLoader.apply_config_to_registry(config, registry)

    # Load custom checks from explicit module paths (old method)
    custom_checks = ConfigLoader.load_custom_checks(config, registry)
    if custom_checks:
        logger.info(
            f"Loaded {len(custom_checks)} custom checks from modules: {', '.join(custom_checks)}"
        )

    # Auto-discover custom checks from directory (new method)
    # Priority: CLI arg > config file > default None
    checks_dir = custom_checks_dir or config.custom_checks_dir
    if checks_dir:
        checks_dir_path = Path(checks_dir).resolve()
        discovered_checks = ConfigLoader.discover_checks_in_directory(checks_dir_path, registry)
        if discovered_checks:
            logger.info(
                f"Auto-discovered {len(discovered_checks)} custom checks from {checks_dir_path}"
            )

    # Apply configuration again to include custom checks
    # This allows configuring auto-discovered checks via the config file
    ConfigLoader.apply_config_to_registry(config, registry)

    # Get fail_on_severity setting from config
    fail_on_severities = config.get_setting("fail_on_severity", ["error"])

    # Get cache settings from config
    cache_enabled = config.get_setting("cache_enabled", True)
    cache_ttl_hours = config.get_setting("cache_ttl_hours", constants.DEFAULT_CACHE_TTL_HOURS)
    cache_directory = config.get_setting("cache_directory", None)
    # CLI argument takes precedence over config file
    services_dir = aws_services_dir or config.get_setting("aws_services_dir", None)
    cache_ttl_seconds = cache_ttl_hours * constants.SECONDS_PER_HOUR

    # Validate policies using registry
    async with AWSServiceFetcher(
        enable_cache=cache_enabled,
        cache_ttl=cache_ttl_seconds,
        cache_dir=cache_directory,
        aws_services_dir=services_dir,
    ) as fetcher:
        tasks = [
            _validate_policy_with_registry(
                item[1],  # policy
                item[0],  # file_path
                registry,
                fetcher,
                fail_on_severities,
                policy_type,
                item[2] if len(item) == 3 else None,  # raw_dict (optional)
            )
            for item in policies
        ]

        results = await asyncio.gather(*tasks)

    return list(results)


async def _validate_policy_with_registry(
    policy: IAMPolicy,
    policy_file: str,
    registry: CheckRegistry,
    fetcher: AWSServiceFetcher,
    fail_on_severities: list[str] | None = None,
    policy_type: PolicyType = "IDENTITY_POLICY",
    raw_policy_dict: dict | None = None,
) -> PolicyValidationResult:
    """Validate a single policy using the CheckRegistry system.

    Args:
        policy: IAM policy to validate
        policy_file: Path to the policy file
        registry: CheckRegistry instance with configured checks
        fetcher: AWS service fetcher instance
        fail_on_severities: List of severity levels that should cause validation to fail
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)
        raw_policy_dict: Raw policy dictionary for structural validation (optional, will be loaded if not provided)

    Returns:
        PolicyValidationResult with all findings
    """
    result = PolicyValidationResult(policy_file=policy_file, is_valid=True, policy_type=policy_type)

    # Load raw dict if not provided (for structural validation)
    if raw_policy_dict is None:
        loader = PolicyLoader()
        loaded_result = loader.load_from_file(policy_file, return_raw_dict=True)
        if loaded_result and isinstance(loaded_result, tuple):
            raw_policy_dict = loaded_result[1]

    # Apply automatic policy-type validation (not configurable - always runs)
    # Note: Import here to avoid circular import (policy_checks -> checks -> sdk -> policy_checks)
    from iam_validator.checks import (  # pylint: disable=import-outside-toplevel
        policy_type_validation,
    )

    policy_type_issues = await policy_type_validation.execute_policy(
        policy, policy_file, policy_type=policy_type
    )
    result.issues.extend(policy_type_issues)  # pylint: disable=no-member

    # Run policy-level checks first (checks that need to see the entire policy)
    # These checks examine relationships between statements, not individual statements
    policy_level_issues = await registry.execute_policy_checks(
        policy, policy_file, fetcher, policy_type, raw_policy_dict=raw_policy_dict
    )
    result.issues.extend(policy_level_issues)  # pylint: disable=no-member

    # Execute all statement-level checks for each statement
    for idx, statement in enumerate(policy.statement or []):
        # Execute all registered checks in parallel (with ignore_patterns filtering)
        issues = await registry.execute_checks_parallel(statement, idx, fetcher, policy_file)

        # Add issues to result
        result.issues.extend(issues)  # pylint: disable=no-member

        # Update counters (approximate based on what was checked)
        actions = statement.get_actions()
        resources = statement.get_resources()

        result.actions_checked += len([a for a in actions if a != "*"])
        result.resources_checked += len([r for r in resources if r != "*"])

        # Count condition keys if present
        if statement.condition:
            for conditions in statement.condition.values():
                result.condition_keys_checked += len(conditions)

    # Update final validation status based on fail_on_severities configuration
    result.is_valid = (
        len([i for i in result.issues if _should_fail_on_issue(i, fail_on_severities)]) == 0
    )

    return result
