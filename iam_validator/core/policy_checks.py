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
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.models import (
    IAMPolicy,
    PolicyType,
    PolicyValidationResult,
    ValidationIssue,
)
from iam_validator.core.policy_loader import PolicyLoader

logger = logging.getLogger(__name__)


def _resolve_policy_type(
    policy: IAMPolicy,
    policy_file: str,
    cli_policy_type: PolicyType | None,
    config: ValidatorConfig,
) -> tuple[PolicyType, str, str | None]:
    """Resolve the PolicyType to use for a single policy.

    Priority:
      1. ``cli_policy_type`` (from CLI flag / SDK kwarg) — authoritative.
      2. ``policy_types:`` glob mapping in config — first match wins.
      3. Content auto-detection via ``detect_policy_type()``.
      4. Default ``IDENTITY_POLICY``.

    Args:
        policy: Parsed IAM policy.
        policy_file: Path to the policy file (used for glob matching and logs).
        cli_policy_type: Type explicitly requested by the caller, or ``None``.
        config: Loaded validator config (used for the glob list).

    Returns:
        A ``(resolved_type, source, matched_pattern)`` tuple where ``source``
        is one of ``"cli-flag"``, ``"config-glob"``, ``"auto-detect"``,
        ``"default"`` and ``matched_pattern`` is the glob that matched when
        ``source == "config-glob"`` (otherwise ``None``).
    """
    if cli_policy_type is not None:
        return cli_policy_type, "cli-flag", None

    glob_type = config.get_policy_type_for_path(policy_file)
    if glob_type is not None:
        matched_pattern: str | None = None
        for entry in config.policy_types:
            if glob_type == entry["type"]:
                matched_pattern = entry["pattern"]
                break
        return glob_type, "config-glob", matched_pattern

    # Lazy import — `iam_validator.checks` pulls the whole package which
    # transitively imports from `iam_validator.sdk`, which imports from this
    # module. Importing inside the function breaks the cycle.
    from iam_validator.checks.policy_structure import (  # pylint: disable=import-outside-toplevel
        detect_policy_type,
    )

    detected = detect_policy_type(policy)
    if detected != "IDENTITY_POLICY":
        return detected, "auto-detect", None

    return "IDENTITY_POLICY", "default", None


_ALLOWED_SOURCES: frozenset[str] = frozenset({"cli-flag", "config-glob", "auto-detect", "default"})
_ALLOWED_POLICY_TYPES: frozenset[str] = frozenset(
    {
        "IDENTITY_POLICY",
        "RESOURCE_POLICY",
        "TRUST_POLICY",
        "SERVICE_CONTROL_POLICY",
        "RESOURCE_CONTROL_POLICY",
    }
)


def _log_resolved_policy_type(policy_file: str, resolved_type: PolicyType, source: str, pattern: str | None) -> None:
    """Emit the single machine-greppable debug line per policy.

    Every logged field is derived from a closed-set allowlist or an integer
    length — this breaks CodeQL's taint flow from the YAML config into the
    log sink so ``py/clear-text-logging-sensitive-data`` does not fire on
    non-sensitive resolution metadata. The raw ``pattern`` glob is not
    logged (users can inspect their own config); we log its length and a
    presence flag instead.

    Format (one of):
        policy_type=<TYPE> source=cli-flag file=<basename>
        policy_type=<TYPE> source=config-glob pattern_present=true pattern_len=<n> file=<basename>
        policy_type=<TYPE> source=auto-detect file=<basename>
        policy_type=<TYPE> source=default file=<basename>
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return

    safe_type = resolved_type if resolved_type in _ALLOWED_POLICY_TYPES else "UNKNOWN"
    safe_source = source if source in _ALLOWED_SOURCES else "unknown"
    file_name = Path(policy_file).name

    if safe_source == "config-glob" and pattern is not None:
        logger.debug(
            "policy_type=%s source=%s pattern_present=true pattern_len=%d file=%s",
            safe_type,
            safe_source,
            len(pattern),
            file_name,
        )
    else:
        logger.debug(
            "policy_type=%s source=%s file=%s",
            safe_type,
            safe_source,
            file_name,
        )


def _should_fail_on_issue(issue: ValidationIssue, fail_on_severities: list[str] | None = None) -> bool:
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
    policy_type: PolicyType | None = None,
    aws_services_dir: str | None = None,
) -> list[PolicyValidationResult]:
    """Validate multiple policies concurrently.

    Args:
        policies: List of (file_path, policy) or (file_path, policy, raw_dict) tuples
        config_path: Optional path to configuration file
        custom_checks_dir: Optional path to directory containing custom checks for auto-discovery
        policy_type: Explicit policy type to apply to *every* policy in the run.
            When ``None`` (default), each policy's type is resolved per-file via
            the config ``policy_types:`` glob list, then content auto-detection,
            then a final fallback to ``IDENTITY_POLICY``.
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

    registry = create_default_registry(enable_parallel=enable_parallel, include_builtin_checks=enable_builtin_checks)

    if not enable_builtin_checks:
        logger.info("Built-in checks disabled - using only custom checks")

    # Apply configuration to built-in checks (if they were registered)
    if enable_builtin_checks:
        ConfigLoader.apply_config_to_registry(config, registry)

    # Load custom checks from explicit module paths (old method)
    custom_checks = ConfigLoader.load_custom_checks(config, registry)
    if custom_checks:
        logger.info(f"Loaded {len(custom_checks)} custom checks from modules: {', '.join(custom_checks)}")

    # Auto-discover custom checks from directory (new method)
    # Priority: CLI arg > config file > default None
    checks_dir = custom_checks_dir or config.custom_checks_dir
    if checks_dir:
        checks_dir_path = Path(checks_dir).resolve()
        discovered_checks = ConfigLoader.discover_checks_in_directory(checks_dir_path, registry)
        if discovered_checks:
            logger.info("Auto-discovered %d custom checks from configured directory", len(discovered_checks))

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
        tasks = []
        for item in policies:
            policy_file = item[0]
            policy_obj = item[1]
            raw_dict = item[2] if len(item) == 3 else None

            resolved_type, source, matched_pattern = _resolve_policy_type(policy_obj, policy_file, policy_type, config)
            _log_resolved_policy_type(policy_file, resolved_type, source, matched_pattern)

            tasks.append(
                _validate_policy_with_registry(
                    policy_obj,
                    policy_file,
                    registry,
                    fetcher,
                    fail_on_severities,
                    resolved_type,
                    raw_dict,
                )
            )

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

    policy_type_issues = await policy_type_validation.execute_policy(policy, policy_file, policy_type=policy_type)
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
    result.is_valid = len([i for i in result.issues if _should_fail_on_issue(i, fail_on_severities)]) == 0

    return result
