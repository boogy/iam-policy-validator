"""
Convenience functions for common validation scenarios.

This module provides high-level, easy-to-use functions for common IAM policy
validation tasks without requiring deep knowledge of the internal API.

Every function here validates exactly the way ``iam-validator validate`` does:
the same config resolution, the same checks (including the document-level
structure checks, which need the raw policy dict), and the same treatment of a
file that cannot be parsed — it is returned as a failed result carrying a
``policy_parse_error`` finding instead of being silently skipped.
"""

import json
from pathlib import Path

from iam_validator.core.config.config_loader import ValidatorConfig
from iam_validator.core.models import IAMPolicy, PolicyType, PolicyValidationResult, ValidationIssue
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader


async def _validate_loaded(
    loader: PolicyLoader,
    policies: list[tuple[str, IAMPolicy]],
    source: str | Path,
    *,
    config_path: str | None,
    policy_type: PolicyType | None,
    config: ValidatorConfig | None,
    custom_checks_dir: str | None,
    aws_services_dir: str | None,
    allow_config_custom_checks: bool,
) -> list[PolicyValidationResult]:
    """Validate what ``loader`` loaded and append a failed result per unparseable file."""
    if not policies and not loader.parsing_errors:
        raise ValueError(f"No IAM policies found in {source}")

    results: list[PolicyValidationResult] = []
    if policies:
        results = await validate_policies(
            policies,
            config_path=config_path,
            custom_checks_dir=custom_checks_dir,
            policy_type=policy_type,
            aws_services_dir=aws_services_dir,
            allow_config_custom_checks=allow_config_custom_checks,
            config=config,
        )
    return [*results, *loader.parsing_error_results()]


async def validate_file(
    file_path: str | Path,
    config_path: str | None = None,
    policy_type: PolicyType | None = None,
    *,
    config: ValidatorConfig | None = None,
    custom_checks_dir: str | None = None,
    aws_services_dir: str | None = None,
    allow_config_custom_checks: bool = False,
) -> PolicyValidationResult:
    """
    Validate a single IAM policy file.

    Args:
        file_path: Path to the policy file (JSON or YAML)
        config_path: Optional path to configuration file (``--config``)
        policy_type: Explicit policy type (``--policy-type``). When ``None`` (default),
            the orchestrator resolves the type per-file via the config
            ``policy_types:`` glob list, then content auto-detection, then a
            fallback to ``IDENTITY_POLICY``.
        config: Already-loaded configuration; ``config_path`` is ignored when given.
        custom_checks_dir: Directory of custom checks to load (``--custom-checks-dir``)
        aws_services_dir: Pre-downloaded AWS service definitions (``--aws-services-dir``)
        allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the
            config file (``--allow-config-custom-checks``)

    Returns:
        PolicyValidationResult for the policy. A file that exists but cannot be
        parsed yields ``is_valid=False`` with a ``policy_parse_error`` finding.

    Raises:
        ValueError: If the path is not a loadable policy file (missing, or an
            unsupported extension).

    Example:
        >>> result = await validate_file("policy.json")
        >>> if result.is_valid:
        ...     print("Policy is valid!")
        >>> else:
        ...     for issue in result.issues:
        ...         print(f"{issue.severity}: {issue.message}")
    """
    loader = PolicyLoader()
    policies = loader.load_from_path(str(file_path))
    results = await _validate_loaded(
        loader,
        policies,
        file_path,
        config_path=config_path,
        policy_type=policy_type,
        config=config,
        custom_checks_dir=custom_checks_dir,
        aws_services_dir=aws_services_dir,
        allow_config_custom_checks=allow_config_custom_checks,
    )
    return (
        results[0]
        if results
        else PolicyValidationResult(
            policy_file=str(file_path),
            is_valid=False,
            issues=[],
        )
    )


async def validate_directory(
    dir_path: str | Path,
    config_path: str | None = None,
    recursive: bool = True,
    policy_type: PolicyType | None = None,
    *,
    config: ValidatorConfig | None = None,
    custom_checks_dir: str | None = None,
    aws_services_dir: str | None = None,
    allow_config_custom_checks: bool = False,
) -> list[PolicyValidationResult]:
    """
    Validate all IAM policies in a directory.

    Args:
        dir_path: Path to directory containing policy files
        config_path: Optional path to configuration file
        recursive: Whether to search subdirectories (default: True)
        policy_type: Explicit policy type applied to *every* policy in the
            directory. When ``None`` (default), each policy's type is
            resolved per-file (config glob → content auto-detect → default).
        config: Already-loaded configuration; ``config_path`` is ignored when given.
        custom_checks_dir: Directory of custom checks to load
        aws_services_dir: Pre-downloaded AWS service definitions (offline mode)
        allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the config file

    Returns:
        List of PolicyValidationResults for all policies found, including one
        failed result (``policy_parse_error``) per file that could not be parsed.

    Example:
        >>> results = await validate_directory("./policies")
        >>> valid_count = sum(1 for r in results if r.is_valid)
        >>> print(f"{valid_count}/{len(results)} policies are valid")
    """
    loader = PolicyLoader()
    policies = loader.load_from_path(str(dir_path), recursive=recursive)
    return await _validate_loaded(
        loader,
        policies,
        dir_path,
        config_path=config_path,
        policy_type=policy_type,
        config=config,
        custom_checks_dir=custom_checks_dir,
        aws_services_dir=aws_services_dir,
        allow_config_custom_checks=allow_config_custom_checks,
    )


def _policy_from_json(policy_json: dict | str) -> tuple[IAMPolicy, dict]:
    """Parse ``policy_json`` into ``(IAMPolicy, raw_dict)``.

    Raises:
        json.JSONDecodeError: A string that is not valid JSON.
        TypeError: Input that is not a dict, or JSON that is not an object.
        pydantic.ValidationError: A dict that is not a policy document.
    """
    if isinstance(policy_json, str):
        parsed = json.loads(policy_json.lstrip("\ufeff"))
        if not isinstance(parsed, dict):
            msg = f"Expected JSON object, got {type(parsed).__name__}"
            raise TypeError(msg)
        policy_json = parsed
    if not isinstance(policy_json, dict):
        msg = f"Expected a dict or JSON string, got {type(policy_json).__name__}"
        raise TypeError(msg)
    return IAMPolicy.model_validate(policy_json), policy_json


async def validate_json(
    policy_json: dict | str,
    policy_name: str = "inline-policy",
    config_path: str | None = None,
    policy_type: PolicyType | None = None,
    *,
    config: ValidatorConfig | None = None,
    custom_checks_dir: str | None = None,
    aws_services_dir: str | None = None,
    allow_config_custom_checks: bool = False,
) -> PolicyValidationResult:
    """
    Validate an IAM policy from a Python dictionary or JSON string.

    The raw document is validated too, so structural problems (a misspelled
    ``Effect``, a missing ``Version``, unknown fields, ``Action`` with
    ``NotAction``) are reported exactly as they are for a file.

    Args:
        policy_json: IAM policy as a Python dict or JSON string
        policy_name: Name to identify this policy in results (also matched
            against the config's ``policy_types:`` globs)
        config_path: Optional path to configuration file
        policy_type: Explicit policy type; ``None`` auto-detects
        config: Already-loaded configuration; ``config_path`` is ignored when given.
        custom_checks_dir: Directory of custom checks to load
        aws_services_dir: Pre-downloaded AWS service definitions (offline mode)
        allow_config_custom_checks: Honour a ``custom_checks_dir`` set only in the config file

    Returns:
        PolicyValidationResult for the policy

    Raises:
        json.JSONDecodeError: If a string is provided that is not valid JSON
        TypeError: If policy_json is not a dict or str
        pydantic.ValidationError: If the document is not an IAM policy object

    Example:
        >>> policy = {
        ...     "Version": "2012-10-17",
        ...     "Statement": [{
        ...         "Effect": "Allow",
        ...         "Action": "s3:GetObject",
        ...         "Resource": "arn:aws:s3:::my-bucket/*"
        ...     }]
        ... }
        >>> result = await validate_json(policy)
        >>> print(f"Valid: {result.is_valid}")

        >>> # Also accepts JSON strings:
        >>> result = await validate_json('{"Version": "2012-10-17", ...}')
    """
    policy, raw = _policy_from_json(policy_json)

    results = await validate_policies(
        [(policy_name, policy, raw)],
        config_path=config_path,
        custom_checks_dir=custom_checks_dir,
        policy_type=policy_type,
        aws_services_dir=aws_services_dir,
        allow_config_custom_checks=allow_config_custom_checks,
        config=config,
    )

    return (
        results[0]
        if results
        else PolicyValidationResult(
            policy_file=policy_name,
            is_valid=False,
            issues=[],
        )
    )


async def quick_validate(
    policy: str | Path | dict,
    config_path: str | None = None,
    policy_type: PolicyType | None = None,
) -> bool:
    """
    Quick validation returning just True/False.

    Automatically detects whether input is a file path, directory, or dict.

    Args:
        policy: File path, directory path, or policy dict
        config_path: Optional path to configuration file
        policy_type: Explicit policy type. When ``None`` (default), the
            orchestrator auto-detects (config glob → content → default).

    Returns:
        True if all policies are valid, False otherwise (including when any
        file in the path could not be parsed)

    Example:
        >>> if await quick_validate("policy.json"):
        ...     print("Policy is valid!")
        >>> else:
        ...     print("Policy has issues")
    """
    # If dict, validate as JSON
    if isinstance(policy, dict):
        result = await validate_json(policy, config_path=config_path, policy_type=policy_type)
        return result.is_valid

    # Convert to Path for easier handling
    policy_path = Path(policy)

    if not policy_path.exists():
        raise FileNotFoundError(f"Path does not exist: {policy}")

    # If directory, validate all files in it
    if policy_path.is_dir():
        results = await validate_directory(policy_path, config_path=config_path, policy_type=policy_type)
        return all(r.is_valid for r in results)

    # Otherwise, validate single file
    result = await validate_file(policy_path, config_path=config_path, policy_type=policy_type)
    return result.is_valid


async def get_issues(
    policy: str | Path | dict,
    min_severity: str = "medium",
    config_path: str | None = None,
) -> list[ValidationIssue]:
    """
    Get just the issues from validation, filtered by severity.

    Args:
        policy: File path, directory path, or policy dict
        min_severity: Minimum severity to include (error, critical, high, warning,
            medium, low, info — ranked by ``ValidationIssue.SEVERITY_RANK``)
        config_path: Optional path to configuration file

    Returns:
        List of ValidationIssues meeting the severity threshold

    Example:
        >>> issues = await get_issues("policy.json", min_severity="high")
        >>> for issue in issues:
        ...     print(f"{issue.severity}: {issue.message}")
    """
    min_rank = ValidationIssue.SEVERITY_RANK.get(min_severity.lower(), 0)

    # Get validation results
    if isinstance(policy, dict):
        result = await validate_json(policy, config_path=config_path)
        results = [result]
    else:
        policy_path = Path(policy)
        if policy_path.is_dir():
            results = await validate_directory(policy_path, config_path=config_path)
        else:
            result = await validate_file(policy_path, config_path=config_path)
            results = [result]

    # Collect and filter issues
    all_issues = []
    for result in results:
        for issue in result.issues:
            issue_rank = ValidationIssue.SEVERITY_RANK.get(issue.severity.lower(), 0)
            if issue_rank >= min_rank:
                all_issues.append(issue)

    return all_issues


def filter_issues_by_check_id(
    result: PolicyValidationResult,
    check_id: str,
) -> list[ValidationIssue]:
    """Filter validation issues by check ID.

    Args:
        result: PolicyValidationResult to filter
        check_id: Check ID to filter by (e.g., "wildcard_action", "sensitive_action")

    Returns:
        List of ValidationIssues matching the check ID

    Example:
        >>> result = await validate_file("policy.json")
        >>> wildcard_issues = filter_issues_by_check_id(result, "wildcard_action")
        >>> print(f"Found {len(wildcard_issues)} wildcard action issues")
    """
    return [issue for issue in result.issues if issue.check_id == check_id]


def filter_issues_by_severity(
    result: PolicyValidationResult,
    min_severity: str = "medium",
) -> list[ValidationIssue]:
    """Filter validation issues by minimum severity threshold.

    Uses the severity ranking from :class:`ValidationIssue.SEVERITY_RANK`.

    Args:
        result: PolicyValidationResult to filter
        min_severity: Minimum severity to include. Valid values:
            "error", "critical", "high", "warning", "medium", "low", "info"

    Returns:
        List of ValidationIssues at or above the severity threshold

    Example:
        >>> result = await validate_file("policy.json")
        >>> high_issues = filter_issues_by_severity(result, "high")
        >>> print(f"Found {len(high_issues)} high+ severity issues")
    """
    min_rank = ValidationIssue.SEVERITY_RANK.get(min_severity, 0)
    return [issue for issue in result.issues if issue.get_severity_rank() >= min_rank]


async def count_issues_by_severity(
    policy: str | Path | dict,
    config_path: str | None = None,
) -> dict[str, int]:
    """
    Count issues grouped by severity level.

    Args:
        policy: File path, directory path, or policy dict
        config_path: Optional path to configuration file

    Returns:
        Dictionary mapping severity levels to counts

    Example:
        >>> counts = await count_issues_by_severity("./policies")
        >>> print(f"Critical: {counts.get('critical', 0)}")
        >>> print(f"High: {counts.get('high', 0)}")
        >>> print(f"Medium: {counts.get('medium', 0)}")
    """
    # Get all issues (no filtering)
    all_issues = await get_issues(policy, min_severity="info", config_path=config_path)

    # Count by severity
    counts: dict[str, int] = {}
    for issue in all_issues:
        severity = issue.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1

    return counts
