"""
Convenience functions for common validation scenarios.

This module provides high-level, easy-to-use functions for common IAM policy
validation tasks without requiring deep knowledge of the internal API.
"""

from pathlib import Path

from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader


async def validate_file(
    file_path: str | Path,
    config_path: str | None = None,
) -> PolicyValidationResult:
    """
    Validate a single IAM policy file.

    Args:
        file_path: Path to the policy file (JSON or YAML)
        config_path: Optional path to configuration file

    Returns:
        PolicyValidationResult for the policy

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

    if not policies:
        raise ValueError(f"No IAM policies found in {file_path}")

    results = await validate_policies(
        policies,
        config_path=config_path,
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
) -> list[PolicyValidationResult]:
    """
    Validate all IAM policies in a directory.

    Args:
        dir_path: Path to directory containing policy files
        config_path: Optional path to configuration file
        recursive: Whether to search subdirectories (default: True)

    Returns:
        List of PolicyValidationResults for all policies found

    Example:
        >>> results = await validate_directory("./policies")
        >>> valid_count = sum(1 for r in results if r.is_valid)
        >>> print(f"{valid_count}/{len(results)} policies are valid")
    """
    loader = PolicyLoader()
    policies = loader.load_from_path(str(dir_path), recursive=recursive)

    if not policies:
        raise ValueError(f"No IAM policies found in {dir_path}")

    return await validate_policies(
        policies,
        config_path=config_path,
    )


async def validate_json(
    policy_json: dict,
    policy_name: str = "inline-policy",
    config_path: str | None = None,
) -> PolicyValidationResult:
    """
    Validate an IAM policy from a Python dictionary.

    Args:
        policy_json: IAM policy as a Python dict
        policy_name: Name to identify this policy in results
        config_path: Optional path to configuration file

    Returns:
        PolicyValidationResult for the policy

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
    """
    from iam_validator.core.models import IAMPolicy

    # Parse the dict into an IAMPolicy
    policy = IAMPolicy(**policy_json)

    results = await validate_policies(
        [(policy_name, policy)],
        config_path=config_path,
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
) -> bool:
    """
    Quick validation returning just True/False.

    Automatically detects whether input is a file path, directory, or dict.

    Args:
        policy: File path, directory path, or policy dict
        config_path: Optional path to configuration file

    Returns:
        True if all policies are valid, False otherwise

    Example:
        >>> if await quick_validate("policy.json"):
        ...     print("Policy is valid!")
        >>> else:
        ...     print("Policy has issues")
    """
    # If dict, validate as JSON
    if isinstance(policy, dict):
        result = await validate_json(policy, config_path=config_path)
        return result.is_valid

    # Convert to Path for easier handling
    policy_path = Path(policy)

    if not policy_path.exists():
        raise FileNotFoundError(f"Path does not exist: {policy}")

    # If directory, validate all files in it
    if policy_path.is_dir():
        results = await validate_directory(policy_path, config_path=config_path)
        return all(r.is_valid for r in results)

    # Otherwise, validate single file
    result = await validate_file(policy_path, config_path=config_path)
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
        min_severity: Minimum severity to include (critical, high, medium, low, info)
        config_path: Optional path to configuration file

    Returns:
        List of ValidationIssues meeting the severity threshold

    Example:
        >>> issues = await get_issues("policy.json", min_severity="high")
        >>> for issue in issues:
        ...     print(f"{issue.severity}: {issue.message}")
    """
    # Severity ranking for filtering
    severity_rank = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "warning": 3,  # Treat warning as medium
        "error": 4,  # Treat error as high
    }

    min_rank = severity_rank.get(min_severity.lower(), 0)

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
            issue_rank = severity_rank.get(issue.severity.lower(), 0)
            if issue_rank >= min_rank:
                all_issues.append(issue)

    return all_issues


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
