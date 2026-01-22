"""Validation tools for MCP server.

This module provides MCP tools for validating IAM policies using the existing
SDK validation functionality. All functions wrap the core validation logic
from iam_validator.sdk without reimplementing it.
"""

import atexit
import json
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from iam_validator.core.models import IAMPolicy
from iam_validator.core.policy_checks import validate_policies
from iam_validator.mcp.models import ValidationResult

# Track temp files for cleanup on exit (safety net for abnormal termination)
_temp_files_to_cleanup: set[Path] = set()


def _cleanup_temp_files() -> None:
    """Clean up any remaining temp files on process exit."""
    for temp_path in list(_temp_files_to_cleanup):
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
    _temp_files_to_cleanup.clear()


atexit.register(_cleanup_temp_files)


@contextmanager
def _temp_config_file(
    session_config: Any,
) -> Generator[str | None, None, None]:
    """Context manager for temporary config file with guaranteed cleanup.

    Creates a temporary YAML config file from ValidatorConfig and ensures
    cleanup even if exceptions occur or process is killed.

    Args:
        session_config: ValidatorConfig instance from SessionConfigManager

    Yields:
        Path to temporary config file, or None if no config provided
    """
    if session_config is None:
        yield None
        return

    # ValidatorConfig already has the right structure - just dump its config_dict
    config_dict = session_config.config_dict

    # Create temp file and register for cleanup
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_dict, f)
            temp_path = Path(f.name)
            _temp_files_to_cleanup.add(temp_path)

        yield str(temp_path)
    finally:
        # Clean up temp file
        if temp_path:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            _temp_files_to_cleanup.discard(temp_path)


# Trust policy actions (case-insensitive prefixes for matching)
_TRUST_POLICY_ACTIONS = frozenset(
    [
        "sts:assumerole",
        "sts:assumerolewithwebidentity",
        "sts:assumerolewithsaml",
    ]
)


def _is_trust_action(action: str) -> bool:
    """Check if an action indicates a trust policy (case-insensitive)."""
    action_lower = action.lower()
    # Check exact match or if it's a wildcard that would include assume role
    return action_lower in _TRUST_POLICY_ACTIONS or action_lower in ("sts:*", "*")


def _detect_policy_type(policy: dict[str, Any]) -> str:
    """Auto-detect policy type from structure.

    Analyzes ALL statements in the policy to determine the appropriate policy type
    based on AWS IAM policy patterns. Uses case-insensitive matching for actions.

    Args:
        policy: IAM policy dictionary to analyze

    Returns:
        - "trust" if ANY statement contains sts:AssumeRole* actions with Principal
        - "resource" if ANY statement contains Principal/NotPrincipal without trust actions
        - "identity" otherwise (default, identity-based policy)
    """
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    has_principal = False
    has_trust_action = False

    for stmt in statements:
        # Check for Principal in any statement
        if "Principal" in stmt or "NotPrincipal" in stmt:
            has_principal = True

            # Check for trust policy actions (case-insensitive)
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if _is_trust_action(action):
                    has_trust_action = True
                    break

    # Determine type based on all statements
    if has_principal:
        if has_trust_action:
            return "trust"
        return "resource"

    return "identity"


async def validate_policy(
    policy: dict[str, Any],
    policy_type: str | None = None,
    config_path: str | None = None,
    use_org_config: bool = True,
) -> ValidationResult:
    """Validate an IAM policy dictionary.

    This tool validates a policy object against AWS IAM rules and security best
    practices. It runs all enabled checks and returns detailed validation results.

    Policy Type Auto-Detection:
    If policy_type is None (default), the policy type is automatically detected:
    - "trust" if contains sts:AssumeRole action (trust/assume role policy)
    - "resource" if contains Principal/NotPrincipal (resource-based policy)
    - "identity" otherwise (identity-based policy attached to users/roles/groups)

    Configuration priority:
    1. config_path (if provided) - explicit YAML config file path
    2. Session org config (if use_org_config=True and config set)
    3. Default validator configuration

    Args:
        policy: IAM policy as a Python dictionary (must contain Version and Statement)
        policy_type: Type of policy to validate. If None (default), auto-detects from structure.
            Explicit options:
            - "identity": Identity-based policy (attached to users/roles/groups)
            - "resource": Resource-based policy (attached to resources like S3 buckets)
            - "trust": Trust policy (role assumption policy)
        config_path: Optional path to YAML configuration file
        use_org_config: Whether to use session organization config (default: True)

    Returns:
        ValidationResult with:
            - is_valid: True if no errors/warnings found
            - issues: List of ValidationIssue objects with details
            - policy_file: Set to "inline-policy" for dict validation
            - policy_type_detected: The policy type used (auto-detected or provided)

    Example:
        >>> policy = {
        ...     "Version": "2012-10-17",
        ...     "Statement": [{
        ...         "Effect": "Allow",
        ...         "Action": "s3:GetObject",
        ...         "Resource": "arn:aws:s3:::my-bucket/*"
        ...     }]
        ... }
        >>> result = await validate_policy(policy)
        >>> print(f"Valid: {result.is_valid}, Issues: {len(result.issues)}")
    """
    # Auto-detect policy type if not provided
    effective_policy_type = policy_type
    if effective_policy_type is None:
        effective_policy_type = _detect_policy_type(policy)

    # Map user-friendly policy type names to internal constants
    policy_type_mapping = {
        "identity": "IDENTITY_POLICY",
        "resource": "RESOURCE_POLICY",
        "trust": "TRUST_POLICY",
        "scp": "SERVICE_CONTROL_POLICY",
        "rcp": "RESOURCE_CONTROL_POLICY",
    }

    # Normalize the policy type
    normalized_type = policy_type_mapping.get(effective_policy_type.lower(), "IDENTITY_POLICY")

    # Parse the dict into an IAMPolicy model
    iam_policy = IAMPolicy(**policy)

    # Determine config path and session_config to use
    session_config = None
    if not config_path and use_org_config:
        # Try to use session config
        from iam_validator.mcp.session_config import SessionConfigManager

        session_config = SessionConfigManager.get_config()

    # Use context manager for temp file to ensure cleanup
    with _temp_config_file(session_config) as temp_path:
        effective_config_path = config_path or temp_path

        # Use validate_policies to perform validation with policy_type support
        # This handles all the validation logic including check execution
        results = await validate_policies(
            policies=[("inline-policy", iam_policy)],
            config_path=effective_config_path,
            policy_type=normalized_type,  # type: ignore
        )

    # Get the first (and only) result
    sdk_result = results[0] if results else None
    if not sdk_result:
        # Fallback if no results returned (shouldn't happen)
        from iam_validator.core.models import PolicyValidationResult

        sdk_result = PolicyValidationResult(
            policy_file="inline-policy",
            is_valid=False,
            issues=[],
        )

    # Convert SDK result to MCP ValidationResult
    return ValidationResult(
        is_valid=sdk_result.is_valid,
        issues=sdk_result.issues,
        policy_file=sdk_result.policy_file,
        policy_type_detected=effective_policy_type,
    )


async def validate_policy_json(
    policy_json: str, policy_type: str | None = None
) -> ValidationResult:
    """Validate an IAM policy from a JSON string.

    This tool parses a JSON string into a policy object and validates it.
    Useful when working with policy text from files, API responses, or user input.

    Policy Type Auto-Detection:
    If policy_type is None (default), the policy type is automatically detected
    from the policy structure (see validate_policy for details).

    Args:
        policy_json: IAM policy as a JSON string
        policy_type: Type of policy to validate. If None (default), auto-detects.
            Options: "identity", "resource", "trust"

    Returns:
        ValidationResult with validation status and issues

    Raises:
        Returns ValidationResult with parsing error if JSON is invalid

    Example:
        >>> policy_json = '''
        ... {
        ...   "Version": "2012-10-17",
        ...   "Statement": [{
        ...     "Effect": "Allow",
        ...     "Action": "*",
        ...     "Resource": "*"
        ...   }]
        ... }
        ... '''
        >>> result = await validate_policy_json(policy_json)
        >>> for issue in result.issues:
        ...     print(f"{issue.severity}: {issue.message}")
    """
    try:
        # Parse JSON string to dict
        policy_dict = json.loads(policy_json)
    except json.JSONDecodeError as e:
        # Return validation result with parsing error
        from iam_validator.core.models import ValidationIssue

        return ValidationResult(
            is_valid=False,
            issues=[
                ValidationIssue(
                    severity="error",
                    statement_index=-1,
                    issue_type="json_parse_error",
                    message=f"Failed to parse policy JSON: {e}",
                    suggestion="Ensure the policy is valid JSON format",
                    check_id="policy_structure",
                )
            ],
            policy_file="inline-policy",
        )

    # Validate the parsed policy dict
    return await validate_policy(policy=policy_dict, policy_type=policy_type)


async def quick_validate(policy: dict[str, Any]) -> dict[str, Any]:
    """Quick pass/fail validation check for a policy.

    This is a lightweight validation that returns just the essential information:
    whether the policy is valid, the number of issues found, and critical issues.
    Useful for rapid validation without detailed issue analysis.

    Args:
        policy: IAM policy as a Python dictionary

    Returns:
        Dictionary containing:
            - is_valid (bool): Whether the policy passed validation
            - issue_count (int): Total number of issues found
            - critical_issues (list[str]): List of critical/high severity issue messages
            - sensitive_actions_found (int): Count of sensitive actions detected
            - wildcards_detected (bool): Whether wildcards were found in actions/resources

    Example:
        >>> policy = {"Version": "2012-10-17", "Statement": [...]}
        >>> result = await quick_validate(policy)
        >>> if result["is_valid"]:
        ...     print("Policy is valid!")
        >>> else:
        ...     print(f"Found {result['issue_count']} issues")
        ...     for msg in result["critical_issues"]:
        ...         print(f"  - {msg}")
    """
    # Use validate_policy to get full results
    validation_result = await validate_policy(policy=policy)

    # Filter critical and high severity issues
    critical_issues = []
    sensitive_actions_count = 0
    wildcards_detected = False

    for issue in validation_result.issues:
        severity = issue.severity.lower()
        if severity in {"critical", "high", "error"}:
            critical_issues.append(issue.message)

        # Count sensitive action issues
        if issue.check_id == "sensitive_action":
            sensitive_actions_count += 1

        # Detect wildcard issues
        if issue.check_id in {"wildcard_action", "wildcard_resource", "service_wildcard"}:
            wildcards_detected = True

    # Return simplified result with enhanced fields
    return {
        "is_valid": validation_result.is_valid,
        "issue_count": len(validation_result.issues),
        "critical_issues": critical_issues,
        "sensitive_actions_found": sensitive_actions_count,
        "wildcards_detected": wildcards_detected,
    }
