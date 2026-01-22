"""Query tools for the MCP server.

This module provides query tools for querying AWS service definitions,
listing validation checks, analyzing policies, and querying sensitive actions.
"""

from typing import Any

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.sensitive_actions import (
    CREDENTIAL_EXPOSURE_ACTIONS,
    DATA_ACCESS_ACTIONS,
    PRIV_ESC_ACTIONS,
    RESOURCE_EXPOSURE_ACTIONS,
)
from iam_validator.mcp.models import ActionDetails, PolicySummary
from iam_validator.sdk import get_actions_by_access_level, parse_policy, query_arn_types
from iam_validator.sdk import get_policy_summary as sdk_get_policy_summary
from iam_validator.sdk import query_action_details as sdk_query_action_details
from iam_validator.sdk import query_condition_keys as sdk_query_condition_keys


async def query_service_actions(
    service: str, access_level: str | None = None, fetcher: AWSServiceFetcher | None = None
) -> list[str]:
    """Get all actions for a service, optionally filtered by access level.

    Args:
        service: AWS service prefix (e.g., "s3", "iam", "ec2")
        access_level: Optional filter by access level (read|write|list|tagging|permissions-management)
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        List of action names (e.g., ["s3:GetObject", "s3:PutObject"])

    Example:
        >>> actions = await query_service_actions("s3")
        >>> write_actions = await query_service_actions("s3", "write")
    """
    # Use provided fetcher or create a new one
    if fetcher is not None:
        _fetcher = fetcher
        should_close = False
    else:
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        if access_level:
            # Validate access level
            valid_levels = ["read", "write", "list", "tagging", "permissions-management"]
            if access_level.lower() not in valid_levels:
                raise ValueError(
                    f"Invalid access level '{access_level}'. "
                    f"Must be one of: {', '.join(valid_levels)}"
                )
            return await get_actions_by_access_level(_fetcher, service, access_level)  # type: ignore

        # Get all actions (no filter)
        from iam_validator.sdk import query_actions

        actions = await query_actions(_fetcher, service)
        return [action["action"] for action in actions]
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def query_action_details(
    action: str, fetcher: AWSServiceFetcher | None = None
) -> ActionDetails | None:
    """Get detailed information about a specific action.

    Args:
        action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        ActionDetails object with comprehensive action metadata, or None if not found

    Example:
        >>> details = await query_action_details("s3:GetObject")
        >>> print(f"Access level: {details.access_level}")
        >>> print(f"Resource types: {details.resource_types}")
    """
    # Parse service and action name
    if ":" not in action:
        raise ValueError(f"Invalid action format '{action}'. Expected 'service:action'")

    service, action_name = action.split(":", 1)

    # Use provided fetcher or create a new one
    if fetcher is not None:
        _fetcher = fetcher
        should_close = False
    else:
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        try:
            details = await sdk_query_action_details(_fetcher, service, action_name)

            return ActionDetails(
                action=details["action"],
                service=details["service"],
                access_level=details["access_level"],
                resource_types=details["resource_types"],
                condition_keys=details["condition_keys"],
                description=details.get("description"),
            )
        except ValueError:
            # Action not found
            return None
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def expand_wildcard_action(
    pattern: str, fetcher: AWSServiceFetcher | None = None
) -> list[str]:
    """Expand wildcards like "s3:Get*" to specific actions.

    Args:
        pattern: Action pattern with wildcards (e.g., "s3:Get*", "iam:*User*")
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        List of matching action names

    Example:
        >>> actions = await expand_wildcard_action("s3:Get*")
        >>> # Returns: ["s3:GetObject", "s3:GetObjectAcl", ...]
    """
    # Use provided fetcher or create a new one
    if fetcher is not None:
        _fetcher = fetcher
        should_close = False
    else:
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        try:
            return await _fetcher.expand_wildcard_action(pattern)
        except Exception as e:
            raise ValueError(f"Failed to expand wildcard action '{pattern}': {e}") from e
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def query_condition_keys(service: str, fetcher: AWSServiceFetcher | None = None) -> list[str]:
    """Get all condition keys for a service.

    Args:
        service: AWS service prefix (e.g., "s3", "iam")
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        List of condition key names (e.g., ["s3:prefix", "s3:x-amz-acl"])

    Example:
        >>> keys = await query_condition_keys("s3")
        >>> print(f"S3 has {len(keys)} condition keys")
    """
    # Use provided fetcher or create a new one
    if fetcher is not None:
        _fetcher = fetcher
        should_close = False
    else:
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        keys = await sdk_query_condition_keys(_fetcher, service)
        return [key["condition_key"] for key in keys]
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def query_arn_formats(
    service: str, fetcher: AWSServiceFetcher | None = None
) -> list[dict[str, Any]]:
    """Get ARN formats for a service's resources.

    Args:
        service: AWS service prefix (e.g., "s3", "iam")
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        List of dictionaries with resource_type and arn_formats keys

    Example:
        >>> arns = await query_arn_formats("s3")
        >>> for arn in arns:
        ...     print(f"{arn['resource_type']}: {arn['arn_formats']}")
    """
    # Use provided fetcher or create a new one
    if fetcher is not None:
        _fetcher = fetcher
        should_close = False
    else:
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        return await query_arn_types(_fetcher, service)
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def list_checks() -> list[dict[str, Any]]:
    """List all available validation checks with id, description, severity.

    Returns:
        List of dictionaries with check_id, description, and default_severity

    Example:
        >>> checks = await list_checks()
        >>> for check in checks:
        ...     print(f"{check['check_id']}: {check['description']}")
    """
    registry = create_default_registry()
    checks = []

    for check_id, check_instance in registry._checks.items():
        checks.append(
            {
                "check_id": check_id,
                "description": check_instance.description,
                "default_severity": check_instance.default_severity,
            }
        )

    # Sort by check_id for consistent ordering
    return sorted(checks, key=lambda x: x["check_id"])


async def get_policy_summary(policy: dict[str, Any]) -> PolicySummary:
    """Analyze a policy and return summary statistics.

    Args:
        policy: IAM policy as a dictionary

    Returns:
        PolicySummary object with statistics about the policy

    Example:
        >>> summary = await get_policy_summary(policy_dict)
        >>> print(f"Total statements: {summary.total_statements}")
        >>> print(f"Services used: {summary.services_used}")
    """
    # Parse policy using SDK
    iam_policy = parse_policy(policy)

    # Get summary from SDK
    summary = sdk_get_policy_summary(iam_policy)

    # Extract services from actions
    services = set()
    for action in summary["actions"]:
        if ":" in action:
            service = action.split(":")[0]
            services.add(service)

    return PolicySummary(
        total_statements=summary["statement_count"],
        allow_statements=summary["allow_statements"],
        deny_statements=summary["deny_statements"],
        services_used=sorted(services),
        actions_count=summary["action_count"],
        has_wildcards=summary["has_wildcard_actions"] or summary["has_wildcard_resources"],
        has_conditions=summary["condition_key_count"] > 0,
    )


async def list_sensitive_actions(category: str | None = None) -> list[str]:
    """List sensitive actions, optionally filtered by category.

    Args:
        category: Optional category filter (credential_exposure|data_access|privilege_escalation|resource_exposure)

    Returns:
        List of sensitive action names

    Example:
        >>> all_sensitive = await list_sensitive_actions()
        >>> credential_actions = await list_sensitive_actions("credential_exposure")
    """
    if category is None:
        # Return all sensitive actions
        all_actions = (
            CREDENTIAL_EXPOSURE_ACTIONS
            | DATA_ACCESS_ACTIONS
            | PRIV_ESC_ACTIONS
            | RESOURCE_EXPOSURE_ACTIONS
        )
        return sorted(all_actions)

    # Normalize category name
    category_lower = category.lower()

    # Map category to action set
    category_map = {
        "credential_exposure": CREDENTIAL_EXPOSURE_ACTIONS,
        "data_access": DATA_ACCESS_ACTIONS,
        "privilege_escalation": PRIV_ESC_ACTIONS,
        "priv_esc": PRIV_ESC_ACTIONS,  # Alias
        "resource_exposure": RESOURCE_EXPOSURE_ACTIONS,
    }

    if category_lower not in category_map:
        valid_categories = [k for k in category_map.keys() if not k.endswith("_esc")]
        raise ValueError(
            f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}"
        )

    return sorted(category_map[category_lower])


async def get_condition_requirements(action: str) -> dict[str, Any] | None:
    """Get required conditions for an action.

    This function checks if the action has any condition requirements
    based on the condition requirements configuration.

    Args:
        action: Full action name (e.g., "iam:PassRole", "s3:GetObject")

    Returns:
        Dictionary with condition requirements including severity, suggestion_text,
        and required_conditions, or None if no requirements found.

    Example:
        >>> req = await get_condition_requirements("iam:PassRole")
        >>> if req:
        ...     print(req["severity"])  # "high"
        ...     print(req["suggestion_text"])  # Guidance on how to fix
    """
    import re

    try:
        from iam_validator.core.config.condition_requirements import (
            CONDITION_REQUIREMENTS,
        )
    except ImportError:
        return None

    # CONDITION_REQUIREMENTS is a list of requirement dicts
    # Each has either "actions" (list) or "action_patterns" (regex list)
    for requirement in CONDITION_REQUIREMENTS:
        # Check direct action match
        if "actions" in requirement and action in requirement["actions"]:
            return {
                "action": action,
                "severity": requirement.get("severity", "medium"),
                "suggestion_text": requirement.get("suggestion_text", ""),
                "required_conditions": requirement.get("required_conditions", []),
            }

        # Check pattern match
        if "action_patterns" in requirement:
            for pattern in requirement["action_patterns"]:
                if re.match(pattern, action):
                    return {
                        "action": action,
                        "severity": requirement.get("severity", "medium"),
                        "suggestion_text": requirement.get("suggestion_text", ""),
                        "required_conditions": requirement.get("required_conditions", []),
                    }

    return None


__all__ = [
    "query_service_actions",
    "query_action_details",
    "expand_wildcard_action",
    "query_condition_keys",
    "query_arn_formats",
    "list_checks",
    "get_policy_summary",
    "list_sensitive_actions",
    "get_condition_requirements",
]
