"""Query tools for the MCP server.

This module provides query tools for querying AWS service definitions,
listing validation checks, analyzing policies, and querying sensitive actions.
"""

from typing import Any, cast

from fastmcp import Context
from mcp.types import ToolAnnotations

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.sensitive_actions import (
    CREDENTIAL_EXPOSURE_ACTIONS,
    DATA_ACCESS_ACTIONS,
    PRIV_ESC_ACTIONS,
    RESOURCE_EXPOSURE_ACTIONS,
)
from iam_validator.mcp.component_spec import ToolSpec, infer_output_schema
from iam_validator.mcp.context import get_server_context, get_shared_fetcher
from iam_validator.mcp.models import ActionDetails, PolicySummary
from iam_validator.sdk import ArnTypeInfo, get_actions_by_access_level, parse_policy, query_arn_types
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
                raise ValueError(f"Invalid access level '{access_level}'. Must be one of: {', '.join(valid_levels)}")
            return await get_actions_by_access_level(_fetcher, service, access_level)  # type: ignore

        # Get all actions (no filter)
        from iam_validator.sdk import query_actions

        actions = await query_actions(_fetcher, service)
        return [action["action"] for action in actions]
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def query_action_details(action: str, fetcher: AWSServiceFetcher | None = None) -> ActionDetails | None:
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


async def expand_wildcard_action(pattern: str, fetcher: AWSServiceFetcher | None = None) -> list[str]:
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


async def query_arn_formats(service: str, fetcher: AWSServiceFetcher | None = None) -> list[ArnTypeInfo]:
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
        all_actions = CREDENTIAL_EXPOSURE_ACTIONS | DATA_ACCESS_ACTIONS | PRIV_ESC_ACTIONS | RESOURCE_EXPOSURE_ACTIONS
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
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}")

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


# =============================================================================
# MCP tool wrappers (registered via TOOLS below)
# =============================================================================


async def _query_service_actions_tool(
    service: str,
    ctx: Context,
    access_level: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    verbose: bool = False,
) -> dict[str, Any]:
    """Get all actions for a service, optionally filtered by access level.

    Args:
        service: Service prefix (e.g., "s3", "iam", "ec2")
        access_level: Filter: read|write|list|tagging|permissions-management
        limit: Max actions to return
        offset: Skip N actions for pagination
        verbose: Return full action details (True) or names only (False)

    Returns:
        {actions, total, has_more}
    """
    fetcher = get_shared_fetcher(ctx)
    all_actions = await query_service_actions(service=service, access_level=access_level, fetcher=fetcher)
    total = len(all_actions)

    # Apply pagination
    if offset:
        all_actions = all_actions[offset:]
    if limit:
        all_actions = all_actions[:limit]

    # Lean response: just action names as strings if not verbose
    if not verbose and all_actions and isinstance(all_actions[0], dict):
        all_actions = [a.get("name", a) if isinstance(a, dict) else a for a in all_actions]

    return {
        "actions": all_actions,
        "total": total,
        "has_more": offset + len(all_actions) < total,
    }


async def _query_action_details_tool(action: str, ctx: Context) -> dict[str, Any] | None:
    """Get metadata for a specific action.

    Args:
        action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")

    Returns:
        {action, service, access_level, resource_types, condition_keys, description} or None
    """
    fetcher = get_shared_fetcher(ctx)
    result = await query_action_details(action=action, fetcher=fetcher)
    if result is None:
        return None
    return {
        "action": result.action,
        "service": result.service,
        "access_level": result.access_level,
        "resource_types": result.resource_types,
        "condition_keys": result.condition_keys,
        "description": result.description,
    }


async def _expand_wildcard_action_tool(pattern: str, ctx: Context) -> list[str]:
    """Expand wildcard action pattern to specific actions.

    Args:
        pattern: Pattern with wildcards (e.g., "s3:Get*", "iam:*User*")

    Returns:
        List of matching action names
    """
    fetcher = get_shared_fetcher(ctx)
    return await expand_wildcard_action(pattern=pattern, fetcher=fetcher)


async def _query_condition_keys_tool(service: str, ctx: Context) -> list[str]:
    """Get resource-level condition keys for a service.

    Use with get_condition_requirements_for_action for complete condition coverage (action + resource).

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of condition keys (e.g., ["s3:prefix", "s3:x-amz-acl"])
    """
    fetcher = get_shared_fetcher(ctx)
    return await query_condition_keys(service=service, fetcher=fetcher)


async def _query_arn_formats_tool(service: str, ctx: Context) -> list[dict[str, Any]]:
    """Get ARN format patterns for a service's resources.

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of {resource_type, arn_formats}
    """
    fetcher = get_shared_fetcher(ctx)
    return cast(list[dict[str, Any]], await query_arn_formats(service=service, fetcher=fetcher))


async def get_condition_requirements_for_action(action: str) -> dict[str, Any] | None:
    """Get condition requirements for a specific action.

    Args:
        action: Full action name (e.g., "iam:PassRole", "s3:GetObject")

    Returns:
        Condition requirements dict, or None if no requirements
    """
    return await get_condition_requirements(action=action)


async def query_actions_batch(actions: list[str], ctx: Context) -> dict[str, dict[str, Any] | None]:
    """Get details for multiple actions in parallel (more efficient than multiple query_action_details calls).

    Args:
        actions: Action names (e.g., ["s3:GetObject", "iam:CreateUser"])

    Returns:
        Dict mapping action names to {service, access_level, resource_types, condition_keys} or None
    """
    import asyncio

    # Use shared fetcher from context
    shared_fetcher = get_shared_fetcher(ctx)

    async def query_one(action: str) -> tuple[str, dict[str, Any] | None]:
        """Query a single action and return (action, details) tuple."""
        try:
            details = await query_action_details(action=action, fetcher=shared_fetcher)
            if details:
                return (
                    action,
                    {
                        "service": details.service,
                        "access_level": details.access_level,
                        "resource_types": details.resource_types,
                        "condition_keys": details.condition_keys,
                        "description": details.description,
                    },
                )
            return (action, None)
        except Exception:
            return (action, None)

    # Run all queries in parallel
    query_results = await asyncio.gather(*[query_one(action) for action in actions])
    return dict(query_results)


async def check_actions_batch(
    actions: list[str],
    ctx: Context,
    verbose: bool = False,
) -> dict[str, Any]:
    """Validate existence and check sensitivity for multiple actions in parallel.

    Args:
        actions: AWS actions to check (e.g., ["s3:GetObject", "iam:PassRole"])
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {valid_actions, invalid_actions, sensitive_actions}
    """
    import asyncio

    from iam_validator.core.config.sensitive_actions import (
        SENSITIVE_ACTION_CATEGORIES,
        get_category_for_action,
    )

    async def check_one_action(action: str, fetcher: AWSServiceFetcher) -> dict[str, Any]:
        """Check a single action for validity and sensitivity."""
        result: dict[str, Any] = {
            "action": action,
            "is_valid": False,
            "error": None,
            "sensitive": None,
        }

        # Check if action is valid
        try:
            if "*" in action:
                # Wildcard - try to expand
                expanded = await fetcher.expand_wildcard_action(action)
                if expanded:
                    result["is_valid"] = True
                else:
                    result["error"] = "No matching actions"
            else:
                is_valid, error, _ = await fetcher.validate_action(action)
                if is_valid:
                    result["is_valid"] = True
                else:
                    result["error"] = error or "Unknown error"
        except Exception as e:
            result["error"] = str(e)

        # Check sensitivity (even for invalid actions - they might be typos of sensitive ones)
        category = get_category_for_action(action)
        if category:
            category_data = SENSITIVE_ACTION_CATEGORIES[category]
            result["sensitive"] = {
                "category": category,
                "severity": category_data["severity"],
                "name": category_data["name"],
            }

        return result

    # Try to get shared fetcher from context, fall back to creating new one
    shared_fetcher = get_shared_fetcher(ctx)
    if shared_fetcher:
        # Use shared fetcher - run all checks in parallel
        check_results = await asyncio.gather(*[check_one_action(action, shared_fetcher) for action in actions])
    else:
        # Fall back to creating new fetcher
        async with AWSServiceFetcher() as fetcher:
            check_results = await asyncio.gather(*[check_one_action(action, fetcher) for action in actions])

    # Aggregate results
    valid_actions: list[str] = []
    invalid_actions: list[dict[str, str]] = []
    sensitive_actions: list[dict[str, Any]] = []

    for result in check_results:
        action = result["action"]
        if result["is_valid"]:
            valid_actions.append(action)
        elif result["error"]:
            invalid_actions.append({"action": action, "error": result["error"]})

        if result["sensitive"]:
            sensitive_actions.append({"action": action, **result["sensitive"]})

    if verbose:
        return {
            "valid_actions": valid_actions,
            "invalid_actions": invalid_actions,
            "sensitive_actions": sensitive_actions,
        }
    else:
        return {
            "valid_actions": valid_actions,
            "invalid_count": len(invalid_actions),
            "sensitive_count": len(sensitive_actions),
            "invalid_actions": [ia["action"] for ia in invalid_actions],
            "sensitive_actions": [sa["action"] for sa in sensitive_actions],
        }


async def get_issue_guidance(check_id: str, ctx: Context) -> dict[str, Any]:
    """Get fix guidance for a validation issue (registry-driven).

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, default_severity, fix_steps,
         example_before, example_after, related}
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()
    check = registry.get_check(check_id)

    if check is None:
        return {
            "check_id": check_id,
            "description": f"Unknown check: {check_id}",
            "default_severity": None,
            "fix_steps": [
                "Read the iam://checks resource for the catalog of available checks.",
            ],
            "example_before": None,
            "example_after": None,
            "related": ["iam://checks", "validate_policies"],
        }

    return {
        "check_id": check_id,
        "description": check.description,
        "default_severity": check.default_severity,
        "fix_steps": [
            "Read the issue's `message` and `suggestion` fields from validate_policies",
            "Apply the example fix from the issue, if provided",
            "Re-validate with validate_policies",
        ],
        "example_before": None,
        "example_after": None,
        "related": ["validate_policies"],
    }


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="query",
        name="query_service_actions",
        fn=_query_service_actions_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_query_service_actions_tool),
    ),
    ToolSpec(
        tag="query",
        name="query_action_details",
        fn=_query_action_details_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_query_action_details_tool),
    ),
    ToolSpec(
        tag="query",
        name="expand_wildcard_action",
        fn=_expand_wildcard_action_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_expand_wildcard_action_tool),
    ),
    ToolSpec(
        tag="query",
        name="query_condition_keys",
        fn=_query_condition_keys_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_query_condition_keys_tool),
    ),
    ToolSpec(
        tag="query",
        name="query_arn_formats",
        fn=_query_arn_formats_tool,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(_query_arn_formats_tool),
    ),
    ToolSpec(
        tag="query",
        name="get_condition_requirements_for_action",
        fn=get_condition_requirements_for_action,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(get_condition_requirements_for_action),
    ),
    ToolSpec(
        tag="query",
        name="query_actions_batch",
        fn=query_actions_batch,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(query_actions_batch),
    ),
    ToolSpec(
        tag="query",
        name="check_actions_batch",
        fn=check_actions_batch,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(check_actions_batch),
    ),
    ToolSpec(
        tag="fix",
        name="get_issue_guidance",
        fn=get_issue_guidance,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=infer_output_schema(get_issue_guidance),
    ),
)


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
    "get_condition_requirements_for_action",
    "query_actions_batch",
    "check_actions_batch",
    "get_issue_guidance",
    "TOOLS",
]
