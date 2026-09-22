"""Query tools for the MCP server.

This module provides query tools for querying AWS service definitions,
listing validation checks, analyzing policies, and querying sensitive actions.
"""

import asyncio
from typing import Annotated, Any, Literal, cast

from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, TypeAdapter

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.sensitive_actions import (
    CREDENTIAL_EXPOSURE_ACTIONS,
    DATA_ACCESS_ACTIONS,
    PRIV_ESC_ACTIONS,
    RESOURCE_EXPOSURE_ACTIONS,
    SENSITIVE_ACTION_CATEGORIES,
    get_category_for_action,
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
# `query` — consolidated selector tool (registered via TOOLS below)
# =============================================================================

QueryKind = Literal["service_actions", "action_details", "condition_keys", "arn_formats", "expand_wildcard"]

_ACCESS_LEVELS: tuple[str, ...] = ("read", "write", "list", "tagging", "permissions-management")

# Input field each kind requires; drives both the inputSchema branches and the ToolError backstop.
_REQUIRED_PARAM_FOR_KIND: dict[QueryKind, str] = {
    "service_actions": "service",
    "action_details": "actions",
    "condition_keys": "service",
    "arn_formats": "service",
    "expand_wildcard": "patterns",
}


class SensitiveInfo(BaseModel):
    """Sensitivity classification for a single action, from the sensitive-actions catalog."""

    category: str
    severity: str
    name: str


class ServiceActionsResult(BaseModel):
    """``kind="service_actions"``: all (optionally filtered) actions for a service."""

    kind: Literal["service_actions"] = "service_actions"
    service: str
    actions: list[str]
    total: int


class ActionDetailEntry(BaseModel):
    """One action's validity, metadata and sensitivity — one entry per input action."""

    action: str
    valid: bool
    error: str | None = None
    service: str | None = None
    access_level: str | None = None
    resource_types: list[str] = Field(default_factory=list)
    condition_keys: list[str] = Field(default_factory=list)
    description: str | None = None
    sensitive: SensitiveInfo | None = None


class ActionDetailsResult(BaseModel):
    """``kind="action_details"``: batch action lookup, absorbing query_actions_batch/check_actions_batch."""

    kind: Literal["action_details"] = "action_details"
    results: list[ActionDetailEntry]


class ConditionKeysResult(BaseModel):
    """``kind="condition_keys"``: condition keys supported by a service."""

    kind: Literal["condition_keys"] = "condition_keys"
    service: str
    condition_keys: list[str]


class ArnFormatEntry(BaseModel):
    """ARN format patterns for one resource type."""

    resource_type: str
    arn_formats: list[str]


class ArnFormatsResult(BaseModel):
    """``kind="arn_formats"``: ARN format patterns for a service's resource types."""

    kind: Literal["arn_formats"] = "arn_formats"
    service: str
    arn_formats: list[ArnFormatEntry]


class ExpandWildcardEntry(BaseModel):
    """One pattern's expansion — one entry per input pattern."""

    pattern: str
    actions: list[str] = Field(default_factory=list)
    error: str | None = None


class ExpandWildcardResult(BaseModel):
    """``kind="expand_wildcard"``: batch wildcard expansion."""

    kind: Literal["expand_wildcard"] = "expand_wildcard"
    results: list[ExpandWildcardEntry]


QueryResult = Annotated[
    ServiceActionsResult | ActionDetailsResult | ConditionKeysResult | ArnFormatsResult | ExpandWildcardResult,
    Field(discriminator="kind"),
]

# Derived from QueryResult so the oneOf branches can't drift from the return type.
_QUERY_OUTPUT_SCHEMA: dict[str, Any] = TypeAdapter(QueryResult).json_schema()

# allOf/if/then marks the one parameter each `kind` requires (JSON Schema 2020-12).
_QUERY_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "kind": {
            "type": "string",
            "enum": list(_REQUIRED_PARAM_FOR_KIND),
            "description": "Which query to run; determines which other parameter is required.",
        },
        "service": {
            "type": ["string", "null"],
            "description": "AWS service prefix, e.g. 's3', 'iam'. Required for service_actions|condition_keys|arn_formats.",
        },
        "actions": {
            "type": ["array", "null"],
            "items": {"type": "string"},
            "description": "Full action names, e.g. ['s3:GetObject']. Required for action_details.",
        },
        "patterns": {
            "type": ["array", "null"],
            "items": {"type": "string"},
            "description": "Wildcard action patterns, e.g. ['s3:Get*']. Required for expand_wildcard.",
        },
        "access_level": {
            "type": ["string", "null"],
            "enum": [*_ACCESS_LEVELS, None],
            "description": "Optional access-level filter for service_actions.",
        },
        "name_filter": {
            "type": ["string", "null"],
            "description": "Optional case-insensitive substring filter on action names for service_actions.",
        },
    },
    "required": ["kind"],
    "allOf": [
        {
            "if": {"properties": {"kind": {"const": kind}}, "required": ["kind"]},
            "then": {"required": [param]},
        }
        for kind, param in _REQUIRED_PARAM_FOR_KIND.items()
    ],
    "additionalProperties": False,
}


def _sensitive_info(action: str) -> SensitiveInfo | None:
    category = get_category_for_action(action)
    if category is None:
        return None
    category_data = SENSITIVE_ACTION_CATEGORIES[category]
    return SensitiveInfo(category=category, severity=category_data["severity"], name=category_data["name"])


async def _query_action_details_batch(actions: list[str], fetcher: AWSServiceFetcher | None) -> list[ActionDetailEntry]:
    """Batch existence-check + metadata + sensitivity lookup, in request order.

    Absorbs query_actions_batch and check_actions_batch. Uses
    ``validate_actions_batch`` for validity, which — unlike ``parse_action`` —
    returns a normal result for an action it cannot parse instead of raising.
    """
    _fetcher = fetcher if fetcher is not None else AWSServiceFetcher()
    should_close = fetcher is None
    if should_close:
        await _fetcher.__aenter__()
    try:
        validity = await _fetcher.validate_actions_batch(actions)

        async def build_entry(action: str) -> ActionDetailEntry:
            is_valid, error, _is_wildcard = validity.get(action, (False, "Unknown error", False))
            entry = ActionDetailEntry(action=action, valid=is_valid, error=None if is_valid else error)
            if is_valid:
                details = await query_action_details(action=action, fetcher=_fetcher)
                if details is not None:
                    entry.service = details.service
                    entry.access_level = details.access_level
                    entry.resource_types = details.resource_types
                    entry.condition_keys = details.condition_keys
                    entry.description = details.description
            entry.sensitive = _sensitive_info(action)
            return entry

        return list(await asyncio.gather(*[build_entry(action) for action in actions]))
    finally:
        if should_close:
            await _fetcher.__aexit__(None, None, None)


async def _expand_wildcard_batch(patterns: list[str], fetcher: AWSServiceFetcher | None) -> list[ExpandWildcardEntry]:
    """Batch wildcard expansion, in request order. Absorbs the single-pattern tool."""

    async def expand_one(pattern: str) -> ExpandWildcardEntry:
        try:
            actions = await expand_wildcard_action(pattern=pattern, fetcher=fetcher)
            return ExpandWildcardEntry(pattern=pattern, actions=actions)
        except ValueError as e:
            return ExpandWildcardEntry(pattern=pattern, error=str(e))

    return list(await asyncio.gather(*[expand_one(p) for p in patterns]))


async def query(
    kind: QueryKind,
    ctx: Context,
    service: str | None = None,
    actions: list[str] | None = None,
    patterns: list[str] | None = None,
    access_level: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """Query AWS service/action reference data. One selector for five query kinds.

    Consolidates the former query_service_actions, query_action_details,
    query_actions_batch, check_actions_batch, query_condition_keys,
    query_arn_formats and expand_wildcard_action tools.

    Args:
        kind: Which query to run — service_actions|action_details|condition_keys
            |arn_formats|expand_wildcard. Determines which other parameter is
            required (see the field descriptions below).
        service: AWS service prefix, e.g. "s3", "iam". Required for
            service_actions, condition_keys, arn_formats.
        actions: Full action names, e.g. ["s3:GetObject"]. Required for
            action_details; validity, metadata and sensitivity are checked
            for every entry, in request order (batch — was two tools).
        patterns: Wildcard action patterns, e.g. ["s3:Get*"]. Required for
            expand_wildcard, expanded in request order (batch).
        access_level: Optional read|write|list|tagging|permissions-management
            filter, service_actions only.
        name_filter: Optional case-insensitive substring filter on action
            names, service_actions only.

    Returns:
        A ``{kind, ...}`` object whose remaining shape is fixed by ``kind``
        (see ``query``'s output schema for the exact branch).
    """
    required_param = _REQUIRED_PARAM_FOR_KIND.get(kind)
    if required_param is None:
        raise ToolError(f"kind: invalid value {kind!r}. Must be one of: {', '.join(_REQUIRED_PARAM_FOR_KIND)}")

    provided = {"service": service, "actions": actions, "patterns": patterns}[required_param]
    if not provided:
        raise ToolError(f"kind={kind!r} requires '{required_param}'")

    fetcher = get_shared_fetcher(ctx)

    try:
        if kind == "service_actions":
            assert service is not None
            result_actions = await query_service_actions(service=service, access_level=access_level, fetcher=fetcher)
            if name_filter:
                needle = name_filter.lower()
                result_actions = [a for a in result_actions if needle in a.lower()]
            return ServiceActionsResult(service=service, actions=result_actions, total=len(result_actions)).model_dump()

        if kind == "action_details":
            assert actions is not None
            entries = await _query_action_details_batch(actions, fetcher)
            return ActionDetailsResult(results=entries).model_dump()

        if kind == "condition_keys":
            assert service is not None
            keys = await query_condition_keys(service=service, fetcher=fetcher)
            return ConditionKeysResult(service=service, condition_keys=keys).model_dump()

        if kind == "arn_formats":
            assert service is not None
            arn_formats = cast(list[dict[str, Any]], await query_arn_formats(service=service, fetcher=fetcher))
            return ArnFormatsResult(
                service=service, arn_formats=[ArnFormatEntry(**a) for a in arn_formats]
            ).model_dump()

        assert kind == "expand_wildcard"
        assert patterns is not None
        entries = await _expand_wildcard_batch(patterns, fetcher)
        return ExpandWildcardResult(results=entries).model_dump()
    except ValueError as e:
        raise ToolError(f"kind={kind!r}, service={service!r}: {e}") from e


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
        name="query",
        fn=query,
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        output_schema=_QUERY_OUTPUT_SCHEMA,
        input_schema=_QUERY_INPUT_SCHEMA,
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
    "query",
    "get_issue_guidance",
    "TOOLS",
]
