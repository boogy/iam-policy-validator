"""FastMCP server implementation for IAM Policy Validator.

This module creates and configures the MCP server with all validation
and query tools registered. It serves as the main entry point
for the MCP server functionality.

Optimizations:
- Shared AWSServiceFetcher instance via lifespan context
- Cached check registry for repeated list_checks calls
- Pagination support for large result sets
- Batch operation tools for reduced round-trips
- MCP Resources for static data (checks)
"""

import logging
from typing import Any, cast

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.constants import IAM_POLICY_VERSION_CURRENT
from iam_validator.mcp.context import get_server_context, server_lifespan

logger = logging.getLogger(__name__)

# =============================================================================
# Shared resource lookups (delegate to the ServerContext built by the lifespan)
# =============================================================================


def get_aws_session(ctx: Any, region: str, profile: str | None) -> Any:
    """Return a (cached) boto3 Session for ``(region, profile)``.

    Mirrors ``get_shared_fetcher``'s fallback: if no lifespan context is
    available (tests, direct calls outside MCP), build a fresh session each
    call rather than crashing.
    """
    import boto3

    context = get_server_context(ctx)
    cache = context.aws_sessions if context is not None else None

    if cache is None:
        kwargs: dict[str, Any] = {"region_name": region}
        if profile:
            kwargs["profile_name"] = profile
        return boto3.Session(**kwargs)

    key = (region, profile)
    if key not in cache:
        kwargs = {"region_name": region}
        if profile:
            kwargs["profile_name"] = profile
        cache[key] = boto3.Session(**kwargs)
    return cache[key]


def get_shared_fetcher(ctx: Any) -> AWSServiceFetcher | None:
    """Get the shared AWSServiceFetcher from context.

    Args:
        ctx: FastMCP Context object from tool invocation

    Returns:
        Shared AWSServiceFetcher instance, or None if not available

    Note:
        When None is returned, callers typically create a new fetcher instance.
        Logged at DEBUG level — happens routinely in tests and direct callers
        outside of an MCP request context.
    """
    context = get_server_context(ctx)
    if context is not None:
        return context.fetcher

    logger.debug("Shared fetcher unavailable from context; tool will create a new one.")
    return None


# =============================================================================
# Check catalog for the iam://checks resources and registry-driven guidance
# =============================================================================


def _effective_check_settings(check_id: str, default_severity: str, ctx: Any) -> tuple[bool, str]:
    """``(enabled, severity)`` after the session config that validate_policy applies."""
    context = get_server_context(ctx)
    config = context.mutable.get_config() if context is not None and context.mutable is not None else None
    if config is None:
        return True, default_severity
    return (
        config.is_check_enabled(check_id),
        config.get_check_severity(check_id) or default_severity,
    )


def _get_check_catalog(ctx: Any = None) -> tuple[dict[str, Any], ...]:
    """Every registered check, with session-config enablement and severity resolved.

    Not cached: the session config can change between calls.
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()

    catalog: list[dict[str, Any]] = []
    for check_instance in registry.get_all_checks():
        enabled, severity = _effective_check_settings(check_instance.check_id, check_instance.default_severity, ctx)
        catalog.append(
            {
                "check_id": check_instance.check_id,
                "description": check_instance.description,
                "default_severity": check_instance.default_severity,
                "severity": severity,
                "enabled": enabled,
            }
        )
    return tuple(sorted(catalog, key=lambda x: x["check_id"]))


# =============================================================================
# Base Instructions (constant)
# =============================================================================

_BASE_INSTRUCTIONS_TEMPLATE = """
You are an AWS IAM security expert reviewing policies for least-privilege violations.

## CORE PRINCIPLES
- LEAST PRIVILEGE: Flag permissions broader than the task needs
- RESOURCE SCOPING: Specific ARNs, never wildcards for write operations
- CONDITION GUARDS: Sensitive actions (MFA, IP, time) should carry conditions

## ABSOLUTE RULES (GUARDRAIL: DO NOT REMOVE)
- NEVER guess ARN formats — use query_arn_formats
- ALWAYS validate actions exist — typos create security gaps

## VALIDATION LOOP PREVENTION (GUARDRAIL: DO NOT REMOVE)
HARD LIMIT: maximum 2 validate_policy calls per request.
Fix `error`/`critical` using the issue's `example` field; present the policy with
remaining `high`/`medium`/`low`/`warning` items as informational only.
When in doubt, PRESENT THE POLICY.

## RESOURCES
iam://checks, iam://sensitive-actions/{category},
iam://checks/{check_id}, iam://workflow-examples.
Default policy Version is "__VERSION__".
"""

BASE_INSTRUCTIONS = _BASE_INSTRUCTIONS_TEMPLATE.replace("__VERSION__", IAM_POLICY_VERSION_CURRENT)


def get_instructions(custom: str | None = None) -> str:
    """Build full instructions, appending ``custom`` (session/settings) if given."""
    if custom:
        return f"{BASE_INSTRUCTIONS}\n\n## ORGANIZATION-SPECIFIC INSTRUCTIONS\n\n{custom}"
    return BASE_INSTRUCTIONS


# Create the MCP server instance with lifespan
mcp = FastMCP(
    name="IAM Policy Validator",
    lifespan=server_lifespan,
    instructions=BASE_INSTRUCTIONS,  # Replaced with resolved instructions once the lifespan starts.
)


# =============================================================================
# Profile-based tool gating (FastMCP tag-based enable/disable)
# =============================================================================
#
# We snapshot _transforms after server construction (zero baseline transforms
# at this point) so apply_profile() can reset to a clean slate when the active
# profile changes. _transforms is a private FastMCP attribute; if FastMCP
# renames it the test in tests/mcp/test_profiles.py will catch the regression.
_BASELINE_TRANSFORMS_LEN: int = len(mcp._transforms)
_ACTIVE_PROFILE: str = "full"


PROFILE_DESCRIPTIONS: dict[str, str] = {
    "full": "All tools (default).",
    "validate-only": "Validation tools only — smallest token footprint.",
    "validate-and-query": (
        "Validation + AWS service-reference query tools. Does NOT include the live "
        "AWS Access Analyzer (use 'full' for that)."
    ),
    "read-only": (
        "Excludes any tool tagged 'mutating' (set_/clear_/load_*). Tag-based, not "
        "annotation-based — destructiveHint=False is intentional for session-only "
        "mutators per MCP spec, but they're still hidden here via the mutating tag."
    ),
}


def apply_profile(profile: str) -> None:
    """Apply tool visibility profile by tag-based enable/disable.

    Idempotent: safe to call multiple times. Resets to the baseline transform
    state before applying the new profile so successive calls don't compound.

    Args:
        profile: One of full, validate-only, validate-and-query, read-only.

    Raises:
        ValueError: Unknown profile name.
    """
    # Drop any profile-applied transforms from previous calls.
    del mcp._transforms[_BASELINE_TRANSFORMS_LEN:]

    if profile == "full":
        return
    if profile == "validate-only":
        mcp.enable(tags={"validate"}, only=True)
        return
    if profile == "validate-and-query":
        mcp.enable(tags={"validate", "query"}, only=True)
        return
    if profile == "read-only":
        mcp.disable(tags={"mutating"})
        return
    raise ValueError(f"Unknown profile: {profile}. Allowed: {sorted(PROFILE_DESCRIPTIONS.keys())}")


def set_active_profile(profile: str) -> None:
    """Record the active profile name (for `get_active_profile` introspection)."""
    global _ACTIVE_PROFILE
    _ACTIVE_PROFILE = profile


# =============================================================================
# Validation Tools
# =============================================================================


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def validate_policy(
    policy: dict[str, Any],
    ctx: Context,
    policy_type: str | None = None,
    verbose: bool = True,
    use_org_config: bool = True,
) -> dict[str, Any]:
    """Validate an IAM policy against AWS rules and security best practices.

    Auto-detects policy type (identity/resource/trust) from structure if not specified.

    Args:
        policy: IAM policy dictionary
        policy_type: "identity", "resource", or "trust" (auto-detected if None)
        verbose: Return all fields (True) or essential only (False)
        use_org_config: Apply session org config (default: True)

    Returns:
        {is_valid, issues, policy_file}
    """
    from iam_validator.mcp.tools.validation import issue_to_dict
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    result = await _validate(policy=policy, policy_type=policy_type, use_org_config=use_org_config, ctx=ctx)
    return {
        "is_valid": result.is_valid,
        "issues": [issue_to_dict(i, verbose=verbose) for i in result.issues],
        "policy_file": result.policy_file,
    }


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def quick_validate(policy: dict[str, Any], ctx: Context) -> dict[str, Any]:
    """Quick pass/fail validation returning only essential info.

    Args:
        policy: IAM policy dictionary

    Returns:
        {is_valid, issue_count, critical_issues}
    """
    from iam_validator.mcp.tools.validation import quick_validate as _quick_validate

    return await _quick_validate(policy=policy, ctx=ctx)


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_active_profile() -> dict[str, Any]:
    """Return the active MCP profile and the tools it currently exposes.

    Useful when a tool you expect is missing — confirms the server profile.
    """
    tools = await mcp.list_tools()
    return {
        "profile": _ACTIVE_PROFILE,
        "tool_count": len(tools),
        "tool_names": sorted(t.name for t in tools),
    }


@mcp.tool(
    tags={"analyze"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
)
async def aws_access_analyzer_validate(
    policy: dict[str, Any],
    ctx: Context,
    policy_type: str = "IDENTITY_POLICY",
    partition: str = "aws",
    region: str | None = None,
    profile: str | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run AWS Access Analyzer ValidatePolicy against the policy.

    This tool calls the live AWS Access Analyzer API and requires AWS
    credentials. Complements the local ``validate_policy`` tool by surfacing
    AWS-only checks (deprecated globals, type-specific rules). Slower than
    ``validate_policy`` because it incurs an HTTP round-trip per call.

    Args:
        policy: IAM policy dict (Version + Statement).
        policy_type: One of "IDENTITY_POLICY", "RESOURCE_POLICY",
            "SERVICE_CONTROL_POLICY".
        partition: AWS partition (aws, aws-cn, aws-us-gov, aws-eusc,
            aws-iso, aws-iso-b, aws-iso-e, aws-iso-f). Used to default
            ``region`` if omitted.
        region: AWS region for the API call. When omitted, defaults to the
            canonical region for the chosen ``partition`` (e.g. ``aws-cn`` →
            ``cn-north-1``).
        profile: Optional AWS profile name.
        timeout_seconds: Hard timeout on the AWS API call (default 30s).
            Prevents an unresponsive AWS endpoint from blocking the MCP server.

    Returns:
        ``{findings: [...], finding_count: int}``. Each finding has
        ``finding_type``, ``issue_code``, ``message``, ``learn_more_link``,
        ``locations``.

    Raises:
        ToolError: bad policy_type, unsupported partition, missing AWS
            credentials, AWS API failure, or timeout.
    """
    import asyncio as _asyncio

    from fastmcp.exceptions import ToolError

    from iam_validator.core.constants import PARTITION_DEFAULT_REGION
    from iam_validator.mcp.tools.analyze import analyze_policy as _analyze

    if partition not in PARTITION_DEFAULT_REGION:
        raise ToolError(f"Unsupported partition '{partition}'. Allowed: {', '.join(sorted(PARTITION_DEFAULT_REGION))}.")

    effective_region = region or PARTITION_DEFAULT_REGION[partition]

    session = get_aws_session(ctx, effective_region, profile)
    try:
        return await _asyncio.wait_for(
            _analyze(
                policy=policy,
                policy_type=policy_type,
                region=effective_region,
                profile=profile,
                session=session,
            ),
            timeout=timeout_seconds,
        )
    except _asyncio.TimeoutError as e:
        raise ToolError(f"AWS Access Analyzer call timed out after {timeout_seconds}s.") from e


# =============================================================================
# Query Tools
# =============================================================================


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def query_service_actions(
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
    from iam_validator.mcp.tools.query import query_service_actions as _query

    fetcher = get_shared_fetcher(ctx)
    all_actions = await _query(service=service, access_level=access_level, fetcher=fetcher)
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


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def query_action_details(action: str, ctx: Context) -> dict[str, Any] | None:
    """Get metadata for a specific action.

    Args:
        action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")

    Returns:
        {action, service, access_level, resource_types, condition_keys, description} or None
    """
    from iam_validator.mcp.tools.query import query_action_details as _query

    fetcher = get_shared_fetcher(ctx)
    result = await _query(action=action, fetcher=fetcher)
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


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def expand_wildcard_action(pattern: str, ctx: Context) -> list[str]:
    """Expand wildcard action pattern to specific actions.

    Args:
        pattern: Pattern with wildcards (e.g., "s3:Get*", "iam:*User*")

    Returns:
        List of matching action names
    """
    from iam_validator.mcp.tools.query import expand_wildcard_action as _expand

    fetcher = get_shared_fetcher(ctx)
    return await _expand(pattern=pattern, fetcher=fetcher)


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def query_condition_keys(service: str, ctx: Context) -> list[str]:
    """Get resource-level condition keys for a service.

    Use with get_condition_requirements_for_action for complete condition coverage (action + resource).

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of condition keys (e.g., ["s3:prefix", "s3:x-amz-acl"])
    """
    from iam_validator.mcp.tools.query import query_condition_keys as _query

    fetcher = get_shared_fetcher(ctx)
    return await _query(service=service, fetcher=fetcher)


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def query_arn_formats(service: str, ctx: Context) -> list[dict[str, Any]]:
    """Get ARN format patterns for a service's resources.

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of {resource_type, arn_formats}
    """
    from iam_validator.mcp.tools.query import query_arn_formats as _query

    fetcher = get_shared_fetcher(ctx)
    return cast(list[dict[str, Any]], await _query(service=service, fetcher=fetcher))


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_policy_summary(policy: dict[str, Any]) -> dict[str, Any]:
    """Get summary statistics for a policy.

    Args:
        policy: IAM policy dictionary

    Returns:
        {total_statements, allow_statements, deny_statements, services_used, actions_count, has_wildcards, has_conditions}
    """
    from iam_validator.mcp.tools.query import get_policy_summary as _get_summary

    result = await _get_summary(policy=policy)
    return {
        "total_statements": result.total_statements,
        "allow_statements": result.allow_statements,
        "deny_statements": result.deny_statements,
        "services_used": result.services_used,
        "actions_count": result.actions_count,
        "has_wildcards": result.has_wildcards,
        "has_conditions": result.has_conditions,
    }


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_condition_requirements_for_action(action: str) -> dict[str, Any] | None:
    """Get condition requirements for a specific action.

    Args:
        action: Full action name (e.g., "iam:PassRole", "s3:GetObject")

    Returns:
        Condition requirements dict, or None if no requirements
    """
    from iam_validator.mcp.tools.query import get_condition_requirements as _get_reqs

    return await _get_reqs(action=action)


# =============================================================================
# Fix and Help Tools
# =============================================================================


@mcp.tool(
    tags={"fix"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
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
            "related": ["iam://checks", "validate_policy"],
        }

    return {
        "check_id": check_id,
        "description": check.description,
        "default_severity": check.default_severity,
        "fix_steps": [
            "Read the issue's `message` and `suggestion` fields from validate_policy",
            "Apply the example fix from the issue, if provided",
            "Re-validate with validate_policy",
        ],
        "example_before": None,
        "example_after": None,
        "related": ["validate_policy"],
    }


# =============================================================================
# Advanced Analysis Tools
# =============================================================================


async def get_check_details(check_id: str, ctx: Any = None) -> dict[str, Any]:
    """Get full documentation for a validation check (registry-driven).

    Exposed as the parameterised MCP resource ``iam://checks/{check_id}``.

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, default_severity, category, example_violation,
         example_fix, configuration, related}
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()
    check = registry.get_check(check_id)

    if check is None:
        return {
            "check_id": check_id,
            "description": "Check not found",
            "default_severity": None,
            "category": "unknown",
            "example_violation": None,
            "example_fix": None,
            "configuration": {},
            "related": [],
        }

    enabled, severity = _effective_check_settings(check_id, check.default_severity, ctx)

    return {
        "check_id": check_id,
        "description": check.description,
        "default_severity": check.default_severity,
        "category": "general",
        "example_violation": None,
        "example_fix": None,
        "configuration": {"enabled": enabled, "severity": severity},
        "related": [],
    }


# =============================================================================
# Batch Operations (Reduced Round-Trips)
# =============================================================================


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def validate_policies_batch(
    policies: list[dict[str, Any]],
    ctx: Context,
    policy_type: str | None = None,
    verbose: bool = False,
    max_concurrency: int = 10,
) -> list[dict[str, Any]]:
    """Validate multiple IAM policies in parallel (more efficient than multiple validate_policy calls).

    Args:
        policies: List of IAM policy dictionaries
        policy_type: "identity", "resource", or "trust" (auto-detected if None)
        verbose: Return all fields (True) or essential only (False)
        max_concurrency: Maximum concurrent validations (default 10) — caps the
            thundering herd against AWS-side rate limits when N is large.

    Returns:
        List of {policy_index, is_valid, issues}
    """
    import asyncio

    from iam_validator.mcp.tools.validation import issue_to_dict
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    # Ensure shared fetcher is available (validates actions exist)
    _ = get_shared_fetcher(ctx)

    sem = asyncio.Semaphore(max(1, max_concurrency))

    async def validate_one(idx: int, policy: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            result = await _validate(policy=policy, policy_type=policy_type, ctx=ctx)
        return {
            "policy_index": idx,
            "is_valid": result.is_valid,
            "issues": [issue_to_dict(i, verbose=verbose) for i in result.issues],
        }

    # Run all validations in parallel (capped by max_concurrency)
    results = await asyncio.gather(*[validate_one(i, p) for i, p in enumerate(policies)])
    return list(results)


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def query_actions_batch(actions: list[str], ctx: Context) -> dict[str, dict[str, Any] | None]:
    """Get details for multiple actions in parallel (more efficient than multiple query_action_details calls).

    Args:
        actions: Action names (e.g., ["s3:GetObject", "iam:CreateUser"])

    Returns:
        Dict mapping action names to {service, access_level, resource_types, condition_keys} or None
    """
    import asyncio

    from iam_validator.mcp.tools.query import query_action_details as _query

    # Use shared fetcher from context
    shared_fetcher = get_shared_fetcher(ctx)

    async def query_one(action: str) -> tuple[str, dict[str, Any] | None]:
        """Query a single action and return (action, details) tuple."""
        try:
            details = await _query(action=action, fetcher=shared_fetcher)
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


@mcp.tool(
    tags={"query"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
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

    from iam_validator.core.aws_service import AWSServiceFetcher
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


# =============================================================================
# Organization Configuration Tools
# =============================================================================


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def set_organization_config(
    config: dict[str, Any],
    ctx: Context,
) -> dict[str, Any]:
    """Set validator configuration for this MCP session.

    Args:
        config: Config with "settings" (fail_on_severity, parallel_execution) and
            check IDs as keys (enabled, severity, ignore_patterns)

    Returns:
        {success, applied_config, warnings}
    """
    from iam_validator.mcp.tools.org_config_tools import set_organization_config_impl

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await set_organization_config_impl(config, session)


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_organization_config(ctx: Context) -> dict[str, Any]:
    """Get the current session organization configuration.

    Returns:
        {has_config, config, source}
    """
    from iam_validator.mcp.tools.org_config_tools import get_organization_config_impl

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await get_organization_config_impl(session)


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def clear_organization_config(ctx: Context) -> dict[str, str]:
    """Clear session organization config, reverting to defaults.

    Returns:
        {status: "cleared" or "no_config_set"}
    """
    from iam_validator.mcp.tools.org_config_tools import clear_organization_config_impl

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await clear_organization_config_impl(session)


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def load_organization_config_from_yaml(
    yaml_content: str,
    ctx: Context,
) -> dict[str, Any]:
    """Load validator configuration from YAML content and set as session config.

    Args:
        yaml_content: YAML string with settings and check configurations

    Returns:
        {success, applied_config, warnings, error}
    """
    from iam_validator.mcp.tools.org_config_tools import (
        load_organization_config_from_yaml_impl,
    )

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await load_organization_config_from_yaml_impl(yaml_content, session)


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def check_org_compliance(
    policy: dict[str, Any],
    ctx: Context,
    verbose: bool = False,
) -> dict[str, Any]:
    """Validate a policy using session org config (or defaults if none set).

    Args:
        policy: IAM policy dictionary
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {compliant, has_org_config, violations, warnings, suggestions}
    """
    from iam_validator.mcp.tools.org_config_tools import check_org_compliance_impl

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    result = await check_org_compliance_impl(policy, session, ctx=ctx)

    if not verbose:
        # Lean response: counts instead of full lists
        result["violation_count"] = len(result.get("violations", []))
        result["warning_count"] = len(result.get("warnings", []))
        if "suggestions" in result and isinstance(result["suggestions"], list):
            result["suggestion_count"] = len(result["suggestions"])
            del result["suggestions"]

    return result


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def validate_with_config(
    policy: dict[str, Any],
    config: dict[str, Any],
    ctx: Context,
    policy_type: str | None = None,
) -> dict[str, Any]:
    """Validate a policy with inline configuration (one-off, doesn't modify session).

    Args:
        policy: IAM policy to validate
        config: Same format as set_organization_config
        policy_type: "identity", "resource", or "trust" (auto-detected if None)

    Returns:
        {is_valid, issues, config_applied}
    """
    from iam_validator.mcp.tools.org_config_tools import validate_with_config_impl

    return await validate_with_config_impl(policy, config, policy_type, ctx=ctx)


# =============================================================================
# Custom Instructions Tools
# =============================================================================


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def set_custom_instructions(
    instructions: str,
    ctx: Context,
) -> dict[str, Any]:
    """Set custom validation guidelines for this session.

    Instructions are appended to default server instructions.

    Args:
        instructions: Custom instructions text (markdown supported)

    Returns:
        {success, instructions_preview, previous_source}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None

    if session is None:
        return {
            "success": False,
            "instructions_preview": None,
            "previous_source": "none",
            "error": "Session-scoped configuration is not available in hosted mode",
        }

    previous_source = session.get_instructions_source()

    session.set_instructions(instructions, source="api")

    # Update the server instructions
    mcp.instructions = get_instructions(session.get_instructions())

    preview = instructions[:200] + "..." if len(instructions) > 200 else instructions

    return {
        "success": True,
        "instructions_preview": preview,
        "previous_source": previous_source,
    }


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_custom_instructions(ctx: Context) -> dict[str, Any]:
    """Get current custom instructions.

    Returns:
        {has_instructions, instructions, source}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    instructions = session.get_instructions() if session is not None else None

    return {
        "has_instructions": instructions is not None,
        "instructions": instructions,
        "source": session.get_instructions_source() if session is not None else "none",
    }


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def clear_custom_instructions(ctx: Context) -> dict[str, str]:
    """Clear custom instructions, reverting to defaults.

    Returns:
        {status: "cleared" or "no_instructions_set"}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    had_instructions = session.clear_instructions() if session is not None else False

    # Reset to base instructions
    mcp.instructions = BASE_INSTRUCTIONS

    return {
        "status": "cleared" if had_instructions else "no_instructions_set",
    }


# =============================================================================
# MCP Resources (Static Data - Client Cacheable)
# =============================================================================


@mcp.resource("iam://checks")
async def checks_resource(ctx: Context | None = None) -> str:
    """List of all available validation checks.

    Each entry carries the check's id, description and class ``default_severity``
    plus the ``severity`` and ``enabled`` flag the current session config resolves
    to, so the catalog matches what validate_policy will actually run.
    """
    import json

    return json.dumps(_get_check_catalog(ctx), indent=2)


@mcp.resource("iam://sensitive-categories")
async def sensitive_categories_resource() -> str:
    """Sensitive action categories and their descriptions.

    This resource describes the 4 categories of sensitive actions
    that the validator tracks.
    """
    import json

    from iam_validator.core.config.sensitive_actions import SENSITIVE_ACTION_CATEGORIES

    # Convert frozensets to lists for JSON serialization
    serializable = {
        category_id: {
            "name": data["name"],
            "description": data["description"],
            "severity": data["severity"],
            "action_count": len(data["actions"]),
        }
        for category_id, data in SENSITIVE_ACTION_CATEGORIES.items()
    }

    return json.dumps(serializable, indent=2)


@mcp.resource("iam://sensitive-actions/{category}")
async def sensitive_actions_resource(category: str) -> str:
    """List sensitive actions for a category (parameterized resource).

    Replaces the former ``list_sensitive_actions`` tool. Categories:
    credential_exposure, data_access, privilege_escalation, resource_exposure.
    """
    import json

    from iam_validator.mcp.tools.query import list_sensitive_actions as _list_sensitive

    actions = await _list_sensitive(category=category)
    return json.dumps({"category": category, "actions": actions}, indent=2)


@mcp.resource("iam://checks/{check_id}")
async def check_details_resource(check_id: str, ctx: Context | None = None) -> str:
    """Per-check documentation (parameterized resource).

    Replaces the former ``get_check_details`` tool.
    """
    import json

    return json.dumps(await get_check_details(check_id, ctx), indent=2)


@mcp.resource("iam://config-schema")
def config_schema_resource() -> str:
    """JSON Schema for session configuration.

    Returns the schema for valid configuration settings,
    useful for AI assistants to validate config before setting.
    """
    import json

    from iam_validator.core.config.config_loader import SettingsSchema

    return json.dumps(SettingsSchema.model_json_schema(), indent=2)


@mcp.resource("iam://config-examples")
def config_examples_resource() -> str:
    """Example configurations for common scenarios.

    Provides examples for different security postures and use cases.
    These configurations use the same format as the CLI validator YAML config.
    All validation is done by the IAM validator's built-in checks.
    """
    return """
# Configuration Examples

These configurations can be used with both the CLI (`--config`) and MCP server.
They control which checks run and their severity levels.

## 1. Enterprise Security (Strict)
Maximum security - all wildcards are critical, sensitive actions flagged.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Make all wildcard checks critical severity
wildcard_action:
  enabled: true
  severity: critical

wildcard_resource:
  enabled: true
  severity: critical

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: critical

# Flag all sensitive/privileged actions
sensitive_action:
  enabled: true
  severity: high

# Require conditions on sensitive actions
action_condition_enforcement:
  enabled: true
  severity: error
```

## 2. Development Environment (Permissive)
Relaxed settings for dev/sandbox - only catch critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical

# Disable sensitive action warnings in dev
sensitive_action:
  enabled: false

# Lower severity for wildcards (warn but don't fail)
wildcard_action:
  enabled: true
  severity: medium

wildcard_resource:
  enabled: true
  severity: medium

# Still catch full admin access
full_wildcard:
  enabled: true
  severity: critical
```

## 3. Compliance-Focused
Emphasizes policy structure and AWS validation.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Ensure all actions are valid AWS actions
action_validation:
  enabled: true
  severity: error

# Validate condition keys and operators
condition_key_validation:
  enabled: true
  severity: error

condition_type_mismatch:
  enabled: true
  severity: error

# Ensure proper policy structure
policy_structure:
  enabled: true
  severity: error

# Check policy size limits
policy_size:
  enabled: true
  severity: error
```

## 4. Security Audit
Comprehensive security review - everything enabled at high severity.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high
    - medium

# All security checks at high severity
wildcard_action:
  enabled: true
  severity: high

wildcard_resource:
  enabled: true
  severity: high

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: high

sensitive_action:
  enabled: true
  severity: high

action_condition_enforcement:
  enabled: true
  severity: high

# Catch NotAction/NotResource anti-patterns
not_action_not_resource:
  enabled: true
  severity: high
```

## 5. Minimal Validation
Quick validation - only structural and critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
  parallel_execution: true

# Only critical checks
policy_structure:
  enabled: true
  severity: error

full_wildcard:
  enabled: true
  severity: critical

# Disable detailed checks for speed
action_validation:
  enabled: false

sensitive_action:
  enabled: false

condition_key_validation:
  enabled: false
```
"""


@mcp.resource("iam://workflow-examples")
def workflow_examples_resource() -> str:
    """Detailed workflow examples for common IAM policy tasks.

    This resource contains step-by-step examples showing how to use
    the IAM Policy Validator tools effectively.
    """
    return """
# IAM Policy Validator - Workflow Examples

## Example 1: Create Policy from Template

USER: "I need a policy for Lambda to read from S3"

STEPS:
1. list_templates → found "lambda-s3-trigger"
2. ASK USER: "What's your S3 bucket name?"
3. generate_policy_from_template(
     template_name="lambda-s3-trigger",
     variables={"bucket_name": "user-bucket", "function_name": "my-func", ...}
   )
4. validate_policy on result
5. Present validated policy to user

## Example 2: Validate Overly Permissive Policy

USER: "Validate this policy: {Action: *, Resource: *}"

STEPS:
1. validate_policy → returns issues (wildcard_action, wildcard_resource)
2. fix_policy_issues → unfixed_issues shows wildcards can't be auto-fixed
3. RESPOND to user:
   "This policy grants full admin access. I need to know:
   - Which AWS service(s) do you need access to?
   - What operations (read/write/delete)?
   - Which specific resources (bucket names, table names, etc.)?"

## Example 3: Build Custom Policy

USER: "Create a policy to read DynamoDB table 'users' and write to S3 bucket 'backups'"

STEPS:
1. suggest_actions("read DynamoDB", "dynamodb") → get read actions
2. suggest_actions("write S3", "s3") → get write actions
3. build_minimal_policy(
     actions=["dynamodb:GetItem", "dynamodb:Query", "s3:PutObject"],
     resources=[
       "arn:aws:dynamodb:us-east-1:123456789012:table/users",
       "arn:aws:s3:::backups/*"
     ]
   )
4. validate_policy on result
5. Review security_notes and present to user

## Example 4: Fix Validation Issues

USER provides policy with issues

STEPS:
1. validate_policy → returns is_valid=false with issues
2. For each issue, read the `example` field - it shows the exact fix
3. fix_policy_issues → applies auto-fixes (Version, SIDs)
4. For remaining unfixed_issues:
   - If wildcard: ask user for specific actions/resources
   - If missing condition: use get_required_conditions to see what's needed
5. Re-validate until is_valid=true

## Example 5: Research Actions

USER: "What S3 write actions exist?"

STEPS:
1. query_service_actions(service="s3", access_level="write")
2. Present the list to user
3. If they pick actions, use check_sensitive_actions to warn about risks

## Example 6: Batch Validation

USER provides multiple policies to check

STEPS:
1. validate_policies_batch(policies=[...], verbose=False)
2. For each result, show policy_index and is_valid
3. Detail issues only for invalid policies
"""


# =============================================================================
# Prompts - Guided Workflows for LLM Clients
# =============================================================================


@mcp.prompt
def generate_secure_policy(
    service: str,
    operations: str,
    resources: str,
    principal_type: str = "Lambda function",
) -> str:
    """Generate a secure IAM policy with proper validation.

    This prompt guides you through creating a least-privilege IAM policy
    that passes all critical validation checks.

    Args:
        service: AWS service (e.g., "s3", "dynamodb", "lambda")
        operations: What operations are needed (e.g., "read objects", "write items")
        resources: Specific resources (e.g., "bucket my-app-data", "table users")
        principal_type: Who needs access (e.g., "Lambda function", "EC2 instance")
    """
    return f"""Generate a secure IAM policy for the following requirement:

**Service**: {service}
**Operations needed**: {operations}
**Resources**: {resources}
**Principal**: {principal_type}

## WORKFLOW (Follow these steps in order):

### Step 1: Find a Template
Call `list_templates` to check if a pre-built secure template exists for {service}.
If found, use `generate_policy_from_template` with the resource values.

### Step 2: If No Template, Build Manually
1. Call `query_service_actions("{service}")` to find exact action names
2. Call `query_arn_formats("{service}")` to get correct ARN patterns
3. Call `build_minimal_policy` with the specific actions and resources

### Step 3: Validate ONCE
Call `validate_policy` on the generated policy.

### Step 4: Fix Only BLOCKING Issues
BLOCKING issues (MUST fix): severity = "error" or "critical"
- Use the `example` field from the issue - it shows the exact fix
- Apply the fix directly

NON-BLOCKING issues (present with warnings): severity = "high", "medium", "low", "warning"
- Do NOT try to fix these automatically
- Present them to the user as security recommendations

### Step 5: Present the Policy
Show the final policy with:
1. The complete JSON policy
2. Any non-blocking warnings as "Security Considerations"
3. Explanation of what permissions are granted

⚠️ IMPORTANT: Do NOT validate more than once. Do NOT loop trying to fix warnings.
"""


@mcp.prompt
def fix_policy_issues_workflow(policy_json: str, issues_description: str) -> str:
    """Systematic workflow to fix IAM policy validation issues.

    Use this prompt when you have a policy with validation issues and need
    to fix them systematically without getting into a loop.

    Args:
        policy_json: The IAM policy JSON that has issues
        issues_description: Description of the issues found (from validate_policy)
    """
    return f"""Fix the following IAM policy issues systematically:

**Current Policy**:
```json
{policy_json}
```

**Issues Found**:
{issues_description}

## FIX WORKFLOW (Maximum 2 iterations):

### Iteration 1: Fix All BLOCKING Issues
For each issue with severity "error" or "critical":
1. Read the `example` field - it shows exactly how to fix it
2. Apply the fix to the policy
3. For structural issues (Version, Effect case), use `fix_policy_issues` tool

### After Fixing:
Call `validate_policy` ONE more time to verify blocking issues are resolved.

### Iteration 2 (only if needed):
If new "error" or "critical" issues appeared, fix those.
If only "high/medium/low/warning" issues remain, STOP fixing.

## STOP CONDITIONS (Present policy when ANY is true):
✅ No "error" or "critical" issues remain
✅ You've done 2 fix iterations
✅ Remaining issues are "high", "medium", "low", or "warning" severity
✅ Issues require user input (e.g., "specify resource ARN")

## Final Output:
Present the policy with:
1. The fixed JSON
2. List of remaining warnings (if any) as "Security Recommendations"
3. Note: "These recommendations are informational. The policy is valid for AWS."

⚠️ DO NOT keep iterating to eliminate warnings - they are advisory only.
"""


@mcp.prompt
def review_policy_security(policy_json: str) -> str:
    """Review an existing IAM policy for security issues.

    Use this prompt to analyze a policy the user provides and give
    security recommendations without modifying it.

    Args:
        policy_json: The IAM policy JSON to review
    """
    return f"""Review this IAM policy for security issues:

```json
{policy_json}
```

## REVIEW WORKFLOW:

### Step 1: Validate
Call `validate_policy` with the policy above.

### Step 2: Check Sensitive Actions
Call `check_sensitive_actions` to identify high-risk permissions.

### Step 3: Analyze Results
Categorize issues by severity:
- 🔴 CRITICAL/ERROR: Must be fixed before deployment
- 🟠 HIGH: Strong recommendation to address
- 🟡 MEDIUM/WARNING: Best practice suggestions
- 🟢 LOW: Minor improvements

### Step 4: Present Findings
Format your response as:

**Policy Status**: [VALID / HAS BLOCKING ISSUES]

**Critical Issues** (must fix):
- [List any error/critical issues with the fix from the `example` field]

**Security Recommendations** (should consider):
- [List high/medium issues with explanations]

**Sensitive Actions Detected**:
- [List any sensitive actions and their risk category]

**Overall Assessment**:
[Brief summary of the policy's security posture]

⚠️ Do NOT attempt to fix the policy unless the user asks. Just report findings.
"""


# =============================================================================
# Server Entry Points
# =============================================================================


def create_server() -> FastMCP:
    """Create and return the configured MCP server instance.

    Returns:
        FastMCP: The configured MCP server with all tools registered
    """
    return mcp


def run_server() -> None:
    """Run the MCP server.

    This is the entry point for the iam-validator-mcp command.
    Uses stdio transport by default for Claude Desktop integration.

    Custom instructions are resolved from ``ServerSettings`` (env vars, in turn
    fed by CLI flags — see ``iam_validator.mcp.__init__``) once the lifespan
    starts, and appended to the default instructions there.
    """
    mcp.run()


__all__ = ["mcp", "create_server", "run_server", "get_instructions", "BASE_INSTRUCTIONS"]
