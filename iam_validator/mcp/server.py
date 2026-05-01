"""FastMCP server implementation for IAM Policy Validator.

This module creates and configures the MCP server with all validation,
generation, and query tools registered. It serves as the main entry point
for the MCP server functionality.

Optimizations:
- Shared AWSServiceFetcher instance via lifespan context
- Cached check registry for repeated list_checks calls
- Pagination support for large result sets
- Batch operation tools for reduced round-trips
- MCP Resources for static data (templates, checks)
"""

import functools
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry, create_default_registry
from iam_validator.core.constants import (
    IAM_POLICY_VERSION_CURRENT,
    IAM_POLICY_VERSIONS_VALID,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Lifespan Management - Shared Resources
# =============================================================================


@asynccontextmanager
async def server_lifespan(_server: FastMCP):
    """Manage server lifecycle with shared resources.

    This context manager initializes expensive resources once at startup
    and shares them across all tool invocations via the Context object.
    """
    # Initialize shared AWSServiceFetcher
    fetcher = AWSServiceFetcher(
        prefetch_common=True,  # Pre-fetch common services at startup
        memory_cache_size=512,  # Larger cache for server use
    )
    await fetcher.__aenter__()

    # Cache boto3 sessions per (region, profile) — Session() costs ~50ms each.
    aws_sessions: dict[tuple[str, str | None], Any] = {}

    try:
        yield {"fetcher": fetcher, "aws_sessions": aws_sessions}
    finally:
        await fetcher.__aexit__(None, None, None)


def get_aws_session(ctx: Any, region: str, profile: str | None) -> Any:
    """Return a (cached) boto3 Session for ``(region, profile)``.

    Mirrors ``get_shared_fetcher``'s fallback: if no lifespan context is
    available (tests, direct calls outside MCP), build a fresh session each
    call rather than crashing.
    """
    import boto3

    lifespan = getattr(getattr(ctx, "request_context", None), "lifespan_context", None)
    cache = lifespan.get("aws_sessions") if isinstance(lifespan, dict) else None

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
    if ctx and hasattr(ctx, "request_context") and ctx.request_context:
        lifespan_ctx = ctx.request_context.lifespan_context
        if lifespan_ctx and "fetcher" in lifespan_ctx:
            return lifespan_ctx["fetcher"]

    logger.debug("Shared fetcher unavailable from context; tool will create a new one.")
    return None


# =============================================================================
# Cached Registry for list_checks and registry-driven guidance
# =============================================================================

# Module-level: built once at import. Tools just read.
# create_default_registry() is sync and cheap (no I/O, just instantiates check
# classes), so eager init eliminates any race-condition surface.
_REGISTRY: CheckRegistry = create_default_registry()


@functools.lru_cache(maxsize=1)
def _get_cached_checks() -> tuple[dict[str, Any], ...]:
    """Get cached check registry (initialized once, thread-safe via lru_cache)."""
    return tuple(
        sorted(
            [
                {
                    "check_id": check_instance.check_id,
                    "description": check_instance.description,
                    "default_severity": check_instance.default_severity,
                }
                for check_instance in _REGISTRY.get_all_checks()
            ],
            key=lambda x: x["check_id"],
        )
    )


# =============================================================================
# Base Instructions (constant)
# =============================================================================

_BASE_INSTRUCTIONS_TEMPLATE = """
You are an AWS IAM security expert generating secure, least-privilege policies.

## CORE PRINCIPLES
- LEAST PRIVILEGE: Only permissions needed for the task
- RESOURCE SCOPING: Specific ARNs, never wildcards for write operations
- CONDITION GUARDS: Add conditions for sensitive actions (MFA, IP, time)

## ABSOLUTE RULES (GUARDRAIL: DO NOT REMOVE)
- NEVER generate `"Action": "*"` or `"Resource": "*"` with write actions
- NEVER allow `iam:*`, `sts:AssumeRole`, `kms:*` without conditions
- NEVER guess ARN formats — use query_arn_formats
- ALWAYS validate actions exist — typos create security gaps
- ALWAYS present security_notes from generation tools

## VALIDATION LOOP PREVENTION (GUARDRAIL: DO NOT REMOVE)
HARD LIMIT: maximum 2 validate_policy calls per request.
Fix `error`/`critical` using the issue's `example` field; present the policy with
remaining `high`/`medium`/`low`/`warning` items as informational only.
When in doubt, PRESENT THE POLICY.

## RESOURCES
iam://templates, iam://checks, iam://sensitive-actions/{category},
iam://checks/{check_id}, iam://workflow-examples.
Default policy Version is "__VERSION__".
"""

BASE_INSTRUCTIONS = _BASE_INSTRUCTIONS_TEMPLATE.replace("__VERSION__", IAM_POLICY_VERSION_CURRENT)


def get_instructions() -> str:
    """Build full instructions including any custom instructions.

    Returns:
        Combined base instructions + custom instructions (if set)
    """
    from iam_validator.mcp.session_config import CustomInstructionsManager

    custom = CustomInstructionsManager.get_instructions()
    if custom:
        return f"{BASE_INSTRUCTIONS}\n\n## ORGANIZATION-SPECIFIC INSTRUCTIONS\n\n{custom}"
    return BASE_INSTRUCTIONS


# Create the MCP server instance with lifespan
mcp = FastMCP(
    name="IAM Policy Validator",
    lifespan=server_lifespan,
    instructions=BASE_INSTRUCTIONS,  # Will be updated dynamically in run_server()
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
        "AWS Access Analyzer (use 'full' or 'no-generation' for that)."
    ),
    "no-generation": "Everything except policy generation tools.",
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
        profile: One of full, validate-only, validate-and-query, no-generation,
            read-only.

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
    if profile == "no-generation":
        mcp.disable(tags={"generation"})
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

    result = await _validate(policy=policy, policy_type=policy_type, use_org_config=use_org_config)
    return {
        "is_valid": result.is_valid,
        "issues": [issue_to_dict(i, verbose=verbose) for i in result.issues],
        "policy_file": result.policy_file,
    }


@mcp.tool(
    tags={"validate"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def quick_validate(policy: dict[str, Any]) -> dict[str, Any]:
    """Quick pass/fail validation returning only essential info.

    Args:
        policy: IAM policy dictionary

    Returns:
        {is_valid, issue_count, critical_issues}
    """
    from iam_validator.mcp.tools.validation import quick_validate as _quick_validate

    return await _quick_validate(policy=policy)


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
# Generation Tools
# =============================================================================


@mcp.tool(
    tags={"generation"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def generate_policy_from_template(
    template_name: str,
    variables: dict[str, str],
    verbose: bool = False,
) -> dict[str, Any]:
    """Generate an IAM policy from a built-in template.

    Call list_templates first to see available templates and required variables.

    Args:
        template_name: Template name (e.g., "s3-read-only", "lambda-basic-execution")
        variables: Template variables (e.g., {"bucket_name": "my-bucket", "account_id": "123456789012"})
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {policy, validation, security_notes, template_used}
    """
    from iam_validator.mcp.tools.generation import (
        generate_policy_from_template as _generate,
    )
    from iam_validator.mcp.tools.validation import issue_to_dict

    result = await _generate(template_name=template_name, variables=variables)

    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": [issue_to_dict(i, verbose=verbose) for i in result.validation.issues],
        },
        "security_notes": result.security_notes,
        "template_used": result.template_used,
    }


@mcp.tool(
    tags={"generation"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def build_minimal_policy(
    actions: list[str],
    resources: list[str],
    conditions: dict[str, Any] | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Build a minimal IAM policy from explicit actions and resources.

    Args:
        actions: AWS actions (e.g., ["s3:GetObject", "s3:ListBucket"])
        resources: Resource ARNs (e.g., ["arn:aws:s3:::my-bucket/*"])
        conditions: Optional conditions to add
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {policy, validation, security_notes}
    """
    from iam_validator.mcp.tools.generation import build_minimal_policy as _build
    from iam_validator.mcp.tools.validation import issue_to_dict

    result = await _build(actions=actions, resources=resources, conditions=conditions)

    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": [issue_to_dict(i, verbose=verbose) for i in result.validation.issues],
        },
        "security_notes": result.security_notes,
    }


@mcp.tool(
    tags={"generation"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def suggest_actions(
    description: str,
    service: str | None = None,
) -> list[str]:
    """Suggest AWS actions based on natural language description.

    Args:
        description: What you need (e.g., "read files from S3")
        service: Optional service filter (e.g., "s3", "lambda")

    Returns:
        List of suggested action names
    """
    from iam_validator.mcp.tools.generation import suggest_actions as _suggest

    return await _suggest(description=description, service=service)


@mcp.tool(
    tags={"generation"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_required_conditions(actions: list[str]) -> dict[str, Any]:
    """Get recommended IAM conditions for actions based on security best practices.

    NOTE: Also check query_condition_keys(service) for resource-level conditions.

    Args:
        actions: AWS actions to analyze (e.g., ["iam:PassRole"])

    Returns:
        Condition requirements grouped by type
    """
    from iam_validator.mcp.tools.generation import (
        get_required_conditions as _get_conditions,
    )

    return await _get_conditions(actions=actions)


@mcp.tool(
    tags={"generation"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def check_sensitive_actions(
    actions: list[str],
    verbose: bool = False,
) -> dict[str, Any]:
    """Check if actions are sensitive and get remediation guidance.

    Analyzes actions against 490+ sensitive actions catalog. Also verify
    resource-level conditions with query_condition_keys(service).

    Args:
        actions: Actions to check (e.g., ["iam:PassRole", "s3:GetObject"])
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {sensitive_actions, total_checked, sensitive_count, categories_found, has_critical, summary}
    """
    from iam_validator.mcp.tools.generation import (
        check_sensitive_actions as _check_sensitive,
    )

    result = await _check_sensitive(actions=actions)

    if not verbose and "sensitive_actions" in result:
        # Lean response: only essential fields per action
        result["sensitive_actions"] = [
            {
                "action": sa.get("action"),
                "category": sa.get("category"),
                "severity": sa.get("severity"),
            }
            for sa in result.get("sensitive_actions", [])
        ]

    return result


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

    Use with get_required_conditions for complete condition coverage (action + resource).

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
    return await _query(service=service, fetcher=fetcher)


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
async def fix_policy_issues(
    policy: dict[str, Any],
    issues_to_fix: list[str] | None = None,
    policy_type: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Auto-fix structural policy issues (Version, duplicate SIDs, action case).

    Does NOT fix wildcards or missing conditions - those need user input.

    Args:
        policy: IAM policy to fix
        issues_to_fix: Check IDs to fix (None = all structural fixes)
        policy_type: "identity", "resource", or "trust" (auto-detected if None)
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {fixed_policy, fixes_applied, unfixed_issues, validation}
    """
    import copy

    from iam_validator.mcp.tools.validation import _detect_policy_type
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    fixed_policy = copy.deepcopy(policy)
    fixes_applied: list[str] = []
    unfixed_issues: list[dict[str, Any]] = []

    # Auto-detect policy type if not provided
    effective_policy_type = policy_type if policy_type else _detect_policy_type(policy)

    # First, validate to get current issues
    initial_result = await _validate(policy=policy, policy_type=effective_policy_type)
    issue_check_ids = {issue.check_id for issue in initial_result.issues if issue.check_id}

    # Apply fixes based on check_ids
    def should_fix(check_id: str) -> bool:
        return issues_to_fix is None or check_id in issues_to_fix

    # Fix 1: Missing or invalid Version (structural fix)
    if should_fix("policy_structure"):
        if "Version" not in fixed_policy or fixed_policy.get("Version") not in IAM_POLICY_VERSIONS_VALID:
            fixed_policy["Version"] = IAM_POLICY_VERSION_CURRENT
            fixes_applied.append(f"Added Version: {IAM_POLICY_VERSION_CURRENT}")

    # Fix 2: Duplicate SIDs (structural fix)
    if should_fix("sid_uniqueness") and "sid_uniqueness" in issue_check_ids:
        statements = fixed_policy.get("Statement", [])
        seen_sids: dict[str, int] = {}
        for i, stmt in enumerate(statements):
            sid = stmt.get("Sid")
            if sid:
                if sid in seen_sids:
                    new_sid = f"{sid}_{i}"
                    stmt["Sid"] = new_sid
                    fixes_applied.append(f"Renamed duplicate SID '{sid}' to '{new_sid}'")
                else:
                    seen_sids[sid] = i

    # Fix 3: Normalize action case (service prefix should be lowercase) on
    # both Action AND NotAction. Service prefixes in IAM are always lowercase;
    # `S3:GetObject` is invalid AWS syntax regardless of which key holds it.
    if should_fix("action_validation"):
        statements = fixed_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            for action_key in ("Action", "NotAction"):
                if action_key not in stmt:
                    continue
                actions = stmt[action_key]
                was_string = isinstance(actions, str)
                if was_string:
                    actions = [actions]

                normalized = []
                for action in actions:
                    if ":" in action:
                        service, name = action.split(":", 1)
                        if service != service.lower():
                            new_action = f"{service.lower()}:{name}"
                            normalized.append(new_action)
                            fixes_applied.append(f"Normalized {action_key} case: {action} → {new_action}")
                        else:
                            normalized.append(action)
                    else:
                        normalized.append(action)

                if normalized:
                    stmt[action_key] = normalized[0] if (was_string and len(normalized) == 1) else normalized

    # Collect issues that require manual intervention
    # Include the example and suggestion from the validator for guidance
    for issue in initial_result.issues:
        check_id = issue.check_id or "unknown"

        # Skip structural issues we can fix
        if check_id in {"policy_structure", "sid_uniqueness", "action_validation"}:
            continue

        # All other issues need manual fix - include validator's guidance
        unfixed_issues.append(
            {
                "check_id": check_id,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "severity": issue.severity,
            }
        )

    from iam_validator.mcp.tools.validation import issue_to_dict

    # Re-validate the fixed policy
    final_result = await _validate(policy=fixed_policy, policy_type=effective_policy_type)

    return {
        "fixed_policy": fixed_policy,
        "fixes_applied": fixes_applied,
        "unfixed_issues": unfixed_issues,
        "unfixed_count": len(unfixed_issues),
        "validation": {
            "is_valid": final_result.is_valid,
            "issue_count": len(final_result.issues),
            "issues": [issue_to_dict(i, verbose=verbose) for i in final_result.issues],
        },
    }


@mcp.tool(
    tags={"fix"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_issue_guidance(check_id: str) -> dict[str, Any]:
    """Get fix guidance for a validation issue (registry-driven).

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, default_severity, fix_steps,
         example_before, example_after, related}
    """
    from iam_validator.mcp.check_metadata import get_check_metadata

    check = _REGISTRY.get_check(check_id)
    metadata = get_check_metadata(check_id)

    if check is None and not metadata:
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
        "description": check.description if check else metadata.get("description", ""),
        "default_severity": check.default_severity if check else None,
        "fix_steps": metadata.get(
            "fix_steps",
            [
                "Read the issue's `message` and `suggestion` fields from validate_policy",
                "Apply the example fix from the issue, if provided",
                "Re-validate with validate_policy",
            ],
        ),
        "example_before": metadata.get("example_violation"),
        "example_after": metadata.get("example_fix"),
        "related": metadata.get("related", ["validate_policy", "fix_policy_issues"]),
    }


# =============================================================================
# Advanced Analysis Tools
# =============================================================================


async def get_check_details(check_id: str) -> dict[str, Any]:
    """Get full documentation for a validation check (registry-driven).

    Exposed as the parameterised MCP resource ``iam://checks/{check_id}``.

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, default_severity, category, example_violation,
         example_fix, configuration, related}
    """
    from iam_validator.mcp.check_metadata import get_check_metadata

    check = _REGISTRY.get_check(check_id)
    metadata = get_check_metadata(check_id)

    if check is None:
        return {
            "check_id": check_id,
            "description": "Check not found",
            "default_severity": None,
            "category": metadata.get("category", "unknown"),
            "example_violation": metadata.get("example_violation"),
            "example_fix": metadata.get("example_fix"),
            "configuration": {},
            "related": metadata.get("related", []),
        }

    return {
        "check_id": check_id,
        "description": check.description,
        "default_severity": check.default_severity,
        "category": metadata.get("category", "general"),
        "example_violation": metadata.get("example_violation"),
        "example_fix": metadata.get("example_fix"),
        "configuration": {"enabled": True, "severity": check.default_severity},
        "related": metadata.get("related", []),
    }


@mcp.tool(
    tags={"fix"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def explain_policy(
    policy: dict[str, Any],
    ctx: Context,
    verbose: bool = False,
) -> dict[str, Any]:
    """Generate a human-readable explanation of policy permissions.

    Access-level classification is sourced from the live AWS service reference
    (Read / Write / List / Tagging / Permissions management) — not a name-prefix
    heuristic. NotAction / NotResource / Principal / NotPrincipal are surfaced
    explicitly because they invert the meaning of a statement.

    Args:
        policy: IAM policy dictionary
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {summary, statements, services_accessed, security_concerns,
         recommendations, has_wildcards, has_conditions}
    """
    from iam_validator.checks.utils.action_parser import parse_action
    from iam_validator.mcp.tools.query import get_policy_summary as _get_summary
    from iam_validator.sdk.query_utils import _get_access_level

    summary = await _get_summary(policy)

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    fetcher = get_shared_fetcher(ctx)

    # Cache fetched service definitions across statements (one fetch per service).
    service_cache: dict[str, Any] = {}

    async def _classify(action: str) -> str:
        """Authoritative access-level for one action via the live service ref.

        Returns one of: "full" (`*` or `service:*`), "wildcard-pattern"
        (e.g. `s3:Get*`), "Read"/"Write"/"List"/"Tagging"/"permissions-management"
        for resolved actions, or "unknown" when the lookup fails.
        """
        if action == "*":
            return "full"
        parsed = parse_action(action)
        if parsed is None:
            return "unknown"
        if parsed.action_name == "*":
            return "full"
        if "*" in parsed.action_name:
            return "wildcard-pattern"
        if fetcher is None:
            return "unknown"
        try:
            if parsed.service not in service_cache:
                service_cache[parsed.service] = await fetcher.fetch_service_by_name(parsed.service)
            service_detail = service_cache[parsed.service]
            actions_dict = getattr(service_detail, "actions", {}) or {}
            # Case-insensitive lookup; AWS canonical casing varies.
            detail = actions_dict.get(parsed.action_name)
            if detail is None:
                for k, v in actions_dict.items():
                    if k.lower() == parsed.action_name.lower():
                        detail = v
                        break
            if detail is None:
                return "unknown"
            return _get_access_level(detail)
        except Exception:
            return "unknown"

    def _as_list(v: Any) -> list[Any]:
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    statement_explanations: list[dict[str, Any]] = []
    security_concerns: list[str] = []
    recommendations: list[str] = []
    services_with_access: dict[str, set[str]] = {}

    total_allow = 0
    total_deny = 0

    for idx, stmt in enumerate(statements):
        effect_raw = (stmt.get("Effect") or "Allow").strip()
        effect_lower = effect_raw.lower()
        if effect_lower == "allow":
            total_allow += 1
        elif effect_lower == "deny":
            total_deny += 1

        actions = _as_list(stmt.get("Action"))
        not_actions = _as_list(stmt.get("NotAction"))
        resources = _as_list(stmt.get("Resource"))
        not_resources = _as_list(stmt.get("NotResource"))
        principal = stmt.get("Principal")
        not_principal = stmt.get("NotPrincipal")
        conditions = stmt.get("Condition") or {}

        action_list = actions or not_actions
        action_negated = bool(not_actions and not actions)

        # Per-service access classification using the authoritative service ref.
        for action in action_list:
            if action == "*":
                services_with_access.setdefault("*", set()).add("full")
                continue
            level = await _classify(str(action))
            parsed = parse_action(str(action))
            service = parsed.service if parsed else "*"
            services_with_access.setdefault(service, set()).add(level)

        # Security concerns. Allow + wildcards is the classic anti-pattern; the
        # `Not*` keywords flip the meaning so they get their own concern lines.
        if effect_lower == "allow":
            if any(a == "*" for a in actions):
                if any(r == "*" for r in resources):
                    security_concerns.append(
                        f"Statement {idx}: Allow Action:*, Resource:* — full administrative access."
                    )
                    recommendations.append(
                        f'Statement {idx}: replace `Action: "*"` and `Resource: "*"` with explicit values.'
                    )
                else:
                    security_concerns.append(
                        f"Statement {idx}: Allow Action:* — grants every action on the listed resources."
                    )
                    recommendations.append(f'Statement {idx}: replace `Action: "*"` with the explicit action list.')
            elif any(r == "*" for r in resources):
                security_concerns.append(f"Statement {idx}: Allow with Resource:* — scope resources to specific ARNs.")
                recommendations.append(f'Statement {idx}: replace `Resource: "*"` with explicit ARN(s).')

            if not_actions:
                security_concerns.append(
                    f"Statement {idx}: Effect:Allow with NotAction is an anti-pattern — "
                    "the Allow surface is everything *except* the listed actions."
                )
                recommendations.append(
                    f"Statement {idx}: prefer an explicit `Action` allow-list. "
                    "If you mean to deny, use `Effect:Deny` with `Action`."
                )
            if not_resources:
                security_concerns.append(
                    f"Statement {idx}: NotResource is rarely correct — implicit allow on every "
                    "ARN except the listed ones."
                )

        # Trust-policy / resource-policy concerns.
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            security_concerns.append(f"Statement {idx}: Principal AWS:* — allows access from any AWS account.")
        elif principal == "*":
            security_concerns.append(f"Statement {idx}: Principal:* — anonymous public access.")
        if not_principal:
            security_concerns.append(
                f"Statement {idx}: NotPrincipal is fragile — confirm intent (negation in resource policies)."
            )

        # Per-statement explanation.
        action_desc_field = "NotAction" if action_negated else "Action"
        action_desc = ", ".join(map(str, action_list[:3])) + ("..." if len(action_list) > 3 else "")
        resource_desc_field = "NotResource" if (not_resources and not resources) else "Resource"
        resource_target = not_resources if (not_resources and not resources) else resources
        resource_desc = ", ".join(map(str, resource_target[:2])) + ("..." if len(resource_target) > 2 else "")
        condition_desc = f" with {len(conditions)} condition(s)" if conditions else ""

        explanation = (
            f"{effect_raw}s {action_desc_field} {action_desc or '<empty>'} "
            f"on {resource_desc_field} {resource_desc or '<empty>'}{condition_desc}"
        )
        statement_explanations.append(
            {
                "index": idx,
                "sid": stmt.get("Sid", f"Statement{idx}"),
                "effect": effect_raw,
                "uses_not_action": action_negated,
                "uses_not_resource": bool(not_resources and not resources),
                "explanation": explanation,
                "action_count": len(action_list),
                "has_conditions": bool(conditions),
                "condition_keys": sorted(
                    {k for op_block in conditions.values() if isinstance(op_block, dict) for k in op_block.keys()}
                )
                if isinstance(conditions, dict)
                else [],
            }
        )

    services_summary = [
        {"service": service, "access_types": sorted(levels)} for service, levels in sorted(services_with_access.items())
    ]

    brief_summary = (
        f"Policy with {len(statements)} statement(s): "
        f"{total_allow} Allow, {total_deny} Deny across {len(services_with_access)} service(s)"
    )

    if verbose:
        return {
            "summary": brief_summary,
            "statements": statement_explanations,
            "services_accessed": services_summary,
            "security_concerns": security_concerns,
            "recommendations": recommendations,
            "has_wildcards": summary.has_wildcards,
            "has_conditions": summary.has_conditions,
        }
    return {
        "summary": brief_summary,
        "security_concerns": security_concerns,
        "recommendations": recommendations,
        "has_wildcards": summary.has_wildcards,
        "statement_count": len(statement_explanations),
        "services_count": len(services_summary),
    }


@mcp.tool(
    tags={"fix"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def build_arn(
    service: str,
    resource_type: str,
    ctx: Context,
    placeholders: dict[str, str] | None = None,
    resource_name: str | None = None,
    region: str = "",
    account_id: str = "",
    partition: str = "aws",
) -> dict[str, Any]:
    """Build an AWS ARN from the live AWS service reference.

    Call query_arn_formats(service) first to discover placeholder names for the
    target resource_type. Returns valid=False with unfilled_placeholders when
    input is incomplete.

    Args:
        service: AWS service prefix (e.g., "s3", "lambda")
        resource_type: Resource type (e.g., "bucket", "function") — must match
            the live service reference exactly (case-insensitive).
        placeholders: Map of {placeholder_name: value} for resource-specific
            placeholders (e.g., {"BucketName": "my-bucket"}). Use either the
            bare name or `${Name}` form.
        resource_name: DEPRECATED. Pass `placeholders={...}` instead. Removal
            target: v1.21.0. When set on a single-placeholder template (and
            placeholders is empty), the value is substituted automatically.
        region: AWS region. Required for templates that contain `${Region}`.
        account_id: 12-digit AWS account ID. Required for templates that
            contain `${Account}`.
        partition: AWS partition. Supported: aws, aws-cn, aws-us-gov, aws-eusc,
            aws-iso, aws-iso-b, aws-iso-e, aws-iso-f.

    Returns:
        {arn, valid, notes, format_template, unfilled_placeholders}

    Raises:
        ToolError: input-validation errors (bad partition, unknown resource_type).
    """
    import logging as _logging
    import re as _re

    from fastmcp.exceptions import ToolError

    from iam_validator.core.constants import ARN_PARTITION_REGEX
    from iam_validator.mcp.tools.query import query_arn_formats

    if not _re.fullmatch(ARN_PARTITION_REGEX, partition):
        raise ToolError(
            f"Unsupported partition '{partition}'. "
            "Allowed: aws, aws-cn, aws-us-gov, aws-eusc, aws-iso, aws-iso-b, aws-iso-e, aws-iso-f."
        )

    fetcher = get_shared_fetcher(ctx)
    arn_types = await query_arn_formats(service, fetcher=fetcher)

    matched = next(
        (t for t in arn_types if t.get("resource_type", "").lower() == resource_type.lower()),
        None,
    )
    if matched is None:
        raise ToolError(
            f"Unknown resource_type '{resource_type}' for service '{service}'. "
            f"Use query_arn_formats('{service}') to see available types."
        )

    formats = matched.get("arn_formats") or []
    template = formats[0] if formats else None
    if template is None:
        raise ToolError(f"No ARN format published for {service}/{resource_type}.")

    arn = template.replace("${Partition}", partition).replace("${Region}", region).replace("${Account}", account_id)

    user_map = placeholders or {}
    for key, value in user_map.items():
        token = key if key.startswith("${") and key.endswith("}") else f"${{{key}}}"
        arn = arn.replace(token, value)

    remaining = _re.findall(r"\$\{[^}]+\}", arn)

    if resource_name is not None:
        _logging.getLogger(__name__).warning(
            "build_arn(resource_name=...) is deprecated; "
            "pass placeholders={'<Name>': value} instead. Removal target: v1.21.0."
        )
        if len(remaining) == 1 and not user_map:
            arn = arn.replace(remaining[0], resource_name)
            remaining = []

    notes: list[str] = []
    if not region and "${Region}" in template:
        notes.append("Region is required for this ARN format.")
    if not account_id and "${Account}" in template:
        notes.append("Account ID is required for this ARN format.")
    if remaining:
        notes.append(f"Unfilled placeholders remain: {remaining}. Pass them via the `placeholders` dict.")

    return {
        "arn": arn,
        "valid": not remaining and "${Region}" not in arn and "${Account}" not in arn,
        "notes": notes,
        "format_template": template,
        "unfilled_placeholders": remaining,
    }


@mcp.tool(
    tags={"fix"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def compare_policies(
    policy_a: dict[str, Any],
    policy_b: dict[str, Any],
    verbose: bool = False,
) -> dict[str, Any]:
    """Compare two IAM policies and highlight differences.

    Compares actions, NotActions, resources, NotResources, principals,
    NotPrincipals, and conditions independently. Statement-level matching uses
    a canonical signature (effect + sorted actions + sorted resources +
    canonical conditions) — NOT statement index — so a Sid-less rearrangement
    doesn't produce phantom diffs.

    Args:
        policy_a: First policy (baseline)
        policy_b: Second policy (comparison)
        verbose: Return all fields (True) or essential only (False)

    Returns:
        ``{summary, added_actions, removed_actions, added_resources,
        removed_resources, added_not_actions, removed_not_actions,
        added_not_resources, removed_not_resources, added_principals,
        removed_principals, condition_changes, statement_diff}``
    """
    import json as _json

    def _norm_list(v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return [str(x) for x in v]

    def _norm_principal(p: Any) -> list[str]:
        """Flatten Principal/NotPrincipal into a sorted set of "Type:Value" pairs."""
        if p is None:
            return []
        if p == "*":
            return ["*:*"]
        if isinstance(p, dict):
            out: list[str] = []
            for ptype, vals in p.items():
                vals = _norm_list(vals)
                out.extend(f"{ptype}:{v}" for v in vals)
            return sorted(out)
        return [str(p)]

    def _canon_condition(cond: Any) -> str:
        """Canonical JSON for deep condition equality (sorted keys)."""
        if not cond:
            return ""
        try:
            return _json.dumps(cond, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return repr(cond)

    def extract(policy: dict[str, Any]) -> dict[str, Any]:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        actions: set[str] = set()
        not_actions: set[str] = set()
        resources: set[str] = set()
        not_resources: set[str] = set()
        principals: set[str] = set()
        not_principals: set[str] = set()
        condition_keys: set[str] = set()
        # Canonical statement signatures, used for stable per-statement diff.
        signatures: set[tuple[str, ...]] = set()

        for stmt in statements:
            effect = (stmt.get("Effect") or "Allow").strip().lower()
            stmt_actions = sorted(_norm_list(stmt.get("Action")))
            stmt_not_actions = sorted(_norm_list(stmt.get("NotAction")))
            stmt_resources = sorted(_norm_list(stmt.get("Resource")))
            stmt_not_resources = sorted(_norm_list(stmt.get("NotResource")))
            stmt_principals = _norm_principal(stmt.get("Principal"))
            stmt_not_principals = _norm_principal(stmt.get("NotPrincipal"))
            stmt_cond = _canon_condition(stmt.get("Condition"))

            actions.update(stmt_actions)
            not_actions.update(stmt_not_actions)
            resources.update(stmt_resources)
            not_resources.update(stmt_not_resources)
            principals.update(stmt_principals)
            not_principals.update(stmt_not_principals)

            cond_dict = stmt.get("Condition") or {}
            if isinstance(cond_dict, dict):
                for op_block in cond_dict.values():
                    if isinstance(op_block, dict):
                        condition_keys.update(op_block.keys())

            signatures.add(
                (
                    effect,
                    "/".join(stmt_actions),
                    "/".join(stmt_not_actions),
                    "/".join(stmt_resources),
                    "/".join(stmt_not_resources),
                    "/".join(stmt_principals),
                    "/".join(stmt_not_principals),
                    stmt_cond,
                )
            )

        return {
            "actions": actions,
            "not_actions": not_actions,
            "resources": resources,
            "not_resources": not_resources,
            "principals": principals,
            "not_principals": not_principals,
            "condition_keys": condition_keys,
            "signatures": signatures,
        }

    a = extract(policy_a)
    b = extract(policy_b)

    added_actions = sorted(b["actions"] - a["actions"])
    removed_actions = sorted(a["actions"] - b["actions"])
    added_not_actions = sorted(b["not_actions"] - a["not_actions"])
    removed_not_actions = sorted(a["not_actions"] - b["not_actions"])
    added_resources = sorted(b["resources"] - a["resources"])
    removed_resources = sorted(a["resources"] - b["resources"])
    added_not_resources = sorted(b["not_resources"] - a["not_resources"])
    removed_not_resources = sorted(a["not_resources"] - b["not_resources"])
    added_principals = sorted(b["principals"] - a["principals"])
    removed_principals = sorted(a["principals"] - b["principals"])
    added_not_principals = sorted(b["not_principals"] - a["not_principals"])
    removed_not_principals = sorted(a["not_principals"] - b["not_principals"])
    added_condition_keys = sorted(b["condition_keys"] - a["condition_keys"])
    removed_condition_keys = sorted(a["condition_keys"] - b["condition_keys"])

    statements_added = len(b["signatures"] - a["signatures"])
    statements_removed = len(a["signatures"] - b["signatures"])

    parts: list[str] = []
    if added_actions or removed_actions:
        parts.append(f"{len(added_actions)} action(s) added, {len(removed_actions)} removed")
    if added_not_actions or removed_not_actions:
        parts.append(f"NotAction: +{len(added_not_actions)}/-{len(removed_not_actions)}")
    if added_resources or removed_resources:
        parts.append(f"{len(added_resources)} resource(s) added, {len(removed_resources)} removed")
    if added_not_resources or removed_not_resources:
        parts.append(f"NotResource: +{len(added_not_resources)}/-{len(removed_not_resources)}")
    if added_principals or removed_principals:
        parts.append(f"Principal: +{len(added_principals)}/-{len(removed_principals)}")
    if added_condition_keys or removed_condition_keys:
        parts.append(f"condition keys: +{len(added_condition_keys)}/-{len(removed_condition_keys)}")
    if statements_added or statements_removed:
        parts.append(f"statements: +{statements_added}/-{statements_removed}")

    summary = "; ".join(parts) if parts else "No significant differences found"

    full = {
        "summary": summary,
        "added_actions": added_actions,
        "removed_actions": removed_actions,
        "added_not_actions": added_not_actions,
        "removed_not_actions": removed_not_actions,
        "added_resources": added_resources,
        "removed_resources": removed_resources,
        "added_not_resources": added_not_resources,
        "removed_not_resources": removed_not_resources,
        "added_principals": added_principals,
        "removed_principals": removed_principals,
        "added_not_principals": added_not_principals,
        "removed_not_principals": removed_not_principals,
        "added_condition_keys": added_condition_keys,
        "removed_condition_keys": removed_condition_keys,
        "statements_added": statements_added,
        "statements_removed": statements_removed,
    }
    if verbose:
        return full
    # Lean: counts only, but always include `summary` and the headline added/removed lists.
    return {
        "summary": summary,
        "added_actions_count": len(added_actions),
        "removed_actions_count": len(removed_actions),
        "added_resources_count": len(added_resources),
        "removed_resources_count": len(removed_resources),
        "added_principals_count": len(added_principals),
        "removed_principals_count": len(removed_principals),
        "statements_added": statements_added,
        "statements_removed": statements_removed,
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
            result = await _validate(policy=policy, policy_type=policy_type)
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
) -> dict[str, Any]:
    """Set validator configuration for this MCP session.

    Args:
        config: Config with "settings" (fail_on_severity, parallel_execution) and
            check IDs as keys (enabled, severity, ignore_patterns)

    Returns:
        {success, applied_config, warnings}
    """
    from iam_validator.mcp.tools.org_config_tools import set_organization_config_impl

    return await set_organization_config_impl(config)


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_organization_config() -> dict[str, Any]:
    """Get the current session organization configuration.

    Returns:
        {has_config, config, source}
    """
    from iam_validator.mcp.tools.org_config_tools import get_organization_config_impl

    return await get_organization_config_impl()


@mcp.tool(
    tags={"orgconfig", "mutating"},
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def clear_organization_config() -> dict[str, str]:
    """Clear session organization config, reverting to defaults.

    Returns:
        {status: "cleared" or "no_config_set"}
    """
    from iam_validator.mcp.tools.org_config_tools import clear_organization_config_impl

    return await clear_organization_config_impl()


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

    return await load_organization_config_from_yaml_impl(yaml_content)


@mcp.tool(
    tags={"orgconfig"},
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def check_org_compliance(
    policy: dict[str, Any],
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

    result = await check_org_compliance_impl(policy)

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

    return await validate_with_config_impl(policy, config, policy_type)


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
) -> dict[str, Any]:
    """Set custom policy generation guidelines for this session.

    Instructions are appended to default server instructions.

    Args:
        instructions: Custom instructions text (markdown supported)

    Returns:
        {success, instructions_preview, previous_source}
    """
    from iam_validator.mcp.session_config import CustomInstructionsManager

    previous_source = CustomInstructionsManager.get_source()

    CustomInstructionsManager.set_instructions(instructions, source="api")

    # Update the server instructions
    mcp.instructions = get_instructions()

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
async def get_custom_instructions() -> dict[str, Any]:
    """Get current custom instructions.

    Returns:
        {has_instructions, instructions, source}
    """
    from iam_validator.mcp.session_config import CustomInstructionsManager

    instructions = CustomInstructionsManager.get_instructions()

    return {
        "has_instructions": instructions is not None,
        "instructions": instructions,
        "source": CustomInstructionsManager.get_source(),
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
async def clear_custom_instructions() -> dict[str, str]:
    """Clear custom instructions, reverting to defaults.

    Returns:
        {status: "cleared" or "no_instructions_set"}
    """
    from iam_validator.mcp.session_config import CustomInstructionsManager

    had_instructions = CustomInstructionsManager.clear_instructions()

    # Reset to base instructions
    mcp.instructions = BASE_INSTRUCTIONS

    return {
        "status": "cleared" if had_instructions else "no_instructions_set",
    }


# =============================================================================
# MCP Resources (Static Data - Client Cacheable)
# =============================================================================


@mcp.resource("iam://templates")
async def templates_resource() -> str:
    """List of all available policy templates.

    This resource provides metadata about built-in policy templates
    that can be used with generate_policy_from_template.
    """
    import json

    from iam_validator.mcp.tools.generation import list_templates as _list_templates

    templates = await _list_templates()
    return json.dumps(templates, indent=2)


@mcp.resource("iam://checks")
async def checks_resource() -> str:
    """List of all available validation checks.

    This resource provides metadata about all validation checks
    including their IDs, descriptions, and default severities.
    """
    import json

    return json.dumps(_get_cached_checks(), indent=2)


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
async def check_details_resource(check_id: str) -> str:
    """Per-check documentation (parameterized resource).

    Replaces the former ``get_check_details`` tool.
    """
    import json

    return json.dumps(await get_check_details(check_id), indent=2)


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
  parallel: true

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

    Custom instructions are loaded from:
    1. Environment variable: IAM_VALIDATOR_MCP_INSTRUCTIONS
    2. Config file: custom_instructions key in YAML config
    3. CLI: --instructions or --instructions-file arguments

    These are appended to the default instructions.
    """
    from iam_validator.mcp.session_config import CustomInstructionsManager

    # Try to load custom instructions from environment if not already set
    if not CustomInstructionsManager.has_instructions():
        CustomInstructionsManager.load_from_env()

    # Apply custom instructions if any
    mcp.instructions = get_instructions()

    mcp.run()


__all__ = ["mcp", "create_server", "run_server", "get_instructions", "BASE_INSTRUCTIONS"]
