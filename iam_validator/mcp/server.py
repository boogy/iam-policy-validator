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

from iam_validator.core.aws_service import AWSServiceFetcher

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

    try:
        # Store fetcher in server context for tools to access
        yield {"fetcher": fetcher}
    finally:
        # Cleanup on shutdown
        await fetcher.__aexit__(None, None, None)


def get_shared_fetcher(ctx: Any) -> AWSServiceFetcher | None:
    """Get the shared AWSServiceFetcher from context.

    Args:
        ctx: FastMCP Context object from tool invocation

    Returns:
        Shared AWSServiceFetcher instance, or None if not available

    Note:
        When None is returned, callers typically create a new fetcher instance.
        This is logged as a warning since it may lead to:
        - Redundant HTTP connections
        - Cache misses (new fetcher has empty cache)
        - Potential performance degradation
    """
    if ctx and hasattr(ctx, "request_context") and ctx.request_context:
        lifespan_ctx = ctx.request_context.lifespan_context
        if lifespan_ctx and "fetcher" in lifespan_ctx:
            return lifespan_ctx["fetcher"]

    logger.warning(
        "Shared fetcher unavailable from context. A new fetcher instance will be created, which may impact performance."
    )
    return None


# =============================================================================
# Cached Registry for list_checks
# =============================================================================


@functools.lru_cache(maxsize=1)
def _get_cached_checks() -> tuple[dict[str, Any], ...]:
    """Get cached check registry (initialized once, thread-safe via lru_cache)."""
    from iam_validator.core.check_registry import create_default_registry

    registry = create_default_registry()
    return tuple(
        sorted(
            [
                {
                    "check_id": check_id,
                    "description": check_instance.description,
                    "default_severity": check_instance.default_severity,
                }
                for check_id, check_instance in registry._checks.items()
            ],
            key=lambda x: x["check_id"],
        )
    )


# =============================================================================
# Base Instructions (constant)
# =============================================================================

BASE_INSTRUCTIONS = """
You are an AWS IAM security expert generating secure, least-privilege policies.

## CORE PRINCIPLES
- LEAST PRIVILEGE: Only permissions needed for the task
- RESOURCE SCOPING: Specific ARNs, never wildcards for write operations
- CONDITION GUARDS: Add conditions for sensitive actions (MFA, IP, time)

## ABSOLUTE RULES (GUARDRAIL: DO NOT REMOVE)
- NEVER generate `"Action": "*"` or `"Resource": "*"` with write actions
- NEVER allow `iam:*`, `sts:AssumeRole`, `kms:*` without conditions
- NEVER guess ARN formats - use query_arn_formats
- ALWAYS validate actions exist - typos create security gaps
- ALWAYS present security_notes from generation tools

## VALIDATION LOOP PREVENTION (GUARDRAIL: DO NOT REMOVE)

⛔ **HARD LIMIT: Maximum 2 validate_policy calls per request**

| Severity | Action |
|----------|--------|
| error/critical | Fix using `example` field |
| high/medium/low/warning | **PRESENT AS-IS** - informational only |

**Workflow:**
1. Generate policy (template or build_minimal_policy)
2. validate_policy (call #1) → fix error/critical only
3. validate_policy (call #2) → **FINAL - present policy with any warnings**

**Stop signs:** Called validate >2 times, same warning repeating, trying to "fix" warnings.
**When in doubt: PRESENT THE POLICY.**

## SENSITIVE ACTIONS (490+ tracked)
- credential_exposure (CRITICAL): sts:AssumeRole, iam:CreateAccessKey → MFA, IP limits
- privilege_escalation (CRITICAL): iam:AttachUserPolicy, iam:PassRole → resource scope
- data_access/resource_exposure (HIGH): s3:GetObject, s3:PutBucketPolicy → scope, encryption

## TOOL QUICK REFERENCE
| Task | Tool |
|------|------|
| Create policy | list_templates → generate_policy_from_template, or build_minimal_policy |
| Validate | validate_policy (full) or quick_validate (summary) |
| Fix structure | fix_policy_issues (Version, SIDs, case) |
| Fix guidance | get_issue_guidance or issue.example field |
| Find actions | query_service_actions or suggest_actions |
| ARN formats | query_arn_formats |
| Batch ops | validate_policies_batch, query_actions_batch |

## CONDITION KEYS (IMPORTANT)
When adding conditions, check BOTH:
1. **Action conditions**: Use get_required_conditions or query_action_details for action-specific keys
2. **Resource conditions**: Use query_condition_keys(service) - resources have their own condition keys
Example: s3:GetObject supports action conditions AND s3 bucket/object resource conditions (s3:prefix, etc.)

## ANTI-PATTERNS
- `"Resource": "arn:aws:s3:::*"` → use specific bucket ARN
- `"Action": "s3:*"` → use specific actions with resources
- `iam:PassRole` without `iam:PassedToService` condition

## TRUST POLICIES
Principal required, Resource not used. Auto-detected by validate_policy.
Use generate_policy_from_template("cross-account-assume-role") for cross-account.

## IAM ACTION FORMAT (CRITICAL)
Format: `<service>:<ActionName>` (e.g., `s3:GetObject`, `lambda:InvokeFunction`)
- Service: lowercase (`s3`, not `S3`)
- Action: PascalCase (`GetObject`, not `getobject`)
- Wildcards: `s3:Get*`, `s3:*`

## POLICY STRUCTURE
```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}]}
```
- Version: Always "2012-10-17"
- Effect: "Allow" or "Deny" (exact case)
- Use query_arn_formats for correct ARN patterns

## RESOURCES
- iam://templates, iam://checks, iam://workflow-examples
- Prompts: generate_secure_policy, fix_policy_issues_workflow, review_policy_security
"""


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
# Validation Tools
# =============================================================================


@mcp.tool()
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
    from iam_validator.mcp.tools.validation import validate_policy as _validate

    result = await _validate(policy=policy, policy_type=policy_type, use_org_config=use_org_config)

    # Build issue list based on verbosity
    if verbose:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "check_id": issue.check_id,
                "statement_index": issue.statement_index,
                "action": getattr(issue, "action", None),
                "resource": getattr(issue, "resource", None),
                "field_name": getattr(issue, "field_name", None),
                "risk_explanation": issue.risk_explanation,
                "documentation_url": issue.documentation_url,
                "remediation_steps": issue.remediation_steps,
            }
            for issue in result.issues
        ]
    else:
        # Lean response - only essential fields
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "check_id": issue.check_id,
            }
            for issue in result.issues
        ]

    return {
        "is_valid": result.is_valid,
        "issues": issues,
        "policy_file": result.policy_file,
    }


@mcp.tool()
async def quick_validate(policy: dict[str, Any]) -> dict[str, Any]:
    """Quick pass/fail validation returning only essential info.

    Args:
        policy: IAM policy dictionary

    Returns:
        {is_valid, issue_count, critical_issues}
    """
    from iam_validator.mcp.tools.validation import quick_validate as _quick_validate

    return await _quick_validate(policy=policy)


# =============================================================================
# Generation Tools
# =============================================================================


@mcp.tool()
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

    result = await _generate(template_name=template_name, variables=variables)

    if verbose:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "check_id": issue.check_id,
                "risk_explanation": issue.risk_explanation,
                "remediation_steps": issue.remediation_steps,
            }
            for issue in result.validation.issues
        ]
    else:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "check_id": issue.check_id,
            }
            for issue in result.validation.issues
        ]

    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": issues,
        },
        "security_notes": result.security_notes,
        "template_used": result.template_used,
    }


@mcp.tool()
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

    result = await _build(actions=actions, resources=resources, conditions=conditions)

    if verbose:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "check_id": issue.check_id,
                "risk_explanation": issue.risk_explanation,
                "remediation_steps": issue.remediation_steps,
            }
            for issue in result.validation.issues
        ]
    else:
        issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "check_id": issue.check_id,
            }
            for issue in result.validation.issues
        ]

    return {
        "policy": result.policy,
        "validation": {
            "is_valid": result.validation.is_valid,
            "issues": issues,
        },
        "security_notes": result.security_notes,
    }


@mcp.tool()
async def list_templates() -> list[dict[str, Any]]:
    """List available policy templates and their required variables.

    Call this before generate_policy_from_template.

    Returns:
        List of {name, description, variables}
    """
    from iam_validator.mcp.tools.generation import list_templates as _list_templates

    return await _list_templates()


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
async def query_service_actions(
    service: str,
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

    all_actions = await _query(service=service, access_level=access_level)
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


@mcp.tool()
async def query_action_details(action: str) -> dict[str, Any] | None:
    """Get metadata for a specific action.

    Args:
        action: Full action name (e.g., "s3:GetObject", "iam:CreateUser")

    Returns:
        {action, service, access_level, resource_types, condition_keys, description} or None
    """
    from iam_validator.mcp.tools.query import query_action_details as _query

    result = await _query(action=action)
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


@mcp.tool()
async def expand_wildcard_action(pattern: str) -> list[str]:
    """Expand wildcard action pattern to specific actions.

    Args:
        pattern: Pattern with wildcards (e.g., "s3:Get*", "iam:*User*")

    Returns:
        List of matching action names
    """
    from iam_validator.mcp.tools.query import expand_wildcard_action as _expand

    return await _expand(pattern=pattern)


@mcp.tool()
async def query_condition_keys(service: str) -> list[str]:
    """Get resource-level condition keys for a service.

    Use with get_required_conditions for complete condition coverage (action + resource).

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of condition keys (e.g., ["s3:prefix", "s3:x-amz-acl"])
    """
    from iam_validator.mcp.tools.query import query_condition_keys as _query

    return await _query(service=service)


@mcp.tool()
async def query_arn_formats(service: str) -> list[dict[str, Any]]:
    """Get ARN format patterns for a service's resources.

    Args:
        service: Service prefix (e.g., "s3", "iam")

    Returns:
        List of {resource_type, arn_formats}
    """
    from iam_validator.mcp.tools.query import query_arn_formats as _query

    return await _query(service=service)


@mcp.tool()
async def list_checks() -> list[dict[str, Any]]:
    """List all available validation checks.

    Returns:
        List of {check_id, description, default_severity}
    """
    # Use cached registry instead of creating new one each call
    # Convert tuple back to list for API compatibility
    return list(_get_cached_checks())


@mcp.tool()
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


@mcp.tool()
async def list_sensitive_actions(
    category: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    verbose: bool = False,
) -> dict[str, Any]:
    """List sensitive actions from the 490+ action catalog.

    Args:
        category: Filter by "credential_exposure", "data_access", "privilege_escalation", or "resource_exposure"
        limit: Max actions to return
        offset: Skip N actions for pagination
        verbose: Return full action details (True) or names only (False)

    Returns:
        {actions, total, has_more}
    """
    from iam_validator.mcp.tools.query import list_sensitive_actions as _list_sensitive

    all_actions = await _list_sensitive(category=category)
    total = len(all_actions)

    # Apply pagination
    if offset:
        all_actions = all_actions[offset:]
    if limit:
        all_actions = all_actions[:limit]

    # Lean response: just action names if not verbose
    if not verbose and all_actions and isinstance(all_actions[0], dict):
        all_actions = [a.get("action", a) if isinstance(a, dict) else a for a in all_actions]

    return {
        "actions": all_actions,
        "total": total,
        "has_more": offset + len(all_actions) < total,
    }


@mcp.tool()
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


@mcp.tool()
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
        if "Version" not in fixed_policy or fixed_policy.get("Version") not in [
            "2012-10-17",
            "2008-10-17",
        ]:
            fixed_policy["Version"] = "2012-10-17"
            fixes_applied.append("Added Version: 2012-10-17")

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

    # Fix 3: Normalize action case (service prefix should be lowercase)
    if should_fix("action_validation"):
        statements = fixed_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            actions = stmt.get("Action", [])
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
                        fixes_applied.append(f"Normalized action case: {action} → {new_action}")
                    else:
                        normalized.append(action)
                else:
                    normalized.append(action)

            if normalized:
                stmt["Action"] = (
                    normalized[0] if (was_string and len(normalized) == 1) else normalized
                )

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

    # Re-validate the fixed policy
    final_result = await _validate(policy=fixed_policy, policy_type=effective_policy_type)

    if verbose:
        validation_issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "suggestion": issue.suggestion,
                "example": issue.example,
                "check_id": issue.check_id,
            }
            for issue in final_result.issues
        ]
    else:
        validation_issues = [
            {
                "severity": issue.severity,
                "message": issue.message,
                "check_id": issue.check_id,
            }
            for issue in final_result.issues
        ]

    return {
        "fixed_policy": fixed_policy,
        "fixes_applied": fixes_applied,
        "unfixed_issues": unfixed_issues if verbose else len(unfixed_issues),
        "validation": {
            "is_valid": final_result.is_valid,
            "issue_count": len(final_result.issues),
            "issues": validation_issues,
        },
    }


@mcp.tool()
async def get_issue_guidance(check_id: str) -> dict[str, Any]:
    """Get step-by-step fix guidance for a validation issue.

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, common_causes, fix_steps, example_before, example_after, related_tools}
    """
    guidance_db: dict[str, dict[str, Any]] = {
        "wildcard_action": {
            "check_id": "wildcard_action",
            "description": "Detects policies that use Action: '*' granting all permissions",
            "common_causes": [
                "Trying to grant broad access without knowing specific actions",
                "Copy-pasted from an overly permissive example",
            ],
            "fix_steps": [
                "1. Identify what the policy user actually needs to do",
                "2. Use suggest_actions('describe what you need', 'service') to find actions",
                "3. Replace '*' with the specific action list",
                "4. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": "*", "Resource": "*"}',
            "example_after": '{"Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::my-bucket/*"}',
            "related_tools": ["suggest_actions", "query_service_actions", "list_templates"],
        },
        "wildcard_resource": {
            "check_id": "wildcard_resource",
            "description": "Detects policies that use Resource: '*' granting access to all resources",
            "common_causes": [
                "Not knowing the correct ARN format",
                "Wanting the policy to work across multiple resources",
            ],
            "fix_steps": [
                "1. Determine which specific resources need access",
                "2. Use query_arn_formats('service') to get ARN patterns",
                "3. Replace '*' with specific ARNs or ARN patterns",
                "4. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": ["s3:GetObject"], "Resource": "*"}',
            "example_after": '{"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"]}',
            "related_tools": ["query_arn_formats", "get_policy_summary"],
        },
        "action_validation": {
            "check_id": "action_validation",
            "description": "Detects actions that don't exist in AWS",
            "common_causes": [
                "Typo in action name (e.g., 'S3:GetObject' instead of 's3:GetObject')",
                "Using deprecated action name",
                "Wrong service prefix",
            ],
            "fix_steps": [
                "1. Check the service prefix is lowercase (s3, not S3)",
                "2. Use query_service_actions('service') to list valid actions",
                "3. Use query_action_details('service:action') to verify action exists",
                "4. Fix the action name and re-validate",
            ],
            "example_before": '{"Action": ["S3:GetObjects"]}',
            "example_after": '{"Action": ["s3:GetObject"]}',
            "related_tools": [
                "query_service_actions",
                "query_action_details",
                "expand_wildcard_action",
            ],
        },
        "sensitive_action": {
            "check_id": "sensitive_action",
            "description": "Detects high-risk actions that can lead to privilege escalation or data exposure",
            "common_causes": [
                "Granting IAM, STS, or KMS permissions without restrictions",
                "Allowing actions that can modify security settings",
            ],
            "fix_steps": [
                "1. Verify the sensitive action is truly needed",
                "2. Use check_sensitive_actions(['action']) to understand the risk",
                "3. Use get_required_conditions(['action']) to get recommended conditions",
                "4. Add conditions to restrict when the action can be used",
                "5. Re-validate with validate_policy",
            ],
            "example_before": '{"Action": ["iam:PassRole"], "Resource": "*"}',
            "example_after": '{"Action": ["iam:PassRole"], "Resource": "arn:aws:iam::123456789012:role/LambdaRole", "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}',
            "related_tools": [
                "check_sensitive_actions",
                "get_required_conditions",
                "fix_policy_issues",
            ],
        },
        "action_condition_enforcement": {
            "check_id": "action_condition_enforcement",
            "description": "Detects sensitive actions that should have conditions but don't",
            "common_causes": [
                "Not aware that certain actions need conditions",
                "Conditions were forgotten during policy creation",
            ],
            "fix_steps": [
                "1. Use get_required_conditions(['action']) to see what's needed",
                "2. Add the Condition block to the statement",
                "3. Common conditions: MFA, SourceIp, PassedToService",
                "4. Use fix_policy_issues to auto-add basic conditions",
            ],
            "example_before": '{"Action": ["iam:CreateUser"], "Resource": "*"}',
            "example_after": '{"Action": ["iam:CreateUser"], "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}',
            "related_tools": [
                "get_required_conditions",
                "fix_policy_issues",
                "check_sensitive_actions",
            ],
        },
        "policy_structure": {
            "check_id": "policy_structure",
            "description": "Detects missing or malformed policy structure",
            "common_causes": [
                "Missing Version field",
                "Missing Statement array",
                "Invalid Effect value",
            ],
            "fix_steps": [
                "1. Ensure Version is '2012-10-17' (recommended)",
                "2. Ensure Statement is an array of statement objects",
                "3. Each statement must have Effect, Action, and Resource",
                "4. Use fix_policy_issues to auto-fix structure issues",
            ],
            "example_before": '{"Statement": [{"Action": "s3:*"}]}',
            "example_after": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]}',
            "related_tools": ["fix_policy_issues", "validate_policy"],
        },
    }

    if check_id in guidance_db:
        return guidance_db[check_id]

    # Generic guidance for unknown check_id
    return {
        "check_id": check_id,
        "description": f"Validation check: {check_id}",
        "common_causes": ["Check the validation message for specific details"],
        "fix_steps": [
            "1. Read the issue message and suggestion from validate_policy",
            "2. Use the example field if provided",
            "3. Use list_checks() to get more info about available checks",
            "4. Consult AWS IAM documentation",
        ],
        "example_before": "See the issue's example field",
        "example_after": "Apply the suggestion from the issue",
        "related_tools": ["validate_policy", "list_checks", "fix_policy_issues"],
    }


# =============================================================================
# Advanced Analysis Tools
# =============================================================================


@mcp.tool()
async def get_check_details(check_id: str) -> dict[str, Any]:
    """Get full documentation for a validation check.

    Args:
        check_id: Check ID (e.g., "wildcard_action", "sensitive_action")

    Returns:
        {check_id, description, default_severity, category, example_violation, example_fix, configuration, related_checks}
    """
    from iam_validator.core.check_registry import create_default_registry

    registry = create_default_registry()

    # Check metadata database
    check_metadata: dict[str, dict[str, Any]] = {
        "wildcard_action": {
            "category": "security",
            "example_violation": {"Effect": "Allow", "Action": "*", "Resource": "*"},
            "example_fix": {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
            "configuration": {"enabled": True, "severity": "configurable"},
            "related_checks": ["wildcard_resource", "full_wildcard", "service_wildcard"],
        },
        "wildcard_resource": {
            "category": "security",
            "example_violation": {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": "*",
            },
            "example_fix": {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
            "configuration": {"enabled": True, "severity": "configurable"},
            "related_checks": ["wildcard_action", "full_wildcard"],
        },
        "sensitive_action": {
            "category": "security",
            "example_violation": {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "*",
            },
            "example_fix": {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "arn:aws:iam::123456789012:user/${aws:username}",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            "configuration": {"enabled": True, "severity": "high"},
            "related_checks": ["action_condition_enforcement"],
        },
        "action_validation": {
            "category": "aws",
            "example_violation": {"Effect": "Allow", "Action": ["S3:GetObjects"], "Resource": "*"},
            "example_fix": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            "configuration": {"enabled": True},
            "related_checks": ["policy_structure"],
        },
        "policy_structure": {
            "category": "structure",
            "example_violation": {"Statement": [{"Action": "s3:*"}]},
            "example_fix": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
            },
            "configuration": {"enabled": True},
            "related_checks": ["sid_uniqueness"],
        },
    }

    # Get check from registry
    if check_id in registry._checks:
        check = registry._checks[check_id]
        metadata = check_metadata.get(check_id, {})

        return {
            "check_id": check_id,
            "description": check.description,
            "default_severity": check.default_severity,
            "category": metadata.get("category", "general"),
            "example_violation": metadata.get("example_violation"),
            "example_fix": metadata.get("example_fix"),
            "configuration": metadata.get("configuration", {"enabled": True}),
            "related_checks": metadata.get("related_checks", []),
        }

    return {
        "check_id": check_id,
        "description": "Check not found",
        "default_severity": "unknown",
        "category": "unknown",
        "example_violation": None,
        "example_fix": None,
        "configuration": {},
        "related_checks": [],
    }


@mcp.tool()
async def explain_policy(
    policy: dict[str, Any],
    verbose: bool = False,
) -> dict[str, Any]:
    """Generate human-readable explanation of policy permissions and security concerns.

    Args:
        policy: IAM policy dictionary
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {summary, statements, services_accessed, security_concerns, recommendations}
    """
    from iam_validator.mcp.tools.query import get_policy_summary as _get_summary

    summary = await _get_summary(policy)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    statement_explanations = []
    security_concerns = []
    recommendations = []
    services_with_access: dict[str, set[str]] = {}

    for idx, stmt in enumerate(statements):
        effect = stmt.get("Effect", "Allow")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        conditions = stmt.get("Condition", {})

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Analyze actions by service
        for action in actions:
            if ":" in action:
                service = action.split(":")[0]
                action_name = action.split(":")[1]
                if service not in services_with_access:
                    services_with_access[service] = set()

                if action_name == "*":
                    services_with_access[service].add("full")
                elif (
                    action_name.startswith("Get")
                    or action_name.startswith("List")
                    or action_name.startswith("Describe")
                ):
                    services_with_access[service].add("read")
                elif (
                    action_name.startswith("Put")
                    or action_name.startswith("Create")
                    or action_name.startswith("Update")
                ):
                    services_with_access[service].add("write")
                elif action_name.startswith("Delete") or action_name.startswith("Remove"):
                    services_with_access[service].add("delete")
                else:
                    services_with_access[service].add("other")
            elif action == "*":
                security_concerns.append(f"Statement {idx}: Full admin access with Action: '*'")
                recommendations.append("Replace Action: '*' with specific actions")

        # Check for wildcards
        if "*" in resources:
            if effect == "Allow":
                security_concerns.append(f"Statement {idx}: Allows access to all resources")
                recommendations.append(f"Statement {idx}: Scope resources to specific ARNs")

        # Build explanation
        action_desc = ", ".join(actions[:3]) + ("..." if len(actions) > 3 else "")
        resource_desc = ", ".join(resources[:2]) + ("..." if len(resources) > 2 else "")
        condition_desc = f" with {len(conditions)} condition(s)" if conditions else ""

        explanation = f"{effect}s {action_desc} on {resource_desc}{condition_desc}"
        statement_explanations.append(
            {
                "index": idx,
                "sid": stmt.get("Sid", f"Statement{idx}"),
                "effect": effect,
                "explanation": explanation,
                "action_count": len(actions),
                "has_conditions": bool(conditions),
            }
        )

    # Build services summary
    services_summary = []
    for service, access_types in services_with_access.items():
        services_summary.append(
            {
                "service": service,
                "access_types": sorted(access_types),
            }
        )

    # Generate summary
    total_allow = sum(1 for s in statements if s.get("Effect") == "Allow")
    total_deny = len(statements) - total_allow
    brief_summary = f"Policy with {len(statements)} statement(s): {total_allow} Allow, {total_deny} Deny across {len(services_with_access)} service(s)"

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
    else:
        return {
            "summary": brief_summary,
            "security_concerns": security_concerns,
            "recommendations": recommendations,
            "has_wildcards": summary.has_wildcards,
            "statement_count": len(statement_explanations),
            "services_count": len(services_summary),
        }


@mcp.tool()
async def build_arn(
    service: str,
    resource_type: str,
    resource_name: str,
    region: str = "",
    account_id: str = "",
    partition: str = "aws",
) -> dict[str, Any]:
    """Build a valid ARN from components with format validation.

    Args:
        service: AWS service (e.g., "s3", "lambda", "dynamodb")
        resource_type: Resource type (e.g., "bucket", "function", "table")
        resource_name: Name of the resource
        region: AWS region (empty for global resources)
        account_id: 12-digit AWS account ID (empty for S3)
        partition: "aws", "aws-cn", or "aws-us-gov"

    Returns:
        {arn, valid, notes}
    """
    # ARN format patterns by service
    arn_patterns: dict[str, dict[str, Any]] = {
        "s3": {
            "bucket": {
                "format": "arn:{partition}:s3:::{resource}",
                "needs_region": False,
                "needs_account": False,
            },
            "object": {
                "format": "arn:{partition}:s3:::{resource}",
                "needs_region": False,
                "needs_account": False,
            },
        },
        "lambda": {
            "function": {
                "format": "arn:{partition}:lambda:{region}:{account}:function:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "dynamodb": {
            "table": {
                "format": "arn:{partition}:dynamodb:{region}:{account}:table/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "iam": {
            "user": {
                "format": "arn:{partition}:iam::{account}:user/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
            "role": {
                "format": "arn:{partition}:iam::{account}:role/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
            "policy": {
                "format": "arn:{partition}:iam::{account}:policy/{resource}",
                "needs_region": False,
                "needs_account": True,
            },
        },
        "sqs": {
            "queue": {
                "format": "arn:{partition}:sqs:{region}:{account}:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "sns": {
            "topic": {
                "format": "arn:{partition}:sns:{region}:{account}:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "ec2": {
            "instance": {
                "format": "arn:{partition}:ec2:{region}:{account}:instance/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
            "vpc": {
                "format": "arn:{partition}:ec2:{region}:{account}:vpc/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "secretsmanager": {
            "secret": {
                "format": "arn:{partition}:secretsmanager:{region}:{account}:secret:{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
        "kms": {
            "key": {
                "format": "arn:{partition}:kms:{region}:{account}:key/{resource}",
                "needs_region": True,
                "needs_account": True,
            },
        },
    }

    notes: list[str] = []
    valid = True

    # Get pattern for service/resource type
    service_patterns = arn_patterns.get(service.lower(), {})
    pattern_info = service_patterns.get(resource_type.lower())

    if not pattern_info:
        # Generic fallback
        if region and account_id:
            arn = f"arn:{partition}:{service}:{region}:{account_id}:{resource_type}/{resource_name}"
        elif account_id:
            arn = f"arn:{partition}:{service}::{account_id}:{resource_type}/{resource_name}"
        else:
            arn = f"arn:{partition}:{service}:::{resource_type}/{resource_name}"
        notes.append("Unknown service/resource combination. Using generic format.")
        return {"arn": arn, "valid": True, "notes": notes}

    # Validate required fields
    if pattern_info["needs_region"] and not region:
        notes.append(f"Region is required for {service}:{resource_type}")
        valid = False
        region = "{region}"

    if pattern_info["needs_account"] and not account_id:
        notes.append(f"Account ID is required for {service}:{resource_type}")
        valid = False
        account_id = "{account_id}"

    # Build ARN from pattern
    arn = pattern_info["format"].format(
        partition=partition,
        region=region,
        account=account_id,
        resource=resource_name,
    )

    return {"arn": arn, "valid": valid, "notes": notes}


@mcp.tool()
async def compare_policies(
    policy_a: dict[str, Any],
    policy_b: dict[str, Any],
    verbose: bool = False,
) -> dict[str, Any]:
    """Compare two IAM policies and highlight differences.

    Args:
        policy_a: First policy (baseline)
        policy_b: Second policy (comparison)
        verbose: Return all fields (True) or essential only (False)

    Returns:
        {summary, added_actions, removed_actions, added_resources, removed_resources, condition_changes, effect_changes}
    """

    def extract_policy_elements(policy: dict[str, Any]) -> dict[str, Any]:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        all_actions: set[str] = set()
        all_resources: set[str] = set()
        all_conditions: list[dict[str, Any]] = []
        effects: dict[str, str] = {}

        for idx, stmt in enumerate(statements):
            sid = stmt.get("Sid", f"stmt_{idx}")
            effect = stmt.get("Effect", "Allow")
            effects[sid] = effect

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            all_actions.update(actions)

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            all_resources.update(resources)

            if "Condition" in stmt:
                all_conditions.append({"sid": sid, "condition": stmt["Condition"]})

        return {
            "actions": all_actions,
            "resources": all_resources,
            "conditions": all_conditions,
            "effects": effects,
        }

    elements_a = extract_policy_elements(policy_a)
    elements_b = extract_policy_elements(policy_b)

    added_actions = sorted(elements_b["actions"] - elements_a["actions"])
    removed_actions = sorted(elements_a["actions"] - elements_b["actions"])
    added_resources = sorted(elements_b["resources"] - elements_a["resources"])
    removed_resources = sorted(elements_a["resources"] - elements_b["resources"])

    # Compare effects for matching SIDs
    effect_changes = []
    common_sids = set(elements_a["effects"].keys()) & set(elements_b["effects"].keys())
    for sid in common_sids:
        if elements_a["effects"][sid] != elements_b["effects"][sid]:
            effect_changes.append(
                {
                    "sid": sid,
                    "policy_a": elements_a["effects"][sid],
                    "policy_b": elements_b["effects"][sid],
                }
            )

    # Summarize
    changes = []
    if added_actions:
        changes.append(f"{len(added_actions)} action(s) added")
    if removed_actions:
        changes.append(f"{len(removed_actions)} action(s) removed")
    if added_resources:
        changes.append(f"{len(added_resources)} resource(s) added")
    if removed_resources:
        changes.append(f"{len(removed_resources)} resource(s) removed")
    if effect_changes:
        changes.append(f"{len(effect_changes)} effect change(s)")

    summary = ", ".join(changes) if changes else "No significant differences found"

    if verbose:
        return {
            "summary": summary,
            "added_actions": added_actions,
            "removed_actions": removed_actions,
            "added_resources": added_resources,
            "removed_resources": removed_resources,
            "condition_changes": {
                "policy_a_conditions": len(elements_a["conditions"]),
                "policy_b_conditions": len(elements_b["conditions"]),
            },
            "effect_changes": effect_changes,
        }
    else:
        return {
            "summary": summary,
            "added_actions_count": len(added_actions),
            "removed_actions_count": len(removed_actions),
            "added_resources_count": len(added_resources),
            "removed_resources_count": len(removed_resources),
            "effect_changes_count": len(effect_changes),
        }


# =============================================================================
# Batch Operations (Reduced Round-Trips)
# =============================================================================


@mcp.tool()
async def validate_policies_batch(
    policies: list[dict[str, Any]],
    ctx: Context,
    policy_type: str | None = None,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    """Validate multiple IAM policies in parallel (more efficient than multiple validate_policy calls).

    Args:
        policies: List of IAM policy dictionaries
        policy_type: "identity", "resource", or "trust" (auto-detected if None)
        verbose: Return all fields (True) or essential only (False)

    Returns:
        List of {policy_index, is_valid, issues}
    """
    import asyncio

    from iam_validator.mcp.tools.validation import validate_policy as _validate

    # Ensure shared fetcher is available (validates actions exist)
    _ = get_shared_fetcher(ctx)

    async def validate_one(idx: int, policy: dict[str, Any]) -> dict[str, Any]:
        result = await _validate(policy=policy, policy_type=policy_type)

        if verbose:
            issues = [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "example": issue.example,
                    "check_id": issue.check_id,
                    "statement_index": issue.statement_index,
                    "action": getattr(issue, "action", None),
                    "resource": getattr(issue, "resource", None),
                    "field_name": getattr(issue, "field_name", None),
                }
                for issue in result.issues
            ]
        else:
            issues = [
                {
                    "severity": issue.severity,
                    "message": issue.message,
                    "check_id": issue.check_id,
                }
                for issue in result.issues
            ]

        return {
            "policy_index": idx,
            "is_valid": result.is_valid,
            "issues": issues,
        }

    # Run all validations in parallel
    results = await asyncio.gather(*[validate_one(i, p) for i, p in enumerate(policies)])
    return list(results)


@mcp.tool()
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


@mcp.tool()
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
        check_results = await asyncio.gather(
            *[check_one_action(action, shared_fetcher) for action in actions]
        )
    else:
        # Fall back to creating new fetcher
        async with AWSServiceFetcher() as fetcher:
            check_results = await asyncio.gather(
                *[check_one_action(action, fetcher) for action in actions]
            )

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


@mcp.tool()
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


@mcp.tool()
async def get_organization_config() -> dict[str, Any]:
    """Get the current session organization configuration.

    Returns:
        {has_config, config, source}
    """
    from iam_validator.mcp.tools.org_config_tools import get_organization_config_impl

    return await get_organization_config_impl()


@mcp.tool()
async def clear_organization_config() -> dict[str, str]:
    """Clear session organization config, reverting to defaults.

    Returns:
        {status: "cleared" or "no_config_set"}
    """
    from iam_validator.mcp.tools.org_config_tools import clear_organization_config_impl

    return await clear_organization_config_impl()


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
