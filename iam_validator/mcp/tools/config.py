"""Organization configuration tools for MCP server.

This module provides the underlying implementations for MCP tools
that manage session-wide validator configurations.

The session config is used to control which checks are enabled, their
severity levels, and other validator settings. All validation is done
by the IAM validator's built-in checks - not by separate guardrail logic.

Each ``*_impl`` function takes the caller's ``SessionState`` (``ServerContext.mutable``,
``None`` in hosted mode) rather than reaching for a module-level singleton.
"""

from typing import TYPE_CHECKING, Any

from fastmcp import Context
from mcp.types import ToolAnnotations

from iam_validator.mcp.component_spec import ToolSpec, infer_output_schema
from iam_validator.mcp.context import get_server_context

if TYPE_CHECKING:
    from iam_validator.mcp.context import SessionState

_NO_SESSION_ERROR = "Session-scoped configuration is not available in hosted mode"

_MUTATING_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_READ_ONLY_ANNOTATIONS = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


async def set_organization_config_impl(
    config: dict[str, Any],
    session: "SessionState | None",
) -> dict[str, Any]:
    """Set session-wide validator configuration.

    This sets the validator configuration for the MCP session. The config
    uses the same format as the CLI validator's YAML configuration files.

    Args:
        config: Validator configuration dictionary. Supports:
            - settings: Global settings (fail_on_severity, parallel, etc.)
            - Check IDs as keys with enabled/severity/options
        session: The caller's session state, or ``None`` in hosted mode.

    Returns:
        Dictionary with success status, applied config, and any warnings

    Example:
        >>> await set_organization_config_impl({
        ...     "settings": {"fail_on_severity": ["error", "critical"]},
        ...     "wildcard_action": {"enabled": True, "severity": "critical"},
        ...     "sensitive_action": {"enabled": False}
        ... }, session)
    """
    if session is None:
        return {
            "success": False,
            "applied_config": None,
            "warnings": [],
            "error": _NO_SESSION_ERROR,
        }

    warnings: list[str] = []

    try:
        validator_config = session.set_config(config, source="session")

        # Return the applied settings for confirmation
        applied_config = {
            "settings": validator_config.settings,
            "checks": validator_config.checks_config,
        }

        return {
            "success": True,
            "applied_config": applied_config,
            "warnings": warnings,
        }
    except Exception as e:
        return {
            "success": False,
            "applied_config": None,
            "warnings": warnings,
            "error": str(e),
        }


async def get_organization_config_impl(session: "SessionState | None") -> dict[str, Any]:
    """Get the current session validator configuration.

    Args:
        session: The caller's session state, or ``None`` in hosted mode.

    Returns:
        Dictionary with has_config, config, and source
    """
    config = session.get_config() if session is not None else None

    if config is None:
        return {
            "has_config": False,
            "config": None,
            "source": "none",
        }

    return {
        "has_config": True,
        "config": {
            "settings": config.settings,
            "checks": config.checks_config,
        },
        "source": session.get_config_source() if session is not None else "none",
    }


async def clear_organization_config_impl(session: "SessionState | None") -> dict[str, str]:
    """Clear the session validator configuration.

    Args:
        session: The caller's session state, or ``None`` in hosted mode.

    Returns:
        Dictionary with status
    """
    had_config = session.clear_config() if session is not None else False

    return {
        "status": "cleared" if had_config else "no_config_set",
    }


async def load_organization_config_from_yaml_impl(
    yaml_content: str,
    session: "SessionState | None",
) -> dict[str, Any]:
    """Load validator configuration from YAML content.

    Args:
        yaml_content: YAML configuration string (same format as CLI config files)
        session: The caller's session state, or ``None`` in hosted mode.

    Returns:
        Dictionary with success status, applied config, warnings, and errors
    """
    if session is None:
        return {
            "success": False,
            "applied_config": None,
            "warnings": [],
            "error": _NO_SESSION_ERROR,
        }

    try:
        config, warnings = session.load_config_from_yaml(yaml_content)

        return {
            "success": True,
            "applied_config": {
                "settings": config.settings,
                "checks": config.checks_config,
            },
            "warnings": warnings,
        }
    except Exception as e:
        return {
            "success": False,
            "applied_config": None,
            "warnings": [],
            "error": str(e),
        }


async def check_org_compliance_impl(
    policy: dict[str, Any],
    session: "SessionState | None",
    ctx: Any = None,
) -> dict[str, Any]:
    """Check if a policy passes validation with the session configuration.

    This runs the full validator with the session configuration and returns
    the validation results. It does NOT use separate guardrail logic - all
    checking is done by the validator's built-in checks.

    Args:
        policy: IAM policy as a dictionary
        session: The caller's session state, or ``None`` in hosted mode.
        ctx: The MCP request context, forwarded to ``validate_policy``.

    Returns:
        Dictionary with compliance status and validation issues
    """
    from iam_validator.mcp.tools.validate import validate_policy

    config = session.get_config() if session is not None else None

    if config is None:
        # No session config - validate with defaults
        result = await validate_policy(policy=policy, use_org_config=False, ctx=ctx)
        return {
            "compliant": result.is_valid,
            "has_org_config": False,
            "violations": [
                {"type": issue.issue_type, "message": issue.message, "severity": issue.severity}
                for issue in result.issues
            ],
            "warnings": ["No session config set - using default validator settings"],
            "suggestions": [issue.suggestion for issue in result.issues if issue.suggestion],
        }

    # Validate with the session config
    result = await validate_policy(policy=policy, use_org_config=True, ctx=ctx)

    violations = [
        {"type": issue.issue_type, "message": issue.message, "severity": issue.severity} for issue in result.issues
    ]

    suggestions = [issue.suggestion for issue in result.issues if issue.suggestion]

    return {
        "compliant": result.is_valid,
        "has_org_config": True,
        "violations": violations,
        "warnings": [],
        "suggestions": suggestions,
    }


async def validate_with_config_impl(
    policy: dict[str, Any],
    config: dict[str, Any],
    policy_type: str | None = None,
    ctx: Any = None,
) -> dict[str, Any]:
    """Validate a policy with explicit inline configuration.

    This runs validation with the provided config without affecting
    the session configuration.

    Args:
        policy: IAM policy to validate
        config: Inline configuration (same format as CLI config files)
        policy_type: Type of policy. If None, auto-detects from policy structure.
        ctx: The MCP request context, forwarded to ``validate_policy``.

    Returns:
        Dictionary with validation results
    """
    import tempfile
    from pathlib import Path

    import yaml

    from iam_validator.mcp.tools.validate import validate_policy

    # Create a temporary config file for the validator
    temp_config_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config, f)
            temp_config_path = f.name

        # Run validation with the temp config (bypasses session config)
        validation_result = await validate_policy(
            policy=policy,
            policy_type=policy_type,
            config_path=temp_config_path,
            use_org_config=False,
            ctx=ctx,
        )
    except Exception as e:
        return {
            "is_valid": False,
            "issues": [],
            "error": str(e),
            "config_applied": None,
        }
    finally:
        if temp_config_path:
            try:
                Path(temp_config_path).unlink()
            except OSError:
                pass

    # Build issues list
    issues = [
        {
            "severity": issue.severity,
            "message": issue.message,
            "suggestion": issue.suggestion,
            "check_id": issue.check_id,
        }
        for issue in validation_result.issues
    ]

    return {
        "is_valid": validation_result.is_valid,
        "issues": issues,
        "config_applied": config,
    }


# =============================================================================
# MCP tool wrappers (registered via TOOLS below)
# =============================================================================


async def set_organization_config(config: dict[str, Any], ctx: Context) -> dict[str, Any]:
    """Set validator configuration for this MCP session.

    Args:
        config: Config with "settings" (fail_on_severity, parallel_execution) and
            check IDs as keys (enabled, severity, ignore_patterns)

    Returns:
        {success, applied_config, warnings}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await set_organization_config_impl(config, session)


async def get_organization_config(ctx: Context) -> dict[str, Any]:
    """Get the current session organization configuration.

    Returns:
        {has_config, config, source}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await get_organization_config_impl(session)


async def clear_organization_config(ctx: Context) -> dict[str, str]:
    """Clear session organization config, reverting to defaults.

    Returns:
        {status: "cleared" or "no_config_set"}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await clear_organization_config_impl(session)


async def load_organization_config_from_yaml(yaml_content: str, ctx: Context) -> dict[str, Any]:
    """Load validator configuration from YAML content and set as session config.

    Args:
        yaml_content: YAML string with settings and check configurations

    Returns:
        {success, applied_config, warnings, error}
    """
    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    return await load_organization_config_from_yaml_impl(yaml_content, session)


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
    return await validate_with_config_impl(policy, config, policy_type, ctx=ctx)


async def set_custom_instructions(instructions: str, ctx: Context) -> dict[str, Any]:
    """Set custom validation guidelines for this session.

    Instructions are appended to default server instructions.

    Args:
        instructions: Custom instructions text (markdown supported)

    Returns:
        {success, instructions_preview, previous_source}
    """
    from iam_validator.mcp.instructions import get_instructions

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None

    if session is None:
        return {
            "success": False,
            "instructions_preview": None,
            "previous_source": "none",
            "error": _NO_SESSION_ERROR,
        }

    previous_source = session.get_instructions_source()

    session.set_instructions(instructions, source="api")

    # Update the server instructions
    ctx.fastmcp.instructions = get_instructions(session.get_instructions())

    preview = instructions[:200] + "..." if len(instructions) > 200 else instructions

    return {
        "success": True,
        "instructions_preview": preview,
        "previous_source": previous_source,
    }


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


async def clear_custom_instructions(ctx: Context) -> dict[str, str]:
    """Clear custom instructions, reverting to defaults.

    Returns:
        {status: "cleared" or "no_instructions_set"}
    """
    from iam_validator.mcp.instructions import BASE_INSTRUCTIONS

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    had_instructions = session.clear_instructions() if session is not None else False

    # Reset to base instructions
    ctx.fastmcp.instructions = BASE_INSTRUCTIONS

    return {
        "status": "cleared" if had_instructions else "no_instructions_set",
    }


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        name="set_organization_config",
        fn=set_organization_config,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(set_organization_config),
    ),
    ToolSpec(
        tag="orgconfig",
        name="get_organization_config",
        fn=get_organization_config,
        annotations=_READ_ONLY_ANNOTATIONS,
        output_schema=infer_output_schema(get_organization_config),
    ),
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        name="clear_organization_config",
        fn=clear_organization_config,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(clear_organization_config),
    ),
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        name="load_organization_config_from_yaml",
        fn=load_organization_config_from_yaml,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(load_organization_config_from_yaml),
    ),
    ToolSpec(
        tag="orgconfig",
        name="check_org_compliance",
        fn=check_org_compliance,
        annotations=_READ_ONLY_ANNOTATIONS,
        output_schema=infer_output_schema(check_org_compliance),
    ),
    ToolSpec(
        tag="orgconfig",
        name="validate_with_config",
        fn=validate_with_config,
        annotations=_READ_ONLY_ANNOTATIONS,
        output_schema=infer_output_schema(validate_with_config),
    ),
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        name="set_custom_instructions",
        fn=set_custom_instructions,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(set_custom_instructions),
    ),
    ToolSpec(
        tag="orgconfig",
        name="get_custom_instructions",
        fn=get_custom_instructions,
        annotations=_READ_ONLY_ANNOTATIONS,
        output_schema=infer_output_schema(get_custom_instructions),
    ),
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        name="clear_custom_instructions",
        fn=clear_custom_instructions,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(clear_custom_instructions),
    ),
)


__all__ = [
    "set_organization_config_impl",
    "get_organization_config_impl",
    "clear_organization_config_impl",
    "load_organization_config_from_yaml_impl",
    "check_org_compliance_impl",
    "validate_with_config_impl",
    "set_organization_config",
    "get_organization_config",
    "clear_organization_config",
    "load_organization_config_from_yaml",
    "check_org_compliance",
    "validate_with_config",
    "set_custom_instructions",
    "get_custom_instructions",
    "clear_custom_instructions",
    "TOOLS",
]
