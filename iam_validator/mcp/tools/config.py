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
from fastmcp.exceptions import ToolError
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


async def _set_custom_instructions_impl(
    instructions: str,
    session: "SessionState | None",
    ctx: Context,
) -> dict[str, Any]:
    from iam_validator.mcp.instructions import get_instructions

    if session is None:
        return {
            "success": False,
            "instructions_preview": None,
            "previous_source": "none",
            "error": _NO_SESSION_ERROR,
        }

    previous_source = session.get_instructions_source()
    session.set_instructions(instructions, source="api")
    ctx.fastmcp.instructions = get_instructions(session.get_instructions())

    preview = instructions[:200] + "..." if len(instructions) > 200 else instructions
    return {
        "success": True,
        "instructions_preview": preview,
        "previous_source": previous_source,
    }


async def _clear_custom_instructions_impl(session: "SessionState | None", ctx: Context) -> dict[str, str]:
    from iam_validator.mcp.instructions import BASE_INSTRUCTIONS

    had_instructions = session.clear_instructions() if session is not None else False
    ctx.fastmcp.instructions = BASE_INSTRUCTIONS

    return {
        "status": "cleared" if had_instructions else "no_instructions_set",
    }


# =============================================================================
# MCP tool wrappers (registered via TOOLS below)
# =============================================================================


async def get_config(ctx: Context) -> dict[str, Any]:
    """Effective validator config, active profile, and custom instructions.

    Consolidates the former get_organization_config, get_active_profile, and
    get_custom_instructions tools. Always available, in every mode/transport
    (contrast set_config, local/stdio only).

    In hosted mode there is no session override (``context.mutable`` is
    ``None``); this reports the immutable baseline config resolved at startup.

    Returns:
        {has_config, config, source, config_digest, mode, profile,
         tool_count, tool_names, custom_instructions}

    Emits one audit record per call in hosted mode (see mcp/audit.py); local
    mode does not.
    """
    from iam_validator.mcp.audit import audited_call

    async def _do_get_config() -> dict[str, Any]:
        context = get_server_context(ctx)

        if context is not None and context.mutable is None:
            source = str(context.settings.config_source) if context.settings.config_source else "hosted"
            config_result: dict[str, Any] = {
                "has_config": True,
                "config": {
                    "settings": context.config.settings,
                    "checks": context.config.checks_config,
                },
                "source": source,
                "config_digest": context.config_digest,
            }
            instructions_result = {"has_instructions": False, "instructions": None, "source": "none"}
        else:
            session = context.mutable if context is not None else None
            config_result = await get_organization_config_impl(session)
            config_result.setdefault("config_digest", context.config_digest if context is not None else None)
            instructions = session.get_instructions() if session is not None else None
            instructions_result = {
                "has_instructions": instructions is not None,
                "instructions": instructions,
                "source": session.get_instructions_source() if session is not None else "none",
            }

        mode = context.settings.mode if context is not None else "local"
        profile = context.settings.profile if context is not None else "full"
        tools = await ctx.fastmcp.list_tools()

        return {
            **config_result,
            "mode": mode,
            "profile": profile,
            "tool_count": len(tools),
            "tool_names": sorted(t.name for t in tools),
            "custom_instructions": instructions_result,
        }

    return await audited_call("get_config", ctx, 0, _do_get_config)


# The one tool-provenance exemption (every tool must trace to a CLI command or SDK
# export): this edits ServerContext.mutable, an MCP-only concept with no such counterpart.
async def set_config(
    ctx: Context,
    config: dict[str, Any] | None = None,
    yaml_content: str | None = None,
    clear_config: bool = False,
    instructions: str | None = None,
    clear_instructions: bool = False,
) -> dict[str, Any]:
    """Mutate this session's validator config and/or custom instructions.

    Consolidates the former set_organization_config, clear_organization_config,
    load_organization_config_from_yaml, set_custom_instructions, and
    clear_custom_instructions tools. Local mode / stdio transport only — see
    get_config for the read-only, always-available counterpart.

    Args:
        config: Set validator config from a dict (same shape the CLI's YAML
            config uses). Mutually exclusive with yaml_content/clear_config.
        yaml_content: Set validator config by parsing this YAML string.
            Mutually exclusive with config/clear_config.
        clear_config: Clear the session validator config, reverting to
            defaults. Mutually exclusive with config/yaml_content.
        instructions: Set custom instructions for this session. Mutually
            exclusive with clear_instructions.
        clear_instructions: Clear custom instructions, reverting to defaults.
            Mutually exclusive with instructions.

    Returns:
        {config_result?, instructions_result?} — present depending on which
        of the above were passed.
    """
    config_actions = [a for a in (config is not None, yaml_content is not None, clear_config) if a]
    if len(config_actions) > 1:
        raise ToolError("set_config: config, yaml_content, and clear_config are mutually exclusive")

    instructions_actions = [a for a in (instructions is not None, clear_instructions) if a]
    if len(instructions_actions) > 1:
        raise ToolError("set_config: instructions and clear_instructions are mutually exclusive")

    if not config_actions and not instructions_actions:
        raise ToolError(
            "set_config: nothing to do; pass config, yaml_content, clear_config, instructions, or clear_instructions"
        )

    context = get_server_context(ctx)
    session = context.mutable if context is not None else None
    result: dict[str, Any] = {}

    if config is not None:
        result["config_result"] = await set_organization_config_impl(config, session)
    elif yaml_content is not None:
        result["config_result"] = await load_organization_config_from_yaml_impl(yaml_content, session)
    elif clear_config:
        result["config_result"] = await clear_organization_config_impl(session)

    if instructions is not None:
        result["instructions_result"] = await _set_custom_instructions_impl(instructions, session, ctx)
    elif clear_instructions:
        result["instructions_result"] = await _clear_custom_instructions_impl(session, ctx)

    return result


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        tag="orgconfig",
        name="get_config",
        fn=get_config,
        annotations=_READ_ONLY_ANNOTATIONS,
        output_schema=infer_output_schema(get_config),
    ),
    ToolSpec(
        tag="orgconfig",
        mutating=True,
        modes=frozenset({"local"}),
        transports=frozenset({"stdio"}),
        name="set_config",
        fn=set_config,
        annotations=_MUTATING_ANNOTATIONS,
        output_schema=infer_output_schema(set_config),
    ),
)


__all__ = [
    "set_organization_config_impl",
    "get_organization_config_impl",
    "clear_organization_config_impl",
    "load_organization_config_from_yaml_impl",
    "get_config",
    "set_config",
    "TOOLS",
]
