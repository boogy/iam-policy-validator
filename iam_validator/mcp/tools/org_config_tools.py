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

if TYPE_CHECKING:
    from iam_validator.mcp.context import SessionState

_NO_SESSION_ERROR = "Session-scoped configuration is not available in hosted mode"


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
    from iam_validator.mcp.tools.validation import validate_policy

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

    from iam_validator.mcp.tools.validation import validate_policy

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


__all__ = [
    "set_organization_config_impl",
    "get_organization_config_impl",
    "clear_organization_config_impl",
    "load_organization_config_from_yaml_impl",
    "check_org_compliance_impl",
    "validate_with_config_impl",
]
