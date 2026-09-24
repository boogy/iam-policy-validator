"""IAM Policy Validator MCP Server.

This module provides an MCP (Model Context Protocol) server for AI assistants
to interact with the IAM Policy Validator. It exposes tools for:
- Validating IAM policies
- Querying AWS service definitions
- Managing session-wide policy configurations

The server uses FastMCP and provides a security-first approach to policy validation.

Configuration:
    The MCP server uses the same configuration format as the CLI validator.
    You can load configuration from a YAML file using --config, or set the
    equivalent IAM_VALIDATOR_MCP_* environment variables directly; both are
    resolved once, at server startup, via ServerSettings.from_env().
"""

from typing import TYPE_CHECKING

from iam_validator.mcp.models import (
    ActionDetails,
    PolicySummary,
    ValidationResult,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP


def create_server() -> "FastMCP":
    """Create and configure the MCP server.

    Returns:
        FastMCP: Configured MCP server instance

    Raises:
        ImportError: If fastmcp is not installed
    """
    try:
        from iam_validator.mcp.build import build_server
        from iam_validator.mcp.settings import ServerSettings

        return build_server(ServerSettings.from_env())
    except ImportError as e:
        raise ImportError("fastmcp is required for MCP server. Install with: uv sync --extra mcp") from e


def run_server() -> None:
    """Run the MCP server.

    This is the entry point for the iam-validator-mcp command. Flags mirror the
    ``iam-validator mcp`` subcommand (see ``iam_validator.mcp.cli``) and every flag also
    reads its ``IAM_VALIDATOR_MCP_*`` environment variable; flags win.

    Usage:
        iam-validator-mcp
        iam-validator-mcp --config /path/to/config.yaml
        iam-validator-mcp --instructions "Always require MFA for sensitive actions"
        iam-validator-mcp --instructions-file /path/to/instructions.md
        iam-validator-mcp --transport http --host 127.0.0.1 --port 8000

    Raises:
        ImportError: If fastmcp is not installed
    """
    import argparse
    import sys

    from iam_validator.mcp.cli import add_arguments, resolve_settings, run_kwargs

    parser = argparse.ArgumentParser(
        prog="iam-validator-mcp",
        description="IAM Policy Validator MCP Server for AI assistants",
    )
    add_arguments(parser)
    args = parser.parse_args()

    if args.list_profiles:
        from iam_validator.mcp.build import PROFILE_DESCRIPTIONS

        for name, desc in PROFILE_DESCRIPTIONS.items():
            print(f"{name:>20s}  {desc}")
        sys.exit(0)

    try:
        settings = resolve_settings(args)

        from iam_validator.mcp.build import build_server

        mcp = build_server(settings)
        mcp.run(transport=settings.transport, **run_kwargs(settings))
    except ImportError as e:
        raise ImportError("fastmcp is required for MCP server. Install with: uv sync --extra mcp") from e
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Failed to start MCP server: {e}", file=sys.stderr)
        sys.exit(1)


__all__ = [
    "create_server",
    "run_server",
    "ValidationResult",
    "PolicySummary",
    "ActionDetails",
]
