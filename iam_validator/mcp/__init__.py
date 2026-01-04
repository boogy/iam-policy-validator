"""IAM Policy Validator MCP Server.

This module provides an MCP (Model Context Protocol) server for AI assistants
to interact with the IAM Policy Validator. It exposes tools for:
- Validating IAM policies
- Generating policies from templates or descriptions
- Querying AWS service definitions
- Managing session-wide policy configurations

The server uses FastMCP and provides a security-first approach to policy generation.

Configuration:
    The MCP server uses the same configuration format as the CLI validator.
    You can load configuration from a YAML file using --config or set it
    programmatically using SessionConfigManager.
"""

from typing import TYPE_CHECKING

from iam_validator.mcp.models import (
    ActionDetails,
    GenerationResult,
    PolicySummary,
    ValidationResult,
)
from iam_validator.mcp.session_config import (
    SessionConfigManager,
    merge_conditions,
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
        from iam_validator.mcp.server import create_server as _create_server

        return _create_server()
    except ImportError as e:
        raise ImportError(
            "fastmcp is required for MCP server. Install with: uv sync --extra mcp"
        ) from e


def run_server() -> None:
    """Run the MCP server.

    This is the entry point for the iam-validator-mcp command.
    Supports --config argument for loading configuration at startup.

    Usage:
        iam-validator-mcp
        iam-validator-mcp --config /path/to/config.yaml

    Raises:
        ImportError: If fastmcp is not installed
    """
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="iam-validator-mcp",
        description="IAM Policy Validator MCP Server for AI assistants",
    )
    parser.add_argument(
        "--config",
        type=str,
        metavar="FILE",
        help="Path to configuration YAML file to load at startup",
    )
    args = parser.parse_args()

    # Load config if provided
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {args.config}", file=sys.stderr)
            sys.exit(1)

        try:
            config, warnings = SessionConfigManager.load_from_file(str(config_path))

            for warning in warnings:
                print(f"Warning: {warning}", file=sys.stderr)

            print(f"Loaded config from: {args.config}", file=sys.stderr)

        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        from iam_validator.mcp.server import run_server as _run_server

        _run_server()
    except ImportError as e:
        raise ImportError(
            "fastmcp is required for MCP server. Install with: uv sync --extra mcp"
        ) from e


__all__ = [
    "create_server",
    "run_server",
    "ValidationResult",
    "GenerationResult",
    "PolicySummary",
    "ActionDetails",
    "SessionConfigManager",
    "merge_conditions",
]
