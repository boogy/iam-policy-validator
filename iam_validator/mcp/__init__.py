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

    This is the entry point for the iam-validator-mcp command.
    Supports configuration and custom instructions at startup.

    Usage:
        iam-validator-mcp
        iam-validator-mcp --config /path/to/config.yaml
        iam-validator-mcp --instructions "Always require MFA for sensitive actions"
        iam-validator-mcp --instructions-file /path/to/instructions.md

    Custom instructions can also be set via:
        - Environment variable: IAM_VALIDATOR_MCP_INSTRUCTIONS
        - Config file: custom_instructions key in YAML config

    Raises:
        ImportError: If fastmcp is not installed
    """
    import argparse
    import os
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
    # --instructions and --instructions-file are mutually exclusive: ServerSettings
    # itself rejects setting both (see settings.py), so fail fast here too.
    instructions_group = parser.add_mutually_exclusive_group()
    instructions_group.add_argument(
        "--instructions",
        type=str,
        metavar="TEXT",
        help="Inline custom instructions to append to default LLM instructions. Mutually exclusive with --instructions-file.",
    )
    instructions_group.add_argument(
        "--instructions-file",
        type=str,
        metavar="FILE",
        help="Path to file containing custom instructions (markdown, txt). Mutually exclusive with --instructions.",
    )
    parser.add_argument(
        "--custom-checks-dir",
        type=str,
        metavar="DIR",
        help=(
            "Directory of Python modules with custom PolicyCheck subclasses to "
            "auto-discover (CLI parity). Precedence: this flag > YAML config > built-in defaults."
        ),
    )
    parser.add_argument(
        "--aws-services-dir",
        type=str,
        metavar="DIR",
        help=(
            "Directory of pre-downloaded AWS service definitions for offline mode "
            "(populate via 'iam-validator sync-services'). Precedence: this flag > "
            "YAML config > online fetch."
        ),
    )
    parser.add_argument(
        "--profile",
        choices=[
            "full",
            "validate-only",
            "validate-and-query",
            "read-only",
        ],
        default="full",
        help=(
            "Limit which MCP tools are exposed (tag-based gating). "
            "'full' = all tools (default). "
            "'validate-only' = validation tools only (smallest token footprint). "
            "'validate-and-query' = validation + AWS service-reference query tools "
            "(does NOT include the live AWS Access Analyzer; use 'full' for that). "
            "'read-only' = excludes any tool tagged 'mutating' (set_*, clear_*, load_*) — useful for CI / sandbox."
        ),
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="Print the profile -> tool taxonomy and exit.",
    )
    args = parser.parse_args()

    if args.list_profiles:
        from iam_validator.mcp.build import PROFILE_DESCRIPTIONS

        for name, desc in PROFILE_DESCRIPTIONS.items():
            print(f"{name:>20s}  {desc}")
        sys.exit(0)

    # CLI flags bridge to ServerSettings via IAM_VALIDATOR_MCP_* env vars,
    # which the real server resolves once at startup (ServerSettings.from_env(),
    # inside server_lifespan()). Validate paths here for a fast, clear CLI error.
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {args.config}", file=sys.stderr)
            sys.exit(1)
        os.environ["IAM_VALIDATOR_MCP_CONFIG"] = str(config_path)
        print(f"Config: {args.config}", file=sys.stderr)

    if args.instructions_file:
        instructions_path = Path(args.instructions_file)
        if not instructions_path.exists():
            print(
                f"Error: Instructions file not found: {args.instructions_file}",
                file=sys.stderr,
            )
            sys.exit(1)
        os.environ["IAM_VALIDATOR_MCP_INSTRUCTIONS_FILE"] = str(instructions_path)
        print(f"Instructions file: {args.instructions_file}", file=sys.stderr)

    elif args.instructions:
        os.environ["IAM_VALIDATOR_MCP_INSTRUCTIONS"] = args.instructions
        print("Custom instructions set from CLI argument", file=sys.stderr)

    if args.custom_checks_dir:
        os.environ["IAM_VALIDATOR_MCP_CUSTOM_CHECKS_DIR"] = args.custom_checks_dir
        print(f"Custom checks dir: {args.custom_checks_dir}", file=sys.stderr)

    if args.aws_services_dir:
        os.environ["IAM_VALIDATOR_MCP_AWS_SERVICES_DIR"] = args.aws_services_dir
        print(f"AWS services dir: {args.aws_services_dir}", file=sys.stderr)

    if args.profile != "full":
        os.environ["IAM_VALIDATOR_MCP_PROFILE"] = args.profile
        print(f"MCP profile: {args.profile}", file=sys.stderr)

    try:
        from iam_validator.mcp.build import build_server
        from iam_validator.mcp.settings import ServerSettings

        mcp = build_server(ServerSettings.from_env())
        mcp.run()
    except ImportError as e:
        raise ImportError("fastmcp is required for MCP server. Install with: uv sync --extra mcp") from e


__all__ = [
    "create_server",
    "run_server",
    "ValidationResult",
    "PolicySummary",
    "ActionDetails",
]
