"""MCP command for IAM Policy Validator."""

import argparse
import logging

from iam_validator.commands.base import Command


class MCPCommand(Command):
    """Command to start MCP server for AI assistant integration."""

    @property
    def name(self) -> str:
        return "mcp"

    @property
    def help(self) -> str:
        return "Start MCP server for AI assistant integration"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Start MCP server with stdio transport (for Claude Desktop)
  iam-validator mcp

  # Start with streamable HTTP transport on custom host/port
  iam-validator mcp --transport http --host 127.0.0.1 --port 8000

  # Start with config preloaded
  iam-validator mcp --config ./config.yaml

Claude Desktop Configuration:
  Add to your claude_desktop_config.json:
  {
    "mcpServers": {
      "iam-validator": {
        "command": "iam-validator",
        "args": ["mcp"]
      }
    }
  }

  With configuration:
  {
    "mcpServers": {
      "iam-validator": {
        "command": "iam-validator",
        "args": ["mcp", "--config", "/path/to/config.yaml"]
      }
    }
  }

Config File (YAML) - same format as CLI validator:
  settings:
    fail_on_severity: [error, critical, high]
  wildcard_resource:
    severity: critical
  sensitive_action:
    enabled: true
    severity: high

Every flag also reads its IAM_VALIDATOR_MCP_* environment variable (flags win); see
'iam-validator-mcp --help' -- both entry points resolve the same flags identically.

Features:
  - Policy validation with 20+ security checks
  - AWS service queries (actions, resources, condition keys)
  - Session-wide configuration management
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add MCP command arguments."""
        from iam_validator.mcp.cli import add_arguments

        add_arguments(parser)

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the MCP server command.

        Args:
            args: Parsed command-line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            import fastmcp  # noqa: F401
        except ImportError:
            logging.error(
                "FastMCP is not installed. Install with: uv sync --extra mcp or pip install 'iam-validator[mcp]'"
            )
            return 1

        if args.list_profiles:
            from iam_validator.mcp.build import PROFILE_DESCRIPTIONS

            for name, desc in PROFILE_DESCRIPTIONS.items():
                print(f"{name:>20s}  {desc}")
            return 0

        try:
            from iam_validator.mcp.build import build_server
            from iam_validator.mcp.cli import resolve_settings, run_kwargs
        except ImportError as e:
            logging.error(f"Failed to import MCP server: {e}")
            logging.error("Make sure the MCP module is properly installed with: uv sync --extra mcp")
            return 1

        settings = resolve_settings(args)

        try:
            server = build_server(settings)
            logging.info(f"Starting MCP server with {settings.transport} transport...")
            await server.run_async(transport=settings.transport, **run_kwargs(settings))
            return 0
        except KeyboardInterrupt:
            logging.info("\nMCP server stopped by user")
            return 0
        except Exception as e:
            logging.error(f"Failed to start MCP server: {e}")
            return 1
