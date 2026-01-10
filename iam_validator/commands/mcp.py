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

  # Start with SSE transport on custom host/port
  iam-validator mcp --transport sse --host 127.0.0.1 --port 8000

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

Features:
  - Policy generation from natural language descriptions
  - Template-based policy generation (15 built-in templates)
  - Policy validation with 19 security checks
  - AWS service queries (actions, resources, condition keys)
  - Security enforcement (auto-adds required conditions)
  - Session-wide configuration management
        """

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add MCP command arguments."""
        parser.add_argument(
            "--transport",
            choices=["stdio", "sse"],
            default="stdio",
            help="Transport protocol (default: stdio for Claude Desktop, sse for HTTP/SSE)",
        )

        parser.add_argument(
            "--host",
            default="127.0.0.1",
            help="Host for SSE transport (default: 127.0.0.1)",
        )

        parser.add_argument(
            "--port",
            type=int,
            default=8000,
            help="Port for SSE transport (default: 8000)",
        )

        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Enable verbose logging",
        )

        parser.add_argument(
            "--config",
            type=str,
            metavar="FILE",
            help="Path to configuration YAML file to load at startup",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the MCP server command.

        Args:
            args: Parsed command-line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        # Check if fastmcp is installed
        try:
            import fastmcp  # noqa: F401
        except ImportError:
            logging.error(
                "FastMCP is not installed. Install with: uv sync --extra mcp or pip install 'iam-validator[mcp]'"
            )
            return 1

        # Import and create the MCP server
        try:
            from iam_validator.mcp import create_server
        except ImportError as e:
            logging.error(f"Failed to import MCP server: {e}")
            logging.error(
                "Make sure the MCP module is properly installed with: uv sync --extra mcp"
            )
            return 1

        # Set up logging level
        if args.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        # Load config if provided
        if args.config:
            try:
                from pathlib import Path

                from iam_validator.mcp.session_config import SessionConfigManager

                config_path = Path(args.config)
                if not config_path.exists():
                    logging.error(f"Config file not found: {args.config}")
                    return 1

                config, warnings = SessionConfigManager.load_from_file(str(config_path))

                for warning in warnings:
                    logging.warning(f"Config warning: {warning}")

                logging.info(f"Loaded config from: {args.config}")

                # Log config summary
                if config.settings:
                    fail_on = config.settings.get("fail_on_severity", [])
                    if fail_on:
                        logging.info(f"  Fail on severity: {fail_on}")

                if config.checks_config:
                    disabled_checks = [
                        k for k, v in config.checks_config.items() if not v.get("enabled", True)
                    ]
                    if disabled_checks:
                        logging.info(f"  Disabled checks: {disabled_checks}")

            except Exception as e:
                logging.error(f"Failed to load config: {e}")
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                return 1

        try:
            # Create and run the server
            server = create_server()

            if args.transport == "stdio":
                logging.info("Starting MCP server with stdio transport...")
                logging.info("Waiting for client connection...")
                # Run with stdio transport using async method
                await server.run_stdio_async()
            else:
                # SSE transport
                logging.info(
                    f"Starting MCP server with SSE transport on {args.host}:{args.port}..."
                )
                # Run with SSE transport using async method
                await server.run_http_async(host=args.host, port=args.port)

            return 0

        except KeyboardInterrupt:
            logging.info("\nMCP server stopped by user")
            return 0
        except Exception as e:
            logging.error(f"Failed to start MCP server: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1
