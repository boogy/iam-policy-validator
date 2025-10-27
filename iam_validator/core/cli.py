"""Command-line interface for IAM Policy Validator."""

import argparse
import asyncio
import logging
import os
import sys

from iam_validator.__version__ import __version__
from iam_validator.commands import ALL_COMMANDS


def setup_logging(log_level: str | None = None, verbose: bool = False) -> None:
    """Setup logging configuration.

    Args:
        log_level: Log level from CLI argument (debug, info, warning, error, critical)
        verbose: Enable verbose logging (deprecated, use --log-level debug instead)

    Environment Variables:
        LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Priority:
        1. --log-level CLI argument (highest priority)
        2. LOG_LEVEL environment variable
        3. --verbose flag (sets DEBUG level)
        4. Default: WARNING (lowest priority)
    """
    # Check for LOG_LEVEL environment variable
    env_log_level = os.getenv("LOG_LEVEL", "").upper()

    # Map string to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    # Priority: CLI --log-level > LOG_LEVEL env var > --verbose flag > default (WARNING)
    if log_level:
        level = level_map[log_level.upper()]
    elif env_log_level in level_map:
        level = level_map[env_log_level]
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description="Validate AWS IAM policies for correctness and security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Add version argument
    parser.add_argument(
        "--version",
        action="version",
        version=f"iam-validator {__version__}",
        help="Show version information and exit",
    )

    # Add global log level argument
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default=None,
        help="Set logging level (default: warning)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Register all commands
    command_map = {}
    for command in ALL_COMMANDS:
        cmd_parser = subparsers.add_parser(
            command.name,
            help=command.help,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=command.epilog,
        )
        command.add_arguments(cmd_parser)
        command_map[command.name] = command

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Setup logging
    log_level = getattr(args, "log_level", None)
    verbose = getattr(args, "verbose", False)
    setup_logging(log_level, verbose)

    # Execute command
    try:
        command = command_map[args.command]
        exit_code = asyncio.run(command.execute(args))
        return exit_code
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        return 130  # Standard exit code for SIGINT
    except asyncio.CancelledError:
        logging.warning("Operation cancelled")
        return 130
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return 1
    except PermissionError as e:
        logging.error(f"Permission denied: {e}")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
