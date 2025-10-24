"""Command-line interface for IAM Policy Validator."""

import argparse
import asyncio
import logging
import os
import sys

from iam_validator import __version__
from iam_validator.commands import ALL_COMMANDS


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration.

    Args:
        verbose: Enable verbose logging

    Environment Variables:
        LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
                   Overrides the --verbose flag if set
    """
    # Check for LOG_LEVEL environment variable
    log_level_str = os.getenv("LOG_LEVEL", "").upper()

    # Map string to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    # Priority: LOG_LEVEL env var > --verbose flag > default (INFO)
    if log_level_str in level_map:
        level = level_map[log_level_str]
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

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
    verbose = getattr(args, "verbose", False)
    setup_logging(verbose)

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
