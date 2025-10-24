"""Base command class for CLI commands."""

import argparse
from abc import ABC, abstractmethod


class Command(ABC):
    """Base class for all CLI commands."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Command name (e.g., 'validate', 'post-to-pr')."""
        pass

    @property
    @abstractmethod
    def help(self) -> str:
        """Short help text for the command."""
        pass

    @property
    def epilog(self) -> str | None:
        """Optional epilog with examples."""
        return None

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Add command-specific arguments to the parser.

        Args:
            parser: ArgumentParser for this command
        """
        pass

    @abstractmethod
    async def execute(self, args: argparse.Namespace) -> int:
        """
        Execute the command.

        Args:
            args: Parsed command-line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        pass
