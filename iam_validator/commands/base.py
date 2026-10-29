"""Base command class for CLI commands."""

import argparse
from abc import ABC, abstractmethod

from iam_validator.commands.examples import ExamplesAction, ExampleSections, print_examples


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
        """Help epilog; points to ``--examples`` when the command has examples."""
        if self.examples:
            return f"Run 'iam-validator {self.name} --examples' for usage examples."
        return None

    @property
    def examples(self) -> ExampleSections:
        """Usage examples as (title, commands) sections, shown by ``--examples``."""
        return []

    @property
    def examples_notes(self) -> str | None:
        """Optional verbatim text printed after the examples."""
        return None

    def print_examples(self) -> None:
        """Print this command's usage examples."""
        print_examples(self.examples, notes=self.examples_notes)

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        """Add the command's arguments plus ``--examples`` when it has examples."""
        self.add_arguments(parser)
        if self.examples:
            parser.add_argument(
                "--examples", action=ExamplesAction, printer=self.print_examples, help="Show usage examples and exit"
            )

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
