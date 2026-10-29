"""Usage examples for CLI commands, printed by ``--examples``."""

import argparse
from collections.abc import Callable
from typing import Any

from rich.console import Console
from rich.text import Text

ExampleSections = list[tuple[str, list[str]]]


def print_examples(sections: ExampleSections, heading: str | None = None, notes: str | None = None) -> None:
    """Print example sections (title + commands) and optional verbatim notes."""
    console = Console()
    if heading:
        console.print(Text(heading, style="bold"))
    for title, commands in sections:
        console.print(Text(f"  # {title}", style="dim"))
        for command in commands:
            console.print(Text.assemble(("  $ ", "cyan"), command), soft_wrap=True)
    if notes:
        console.print()
        console.print(Text(notes), soft_wrap=True)
    console.print()


class ExamplesAction(argparse.Action):
    """``--examples``: print the command's examples and exit before required-argument checks."""

    def __init__(self, option_strings: list[str], dest: str, printer: Callable[[], None], **kwargs: Any) -> None:
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, **kwargs)
        self.printer = printer

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        self.printer()
        parser.exit()
