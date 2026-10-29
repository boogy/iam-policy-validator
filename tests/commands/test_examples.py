import argparse
import sys
from unittest.mock import patch

import pytest

from iam_validator.commands import ALL_COMMANDS
from iam_validator.core.cli import main

COMMANDS_WITH_EXAMPLES = [c.name for c in ALL_COMMANDS if c.examples]


def test_every_command_has_examples() -> None:
    assert COMMANDS_WITH_EXAMPLES == [c.name for c in ALL_COMMANDS]


@pytest.mark.parametrize("command_name", COMMANDS_WITH_EXAMPLES)
def test_examples_flag_prints_and_exits_without_required_args(command_name: str, capsys) -> None:
    with patch.object(sys, "argv", ["iam-validator", command_name, "--examples"]), pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert f"iam-validator {command_name}" in capsys.readouterr().out


@pytest.mark.parametrize("command", ALL_COMMANDS, ids=lambda c: c.name)
def test_help_points_to_examples_instead_of_listing_them(command) -> None:
    parser = argparse.ArgumentParser(epilog=command.epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    command.configure_parser(parser)
    help_text = parser.format_help()
    assert f"iam-validator {command.name} --examples" in help_text
    assert "Examples:" not in help_text
    assert f"  iam-validator {command.name} " not in help_text


def test_examples_notes_printed_after_examples(capsys) -> None:
    command = next(c for c in ALL_COMMANDS if c.name == "sync-services")
    command.print_examples()
    out = capsys.readouterr().out
    assert out.index("$ iam-validator sync-services") < out.index("Directory structure:")
