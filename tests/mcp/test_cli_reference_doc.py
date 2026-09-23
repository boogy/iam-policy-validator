"""Guard rail: docs/user-guide/cli-reference.md's mcp options table must not drift
from iam_validator/mcp/cli.py's actual flags."""

import argparse
import re
from pathlib import Path

from iam_validator.mcp.cli import add_arguments

_DOC_PATH = Path(__file__).parents[2] / "docs" / "user-guide" / "cli-reference.md"


def _parser_long_flags() -> set[str]:
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    flags: set[str] = set()
    for action in parser._actions:
        for option in action.option_strings:
            if option.startswith("--") and option != "--help":
                flags.add(option)
    return flags


def test_every_mcp_flag_is_documented():
    doc_text = _DOC_PATH.read_text()
    section = doc_text.split("## mcp", 1)[1].split("## Exit Codes", 1)[0]
    documented = set(re.findall(r"`(--[a-z-]+)`", section))

    missing = _parser_long_flags() - documented
    assert not missing, f"Flags missing from cli-reference.md's mcp section: {sorted(missing)}"


def test_no_documented_flag_is_stale():
    doc_text = _DOC_PATH.read_text()
    section = doc_text.split("## mcp", 1)[1].split("## Exit Codes", 1)[0]
    documented = set(re.findall(r"`(--[a-z-]+)`", section))

    stale = documented - _parser_long_flags()
    assert not stale, f"cli-reference.md documents flags that no longer exist: {sorted(stale)}"


def test_sse_transport_not_documented():
    doc_text = _DOC_PATH.read_text()
    section = doc_text.split("## mcp", 1)[1].split("## Exit Codes", 1)[0]
    assert "--transport sse" not in section
