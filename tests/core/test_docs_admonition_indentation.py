"""Guard rail: prettier dedents an unindented admonition body into an empty box."""

import re
from pathlib import Path

_DOCS_ROOT = Path(__file__).parents[2] / "docs"
_README = Path(__file__).parents[2] / "README.md"

_HEADER_PATTERN = re.compile(r"^(!!!|\?\?\?\+?) ")
_FENCE_PATTERN = re.compile(r"^[ \t]*(`{3,}|~{3,})")


def _markdown_files() -> list[Path]:
    return [*sorted(_DOCS_ROOT.rglob("*.md")), _README]


def _indent(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))


def _find_violations(text: str) -> list[int]:
    lines = text.split("\n")
    violations = []
    in_fence = False
    for i, line in enumerate(lines):
        if _FENCE_PATTERN.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = line[_indent(line) :]
        if not _HEADER_PATTERN.match(stripped):
            continue
        header_indent = _indent(line)
        j = i + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        if j == len(lines) or _indent(lines[j]) <= header_indent:
            violations.append(i + 1)
    return violations


def test_admonition_header_followed_by_indented_body():
    violations: list[str] = []
    for path in _markdown_files():
        for line_number in _find_violations(path.read_text()):
            violations.append(f"{path}:{line_number}")

    assert not violations, (
        f"Admonition header not followed by an indented body (prettier will collapse the box): {violations}"
    )
