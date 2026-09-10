"""Console output must render at the width Rich measured for it."""

import ast
import unicodedata
from pathlib import Path

import pytest
from rich.cells import cell_len

from iam_validator.core.formatters.enhanced import EnhancedFormatter
from iam_validator.core.models import PolicyValidationResult, ValidationIssue, ValidationReport

# Modules whose every string literal is rendered to a terminal.
CONSOLE_MODULES = [
    Path("iam_validator/core/formatters/enhanced.py"),
    Path("iam_validator/core/formatters/console.py"),
]

REPO_ROOT = Path(__file__).resolve().parents[2]


def terminal_width(text: str) -> int:
    """Columns a wcwidth-based terminal advances for ``text``."""
    total = 0
    for char in text:
        if unicodedata.category(char) in ("Mn", "Me", "Cf", "Cc"):
            continue
        total += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return total


def _report(*, errors: int, findings: int, finding_severity: str = "high") -> ValidationReport:
    results = []
    for index in range(errors):
        results.append(
            PolicyValidationResult(
                policy_file=f"invalid-{index}.json",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="error",
                        statement_index=0,
                        issue_type="invalid_action",
                        message="Action 's3:Nope' does not exist",
                    )
                ],
            )
        )
    for index in range(findings):
        results.append(
            PolicyValidationResult(
                policy_file=f"finding-{index}.json",
                is_valid=True,
                issues=[
                    ValidationIssue(
                        severity=finding_severity,
                        statement_index=0,
                        issue_type="wildcard_action",
                        message="Wildcard action grants broad access",
                    )
                ],
            )
        )
    if not results:
        results.append(PolicyValidationResult(policy_file="clean.json", is_valid=True))
    total_issues = sum(len(r.issues) for r in results)
    return ValidationReport(
        total_policies=len(results),
        valid_policies=sum(1 for r in results if r.is_valid),
        invalid_policies=sum(1 for r in results if not r.is_valid),
        total_issues=total_issues,
        results=results,
    )


# One report per branch of _print_final_status.
REPORTS = {
    "clean": _report(errors=0, findings=0),
    "findings": _report(errors=0, findings=1),
    "advisories": _report(errors=0, findings=2, finding_severity="low"),
    "failed": _report(errors=1, findings=1),
}


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_final_status_panel_is_rectangular(name):
    lines = [line.rstrip() for line in EnhancedFormatter().format(REPORTS[name], color=False).splitlines()]
    start = max(index for index, line in enumerate(lines) if line.startswith("\u256d"))
    end = next(index for index, line in enumerate(lines[start:], start) if line.startswith("\u2570"))
    widths = {terminal_width(line) for line in lines[start : end + 1]}
    assert widths == {terminal_width(lines[start])}


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_rendered_lines_match_rich_measurement(name):
    output = EnhancedFormatter().format(REPORTS[name], color=False)
    for line in output.splitlines():
        stripped = line.rstrip()
        assert terminal_width(stripped) == cell_len(stripped), repr(stripped)


@pytest.mark.parametrize("module", CONSOLE_MODULES, ids=lambda p: p.name)
def test_console_literals_have_unambiguous_width(module):
    tree = ast.parse((REPO_ROOT / module).read_text(), filename=str(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert terminal_width(node.value) == cell_len(node.value), (
                f"{module}:{node.lineno} renders at a width Rich does not predict: {node.value!r}"
            )
