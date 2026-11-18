"""Location labels in the default console report."""

from rich.console import Console

from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.core.report import ReportGenerator


def _render(statement_index: int) -> str:
    issue = ValidationIssue(
        severity="error",
        statement_index=statement_index,
        issue_type="invalid_condition_requirement",
        message="msg",
    )
    generator = ReportGenerator()
    generator.console = Console(record=True, width=200)
    generator._print_policy_result(PolicyValidationResult(policy_file="p.json", is_valid=False, issues=[issue]))
    return generator.console.export_text()


def test_policy_level_issue_is_labelled_policy_level():
    text = _render(-1)
    assert "Policy-level: msg" in text
    assert "Statement 0" not in text


def test_statement_issue_is_labelled_with_one_based_number():
    assert "Statement 1: msg" in _render(0)
