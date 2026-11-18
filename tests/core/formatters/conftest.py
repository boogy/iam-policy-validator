import pytest

from iam_validator.core.models import PolicyValidationResult, ValidationIssue, ValidationReport


def _issue(statement_index: int, message: str) -> ValidationIssue:
    return ValidationIssue(
        severity="error", statement_index=statement_index, issue_type="t", message=message, suggestion=None
    )


@pytest.fixture
def report() -> ValidationReport:
    issues = [_issue(-1, "policy-level-msg"), _issue(0, "first-statement-msg")]
    return ValidationReport(
        total_policies=1,
        valid_policies=0,
        invalid_policies=1,
        total_issues=len(issues),
        results=[PolicyValidationResult(policy_file="p.json", is_valid=False, issues=issues)],
    )
