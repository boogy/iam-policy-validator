"""The PR summary's Issue Breakdown lists each severity on its own row."""

import pytest

from iam_validator.core import constants
from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.core.report import ReportGenerator


def _report(*severities: str):
    issues = [ValidationIssue(severity=s, statement_index=0, issue_type="t", message="m") for s in severities]
    result = PolicyValidationResult(policy_file="policy.json", is_valid=False, issues=issues)
    return ReportGenerator().generate_report([result])


def _breakdown_rows(comment: str) -> list[str]:
    section = comment.split("### 🔍 Issue Breakdown", 1)[1]
    table = section.split("\n\n", 2)[1]
    return [line for line in table.splitlines() if line.startswith("| ") and "Severity" not in line]


@pytest.mark.parametrize("render", ["single", "split"])
def test_every_severity_has_its_own_row_most_severe_first(render):
    report = _report("low", "medium", "warning", "info", "high", "critical", "error", "medium")
    generator = ReportGenerator()
    if render == "single":
        comment = generator.generate_github_comment(report)
    else:
        # The header the multi-part comment path puts in its first part.
        comment = "\n".join(generator._generate_header(report, 0, None, False, None))

    rows = _breakdown_rows(comment)
    labels = [row.split("**")[1] for row in rows]
    assert labels == ["Error", "Critical", "High", "Warning", "Medium", "Low", "Info"]
    assert f"| {constants.SEVERITY_CONFIG['medium']['emoji']} **Medium** | 2 |" in rows


def test_absent_severities_get_no_row():
    rows = _breakdown_rows(ReportGenerator().generate_github_comment(_report("high", "low")))
    assert [row.split("**")[1] for row in rows] == ["High", "Low"]


def test_no_breakdown_without_findings():
    report = ReportGenerator().generate_report(
        [PolicyValidationResult(policy_file="policy.json", is_valid=True, issues=[])]
    )
    assert "Issue Breakdown" not in ReportGenerator().generate_github_comment(report)
